#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "fd_udpsock.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

/* FD_UDPSOCK_FRAME_ALIGN is the alignment of a packet frame */

#define FD_UDPSOCK_FRAME_ALIGN (16UL)
#define FD_UDPSOCK_HEADROOM    (18UL+20UL+8UL)  /* Ethernet, IPv4, UDP */

struct fd_udpsock {
  fd_aio_t         aio_self;  /* aio provided by udpsock */
  fd_aio_t const * aio_rx;    /* aio provided by receiver */

  int fd;  /* file descriptor of actual socket */

  /* Mock Ethernet fields */

  uchar eth_self_addr[ 6 ];
  uchar eth_peer_addr[ 6 ];

  /* Mock UDP/IPv4 fields (big endian) */

  uint   ip_self_addr;
  ushort udp_self_port;

  /* Pointers to variable length data structures */

  ulong               rx_cnt;
  struct mmsghdr *    rx_msg;
  struct iovec   *    rx_iov;
  void *              rx_frame;
  fd_aio_pkt_info_t * rx_pkt;
  ulong               tx_cnt;
  struct mmsghdr *    tx_msg;
  struct iovec   *    tx_iov;
  void *              tx_frame;

  /* Variable length data structures follow ...

       struct mmsghdr    [ rx_cnt ] (rx)
       struct mmsghdr    [ tx_cnt ] (tx)
       struct iovec      [ rx_cnt ] (rx)
       struct iovec      [ tx_cnt ] (tx)
       uchar      [ mtu ][ rx_cnt ] (rx)
       fd_aio_pkt_t      [ rx_cnt ] (rx)
       struct sockaddr_in[ rx_cnt ] (rx)
       struct sockaddr_in[ tx_cnt ] (tx) */
};

/* Forward declaration */
static int
fd_udpsock_send( void *                    ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush );

FD_FN_CONST ulong
fd_udpsock_align( void ) {
  return alignof(fd_udpsock_t);
}

FD_FN_CONST ulong
fd_udpsock_footprint( ulong mtu,
                      ulong rx_pkt_cnt,
                      ulong tx_pkt_cnt ) {

  if( FD_UNLIKELY( ( mtu       ==0UL                 )
                 | ( mtu       <=FD_UDPSOCK_HEADROOM )
                 | ( rx_pkt_cnt==0UL                 )
                 | ( tx_pkt_cnt==0UL                 ) ) )
    return 0UL;

  ulong tot_pkt_cnt = rx_pkt_cnt + tx_pkt_cnt;
  ulong aligned_mtu = fd_ulong_align_up( mtu, FD_UDPSOCK_FRAME_ALIGN );

  return
    FD_LAYOUT_FINI  ( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof( fd_udpsock_t   ),                 sizeof(  fd_udpsock_t  )     ),
      alignof( struct mmsghdr ),     tot_pkt_cnt*sizeof( struct mmsghdr )     ),
      alignof( struct iovec   ),     tot_pkt_cnt*sizeof( struct iovec   )     ),
      FD_UDPSOCK_FRAME_ALIGN,        rx_pkt_cnt *aligned_mtu                  ),
      alignof( fd_aio_pkt_info_t  ), rx_pkt_cnt *sizeof( fd_aio_pkt_info_t  ) ),
      alignof( struct sockaddr_in ), tot_pkt_cnt*sizeof( struct sockaddr_in ) ),
      FD_UDPSOCK_ALIGN );
}

void *
fd_udpsock_new( void * shmem,
                ulong  mtu,
                ulong  rx_pkt_cnt,
                ulong  tx_pkt_cnt ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  ulong laddr = (ulong)shmem;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( laddr, fd_udpsock_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  ulong footprint = fd_udpsock_footprint( mtu, rx_pkt_cnt, tx_pkt_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return NULL;
  }
  laddr += FD_LAYOUT_INIT;

  /* Allocate main struct */

  laddr  = fd_ulong_align_up( laddr, alignof(fd_udpsock_t) );
  fd_udpsock_t * sock = (fd_udpsock_t *)laddr;
  memset( sock, 0, sizeof(fd_udpsock_t) );
  sock->fd     = -1;
  sock->rx_cnt = rx_pkt_cnt;
  sock->tx_cnt = tx_pkt_cnt;
  laddr += sizeof(fd_udpsock_t);

  ulong tot_pkt_cnt = rx_pkt_cnt + tx_pkt_cnt;
  ulong aligned_mtu = fd_ulong_align_up( mtu, FD_UDPSOCK_FRAME_ALIGN );

  /* Set defaults for mock network headers */

  memcpy( sock->eth_self_addr, (uchar[6]){0x00, 0x00, 0x5e, 0x00, 0x53, 0x42}, 6 );
  memcpy( sock->eth_self_addr, (uchar[6]){0x00, 0x00, 0x5e, 0x00, 0x53, 0x43}, 6 );

  sock->ip_self_addr  = FD_IP4_ADDR( 0, 0, 0, 0 );
  sock->udp_self_port = 0;

  sock->aio_self = (fd_aio_t){
    .ctx       = sock,
    .send_func = fd_udpsock_send
  };

  /* Allocate variable-length data structures */

  laddr  = fd_ulong_align_up( laddr, alignof(struct mmsghdr) );
  struct mmsghdr * msg = (struct mmsghdr *)laddr;
  sock->rx_msg = msg;
  sock->tx_msg = msg + rx_pkt_cnt;
  laddr += tot_pkt_cnt*sizeof(struct mmsghdr);

  laddr  = fd_ulong_align_up( laddr, alignof(struct iovec) );
  struct iovec * iov = (struct iovec *)laddr;
  sock->rx_iov = iov;
  sock->tx_iov = iov + rx_pkt_cnt;
  laddr += tot_pkt_cnt*sizeof(struct iovec);

  laddr  = fd_ulong_align_up( laddr, FD_UDPSOCK_FRAME_ALIGN );
  ulong frame_base = laddr;
  sock->rx_frame = (void *)laddr;
  sock->tx_frame = (void *)(laddr + aligned_mtu*rx_pkt_cnt);
  laddr += rx_pkt_cnt*aligned_mtu;

  laddr  = fd_ulong_align_up( laddr, alignof(fd_aio_pkt_info_t) );
  fd_aio_pkt_info_t * pkt = (fd_aio_pkt_info_t *)laddr;
  sock->rx_pkt = pkt;
  laddr += rx_pkt_cnt*sizeof(fd_aio_pkt_info_t);

  laddr  = fd_ulong_align_up( laddr, alignof(struct sockaddr_in) );
  struct sockaddr_in * saddrs = (struct sockaddr_in *)laddr;
  laddr += tot_pkt_cnt*sizeof(struct sockaddr_in);

  /* Prepare iovec and msghdr buffers */

  for( ulong i=0; i<rx_pkt_cnt; i++ ) {
    iov[i].iov_base            = (void *)(frame_base + i*aligned_mtu + FD_UDPSOCK_HEADROOM);
    iov[i].iov_len             = aligned_mtu - FD_UDPSOCK_HEADROOM;
    msg[i].msg_hdr.msg_iov     = &iov[i];
    msg[i].msg_hdr.msg_iovlen  = 1;
    msg[i].msg_hdr.msg_name    = &saddrs[i];
    msg[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
  }
  for( ulong i=rx_pkt_cnt; i<tot_pkt_cnt; i++ ) {
    msg[i].msg_hdr.msg_iov     = &iov[i];
    msg[i].msg_hdr.msg_iovlen  = 1;
    msg[i].msg_hdr.msg_name    = &saddrs[i];
    msg[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
  }

  return shmem;
}

fd_udpsock_t *
fd_udpsock_join( void * shsock,
                 int    fd ) {

  fd_udpsock_t * sock = (fd_udpsock_t *)shsock;
  sock->fd = fd;

  /* Extract socket address */
  struct sockaddr addr;
  socklen_t addrlen = sizeof(addr);
  int res = getsockname( fd, &addr, &addrlen );
  if( FD_UNLIKELY( res < 0 ) ) {
    FD_LOG_WARNING(( "getsockname(%d) failed (%d-%s)", fd, errno, strerror(errno) ));
    return NULL;
  }
  if( FD_UNLIKELY( addr.sa_family != AF_INET ) ) {
    FD_LOG_WARNING(( "getsockname(%d) returned non-IPv4 address", fd ));
    return NULL;
  }
  struct sockaddr_in const * sin = (struct sockaddr_in const *)fd_type_pun_const( &addr );
  sock->ip_self_addr  = fd_uint_bswap( sin->sin_addr.s_addr );
  sock->udp_self_port = fd_ushort_bswap( sin->sin_port );

  return sock;
}

void *
fd_udpsock_leave( fd_udpsock_t * sock ) {
  sock->fd = -1;
  return (void *)sock;
}

void *
fd_udpsock_delete( void * shsock ) {
  return shsock;
}

void
fd_udpsock_set_rx( fd_udpsock_t *   sock,
                   fd_aio_t const * aio ) {
  sock->aio_rx = aio;
}

FD_FN_CONST fd_aio_t const *
fd_udpsock_get_rx( fd_udpsock_t * sock ) {
  return &sock->aio_self;
}

void
fd_udpsock_service( fd_udpsock_t * sock ) {
  /* Receive packets into iovecs */

  int fd  = sock->fd;
  int res = recvmmsg( fd, sock->rx_msg, (uint)sock->rx_cnt, MSG_DONTWAIT, NULL );
  if( FD_UNLIKELY( res<0 ) ) {
    if( FD_LIKELY( (errno==EAGAIN) | (errno==EWOULDBLOCK) ) )
      return;
    FD_LOG_WARNING(( "recvmmsg(%d) failed (%d-%s)", fd, errno, strerror(errno) ));
    return;
  }
  ulong msg_cnt = (ulong)res;

  /* Create fake headers and prepare an aio batch */

  for( ulong i=0UL; i<msg_cnt; i++ ) {
    struct sockaddr_in const * addr = (struct sockaddr_in const *)sock->rx_msg[i].msg_hdr.msg_name;

    void * frame_base = (void *)( (ulong)sock->rx_iov[i].iov_base - FD_UDPSOCK_HEADROOM );
    fd_eth_hdr_t * eth = (fd_eth_hdr_t *)frame_base;
    memcpy( eth->dst, sock->eth_self_addr, 6 );
    memcpy( eth->src, sock->eth_peer_addr, 6 );
    eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

    fd_ip4_hdr_t * ip4 = (fd_ip4_hdr_t *)((ulong)eth + sizeof(fd_eth_hdr_t));
    *ip4 = (fd_ip4_hdr_t) {
      .ihl          = 5,
      .version      = 4,
      .tos          = 0,
      .net_tot_len  = (ushort)fd_ushort_bswap( (ushort)(sock->rx_iov[i].iov_len - sizeof(fd_eth_hdr_t)) ),
      .net_id       = 0,
      .net_frag_off = 0,
      .ttl          = 64,
      .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
      .check        = 0,
      .saddr        = addr->sin_addr.s_addr,
      .daddr        = sock->ip_self_addr
    };

    fd_udp_hdr_t * udp = (fd_udp_hdr_t *)((ulong)ip4 + sizeof(fd_ip4_hdr_t));
    *udp = (fd_udp_hdr_t) {
      .net_sport = (ushort)addr->sin_port,
      .net_dport = (ushort)fd_ushort_bswap( sock->udp_self_port ),
      .net_len   = (ushort)fd_ushort_bswap( (ushort)(sock->rx_iov[i].iov_len - sizeof(fd_eth_hdr_t) - sizeof(fd_ip4_hdr_t)) ),
      .check     = 0
    };

    sock->rx_pkt[i] = (fd_aio_pkt_info_t) {
      .buf    = frame_base,
      .buf_sz = (ushort)( FD_UDPSOCK_HEADROOM + sock->rx_msg[i].msg_len )
    };
  }

  /* Dispatch to recipient ignoring errors */

  fd_aio_send( sock->aio_rx, sock->rx_pkt, msg_cnt, NULL, 0 );
}

static int
fd_udpsock_send( void *                    ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush ) {

  fd_udpsock_t * sock = (fd_udpsock_t *)ctx;

  if( FD_UNLIKELY( batch_cnt == 0 ) )
    return FD_AIO_SUCCESS;
  ulong send_cnt = fd_ulong_if( batch_cnt > sock->tx_cnt, sock->tx_cnt, batch_cnt );

  ulong _dummy_batch_idx;
  opt_batch_idx = opt_batch_idx ? opt_batch_idx : &_dummy_batch_idx;

  /* Set up iovecs */

  for( ulong i=0UL; i<send_cnt; i++ ) {
    uint   daddr = 0U;
    ushort dport = 0U;

    if( FD_LIKELY( batch[i].buf_sz >= sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t) ) ) {
      fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)( (ulong)batch[i].buf + sizeof(fd_eth_hdr_t) );
      daddr = ip4->daddr;
      fd_udp_hdr_t const * udp = (fd_udp_hdr_t const *)( (ulong)ip4 + (ulong)ip4->ihl*4 );
      dport = udp->net_dport;

      sock->tx_iov[i].iov_base = (void *)( (ulong)batch[i].buf + FD_UDPSOCK_HEADROOM );
      sock->tx_iov[i].iov_len  = batch[i].buf_sz - FD_UDPSOCK_HEADROOM;
      struct sockaddr_in * addr = (struct sockaddr_in *)sock->tx_msg[i].msg_hdr.msg_name;
      addr->sin_addr = (struct in_addr) { .s_addr = daddr };
      addr->sin_port = dport;

      sock->rx_msg[i].msg_len = !!ip4->ttl;
    } else {
      sock->rx_msg[i].msg_len = 0;
    }
  }
  int fd  = sock->fd;
  int res = sendmmsg( sock->fd, sock->tx_msg, (uint)send_cnt, flush ? 0 : MSG_DONTWAIT );
  if( FD_UNLIKELY( res<0 ) ) {
    *opt_batch_idx = 0UL;
    if( FD_LIKELY( (errno==EAGAIN) | (errno==EWOULDBLOCK) ) )
      return FD_AIO_ERR_AGAIN;
    FD_LOG_WARNING(( "sendmmsg(%d) failed (%d-%s)", fd, errno, strerror(errno) ));
    return FD_AIO_ERR_INVAL;
  }
  ulong sent_cnt = (ulong)res;

  if( FD_UNLIKELY( send_cnt<sent_cnt ) ) {
    *opt_batch_idx = send_cnt;
    return FD_AIO_ERR_AGAIN;
  }
  return FD_AIO_SUCCESS;
}

