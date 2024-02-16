#include "../../util/fd_util.h"
#include "fd_udpsock.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

int
echo_aio_recv( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx,
               int                       flush ) {

  /* Swap UDP/IP source and destination */

  for( ulong i=0UL; i<batch_cnt; i++ ) {
    fd_eth_hdr_t * eth_hdr = (fd_eth_hdr_t *)batch[i].buf;
    fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)(eth_hdr+1);
    fd_udp_hdr_t * udp_hdr = (fd_udp_hdr_t *)((ulong)ip4_hdr+((ulong)FD_IP4_GET_LEN(*ip4_hdr)));
    uint           ip4_src;
    uint           ip4_dst;
    memcpy( &ip4_src, ip4_hdr->saddr_c, 4U );
    memcpy( &ip4_dst, ip4_hdr->daddr_c, 4U );
    ushort         udp_src = udp_hdr->net_sport;
    ushort         udp_dst = udp_hdr->net_dport;
    /* switch source and destination */
    memcpy( &ip4_dst, ip4_hdr->saddr_c, 4U );
    memcpy( &ip4_src, ip4_hdr->daddr_c, 4U );
    ip4_hdr->ttl--;
    udp_hdr->net_sport = udp_dst;
    udp_hdr->net_dport = udp_src;
  }

  fd_aio_t const * out = (fd_aio_t const *)ctx;
  fd_aio_send( out, batch, batch_cnt, opt_batch_idx, flush );
  return FD_AIO_SUCCESS;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  uint port = fd_env_strip_cmdline_ushort( &argc, &argv, "--port", NULL, 8080U );

  /* Create new UDP socket and listen */

  FD_LOG_NOTICE(( "Listening at 0.0.0.0:%d", port ));

  int sock_fd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
  if( FD_UNLIKELY( sock_fd<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_in listen_addr = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = 0U },
    .sin_port   = (ushort)fd_ushort_bswap( (ushort)port ),
  };
  if( FD_UNLIKELY( 0!=bind( sock_fd, (struct sockaddr const *)fd_type_pun_const( &listen_addr ), sizeof(struct sockaddr_in) ) ) ) {
    FD_LOG_ERR(( "bind(sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Allocate fd_udpsock */

  ulong mtu        = 1300UL;
  ulong rx_pkt_cnt = 1024UL;
  ulong tx_pkt_cnt = 1024UL;

  fd_udpsock_t * sock = fd_udpsock_join( fd_udpsock_new( aligned_alloc( fd_udpsock_align(), fd_udpsock_footprint( mtu, rx_pkt_cnt, tx_pkt_cnt ) ), mtu, rx_pkt_cnt, tx_pkt_cnt ), sock_fd );
  FD_TEST( sock );

  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, (void *)fd_udpsock_get_tx( sock ), echo_aio_recv ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  fd_udpsock_set_rx( sock, aio );

  for(;;) {
    fd_udpsock_service( sock );
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_aio_delete( fd_aio_leave( aio ) );
  free( fd_udpsock_delete( fd_udpsock_leave( sock ) ) );

  if( FD_UNLIKELY( close( sock_fd )<0 ) ) FD_LOG_ERR(( "close(sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
