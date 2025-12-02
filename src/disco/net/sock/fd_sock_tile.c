#define _GNU_SOURCE /* dup3 */
#include "fd_sock_tile_private.h"
#include "../../../util/net/fd_net_common.h"
#include "../../topo/fd_topo.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"

#include <assert.h> /* assert */
#include <stdalign.h> /* alignof */
#include <errno.h>
#include <fcntl.h> /* fcntl */
#include <unistd.h> /* dup3, close */
#include <netinet/in.h> /* sockaddr_in */
#include <sys/socket.h> /* socket */
#include "../../metrics/fd_metrics.h"

#include "generated/fd_sock_tile_seccomp.h"

/* recv/sendmmsg packet count in batch and tango burst depth
   FIXME make configurable in the future?
   FIXME keep in sync with fd_net_tile_topo.c */
#define STEM_BURST (64UL)

/* Place RX socket file descriptors in contiguous integer range. */
#define RX_SOCK_FD_MIN (128)

/* Controls max ancillary data size.
   Must be aligned by alignof(struct cmsghdr) */
#define FD_SOCK_CMSG_MAX (64UL)

/* Value of the sock_idx for Firedancer repair intake.
   Used to determine whether repair packets should go to shred vs repair tile.
   This value is validated at startup. */
#define REPAIR_SHRED_SOCKET_ID (4U)

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_sock_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sock_tile_t), sizeof(fd_sock_tile_t) );

  populate_sock_filter_policy_fd_sock_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->tx_sock, RX_SOCK_FD_MIN, RX_SOCK_FD_MIN+(uint)ctx->sock_cnt );
  return sock_filter_policy_fd_sock_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_sock_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sock_tile_t), sizeof(fd_sock_tile_t) );

  ulong sock_cnt = ctx->sock_cnt;
  if( FD_UNLIKELY( out_fds_cnt<sock_cnt+3UL ) ) {
    FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  }

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = ctx->tx_sock;
  for( ulong j=0UL; j<sock_cnt; j++ ) {
    out_fds[ out_cnt++ ] = ctx->pollfd[ j ].fd;
  }
  return out_cnt;
}

FD_FN_CONST static inline ulong
tx_scratch_footprint( void ) {
  return STEM_BURST * fd_ulong_align_up( FD_NET_MTU, FD_CHUNK_ALIGN );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sock_tile_t),     sizeof(fd_sock_tile_t)                );
  l = FD_LAYOUT_APPEND( l, alignof(struct iovec),       STEM_BURST*sizeof(struct iovec)       );
  l = FD_LAYOUT_APPEND( l, alignof(struct cmsghdr),     STEM_BURST*FD_SOCK_CMSG_MAX           );
  l = FD_LAYOUT_APPEND( l, alignof(struct sockaddr_in), STEM_BURST*sizeof(struct sockaddr_in) );
  l = FD_LAYOUT_APPEND( l, alignof(struct mmsghdr),     STEM_BURST*sizeof(struct mmsghdr)     );
  l = FD_LAYOUT_APPEND( l, FD_CHUNK_ALIGN,              tx_scratch_footprint()                );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* create_udp_socket creates and configures a new UDP socket for the
   sock tile at the given file descriptor ID. */

static void
create_udp_socket( int    sock_fd,
                   uint   bind_addr,
                   ushort udp_port,
                   int    so_rcvbuf ) {

  if( fcntl( sock_fd, F_GETFD, 0 )!=-1 ) {
    FD_LOG_ERR(( "file descriptor %d already exists", sock_fd ));
  } else if( errno!=EBADF ) {
    FD_LOG_ERR(( "fcntl(F_GETFD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int orig_fd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
  if( FD_UNLIKELY( orig_fd<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int reuseport = 1;
  if( FD_UNLIKELY( setsockopt( orig_fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(int) )<0 ) ) {
    FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_REUSEPORT,1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int ip_pktinfo = 1;
  if( FD_UNLIKELY( setsockopt( orig_fd, IPPROTO_IP, IP_PKTINFO, &ip_pktinfo, sizeof(int) )<0 ) ) {
    FD_LOG_ERR(( "setsockopt(IPPROTO_IP,IP_PKTINFO,1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=setsockopt( orig_fd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_RCVBUF,%i) failed (%i-%s)", so_rcvbuf, errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_in saddr = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = bind_addr,
    .sin_port        = fd_ushort_bswap( udp_port ),
  };
  if( FD_UNLIKELY( 0!=bind( orig_fd, fd_type_pun_const( &saddr ), sizeof(struct sockaddr_in) ) ) ) {
    FD_LOG_ERR(( "bind(0.0.0.0:%i) failed (%i-%s)", udp_port, errno, fd_io_strerror( errno ) ));
  }

# if defined(__linux__)
  int dup_res = dup3( orig_fd, sock_fd, O_CLOEXEC );
# else
  int dup_res = dup2( orig_fd, sock_fd );
# endif
  if( FD_UNLIKELY( dup_res!=sock_fd ) ) {
    FD_LOG_ERR(( "dup2 returned %i (%i-%s)", sock_fd, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=close( orig_fd ) ) ) {
    FD_LOG_ERR(( "close(%d) failed (%i-%s)", orig_fd, errno, fd_io_strerror( errno ) ));
  }

}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_sock_tile_t *     ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sock_tile_t),     sizeof(fd_sock_tile_t)                );
  struct iovec   *     batch_iov  = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct iovec),       STEM_BURST*sizeof(struct iovec)       );
  void *               batch_cmsg = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct cmsghdr),     STEM_BURST*FD_SOCK_CMSG_MAX           );
  struct sockaddr_in * batch_sa   = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct sockaddr_in), STEM_BURST*sizeof(struct sockaddr_in) );
  struct mmsghdr *     batch_msg  = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct mmsghdr),     STEM_BURST*sizeof(struct mmsghdr)     );
  uchar *              tx_scratch = FD_SCRATCH_ALLOC_APPEND( l, FD_CHUNK_ALIGN,              tx_scratch_footprint()                );

  assert( scratch==ctx );

  fd_memset( ctx,       0, sizeof(fd_sock_tile_t)                );
  fd_memset( batch_iov, 0, STEM_BURST*sizeof(struct iovec)       );
  fd_memset( batch_sa,  0, STEM_BURST*sizeof(struct sockaddr_in) );
  fd_memset( batch_msg, 0, STEM_BURST*sizeof(struct mmsghdr)     );

  ctx->batch_cnt   = 0UL;
  ctx->batch_iov   = batch_iov;
  ctx->batch_cmsg  = batch_cmsg;
  ctx->batch_sa    = batch_sa;
  ctx->batch_msg   = batch_msg;
  ctx->tx_scratch0 = tx_scratch;
  ctx->tx_scratch1 = tx_scratch + tx_scratch_footprint();
  ctx->tx_ptr      = tx_scratch;

  /* Create receive sockets.  Incrementally assign them to file
     descriptors starting at sock_fd_min. */

  int sock_fd_min = RX_SOCK_FD_MIN;
  ushort udp_port_candidates[] = {
    (ushort)tile->sock.net.legacy_transaction_listen_port,
    (ushort)tile->sock.net.quic_transaction_listen_port,
    (ushort)tile->sock.net.shred_listen_port,
    (ushort)tile->sock.net.gossip_listen_port,
    (ushort)tile->sock.net.repair_intake_listen_port,
    (ushort)tile->sock.net.repair_serve_listen_port,
    (ushort)tile->sock.net.send_src_port
  };
  static char const * udp_port_links[] = {
    "net_quic",   /* legacy_transaction_listen_port */
    "net_quic",   /* quic_transaction_listen_port */
    "net_shred",  /* shred_listen_port (turbine) */
    "net_gossvf", /* gossip_listen_port */
    "net_shred",  /* shred_listen_port (repair) */
    "net_repair", /* repair_serve_listen_port */
    "net_send"    /* send_src_port */
  };
  static uchar const udp_port_protos[] = {
    DST_PROTO_TPU_UDP,  /* legacy_transaction_listen_port */
    DST_PROTO_TPU_QUIC, /* quic_transaction_listen_port */
    DST_PROTO_SHRED,    /* shred_listen_port (turbine) */
    DST_PROTO_GOSSIP,   /* gossip_listen_port */
    DST_PROTO_REPAIR,   /* shred_listen_port (repair) */
    DST_PROTO_REPAIR,   /* repair_serve_listen_port */
    DST_PROTO_SEND      /* send_src_port */
  };
  for( uint candidate_idx=0U; candidate_idx<7; candidate_idx++ ) {
    if( !udp_port_candidates[ candidate_idx ] ) continue;
    uint sock_idx = ctx->sock_cnt;
    if( sock_idx>=FD_SOCK_TILE_MAX_SOCKETS ) FD_LOG_ERR(( "too many sockets" ));
    ushort port = (ushort)udp_port_candidates[ candidate_idx ];

    /* Validate value of REPAIR_SHRED_SOCKET_ID */
    if( tile->sock.net.repair_intake_listen_port &&
       udp_port_candidates[sock_idx]==tile->sock.net.repair_intake_listen_port )
      FD_TEST( sock_idx==REPAIR_SHRED_SOCKET_ID );
    if( tile->sock.net.repair_serve_listen_port &&
       udp_port_candidates[sock_idx]==tile->sock.net.repair_serve_listen_port )
      FD_TEST( sock_idx==REPAIR_SHRED_SOCKET_ID+1 );

    char const * target_link = udp_port_links[ candidate_idx ];
    ctx->link_rx_map[ sock_idx ] = 0xFF;
    for( ulong j=0UL; j<(tile->out_cnt); j++ ) {
      if( 0==strcmp( topo->links[ tile->out_link_id[ j ] ].name, target_link ) ) {
        ctx->proto_id    [ sock_idx ] = (uchar)udp_port_protos[ candidate_idx ];
        ctx->link_rx_map [ sock_idx ] = (uchar)j;
        ctx->rx_sock_port[ sock_idx ] = (ushort)port;
        break;
      }
    }
    if( ctx->link_rx_map[ sock_idx ]==0xFF ) {
      continue; /* listen port number has no associated links */
    }

    int sock_fd = sock_fd_min + (int)sock_idx;
    create_udp_socket( sock_fd, tile->sock.net.bind_address, port, tile->sock.so_rcvbuf );
    ctx->pollfd[ sock_idx ].fd     = sock_fd;
    ctx->pollfd[ sock_idx ].events = POLLIN;
    ctx->sock_cnt++;
  }

  /* Create transmit socket */

  int tx_sock = socket( AF_INET, SOCK_RAW|SOCK_CLOEXEC, FD_IP4_HDR_PROTOCOL_UDP );
  if( FD_UNLIKELY( tx_sock<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_RAW|SOCK_CLOEXEC,17) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=setsockopt( tx_sock, SOL_SOCKET, SO_SNDBUF, &tile->sock.so_sndbuf, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_SNDBUF,%i) failed (%i-%s)", tile->sock.so_sndbuf, errno, fd_io_strerror( errno ) ));
  }

  ctx->tx_sock      = tx_sock;
  ctx->bind_address = tile->sock.net.bind_address;

}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_sock_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->out_cnt > MAX_NET_OUTS ) ) {
    FD_LOG_ERR(( "sock tile has %lu out links which exceeds the max (%lu)", tile->out_cnt, MAX_NET_OUTS ));
  }

  for( ulong i=0UL; i<(tile->out_cnt); i++ ) {
    if( 0!=strncmp( topo->links[ tile->out_link_id[ i ] ].name, "net_", 4 ) ) {
      FD_LOG_ERR(( "out link %lu is not a net RX link", i ));
    }
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ i ] ];
    ctx->link_rx[ i ].base   = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->link_rx[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->link_rx[ i ].base, link->dcache );
    ctx->link_rx[ i ].wmark  = fd_dcache_compact_wmark(  ctx->link_rx[ i ].base, link->dcache, link->mtu );
    ctx->link_rx[ i ].chunk  = ctx->link_rx[ i ].chunk0;
    if( FD_UNLIKELY( link->burst < STEM_BURST ) ) {
      FD_LOG_ERR(( "link %lu dcache burst is too low (%lu<%lu)",
                   tile->out_link_id[ i ], link->burst, STEM_BURST ));
    }
  }

  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    if( !strstr( topo->links[ tile->in_link_id[ i ] ].name, "_net" ) ) {
      FD_LOG_ERR(( "in link %lu is not a net TX link", i ));
    }
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    ctx->link_tx[ i ].base   = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->link_tx[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->link_tx[ i ].base, link->dcache );
    ctx->link_tx[ i ].wmark  = fd_dcache_compact_wmark(  ctx->link_tx[ i ].base, link->dcache, link->mtu );
  }

}

/* RX PATH (socket->tango) ********************************************/

/* FIXME Pace RX polling and interleave it with TX jobs to reduce TX
         tail latency */

/* poll_rx_socket does one recvmmsg batch receive on the given socket
   index.  Returns the number of packets returned by recvmmsg. */

static ulong
poll_rx_socket( fd_sock_tile_t *    ctx,
                fd_stem_context_t * stem,
                uint                sock_idx,
                int                 sock_fd,
                ushort              proto ) {
  ulong  hdr_sz      = sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);
  ulong  payload_max = FD_NET_MTU-hdr_sz;
  uchar  rx_link     = ctx->link_rx_map[ sock_idx ];
  ushort dport       = ctx->rx_sock_port[ sock_idx ];

  fd_sock_link_rx_t * link = ctx->link_rx + rx_link;
  void * const base       = link->base;
  ulong  const chunk0     = link->chunk0;
  ulong  const wmark      = link->wmark;
  ulong        chunk_next = link->chunk;
  uchar *      cmsg_next  = ctx->batch_cmsg;

  for( ulong j=0UL; j<STEM_BURST; j++ ) {
    ctx->batch_iov[ j ].iov_base = (uchar *)fd_chunk_to_laddr( base, chunk_next ) + hdr_sz;
    ctx->batch_iov[ j ].iov_len  = payload_max;
    ctx->batch_msg[ j ].msg_hdr  = (struct msghdr) {
      .msg_iov        = ctx->batch_iov+j,
      .msg_iovlen     = 1,
      .msg_name       = ctx->batch_sa+j,
      .msg_namelen    = sizeof(struct sockaddr_in),
      .msg_control    = cmsg_next,
      .msg_controllen = FD_SOCK_CMSG_MAX,
    };
    cmsg_next += FD_SOCK_CMSG_MAX;
    /* Speculatively prepare all chunk indexes for a receive.
       At function exit, chunks into which a packet was received are
       committed, all others are freed. */
    chunk_next = fd_dcache_compact_next( chunk_next, FD_NET_MTU, chunk0, wmark );
  }

  int msg_cnt = recvmmsg( sock_fd, ctx->batch_msg, STEM_BURST, MSG_DONTWAIT, NULL );
  if( FD_UNLIKELY( msg_cnt<0 ) ) {
    if( FD_LIKELY( errno==EAGAIN ) ) return 0UL;
    /* unreachable if socket is in a valid state */
    FD_LOG_ERR(( "recvmmsg failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  long ts = fd_tickcount();
  ctx->metrics.sys_recvmmsg_cnt++;

  if( FD_UNLIKELY( msg_cnt==0 ) ) return 0UL;

  /* Track the chunk index of the last frag populated, so we can derive
     the chunk indexes for the next poll_rx_socket call.
     Guaranteed to be set since msg_cnt>0. */
  ulong last_chunk;

  for( ulong j=0; j<(ulong)msg_cnt; j++ ) {
    uchar * payload         = ctx->batch_iov[ j ].iov_base;
    ulong   payload_sz      = ctx->batch_msg[ j ].msg_len;
    struct sockaddr_in * sa = ctx->batch_msg[ j ].msg_hdr.msg_name;
    ulong frame_sz          = payload_sz + hdr_sz;
    ctx->metrics.rx_bytes_total += frame_sz;
    if( FD_UNLIKELY( sa->sin_family!=AF_INET ) ) {
      /* unreachable */
      FD_LOG_ERR(( "Received packet with unexpected sin_family %i", sa->sin_family ));
    }

    long daddr = -1;
    struct cmsghdr * cmsg = CMSG_FIRSTHDR( &ctx->batch_msg[ j ].msg_hdr );
    if( FD_LIKELY( cmsg ) ) {
      do {
        if( FD_LIKELY( (cmsg->cmsg_level==IPPROTO_IP) &
                       (cmsg->cmsg_type ==IP_PKTINFO) ) ) {
          struct in_pktinfo const * pi = (struct in_pktinfo const *)CMSG_DATA( cmsg );
          daddr = pi->ipi_addr.s_addr;
        }
        cmsg = CMSG_NXTHDR( &ctx->batch_msg[ j ].msg_hdr, cmsg );
      } while( FD_UNLIKELY( cmsg ) ); /* optimize for 1 cmsg */
    }
    if( FD_UNLIKELY( daddr<0L ) ) {
      /* unreachable because IP_PKTINFO was set */
      FD_LOG_ERR(( "Missing IP_PKTINFO on incoming packet" ));
    }

    fd_eth_hdr_t * eth_hdr    = (fd_eth_hdr_t *)( payload-42UL );
    fd_ip4_hdr_t * ip_hdr     = (fd_ip4_hdr_t *)( payload-28UL );
    fd_udp_hdr_t * udp_hdr    = (fd_udp_hdr_t *)( payload- 8UL );
    memset( eth_hdr->dst, 0, 6 );
    memset( eth_hdr->src, 0, 6 );
    eth_hdr->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );
    *ip_hdr = (fd_ip4_hdr_t) {
      .verihl      = FD_IP4_VERIHL( 4, 5 ),
      .net_tot_len = fd_ushort_bswap( (ushort)( payload_sz+28UL ) ),
      .ttl         = 1,
      .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
    };
    uint daddr_ = (uint)(ulong)daddr;
    memcpy( ip_hdr->saddr_c, &sa->sin_addr.s_addr, 4 );
    memcpy( ip_hdr->daddr_c, &daddr_,              4 );
    *udp_hdr = (fd_udp_hdr_t) {
      .net_sport = sa->sin_port,
      .net_dport = (ushort)fd_ushort_bswap( (ushort)dport ),
      .net_len   = (ushort)fd_ushort_bswap( (ushort)( payload_sz+8UL ) ),
      .check     = 0
    };

    ctx->metrics.rx_pkt_cnt++;
    ulong chunk = fd_laddr_to_chunk( base, eth_hdr );
    ulong sig   = fd_disco_netmux_sig( sa->sin_addr.s_addr, fd_ushort_bswap( sa->sin_port ), sa->sin_addr.s_addr, proto, hdr_sz );
    ulong tspub = fd_frag_meta_ts_comp( ts );

    /* default for repair intake is to send to [shreds] to shred tile.
       ping messages should be routed to the repair. */
    if( FD_UNLIKELY( sock_idx==REPAIR_SHRED_SOCKET_ID && frame_sz==REPAIR_PING_SZ ) ) {
      uchar repair_rx_link = ctx->link_rx_map[ REPAIR_SHRED_SOCKET_ID+1 ];
      fd_sock_link_rx_t * repair_link = ctx->link_rx + repair_rx_link;
      uchar * repair_buf = fd_chunk_to_laddr( repair_link->base, repair_link->chunk );
      memcpy( repair_buf, eth_hdr, frame_sz );
      fd_stem_publish( stem, repair_rx_link, sig, repair_link->chunk, frame_sz, 0UL, 0UL, tspub );
      repair_link->chunk = fd_dcache_compact_next( repair_link->chunk, FD_NET_MTU, repair_link->chunk0, repair_link->wmark );
    } else {
      fd_stem_publish( stem, rx_link, sig, chunk, frame_sz, 0UL, 0UL, tspub );
    }

    last_chunk = chunk;
  }

  /* Rewind the chunk index to the first free index. */
  link->chunk = fd_dcache_compact_next( last_chunk, FD_NET_MTU, chunk0, wmark );
  return (ulong)msg_cnt;
}

static ulong
poll_rx( fd_sock_tile_t *    ctx,
         fd_stem_context_t * stem ) {
  ulong pkt_cnt = 0UL;
  if( FD_UNLIKELY( ctx->batch_cnt ) ) {
    FD_LOG_ERR(( "Batch is not clean" ));
  }
  ctx->tx_idle_cnt = 0; /* restart TX polling */
  if( FD_UNLIKELY( fd_syscall_poll( ctx->pollfd, ctx->sock_cnt, 0 )<0 ) ) {
    FD_LOG_ERR(( "fd_syscall_poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  for( uint j=0UL; j<ctx->sock_cnt; j++ ) {
    if( ctx->pollfd[ j ].revents & (POLLIN|POLLERR) ) {
      pkt_cnt += poll_rx_socket(
        ctx,
        stem,
        j,
        ctx->pollfd[ j ].fd,
        ctx->proto_id[ j ]
      );
    }
    ctx->pollfd[ j ].revents = 0;
  }
  return pkt_cnt;
}

/* TX PATH (tango->socket) ********************************************/

static void
flush_tx_batch( fd_sock_tile_t * ctx ) {
  ulong batch_cnt = ctx->batch_cnt;
  for( int j = 0; j < (int)batch_cnt; /* incremented in loop */ ) {
    int remain   = (int)batch_cnt - j;
    int send_cnt = sendmmsg( ctx->tx_sock, ctx->batch_msg + j, (uint)remain, MSG_DONTWAIT );
    if( send_cnt>=0 ) {
      ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SOCK_ERR_V_NO_ERROR_IDX ]++;
    }
    if( FD_UNLIKELY( send_cnt < remain ) ) {
      ctx->metrics.tx_drop_cnt++;
      if( FD_UNLIKELY( send_cnt < 0 ) ) {
        switch( errno ) {
        case EAGAIN:
        case ENOBUFS:
          ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SOCK_ERR_V_SLOW_IDX ]++;
          break;
        case EPERM:
          ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SOCK_ERR_V_PERM_IDX ]++;
          break;
        case ENETUNREACH:
        case EHOSTUNREACH:
          ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SOCK_ERR_V_UNREACH_IDX ]++;
          break;
        case ENONET:
        case ENETDOWN:
        case EHOSTDOWN:
          ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SOCK_ERR_V_DOWN_IDX ]++;
          break;
        default:
          ctx->metrics.sys_sendmmsg_cnt[ FD_METRICS_ENUM_SOCK_ERR_V_OTHER_IDX ]++;
          /* log with NOTICE, since flushing has a significant negative performance impact */
          FD_LOG_NOTICE(( "sendmmsg failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }

        /* first message failed, so skip failing message and continue */
        j++;
      } else {
        /* send_cnt succeeded, so skip those and also the failing message */
        j += send_cnt + 1;

        /* add the successful count */
        ctx->metrics.tx_pkt_cnt += (ulong)send_cnt;
      }

      continue;
    }

    /* send_cnt == batch_cnt, so we sent everything */
    ctx->metrics.tx_pkt_cnt += (ulong)send_cnt;
    break;
  }

  ctx->tx_ptr = ctx->tx_scratch0;
  ctx->batch_cnt = 0;
}

/* before_frag is called when a new frag has been detected.  The sock
   tile can do early filtering here in the future.  For example, it may
   want to install routing logic here to take turns with an XDP tile.
   (Fast path with slow fallback) */

static inline int
before_frag( fd_sock_tile_t * ctx    FD_PARAM_UNUSED,
             ulong            in_idx FD_PARAM_UNUSED,
             ulong            seq    FD_PARAM_UNUSED,
             ulong            sig ) {
  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_OUTGOING ) ) return 1;
  return 0; /* continue */
}

/* during_frag is called when a new frag passed early filtering.
   Speculatively copies data into a sendmmsg buffer.  (If all tiles
   respect backpressure could eliminate this copy) */

static inline void
during_frag( fd_sock_tile_t * ctx,
             ulong            in_idx,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig,
             ulong            chunk,
             ulong            sz,
             ulong            ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->link_tx[ in_idx ].chunk0 || chunk>ctx->link_tx[ in_idx ].wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->link_tx[ in_idx ].chunk0, ctx->link_tx[ in_idx ].wmark ));
  }

  ulong const hdr_min = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( sz<hdr_min ) ) {
    /* FIXME support ICMP messages in the future? */
    FD_LOG_ERR(( "packet too small %lu (in_idx=%lu)", sz, in_idx ));
  }

  uchar const * frame   = fd_chunk_to_laddr_const( ctx->link_tx[ in_idx ].base, chunk );
  ulong         hdr_sz  = fd_disco_netmux_sig_hdr_sz( sig );
  uchar const * payload = frame+hdr_sz;
  if( FD_UNLIKELY( hdr_sz>sz || hdr_sz<hdr_min ) ) {
    FD_LOG_ERR(( "packet from in_idx=%lu corrupt: hdr_sz=%lu total_sz=%lu",
                 in_idx, hdr_sz, sz ));
  }
  ulong payload_sz = sz-hdr_sz;

  fd_ip4_hdr_t const * ip_hdr  = (fd_ip4_hdr_t const *)( frame  +sizeof(fd_eth_hdr_t) );
  fd_udp_hdr_t const * udp_hdr = (fd_udp_hdr_t const *)( payload-sizeof(fd_udp_hdr_t) );
  if( FD_UNLIKELY( ( FD_IP4_GET_VERSION( *ip_hdr )!=4 ) |
                   ( ip_hdr->protocol != FD_IP4_HDR_PROTOCOL_UDP ) ) ) {
    FD_LOG_ERR(( "packet from in_idx=%lu: sock tile only supports IPv4 UDP for now", in_idx ));
  }

  ulong msg_sz = sizeof(fd_udp_hdr_t) + payload_sz;

  ulong batch_idx = ctx->batch_cnt;
  assert( batch_idx<STEM_BURST );
  struct mmsghdr *     msg  = ctx->batch_msg + batch_idx;
  struct sockaddr_in * sa   = ctx->batch_sa  + batch_idx;
  struct iovec   *     iov  = ctx->batch_iov + batch_idx;
  struct cmsghdr *     cmsg = (void *)( (ulong)ctx->batch_cmsg + batch_idx*FD_SOCK_CMSG_MAX );
  uchar *              buf  = ctx->tx_ptr;

  *iov = (struct iovec) {
    .iov_base = buf,
    .iov_len  = msg_sz,
  };
  sa->sin_family      = AF_INET;
  sa->sin_addr.s_addr = FD_LOAD( uint, ip_hdr->daddr_c );
  sa->sin_port        = 0; /* ignored */

  cmsg->cmsg_level = IPPROTO_IP;
  cmsg->cmsg_type  = IP_PKTINFO;
  cmsg->cmsg_len   = CMSG_LEN( sizeof(struct in_pktinfo) );
  struct in_pktinfo * pi = (struct in_pktinfo *)CMSG_DATA( cmsg );
  pi->ipi_ifindex         = 0;
  pi->ipi_addr.s_addr     = 0;
  pi->ipi_spec_dst.s_addr = fd_uint_if( !!ip_hdr->saddr, ip_hdr->saddr, ctx->bind_address );

  *msg = (struct mmsghdr) {
    .msg_hdr = {
      .msg_name       = sa,
      .msg_namelen    = sizeof(struct sockaddr_in),
      .msg_iov        = iov,
      .msg_iovlen     = 1,
      .msg_control    = cmsg,
      .msg_controllen = CMSG_LEN( sizeof(struct in_pktinfo) )
    }
  };

  memcpy( buf, udp_hdr, sizeof(fd_udp_hdr_t) );
  fd_memcpy( buf+sizeof(fd_udp_hdr_t), payload, payload_sz );
  ctx->metrics.tx_bytes_total += sz;
}

/* after_frag is called when a frag was copied into a sendmmsg buffer. */

static void
after_frag( fd_sock_tile_t *    ctx,
            ulong               in_idx FD_PARAM_UNUSED,
            ulong               seq    FD_PARAM_UNUSED,
            ulong               sig    FD_PARAM_UNUSED,
            ulong               sz,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub  FD_PARAM_UNUSED,
            fd_stem_context_t * stem   FD_PARAM_UNUSED ) {
  /* Commit the packet added in during_frag */

  ctx->tx_idle_cnt = 0;
  ctx->batch_cnt++;
  /* Technically leaves a gap.  sz is always larger than the payload
     written to tx_ptr because Ethernet & IPv4 headers were stripped. */
  ctx->tx_ptr += fd_ulong_align_up( sz, FD_CHUNK_ALIGN );

  if( ctx->batch_cnt >= STEM_BURST ) {
    flush_tx_batch( ctx );
  }
}

/* End TX path ********************************************************/

/* after_credit is called every stem iteration when there are enough
   flow control credits to publish a burst of fragments. */

static inline void
after_credit( fd_sock_tile_t *    ctx,
              fd_stem_context_t * stem,
              int *               poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  if( ctx->tx_idle_cnt > 512 ) {
    if( ctx->batch_cnt ) {
      flush_tx_batch( ctx );
    }
    ulong pkt_cnt = poll_rx( ctx, stem );
    *charge_busy = pkt_cnt!=0;
  }
  ctx->tx_idle_cnt++;
}

static void
metrics_write( fd_sock_tile_t * ctx ) {
  FD_MCNT_SET( SOCK, SYSCALLS_RECVMMSG,       ctx->metrics.sys_recvmmsg_cnt     );
  FD_MCNT_ENUM_COPY( SOCK, SYSCALLS_SENDMMSG, ctx->metrics.sys_sendmmsg_cnt     );
  FD_MCNT_SET( SOCK, RX_PKT_CNT,              ctx->metrics.rx_pkt_cnt           );
  FD_MCNT_SET( SOCK, TX_PKT_CNT,              ctx->metrics.tx_pkt_cnt           );
  FD_MCNT_SET( SOCK, TX_DROP_CNT,             ctx->metrics.tx_drop_cnt          );
  FD_MCNT_SET( SOCK, TX_BYTES_TOTAL,          ctx->metrics.tx_bytes_total       );
  FD_MCNT_SET( SOCK, RX_BYTES_TOTAL,          ctx->metrics.rx_bytes_total       );
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  fd_sock_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  return RX_SOCK_FD_MIN + ctx->sock_cnt;
}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_sock_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_sock_tile_t)

#define STEM_LAZY ((long)10e6) /* 10ms */

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_sock = {
  .name                     = "sock",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
