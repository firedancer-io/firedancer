#define _GNU_SOURCE
/* The vhost tile implements a firedancer-dev-only vhost-user
   (virtio-user) network tile for zero-kernel-overhead container
   networking directly against a vhost-user backend such as VPP.

   On backend disconnect (e.g. VPP restart), the tile terminates via
   FD_LOG_ERR so the supervisor/orchestrator restarts the validator. */

#include "../fd_net_tile.h"
#include "../fd_net_tile_private.h"
#include "fd_vhost.h"
#include "../../topo/fd_topo.h"

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/rtnetlink.h>

#include "../../sleep/fd_sleep.h"
#include "../../../util/pod/fd_pod_format.h"
#define FD_SOCKADDR_IN_SZ   sizeof(struct sockaddr_in)
#define FD_VHOST_PEEK_FLAGS (MSG_PEEK|MSG_DONTWAIT)
#define FD_VHOST_EPOLL_SOCK (ULONG_MAX-1UL)
#include "generated/fd_vhost_tile_seccomp.h"

#define FD_VHOST_TX_FLUSH_TIMEOUT_NS      (  20000L)
#define FD_VHOST_LO_TX_TIMEOUT_NS         ( 500000L)
#define FD_VHOST_HOUSEKEEPING_INTERVAL_NS (1000000L)

struct __attribute__((aligned(64UL))) fd_vhost_tile {
  fd_vhost_t    vhost;
  char          socket_path[ PATH_MAX ];

  /* Free TX descriptor stack (supports out-of-order backend completions) */
  ushort        tx_free_ring[ FD_VHOST_QUEUE_DEPTH_MAX ];
  uint          tx_free_head;
  uint          tx_free_tail;
  ushort        tx_desc_frame_sz[ FD_VHOST_QUEUE_DEPTH_MAX ];
  ushort        tx_avail_published;
  long          tx_flush_timeout_ticks;
  long          tx_flush_deadline_ticks;

  /* Current spare RX chunk in net_umem dcache */
  ulong         rx_cur_chunk;

  /* Periodic control-socket liveness check */
  long          housekeeping_interval_ticks;
  long          housekeeping_deadline_ticks;

  /* Loopback TX raw socket (for local non-Firedancer UDP destinations) */
  long          lo_tx_timeout_ticks;
  long          lo_tx_deadline_ticks;
  int           lo_tx_sock;
  uint          lo_tx_cnt;

  /* Stem parking epoll fd (efficient mode; -1 when parking is disabled) */
  int           epoll_fd;

  fd_net_tile_t net;
  ulong         netdev_seq;

  struct mmsghdr     lo_tx_msg [ FD_VHOST_BATCH_SIZE ];
  struct iovec       lo_tx_iov [ FD_VHOST_BATCH_SIZE ];
  struct sockaddr_in lo_tx_addr[ FD_VHOST_BATCH_SIZE ];
  uchar              lo_tx_buf [ FD_VHOST_BATCH_SIZE ][ FD_NET_MTU ];

  struct {
    ulong tx_no_buffer_cnt;
    ulong tx_loopback_fail_cnt;
    ulong non_fd_pkt_cnt;
  } metrics;
};
typedef struct fd_vhost_tile fd_vhost_tile_t;

static inline uint
tx_free_cnt( fd_vhost_tile_t const * ctx ) {
  return ctx->tx_free_head - ctx->tx_free_tail;
}

static inline void
fd_vhost_tile_tx_flush( fd_vhost_tile_t * ctx ) {
  fd_vhost_vring_t * tx = &ctx->vhost.tx;
  if( FD_UNLIKELY( ctx->tx_avail_published==tx->avail_idx ) ) return;
  __atomic_store_n( &tx->avail->idx, tx->avail_idx, __ATOMIC_RELEASE );
  ctx->tx_avail_published = tx->avail_idx;
  fd_vhost_kick( tx );
}

static inline int
fd_vhost_tile_poll_tx( fd_vhost_tile_t * ctx ) {
  fd_vhost_vring_t * tx = &ctx->vhost.tx;
  ushort const used_idx = __atomic_load_n( &tx->used->idx, __ATOMIC_ACQUIRE );
  ushort       last     = tx->last_used_idx;
  if( last==used_idx ) return 0;

  uint const mask = tx->mask;
  ulong comp_cnt   = 0UL;
  ulong comp_bytes = 0UL;
  while( last!=used_idx ) {
    fd_vring_used_elem_t const elem = tx->used->ring[ last & mask ];
    uint const desc_idx = elem.id & mask;
    ctx->tx_free_ring[ ctx->tx_free_head & mask ] = (ushort)desc_idx;
    ctx->tx_free_head++;
    comp_bytes += ctx->tx_desc_frame_sz[ desc_idx ];
    comp_cnt++;
    last++;
  }
  tx->last_used_idx = last;
  ctx->net.metrics.tx_pkt_cnt     += comp_cnt;
  ctx->net.metrics.tx_bytes_total += comp_bytes;
  return 1;
}

static inline int
fd_vhost_tile_poll_rx( fd_vhost_tile_t *   ctx,
                       fd_stem_context_t * stem ) {
  fd_vhost_vring_t * rx = &ctx->vhost.rx;
  ushort const used_idx = __atomic_load_n( &rx->used->idx, __ATOMIC_ACQUIRE );
  ushort       last     = rx->last_used_idx;
  if( last==used_idx ) return 0;

  uint const  mask   = rx->mask;
  ulong const hdr_sz = ctx->vhost.virtio_hdr_sz;
  ulong const tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

  uint cnt = 0U;
  while( last!=used_idx && cnt<FD_VHOST_BATCH_SIZE ) {
    fd_vring_used_elem_t const elem = rx->used->ring[ last & mask ];
    uint const  desc_idx  = elem.id & mask;
    ulong const total_len = elem.len;

    if( FD_LIKELY( total_len>hdr_sz && total_len-hdr_sz<=FD_NET_MTU ) ) {
      ulong const frame_sz = total_len - hdr_sz;
      uchar const * src    = fd_vhost_buf_ptr( rx, desc_idx ) + hdr_sz;
      uchar *       dst    = fd_chunk_to_laddr( ctx->net.pkt_buf_wksp_base, ctx->rx_cur_chunk );
      fd_memcpy( dst, src, frame_sz );

      ulong freed_chunk = ctx->rx_cur_chunk;
      fd_net_rx_pkt( &ctx->net, stem, ctx->rx_cur_chunk, 0UL, frame_sz, tspub, &freed_chunk, &ctx->metrics.non_fd_pkt_cnt );
      if( FD_UNLIKELY( 0UL==freed_chunk ) ) FD_LOG_CRIT(( "invalid RX chunk in mcache" ));
      ctx->rx_cur_chunk = freed_chunk;
    } else {
      ctx->net.metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    }

    /* Immediately recycle RX descriptor back to avail ring */
    rx->desc[ desc_idx ].len = (uint)FD_VHOST_BUF_STRIDE;
    rx->avail->ring[ rx->avail_idx & mask ] = (ushort)desc_idx;
    rx->avail_idx++;
    last++;
    cnt++;
  }

  rx->last_used_idx = last;
  __atomic_store_n( &rx->avail->idx, rx->avail_idx, __ATOMIC_RELEASE );
  fd_vhost_kick( rx );
  return 1;
}

static void
fd_vhost_tile_lo_tx_flush( fd_vhost_tile_t * ctx ) {
  if( FD_UNLIKELY( 0U==ctx->lo_tx_cnt ) ) return;
  int const  send_cnt = sendmmsg( ctx->lo_tx_sock, ctx->lo_tx_msg, ctx->lo_tx_cnt, MSG_DONTWAIT );
  uint const sent_cnt = -1==send_cnt ? 0U : (uint)send_cnt;
  for( uint i=0U; i<sent_cnt; i++ ) ctx->net.metrics.tx_bytes_total += sizeof(fd_eth_hdr_t)+ctx->lo_tx_iov[ i ].iov_len;
  ctx->net.metrics.tx_pkt_cnt       += sent_cnt;
  ctx->metrics.tx_loopback_fail_cnt += ctx->lo_tx_cnt - sent_cnt;
  ctx->lo_tx_cnt = 0U;
}

static void
fd_vhost_tile_lo_tx_enqueue( fd_vhost_tile_t *    ctx,
                             fd_ip4_hdr_t const * ip4,
                             ulong                ip_sz ) {
  uint const           batch_idx = ctx->lo_tx_cnt;
  struct mmsghdr *     msg       = ctx->lo_tx_msg  + batch_idx;
  struct sockaddr_in * sa        = ctx->lo_tx_addr + batch_idx;
  struct iovec *       iov       = ctx->lo_tx_iov  + batch_idx;
  uchar *              buf       = ctx->lo_tx_buf[ batch_idx ];

  *iov = (struct iovec) {
    .iov_base = buf,
    .iov_len  = ip_sz,
  };
  sa->sin_family      = AF_INET;
  sa->sin_addr.s_addr = ip4->daddr;
  sa->sin_port        = 0;

  *msg = (struct mmsghdr) {
    .msg_hdr = {
      .msg_name    = sa,
      .msg_namelen = sizeof(struct sockaddr_in),
      .msg_iov     = iov,
      .msg_iovlen  = 1UL
    }
  };

  fd_memcpy( buf, ip4, ip_sz );
  ctx->lo_tx_cnt++;
  if( ctx->lo_tx_cnt==FD_VHOST_BATCH_SIZE ) fd_vhost_tile_lo_tx_flush( ctx );
  else if( ctx->lo_tx_cnt==1U ) ctx->lo_tx_deadline_ticks = fd_tickcount()+ctx->lo_tx_timeout_ticks;
}

static inline void
before_credit( fd_vhost_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  fd_net_router_solicit( &ctx->net.router, stem );
  long now = fd_tickcount();
  if( 0U!=ctx->lo_tx_cnt && now>=ctx->lo_tx_deadline_ticks ) {
    fd_vhost_tile_lo_tx_flush( ctx );
    *charge_busy = 1;
  }
  if( ctx->tx_avail_published!=ctx->vhost.tx.avail_idx && now>=ctx->tx_flush_deadline_ticks ) {
    fd_vhost_tile_tx_flush( ctx );
    *charge_busy = 1;
  }
  *charge_busy |= fd_vhost_tile_poll_tx( ctx );
}

static inline void
after_credit( fd_vhost_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;
  *charge_busy |= fd_vhost_tile_poll_rx( ctx, stem );
}

static inline int
prevent_park( fd_vhost_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->tx_avail_published!=ctx->vhost.tx.avail_idx ) ) fd_vhost_tile_tx_flush( ctx );
  if( FD_UNLIKELY( ctx->lo_tx_cnt ) ) fd_vhost_tile_lo_tx_flush( ctx );

  /* Unmask backend->frontend RX call interrupts with full ordering, then
     re-check rx->used->idx to avoid a lost-wakeup race. */
  fd_vhost_vring_t * rx = &ctx->vhost.rx;
  __atomic_store_n( &rx->avail->flags, 0U, __ATOMIC_SEQ_CST );
  ushort const used_idx = __atomic_load_n( &rx->used->idx, __ATOMIC_ACQUIRE );
  if( FD_UNLIKELY( used_idx!=rx->last_used_idx ) ) {
    __atomic_store_n( &rx->avail->flags, FD_VHOST_VRING_AVAIL_F_NO_INTR, __ATOMIC_RELEASE );
    return 1;
  }
  return 0;
}

static inline int
park_wait( fd_vhost_tile_t * ctx,
           ulong *           word,
           long              deadline,
           double            tick_per_ns ) {
  struct epoll_event evs[ 3 ];
  int ev_cnt;
  int cause = fd_sleep_park_wait_epoll( ctx->epoll_fd, word, evs, 3, &ev_cnt, deadline, tick_per_ns );

  /* Re-mask RX interrupts immediately upon wakeup for zero-syscall polling */
  __atomic_store_n( &ctx->vhost.rx.avail->flags, FD_VHOST_VRING_AVAIL_F_NO_INTR, __ATOMIC_RELEASE );

  for( int i=0; i<ev_cnt; i++ ) {
    if( evs[ i ].data.u64==(ulong)ctx->vhost.rx.call_fd ) {
      ulong val;
      (void)read( ctx->vhost.rx.call_fd, &val, sizeof(val) );
    } else if( evs[ i ].data.u64==FD_VHOST_EPOLL_SOCK ) {
      if( FD_UNLIKELY( !fd_vhost_is_connected( &ctx->vhost ) ) ) {
        FD_LOG_ERR(( "vhost-user socket `%s` disconnected (VPP restarted?)", ctx->socket_path ));
      }
    }
  }
  return cause;
}

static inline int
before_frag( fd_vhost_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)seq;
  if( FD_UNLIKELY( ctx->net.in_kind[ in_idx ]==FD_NET_IN_KIND_IPROUTE ) ) return 0;

  if( !fd_net_tx_select( &ctx->net, sig ) ) return 1;

  fd_net_tx_route_t const * route = &ctx->net.tx_route;
  if( FD_UNLIKELY( !route->use_loopback && 0U==tx_free_cnt( ctx ) ) ) {
    fd_vhost_tile_poll_tx( ctx );
    if( FD_UNLIKELY( 0U==tx_free_cnt( ctx ) ) ) {
      ctx->metrics.tx_no_buffer_cnt++;
      return 1;
    }
  }

  fd_net_tx_route_result_increment( &ctx->net );
  return 0;
}

static inline void
during_frag( fd_vhost_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             frame_sz,
             ulong             ctl ) {
  (void)seq; (void)sig; (void)ctl;
  fd_net_in_frag_validate( &ctx->net, in_idx, chunk, frame_sz );

  if( FD_UNLIKELY( fd_net_iproute_msg_stage( &ctx->net, in_idx, chunk, frame_sz ) ) ) return;

  fd_vhost_vring_t const * tx = &ctx->vhost.tx;
  uint const desc_idx = ctx->tx_free_ring[ ctx->tx_free_tail & tx->mask ];
  uchar *    dst      = fd_vhost_buf_ptr( tx, desc_idx ) + ctx->vhost.virtio_hdr_sz;
  fd_net_tx_pkt_cpy( &ctx->net, dst, chunk, frame_sz, in_idx );
}

static void
after_frag( fd_vhost_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               frame_sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)tsorig; (void)tspub;

  if( FD_UNLIKELY( ctx->net.in_kind[ in_idx ]==FD_NET_IN_KIND_IPROUTE ) ) {
    fd_iproute_msg_t const * msg = &ctx->net.iproute_msg;
    if( msg->op==FD_IPROUTE_OP_FLUSH ) {
      fd_fib4_clear( ctx->net.router.fib_local );
      fd_fib4_clear( ctx->net.router.fib_main );
      return;
    }

    fd_fib4_t * fib;
    if( msg->table_id==RT_TABLE_LOCAL )     fib = ctx->net.router.fib_local;
    else if( msg->table_id==RT_TABLE_MAIN ) fib = ctx->net.router.fib_main;
    else return;

    if( msg->op==FD_IPROUTE_OP_UPSERT && FD_UNLIKELY( !fd_fib4_insert( fib, msg->dst_addr, msg->prefix, msg->prio, &msg->hop ) ) ) {
      FD_LOG_WARNING(( "route update dropped: route table full (increase [tiles.netlink].max_routes or [tiles.netlink].max_peer_routes)" ));
      fd_stem_publish( stem, ctx->net.router.netlnk_out_idx, FD_NETLINK_ROUTE4_SYNC_SIG, 0UL, 0UL, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    } else if( msg->op==FD_IPROUTE_OP_DELETE ) {
      fd_fib4_remove( fib, msg->dst_addr, msg->prefix, msg->prio );
    }
    return;
  }

  fd_vhost_vring_t * tx = &ctx->vhost.tx;
  uint const  desc_idx = ctx->tx_free_ring[ ctx->tx_free_tail & tx->mask ];
  ulong const hdr_sz   = ctx->vhost.virtio_hdr_sz;
  uchar *     buf      = fd_vhost_buf_ptr( tx, desc_idx );
  uchar *     frame    = buf + hdr_sz;

  if( FD_UNLIKELY( !fd_net_tx_pkt_prep( &ctx->net, frame, &frame_sz, in_idx ) ) ) return;

  if( FD_UNLIKELY( ctx->net.tx_route.routing_failure ) ) {
    if( FD_LIKELY( fd_net_tx_sock_send( &ctx->net, frame, frame_sz ) ) ) {
      ctx->net.metrics.tx_pkt_cnt++;
      ctx->net.metrics.tx_bytes_total += frame_sz;
      ctx->net.metrics.tx_gre_cnt     += (ulong)ctx->net.tx_route.use_gre;
    }
    return;
  }

  if( FD_UNLIKELY( ctx->net.tx_route.use_loopback ) ) {
    fd_eth_hdr_t const * eth_hdr   = (fd_eth_hdr_t const *)frame;
    fd_ip4_hdr_t const * ip4       = (fd_ip4_hdr_t const *)(eth_hdr+1);
    ulong const          ip_hdr_sz = FD_IP4_GET_LEN( *ip4 );
    ulong const          ip_sz     = fd_ushort_bswap( ip4->net_tot_len );
    if( FD_UNLIKELY( ip4->protocol!=FD_IP4_HDR_PROTOCOL_UDP ||
                     ip4->daddr!=fd_disco_netmux_sig_ip( sig ) ||
                     (fd_ushort_bswap( ip4->net_frag_off ) & ~FD_IP4_HDR_FRAG_OFF_DF) ||
                     ip_sz<ip_hdr_sz+sizeof(fd_udp_hdr_t) ||
                     ip_sz>frame_sz-sizeof(fd_eth_hdr_t) ) ) {
      ctx->net.metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_INVALID_IDX ]++;
      return;
    }
    fd_udp_hdr_t const * udp    = (fd_udp_hdr_t const *)((uchar const *)ip4+ip_hdr_sz);
    ulong const          udp_sz = fd_ushort_bswap( udp->net_len );
    if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) || udp_sz>ip_sz-ip_hdr_sz ) ) {
      ctx->net.metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_INVALID_IDX ]++;
      return;
    }

    int owns_udp_dst = 0;
    if( !ctx->net.bind_address || ctx->net.bind_address==ip4->daddr ) {
      ushort const dst_port = fd_ushort_bswap( udp->net_dport );
      for( ulong i=0UL; i<ctx->net.rx_proto_cnt; i++ ) owns_udp_dst |= ctx->net.rx_listen_ports[ i ]==dst_port;
    }
    if( !owns_udp_dst ) {
      fd_vhost_tile_lo_tx_enqueue( ctx, ip4, ip_sz );
      return;
    }

    uchar * dst = fd_chunk_to_laddr( ctx->net.pkt_buf_wksp_base, ctx->rx_cur_chunk );
    fd_memcpy( dst, frame, frame_sz );
    ulong freed_chunk = ctx->rx_cur_chunk;
    if( fd_net_rx_pkt( &ctx->net, stem, ctx->rx_cur_chunk, 0UL, frame_sz, (ulong)fd_frag_meta_ts_comp( fd_tickcount() ), &freed_chunk, NULL ) ) {
      ctx->rx_cur_chunk = freed_chunk;
    }
    ctx->net.metrics.tx_pkt_cnt++;
    ctx->net.metrics.tx_bytes_total += frame_sz;
    return;
  }

  /* Submit to TX split virtqueue */
  ctx->tx_free_tail++;
  fd_memset( buf, 0, hdr_sz );
  tx->desc[ desc_idx ].len   = (uint)(hdr_sz + frame_sz);
  tx->desc[ desc_idx ].flags = 0U;
  tx->desc[ desc_idx ].next  = 0U;
  ctx->tx_desc_frame_sz[ desc_idx ] = (ushort)frame_sz;

  tx->avail->ring[ tx->avail_idx & tx->mask ] = (ushort)desc_idx;
  tx->avail_idx++;
  ctx->net.metrics.tx_gre_cnt += (ulong)ctx->net.tx_route.use_gre;

  ushort const pending = (ushort)(tx->avail_idx - ctx->tx_avail_published);
  if( pending>=FD_VHOST_BATCH_SIZE || 0U==tx_free_cnt( ctx ) ) {
    fd_vhost_tile_tx_flush( ctx );
  } else if( pending==1U ) {
    ctx->tx_flush_deadline_ticks = fd_tickcount() + ctx->tx_flush_timeout_ticks;
  }
}

static inline void
metrics_write( fd_vhost_tile_t * ctx ) {
  fd_vhost_vring_t const * rx = &ctx->vhost.rx;
  fd_vhost_vring_t const * tx = &ctx->vhost.tx;
  ulong const rx_used_now = (ushort)(__atomic_load_n( &rx->used->idx, __ATOMIC_RELAXED ) - rx->last_used_idx);
  ulong const rx_free_now = rx->depth > rx_used_now ? rx->depth - rx_used_now : 0UL;
  ulong const tx_free_now = tx_free_cnt( ctx );
  ulong const tx_used_now = tx->depth - tx_free_now;

  FD_MCNT_SET(   VHOST, PKT_RX,                 ctx->net.metrics.rx_pkt_cnt           );
  FD_MCNT_SET(   VHOST, PKT_RX_BYTES,           ctx->net.metrics.rx_bytes_total       );
  FD_MCNT_ENUM_COPY( VHOST, PKT_RX_DROPPED,     ctx->net.metrics.rx_drop_cnt          );
  FD_MCNT_SET(   VHOST, NON_FD_PKT_RX,          ctx->metrics.non_fd_pkt_cnt           );
  FD_MCNT_SET(   VHOST, GRE_PKT_RX,             ctx->net.metrics.rx_gre_cnt           );
  FD_MCNT_SET(   VHOST, VLAN_PKT_RX,            ctx->net.metrics.rx_vlan_cnt          );
  FD_MGAUGE_SET( VHOST, RX_BUFFER_USED,         rx_used_now                           );
  FD_MGAUGE_SET( VHOST, RX_BUFFER_FREE,         rx_free_now                           );

  FD_MCNT_SET(   VHOST, PKT_TX_COMPLETED,       ctx->net.metrics.tx_pkt_cnt           );
  FD_MCNT_SET(   VHOST, PKT_TX_COMPLETED_BYTES, ctx->net.metrics.tx_bytes_total       );
  ctx->net.metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_RING_FULL_IDX ] = ctx->metrics.tx_no_buffer_cnt;
  FD_MCNT_ENUM_COPY( VHOST, PKT_TX_DROPPED,          ctx->net.metrics.tx_drop_cnt             );
  FD_MCNT_ENUM_COPY( VHOST, PKT_TX_ROUTED,           ctx->net.metrics.tx_route_result_cnt     );
  FD_MCNT_ENUM_COPY( VHOST, PKT_TX_SLOW_PATH_ROUTED, ctx->net.metrics.tx_slow_path_reason_cnt );
  FD_MCNT_SET(   VHOST, PKT_TX_LOOPBACK_FAILED,      ctx->metrics.tx_loopback_fail_cnt        );
  FD_MCNT_SET(   VHOST, GRE_PKT_TX_SUBMITTED,        ctx->net.metrics.tx_gre_cnt              );
  FD_MCNT_SET(   VHOST, PKT_TX_SLOW_PATH_SUBMITTED,  ctx->net.metrics.tx_slow_path_submit_cnt );
  FD_MGAUGE_SET( VHOST, TX_BUFFER_USED,         tx_used_now                           );
  FD_MGAUGE_SET( VHOST, TX_BUFFER_FREE,         tx_free_now                           );
}

static inline void
during_housekeeping( fd_vhost_tile_t * ctx ) {
  long const now = fd_tickcount();
  if( FD_UNLIKELY( now>=ctx->housekeeping_deadline_ticks ) ) {
    ctx->housekeeping_deadline_ticks = now + ctx->housekeeping_interval_ticks;
    if( FD_UNLIKELY( !fd_vhost_is_connected( &ctx->vhost ) ) ) {
      FD_LOG_ERR(( "vhost-user socket `%s` disconnected (VPP restarted?)", ctx->socket_path ));
    }
  }

  if( FD_UNLIKELY( fd_netdev_tbl_refresh( &ctx->net.router.netdev_tbl, &ctx->net.router.netdev_shared, &ctx->netdev_seq ) ) ) {
    fd_net_gre_tunnels_refresh( &ctx->net, &ctx->net.router.netdev_tbl );
  }
}

static uint
fd_vhost_tile_if_ip4_addr( char const * if_name ) {
  int sock_fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( -1==sock_fd ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct ifreq ifr = { .ifr_addr.sa_family = AF_INET };
  fd_cstr_ncpy( ifr.ifr_name, if_name, sizeof(ifr.ifr_name) );

  if( FD_UNLIKELY( -1==ioctl( sock_fd, SIOCGIFADDR, &ifr ) ) ) {
    FD_LOG_ERR(( "could not get IP address of interface `%s` (%i-%s)",
                 if_name, errno, fd_io_strerror( errno ) ));
  }
  uint ip4_addr = ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;
  if( FD_UNLIKELY( -1==close( sock_fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return ip4_addr;
}

static int
fd_vhost_tile_lo_tx_socket( void ) {
  int sock = socket( AF_INET, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_RAW );
  if( FD_UNLIKELY( -1==sock ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_RAW,IPPROTO_RAW) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", sizeof("lo") ) ) ) {
    FD_LOG_ERR(( "setsockopt(SO_BINDTODEVICE,lo) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return sock;
}

static ulong
scratch_align( void ) {
  return FD_VHOST_PAGE_SZ;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong layout = FD_LAYOUT_INIT;
  layout = FD_LAYOUT_APPEND( layout, alignof(fd_vhost_tile_t), sizeof(fd_vhost_tile_t) );
  layout = FD_LAYOUT_APPEND( layout, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(),       fd_fib4_footprint( tile->vhost.route_max, tile->vhost.route_peer_max ) );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(),       fd_fib4_footprint( tile->vhost.route_max, tile->vhost.route_peer_max ) );
  return FD_LAYOUT_FINI( layout, scratch_align() );
}

fd_fib4_t *
fd_vhost_tile_fib4_join( fd_fib4_t *            out,
                         fd_topo_t const *      topo,
                         fd_topo_tile_t const * tile,
                         int                    main_table ) {
  FD_SCRATCH_ALLOC_INIT( scratch, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_vhost_tile_t), sizeof(fd_vhost_tile_t) );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * local_mem = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(), fd_fib4_footprint( tile->vhost.route_max, tile->vhost.route_peer_max ) );
  void * main_mem  = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(), fd_fib4_footprint( tile->vhost.route_max, tile->vhost.route_peer_max ) );
  return fd_fib4_join( out, main_table ? main_mem : local_mem );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  fd_vhost_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(*ctx) );
  fd_cstr_ncpy( ctx->socket_path, tile->vhost.socket_path, sizeof(ctx->socket_path) );

  /* Connect to vhost-user backend (VPP) before entering sandbox */
  if( FD_UNLIKELY( 0!=fd_vhost_connect( &ctx->vhost,
                                        ctx->socket_path,
                                        tile->vhost.rx_queue_size,
                                        tile->vhost.tx_queue_size ) ) ) {
    FD_LOG_ERR(( "fd_vhost_connect(`%s`) failed (%i-%s)",
                 ctx->socket_path, errno, fd_io_strerror( errno ) ));
  }
  FD_LOG_NOTICE(( "vhost-user connected to `%s` (rx=%u tx=%u features=0x%lx hdr=%luB)",
                  ctx->socket_path, tile->vhost.rx_queue_size, tile->vhost.tx_queue_size,
                  ctx->vhost.features, ctx->vhost.virtio_hdr_sz ));

  /* Initialize free TX descriptor stack */
  for( uint i=0U; i<tile->vhost.tx_queue_size; i++ ) {
    ctx->tx_free_ring[ i ] = (ushort)i;
  }
  ctx->tx_free_head       = tile->vhost.tx_queue_size;
  ctx->tx_free_tail       = 0U;
  ctx->tx_avail_published = 0U;

  /* Routing interface and default source IP */
  uint const interface_idx = if_nametoindex( tile->vhost.if_name );
  if( FD_UNLIKELY( 0U==interface_idx ) ) {
    FD_LOG_ERR(( "interface `%s` lookup failed (%i-%s)",
                 tile->vhost.if_name, errno, fd_io_strerror( errno ) ));
  }
  ctx->net.router.if_virt         = interface_idx;
  ctx->net.router.default_address = fd_vhost_tile_if_ip4_addr( tile->vhost.if_name );

  /* Loopback TX raw socket and fallback routing socket */
  ctx->lo_tx_sock = fd_vhost_tile_lo_tx_socket();
  if( FD_UNLIKELY( !fd_net_sock_init( &ctx->net.sock ) ) ) {
    FD_LOG_ERR(( "fd_net_sock_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Set up epoll for stem parking in efficient mode */
  ctx->epoll_fd = -1;
  if( FD_UNLIKELY( tile->sleep_eventfd ) ) {
    ctx->epoll_fd = epoll_create1( EPOLL_CLOEXEC );
    if( FD_UNLIKELY( ctx->epoll_fd<0 ) ) {
      FD_LOG_ERR(( "epoll_create1() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    struct epoll_event doorbell_ev = { .events = EPOLLIN|EPOLLET, .data.u64 = FD_SLEEP_EPOLL_DOORBELL };
    if( FD_UNLIKELY( -1==epoll_ctl( ctx->epoll_fd, EPOLL_CTL_ADD, FD_SLEEP_EVENTFD( tile->id ), &doorbell_ev ) ) ) {
      FD_LOG_ERR(( "epoll_ctl(ADD,sleep_eventfd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    struct epoll_event call_ev = { .events = EPOLLIN, .data.u64 = (ulong)ctx->vhost.rx.call_fd };
    if( FD_UNLIKELY( -1==epoll_ctl( ctx->epoll_fd, EPOLL_CTL_ADD, ctx->vhost.rx.call_fd, &call_ev ) ) ) {
      FD_LOG_ERR(( "epoll_ctl(ADD,rx_call_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    struct epoll_event sock_ev = { .events = EPOLLRDHUP|EPOLLHUP|EPOLLERR, .data.u64 = FD_VHOST_EPOLL_SOCK };
    if( FD_UNLIKELY( -1==epoll_ctl( ctx->epoll_fd, EPOLL_CTL_ADD, ctx->vhost.sock_fd, &sock_ev ) ) ) {
      FD_LOG_ERR(( "epoll_ctl(ADD,vhost_sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_vhost_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( scratch, ctx );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_vhost_tile_t), sizeof(fd_vhost_tile_t) );
  void * netdev_tbl_local = FD_SCRATCH_ALLOC_APPEND( scratch, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * fib_local_mem    = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(),       fd_fib4_footprint( tile->vhost.route_max, tile->vhost.route_peer_max ) );
  void * fib_main_mem     = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(),       fd_fib4_footprint( tile->vhost.route_max, tile->vhost.route_peer_max ) );

  ctx->tx_flush_timeout_ticks      = (long)(FD_VHOST_TX_FLUSH_TIMEOUT_NS      * fd_tempo_tick_per_ns( NULL ));
  ctx->lo_tx_timeout_ticks         = (long)(FD_VHOST_LO_TX_TIMEOUT_NS         * fd_tempo_tick_per_ns( NULL ));
  ctx->housekeeping_interval_ticks = (long)(FD_VHOST_HOUSEKEEPING_INTERVAL_NS * fd_tempo_tick_per_ns( NULL ));
  ctx->housekeeping_deadline_ticks = fd_tickcount() + ctx->housekeeping_interval_ticks;
  ctx->lo_tx_cnt                   = 0U;
  ctx->net.kind_id                 = tile->kind_id;
  ctx->net.tile_cnt                = fd_topo_tile_name_cnt( topo, tile->name );

  /* Join packet buffer dcache and initialize output mcache chunks */
  void * const packet_dcache_memory = fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id );
  void * const packet_dcache        = fd_dcache_join( packet_dcache_memory );
  FD_TEST( NULL!=packet_dcache );
  ulong const packet_dcache_data_sz = fd_dcache_data_sz( packet_dcache );
  ulong const frame_sz              = FD_NET_MTU;
  ulong const frame_region_sz       = fd_ulong_align_dn( packet_dcache_data_sz, frame_sz );
  void * const workspace_base       = fd_wksp_containing( packet_dcache_memory );
  FD_TEST( NULL!=workspace_base );

  ulong const pkt_buf_chunk0 = ((ulong)packet_dcache - (ulong)workspace_base) >> FD_CHUNK_LG_SZ;
  ulong const pkt_buf_wmark  = pkt_buf_chunk0 + ((frame_region_sz - frame_sz) >> FD_CHUNK_LG_SZ);
  ctx->net.pkt_buf_wksp_base = workspace_base;
  ctx->net.pkt_buf_chunk0    = pkt_buf_chunk0;
  ctx->net.pkt_buf_wmark     = pkt_buf_wmark;

  ulong const frame_chunks = FD_NET_MTU >> FD_CHUNK_LG_SZ;
  ulong       next_chunk   = pkt_buf_chunk0;
  ctx->rx_cur_chunk = next_chunk;
  next_chunk += frame_chunks;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( 0==strcmp( link->name, "net_netlnk" ) ) continue;
    fd_frag_meta_t * mcache = fd_mcache_join( fd_topo_obj_laddr( topo, link->mcache_obj_id ) );
    FD_TEST( NULL!=mcache );
    ulong depth = fd_mcache_depth( mcache );
    for( ulong j=0UL; j<depth; j++ ) {
      mcache[ j ].chunk = (uint)next_chunk;
      mcache[ j ].seq   = fd_seq_dec( j, 1UL );
      next_chunk += frame_chunks;
    }
  }
  if( FD_UNLIKELY( next_chunk-frame_chunks>pkt_buf_wmark ) ) {
    FD_LOG_ERR(( "vhost packet dcache too small" ));
  }

  fd_net_rx_protos_init( &ctx->net, topo, tile );

  /* Input links and buffer bounds */
  if( FD_UNLIKELY( tile->in_cnt>FD_NET_IN_MAX ) ) {
    FD_LOG_ERR(( "vhost tile in link count %lu exceeds max of %lu", tile->in_cnt, FD_NET_IN_MAX ));
  }
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "iproute_out" ) ) {
      ctx->net.in_kind[ i ] = FD_NET_IN_KIND_IPROUTE;
    } else {
      ctx->net.in_kind[ i ] = FD_NET_IN_KIND_TX;
      if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) {
        FD_LOG_ERR(( "vhost tile in link %s MTU %lu, expected %lu", link->name, link->mtu, (ulong)FD_NET_MTU ));
      }
    }
    ctx->net.in_dcache_ctx[ i ].wksp_base = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->net.in_dcache_ctx[ i ].chunk0    = fd_dcache_compact_chunk0( ctx->net.in_dcache_ctx[ i ].wksp_base, link->dcache );
    ctx->net.in_dcache_ctx[ i ].wmark     = fd_dcache_compact_wmark(  ctx->net.in_dcache_ctx[ i ].wksp_base, link->dcache, link->mtu );
  }

  /* Join fib4 tables */
  FD_TEST( NULL!=fd_fib4_join( ctx->net.router.fib_local, fd_fib4_new( fib_local_mem, tile->vhost.route_max, tile->vhost.route_peer_max, tile->vhost.route_peer_seed ) ) );
  FD_TEST( NULL!=fd_fib4_join( ctx->net.router.fib_main,  fd_fib4_new( fib_main_mem,  tile->vhost.route_max, tile->vhost.route_peer_max, tile->vhost.route_peer_seed ) ) );

  /* Join shared and local netdev tables */
  FD_TEST( NULL!=fd_netdev_tbl_join( &ctx->net.router.netdev_shared, fd_topo_obj_laddr( topo, tile->vhost.netdev_tbl_obj_id ) ) );
  FD_TEST( NULL!=fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( NULL!=fd_netdev_tbl_join( &ctx->net.router.netdev_tbl, netdev_tbl_local ) );
  ctx->netdev_seq = fd_netdev_tbl_copy( &ctx->net.router.netdev_tbl, &ctx->net.router.netdev_shared );
  fd_net_gre_tunnels_refresh( &ctx->net, &ctx->net.router.netdev_tbl );
  ctx->net.bind_address = tile->vhost.net.bind_address;

  /* Join shared neighbor table */
  ulong neigh4_obj_id = tile->vhost.neigh4_obj_id;
  ulong ele_max       = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong probe_max     = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong seed          = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  if( FD_UNLIKELY( (ele_max==ULONG_MAX) | (probe_max==ULONG_MAX) | (seed==ULONG_MAX) ) ) {
    FD_LOG_ERR(( "neigh4 hmap properties not set" ));
  }
  if( FD_UNLIKELY( NULL==fd_neigh4_hmap_join( ctx->net.router.neigh4, fd_topo_obj_laddr( topo, neigh4_obj_id ), ele_max, probe_max, seed ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  /* Netlink requests for missing neighbors */
  ctx->net.router.netlnk_out_idx = fd_topo_find_tile_out_link( topo, tile, "net_netlnk", tile->kind_id );
  if( FD_UNLIKELY( ctx->net.router.netlnk_out_idx==ULONG_MAX ) ) FD_LOG_ERR(( "netlink request link not found" ));
  ctx->net.router.solicit_ip = 0U;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( scratch, scratch_align() );
  if( FD_UNLIKELY( scratch_top>(ulong)ctx+scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow" ));
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_vhost_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_vhost_tile( out_cnt, out,
                                             (uint)fd_log_private_logfile_fd(),
                                             (uint)ctx->lo_tx_sock,
                                             (uint)ctx->net.sock.sock,
                                             (uint)ctx->vhost.sock_fd,
                                             (uint)ctx->vhost.rx.kick_fd,
                                             (uint)ctx->vhost.tx.kick_fd,
                                             (uint)ctx->vhost.rx.call_fd,
                                             (uint)ctx->epoll_fd );
  return sock_filter_policy_fd_vhost_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_vhost_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<10UL ) ) FD_LOG_ERR(( "allowed FD array capacity %lu too small", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2;
  if( fd_log_private_logfile_fd()!=-1 ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  out_fds[ out_cnt++ ] = ctx->net.sock.sock;
  out_fds[ out_cnt++ ] = ctx->vhost.sock_fd;
  out_fds[ out_cnt++ ] = ctx->vhost.rx.kick_fd;
  out_fds[ out_cnt++ ] = ctx->vhost.rx.call_fd;
  out_fds[ out_cnt++ ] = ctx->vhost.tx.kick_fd;
  if( ctx->lo_tx_sock>=0 ) out_fds[ out_cnt++ ] = ctx->lo_tx_sock;
  if( FD_UNLIKELY( tile->sleep_eventfd ) ) {
    out_fds[ out_cnt++ ] = ctx->epoll_fd;
    out_fds[ out_cnt++ ] = FD_SLEEP_EVENTFD( tile->id );
  }
  return out_cnt;
}

#define STEM_CALLBACK_CONTEXT_TYPE        fd_vhost_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_vhost_tile_t)
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_PREVENT_PARK        prevent_park
#define STEM_CALLBACK_PARK_WAIT           park_wait
#define STEM_BURST                        (FD_VHOST_BATCH_SIZE+1UL)
#define STEM_LAZY                         270000UL
#include "../../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_vhost = {
  .name                     = "vhost",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
