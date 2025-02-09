/* The net tile translates between AF_XDP and fd_tango
   traffic.  It is responsible for setting up the XDP and
   XSK socket configuration.

   ### Why does this tile bind to loopback?

   The Linux kernel routes outgoing packets addressed to IP addresses
   owned by the system via loopback.  (See `ip route show table local`)
   The net tile partially matches this behavior.  For better performance
   and simplicity, a second XDP socket is used.

   Sending such traffic out through the real network interface to the
   router might result in connectivity issues.

   There are two reasons to send packets to our own public IP address:

   * For testing and development.
   * The Agave code sends local traffic to itself to
     as part of routine operation (eg, when it's the leader
     it sends votes to its own TPU socket).

   So for now we need to also bind to loopback. This is a
   small performance hit for other traffic, but we only
   redirect packets destined for our target IP and port so
   it will not otherwise interfere. Loopback only supports
   XDP in SKB mode. */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h> /* MSG_DONTWAIT needed before importing the net seccomp filter */
#include <linux/if_xdp.h>

#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/netlink/fd_netlink_tile.h" /* neigh4_solicit */
#include "../../../../disco/topo/fd_topo.h"

#include "../../../../waltz/ip/fd_fib4.h"
#include "../../../../waltz/neigh/fd_neigh4_map.h"
#include "../../../../waltz/xdp/fd_xdp_redirect_user.h" /* fd_xsk_activate */
#include "../../../../waltz/xdp/fd_xsk_private.h"
#include "../../../../util/log/fd_dtrace.h"

#include <unistd.h>
#include <linux/unistd.h>

#include "generated/net_seccomp.h"

/* MAX_NET_INS controls the max number of TX links that a net tile can
   serve. */

#define MAX_NET_INS (32UL)

/* FD_XDP_STATS_INTERVAL_NS controls the XDP stats refresh interval.
   This should be lower than the interval at which the metrics tile
   collects metrics. */

#define FD_XDP_STATS_INTERVAL_NS (11e6) /* 11ms */

/* fd_net_in_ctx_t contains consumer information for an incoming tango
   link.  It is used as part of the TX path. */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_net_in_ctx_t;

/* fd_net_out_ctx_t contains publisher information for a link to a
   downstream app tile.  It is used as part of the RX path. */

typedef struct {
  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;
  ulong            seq;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_net_out_ctx_t;

/* fd_net_flusher_t controls the pacing of XDP sendto calls for flushing
   TX batches.  In the 'wakeup' XDP mode, no TX occurs unless the net
   tile wakes up the kernel periodically using the sendto() syscall.
   If sendto() is called too frequently, time is wasted on context
   switches.  If sendto() is called not often enough, packets are
   delayed or dropped.  sendto() calls make almost no guarantees how
   much packets are sent out, nor do they indicate when the kernel
   finishes a wakeup call (asynchronously dispatched).  The net tile
   thus uses a myraid of flush triggers that were tested for best
   performance. */

struct fd_net_flusher {

  /* Packets that were enqueued after the last sendto() wakeup are
     considered "pending".  If there are more than pending_wmark packets
     pending, a wakeup is dispatched.  Thus, this dispatch trigger is
     proportional to packet rate, but does not trigger if I/O is seldom. */
  ulong pending_cnt;
  ulong pending_wmark;

  /* Sometimes, packets are not flushed out even after a sendto()
     wakeup.  This can result in the tail of a burst getting delayed or
     overrun.  If more than tail_flush_backoff ticks pass since the last
     sendto() wakeup and there are still unacknowledged packets in the
     TX ring, issues another wakeup. */
  long next_tail_flush_ticks;
  long tail_flush_backoff;

};

typedef struct fd_net_flusher fd_net_flusher_t;

FD_PROTOTYPES_BEGIN

/* fd_net_flusher_inc marks a new packet as enqueued. */

static inline void
fd_net_flusher_inc( fd_net_flusher_t * flusher,
                    long               now ) {
  flusher->pending_cnt++;
  long next_flush = now + flusher->tail_flush_backoff;
  flusher->next_tail_flush_ticks = fd_long_min( flusher->next_tail_flush_ticks, next_flush );
}

/* fd_net_flusher_check returns 1 if a sendto() wakeup should be issued
   immediately.  now is a recent fd_tickcount() value.
   If tx_ring_empty==0 then the kernel is caught up with the net tile
   on the XDP TX ring.  (Otherwise, the kernel is behind the net tile) */

static inline int
fd_net_flusher_check( fd_net_flusher_t * flusher,
                      long               now,
                      int                tx_ring_empty ) {
  int flush_level   = flusher->pending_cnt >= flusher->pending_wmark;
  int flush_timeout = now >= flusher->next_tail_flush_ticks;
  int flush         = flush_level || flush_timeout;
  if( !flush ) return 0;
  if( FD_UNLIKELY( tx_ring_empty ) ) {
    /* Flush requested but caught up */
    flusher->pending_cnt           = 0UL;
    flusher->next_tail_flush_ticks = LONG_MAX;
    return 0;
  }
  return 1;
}

/* fd_net_flusher_wakeup signals a sendto() wakeup was done.  now is a
   recent fd_tickcount() value. */

static inline void
fd_net_flusher_wakeup( fd_net_flusher_t * flusher,
                       long               now ) {
  flusher->pending_cnt           = 0UL;
  flusher->next_tail_flush_ticks = now + flusher->tail_flush_backoff;
}

FD_PROTOTYPES_END

/* fd_net_free_ring is a FIFO queue that stores pointers to free XDP TX
   frames. */

struct fd_net_free_ring {
  ulong   prod;
  ulong   cons;
  ulong   depth;
  ulong * queue;
};
typedef struct fd_net_free_ring fd_net_free_ring_t;

typedef struct {
  /* An "XSK" is an AF_XDP socket */
  uint       xsk_cnt;
  fd_xsk_t * xsk[ 2 ];
  int        prog_link_fds[ 2 ];

  /* All net tiles are subscribed to the same TX links.  (These are
     incoming links from app tiles asking the net tile to send out packets)
     The net tiles "take turns" doing TX jobs based on the L3+L4 dst hash.
     net_tile_id is the index of the current interface, net_tile_cnt is the
     total amount of interfaces. */
  uint net_tile_id;
  uint net_tile_cnt;

  /* Details pertaining to an inflight send op */
  struct {
    uint   if_idx; /* 0: main interface, 1: loopback */
    void * frame;
    uchar  mac_addrs[12]; /* First 12 bytes of Ethernet header */
  } tx_op;

  /* Round-robin cycle serivce operations */
  uint rr_idx;

  /* Rings tracking free packet buffers */
  fd_net_free_ring_t free_tx[ 2 ];

  uint   src_ip_addr;
  uchar  src_mac_addr[6];

  ushort shred_listen_port;
  ushort quic_transaction_listen_port;
  ushort legacy_transaction_listen_port;
  ushort gossip_listen_port;
  ushort repair_intake_listen_port;
  ushort repair_serve_listen_port;

  ulong in_cnt;
  fd_net_in_ctx_t in[ MAX_NET_INS ];

  fd_net_out_ctx_t quic_out[1];
  fd_net_out_ctx_t shred_out[1];
  fd_net_out_ctx_t gossip_out[1];
  fd_net_out_ctx_t repair_out[1];

  /* XDP stats refresh timer */
  long xdp_stats_interval_ticks;
  long next_xdp_stats_refresh;

  /* TX flush timers */
  fd_net_flusher_t tx_flusher[2]; /* one per XSK */

  /* Route and neighbor tables */
  fd_fib4_t const * fib_local;
  fd_fib4_t const * fib_main;
  fd_neigh4_hmap_t  neigh4[1];
  fd_netlink_neigh4_solicit_link_t neigh4_solicit[1];

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong rx_undersz_cnt;
    ulong rx_fill_blocked_cnt;
    ulong rx_backp_cnt;

    ulong tx_submit_cnt;
    ulong tx_complete_cnt;
    ulong tx_bytes_total;
    ulong tx_route_fail_cnt;
    ulong tx_no_xdp_cnt;
    ulong tx_neigh_fail_cnt;

    ulong xsk_tx_wakeup_cnt;
    ulong xsk_rx_wakeup_cnt;
  } metrics;
} fd_net_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  /* TODO reproducing this conditional memory layout twice is susceptible to bugs. Use more robust object discovery */
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_xsk_align(),        fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),        tile->net.xdp_tx_queue_size * sizeof(ulong) );
  if( FD_UNLIKELY( strcmp( tile->net.interface, "lo" ) && tile->kind_id == 0 ) ) {
    l = FD_LAYOUT_APPEND( l, fd_xsk_align(),      fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) );
    l = FD_LAYOUT_APPEND( l, alignof(ulong),      tile->net.xdp_tx_queue_size * sizeof(ulong) );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_net_ctx_t * ctx ) {
  FD_MCNT_SET( NET, RX_PKT_CNT,          ctx->metrics.rx_pkt_cnt          );
  FD_MCNT_SET( NET, RX_BYTES_TOTAL,      ctx->metrics.rx_bytes_total      );
  FD_MCNT_SET( NET, RX_UNDERSZ_CNT,      ctx->metrics.rx_undersz_cnt      );
  FD_MCNT_SET( NET, RX_FILL_BLOCKED_CNT, ctx->metrics.rx_fill_blocked_cnt );
  FD_MCNT_SET( NET, RX_BACKPRESSURE_CNT, ctx->metrics.rx_backp_cnt        );

  FD_MCNT_SET( NET, TX_SUBMIT_CNT,        ctx->metrics.tx_submit_cnt     );
  FD_MCNT_SET( NET, TX_COMPLETE_CNT,      ctx->metrics.tx_complete_cnt   );
  FD_MCNT_SET( NET, TX_BYTES_TOTAL,       ctx->metrics.tx_bytes_total    );
  FD_MCNT_SET( NET, TX_ROUTE_FAIL_CNT,    ctx->metrics.tx_route_fail_cnt );
  FD_MCNT_SET( NET, TX_NEIGHBOR_FAIL_CNT, ctx->metrics.tx_neigh_fail_cnt );

  FD_MCNT_SET( NET, XSK_TX_WAKEUP_CNT,    ctx->metrics.xsk_tx_wakeup_cnt    );
  FD_MCNT_SET( NET, XSK_RX_WAKEUP_CNT,    ctx->metrics.xsk_rx_wakeup_cnt    );
}

struct xdp_statistics_v0 {
  __u64 rx_dropped; /* Dropped for other reasons */
  __u64 rx_invalid_descs; /* Dropped due to invalid descriptor */
  __u64 tx_invalid_descs; /* Dropped due to invalid descriptor */
};

struct xdp_statistics_v1 {
  __u64 rx_dropped; /* Dropped for other reasons */
  __u64 rx_invalid_descs; /* Dropped due to invalid descriptor */
  __u64 tx_invalid_descs; /* Dropped due to invalid descriptor */
  __u64 rx_ring_full; /* Dropped due to rx ring being full */
  __u64 rx_fill_ring_empty_descs; /* Failed to retrieve item from fill ring */
  __u64 tx_ring_empty_descs; /* Failed to retrieve item from tx ring */
};

static void
poll_xdp_statistics( fd_net_ctx_t * ctx ) {
  struct xdp_statistics_v1 stats = {0};
  ulong xsk_cnt = ctx->xsk_cnt;
  for( ulong j=0UL; j<xsk_cnt; j++ ) {
    struct xdp_statistics_v1 sub_stats;
    uint optlen = (uint)sizeof(struct xdp_statistics_v1);
    if( FD_UNLIKELY( -1==getsockopt( ctx->xsk[ j ]->xsk_fd, SOL_XDP, XDP_STATISTICS, &sub_stats, &optlen ) ) )
      FD_LOG_ERR(( "getsockopt(SOL_XDP, XDP_STATISTICS) failed: %s", strerror( errno ) ));
    if( FD_UNLIKELY( optlen!=sizeof(struct xdp_statistics_v0) &&
                     optlen!=sizeof(struct xdp_statistics_v1) ) ) {
      FD_LOG_ERR(( "getsockopt(SOL_XDP, XDP_STATISTICS) returned unexpected size %u", optlen ));
    }
    stats.rx_dropped               += sub_stats.rx_dropped;
    stats.rx_invalid_descs         += sub_stats.rx_invalid_descs;
    stats.tx_invalid_descs         += sub_stats.tx_invalid_descs;
    stats.rx_ring_full             += sub_stats.rx_ring_full;
    stats.rx_fill_ring_empty_descs += sub_stats.rx_fill_ring_empty_descs;
    stats.tx_ring_empty_descs      += sub_stats.tx_ring_empty_descs;
  }

  FD_MCNT_SET( NET, XDP_RX_DROPPED_OTHER,         stats.rx_dropped               );
  FD_MCNT_SET( NET, XDP_RX_INVALID_DESCS,         stats.rx_invalid_descs         );
  FD_MCNT_SET( NET, XDP_TX_INVALID_DESCS,         stats.tx_invalid_descs         );
  FD_MCNT_SET( NET, XDP_RX_RING_FULL,             stats.rx_ring_full             );
  FD_MCNT_SET( NET, XDP_RX_FILL_RING_EMPTY_DESCS, stats.rx_fill_ring_empty_descs );
  FD_MCNT_SET( NET, XDP_TX_RING_EMPTY_DESCS,      stats.tx_ring_empty_descs      );
}

/* net_is_fatal_xdp_error returns 1 if the given errno returned by an
   XDP API indicates a non-recoverable error code.  The net tile should
   crash if it sees such an error so the problem does not go undetected.
   Otherwise, returns 0. */

static int
net_is_fatal_xdp_error( int err ) {
  return err==ESOCKTNOSUPPORT || err==EOPNOTSUPP || err==EINVAL ||
         err==EPERM;
}

/* net_tx_ready returns 1 if the current XSK is ready to submit a TX send
   job.  If the XSK is blocked for sends, returns 0.  Reasons for block
   include:
   - No XSK TX buffer is available
   - XSK TX ring is full */

static int
net_tx_ready( fd_net_ctx_t * ctx,
              uint           if_idx ) {
  fd_xsk_t *           xsk     = ctx->xsk[ if_idx ];
  fd_ring_desc_t *     tx_ring = &xsk->ring_tx;
  fd_net_free_ring_t * free    = ctx->free_tx + if_idx;
  if( free->prod == free->cons ) return 0; /* drop */
  if( tx_ring->prod - tx_ring->cons >= tx_ring->depth ) return 0; /* drop */
  return 1;
}

/* net_rx_wakeup triggers xsk_recvmsg to run in the kernel.  Needs to be
   called periodically in order to receive packets. */

static void
net_rx_wakeup( fd_net_ctx_t * ctx,
               fd_xsk_t *     xsk ) {
  if( !fd_xsk_rx_need_wakeup( xsk ) ) return;
  struct msghdr _ignored[ 1 ] = { 0 };
  if( FD_UNLIKELY( -1==recvmsg( xsk->xsk_fd, _ignored, MSG_DONTWAIT ) ) ) {
    if( FD_UNLIKELY( net_is_fatal_xdp_error( errno ) ) ) {
      FD_LOG_ERR(( "xsk recvmsg failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( errno!=EAGAIN ) ) {
      long ts = fd_log_wallclock();
      if( ts > xsk->log_suppress_until_ns ) {
        FD_LOG_WARNING(( "xsk recvmsg failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
        xsk->log_suppress_until_ns = ts + (long)1e9;
      }
    }
  }
  ctx->metrics.xsk_rx_wakeup_cnt++;
}

/* net_tx_wakeup triggers xsk_sendmsg to run in the kernel.  Needs to be
   called periodically in order to transmit packets. */

static void
net_tx_wakeup( fd_net_ctx_t * ctx,
               fd_xsk_t *     xsk ) {
  if( !fd_xsk_tx_need_wakeup( xsk ) ) return;
  if( FD_VOLATILE_CONST( *xsk->ring_tx.prod )==FD_VOLATILE_CONST( *xsk->ring_tx.cons ) ) return;
  if( FD_UNLIKELY( -1==sendto( xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0 ) ) ) {
    if( FD_UNLIKELY( net_is_fatal_xdp_error( errno ) ) ) {
      FD_LOG_ERR(( "xsk sendto failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( errno!=EAGAIN ) ) {
      long ts = fd_log_wallclock();
      if( ts > xsk->log_suppress_until_ns ) {
        FD_LOG_WARNING(( "xsk sendto failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
        xsk->log_suppress_until_ns = ts + (long)1e9;
      }
    }
  }
  ctx->metrics.xsk_tx_wakeup_cnt++;
}

/* net_tx_periodic_wakeup does a timer based xsk_sendmsg wakeup. */

static inline void
net_tx_periodic_wakeup( fd_net_ctx_t * ctx,
                        uint           if_idx,
                        long           now ) {
  uint tx_prod = FD_VOLATILE_CONST( *ctx->xsk[ if_idx ]->ring_tx.prod );
  uint tx_cons = FD_VOLATILE_CONST( *ctx->xsk[ if_idx ]->ring_tx.cons );
  int tx_ring_empty = tx_prod==tx_cons;
  if( fd_net_flusher_check( ctx->tx_flusher+if_idx, now, tx_ring_empty ) ) {
    net_tx_wakeup( ctx, ctx->xsk[ if_idx ] );
    fd_net_flusher_wakeup( ctx->tx_flusher+if_idx, now );
  }
}

static void
during_housekeeping( fd_net_ctx_t * ctx ) {
  long now = fd_tickcount();

  if( now > ctx->next_xdp_stats_refresh ) {
    ctx->next_xdp_stats_refresh = now + ctx->xdp_stats_interval_ticks;
    poll_xdp_statistics( ctx );
  }

  for( uint j=0U; j<ctx->xsk_cnt; j++ ) {
    net_rx_wakeup( ctx, ctx->xsk[ j ] );
  }
}

/* net_tx_route resolves the destination interface index, src MAC address,
   and dst MAC address.  Returns 1 on success, 0 on failure.  On success,
   tx_op->{if_idx,mac_addrs} is set. */

static int
net_tx_route( fd_net_ctx_t * ctx,
              uint           dst_ip ) {

  /* Route lookup */

  fd_fib4_hop_t hop[2] = {0};
  fd_fib4_lookup( ctx->fib_local, hop+0, dst_ip, 0UL );
  fd_fib4_lookup( ctx->fib_main,  hop+1, dst_ip, 0UL );
  fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );

  uint rtype  = next_hop->rtype;
  uint if_idx = next_hop->if_idx;

  if( FD_UNLIKELY( rtype==FD_FIB4_RTYPE_LOCAL ) ) {
    rtype  = FD_FIB4_RTYPE_UNICAST;
    if_idx = 1;
  }

  if( FD_UNLIKELY( rtype!=FD_FIB4_RTYPE_UNICAST ) ) {
    ctx->metrics.tx_route_fail_cnt++;
    return 0;
  }

  if( if_idx==1 ) {
    /* Set Ethernet src and dst address to 00:00:00:00:00:00 */
    memset( ctx->tx_op.mac_addrs, 0, 12UL );
    ctx->tx_op.if_idx = 1;
    return 1;
  }

  if( FD_UNLIKELY( if_idx!=ctx->xsk[ 0 ]->if_idx ) ) {
    ctx->metrics.tx_no_xdp_cnt++;
    return 0;
  }
  ctx->tx_op.if_idx = 0;

  /* Neighbor resolve */

  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_hmap_query_t neigh_query[1];
  int neigh_res = fd_neigh4_hmap_query_try( ctx->neigh4, &neigh_ip, NULL, neigh_query, 0 );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) {
    /* Neighbor not found */
    fd_netlink_neigh4_solicit( ctx->neigh4_solicit, neigh_ip, if_idx, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }
  fd_neigh4_entry_t const * neigh = fd_neigh4_hmap_query_ele_const( neigh_query );
  if( FD_UNLIKELY( neigh->state != FD_NEIGH4_STATE_ACTIVE ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }

  memcpy( ctx->tx_op.mac_addrs+0, neigh->mac_addr,   6 );
  memcpy( ctx->tx_op.mac_addrs+6, ctx->src_mac_addr, 6 );

  if( FD_UNLIKELY( fd_neigh4_hmap_query_test( neigh_query ) ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }

  return 1;
}

/* before_frag is called when a new metadata descriptor for a TX job is
   found.  This callback determines whether this net tile is responsible
   for the TX job.  If so, it prepares the TX op for the during_frag and
   after_frag callbacks. */

static inline int
before_frag( fd_net_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig ) {
  (void)in_idx; (void)seq;

  /* Find interface index of next packet */

  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_OUTGOING ) ) return 1;

  uint dst_ip = fd_disco_netmux_sig_dst_ip( sig );
  if( FD_UNLIKELY( !net_tx_route( ctx, dst_ip ) ) ) return 1;

  uint net_tile_id  = ctx->net_tile_id;
  uint net_tile_cnt = ctx->net_tile_cnt;
  uint if_idx       = ctx->tx_op.if_idx;
  if( FD_UNLIKELY( if_idx>ctx->xsk_cnt ) ) return 1; /* ignore */

  /* Load balance TX */

  uint hash       = (uint)fd_disco_netmux_sig_hash( sig );
  uint target_idx = hash % net_tile_cnt;
  if( if_idx==1 ) target_idx = 0; /* loopback always targets tile 0 */

  /* Skip if another net tile is responsible for this packet */

  if( net_tile_id!=target_idx ) return 1; /* ignore */

  /* Skip if TX is blocked */

  if( FD_UNLIKELY( !net_tx_ready( ctx, if_idx ) ) ) return 1;

  /* Allocate buffer for receive */

  fd_net_free_ring_t * free      = ctx->free_tx + if_idx;
  ulong                alloc_seq = free->cons;
  void *               frame     = (void *)free->queue[ alloc_seq % free->depth ];
  free->cons = fd_seq_inc( alloc_seq, 1UL );

  ctx->tx_op.if_idx    = if_idx;
  ctx->tx_op.frame     = frame;

  return 0; /* continue */
}

/* during_frag is called when before_frag has committed to transmit an
   outgoing packet. */

static inline void
during_frag( fd_net_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig,
             ulong          chunk,
             ulong          sz ) {
  (void)in_idx; (void)seq; (void)sig;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  if( FD_UNLIKELY( sz<14UL ) )
    FD_LOG_ERR(( "packet too small %lu (in_idx=%lu)", sz, in_idx ));

  fd_xsk_t * xsk = ctx->xsk[ ctx->tx_op.if_idx ];

  void * frame = ctx->tx_op.frame;
  if( FD_UNLIKELY( (ulong)frame+sz > (ulong)xsk->umem.addr + xsk->umem.len ) )
    FD_LOG_ERR(( "frame %p out of bounds (beyond %p)", frame, (void *)( (ulong)xsk->umem.addr + xsk->umem.len ) ));
  if( FD_UNLIKELY( (ulong)frame < (ulong)xsk->umem.addr ) )
    FD_LOG_ERR(( "frame %p out of bounds (below %p)", frame, (void *)xsk->umem.addr ));

  /* Speculatively copy frame into XDP buffer */
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
  fd_memcpy( ctx->tx_op.frame, src, sz );
}

/* after_frag is called when the during_frag memcpy was _not_ overrun. */

static void
after_frag( fd_net_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)tsorig; (void)stem;

  /* Current send operation */

  uint       if_idx = ctx->tx_op.if_idx;
  uchar *    frame  = ctx->tx_op.frame;
  fd_xsk_t * xsk    = ctx->xsk[ if_idx ];

  memcpy( frame, ctx->tx_op.mac_addrs, 12 );

  /* Submit packet TX job

     Invariant for ring_tx: prod-cons<length
     (This invariant breaks if any other packet is sent over this ring
     between before_frag and this point, e.g. send_arp_probe.) */

  fd_ring_desc_t * tx_ring = &xsk->ring_tx;
  uint             tx_seq  = FD_VOLATILE_CONST( *tx_ring->prod );
  uint             tx_mask = tx_ring->depth - 1U;
  xsk->ring_tx.packet_ring[ tx_seq&tx_mask ] = (struct xdp_desc) {
    .addr    = (ulong)frame - (ulong)xsk->umem.addr,
    .len     = (uint)sz,
    .options = 0
  };

  /* Frame is now owned by kernel. Clear tx_op. */
  ctx->tx_op.frame = NULL;

  /* Register newly enqueued packet */
  FD_VOLATILE( *xsk->ring_tx.prod ) = tx_ring->cached_prod = tx_seq+1U;
  ctx->metrics.tx_submit_cnt++;
  ctx->metrics.tx_bytes_total += sz;
  fd_net_flusher_inc( ctx->tx_flusher+if_idx, fd_tickcount() );

}

/* net_rx_packet is called when a new Ethernet frame is available.
   Attempts to copy out the frame to a downstream tile. */

static void
net_rx_packet( fd_net_ctx_t *      ctx,
               fd_stem_context_t * stem,
               uchar const *       packet,
               ulong               sz ) {

  uchar const * packet_end = packet + sz;
  uchar const * iphdr      = packet + 14U;

  /* Filter for UDP/IPv4 packets. Test for ethtype and ipproto in 1
      branch */
  uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
  if( FD_UNLIKELY( test_ethip!=0x080011 ) )
    FD_LOG_ERR(( "Firedancer received a packet from the XDP program that was either "
                  "not an IPv4 packet, or not a UDP packet. It is likely your XDP program "
                  "is not configured correctly." ));

  /* IPv4 is variable-length, so lookup IHL to find start of UDP */
  uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
  uchar const * udp = iphdr + iplen;

  /* Ignore if UDP header is too short */
  if( FD_UNLIKELY( udp+8U > packet_end ) ) {
    FD_DTRACE_PROBE( net_tile_err_rx_undersz );
    ctx->metrics.rx_undersz_cnt++;
    return;
  }

  /* Extract IP dest addr and UDP src/dest port */
  uint ip_srcaddr    =                  *(uint   *)( iphdr+12UL );
  ushort udp_srcport = fd_ushort_bswap( *(ushort *)( udp+0UL    ) );
  ushort udp_dstport = fd_ushort_bswap( *(ushort *)( udp+2UL    ) );

  FD_DTRACE_PROBE_4( net_tile_pkt_rx, ip_srcaddr, udp_srcport, udp_dstport, sz );

  ushort proto;
  fd_net_out_ctx_t * out;
  if(      FD_UNLIKELY( udp_dstport==ctx->shred_listen_port ) ) {
    proto = DST_PROTO_SHRED;
    out = ctx->shred_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->quic_transaction_listen_port ) ) {
    proto = DST_PROTO_TPU_QUIC;
    out = ctx->quic_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->legacy_transaction_listen_port ) ) {
    proto = DST_PROTO_TPU_UDP;
    out = ctx->quic_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->gossip_listen_port ) ) {
    proto = DST_PROTO_GOSSIP;
    out = ctx->gossip_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->repair_intake_listen_port ) ) {
    proto = DST_PROTO_REPAIR;
    out = ctx->repair_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->repair_serve_listen_port ) ) {
    proto = DST_PROTO_REPAIR;
    out = ctx->repair_out;
  } else {

    FD_LOG_ERR(( "Firedancer received a UDP packet on port %hu which was not expected. "
                  "Only the following ports should be configured to forward packets: "
                  "%hu, %hu, %hu, %hu, %hu, %hu (excluding any 0 ports, which can be ignored)."
                  "Please report this error to Firedancer maintainers.",
                  udp_dstport,
                  ctx->shred_listen_port,
                  ctx->quic_transaction_listen_port,
                  ctx->legacy_transaction_listen_port,
                  ctx->gossip_listen_port,
                  ctx->repair_intake_listen_port,
                  ctx->repair_serve_listen_port ));
  }

  fd_memcpy( fd_chunk_to_laddr( out->mem, out->chunk ), packet, sz );

  /* tile can decide how to partition based on src ip addr and src port */
  ulong sig = fd_disco_netmux_sig( ip_srcaddr, udp_srcport, 0U, proto, 14UL+8UL+iplen );

  ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( out->mcache, out->depth, out->seq, sig, out->chunk, sz, 0, 0, tspub );

  *stem->cr_avail -= stem->cr_decrement_amount;

  out->seq = fd_seq_inc( out->seq, 1UL );
  out->chunk = fd_dcache_compact_next( out->chunk, FD_NET_MTU, out->chunk0, out->wmark );

  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += sz;

}

/* net_comp_event is called when an XDP TX frame is free again. */

static void
net_comp_event( fd_net_ctx_t * ctx,
                fd_xsk_t *     xsk,
                uint           xsk_idx,
                uint           comp_seq ) {

  /* Locate the incoming frame */

  fd_ring_desc_t * comp_ring  = &xsk->ring_cr;
  uint             comp_mask  = comp_ring->depth - 1U;
  ulong            frame      = FD_VOLATILE_CONST( comp_ring->frame_ring[ comp_seq&comp_mask ] );
  ulong const      frame_mask = FD_NET_MTU - 1UL;
  if( FD_UNLIKELY( frame+FD_NET_MTU > xsk->umem.len ) ) {
    FD_LOG_ERR(( "Bounds check failed: frame=0x%lx umem.len=0x%lx",
                 frame, (ulong)xsk->umem.len ));
  }

  /* Check if we have space to return the freed frame */

  fd_net_free_ring_t * free      = ctx->free_tx + xsk_idx;
  ulong                free_prod = free->prod;
  ulong                free_mask = free->depth - 1UL;
  long free_cnt = fd_seq_diff( free_prod, free->cons );
  if( FD_UNLIKELY( free_cnt>=(long)free->depth ) ) return; /* blocked */

  free->queue[ free_prod&free_mask ] = xsk->umem.addr + (frame & (~frame_mask));
  free->prod = fd_seq_inc( free_prod, 1UL );

  /* Wind up for next iteration */

  FD_VOLATILE( *comp_ring->cons ) = comp_ring->cached_cons = comp_seq+1U;

  ctx->metrics.tx_complete_cnt++;

}

/* net_rx_event is called when a new XDP RX frame is available.  Calls
   net_rx_packet, then returns the packet back to the kernel via the fill
   ring.  */

static void
net_rx_event( fd_net_ctx_t *      ctx,
              fd_stem_context_t * stem,
              fd_xsk_t *          xsk,
              uint                rx_seq ) {

  if( FD_UNLIKELY( *stem->cr_avail < stem->cr_decrement_amount ) ) {
    ctx->metrics.rx_backp_cnt++;
    return;
  }

  /* Locate the incoming frame */

  fd_ring_desc_t * rx_ring = &xsk->ring_rx;
  uint             rx_mask = rx_ring->depth - 1U;
  struct xdp_desc  frame   = FD_VOLATILE_CONST( rx_ring->packet_ring[ rx_seq&rx_mask ] );

  if( FD_UNLIKELY( frame.len>FD_NET_MTU ) )
    FD_LOG_ERR(( "received a UDP packet with a too large payload (%u)", frame.len ));

  /* Check if we have space in the fill ring to free the frame */

  fd_ring_desc_t * fill_ring  = &xsk->ring_fr;
  uint             fill_depth = fill_ring->depth;
  uint             fill_mask  = fill_depth-1U;
  ulong            frame_mask = FD_NET_MTU - 1UL;
  uint             fill_prod  = FD_VOLATILE_CONST( *fill_ring->prod );
  uint             fill_cons  = FD_VOLATILE_CONST( *fill_ring->cons );

  if( FD_UNLIKELY( (int)(fill_prod-fill_cons) >= (int)fill_depth ) ) {
    ctx->metrics.rx_fill_blocked_cnt++;
    return; /* blocked */
  }

  /* Pass it to the receive handler */

  uchar const * packet = (uchar const *)xsk->umem.addr + frame.addr;
  net_rx_packet( ctx, stem, packet, frame.len );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *rx_ring->cons ) = rx_ring->cached_cons = rx_seq+1U;

  /* Free the frame by returning it back to the fill ring */

  fill_ring->frame_ring[ fill_prod&fill_mask ] = frame.addr & (~frame_mask);
  FD_VOLATILE( *fill_ring->prod ) = fill_ring->cached_prod = fill_prod+1U;

}

/* before_credit is called every loop iteration. */

static void
before_credit( fd_net_ctx_t *      ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  /* A previous send attempt was overrun.  A corrupt copy of the packet was
     placed into an XDP frame, but the frame was not yet submitted to the
     TX ring.  Return the tx buffer to the free list. */

  if( ctx->tx_op.frame ) {
    *charge_busy = 1;
    fd_net_free_ring_t * free      = ctx->free_tx + ctx->tx_op.if_idx;
    ulong                alloc_seq = free->prod;
    free->queue[ alloc_seq % free->depth ] = (ulong)ctx->tx_op.frame;
    free->prod = fd_seq_inc( alloc_seq, 1UL );
    ctx->tx_op.frame = NULL;
  }

  /* Check if new packets are available or if TX frames are free again
     (Round-robin through sockets) */

  uint       rr_idx = ctx->rr_idx;
  fd_xsk_t * rr_xsk = ctx->xsk[ rr_idx ];
  ctx->rr_idx++;
  ctx->rr_idx = fd_uint_if( ctx->rr_idx>=ctx->xsk_cnt, 0, ctx->rr_idx );

  uint rx_cons = FD_VOLATILE_CONST( *rr_xsk->ring_rx.cons );
  uint rx_prod = FD_VOLATILE_CONST( *rr_xsk->ring_rx.prod );
  if( rx_cons!=rx_prod ) {
    *charge_busy = 1;
    rr_xsk->ring_rx.cached_prod = rx_prod;
    net_rx_event( ctx, stem, rr_xsk, rx_cons );
  }

  uint comp_cons = FD_VOLATILE_CONST( *rr_xsk->ring_cr.cons );
  uint comp_prod = FD_VOLATILE_CONST( *rr_xsk->ring_cr.prod );
  if( comp_cons!=comp_prod ) {
    *charge_busy = 1;
    rr_xsk->ring_cr.cached_prod = comp_prod;
    net_comp_event( ctx, rr_xsk, rr_idx, comp_cons );
  }

  net_tx_periodic_wakeup( ctx, rr_idx, fd_tickcount() );

}

/* net_xsk_bootstrap does the initial UMEM frame to RX/TX ring assignments.
   First assigns UMEM frames to the XDP FILL ring, then assigns frames to
   the net tile free_tx queue. */

static void
net_xsk_bootstrap( fd_net_ctx_t * ctx,
                   uint           xsk_idx ) {
  fd_xsk_t * xsk = ctx->xsk[ xsk_idx ];

  ulong       frame_off = 0UL;
  ulong const frame_sz  = FD_NET_MTU;
  ulong const rx_depth  = ctx->xsk[ xsk_idx ]->ring_rx.depth;
  ulong const tx_depth  = ctx->free_tx[ xsk_idx ].depth;

  fd_ring_desc_t * fill      = &xsk->ring_fr;
  uint             fill_prod = fill->cached_prod;
  for( ulong j=0UL; j<rx_depth; j++ ) {
    fill->frame_ring[ j ] = frame_off;
    frame_off += frame_sz;
  }
  FD_VOLATILE( *fill->prod ) = fill->cached_prod = fill_prod + (uint)rx_depth;

  ulong const umem_base = xsk->umem.addr;
  for( ulong j=0; j<tx_depth; j++ ) {
    ctx->free_tx[ xsk_idx ].queue[ j ] = umem_base + frame_off;
    frame_off += frame_sz;
  }
  ctx->free_tx[ xsk_idx ].prod  = tx_depth;
  ctx->free_tx[ xsk_idx ].depth = tx_depth;
}

/* init_link_session is part of privileged_init.  It only runs on net
   tile 0.  This function does shared pre-configuration used by all
   other net tiles.  This includes installing the XDP program and
   setting up the XSKMAP into which the other net tiles can register
   themselves into.

   session, link_session, lo_session get initialized with session
   objects.  tile points to the net tile's config.  if_idx, lo_idx
   locate the device IDs of the main and loopback interface.
   *xsk_map_fd, *lo_xsk_map_fd are set to the newly created XSKMAP file
   descriptors.

   Note that if the main interface is loopback, then the loopback-
   related structures are uninitialized.

   Kernel object references:

     BPF_LINK file descriptor
      |
      +-> XDP program installation on NIC
      |    |
      |    +-> XDP program <-- BPF_PROG file descriptor (prog_fd)
      |
      +-> XSKMAP object <-- BPF_MAP file descriptor (xsk_map)
      |
      +-> BPF_MAP object <-- BPF_MAP file descriptor (udp_dsts) */

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );

  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_net_ctx_t) );

  uint if_idx = if_nametoindex( tile->net.interface );
  if( FD_UNLIKELY( !if_idx ) ) FD_LOG_ERR(( "if_nametoindex(%s) failed", tile->net.interface ));

  /* Create and install XSKs */

  int xsk_map_fd = 123462;
  ctx->prog_link_fds[ 0 ] = 123463;
  ctx->xsk[ 0 ] =
      fd_xsk_join(
      fd_xsk_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_align(), fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) ),
                  FD_NET_MTU,
                  tile->net.xdp_rx_queue_size,
                  tile->net.xdp_rx_queue_size,
                  tile->net.xdp_tx_queue_size,
                  tile->net.xdp_tx_queue_size ) );
  if( FD_UNLIKELY( !ctx->xsk[ 0 ] ) )                                                    FD_LOG_ERR(( "fd_xsk_new failed" ));
  uint flags = tile->net.zero_copy ? XDP_ZEROCOPY : XDP_COPY;
  if( FD_UNLIKELY( !fd_xsk_init( ctx->xsk[ 0 ], if_idx, (uint)tile->kind_id, flags ) ) ) FD_LOG_ERR(( "failed to bind xsk for net tile %lu", tile->kind_id ));
  if( FD_UNLIKELY( !fd_xsk_activate( ctx->xsk[ 0 ], xsk_map_fd ) ) )                     FD_LOG_ERR(( "failed to activate xsk for net tile %lu", tile->kind_id ));

  if( FD_UNLIKELY( fd_sandbox_gettid()==fd_sandbox_getpid() ) ) {
    /* Kind of gross.. in single threaded mode we don't want to close the xsk_map_fd
       since it's shared with other net tiles.  Just check for that by seeing if we
       are the only thread in the process. */
    if( FD_UNLIKELY( -1==close( xsk_map_fd ) ) )                                         FD_LOG_ERR(( "close(%d) failed (%d-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));
  }

  ctx->free_tx[ 0 ].queue = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->net.xdp_tx_queue_size * sizeof(ulong) );
  ctx->free_tx[ 0 ].depth = tile->net.xdp_tx_queue_size;

  /* Networking tile at index 0 also binds to loopback (only queue 0 available on lo) */

  if( FD_UNLIKELY( strcmp( tile->net.interface, "lo" ) && !tile->kind_id ) ) {
    ctx->xsk_cnt = 2;

    ushort udp_port_candidates[] = {
      (ushort)tile->net.legacy_transaction_listen_port,
      (ushort)tile->net.quic_transaction_listen_port,
      (ushort)tile->net.shred_listen_port,
      (ushort)tile->net.gossip_listen_port,
      (ushort)tile->net.repair_intake_listen_port,
      (ushort)tile->net.repair_serve_listen_port,
    };

    uint lo_idx = if_nametoindex( "lo" );
    if( FD_UNLIKELY( !lo_idx ) ) FD_LOG_ERR(( "if_nametoindex(lo) failed" ));

    fd_xdp_fds_t lo_fds = fd_xdp_install( lo_idx,
                                          tile->net.src_ip_addr,
                                          sizeof(udp_port_candidates)/sizeof(udp_port_candidates[0]),
                                          udp_port_candidates,
                                          "skb" );

    ctx->prog_link_fds[ 1 ] = lo_fds.prog_link_fd;
    ctx->xsk[ 1 ] =
        fd_xsk_join(
        fd_xsk_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_align(), fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) ),
                    FD_NET_MTU,
                    tile->net.xdp_rx_queue_size,
                    tile->net.xdp_rx_queue_size,
                    tile->net.xdp_tx_queue_size,
                    tile->net.xdp_tx_queue_size ) );
    if( FD_UNLIKELY( !ctx->xsk[ 1 ] ) )                                                            FD_LOG_ERR(( "fd_xsk_join failed" ));
    if( FD_UNLIKELY( !fd_xsk_init( ctx->xsk[ 1 ], lo_idx, (uint)tile->kind_id, 0 /* flags */ ) ) ) FD_LOG_ERR(( "failed to bind lo_xsk" ));
    if( FD_UNLIKELY( !fd_xsk_activate( ctx->xsk[ 1 ], lo_fds.xsk_map_fd ) ) )                          FD_LOG_ERR(( "failed to activate lo_xsk" ));
    if( FD_UNLIKELY( -1==close( lo_fds.xsk_map_fd ) ) )                                                FD_LOG_ERR(( "close(%d) failed (%d-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));

    ctx->free_tx[ 1 ].queue = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->net.xdp_tx_queue_size * sizeof(ulong) );
    ctx->free_tx[ 1 ].depth = tile->net.xdp_tx_queue_size;
  }

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ctx->xdp_stats_interval_ticks = (long)( FD_XDP_STATS_INTERVAL_NS * tick_per_ns );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );

  ctx->net_tile_id  = (uint)tile->kind_id;
  ctx->net_tile_cnt = (uint)fd_topo_tile_name_cnt( topo, tile->name );

  ctx->src_ip_addr = tile->net.src_ip_addr;
  memcpy( ctx->src_mac_addr, tile->net.src_mac_addr, 6UL );

  ctx->shred_listen_port              = tile->net.shred_listen_port;
  ctx->quic_transaction_listen_port   = tile->net.quic_transaction_listen_port;
  ctx->legacy_transaction_listen_port = tile->net.legacy_transaction_listen_port;
  ctx->gossip_listen_port             = tile->net.gossip_listen_port;
  ctx->repair_intake_listen_port      = tile->net.repair_intake_listen_port;
  ctx->repair_serve_listen_port       = tile->net.repair_serve_listen_port;

  /* Put a bound on chunks we read from the input, to make sure they
     are within in the data region of the workspace. */

  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "net tile in link cnt is zero" ));
  if( FD_UNLIKELY( tile->in_cnt>MAX_NET_INS ) ) FD_LOG_ERR(( "net tile in link cnt %lu exceeds MAX_NET_INS %lu", tile->in_cnt, MAX_NET_INS ));
  FD_TEST( tile->in_cnt<=32 );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "net tile in link does not have a normal MTU" ));

    ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  for( ulong i = 0; i < tile->out_cnt; i++ ) {
    fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ i  ] ];
    if( strcmp( out_link->name, "net_quic" ) == 0 ) {
      fd_topo_link_t * quic_out = out_link;
      ctx->quic_out->mcache = quic_out->mcache;
      ctx->quic_out->sync   = fd_mcache_seq_laddr( ctx->quic_out->mcache );
      ctx->quic_out->depth  = fd_mcache_depth( ctx->quic_out->mcache );
      ctx->quic_out->seq    = fd_mcache_seq_query( ctx->quic_out->sync );
      ctx->quic_out->chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( quic_out->dcache ), quic_out->dcache );
      ctx->quic_out->mem    = topo->workspaces[ topo->objs[ quic_out->dcache_obj_id ].wksp_id ].wksp;
      ctx->quic_out->wmark  = fd_dcache_compact_wmark ( ctx->quic_out->mem, quic_out->dcache, quic_out->mtu );
      ctx->quic_out->chunk  = ctx->quic_out->chunk0;
    } else if( strcmp( out_link->name, "net_shred" ) == 0 ) {
      fd_topo_link_t * shred_out = out_link;
      ctx->shred_out->mcache = shred_out->mcache;
      ctx->shred_out->sync   = fd_mcache_seq_laddr( ctx->shred_out->mcache );
      ctx->shred_out->depth  = fd_mcache_depth( ctx->shred_out->mcache );
      ctx->shred_out->seq    = fd_mcache_seq_query( ctx->shred_out->sync );
      ctx->shred_out->chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( shred_out->dcache ), shred_out->dcache );
      ctx->shred_out->mem    = topo->workspaces[ topo->objs[ shred_out->dcache_obj_id ].wksp_id ].wksp;
      ctx->shred_out->wmark  = fd_dcache_compact_wmark ( ctx->shred_out->mem, shred_out->dcache, shred_out->mtu );
      ctx->shred_out->chunk  = ctx->shred_out->chunk0;
    } else if( strcmp( out_link->name, "net_gossip" ) == 0 ) {
      fd_topo_link_t * gossip_out = out_link;
      ctx->gossip_out->mcache = gossip_out->mcache;
      ctx->gossip_out->sync   = fd_mcache_seq_laddr( ctx->gossip_out->mcache );
      ctx->gossip_out->depth  = fd_mcache_depth( ctx->gossip_out->mcache );
      ctx->gossip_out->seq    = fd_mcache_seq_query( ctx->gossip_out->sync );
      ctx->gossip_out->chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( gossip_out->dcache ), gossip_out->dcache );
      ctx->gossip_out->mem    = topo->workspaces[ topo->objs[ gossip_out->dcache_obj_id ].wksp_id ].wksp;
      ctx->gossip_out->wmark  = fd_dcache_compact_wmark ( ctx->gossip_out->mem, gossip_out->dcache, gossip_out->mtu );
      ctx->gossip_out->chunk  = ctx->gossip_out->chunk0;
    } else if( strcmp( out_link->name, "net_repair" ) == 0 ) {
      fd_topo_link_t * repair_out = out_link;
      ctx->repair_out->mcache = repair_out->mcache;
      ctx->repair_out->sync   = fd_mcache_seq_laddr( ctx->repair_out->mcache );
      ctx->repair_out->depth  = fd_mcache_depth( ctx->repair_out->mcache );
      ctx->repair_out->seq    = fd_mcache_seq_query( ctx->repair_out->sync );
      ctx->repair_out->chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( repair_out->dcache ), repair_out->dcache );
      ctx->repair_out->mem    = topo->workspaces[ topo->objs[ repair_out->dcache_obj_id ].wksp_id ].wksp;
      ctx->repair_out->wmark  = fd_dcache_compact_wmark ( ctx->repair_out->mem, repair_out->dcache, repair_out->mtu );
      ctx->repair_out->chunk  = ctx->repair_out->chunk0;
    } else if( strcmp( out_link->name, "net_netlink" ) == 0 ) {
      fd_topo_link_t * netlink_out = out_link;
      ctx->neigh4_solicit->mcache = netlink_out->mcache;
      ctx->neigh4_solicit->depth  = fd_mcache_depth( ctx->neigh4_solicit->mcache );
      ctx->neigh4_solicit->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr( ctx->neigh4_solicit->mcache ) );
    } else {
      FD_LOG_ERR(( "unrecognized out link `%s`", out_link->name ));
    }
  }

  /* Check if any of the tiles we set a listen port for do not have an outlink. */
  if( FD_UNLIKELY( ctx->shred_listen_port!=0 && ctx->shred_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "shred listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->quic_transaction_listen_port!=0 && ctx->quic_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "quic transaction listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->legacy_transaction_listen_port!=0 && ctx->quic_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "legacy transaction listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->gossip_listen_port!=0 && ctx->gossip_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "gossip listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->repair_intake_listen_port!=0 && ctx->repair_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "repair intake port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->repair_serve_listen_port!=0 && ctx->repair_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "repair serve listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->neigh4_solicit->mcache==NULL ) ) {
    FD_LOG_ERR(( "netlink request link not found" ));
  }

  for( uint j=0U; j<2U; j++ ) {
    ctx->tx_flusher[ j ].pending_wmark         = (ulong)( (double)tile->net.xdp_tx_queue_size * 0.7 );
    ctx->tx_flusher[ j ].tail_flush_backoff    = (long)( (double)tile->net.tx_flush_timeout_ns * fd_tempo_tick_per_ns( NULL ) );
    ctx->tx_flusher[ j ].next_tail_flush_ticks = LONG_MAX;
  }

  /* Join netbase objects */
  ctx->fib_local = fd_fib4_join( fd_topo_obj_laddr( topo, tile->net.fib4_local_obj_id ) );
  ctx->fib_main  = fd_fib4_join( fd_topo_obj_laddr( topo, tile->net.fib4_main_obj_id  ) );
  if( FD_UNLIKELY( !ctx->fib_local || !ctx->fib_main ) ) FD_LOG_ERR(( "fd_fib4_join failed" ));
  if( FD_UNLIKELY( !fd_neigh4_hmap_join(
      ctx->neigh4,
      fd_topo_obj_laddr( topo, tile->net.neigh4_obj_id ),
      fd_topo_obj_laddr( topo, tile->net.neigh4_ele_obj_id ) ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  for( uint j=0U; j<ctx->xsk_cnt; j++ ) {
    net_xsk_bootstrap( ctx, j );
    net_rx_wakeup( ctx, ctx->xsk[ j ] );
    net_tx_wakeup( ctx, ctx->xsk[ j ] );
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );

  /* A bit of a hack, if there is no loopback XSK for this tile, we still need to pass
     two "allow" FD arguments to the net policy, so we just make them both the same. */
  int allow_fd2 = ctx->xsk_cnt>1UL ? ctx->xsk[ 1 ]->xsk_fd : ctx->xsk[ 0 ]->xsk_fd;
  FD_TEST( ctx->xsk[ 0 ]->xsk_fd >= 0 && allow_fd2 >= 0 );
  populate_sock_filter_policy_net( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->xsk[ 0 ]->xsk_fd, (uint)allow_fd2 );
  return sock_filter_policy_net_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<6UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

                                      out_fds[ out_cnt++ ] = ctx->xsk[ 0 ]->xsk_fd;
                                      out_fds[ out_cnt++ ] = ctx->prog_link_fds[ 0 ];
  if( FD_LIKELY( ctx->xsk_cnt>1UL ) ) out_fds[ out_cnt++ ] = ctx->xsk[ 1 ]->xsk_fd;
  if( FD_LIKELY( ctx->xsk_cnt>1UL ) ) out_fds[ out_cnt++ ] = ctx->prog_link_fds[ 1 ];
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY ((ulong)30e3) /* 30 us */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_net_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_net_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_net = {
  .name                     = "net",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
