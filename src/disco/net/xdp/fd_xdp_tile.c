/* The xdp tile translates between AF_XDP and fd_tango
   traffic.  It is responsible for setting up the XDP and
   XSK socket configuration. */

#include "../fd_net_tile.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h> /* MSG_DONTWAIT needed before importing the net seccomp filter */
#include <linux/if_xdp.h>

#include "../fd_net_common.h"
#include "../../metrics/fd_metrics.h"
#include "../../netlink/fd_netlink_tile.h" /* neigh4_solicit */
#include "../../topo/fd_topo.h"

#include "../../../waltz/ip/fd_fib4.h"
#include "../../../waltz/ip/fd_iproute.h"
#include "../../../waltz/neigh/fd_neigh4_map.h"
#include "../../../waltz/mib/fd_netdev_tbl.h"
#include "../../../waltz/xdp/fd_xdp_redirect_user.h" /* fd_xsk_activate */
#include "../../../waltz/xdp/fd_xsk.h"
#include "../../../util/log/fd_dtrace.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_gre.h"
#include "../../../util/pod/fd_pod_format.h"

#include <unistd.h>
#include <linux/if.h> /* struct ifreq */
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>

#include "generated/fd_xdp_tile_seccomp.h"

/* MAX_NET_INS controls the max number of TX links that a net tile can
   serve. */

#define MAX_NET_INS (32UL)

#define IN_KIND_NET     (0U)
#define IN_KIND_IPROUTE (1U)

/* FD_XDP_STATS_INTERVAL_NS controls the XDP stats refresh interval.
   This should be lower than the interval at which the metrics tile
   collects metrics. */

#define FD_XDP_STATS_INTERVAL_NS (11e6) /* 11ms */

/* XSK_IDX_{MAIN,LO} are the hardcoded XSK indices in ctx->xsk[ ... ].
   Only net tile 0 has XSK_IDX_LO, all net tiles have XSK_IDX_MAIN. */

#define XSK_IDX_MAIN 0
#define XSK_IDX_LO   1

/* XSK 'busy_poll_usecs' value (max amount of time
   spent spinning in a NAPI poll before returning back to
   userspace if the processing budget hasn't already ran out).

   64us chosen based on napibusy configuration tested and
   shown in https://lwn.net/Articles/997491/ Linux patch
   cover letter.  Chosen over fullbusy since for Firedancer
   the values of fullbusy are unnecessarily high and could
   cause some extra latency to regular non-Firedancer traffic.*/
#define PREFBUSY_TIME_BUDGET_MICROS (64L)

/* PREFBUSY_RX_BUDGET is the NAPI RX processing budget (max num RX
   packets that the NIC driver can move from the hw rings into the
   XSK rings per poll).

   Default RX budget used by NIC drivers is 64, therefore
   it is safest to use 64 in prefbusy polling.  Also reduces
   TX starvation risks as the TX budget set by the NIC driver
   is also generally 64. */
#define PREFBUSY_RX_BUDGET (64L)

/* Min time between each prefbusy poll.  Necessary to avoid a no RX
   scenario livelocking TX with overly frequent sendto calls, given
   prefbusy polls whenever the RX queue is empty.

   Value chosen based on experimentation on ixgbe, mlx5 and i40e as well
   as on varying CPUs and clock speeds.  Too low -> lower max TX
   throughput when RX is very low.  Too high -> lower max RX and TX throughput. */
#define PREFBUSY_MIN_INTERVAL_NS (5e3) /* 5us */

/* Max time since last prefbusy poll before a prefbusy poll is
   forced (has been read that polling can sometimes resolve a stall).

   Exact value again not particularly important as this is just extra
   protection against stalls which have not been observed in testing but
   are still good to protect against since there is no cost to doing so.

   Value of 150us chosen since it is easily large enough to not interfere
   with standard prefbusy runtime unless there is a serious problem. */
#define PREFBUSY_STALL_TIMEOUT_NS (150e3) /* 150us */

/* MAX_GRE_CNT is the maximum number of GRE tunnels the XDP tile will
   monitor.  If a packet comes in with a source IP that doesn't match
   the endpoint of one of the first MAX_GRE_CNT tunnels (in the order
   the OS enumerates them), it will be dropped.  This is limited for
   performance reasons. */
#define MAX_GRE_CNT 4UL

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
     TX ring, issues another wakeup. Only used by "softirq" poll mode. */
  long next_tail_flush_ticks;
  long tail_flush_backoff;

  /* When the most recent prefbusy poll was. */
  long prefbusy_last_poll_ticks;
  /* Min time between each prefbusy poll. */
  long prefbusy_min_interval_ticks;
  /* Max time since last prefbusy poll before a prefbusy poll is
     forced (has been read that polling can sometimes resolve a stall). */
  long prefbusy_stall_timeout_ticks;
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
  uint     xsk_cnt;
  fd_xsk_t xsk[ 2 ];
  int      prog_link_fds[ 2 ];
  uint     if_virt;

  /* UMEM frame region within dcache */
  void *   umem;    /* Start of UMEM */
  ulong    umem_sz; /* Size  of UMEM */

  /* UMEM chunk region within workspace */
  uint     umem_chunk0; /* Lowest allowed chunk number */
  uint     umem_wmark;  /* Highest allowed chunk number */

  /* All net tiles are subscribed to the same TX links.  (These are
     incoming links from app tiles asking the net tile to send out packets)
     The net tiles "take turns" doing TX jobs based on the L3+L4 dst hash.
     net_tile_id is the index of the current interface, net_tile_cnt is the
     total amount of interfaces. */
  uint net_tile_id;
  uint net_tile_cnt;

  /* Details pertaining to an inflight send op */
  struct {
    uint   xsk_idx;
    void * frame;
    uchar  mac_addrs[12];     /* First 12 bytes of Ethernet header */
    uint   src_ip;            /* src_ip in net order */

    uint   use_gre;           /* The tx packet will be GRE-encapsulated */
    uint   gre_outer_src_ip;  /* For GRE: Outer iphdr's src_ip in net order */
    uint   gre_outer_dst_ip;  /* For GRE: Outer iphdr's dst_ip in net order */
  } tx_op;

  /* Round-robin cycle serivce operations */
  uint rr_idx;

  /* Ring tracking free packet buffers */
  fd_net_free_ring_t free_tx;

  uchar  src_mac_addr[6];
  uint   default_address;

  uint   bind_address;
  ushort shred_listen_port;
  ushort quic_transaction_listen_port;
  ushort legacy_transaction_listen_port;
  ushort gossip_listen_port;
  ushort repair_client_listen_port;
  ushort repair_serve_listen_port;
  ushort txsend_src_port;

  ulong in_cnt;
  fd_net_in_ctx_t in[ MAX_NET_INS ];
  uchar in_kind[ MAX_NET_INS ];
  fd_iproute_msg_t iproute_msg;

  fd_net_out_ctx_t quic_out[1];
  fd_net_out_ctx_t shred_out[1];
  fd_net_out_ctx_t gossvf_out[1];
  fd_net_out_ctx_t repair_out[1];
  fd_net_out_ctx_t txsend_out[1];

  fd_net_out_ctx_t rserve_out[1];
  int rserve_enabled;

  /* XDP stats refresh timer */
  long xdp_stats_interval_ticks;
  long next_xdp_stats_refresh;

  /* TX flush timers */
  fd_net_flusher_t tx_flusher[2]; /* one per XSK */

  /* Route and neighbor tables */
  fd_fib4_t fib_local[1];
  fd_fib4_t fib_main[1];
  fd_neigh4_hmap_t  neigh4[1];
  fd_netlink_neigh4_solicit_link_t neigh4_solicit[1];

  /* Netdev table */
  fd_netdev_tbl_join_t netdev_tbl;                 /* local copy in scratch (hot path) */
  fd_netdev_tbl_join_t netdev_shared;              /* shared table in netbase (seqlock protected) */
  uint                 gre_tunnel_ip[MAX_GRE_CNT]; /* 0 means unused */

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong rx_src_addr_invalid_cnt;
    ulong rx_undersz_cnt;
    ulong rx_fill_blocked_cnt;
    ulong rx_backp_cnt;
    long  rx_busy_cnt;
    long  rx_idle_cnt;

    ulong tx_submit_cnt;
    ulong tx_complete_cnt;
    ulong tx_bytes_total;
    ulong tx_route_fail_cnt[ FD_METRICS_COUNTER_NET_PKT_TX_ROUTE_FAIL_CNT ];
    ulong tx_invalid_cnt;
    ulong tx_no_xdp_cnt;
    ulong tx_neigh_fail_cnt;
    ulong tx_full_fail_cnt;
    long  tx_busy_cnt;
    long  tx_idle_cnt;

    ulong xsk_tx_wakeup_cnt;
    ulong xsk_rx_wakeup_cnt;

    ulong rx_gre_cnt;
    ulong rx_gre_ignored_cnt;
    ulong rx_gre_inv_pkt_cnt;
    ulong tx_gre_cnt;
    ulong tx_gre_route_fail_cnt;
  } metrics;
} fd_net_ctx_t;

fd_fib4_t *
fd_net_tile_fib4_join( fd_fib4_t *              out,
                       fd_topo_t const *         topo,
                       fd_topo_tile_t const *    tile,
                       int                      main_table ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  (void)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );
  (void)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->xdp.free_ring_depth*sizeof(ulong) );
  (void)FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * local_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->xdp.route_max, tile->xdp.route_peer_max ) );
  void * main_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->xdp.route_max, tile->xdp.route_peer_max ) );
  return fd_fib4_join( out, main_table ? main_mem : local_mem );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t)                      );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),        tile->xdp.free_ring_depth * sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  for( ulong i=0UL; i<2UL; i++ ) l = FD_LAYOUT_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->xdp.route_max, tile->xdp.route_peer_max ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_net_ctx_t * ctx ) {
  FD_MCNT_SET(   NET, PKT_RX,              ctx->metrics.rx_pkt_cnt          );
  FD_MCNT_SET(   NET, PKT_RX_BYTES,        ctx->metrics.rx_bytes_total      );
  FD_MCNT_SET(   NET, PKT_RX_UNDERSIZE,    ctx->metrics.rx_undersz_cnt      );
  FD_MCNT_SET(   NET, PKT_RX_FILL_RING_FULL, ctx->metrics.rx_fill_blocked_cnt );
  FD_MCNT_SET(   NET, PKT_RX_BACKPRESSURE, ctx->metrics.rx_backp_cnt        );
  FD_MGAUGE_SET( NET, RX_BUFFER_BUSY, (ulong)fd_long_max( ctx->metrics.rx_busy_cnt, 0L ) );
  FD_MGAUGE_SET( NET, RX_BUFFER_IDLE, (ulong)fd_long_max( ctx->metrics.rx_idle_cnt, 0L ) );
  FD_MGAUGE_SET( NET, TX_BUFFER_BUSY, (ulong)fd_long_max( ctx->metrics.tx_busy_cnt, 0L ) );
  FD_MGAUGE_SET( NET, TX_BUFFER_IDLE, (ulong)fd_long_max( ctx->metrics.tx_idle_cnt, 0L ) );

  FD_MCNT_SET( NET, PKT_TX_SUBMITTED,     ctx->metrics.tx_submit_cnt     );
  FD_MCNT_SET( NET, PKT_TX_COMPLETED,     ctx->metrics.tx_complete_cnt   );
  FD_MCNT_SET( NET, PKT_TX_BYTES,         ctx->metrics.tx_bytes_total    );
  FD_MCNT_ENUM_COPY( NET, PKT_TX_ROUTE_FAIL, ctx->metrics.tx_route_fail_cnt );
  FD_MCNT_SET( NET, PKT_TX_INVALID,     ctx->metrics.tx_invalid_cnt    );
  FD_MCNT_SET( NET, PKT_TX_NO_NEIGHBOR, ctx->metrics.tx_neigh_fail_cnt );
  FD_MCNT_SET( NET, PKT_TX_RING_FULL,     ctx->metrics.tx_full_fail_cnt  );

  FD_MCNT_SET( NET, XSK_SYSCALL_TX,    ctx->metrics.xsk_tx_wakeup_cnt    );
  FD_MCNT_SET( NET, XSK_SYSCALL_RX,    ctx->metrics.xsk_rx_wakeup_cnt    );

  FD_MCNT_SET( NET, GRE_PKT_RX,            ctx->metrics.rx_gre_cnt            );
  FD_MCNT_SET( NET, GRE_PKT_RX_INVALID,    ctx->metrics.rx_gre_inv_pkt_cnt    );
  FD_MCNT_SET( NET, GRE_PKT_RX_IGNORED,    ctx->metrics.rx_gre_ignored_cnt    );
  FD_MCNT_SET( NET, GRE_PKT_TX_SUBMITTED,            ctx->metrics.tx_gre_cnt            );
  FD_MCNT_SET( NET, GRE_PKT_TX_NO_ROUTE, ctx->metrics.tx_gre_route_fail_cnt );
  FD_MCNT_SET( NET, PKT_RX_SRC_INVALID, ctx->metrics.rx_src_addr_invalid_cnt );
  /* fd_fib4_cnt includes the synthetic throw route at index zero. */
  FD_MGAUGE_SET( NET, ROUTE_COUNT_LOCAL, fd_ulong_sat_sub( fd_fib4_cnt( ctx->fib_local ), 1UL ) );
  FD_MGAUGE_SET( NET, ROUTE_COUNT_MAIN,  fd_ulong_sat_sub( fd_fib4_cnt( ctx->fib_main  ), 1UL ) );
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
    struct xdp_statistics_v1 sub_stats = {0};
    uint optlen = (uint)sizeof(struct xdp_statistics_v1);
    if( FD_UNLIKELY( -1==getsockopt( ctx->xsk[ j ].xsk_fd, SOL_XDP, XDP_STATISTICS, &sub_stats, &optlen ) ) )
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

  FD_MCNT_SET( NET, XDP_RX_OTHER_DROPPED,         stats.rx_dropped               );
  FD_MCNT_SET( NET, XDP_RX_INVALID_DESCRIPTOR,    stats.rx_invalid_descs         );
  FD_MCNT_SET( NET, XDP_TX_INVALID_DESCRIPTOR,    stats.tx_invalid_descs         );
  FD_MCNT_SET( NET, XDP_RX_RING_FULL,             stats.rx_ring_full             );
  FD_MCNT_SET( NET, XDP_RX_FILL_RING_EMPTY,       stats.rx_fill_ring_empty_descs );
  FD_MCNT_SET( NET, XDP_TX_RING_EMPTY,            stats.tx_ring_empty_descs      );
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

/* net_gre_tunnel_ip fills ctx->gre_tunnel_ip.  The first gre_tunnel_cnt
   entries will be populated with the IP address of the GRE tunnel peer
   for the first gre_tunnel_cnt untagged GRE tunnels, and the rest of
   the entries will be set to 0, where gre_tunnel_cnt = min(MAX_GRE_CNT,
   the number of untagged GRE tunnels).  Returns gre_tunnel_cnt. */

static ulong
net_gre_tunnel_ip( fd_net_ctx_t * ctx ) {
  fd_netdev_t * dev_tbl = ctx->netdev_tbl.dev_tbl;
  ushort        dev_cnt = ctx->netdev_tbl.hdr->dev_cnt;

  ulong gre_tunnel_cnt = 0UL;
  memset( ctx->gre_tunnel_ip, '\0', MAX_GRE_CNT*sizeof(uint) );
  for( ushort if_idx = 0; (if_idx<dev_cnt) & (gre_tunnel_cnt<MAX_GRE_CNT); if_idx++ ) {
    fd_netdev_t const * dev = dev_tbl+if_idx;
    if( dev->dev_type==ARPHRD_IPGRE && dev->gre_dst_ip ) ctx->gre_tunnel_ip[ gre_tunnel_cnt++ ] = dev->gre_dst_ip;
  }
  return gre_tunnel_cnt;
}


/* net_tx_ready returns 1 if we can submit a job to this TX ring, and 0 otherwise.
   Reasons for block include:
   - No TX buffer is available (free ring empty)
   - TX ring is full

   tx_ring: pointer to the XDP TX ring
   free_ring: pointer to the free TX ring */

static int
net_tx_ready( fd_xdp_ring_t *      tx_ring,
              fd_net_free_ring_t * free_ring ) {
  if( FD_UNLIKELY( free_ring->prod == free_ring->cons ) ) return 0; /* drop - no free buffers */
  if( FD_UNLIKELY( fd_xdp_ring_full( tx_ring ) ) )        return 0; /* drop - tx ring full */
  return 1;
}

/* net_rx_wakeup triggers xsk_recvmsg to run in the kernel.  Needs to be
   called periodically in order to receive packets. */

static void
net_rx_wakeup( fd_net_ctx_t * ctx,
               fd_xsk_t *     xsk,
               int *          charge_busy ) {
  FD_VOLATILE( *xsk->ring_rx.cons ) = xsk->ring_rx.cached_cons; /* write-back local copies to fseqs */
  FD_VOLATILE( *xsk->ring_fr.prod ) = xsk->ring_fr.cached_prod;
  if( !fd_xsk_rx_need_wakeup( xsk ) ) return;
  *charge_busy = 1;
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
   called periodically in order to transmit packets. Should only be called
   if there are unconsumed packets in Tx ring. */

static void
net_tx_wakeup( fd_net_ctx_t * ctx,
               fd_xsk_t *     xsk,
               int *          charge_busy ) {
  FD_VOLATILE( *xsk->ring_tx.prod ) = xsk->ring_tx.cached_prod; /* write-back local copies to fseqs */
  FD_VOLATILE( *xsk->ring_cr.cons ) = xsk->ring_cr.cached_cons;
  if( !fd_xsk_tx_need_wakeup( xsk ) ) return;
  *charge_busy = 1;
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

static inline int
net_tx_periodic_wakeup( fd_net_ctx_t * ctx,
                        uint           xsk_idx,
                        long           now,
                        int *          charge_busy ) {
  fd_xdp_ring_t * tx_ring        = &ctx->xsk[ xsk_idx ].ring_tx;
  int             tx_ring_empty  = fd_xdp_ring_empty( tx_ring, FD_XDP_RING_ROLE_PROD );
  if( fd_net_flusher_check( ctx->tx_flusher+xsk_idx, now, tx_ring_empty ) ) {
    net_tx_wakeup( ctx, &ctx->xsk[ xsk_idx ], charge_busy );
    fd_net_flusher_wakeup( ctx->tx_flusher+xsk_idx, now );
  }
  return 0;
}

static void
during_housekeeping( fd_net_ctx_t * ctx ) {
  long now = fd_tickcount();
  if( FD_LIKELY( !fd_seqlock_locked_hint( &ctx->netdev_shared.hdr->seqlock ) ) ) {
    fd_netdev_tbl_copy( &ctx->netdev_tbl, &ctx->netdev_shared );
  }
  net_gre_tunnel_ip( ctx );

  ctx->metrics.rx_busy_cnt = 0UL;
  ctx->metrics.rx_idle_cnt = 0UL;
  ctx->metrics.tx_busy_cnt = 0UL;
  ctx->metrics.tx_idle_cnt = fd_seq_diff( ctx->free_tx.prod, ctx->free_tx.cons );
  for( uint j=0U; j<ctx->xsk_cnt; j++ ) {
    fd_xsk_t * xsk = &ctx->xsk[ j ];
    FD_COMPILER_MFENCE();
    /* Write back local copies to fseqs that we own */
    FD_VOLATILE( *xsk->ring_fr.prod ) = xsk->ring_fr.cached_prod;
    FD_VOLATILE( *xsk->ring_rx.cons ) = xsk->ring_rx.cached_cons;
    FD_VOLATILE( *xsk->ring_tx.prod ) = xsk->ring_tx.cached_prod;
    FD_VOLATILE( *xsk->ring_cr.cons ) = xsk->ring_cr.cached_cons;

    /* Refresh kernel-owned seq numbers for accurate stats */
    xsk->ring_fr.cached_cons = FD_VOLATILE_CONST( *xsk->ring_fr.cons );
    xsk->ring_rx.cached_prod = FD_VOLATILE_CONST( *xsk->ring_rx.prod );
    xsk->ring_tx.cached_cons = FD_VOLATILE_CONST( *xsk->ring_tx.cons );
    xsk->ring_cr.cached_prod = FD_VOLATILE_CONST( *xsk->ring_cr.prod );

    FD_COMPILER_MFENCE();
    ctx->metrics.rx_busy_cnt += (long)(int)( xsk->ring_rx.cached_prod - xsk->ring_rx.cached_cons );
    ctx->metrics.rx_idle_cnt += (long)(int)( xsk->ring_fr.cached_prod - xsk->ring_fr.cached_cons );
    ctx->metrics.tx_busy_cnt += (long)(int)( xsk->ring_tx.cached_prod - xsk->ring_tx.cached_cons );
    ctx->metrics.tx_busy_cnt += (long)(int)( xsk->ring_cr.cached_prod - xsk->ring_cr.cached_cons );
  }

  if( now > ctx->next_xdp_stats_refresh ) {
    ctx->next_xdp_stats_refresh = now + ctx->xdp_stats_interval_ticks;
    poll_xdp_statistics( ctx );
  }
}


/* net_tx_route resolves the xsk index, src ip address, src MAC address, and
   dst MAC address.  Returns 1 on success, 0 on failure.
   On success, tx_op->{xsk_idx,src_ip,mac_addrs} is set, and if the dst_ip
   belongs to a GRE interface, is_gre_inf will set to 1 and
   tx_op->{gre_outer_src_ip, gre_outer_dst_ip} will be loaded from the netdev
   table. is_gre_inf is set to 0 if dst_ip doesn't belong to a GRE interface. */

static int
net_tx_route( fd_net_ctx_t * ctx,
              uint           dst_ip,
              uint *         is_gre_inf ) {

  /* Route lookup */

  fd_fib4_hop_t hop[2] = {0};
  hop[0] = fd_fib4_lookup( ctx->fib_local, dst_ip, 0UL );
  hop[1] = fd_fib4_lookup( ctx->fib_main,  dst_ip, 0UL );
  fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );

  uint rtype   = next_hop->rtype;
  uint if_idx  = next_hop->if_idx;
  uint ip4_src = next_hop->ip4_src;

  if( FD_UNLIKELY( rtype==FD_FIB4_RTYPE_LOCAL ) ) {
    rtype  = FD_FIB4_RTYPE_UNICAST;
    if_idx = 1;
  }

  if( FD_UNLIKELY( rtype!=FD_FIB4_RTYPE_UNICAST ) ) {
    uint reason = fd_uint_if( rtype==FD_FIB4_RTYPE_THROW,
        FD_METRICS_ENUM_ROUTE_FAIL_V_NO_ROUTE_IDX,
        FD_METRICS_ENUM_ROUTE_FAIL_V_ROUTE_TYPE_IDX );
    ctx->metrics.tx_route_fail_cnt[ reason ]++;
    return 0;
  }

  fd_netdev_t * netdev = fd_netdev_tbl_query( &ctx->netdev_tbl, if_idx );
  if( !netdev ) {
    ctx->metrics.tx_route_fail_cnt[ FD_METRICS_ENUM_ROUTE_FAIL_V_INTERFACE_IDX ]++;
    return 0;
  }

  ip4_src = fd_uint_if( !!ctx->bind_address, ctx->bind_address, ip4_src );
  ctx->tx_op.src_ip  = ip4_src;
  ctx->tx_op.xsk_idx = UINT_MAX;

  FD_TEST( is_gre_inf );
  *is_gre_inf = 0;
  if( netdev->dev_type==ARPHRD_LOOPBACK ) {
    /* Set Ethernet src and dst address to 00:00:00:00:00:00 */
    memset( ctx->tx_op.mac_addrs, 0, 12UL );
    ctx->tx_op.xsk_idx = XSK_IDX_LO;
    /* Set preferred src address to 127.0.0.1 if no bind address is set */
    if( !ctx->tx_op.src_ip ) ctx->tx_op.src_ip = FD_IP4_ADDR( 127,0,0,1 );
    return 1;
  } else if( netdev->dev_type==ARPHRD_IPGRE ) {
    /* skip MAC addrs lookup for GRE inner dst ip */
    if( netdev->gre_src_ip ) ctx->tx_op.gre_outer_src_ip = netdev->gre_src_ip;
    ctx->tx_op.gre_outer_dst_ip = netdev->gre_dst_ip;
    *is_gre_inf = 1;
    return 1;
  }

  if( FD_UNLIKELY( netdev->dev_type!=ARPHRD_ETHER ) ) return 0; // drop

  if( FD_UNLIKELY( if_idx!=ctx->if_virt ) ) {
    ctx->metrics.tx_no_xdp_cnt++;
    return 0;
  }
  ctx->tx_op.xsk_idx = XSK_IDX_MAIN;

  /* Neighbor resolve */
  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_entry_t neigh[1];
  int neigh_res = fd_neigh4_hmap_query_entry( ctx->neigh4, neigh_ip, neigh );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) {
    /* Neighbor not found */
    fd_netlink_neigh4_solicit( ctx->neigh4_solicit, neigh_ip, if_idx, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }
  if( FD_UNLIKELY( neigh->state != FD_NEIGH4_STATE_ACTIVE ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }
  ip4_src = fd_uint_if( !ip4_src, ctx->default_address, ip4_src );
  ctx->tx_op.src_ip = ip4_src;
  memcpy( ctx->tx_op.mac_addrs+0, neigh->mac_addr, 6 );
  memcpy( ctx->tx_op.mac_addrs+6, netdev->mac_addr,  6 );

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
  (void)seq;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) return 0;

  /* Find interface index of next packet */
  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_OUTGOING ) ) return 1;

  /* Load balance TX */
  uint net_tile_cnt = ctx->net_tile_cnt;
  uint hash         = (uint)fd_disco_netmux_sig_hash( sig );
  uint target_idx   = hash % net_tile_cnt;
  uint net_tile_id  = ctx->net_tile_id;
  uint dst_ip       = fd_disco_netmux_sig_ip( sig );

  /* Skip if another net tile is responsible for this packet.
     Fast path for net tiles other than net_tile 0. */

  if( net_tile_id!=0 && net_tile_id!=target_idx ) return 1; /* ignore */


  ctx->tx_op.use_gre          = 0;
  ctx->tx_op.gre_outer_dst_ip = 0;
  ctx->tx_op.gre_outer_src_ip = 0;
  uint is_gre_inf             = 0;

  if( FD_UNLIKELY( !net_tx_route( ctx, dst_ip, &is_gre_inf ) ) ) {
    return 1; /* metrics incremented by net_tx_route */
  }

  uint xsk_idx     = ctx->tx_op.xsk_idx;

  if( is_gre_inf ) {
    uint inner_src_ip = ctx->tx_op.src_ip;
    if( FD_UNLIKELY( !inner_src_ip ) ) {
      ctx->metrics.tx_gre_route_fail_cnt++;
      return 1;
    }
    /* Find the MAC addrs for the eth hdr, and src ip for outer ip4 hdr if not found in netdev tbl */
    ctx->tx_op.src_ip  = 0;
    is_gre_inf         = 0;
    if( FD_UNLIKELY( !net_tx_route( ctx, ctx->tx_op.gre_outer_dst_ip, &is_gre_inf ) ) ) {
      ctx->metrics.tx_gre_route_fail_cnt++;
      return 1;
    }
    if( is_gre_inf ) {
      /* Only one layer of tunnelling supported */
      ctx->metrics.tx_gre_route_fail_cnt++;
      return 1;
    }
    if( !ctx->tx_op.gre_outer_src_ip ) {
      ctx->tx_op.gre_outer_src_ip = ctx->tx_op.src_ip;
    }
    ctx->tx_op.use_gre = 1; /* indicate to during_frag to use GRE header */
    ctx->tx_op.src_ip  = inner_src_ip;
    xsk_idx = XSK_IDX_MAIN;
  }

  if( FD_UNLIKELY( xsk_idx>=ctx->xsk_cnt ) ) {
    /* Packet does not route to an XDP interface */
    ctx->metrics.tx_no_xdp_cnt++;
    return 1;
  }

  if( xsk_idx==XSK_IDX_LO ) target_idx = 0; /* loopback always targets tile 0 */

  /* Skip if another net tile is responsible for this packet */

  if( net_tile_id!=target_idx ) return 1; /* ignore */

  /* Skip if TX is blocked */

  fd_xsk_t *           xsk  = &ctx->xsk[ xsk_idx ];
  fd_net_free_ring_t * free = &ctx->free_tx;
  if( FD_UNLIKELY( !net_tx_ready( &xsk->ring_tx, free ) ) ) {
    ctx->metrics.tx_full_fail_cnt++;
    return 1;
  }

  /* Allocate buffer for receive */
  ulong                alloc_seq = free->cons;
  void *               frame     = (void *)free->queue[ alloc_seq % free->depth ];
  free->cons = fd_seq_inc( alloc_seq, 1UL );

  ctx->tx_op.frame = frame;

  return 0; /* continue */
}

/* during_frag is called when before_frag has committed to transmit an
   outgoing packet. */

static inline void
during_frag( fd_net_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq FD_PARAM_UNUSED,
             ulong          sig FD_PARAM_UNUSED,
             ulong          chunk,
             ulong          sz,
             ulong          ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  if( FD_UNLIKELY( ctx->in_kind[in_idx]==IN_KIND_IPROUTE ) ) {
    if( FD_UNLIKELY( sz!=sizeof(fd_iproute_msg_t) ) ) FD_LOG_ERR(( "invalid iproute message size %lu", sz ));
    fd_memcpy( &ctx->iproute_msg, fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk ), sizeof(fd_iproute_msg_t) );
    return;
  }

  if( FD_UNLIKELY( sz<( sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t) ) ) )
    FD_LOG_ERR(( "packet too small %lu (in_idx=%lu)", sz, in_idx ));

  if( FD_UNLIKELY( sz>FD_ETH_PAYLOAD_MAX ) )
    FD_LOG_ERR(( "packet too big %lu (in_idx=%lu)", sz, in_idx ));

  void * frame = ctx->tx_op.frame;
  if( FD_UNLIKELY( (ulong)frame < (ulong)ctx->umem ) )
    FD_LOG_ERR(( "frame %p out of bounds (below %p)", frame, (void *)ctx->umem ));
  ulong umem_off = (ulong)frame - (ulong)ctx->umem;
  if( FD_UNLIKELY( (ulong)umem_off > (ulong)ctx->umem_sz ) )
    FD_LOG_ERR(( "frame %p out of bounds (beyond %p)", frame, (void *)ctx->umem_sz ));

  /* Speculatively copy frame into XDP buffer */
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

  if( ctx->tx_op.use_gre ) {
    /* Discard the ethernet hdr from src. Copy the rest to where the inner ip4_hdr is.
       Safe from overflow: FD_ETH_PAYLOAD_MAX + header overhead < frame size (2048UL) */
    ulong overhead = sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_gre_hdr_t);
    fd_memcpy( (void *)( (ulong)ctx->tx_op.frame + overhead ), src + sizeof(fd_eth_hdr_t), sz - sizeof(fd_eth_hdr_t) );
  } else {
    fd_memcpy( ctx->tx_op.frame, src, sz );
  }
}

/* after_frag is called when the during_frag memcpy was _not_ overrun. */

static void
after_frag( fd_net_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)tsorig; (void)tspub; (void)stem;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) {
    fd_iproute_msg_t const * msg = &ctx->iproute_msg;
    if( msg->op==FD_IPROUTE_OP_FLUSH ) {
      fd_fib4_clear( ctx->fib_local );
      fd_fib4_clear( ctx->fib_main );
      return;
    }
    fd_fib4_t * fib;
    if( msg->table_id==RT_TABLE_LOCAL ) fib = ctx->fib_local;
    else if( msg->table_id==RT_TABLE_MAIN ) fib = ctx->fib_main;
    else return;
    if( msg->op==FD_IPROUTE_OP_UPSERT && FD_UNLIKELY( !fd_fib4_insert( fib, msg->dst_addr, msg->prefix, msg->prio, &msg->hop ) ) ) {
      FD_LOG_WARNING(( "route update dropped: route table full (increase [net.max_routes] or [net.max_peer_routes])" ));
      if( FD_UNLIKELY( ctx->net_tile_id==0U ) ) {
        fd_netlink_route4_sync( ctx->neigh4_solicit, fd_frag_meta_ts_comp( fd_tickcount() ) );
      }
    }
    else if( msg->op==FD_IPROUTE_OP_DELETE ) fd_fib4_remove( fib, msg->dst_addr, msg->prefix, msg->prio );
    return;
  }

  /* Current send operation */

  uchar *    frame   = ctx->tx_op.frame;
  uint       xsk_idx = ctx->tx_op.xsk_idx;

  /* Select Ethernet addresses */
  memcpy( frame, ctx->tx_op.mac_addrs, 12 );

  uchar * iphdr = frame + sizeof(fd_eth_hdr_t);

  if( ctx->tx_op.use_gre ) {

    /* For GRE packets, the ethertype will always be FD_ETH_HDR_TYPE_IP. outer source ip can't be 0 */
    if( FD_UNLIKELY( ctx->tx_op.gre_outer_src_ip==0 ) ) {
      ctx->metrics.tx_gre_route_fail_cnt++;
      return;
    }

    /* Write the last two bytes for eth_hdr */
    FD_STORE( ushort, frame+12, fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );

    uchar * outer_iphdr       = frame + sizeof(fd_eth_hdr_t);
    uchar * gre_hdr           = outer_iphdr + sizeof(fd_ip4_hdr_t);
    uchar * inner_iphdr       = gre_hdr + sizeof(fd_gre_hdr_t);

    /* outer hdr + gre hdr + inner net_tot_len */
    ushort  outer_net_tot_len = (ushort)( sizeof(fd_ip4_hdr_t) + sizeof(fd_gre_hdr_t) + fd_ushort_bswap( ( (fd_ip4_hdr_t *)inner_iphdr )->net_tot_len ) );

    /* Construct outer ip header */
    fd_ip4_hdr_t ip4_outer = (fd_ip4_hdr_t) {
      .verihl       = FD_IP4_VERIHL( 4,5 ),
      .tos          = 0,
      .net_tot_len  = fd_ushort_bswap( outer_net_tot_len ),
      .net_id       = 0,
      .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
      .ttl          = 64,
      .protocol     = FD_IP4_HDR_PROTOCOL_GRE,
      .check        = 0,
      .saddr        = ctx->tx_op.gre_outer_src_ip,
      .daddr        = ctx->tx_op.gre_outer_dst_ip,
    };
    ip4_outer.check = fd_ip4_hdr_check_fast( &ip4_outer );
    FD_STORE( fd_ip4_hdr_t, outer_iphdr, ip4_outer );

    /* Construct gre header */
    fd_gre_hdr_t gre_hdr_ = {
      .flags_version = FD_GRE_HDR_FLG_VER_BASIC,
      .protocol      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
    };
    FD_STORE( fd_gre_hdr_t, gre_hdr, gre_hdr_ );

    iphdr   = inner_iphdr;
    sz      = sizeof(fd_eth_hdr_t) + outer_net_tot_len;
    xsk_idx = 0;
  }

  /* Construct (inner) ip header */
  uint   ihl       = FD_IP4_GET_LEN( *(fd_ip4_hdr_t *)iphdr );
  uint   ver       = FD_IP4_GET_VERSION( *(fd_ip4_hdr_t *)iphdr );
  uint   ip4_saddr = FD_LOAD( uint, iphdr+12 );
  ushort ethertype = FD_LOAD( ushort, frame+12 );

  if( FD_UNLIKELY( ethertype!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) {
    FD_LOG_CRIT(( "in link %lu attempted to send packet with invalid ethertype %04x",
                  in_idx, fd_ushort_bswap( ethertype ) ));
  }

  if( FD_UNLIKELY( ver!=0x4 ) ) {
    FD_LOG_WARNING(( "in_idx %lu: invalid IP version (%u)", in_idx, ver ));
    ctx->metrics.tx_invalid_cnt++;
    return;
  }

  if( FD_UNLIKELY( ihl<sizeof(fd_ip4_hdr_t) ||
                   (sizeof(fd_eth_hdr_t)+ihl)>sz ) ) {
    FD_LOG_WARNING(( "in_idx %lu: invalid IHL (%u)", in_idx, ihl ));
    ctx->metrics.tx_invalid_cnt++;
    return;
  }

  if( ip4_saddr==0 ) {
    if( FD_UNLIKELY( ctx->tx_op.src_ip==0 ) ) {
      /* Outgoing IPv4 packet with unknown src IP or invalid IHL */
      ctx->metrics.tx_route_fail_cnt[ FD_METRICS_ENUM_ROUTE_FAIL_V_SOURCE_IP_IDX ]++;
      return;
    }
    /* Recompute checksum after changing header */
    FD_STORE( uint,   iphdr+12, ctx->tx_op.src_ip );
    FD_STORE( ushort, iphdr+10, 0 );
    FD_STORE( ushort, iphdr+10, fd_ip4_hdr_check( iphdr ) );
  }

  /* Submit packet TX job

     Invariant for ring_tx: prod-cons<length
     (This invariant breaks if any other packet is sent over this ring
     between before_frag and this point, e.g. send_arp_probe.) */

  fd_xsk_t      * xsk     = &ctx->xsk[ xsk_idx ];
  fd_xdp_ring_t * tx_ring = &xsk->ring_tx;
  uint            tx_seq  = tx_ring->cached_prod;
  uint            tx_mask = tx_ring->depth - 1U;
  xsk->ring_tx.packet_ring[ tx_seq&tx_mask ] = (struct xdp_desc) {
    .addr    = (ulong)frame - (ulong)ctx->umem,
    .len     = (uint)sz,
    .options = 0
  };

  /* Frame is now owned by kernel. Clear tx_op. */
  ctx->tx_op.frame = NULL;

  /* Register newly enqueued packet */
  tx_ring->cached_prod = tx_seq+1U;
  ctx->metrics.tx_submit_cnt++;
  ctx->metrics.tx_bytes_total += sz;
  if( ctx->tx_op.use_gre ) ctx->metrics.tx_gre_cnt++;
  fd_net_flusher_inc( ctx->tx_flusher+xsk_idx, fd_tickcount() );
}

/* net_rx_packet is called when a new Ethernet frame is available.
   Attempts to copy out the frame to a downstream tile. */

static void
net_rx_packet( fd_net_ctx_t * ctx,
               ulong          umem_off,
               ulong          sz,
               uint *         freed_chunk ) {

  if( FD_UNLIKELY( sz<sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) ) {
    FD_DTRACE_PROBE( net_tile_err_rx_undersz );
    ctx->metrics.rx_undersz_cnt++;
    return;
  }

  uchar        * packet     = (uchar *)ctx->umem + umem_off;
  uchar const  * packet_end = packet + sz;
  fd_ip4_hdr_t * iphdr      = (fd_ip4_hdr_t *)(packet + sizeof(fd_eth_hdr_t));

  if( FD_UNLIKELY( ((fd_eth_hdr_t *)packet)->net_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) return;

  int is_packet_gre = 0;
  /* Discard the GRE overhead (outer iphdr and gre hdr) */
  if( iphdr->protocol == FD_IP4_HDR_PROTOCOL_GRE ) {
    if( FD_UNLIKELY( !ctx->gre_tunnel_ip[0] ) ) { /* if the first entry is 0, they all are */
      ctx->metrics.rx_gre_ignored_cnt++;
      return;
    }
    ulong gre_ipver = FD_IP4_GET_VERSION( *iphdr );
    ulong gre_iplen = FD_IP4_GET_LEN( *iphdr );
    if( FD_UNLIKELY( gre_ipver!=0x4 || gre_iplen<20 ) ) {
      FD_DTRACE_PROBE( net_tile_err_rx_noip );
      ctx->metrics.rx_gre_inv_pkt_cnt++; /* drop IPv6 packets */
      return;
    }

    int found = 0;
    for( ulong i=0UL; i<MAX_GRE_CNT; i++ ) found |= (iphdr->saddr==ctx->gre_tunnel_ip[i]);
    if( FD_UNLIKELY( (!found) | (iphdr->saddr==0U) ) ) {
      ctx->metrics.rx_src_addr_invalid_cnt++;
      return;
    }

    ulong overhead = gre_iplen + sizeof(fd_gre_hdr_t);
    if( FD_UNLIKELY( (uchar *)iphdr+overhead+sizeof(fd_ip4_hdr_t)>packet_end ) ) {
      FD_DTRACE_PROBE( net_tile_err_rx_undersz );
      ctx->metrics.rx_undersz_cnt++;  /* inner ip4 header invalid */
      return;
    }

    /* The new iphdr is where the inner iphdr was. Copy over the eth_hdr */
    iphdr              = (fd_ip4_hdr_t *)((uchar *)iphdr + overhead);
    uchar * new_packet = (uchar *)iphdr - sizeof(fd_eth_hdr_t);
    fd_memcpy( new_packet, packet, sizeof(fd_eth_hdr_t) );
    sz                 -= overhead;
    packet             = new_packet;
    umem_off           = (ulong)( packet - (uchar *)ctx->umem );
    is_packet_gre      = 1;
  }

  /* Translate packet to UMEM frame index */
  ulong chunk       = ctx->umem_chunk0 + (umem_off>>FD_CHUNK_LG_SZ);
  ulong ctl         = umem_off & 0x3fUL;

  /* Filter for UDP/IPv4 packets. */
  ulong ipver = FD_IP4_GET_VERSION( *iphdr );
  ulong iplen = FD_IP4_GET_LEN    ( *iphdr );
  if( FD_UNLIKELY( ipver!=0x4 || iplen<20 ||
                   iphdr->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) {
    FD_DTRACE_PROBE( net_tile_err_rx_noip );
    ctx->metrics.rx_undersz_cnt++; /* drop IPv6 packets */
    return;
  }

  uchar const * udp = (uchar *)iphdr + iplen;
  if( FD_UNLIKELY( udp+sizeof(fd_udp_hdr_t) > packet_end ) ) {
    FD_DTRACE_PROBE( net_tile_err_rx_undersz );
    ctx->metrics.rx_undersz_cnt++;
    return;
  }

  fd_udp_hdr_t const * udp_hdr = (fd_udp_hdr_t const *)udp;
  ulong        const   udp_sz  = fd_ushort_bswap( udp_hdr->net_len );
  if( FD_UNLIKELY( (udp_sz<sizeof(fd_udp_hdr_t)) | (udp+udp_sz>packet_end) ) ) {
    FD_DTRACE_PROBE( net_tile_err_rx_undersz );
    ctx->metrics.rx_undersz_cnt++;
    return;
  }

  /* Extract IP dest addr and UDP src/dest port */
  uint   ip_srcaddr   =  iphdr->saddr;
  ushort udp_srcport  =  fd_ushort_bswap( udp_hdr->net_sport );
  ushort udp_dstport  =  fd_ushort_bswap( udp_hdr->net_dport );

  if( FD_UNLIKELY( fd_ip4_addr_is_mcast( ip_srcaddr ) ) ) {
    ctx->metrics.rx_src_addr_invalid_cnt++;
    return;
  }

  FD_DTRACE_PROBE_4( net_tile_pkt_rx, ip_srcaddr, udp_srcport, udp_dstport, sz );

  /* Route packet to downstream tile */
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
    out = ctx->gossvf_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->repair_client_listen_port ) ) {
    proto = DST_PROTO_REPAIR;
    if( FD_UNLIKELY( sz == REPAIR_PING_SZ ) ) out = ctx->repair_out; /* ping-pong */
    else                                      out = ctx->shred_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->repair_serve_listen_port ) ) {
    if( FD_UNLIKELY( !ctx->rserve_enabled ) ) return;
    proto = DST_PROTO_RSERVE;
    out = ctx->rserve_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->txsend_src_port ) ) {
    proto = DST_PROTO_SEND;
    out = ctx->txsend_out;
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
                  ctx->repair_client_listen_port,
                  ctx->repair_serve_listen_port ));
  }

  /* tile can decide how to partition based on src ip addr and src port */
  ulong sig              = fd_disco_netmux_sig( ip_srcaddr, udp_srcport, ip_srcaddr, proto, 14UL+8UL+iplen );

  /* Peek the mline for an old frame */
  fd_frag_meta_t * mline = out->mcache + fd_mcache_line_idx( out->seq, out->depth );
  *freed_chunk           = mline->chunk;

  /* Overwrite the mline with the new frame */
  ulong tspub            = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
# if FD_HAS_AVX
  fd_mcache_publish_avx( out->mcache, out->depth, out->seq, sig, chunk, sz, ctl, 0, tspub );
# else
  fd_mcache_publish( out->mcache, out->depth, out->seq, sig, chunk, sz, ctl, 0, tspub );
# endif

  /* Wind up for the next iteration */
  out->seq               = fd_seq_inc( out->seq, 1UL );

  if( is_packet_gre ) ctx->metrics.rx_gre_cnt++;
  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += sz;
}

/* net_comp_event is called when an XDP TX frame is free again. */

static void
net_comp_event( fd_net_ctx_t * ctx,
                fd_xsk_t *     xsk,
                uint           comp_seq ) {

  /* Locate the incoming frame */

  fd_xdp_ring_t * comp_ring  = &xsk->ring_cr;
  uint            comp_mask  = comp_ring->depth - 1U;
  ulong           frame      = FD_VOLATILE_CONST( comp_ring->frame_ring[ comp_seq&comp_mask ] );
  ulong const     frame_mask = FD_NET_MTU - 1UL;
  FD_STATIC_ASSERT( FD_ULONG_IS_POW2( FD_NET_MTU ), "FD_NET_MTU must be a power of two" );
  if( FD_UNLIKELY( frame+FD_NET_MTU > ctx->umem_sz ) ) {
    FD_LOG_ERR(( "Bounds check failed: frame=0x%lx umem_sz=0x%lx",
                 frame, (ulong)ctx->umem_sz ));
  }

  /* Check if we have space to return the freed frame */

  fd_net_free_ring_t * free      = &ctx->free_tx;
  ulong                free_prod = free->prod;
  ulong                free_mask = free->depth - 1UL;
  ulong                free_cons = free->cons;
  long                 free_cnt = fd_seq_diff( free_prod, free_cons );
  FD_TEST( free_prod >= free_cons );
  if( FD_UNLIKELY( free_cnt>=(long)free->depth ) ) return; /* blocked */

  free->queue[ free_prod&free_mask ] = (ulong)ctx->umem + (frame & (~frame_mask));
  free->prod = fd_seq_inc( free_prod, 1UL );

  /* Wind up for next iteration */

  comp_ring->cached_cons = comp_seq+1U;
  ctx->metrics.tx_complete_cnt++;
}

/* net_rx_event is called when a new XDP RX frame is available.  Calls
   net_rx_packet, then returns the packet back to the kernel via the fill
   ring.  */

static void
net_rx_event( fd_net_ctx_t * ctx,
              fd_xsk_t *     xsk,
              uint           rx_seq ) {
  /* Locate the incoming frame */

  fd_xdp_ring_t * rx_ring = &xsk->ring_rx;
  uint            rx_mask = rx_ring->depth - 1U;
  struct xdp_desc frame   = FD_VOLATILE_CONST( rx_ring->packet_ring[ rx_seq&rx_mask ] );

  if( FD_UNLIKELY( frame.len>FD_NET_MTU ) )
    FD_LOG_ERR(( "received a UDP packet with a too large payload (%u)", frame.len ));

  /* Check if we have space in the fill ring to free the frame */

  fd_xdp_ring_t * fill_ring  = &xsk->ring_fr;
  if( FD_UNLIKELY( fd_xdp_ring_full( fill_ring ) ) ) {
    ctx->metrics.rx_fill_blocked_cnt++;
    return; /* blocked */
  }

  /* Pass it to the receive handler */

  uint freed_chunk = (uint)( ctx->umem_chunk0 + (frame.addr>>FD_CHUNK_LG_SZ) );
  net_rx_packet( ctx, frame.addr, frame.len, &freed_chunk );
  FD_COMPILER_MFENCE();
  rx_ring->cached_cons = rx_seq+1U;

  /* Every RX operation returns one frame to the FILL ring.  If the
     packet was forwarded to a downstream ring, the newly shadowed frame
     is returned.  Otherwise, the frame just received is returned. */

  if( FD_UNLIKELY( ( freed_chunk < ctx->umem_chunk0 ) |
                    ( freed_chunk > ctx->umem_wmark ) ) ) {
    FD_LOG_CRIT(( "mcache corruption detected: chunk=%u chunk0=%u wmark=%u",
                  freed_chunk, ctx->umem_chunk0, ctx->umem_wmark ));
  }

  FD_STATIC_ASSERT( FD_ULONG_IS_POW2( FD_NET_MTU ), "FD_NET_MTU must be a power of two" );
  uint  fill_prod  = fill_ring->cached_prod;
  uint  fill_mask  = (fill_ring->depth)-1U;
  ulong frame_mask = FD_NET_MTU - 1UL;
  ulong freed_off  = (freed_chunk - ctx->umem_chunk0)<<FD_CHUNK_LG_SZ;
  fill_ring->frame_ring[ fill_prod&fill_mask ] = freed_off & (~frame_mask);
  fill_ring->cached_prod = fill_prod+1U;
}

static void
before_credit_softirq( fd_net_ctx_t *      ctx,
                       int *               charge_busy,
                       uint                rr_idx,
                       fd_xsk_t *          rr_xsk ) {

  net_tx_periodic_wakeup( ctx, rr_idx, fd_tickcount(), charge_busy );

  /* Fire RX event if we have RX desc avail */
  if( !fd_xdp_ring_empty( &rr_xsk->ring_rx, FD_XDP_RING_ROLE_CONS ) ) {
    *charge_busy = 1;
    net_rx_event( ctx, rr_xsk, rr_xsk->ring_rx.cached_cons );
  } else {
    net_rx_wakeup( ctx, rr_xsk, charge_busy );

    /* Iterate onto the next NAPI queue. */
    ctx->rr_idx++;
    ctx->rr_idx = fd_uint_if( ctx->rr_idx>=ctx->xsk_cnt, 0, ctx->rr_idx );
  }
}

static int
net_prefbusy_poll_ready( fd_xsk_t *         rr_xsk,
                         fd_net_flusher_t * flusher,
                         long               now ) {

  if( FD_LIKELY( now < ( flusher->prefbusy_last_poll_ticks + flusher->prefbusy_min_interval_ticks ) ) ) return 0;
  if( FD_UNLIKELY( now > ( flusher->prefbusy_last_poll_ticks + flusher->prefbusy_stall_timeout_ticks ) ) ) return 1;

  int rx_empty = fd_xdp_ring_empty( &rr_xsk->ring_rx, FD_XDP_RING_ROLE_CONS );

  return rx_empty;
}

static void
net_prefbusy_poll_flush( fd_net_flusher_t * flusher,
                         long               now ) {
  flusher->prefbusy_last_poll_ticks = now;
}

static void
before_credit_prefbusy( fd_net_ctx_t *      ctx,
                        int *               charge_busy,
                        uint                rr_idx,
                        fd_xsk_t *          rr_xsk ) {

  fd_net_flusher_t * flusher = ctx->tx_flusher+rr_idx;
  if( FD_UNLIKELY( net_prefbusy_poll_ready( rr_xsk, flusher, fd_tickcount() ) ) ) {
    /* NAPI needs to be polled to process new TX from
       Firedancer's net tile and process new RX from the NIC. */

    FD_VOLATILE( *rr_xsk->ring_tx.prod ) = rr_xsk->ring_tx.cached_prod; /* write-back local copies to fseqs */
    FD_VOLATILE( *rr_xsk->ring_cr.cons ) = rr_xsk->ring_cr.cached_cons;
    FD_VOLATILE( *rr_xsk->ring_rx.cons ) = rr_xsk->ring_rx.cached_cons;
    FD_VOLATILE( *rr_xsk->ring_fr.prod ) = rr_xsk->ring_fr.cached_prod;

    if( FD_UNLIKELY( -1==sendto( rr_xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0 ) ) ) {
      if( FD_UNLIKELY( net_is_fatal_xdp_error( errno ) ) ) {
        FD_LOG_ERR(( "xsk sendto failed xsk_fd=%d (%i-%s)", rr_xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
      }
      if( FD_UNLIKELY( errno!=EAGAIN ) ) {
        long ts = fd_log_wallclock();
        if( ts > rr_xsk->log_suppress_until_ns ) {
          FD_LOG_WARNING(( "xsk sendto failed xsk_fd=%d (%i-%s)", rr_xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
          rr_xsk->log_suppress_until_ns = ts + (long)1e9;
        }
      }
    }
    /* Since xsk sendmsg in prefbusy mode drives both rx and tx, both are incremented */
    ctx->metrics.xsk_tx_wakeup_cnt++;
    ctx->metrics.xsk_rx_wakeup_cnt++;

    net_prefbusy_poll_flush( flusher, fd_tickcount() );
  }

  /* Process new RX from xsk ring if there is any. */
  if( !fd_xdp_ring_empty( &rr_xsk->ring_rx, FD_XDP_RING_ROLE_CONS ) ) {
    *charge_busy = 1;
    net_rx_event( ctx, rr_xsk, rr_xsk->ring_rx.cached_cons );
  }
  /* Iterate onto the next NAPI queue. */
  ctx->rr_idx++;
  ctx->rr_idx = fd_uint_if( ctx->rr_idx>=ctx->xsk_cnt, 0, ctx->rr_idx );
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
    fd_net_free_ring_t * free      = &ctx->free_tx;
    ulong                alloc_seq = free->prod;
    free->queue[ alloc_seq % free->depth ] = (ulong)ctx->tx_op.frame;
    free->prod = fd_seq_inc( alloc_seq, 1UL );
    ctx->tx_op.frame = NULL;
  }

  /* Check if new packets are available or if TX frames are free again
     (Round-robin through sockets) */

  uint       rr_idx = ctx->rr_idx;
  fd_xsk_t * rr_xsk = &ctx->xsk[ rr_idx ];

  if( FD_LIKELY( !rr_xsk->prefbusy_poll_enabled ) ) {
    /* Default poll mode which relies on irqs and wakeups */
    before_credit_softirq( ctx, charge_busy, rr_idx, rr_xsk );
  } else {
    before_credit_prefbusy( ctx, charge_busy, rr_idx, rr_xsk );
  }

  /* Fire comp event if we have comp desc avail */
  if( !fd_xdp_ring_empty( &rr_xsk->ring_cr, FD_XDP_RING_ROLE_CONS ) ) {
    *charge_busy = 1;
    net_comp_event( ctx, rr_xsk, rr_xsk->ring_cr.cached_cons );
  }
}

/* net_xsk_bootstrap assigns UMEM frames to the FILL ring. */

static ulong
net_xsk_bootstrap( fd_net_ctx_t * ctx,
                   uint           xsk_idx,
                   ulong          frame_off ) {
  fd_xsk_t * xsk = &ctx->xsk[ xsk_idx ];

  ulong const frame_sz  = FD_NET_MTU;
  ulong const fr_depth  = ctx->xsk[ xsk_idx ].ring_fr.depth/2UL;

  fd_xdp_ring_t * fill      = &xsk->ring_fr;
  uint            fill_prod = fill->cached_prod;
  for( ulong j=0UL; j<fr_depth; j++ ) {
    fill->frame_ring[ j ] = frame_off;
    frame_off += frame_sz;
  }
  FD_VOLATILE( *fill->prod ) = fill->cached_prod = fill_prod + (uint)fr_depth;

  return frame_off;
}

/* FIXME source MAC address from netlnk tile instead */

static void
interface_addrs( const char * interface,
                 uchar *      mac,
                 uint *       ip4_addr ) {
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  struct ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;

  strncpy( ifr.ifr_name, interface, IFNAMSIZ );
  if( FD_UNLIKELY( ioctl( fd, SIOCGIFHWADDR, &ifr ) ) )
    FD_LOG_ERR(( "could not get MAC address of interface `%s`: (%i-%s)", interface, errno, fd_io_strerror( errno ) ));
  fd_memcpy( mac, ifr.ifr_hwaddr.sa_data, 6 );

  if( FD_UNLIKELY( ioctl( fd, SIOCGIFADDR, &ifr ) ) )
    FD_LOG_ERR(( "could not get IP address of interface `%s`: (%i-%s)", interface, errno, fd_io_strerror( errno ) ));
  *ip4_addr = ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;

  if( FD_UNLIKELY( close(fd) ) )
    FD_LOG_ERR(( "could not close socket (%i-%s)", errno, fd_io_strerror( errno ) ));
}

/* privileged_init does the following initialization steps:

   - Create an AF_XDP socket
   - Map XDP metadata rings
   - Register UMEM data region with socket
   - Insert AF_XDP socket into xsk_map

   Net tile 0 also runs fd_xdp_install and repeats the above step for
   the loopback device.  (Unless the main interface is already loopback)

   Kernel object references:

     BPF_LINK file descriptor
      |
      +-> XDP program installation on NIC
      |    |
      |    +-> XDP program <-- BPF_PROG file descriptor (prog_fd)
      |
      +-> XSKMAP object <-- BPF_MAP file descriptor (xsk_map) */

FD_FN_UNUSED static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );
  ulong *        free_tx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->xdp.free_ring_depth * sizeof(ulong) );;

  fd_memset( ctx, 0, sizeof(fd_net_ctx_t) );

  interface_addrs( tile->xdp.if_virt, ctx->src_mac_addr, &ctx->default_address );
  ctx->if_virt = if_nametoindex( tile->xdp.if_virt ); FD_TEST( ctx->if_virt );

  /* Load up dcache containing UMEM */

  void * const dcache_mem          = fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id );
  void * const umem                = fd_dcache_join( dcache_mem );
  ulong  const umem_dcache_data_sz = fd_dcache_data_sz( umem );
  ulong  const umem_frame_sz       = 2048UL;
  ulong  const umem_sz             = fd_ulong_align_dn( umem_dcache_data_sz, umem_frame_sz );

  /* Derive chunk bounds */

  void * const umem_base   = fd_wksp_containing( dcache_mem );
  ulong  const umem_chunk0 = ( (ulong)umem - (ulong)umem_base )>>FD_CHUNK_LG_SZ;
  ulong  const umem_wmark  = umem_chunk0 + ( ( umem_sz-umem_frame_sz )>>FD_CHUNK_LG_SZ );

  if( FD_UNLIKELY( umem_chunk0>UINT_MAX || umem_wmark>UINT_MAX || umem_chunk0>umem_wmark ) ) {
    FD_LOG_ERR(( "Calculated invalid UMEM bounds [%lu,%lu]", umem_chunk0, umem_wmark ));
  }

  if( FD_UNLIKELY( !umem_base ) ) FD_LOG_ERR(( "UMEM dcache is not in a workspace" ));

  ctx->umem        = umem;
  ctx->umem_sz     = umem_sz;
  ctx->umem_chunk0 = (uint)umem_chunk0;
  ctx->umem_wmark  = (uint)umem_wmark;

  ctx->free_tx.queue = free_tx;
  ctx->free_tx.depth = tile->xdp.xdp_tx_queue_size;

  /* Create and install XSKs */

  uint if_phys_if_idx = if_nametoindex( tile->xdp.if_phys );
  if( FD_UNLIKELY( !if_phys_if_idx ) ) FD_LOG_ERR(( "if_nametoindex(%s) failed", tile->xdp.if_phys ));

  fd_xsk_params_t params0 = {
    .if_idx      = if_phys_if_idx,
    .if_queue_id = tile->xdp.if_queue,

    /* Some kernels produce EOPNOTSUP errors on sendto calls when
       starting up without either XDP_ZEROCOPY or XDP_COPY
       (e.g. 5.14.0-503.23.1.el9_5 with i40e) */
    .bind_flags  = tile->xdp.zero_copy ? XDP_ZEROCOPY : XDP_COPY,

    .prefbusy_time_budget_micros = PREFBUSY_TIME_BUDGET_MICROS,

    .prefbusy_rx_budget = PREFBUSY_RX_BUDGET,

    .fr_depth  = tile->xdp.xdp_rx_queue_size*2,
    .rx_depth  = tile->xdp.xdp_rx_queue_size,
    .cr_depth  = tile->xdp.xdp_tx_queue_size,
    .tx_depth  = tile->xdp.xdp_tx_queue_size,

    .umem_addr = umem,
    .frame_sz  = umem_frame_sz,
    .umem_sz   = umem_sz,

    .core_dump = tile->xdp.xsk_core_dump,
  };

  fd_cstr_ncpy( params0.poll_mode, tile->xdp.poll_mode, sizeof(params0.poll_mode) );

  /* Re-derive XDP file descriptors */

  fd_xdp_fds_t xdp_fds[ FD_TOPO_XDP_FDS_MAX ];
  uint         xdp_fds_cnt = FD_TOPO_XDP_FDS_MAX;
  fd_topo_install_xdp( topo, xdp_fds, &xdp_fds_cnt, 0U, /* dry_run */ 1 );

  int xsk_map_fd = -1;
  for( uint i=0U; i<xdp_fds_cnt; i++ ) {
    if( xdp_fds[ i ].if_idx==if_phys_if_idx ) {
      xsk_map_fd              = xdp_fds[ i ].xsk_map_fd;
      ctx->prog_link_fds[ 0 ] = xdp_fds[ i ].prog_link_fd;
      xdp_fds[ i ].prog_link_fd = -1; /* mark as used */
      break;
    }
  }
  FD_TEST( xsk_map_fd>=0 );

  /* Init XSK */
  if( FD_UNLIKELY( !fd_xsk_init( &ctx->xsk[ 0 ], &params0 ) ) )       FD_LOG_ERR(( "failed to bind xsk for net tile %lu", tile->kind_id ));
  if( FD_UNLIKELY( !fd_xsk_activate( &ctx->xsk[ 0 ], xsk_map_fd ) ) ) FD_LOG_ERR(( "failed to activate xsk for net tile %lu", tile->kind_id ));
  ctx->xsk_cnt = 1;

  /* Networking tile at index 0 also binds to loopback (only queue 0 available on lo) */

  if( FD_UNLIKELY( strcmp( tile->xdp.if_virt, "lo" ) && !tile->kind_id ) ) {
    ctx->xsk_cnt = 2;

    uint lo_idx = if_nametoindex( "lo" );
    if( FD_UNLIKELY( !lo_idx ) ) FD_LOG_ERR(( "if_nametoindex(lo) failed" ));

    int lo_xsk_map_fd = -1;
    for( uint i=0U; i<xdp_fds_cnt; i++ ) {
      if( xdp_fds[ i ].if_idx==lo_idx ) {
        lo_xsk_map_fd           = xdp_fds[ i ].xsk_map_fd;
        ctx->prog_link_fds[ 1 ] = xdp_fds[ i ].prog_link_fd;
        xdp_fds[ i ].prog_link_fd = -1; /* mark as used */
        break;
      }
    }
    FD_TEST( lo_xsk_map_fd>=0 );

    /* init xsk 1 */
    fd_xsk_params_t params1 = params0;
    params1.if_idx      = lo_idx; /* probably always 1 */
    params1.if_queue_id = 0;
    params1.bind_flags  = 0;
    if( FD_UNLIKELY( !fd_xsk_init( &ctx->xsk[ 1 ], &params1 ) ) )          FD_LOG_ERR(( "failed to bind lo_xsk" ));
    if( FD_UNLIKELY( !fd_xsk_activate( &ctx->xsk[ 1 ], lo_xsk_map_fd ) ) ) FD_LOG_ERR(( "failed to activate lo_xsk" ));
  }

  /* Close unused XDP fds */

  if( FD_UNLIKELY( fd_sandbox_gettid()==fd_sandbox_getpid() ) ) {
    /* Kind of gross.. in single threaded mode we don't want to close the xsk_map_fd
       since it's shared with other net tiles.  Just check for that by seeing if we
       are the only thread in the process. */
    for( uint i=0U; i<xdp_fds_cnt; i++ ) {
      if( -1==close( xdp_fds[ i ].xsk_map_fd ) ) {
        FD_LOG_ERR(( "close(%d) failed (%d-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));
      }
      if( xdp_fds[ i ].prog_link_fd>0 &&
          -1==close( xdp_fds[ i ].prog_link_fd ) ) {
        FD_LOG_ERR(( "close(%d) failed (%d-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));
      }
    }
  }

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ctx->xdp_stats_interval_ticks = (long)( FD_XDP_STATS_INTERVAL_NS * tick_per_ns );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
init_device_table( fd_net_ctx_t * ctx,
                   void *         netdev_tbl_shm,
                   void *         netdev_tbl_local ) {
  FD_TEST( fd_netdev_tbl_join( &ctx->netdev_shared, netdev_tbl_shm ) );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->netdev_tbl, netdev_tbl_local ) );
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );
  FD_TEST( ctx->xsk_cnt!=0 );
  FD_TEST( ctx->free_tx.queue!=NULL );
  (void)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->xdp.free_ring_depth * sizeof(ulong) );
  void * netdev_tbl_local = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * fib_local_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->xdp.route_max, tile->xdp.route_peer_max ) );
  void * fib_main_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_align(), fd_fib4_footprint( tile->xdp.route_max, tile->xdp.route_peer_max ) );
  FD_TEST( fd_fib4_join( ctx->fib_local,         fd_fib4_new( fib_local_mem,         tile->xdp.route_max, tile->xdp.route_peer_max, tile->xdp.route_peer_seed ) ) );
  FD_TEST( fd_fib4_join( ctx->fib_main,          fd_fib4_new( fib_main_mem,          tile->xdp.route_max, tile->xdp.route_peer_max, tile->xdp.route_peer_seed ) ) );

  ctx->net_tile_id  = (uint)tile->kind_id;
  ctx->net_tile_cnt = (uint)fd_topo_tile_name_cnt( topo, tile->name );

  ctx->bind_address                   = tile->net.bind_address;
  ctx->shred_listen_port              = tile->net.shred_listen_port;
  ctx->quic_transaction_listen_port   = tile->net.quic_transaction_listen_port;
  ctx->legacy_transaction_listen_port = tile->net.legacy_transaction_listen_port;
  ctx->gossip_listen_port             = tile->net.gossip_listen_port;
  ctx->repair_client_listen_port      = tile->net.repair_client_listen_port;
  ctx->repair_serve_listen_port       = tile->net.repair_serve_listen_port;
  ctx->txsend_src_port                = tile->net.txsend_src_port;

  /* Put a bound on chunks we read from the input, to make sure they
     are within in the data region of the workspace. */

  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "net tile in link cnt is zero" ));
  if( FD_UNLIKELY( tile->in_cnt>MAX_NET_INS ) ) FD_LOG_ERR(( "net tile in link cnt %lu exceeds MAX_NET_INS %lu", tile->in_cnt, MAX_NET_INS ));
  FD_TEST( tile->in_cnt<=32 );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "iproute_out" ) ) ctx->in_kind[i] = IN_KIND_IPROUTE;
    else {
      ctx->in_kind[i] = IN_KIND_NET;
      if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "net tile in link %s does not have a normal MTU", link->name ));
    }

    ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ctx->rserve_enabled = 0;
  for( ulong i = 0; i < tile->out_cnt; i++ ) {
    fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ i  ] ];
    if( strcmp( out_link->name, "net_quic" ) == 0 ) {
      fd_topo_link_t const * quic_out = out_link;
      ctx->quic_out->mcache = quic_out->mcache;
      ctx->quic_out->sync   = fd_mcache_seq_laddr( ctx->quic_out->mcache );
      ctx->quic_out->depth  = fd_mcache_depth( ctx->quic_out->mcache );
      ctx->quic_out->seq    = fd_mcache_seq_query( ctx->quic_out->sync );
    } else if( strcmp( out_link->name, "net_shred" ) == 0 ) {
      fd_topo_link_t const * shred_out = out_link;
      ctx->shred_out->mcache = shred_out->mcache;
      ctx->shred_out->sync   = fd_mcache_seq_laddr( ctx->shred_out->mcache );
      ctx->shred_out->depth  = fd_mcache_depth( ctx->shred_out->mcache );
      ctx->shred_out->seq    = fd_mcache_seq_query( ctx->shred_out->sync );
    } else if( strcmp( out_link->name, "net_gossvf" ) == 0 ) {
      fd_topo_link_t const * gossip_out = out_link;
      ctx->gossvf_out->mcache = gossip_out->mcache;
      ctx->gossvf_out->sync   = fd_mcache_seq_laddr( ctx->gossvf_out->mcache );
      ctx->gossvf_out->depth  = fd_mcache_depth( ctx->gossvf_out->mcache );
      ctx->gossvf_out->seq    = fd_mcache_seq_query( ctx->gossvf_out->sync );
    } else if( strcmp( out_link->name, "net_repair" ) == 0 ) {
      fd_topo_link_t const * repair_out = out_link;
      ctx->repair_out->mcache = repair_out->mcache;
      ctx->repair_out->sync   = fd_mcache_seq_laddr( ctx->repair_out->mcache );
      ctx->repair_out->depth  = fd_mcache_depth( ctx->repair_out->mcache );
      ctx->repair_out->seq    = fd_mcache_seq_query( ctx->repair_out->sync );
    } else if( strcmp( out_link->name, "net_netlnk" ) == 0 ) {
      fd_topo_link_t const * netlink_out = out_link;
      ctx->neigh4_solicit->mcache = netlink_out->mcache;
      ctx->neigh4_solicit->depth  = fd_mcache_depth( ctx->neigh4_solicit->mcache );
      ctx->neigh4_solicit->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr( ctx->neigh4_solicit->mcache ) );
    } else if( strcmp( out_link->name, "net_txsend" ) == 0 ) {
      fd_topo_link_t const * txsend_out = out_link;
      ctx->txsend_out->mcache = txsend_out->mcache;
      ctx->txsend_out->sync   = fd_mcache_seq_laddr( ctx->txsend_out->mcache );
      ctx->txsend_out->depth  = fd_mcache_depth( ctx->txsend_out->mcache );
      ctx->txsend_out->seq    = fd_mcache_seq_query( ctx->txsend_out->sync );
    } else if( strcmp( out_link->name, "net_rserve" ) == 0 ) {
      fd_topo_link_t const * rserve_out = out_link;
      ctx->rserve_out->mcache = rserve_out->mcache;
      ctx->rserve_out->sync   = fd_mcache_seq_laddr( ctx->rserve_out->mcache );
      ctx->rserve_out->depth  = fd_mcache_depth( ctx->rserve_out->mcache );
      ctx->rserve_out->seq    = fd_mcache_seq_query( ctx->rserve_out->sync );
      ctx->rserve_enabled     = 1;
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
  } else if( FD_UNLIKELY( ctx->gossip_listen_port!=0 && ctx->gossvf_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "gossip listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->repair_client_listen_port!=0 && ctx->repair_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "repair intake port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->repair_serve_listen_port!=0 && ctx->repair_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "repair serve listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->neigh4_solicit->mcache==NULL ) ) {
    FD_LOG_ERR(( "netlink request link not found" ));
  } else if( FD_UNLIKELY( ctx->txsend_src_port!=0 && ctx->txsend_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "txsend listen port set but no out link was found" ));
  }

  for( uint j=0U; j<2U; j++ ) {
    ctx->tx_flusher[ j ].pending_wmark         = (ulong)( (double)tile->xdp.xdp_tx_queue_size * 0.7 );
    ctx->tx_flusher[ j ].tail_flush_backoff    = (long)( (double)tile->xdp.tx_flush_timeout_ns * fd_tempo_tick_per_ns( NULL ) );
    ctx->tx_flusher[ j ].next_tail_flush_ticks = LONG_MAX;

    ctx->tx_flusher[ j ].prefbusy_last_poll_ticks     = 0L;
    ctx->tx_flusher[ j ].prefbusy_min_interval_ticks  = (long)( PREFBUSY_MIN_INTERVAL_NS * fd_tempo_tick_per_ns( NULL ) );
    ctx->tx_flusher[ j ].prefbusy_stall_timeout_ticks = (long)( PREFBUSY_STALL_TIMEOUT_NS * fd_tempo_tick_per_ns( NULL ) );
  }

  ulong neigh4_obj_id = tile->xdp.neigh4_obj_id;
  ulong ele_max   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong probe_max = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong seed      = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  if( FD_UNLIKELY( (ele_max==ULONG_MAX) | (probe_max==ULONG_MAX) | (seed==ULONG_MAX) ) )
    FD_LOG_ERR(( "neigh4 hmap properties not set" ));
  if( FD_UNLIKELY( !fd_neigh4_hmap_join(
      ctx->neigh4,
      fd_topo_obj_laddr( topo, neigh4_obj_id ),
      ele_max,
      probe_max,
      seed ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  init_device_table( ctx, fd_topo_obj_laddr( topo, tile->xdp.netdev_tbl_obj_id ), netdev_tbl_local );

  /* Initialize TX free ring */

  ulong const frame_sz  = 2048UL;
  ulong       frame_off = 0UL;
  ulong const tx_depth  = ctx->free_tx.depth;
  for( ulong j=0; j<tx_depth; j++ ) {
    ctx->free_tx.queue[ j ] = (ulong)ctx->umem + frame_off;
    frame_off += frame_sz;
  }
  ctx->free_tx.prod = tx_depth;

  /* Initialize RX mcache chunks */

  for( ulong i=0UL; i<(tile->out_cnt); i++ ) {
    fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ i  ] ];
    fd_frag_meta_t * mcache = out_link->mcache;
    for( ulong j=0UL; j<fd_mcache_depth( mcache ); j++ ) {
      mcache[ j ].chunk = (uint)( ctx->umem_chunk0 + (frame_off>>FD_CHUNK_LG_SZ) );
      frame_off += frame_sz;
    }
  }

  /* Initialize FILL ring */

  int _charge_busy = 0;
  for( uint j=0U; j<ctx->xsk_cnt; j++ ) {
    frame_off = net_xsk_bootstrap( ctx, j, frame_off );
    net_rx_wakeup( ctx, &ctx->xsk[ j ], &_charge_busy );
    net_tx_wakeup( ctx, &ctx->xsk[ j ], &_charge_busy );
  }

  if( FD_UNLIKELY( frame_off > ctx->umem_sz ) ) {
    FD_LOG_ERR(( "UMEM is too small" ));
  }
}

FD_FN_UNUSED static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );

  /* A bit of a hack, if there is no loopback XSK for this tile, we still need to pass
     two "allow" FD arguments to the net policy, so we just make them both the same. */
  int allow_fd2 = ctx->xsk_cnt>1UL ? ctx->xsk[ 1 ].xsk_fd : ctx->xsk[ 0 ].xsk_fd;
  FD_TEST( ctx->xsk[ 0 ].xsk_fd >= 0 && allow_fd2 >= 0 );

  populate_sock_filter_policy_fd_xdp_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->xsk[ 0 ].xsk_fd, (uint)allow_fd2 );
  return sock_filter_policy_fd_xdp_tile_instr_cnt;
}

FD_FN_UNUSED static ulong
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

                                      out_fds[ out_cnt++ ] = ctx->xsk[ 0 ].xsk_fd;
                                      out_fds[ out_cnt++ ] = ctx->prog_link_fds[ 0 ];
  if( FD_LIKELY( ctx->xsk_cnt>1UL ) ) out_fds[ out_cnt++ ] = ctx->xsk[ 1 ].xsk_fd;
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

#include "../../stem/fd_stem.c"

#ifndef FD_TILE_TEST
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
#endif
