#include "../../netlink/fd_netlink_tile.h" /* neigh4_solicit */
#include "../../../waltz/ip/fd_fib4.h"
#include "../../../waltz/neigh/fd_neigh4_map.h"
#include "../../../waltz/xdp/fd_xdp_redirect_user.h" /* fd_xsk_activate */
#include "../../../waltz/xdp/fd_xsk.h"

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
} fd_net_out_ctx_t;

/* fd_net_free_ring is a FIFO queue that stores pointers to free XDP TX
   frames. */

struct fd_net_free_ring {
  ulong   prod;
  ulong   cons;
  ulong   depth;
  ulong * queue;
};
typedef struct fd_net_free_ring fd_net_free_ring_t;

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

struct fd_net_tile_ctx {
  /* An "XSK" is an AF_XDP socket */
  uint     xsk_cnt;
  fd_xsk_t xsk[ 2 ];
  int      prog_link_fds[ 2 ];

  /* UMEM frame region within dcache */
  void *   umem_frame0; /* First UMEM frame (>=umem_base) */
  ulong    umem_sz;     /* Usable UMEM size starting at frame0 */

  /* UMEM chunk region within workspace */
  void *   umem_base;   /* UMEM workspace base */
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
    uint   if_idx; /* 0: main interface, 1: loopback */
    void * frame;
    uchar  mac_addrs[12]; /* First 12 bytes of Ethernet header */
  } tx_op;

  /* Round-robin cycle serivce operations */
  uint rr_idx;

  /* Ring tracking free packet buffers */
  fd_net_free_ring_t free_tx;

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

  /* suppress log messages until this time */
  long log_suppress_until_ns;

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong rx_undersz_cnt;
    ulong rx_fill_blocked_cnt;
    ulong rx_backp_cnt;
    long  rx_busy_cnt;
    long  rx_idle_cnt;

    ulong tx_submit_cnt;
    ulong tx_complete_cnt;
    ulong tx_bytes_total;
    ulong tx_route_fail_cnt;
    ulong tx_no_xdp_cnt;
    ulong tx_neigh_fail_cnt;
    ulong tx_full_fail_cnt;
    long  tx_busy_cnt;
    long  tx_idle_cnt;

    ulong xsk_tx_wakeup_cnt;
    ulong xsk_rx_wakeup_cnt;
  } metrics;
};

typedef struct fd_net_tile_ctx fd_net_ctx_t;

struct xdp_statistics_v0 {
  ulong rx_dropped; /* Dropped for other reasons */
  ulong rx_invalid_descs; /* Dropped due to invalid descriptor */
  ulong tx_invalid_descs; /* Dropped due to invalid descriptor */
};

struct xdp_statistics_v1 {
  ulong rx_dropped; /* Dropped for other reasons */
  ulong rx_invalid_descs; /* Dropped due to invalid descriptor */
  ulong tx_invalid_descs; /* Dropped due to invalid descriptor */
  ulong rx_ring_full; /* Dropped due to rx ring being full */
  ulong rx_fill_ring_empty_descs; /* Failed to retrieve item from fill ring */
  ulong tx_ring_empty_descs; /* Failed to retrieve item from tx ring */
};

FD_PROTOTYPES_BEGIN

/* fd_xdp_tile_softirq_run runs a net tile main loop.  Assumes XDP
   sockets are in 'use wakeup' mode.  Coordinates with ksoftirqd
   threads.  Uses sendto() and recvmsg() syscalls for wakeups. */

void
fd_xdp_tile_softirq_run( fd_topo_t *      topo,
                         fd_topo_tile_t * tile );

/* fd_xdp_tile_poll_run runs a net tile main loop in busy polling mode.
   Assumes XDP sockets are configured to do preferred busy polling.
   Assumes NIC sysfs is configured to suppress IRQs.  Uses poll()
   syscall for wakeups. */

void
fd_xdp_tile_poll_run( fd_topo_t *      topo,
                      fd_topo_tile_t * tile );

FD_PROTOTYPES_END
