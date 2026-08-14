#ifndef HEADER_fd_src_disco_netlink_fd_netlink_tile_private_h
#define HEADER_fd_src_disco_netlink_fd_netlink_tile_private_h

#include "../../waltz/ip/fd_netlink1.h"
#include "../metrics/generated/fd_metrics_netlnk.h"
#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../../waltz/neigh/fd_neigh4_probe.h"

/* FD_NETLINK_TILE_CTX_MAGIC uniquely identifies a fd_netlink_tile_ctx_t.
   CHange this whenever the fd_netlink_tile_ctx_t struct changes. */

#define FD_NETLINK_TILE_CTX_MAGIC (0xb86244c543ddca5fUL) /* random */

struct fd_netlink_tile_ctx {
  ulong magic; /* ==FD_NETLINK_TILE_CTX_MAGIC */

  fd_netlink_t nl_monitor[1];
  fd_netlink_t nl_req[1];

  /* Pending actions */
  ulong action;
# define FD_NET_TILE_ACTION_ROUTE4_UPDATE (1UL<<0)
# define FD_NET_TILE_ACTION_LINK_UPDATE   (1UL<<1)
# define FD_NET_TILE_ACTION_NEIGH_UPDATE  (1UL<<2)

  /* Rate limit link and route table changes (in ticks) */
  long update_backoff;
  long route4_update_ts;
  long link_update_ts;

  /* Link table (shared, seqlock protected) */
  fd_netdev_tbl_join_t netdev_tbl[1];

  /* Route update output */
  void * out_mem;
  ulong  out_chunk;
  ulong  out_chunk0;
  ulong  out_wmark;
  ulong  route_max;
  ulong  route_peer_max;
  ulong  dump_route_cnt[2];
  ulong  dump_peer_cnt[2];
  int    dump_overflow;
  uint   dump_table_id;
  int    dump_active;
  int    dump_advance;
  int    dump_intr;
  fd_netlink_iter_t dump_iter[1];
  uchar             dump_buf[4096];

  /* A netlink datagram can contain multiple messages.  Retain the
     unprocessed suffix when a route publication consumes the last
     available Stem credit. */
  uchar monitor_buf[16384];
  long  monitor_buf_sz;
  long  monitor_buf_off;

  /* Neighbor table */
  fd_neigh4_hmap_t neigh4[1];   /* join to global map */
  uint             neigh4_ifidx;
  long             idle_cnt;

  /* Neighbor table prober */
  fd_neigh4_prober_t prober[1];

  struct {
    ulong link_full_syncs;
    ulong route_full_syncs;
    ulong update_cnt[ FD_METRICS_COUNTER_NETLNK_UPDATE_PROCESSED_CNT ];
    ulong neigh_solicits_sent;
    ulong neigh_solicits_fails;
  } metrics;
};

typedef struct fd_netlink_tile_ctx fd_netlink_tile_ctx_t;

#endif /* HEADER_fd_src_disco_netlink_fd_netlink_tile_private_h */
