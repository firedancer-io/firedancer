#ifndef HEADER_fd_src_app_firedancer_commands_monitor_gossip_gossip_diag_h
#define HEADER_fd_src_app_firedancer_commands_monitor_gossip_gossip_diag_h

#include "../../../shared/fd_config.h"
#include "../../../../disco/topo/fd_topo.h"
#include "../../../../disco/metrics/fd_metrics.h"

/* fd_gossip_diag provides shared gossip diagnostic display logic that
   can be used both by the standalone gossip command (which launches its
   own topology) and the monitor-gossip command (which attaches to a
   running validator's shared memory). */

/* fd_gossip_diag_gossvf_t holds per-gossvf-tile state. */

typedef struct {
  ulong                tile_count;
  fd_topo_tile_t **    tiles;
  volatile ulong **    metrics;
  ulong **             prev_metrics;
  volatile ulong **    net_links;
} fd_gossip_diag_gossvf_t;

/* fd_gossip_diag_ctx_t holds all state needed by the gossip
   diagnostic display loop.  Members are populated by
   fd_gossip_diag_init and then used by fd_gossip_diag_render. */

typedef struct {
  fd_topo_t *                 topo;
  config_t *                  config;

  fd_topo_tile_t *            gossip_tile;
  volatile ulong *            gossip_metrics;
  ulong *                     gossip_prev;

  fd_gossip_diag_gossvf_t     gossvf;

  ulong                       net_tile_cnt;
  volatile ulong const **     net_metrics;
  ulong *                     prev_net_tx_bytes;
  ulong *                     prev_net_rx_bytes;

  volatile ulong *            net0_link;
  ulong                       prev_net0_rx_bytes;

  int                         is_xdp;

  /* Return values from last render */
  ulong                       last_total_crds;
  ulong                       last_total_contact_infos;
} fd_gossip_diag_ctx_t;

struct rx_deltas {
  ulong pull_request_rx;
  ulong pull_request_rx_drop;
  ulong pull_request_rx_bytes;
  ulong pull_request_tx;
  ulong pull_request_tx_bytes;

  ulong pull_response_rx;
  ulong pull_response_rx_drop;
  ulong pull_response_rx_bytes;
  ulong pull_response_tx;
  ulong pull_response_tx_bytes;

  ulong push_rx;
  ulong push_rx_drop;
  ulong push_rx_bytes;
  ulong push_tx;
  ulong push_tx_bytes;

  ulong prune_rx;
  ulong prune_rx_drop;
  ulong prune_rx_bytes;
  ulong prune_tx;
  ulong prune_tx_bytes;

  ulong ping_rx;
  ulong ping_rx_drop;
  ulong ping_rx_bytes;
  ulong ping_tx;
  ulong ping_tx_bytes;

  ulong pong_rx;
  ulong pong_rx_drop;
  ulong pong_rx_bytes;
  ulong pong_tx;
  ulong pong_tx_bytes;
};

typedef struct rx_deltas rx_deltas_t;

FD_PROTOTYPES_BEGIN

/* fd_gossip_diag_init initializes the diagnostic context by finding
   gossip, gossvf, and net tiles in the topology and setting up metrics
   pointers.  Returns 0 on success or -1 if the required tiles are
   not found. */

int
fd_gossip_diag_init( fd_gossip_diag_ctx_t * ctx,
                     fd_topo_t *            topo,
                     config_t *             config );

/* fd_gossip_diag_render prints one frame of the gossip diagnostic
   display.  Reads current metrics, computes deltas from the previous
   snapshot, prints formatted tables, and updates the previous
   snapshot.  If compact_mode is nonzero, prints a compact one-line
   summary instead.  After return, ctx->last_total_crds and
   ctx->last_total_contact_infos hold the latest values. */

void
fd_gossip_diag_render( fd_gossip_diag_ctx_t * ctx,
                       int                    compact_mode );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_firedancer_commands_monitor_gossip_gossip_diag_h */
