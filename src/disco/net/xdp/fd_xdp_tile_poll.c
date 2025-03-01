/* Busy polling variant of the net tile.

   Periodically 'wakes up' XDP kernel code. */

#include "fd_xdp_tile_common.c"

static void
during_housekeeping( fd_net_ctx_t * ctx ) {
  metrics_collect( ctx );
}

/* after_credit is called every loop iteration. */

static void
after_credit( fd_net_ctx_t *      ctx,
              fd_stem_context_t * stem FD_PARAM_UNUSED,
              long                last_tc,
              int *               poll_in,
              int *               charge_busy ) {
  net_tx_finish( ctx );

  /* Round robin cycle through XDP sockets */

  uint               rr_idx  = ctx->rr_idx;
  rr_idx = 0;
  fd_xsk_t *         rr_xsk  = &ctx->xsk[ rr_idx  ];
  fd_net_flusher_t * flusher = ctx->tx_flusher+rr_idx;
  ctx->rr_idx++;
  ctx->rr_idx = fd_uint_if( ctx->rr_idx>=ctx->xsk_cnt, 0, ctx->rr_idx );

  /* Fetch sequence numbers */

  uint rx_prod   = rr_xsk->ring_rx.cached_prod;
  uint rx_cons   = rr_xsk->ring_rx.cached_cons;
  uint tx_prod   = rr_xsk->ring_tx.cached_prod;
  uint tx_cons   = rr_xsk->ring_tx.cached_cons;
  uint comp_prod = rr_xsk->ring_cr.cached_prod;
  uint comp_cons = rr_xsk->ring_cr.cached_cons;

  /* Process queued XDP events */

  if( comp_cons!=comp_prod ) {
    net_comp_event( ctx, rr_xsk, comp_cons );
  }

  if( rx_cons!=rx_prod ) {
    net_rx_event( ctx, stem, rr_xsk, last_tc );
    return;
  }

  /* Wake up network driver if TX ring is full */

  uint tx_depth = rr_xsk->ring_tx.depth;
  if( FD_UNLIKELY( (int)(tx_prod-tx_cons) >= (int)tx_depth ) ) {
  FD_LOG_ERR(( "Tx"));
    net_tx_wakeup( ctx, rr_xsk, charge_busy );
    fd_net_flusher_wakeup( flusher, last_tc );
    *poll_in = 0;
    return;
  }

  /* Wake up network driver periodically */

  int flush_timeout = last_tc >= flusher->next_tail_flush_ticks;
  if( FD_UNLIKELY( flush_timeout ) ) {
    net_rx_wakeup( ctx, rr_xsk );
    fd_net_flusher_wakeup( flusher, last_tc );
    *poll_in = 1;
    //*charge_busy = rr_xsk->ring_rx.cached_cons != rr_xsk->ring_rx.cached_prod;
    //  /* FIXME CPU usage overreported when packets arrive spaced out at a low rate? */
    return;
  }

}

#define STEM_BURST (1UL)
#define STEM_LAZY ((ulong)1e6) /* 1 ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_net_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_net_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../stem/fd_stem.c"

void
fd_xdp_tile_poll_run( fd_topo_t *      topo,
                      fd_topo_tile_t * tile ) {
  stem_run( topo, tile );
}
