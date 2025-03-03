/* 'Use wakeup' variant of the net tile.

   Mostly relies on IRQs and ksoftirq to ingest new traffic.  Will
   occasionally wake up the kernel if ksoftirq did not clean RX rings in
   time or if there is TX work to do.

   FIXME cache remote sequence numbers to prevent false sharing */

#define XDP_USE_VOLATILE 1 /* ksoftirqd races our RX wakeups */
#include "fd_xdp_tile_common.c"

/* net_tx_periodic_wakeup does a timer based xsk_sendmsg wakeup. */

static inline int
net_tx_periodic_wakeup( fd_net_ctx_t * ctx,
                        uint           if_idx,
                        long           now,
                        int *          charge_busy ) {
  uint tx_prod = FD_VOLATILE_CONST( *ctx->xsk[ if_idx ].ring_tx.prod );
  uint tx_cons = FD_VOLATILE_CONST( *ctx->xsk[ if_idx ].ring_tx.cons );
  int tx_ring_empty = tx_prod==tx_cons;
  if( fd_net_flusher_check( ctx->tx_flusher+if_idx, now, tx_ring_empty ) ) {
    net_tx_wakeup( ctx, &ctx->xsk[ if_idx ], charge_busy );
    fd_net_flusher_wakeup( ctx->tx_flusher+if_idx, now );
  }
  return 0;
}

static void
during_housekeeping( fd_net_ctx_t * ctx ) {
  metrics_collect( ctx );

  for( uint j=0U; j<ctx->xsk_cnt; j++ ) {
    if( fd_xsk_rx_need_wakeup( &ctx->xsk[ j ] ) ) {
      net_rx_wakeup( ctx, &ctx->xsk[ j ] );
    }
  }
}

/* before_credit is called every loop iteration. */

static void
before_credit( fd_net_ctx_t *      ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  net_tx_finish( ctx );

  /* Check if new packets are available or if TX frames are free again
     (Round-robin through sockets) */

  uint       rr_idx = ctx->rr_idx;
  fd_xsk_t * rr_xsk = &ctx->xsk[ rr_idx ];
  ctx->rr_idx++;
  ctx->rr_idx = fd_uint_if( ctx->rr_idx>=ctx->xsk_cnt, 0, ctx->rr_idx );

  net_tx_periodic_wakeup( ctx, rr_idx, fd_tickcount(), charge_busy );

  uint rx_cons =                    *rr_xsk->ring_rx.cons;
  uint rx_prod = FD_VOLATILE_CONST( *rr_xsk->ring_rx.prod );
  if( rx_cons!=rx_prod ) {
    *charge_busy = 1;
    net_rx_event( ctx, stem, rr_xsk, rx_cons );
  } else {
    if( fd_xsk_rx_need_wakeup( rr_xsk ) ) {
      *charge_busy = 1;
      net_rx_wakeup( ctx, rr_xsk );
    }
  }

  uint comp_cons =                    *rr_xsk->ring_cr.cons;
  uint comp_prod = FD_VOLATILE_CONST( *rr_xsk->ring_cr.prod );
  if( comp_cons!=comp_prod ) {
    *charge_busy = 1;
    net_comp_event( ctx, rr_xsk, comp_cons );
  }

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

void
fd_xdp_tile_softirq_run( fd_topo_t *      topo,
                         fd_topo_tile_t * tile ) {
  stem_run( topo, tile );
}
