#include "fd_trtt_tile.h"
#include "../../../../disco/stem/fd_stem.h"

static void
after_credit( fd_trtt_tile_t *    ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in; (void)charge_busy;
  if( ctx->inflight ) return;
  long now = fd_tickcount();
  ctx->tsref = now;
  ulong tsorig, tspub;
  tsorig = tspub = fd_frag_meta_ts_comp( now );
  fd_stem_publish( stem, 0UL, 0UL, 0UL, 0UL, 0UL, tsorig, tspub );
  ctx->inflight = 1;
}

static void
after_frag( fd_trtt_tile_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig_comp,
            ulong               tspub_comp,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)tspub_comp; (void)stem;
  long tsorig = fd_frag_meta_ts_decomp( tsorig_comp, ctx->tsref );
  long now    = fd_tickcount();
  long rtt    = fd_long_max( 0L, now-tsorig );
  fd_histf_sample( ctx->rtt_hist, (ulong)rtt );
  ctx->inflight = 0;
}

#define STEM_BURST                  (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  fd_trtt_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_trtt_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#include "../../../../disco/stem/fd_stem.c"

static ulong scratch_align( void ) { return alignof(fd_trtt_tile_t); }
static ulong scratch_footprint( fd_topo_tile_t const * tile ) { (void)tile; return sizeof(fd_trtt_tile_t); }

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_trtt_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(fd_trtt_tile_t) );
  fd_histf_join( fd_histf_new( ctx->rtt_hist, 1, (ulong)1e7 ) );
}

fd_topo_run_tile_t fd_tile_trtt = {
  .name              = "trtt",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
