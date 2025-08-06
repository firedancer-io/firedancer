/* bench_solcap_producer generates a flood of garbage packets with a
   deterministic RNG pattern.  The consumer side can then check whether
   the same pattern is seen downstream (e.g. in a solcap file written
   to disk).  Outputs to up to 2 streams. */

#include "../../../../disco/topo/fd_topo.h"

struct bench_solcap_pktgen {
  fd_rng_t rng[1];

  void * base;
  ulong  chunk;
  ulong  chunk0;
  ulong  wmark;
  ulong  mtu;
};

typedef struct bench_solcap_pktgen bench_solcap_pktgen_t;

/* after_credit is called every loop iteration if there are sufficient
   flow control credits to burst one frag. */

static void
after_credit( bench_solcap_pktgen_t * ctx,
              fd_stem_context_t *     stem,
              int *                   poll_in,
              int *                   charge_busy ) {
  (void)stem; (void)poll_in;
  *charge_busy = 1;
  fd_rng_t * rng = ctx->rng;

  ulong   const sz    = 32UL;
  ulong   const chunk = ctx->chunk;
  uchar * const pkt   = fd_chunk_to_laddr( ctx->base, chunk );
  FD_STORE( ulong, pkt+ 0, fd_rng_ulong( rng ) );
  FD_STORE( ulong, pkt+ 8, fd_rng_ulong( rng ) );
  FD_STORE( ulong, pkt+16, fd_rng_ulong( rng ) );
  FD_STORE( ulong, pkt+24, fd_rng_ulong( rng ) );

  ulong const ctl = fd_frag_meta_ctl( 0UL, 0, 0, 0 );
  fd_stem_publish( stem, 0UL, 0UL, chunk, sz, ctl, 0UL, 0UL );

  ctx->chunk = fd_dcache_compact_next( chunk, ctx->mtu, ctx->chunk0, ctx->wmark );
}

#define STEM_BURST                  1UL
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(bench_solcap_pktgen_t)
#define STEM_CALLBACK_CONTEXT_TYPE  bench_solcap_pktgen_t
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#include "../../../../disco/stem/fd_stem.c"

static ulong
scratch_align( void ) {
  return alignof(bench_solcap_pktgen_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(bench_solcap_pktgen_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  bench_solcap_pktgen_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(bench_solcap_pktgen_t) );

  FD_TEST( tile->out_cnt==1 );
  fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ 0 ] ];
  uchar * dcache = link->dcache;
  ctx->base   = fd_wksp_containing( dcache );
  ctx->chunk0 = fd_dcache_compact_chunk0( ctx->base, dcache );
  ctx->wmark  = fd_dcache_compact_wmark( ctx->base, dcache, link->mtu );
  ctx->chunk  = ctx->chunk0;
  ctx->mtu    = link->mtu;

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 1871U, 0UL ) ) );
}

fd_topo_run_tile_t bench_solcap_producer_tile = {
  .name              = "pktgn1",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
