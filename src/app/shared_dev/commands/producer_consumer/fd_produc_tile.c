// fd_producer_tile.c
#include "../../../../disco/topo/fd_topo.h"
// #include <time.h>  // For clock_nanosleep

struct fd_producer_tile_ctx {
  void * out_base;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;
  ulong  counter;
  long   next_produce_time;  // Next time to produce data (in nanoseconds)
};
typedef struct fd_producer_tile_ctx fd_producer_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_producer_tile_ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_producer_tile_ctx_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_producer_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  
  FD_TEST( tile->out_cnt==1UL );
  void * out_base   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  void * out_dcache = topo->links[ tile->out_link_id[ 0 ] ].dcache;
  
  ctx->out_base = out_base;
  ctx->chunk0   = fd_dcache_compact_chunk0( out_base, out_dcache );
  ctx->wmark    = fd_dcache_compact_wmark( out_base, out_dcache, 256UL );
  ctx->chunk    = ctx->chunk0;
  ctx->counter  = 0UL;
  ctx->next_produce_time = fd_log_wallclock();
}

// TODO: make it to after credit -- otherwise overloading our consumer cuz it does it before credit check
static void
before_credit( fd_producer_tile_ctx_t * ctx,
               fd_stem_context_t *      stem,
               int *                    charge_busy ) {
  
  long now = fd_log_wallclock();
  if (now < ctx->next_produce_time) {
    return;
  }

  // Time to produce data
  *charge_busy = 1;
  
  // Schedule next production in 10 seconds (10 billion nanoseconds)
  ctx->next_produce_time = now + 10000000000L;
  
  ulong   chunk = ctx->chunk;
  uchar * data = fd_chunk_to_laddr( ctx->out_base, chunk );
  ulong   counter = ctx->counter;
  
  // Write counter value to the data
  FD_STORE( ulong, data, counter );
  
  // Publish fragment with simple signature
  fd_stem_publish( stem, 0UL, 1UL, chunk, sizeof(ulong), 0UL, 0UL, 0UL );
  
  // Log every message to show the timing
  FD_LOG_NOTICE(( "Producer sent counter %lu at wallclock time %ld", 
                  counter, now ));
  
  // Update for next iteration
  chunk++;
  chunk = fd_ulong_if( chunk > ctx->wmark, ctx->chunk0, chunk );
  ctx->counter = counter + 1UL;
  ctx->chunk = chunk;
}

#define STEM_BURST (1UL)
#define STEM_CAN_SLEEP (1)
#define STEM_CALLBACK_CONTEXT_TYPE fd_producer_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_producer_tile_ctx_t)
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_produc = {
  .name              = "produc",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};