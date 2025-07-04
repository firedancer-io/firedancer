#include "../tiles.h"


typedef struct {
  ulong      cnt;
} fd_empty_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_empty_ctx_t), sizeof(fd_empty_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_empty_ctx_t * ctx FD_PARAM_UNUSED ) {
  FD_SPIN_PAUSE();
}

static inline int
before_frag( fd_empty_ctx_t * ctx FD_PARAM_UNUSED,
             ulong            in_idx FD_PARAM_UNUSED,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig FD_PARAM_UNUSED ) {
  FD_SPIN_PAUSE();
  return 0;
}

static void
during_frag( fd_empty_ctx_t * ctx FD_PARAM_UNUSED,
             ulong            in_idx FD_PARAM_UNUSED,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig FD_PARAM_UNUSED,
             ulong            chunk FD_PARAM_UNUSED,
             ulong            sz FD_PARAM_UNUSED,
             ulong            ctl FD_PARAM_UNUSED ) {
  (void)ctx;
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)ctl;
  FD_SPIN_PAUSE();
}

static void
after_frag( fd_empty_ctx_t *    ctx,
            ulong               in_idx FD_PARAM_UNUSED,
            ulong               seq FD_PARAM_UNUSED,
            ulong               sig FD_PARAM_UNUSED,
            ulong               sz FD_PARAM_UNUSED,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               _tspub FD_PARAM_UNUSED,
            fd_stem_context_t * stem FD_PARAM_UNUSED ) {
  ctx->cnt += 1;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( scratch!=NULL );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_empty_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_empty_ctx_t ), sizeof( fd_empty_ctx_t ) );

  ctx->cnt = 0UL;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}


#define STEM_BURST (1UL)
#define STEM_LAZY  (128L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_empty_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_empty_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_empty = {
  .name                     = "empty",
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
