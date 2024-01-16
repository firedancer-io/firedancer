#include "tiles.h"

typedef struct {
  uchar __attribute__((aligned(32UL))) mem[ FD_SHRED_STORE_MTU ];

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;
} fd_store_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_store_ctx_t ), sizeof( fd_store_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_store_ctx_t ) );
}

static inline void
metrics_write( void * _ctx ) {
  fd_store_ctx_t * ctx = (fd_store_ctx_t *)_ctx;

  (void)ctx;
}

static void const * fd_ext_blockstore;

void
fd_ext_store_initialize( void const * blockstore ) {
  fd_ext_blockstore = blockstore;
  FD_COMPILER_MFENCE();
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)sig;
  (void)seq;
  (void)in_idx;
  (void)opt_filter;

  fd_store_ctx_t * ctx = (fd_store_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz>FD_SHRED_STORE_MTU || sz<32UL ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );

  fd_memcpy( ctx->mem, src, sz );
}

extern int
fd_ext_blockstore_insert_shreds( void const *  blockstore,
                                 ulong         shred_cnt,
                                 uchar const * shred_bytes,
                                 ulong         shred_sz,
                                 ulong         stride );

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_tsorig;
  (void)opt_filter;
  (void)mux;

  fd_store_ctx_t * ctx = (fd_store_ctx_t *)_ctx;

  fd_shred34_t * shred34 = (fd_shred34_t *)ctx->mem;

  FD_TEST( shred34->shred_sz<=shred34->stride );
  FD_TEST( shred34->shred_cnt==0UL || (shred34->offset + shred34->stride*(shred34->shred_cnt-1) + shred34->shred_sz <= *opt_sz) );

  /* No error code because this cannot fail. */
  fd_ext_blockstore_insert_shreds( fd_ext_blockstore, shred34->shred_cnt, ctx->mem+shred34->offset, shred34->shred_sz, shred34->stride );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_store_ctx_t ), sizeof( fd_store_ctx_t ) );

  FD_LOG_NOTICE(( "Waiting to acquire blockstore..." ));
  for(;;) {
    if( FD_LIKELY( FD_VOLATILE_CONST( fd_ext_blockstore ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  FD_LOG_NOTICE(( "Got blockstore" ));

  ctx->in_mem = topo->workspaces[ topo->links[ tile->in_link_id[ 0UL ] ].wksp_id ].wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark ( ctx->in_mem, topo->links[ tile->in_link_id[ 0UL ] ].dcache, topo->links[ tile->in_link_id[ 0UL ] ].mtu );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

fd_tile_config_t fd_tile_store = {
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .mux_metrics_write        = metrics_write,
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
};
