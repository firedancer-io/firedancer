#include "fd_store_tile.h"

FD_FN_CONST ulong
fd_store_tile_align( void ) {
  return FD_STORE_TILE_ALIGN;
}

FD_FN_PURE ulong
fd_store_tile_footprint( void const * args ) {
  (void)args;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_store_tile_t ), sizeof( fd_store_tile_t ) );
  return FD_LAYOUT_FINI( l, fd_store_tile_align() );
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

  fd_store_tile_t * ctx = (fd_store_tile_t *)_ctx;

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

  fd_store_tile_t * ctx = (fd_store_tile_t *)_ctx;

  fd_shred34_t * shred34 = (fd_shred34_t *)ctx->mem;

  FD_TEST( shred34->shred_sz<=shred34->stride );
  FD_TEST( shred34->shred_cnt==0UL || (shred34->offset + shred34->stride*(shred34->shred_cnt-1) + shred34->shred_sz <= *opt_sz) );

  /* No error code because this cannot fail. */
  fd_ext_blockstore_insert_shreds( fd_ext_blockstore, shred34->shred_cnt, ctx->mem+shred34->offset, shred34->shred_sz, shred34->stride );
}

fd_store_tile_t *
fd_store_tile_join( void *                       shstore,
                    void const *                 args,
                    fd_store_tile_topo_t const * topo ) {
  FD_SCRATCH_ALLOC_INIT( l, shstore );
  fd_store_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_store_tile_t ), sizeof( fd_store_tile_t ) );

  FD_LOG_NOTICE(( "Waiting to acquire blockstore..." ));
  for(;;) {
    if( FD_LIKELY( FD_VOLATILE_CONST( fd_ext_blockstore ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  FD_LOG_NOTICE(( "Got blockstore" ));

  ctx->in_mem = topo->in_wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, topo->in_dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark ( ctx->in_mem, topo->in_dcache, topo->in_mtu );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)shstore + fd_store_tile_footprint( args ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)shstore - fd_store_tile_footprint( args ), scratch_top, (ulong)shstore + fd_store_tile_footprint( args ) ));

  return ctx;
}

void
fd_store_tile_run( fd_store_tile_t *       ctx,
                   fd_cnc_t *              cnc,
                   ulong                   in_cnt,
                   fd_frag_meta_t const ** in_mcache,
                   ulong **                in_fseq,
                   fd_frag_meta_t *        mcache,
                   ulong                   out_cnt,
                   ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .during_frag         = during_frag,
    .after_frag          = after_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_MANUAL_PUBLISH,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}
