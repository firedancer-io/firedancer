#include "../../../../disco/tiles.h"

#include "../../../../disco/metrics/fd_metrics.h"

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_store_in_ctx_t;

typedef struct {
  uchar __attribute__((aligned(32UL))) mem[ FD_SHRED_STORE_MTU ];

  ulong disable_blockstore_from_slot;

  fd_store_in_ctx_t in[ 32 ];
} fd_store_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_store_ctx_t ), sizeof( fd_store_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void const * fd_ext_blockstore;

void
fd_ext_store_initialize( void const * blockstore ) {
  fd_ext_blockstore = blockstore;
  FD_COMPILER_MFENCE();
}

static inline void
during_frag( fd_store_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig,
             ulong            chunk,
             ulong            sz ) {
  (void)sig;
  (void)seq;
  (void)in_idx;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_SHRED_STORE_MTU || sz<32UL ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );

  fd_memcpy( ctx->mem, src, sz );
}

extern int
fd_ext_blockstore_insert_shreds( void const *  blockstore,
                                 ulong         shred_cnt,
                                 uchar const * shred_bytes,
                                 ulong         shred_sz,
                                 ulong         stride,
                                 int           is_trusted );

static inline void
after_frag( fd_store_ctx_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)tsorig;
  (void)stem;

  fd_shred34_t * shred34 = (fd_shred34_t *)ctx->mem;

  FD_TEST( shred34->shred_sz<=shred34->stride );
  if( FD_LIKELY( shred34->shred_cnt ) ) {
    FD_TEST( shred34->offset<sz  );
    FD_TEST( shred34->shred_cnt<=34UL );
    FD_TEST( shred34->stride==sizeof(shred34->pkts[0]) );
    FD_TEST( shred34->offset + shred34->stride*(shred34->shred_cnt - 1UL) + shred34->shred_sz <= sz);
  }

  if( FD_UNLIKELY( ctx->disable_blockstore_from_slot && ( ctx->disable_blockstore_from_slot <= shred34->pkts->shred.slot ) ) ) return;

  /* No error code because this cannot fail. */
  fd_ext_blockstore_insert_shreds( fd_ext_blockstore, shred34->shred_cnt, ctx->mem+shred34->offset, shred34->shred_sz, shred34->stride, !!sig );

  FD_MCNT_INC( STORE_TILE, TRANSACTIONS_INSERTED, shred34->est_txn_cnt );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_store_ctx_t ), sizeof( fd_store_ctx_t ) );

  FD_LOG_INFO(( "Waiting to acquire blockstore..." ));
  for(;;) {
    if( FD_LIKELY( FD_VOLATILE_CONST( fd_ext_blockstore ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  FD_LOG_INFO(( "Got blockstore" ));

  ctx->disable_blockstore_from_slot = tile->store.disable_blockstore_from_slot;

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST (1UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_store_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_store_ctx_t)

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_store = {
  .name              = "store",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};
