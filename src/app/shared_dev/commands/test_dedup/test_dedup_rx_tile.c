#include "../../../../disco/topo/fd_topo.h"

struct test_dedup_rx_ctx {
  fd_rng_t rng[1];

  void * rx_base;

  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * _tcache_sync;
  ulong   tcache_sync;
  ulong * _tcache_ring;
  ulong * _tcache_map;

  ulong diag_iter;
  long  diag_last_ts;
  long  diag_interval;

  uint corrupt : 1;
};

typedef struct test_dedup_rx_ctx test_dedup_rx_ctx_t;

static void
during_housekeeping( test_dedup_rx_ctx_t * ctx ) {
  /* Update synchronization info */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *ctx->_tcache_sync ) = ctx->tcache_sync;
  FD_COMPILER_MFENCE();

  /* Send diagnostic info */
  long now = fd_log_wallclock();
  long dt = now - ctx->diag_last_ts;
  if( FD_UNLIKELY( dt > (long)1e9 ) ) {
    float mfps = (1e3f*(float)ctx->diag_iter) / (float)dt;
    FD_LOG_NOTICE(( "%7.3f Mfrag/s rx", (double)mfps ));
    ctx->diag_last_ts = now;
    ctx->diag_iter    = 0UL;
  }
}

static inline void
during_frag( test_dedup_rx_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz,
             ulong                 ctl ) {
  (void)in_idx; (void)seq; (void)ctl;

  /* Process the received fragment (FIXME: also validate continuity of
      the individual tx streams via sig too, validate control bits, add
      latency and bandwidth stats). */

  int is_dup;
  FD_TCACHE_INSERT( is_dup, ctx->tcache_sync, ctx->_tcache_ring, ctx->tcache_depth, ctx->_tcache_map, ctx->tcache_map_cnt, sig );
  if( FD_UNLIKELY( is_dup ) ) FD_LOG_ERR(( "Received a duplicate" ));

  uchar const * p = (uchar const *)fd_chunk_to_laddr_const( ctx->rx_base, chunk );
  __m256i avx = _mm256_set1_epi64x( (long)sig );
  int mask0 = -1;
  int mask1 = -1;
  int mask2 = -1;
  int mask3 = -1;
  for( ulong off=0UL; off<sz; off+=128UL ) {
    mask0 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *) p       ), avx ) );
    mask1 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *)(p+32UL) ), avx ) );
    mask2 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *)(p+64UL) ), avx ) );
    mask3 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8( _mm256_load_si256( (__m256i *)(p+96UL) ), avx ) );
    p += 128UL;
  }

  /* Validate that the frag payload was as expected */
  ctx->corrupt = ((mask0 & mask1 & mask2 & mask3)!=-1);
}

static inline void
after_frag( test_dedup_rx_ctx_t * ctx,
            ulong                 in_idx,
            ulong                 in_seq,
            ulong                 in_sig,
            ulong                 in_sz,
            ulong                 in_tsorig,
            ulong                 in_tspub,
            fd_stem_context_t *   stem ) {
  (void)in_idx; (void)in_seq; (void)in_sig; (void)in_sz; (void)in_tsorig; (void)in_tspub; (void)stem;
  if( FD_UNLIKELY( ctx->corrupt ) ) FD_LOG_ERR(( "Corrupt payload received" ));
  ctx->diag_iter++;
}

#define STEM_BURST                        1
#define STEM_LAZY                         ((long)2e6)
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(test_dedup_rx_ctx_t)
#define STEM_CALLBACK_CONTEXT_TYPE        test_dedup_rx_ctx_t
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#include "../../../../disco/stem/fd_stem.c"

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(test_dedup_rx_ctx_t), fd_tcache_align() );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(test_dedup_rx_ctx_t), sizeof(test_dedup_rx_ctx_t) ),
      fd_tcache_align(),            fd_tcache_footprint( tile->test_dedup_rx.tcache_depth, tile->test_dedup_rx.tcache_map_cnt ) ),
      scratch_align() );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_TEST( tile->in_cnt>0 );

  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  test_dedup_rx_ctx_t * ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof(test_dedup_rx_ctx_t), sizeof(test_dedup_rx_ctx_t) );
  void *                tcache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_tcache_align(), fd_tcache_footprint( tile->test_dedup_rx.tcache_depth, tile->test_dedup_rx.tcache_map_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  memset( ctx, 0, sizeof(test_dedup_rx_ctx_t) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( tcache_mem, tile->test_dedup_rx.tcache_depth, tile->test_dedup_rx.tcache_map_cnt ) );
  FD_TEST( tcache );

  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->_tcache_sync   = fd_tcache_oldest_laddr( tcache );
  ctx->_tcache_ring   = fd_tcache_ring_laddr  ( tcache );
  ctx->_tcache_map    = fd_tcache_map_laddr   ( tcache );
  ctx->tcache_sync    = *ctx->_tcache_sync;

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, tile->test_dedup_rx.rng_seq, 0UL ) ) );
}

fd_topo_run_tile_t fd_tile_TDupRx = {
  .name              = "TDupRx",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
