#include "../../../../disco/topo/fd_topo.h"
#include "../../../../disco/metrics/fd_metrics.h"

struct test_dedup_tx_ctx {
  fd_rng_t rng[1];

  ulong diag_iter;
  long  diag_last_ts;
  long  diag_interval;

  ulong pkt_framing;
  ulong pkt_payload_max;

  float burst_tau;
  float burst_avg;
  long  burst_next;
  ulong burst_ts;
  ulong burst_rem;

  ulong  tx_orig; /* origin identifier of this tile */
  void * tx_base;
  ulong  tx_chunk0;
  ulong  tx_wmark;
  ulong  tx_chunk;

  uint  dup_thresh;
  float dup_avg_age;
  uint  dup_seq;

  uint  ctl_som : 1;
};

typedef struct test_dedup_tx_ctx test_dedup_tx_ctx_t;

static void
during_housekeeping( test_dedup_tx_ctx_t * ctx ) {
  long now = fd_log_wallclock();
  long dt = now - ctx->diag_last_ts;

  ulong last_backp_cnt = 0UL;
  if( FD_UNLIKELY( dt>=ctx->diag_interval ) ) {
    float mfps = (float)ctx->diag_iter / (float)dt;
    ulong now_backp_cnt = FD_MCNT_GET( TILE, BACKPRESSURE_COUNT );
    FD_LOG_NOTICE(( "%7.3f Mfrag/s tx (in_backp %lu backp_cnt %lu", (double)mfps,
                    FD_MGAUGE_GET( TILE, IN_BACKPRESSURE ),
                    now_backp_cnt-last_backp_cnt ));
    last_backp_cnt = now_backp_cnt;
    ctx->diag_last_ts = now;
    ctx->diag_iter    = 0UL;
  }
}

static void
after_credit( test_dedup_tx_ctx_t * ctx,
              fd_stem_context_t *   stem,
              int *                 opt_poll_in,
              int *                 charge_busy ) {
  (void)opt_poll_in; (void)charge_busy;
  long now = fd_tickcount();

  /* Check if we are waiting for the next burst to start */

  if( FD_LIKELY( ctx->ctl_som ) ) {
    if( FD_UNLIKELY( now < ctx->burst_next ) ) { /* Optimize for burst starting */
      return;
    }
    /* We just "started receiving" the first bytes of the next burst
        from the "NIC".  Record the timestamp. */
    ctx->burst_ts = fd_frag_meta_ts_comp( ctx->burst_next );
  }

  /* We are in the process of "receiving" a burst fragment from the
      "NIC".  Compute the details of the synthetic fragment and fill
      the data region with a suitable test pattern as fast as we can. */

  ulong frag_sz = fd_ulong_min( ctx->burst_rem, ctx->pkt_payload_max );
  ctx->burst_rem -= frag_sz;

  int ctl_eom = !ctx->burst_rem;
  int ctl_err = 0;

  int   is_dup = fd_rng_uint( ctx->rng ) < ctx->dup_thresh;
  uint  age    = is_dup ? (uint)(int)(1.0f + ctx->dup_avg_age*fd_rng_float_exp( ctx->rng )) : 0U;
  ulong sig    = fd_ulong_hash( ((ctx->tx_orig)<<32) | ((ulong)(ctx->dup_seq - age)) );
  sig |= (ulong)(sig==FD_TCACHE_TAG_NULL);
  ctx->dup_seq += (uint)!is_dup;

/*ulong chunk  = ... already at location where next packet will be written ...; */
  ulong sz     = ctx->pkt_framing + frag_sz;
  ulong ctl    = fd_frag_meta_ctl( ctx->tx_orig, ctx->ctl_som, ctl_eom, ctl_err );
  ulong tsorig = ctx->burst_ts;
/*ulong tspub  = ... set "after" finished receiving from the "NIC" ...; */

  uchar * p   = (uchar *)fd_chunk_to_laddr( ctx->tx_base, ctx->tx_chunk );
  __m256i avx = _mm256_set1_epi64x( (long)sig );
  for( ulong off=0UL; off<sz; off+=128UL ) {
    _mm256_store_si256( (__m256i *)(p     ), avx );
    _mm256_store_si256( (__m256i *)(p+32UL), avx );
    _mm256_store_si256( (__m256i *)(p+64UL), avx );
    _mm256_store_si256( (__m256i *)(p+96UL), avx );
    p += 128UL;
  }

  /* We just "finished receiving" the next fragment of the burst from
     the "NIC".  Publish to consumers as frag seq.  This implicitly
     unpublishes frag seq-depth (cyclic) at the same time. */

  ulong tspub = fd_frag_meta_ts_comp( now );
  fd_stem_publish( stem, 0UL, sig, ctx->tx_chunk, sz, ctl, tsorig, tspub );

  /* Wind up for the next iteration */

  ctx->tx_chunk = fd_dcache_compact_next( ctx->tx_chunk, sz, ctx->tx_chunk0, ctx->tx_wmark );
  if( FD_UNLIKELY( !ctl_eom ) ) ctx->ctl_som = 0;
  else {
    ctx->ctl_som = 1;
    do {
      ctx->burst_next +=        (long)(0.5f + ctx->burst_tau*fd_rng_float_exp( ctx->rng ));
      ctx->burst_rem   = (ulong)(long)(0.5f + ctx->burst_avg*fd_rng_float_exp( ctx->rng ));
    } while( FD_UNLIKELY( !ctx->burst_rem ) );
  }
  ctx->diag_iter++;
}

#define STEM_BURST                        1
#define STEM_LAZY                         ((long)2e6)
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(test_dedup_tx_ctx_t)
#define STEM_CALLBACK_CONTEXT_TYPE        test_dedup_tx_ctx_t
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#include "../../../../disco/stem/fd_stem.c"

static ulong
scratch_align( void ) {
  return alignof(test_dedup_tx_ctx_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(test_dedup_tx_ctx_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_TEST( tile->out_cnt==1 );

  test_dedup_tx_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(test_dedup_tx_ctx_t) );

  /* Hook up to the tx dcache */
  fd_topo_link_t * tx_link = &topo->links[ tile->out_link_id[ 0 ] ];
  ctx->tx_base   = fd_wksp_containing( tx_link->dcache );
  ctx->tx_chunk0 = fd_dcache_compact_chunk0( ctx->tx_base, tx_link->dcache );
  ctx->tx_wmark  = fd_dcache_compact_wmark ( ctx->tx_base, tx_link->dcache, tx_link->mtu );
  ctx->tx_chunk  = ctx->tx_chunk0;

  /* Hook up to the random number generator */
  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, tile->test_dedup_rx.rng_seq, 0UL ) ) );

  long now = fd_tickcount();

  ctx->diag_interval = (long)(1e9*fd_tempo_tick_per_ns( NULL ));
  ctx->diag_last_ts  = now;
  ctx->diag_iter     = 0UL;

  /* Configure the synthetic load model */
  ctx->pkt_framing     = tile->test_dedup_tx.pkt_framing;
  ctx->pkt_payload_max = tile->test_dedup_tx.pkt_payload_max;
  ctx->burst_tau       = tile->test_dedup_tx.burst_tau;
  ctx->burst_avg       = tile->test_dedup_tx.burst_avg;

  ctx->ctl_som    = 1;
  ctx->burst_ts   = 0UL;  /* Irrelevant value at init */
  ctx->burst_next = now;
  do {
    ctx->burst_next +=        (long)(0.5f + ctx->burst_tau*fd_rng_float_exp( ctx->rng ));
    ctx->burst_rem   = (ulong)(long)(0.5f + ctx->burst_avg*fd_rng_float_exp( ctx->rng ));
  } while( FD_UNLIKELY( !ctx->burst_rem ) );

  ctx->dup_thresh  = tile->test_dedup_tx.dup_thresh;
  ctx->dup_avg_age = tile->test_dedup_tx.dup_avg_age;
  ctx->dup_seq     = 0U;
}

fd_topo_run_tile_t fd_tile_TDupTx = {
  .name              = "TDupTx",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
