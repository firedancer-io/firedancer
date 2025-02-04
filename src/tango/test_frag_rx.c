#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

FD_STATIC_ASSERT( FD_CHUNK_SZ==64UL, unit_test );

static uchar fseq_mem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));

#define FD_FSEQ_DIAG_PUB_CNT   (0UL)
#define FD_FSEQ_DIAG_PUB_SZ    (1UL)
#define FD_FSEQ_DIAG_FILT_CNT  (2UL)
#define FD_FSEQ_DIAG_FILT_SZ   (3UL)
#define FD_FSEQ_DIAG_OVRNP_CNT (4UL)
#define FD_FSEQ_DIAG_OVRNR_CNT (5UL)
#define FD_FSEQ_DIAG_SLOW_CNT  (6UL)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _cnc    = fd_env_strip_cmdline_cstr( &argc, &argv, "--cnc",    NULL, NULL                 );
  char const * _mcache = fd_env_strip_cmdline_cstr( &argc, &argv, "--mcache", NULL, NULL                 );
  char const * _dcache = fd_env_strip_cmdline_cstr( &argc, &argv, "--dcache", NULL, NULL                 );
  char const * _wksp   = fd_env_strip_cmdline_cstr( &argc, &argv, "--wksp",   NULL, NULL                 );
  char const * _fseq   = fd_env_strip_cmdline_cstr( &argc, &argv, "--fseq",   NULL, NULL                 );
  char const * _init   = fd_env_strip_cmdline_cstr( &argc, &argv, "--init",   NULL, NULL                 );
  uint         seed    = fd_env_strip_cmdline_uint( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() );
  int          lazy    = fd_env_strip_cmdline_int ( &argc, &argv, "--lazy",   NULL, 7                    );

  if( FD_UNLIKELY( !_cnc              ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache           ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( !_dcache && !_wksp ) ) FD_LOG_ERR(( "--dcache or --wksp not specified" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join failed" ));

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong         depth = fd_mcache_depth          ( mcache );
  ulong const * sync  = fd_mcache_seq_laddr_const( mcache );

  ulong seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( sync );

  uchar const * dcache = NULL;
  fd_wksp_t * wksp;
  if( !_wksp ) {
    FD_LOG_NOTICE(( "Joining to --dcache %s", _dcache ));
    dcache = fd_dcache_join( fd_wksp_map( _dcache ) );
    if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "join failed" ));
    wksp = fd_wksp_containing( dcache );
    if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  } else {
    FD_LOG_NOTICE(( "Joining to --wksp %s", _wksp ));
    wksp = fd_wksp_attach( _wksp );
    if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_attach failed" ));
  }

  ulong * fseq;
  if( !_fseq ) {
    FD_LOG_NOTICE(( "Unreliable mode; will not send flow control information to transmitter" ));
    fseq = fd_fseq_join( fd_fseq_new( fseq_mem, 0UL ) );
  } else {
    FD_LOG_NOTICE(( "Reliable mode; joining to --fseq %s for sending flow control information to transmitter", _fseq ));
    fseq = fd_fseq_join( fd_wksp_map( _fseq ) );
  }
  if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "join failed" ));

  ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );

  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;

  ulong ovrnp_cnt = 0UL; /* Count of overruns while polling for next seq */
  ulong ovrnr_cnt = 0UL; /* Count of overruns while processing seq payload */

  FD_LOG_NOTICE(( "Running --init %lu (%s) --lazy %i", seq, _init ? "manual" : "auto", lazy ));

  ulong async_min = 1UL << lazy;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  long  then = fd_log_wallclock();
  ulong iter = 0UL;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Wait for frag seq */

#   define WAIT_STYLE -1
#   define VALIDATE   1

    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   diff;

#   if WAIT_STYLE==-1 /* Compatible with all PUBLISH_STYLE */

    ulong sig;
    ulong chunk;
    ulong sz;
    ulong ctl;
    ulong tsorig;
    ulong tspub;
    FD_MCACHE_WAIT_REG( sig, chunk, sz, ctl, tsorig, tspub, mline, seq_found, diff, async_rem, mcache, depth, seq );

#   elif WAIT_STYLE==0 /* Compatible with all PUBLISH_STYLE */

    fd_frag_meta_t meta[1];
    FD_MCACHE_WAIT( meta, mline, seq_found, diff, async_rem, mcache, depth, seq );

#   elif WAIT_STYLE==1 /* Compatible with all PUBLISH_STYLE */

    __m128i meta_sse0;
    __m128i meta_sse1;
    FD_MCACHE_WAIT_SSE( meta_sse0, meta_sse1, mline, seq_found, diff, async_rem, mcache, depth, seq );

#   else /* Compatible with PUBLISH_STYLE==2, requires target with atomic aligned AVX load / store */

    __m256i meta_avx;
    FD_MCACHE_WAIT_AVX( meta_avx, mline, seq_found, diff, async_rem, mcache, depth, seq );

#   endif

    /* Do housekeeping in background */
    if( FD_UNLIKELY( !async_rem ) ) {

      /* Send flow control credits */
      fd_fctl_rx_cr_return( fseq, seq );

      /* Send diagnostic info */
      long now = fd_log_wallclock();
      fd_cnc_heartbeat( cnc, now );

      long dt = now - then;
      if( FD_UNLIKELY( dt > (long)1e9 ) ) {
        float mfps = (1e3f*(float)iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s rx (ovrnp %lu ovrnr %lu)", (double)mfps, ovrnp_cnt, ovrnr_cnt ));
        FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = FD_VOLATILE_CONST( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) + ovrnp_cnt;
        FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = FD_VOLATILE_CONST( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) + ovrnr_cnt;
        ovrnp_cnt = 0UL;
        ovrnr_cnt = 0UL;
        then      = now;
        iter      = 0UL;
      }

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Reload housekeeping timer */
      async_rem = fd_tempo_async_reload( rng, async_min );
      continue;
    }

    /* Handle overrun */

    if( FD_UNLIKELY( diff ) ) {
    //FD_LOG_NOTICE(( "Overrun while polling (skipping from %lu to %lu to try to recover)", seq, seq_found ));
      ovrnp_cnt++;
      seq = seq_found;
#     if WAIT_STYLE!=2
      continue; /* We can't trust the metadata we just loaded, so we try again */
#     endif
      /* Note: we could also do (for any wait style)
           seq = fd_mcache_seq_query( sync );
           continue;
         here to recover from the most recent seq advertised by the
         producer.  But this can create cache hotspots and the simpler
         and fast handling is often even more current in practice that
         the above. */
    }

    /* At this point, we've atomically loaded the fragment metadata for
       seq (the fragment we were looking for).  Validate the metadata
       and validate the corresponding fragment in the dcache. */

#   if WAIT_STYLE==-1

    /* Already loaded into registers as part of the wait */

#   elif WAIT_STYLE==0

    ulong sig    = (ulong)meta->sig;
    ulong chunk  = (ulong)meta->chunk;
    ulong sz     = (ulong)meta->sz;
    ulong ctl    = (ulong)meta->ctl;
    ulong tsorig = (ulong)meta->tsorig;
    ulong tspub  = (ulong)meta->tspub;

#   elif WAIT_STYLE==1

    ulong sig    = fd_frag_meta_sse0_sig   ( meta_sse0 );
    ulong chunk  = fd_frag_meta_sse1_chunk ( meta_sse1 );
    ulong sz     = fd_frag_meta_sse1_sz    ( meta_sse1 );
    ulong ctl    = fd_frag_meta_sse1_ctl   ( meta_sse1 );
    ulong tsorig = fd_frag_meta_sse1_tsorig( meta_sse1 );
    ulong tspub  = fd_frag_meta_sse1_tspub ( meta_sse1 );

#   else

    ulong sig    = fd_frag_meta_avx_sig   ( meta_avx );
    ulong chunk  = fd_frag_meta_avx_chunk ( meta_avx );
    ulong sz     = fd_frag_meta_avx_sz    ( meta_avx );
    ulong ctl    = fd_frag_meta_avx_ctl   ( meta_avx );
    ulong tsorig = fd_frag_meta_avx_tsorig( meta_avx );
    ulong tspub  = fd_frag_meta_avx_tspub ( meta_avx );

#   endif

#   if VALIDATE
    uchar const * p = (uchar const *)fd_chunk_to_laddr_const( wksp, chunk );
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
#   else
    (void)sig; (void)chunk; (void)sz;
#   endif
    (void)ctl;                 /* FIXME: ADD REASSEMBLY LOGIC */
    (void)tsorig; (void)tspub; /* FIXME: ADD LATENCY AND BANDWIDTH STATS */

    /* At this point, we've loaded the metadata and speculatively
       processed the fragment payload.  Check that we weren't overrun
       while processing.  Since fd_mcache_query is a compiler memory
       fence, this check will not execute until the speculative loads
       above are complete.  Also note that this check in normal
       operation is typically a very fast L1 cache hit on the already
       loaded metadata above (the tx is unlikely clobbered the value or
       touched the same cache or an adjacent one since). */

    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, seq ) ) ) {
    //FD_LOG_NOTICE(( "Overrun while reading (skipping from %lu to %lu to try to recover)", seq, seq_found ));
      ovrnr_cnt++;
      seq = seq_found;
      continue;
    }

#   if VALIDATE
    /* Validate that the frag payload was as expected */
    int corrupt = ((mask0 & mask1 & mask2 & mask3)!=-1);
    if( FD_UNLIKELY( corrupt ) ) FD_LOG_ERR(( "Corrupt payload received" ));
#   endif

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );
    iter++;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( !_fseq ) fd_wksp_delete( fd_fseq_leave( fseq ) );
  else         fd_wksp_unmap ( fd_fseq_leave( fseq ) );
  if( !_wksp ) fd_wksp_unmap ( fd_dcache_leave( dcache ) );
  else         fd_wksp_detach( wksp );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED and FD_HAS_AVX capabilities" ));
  fd_halt();
  return 0;
}

#endif
