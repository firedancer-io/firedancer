#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

FD_STATIC_ASSERT( FD_CHUNK_SZ==64UL, unit_test );

static uchar fseq_mem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  char const * _cnc    = fd_env_strip_cmdline_cstr( &argc, &argv, "--cnc",    NULL, NULL                 );
  char const * _mcache = fd_env_strip_cmdline_cstr( &argc, &argv, "--mcache", NULL, NULL                 );
  char const * _dcache = fd_env_strip_cmdline_cstr( &argc, &argv, "--dcache", NULL, NULL                 );
  char const * _fctl   = fd_env_strip_cmdline_cstr( &argc, &argv, "--fctl",   NULL, NULL                 );
  char const * _init   = fd_env_strip_cmdline_cstr( &argc, &argv, "--init",   NULL, NULL                 );
  uint         seed    = fd_env_strip_cmdline_uint( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() );

  if( FD_UNLIKELY( !_cnc    ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( !_dcache ) ) FD_LOG_ERR(( "--dcache not specified" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join failed" ));

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong         depth   = fd_mcache_depth          ( mcache );
  ulong const * _tx_seq = fd_mcache_seq_laddr_const( mcache );

  ulong rx_seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( _tx_seq );

  FD_LOG_NOTICE(( "Joining to --dcache %s", _dcache ));

  uchar const * dcache = fd_dcache_join( fd_wksp_map( _dcache ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "join failed" ));

  void const * base = fd_wksp_containing( dcache );
  if( FD_UNLIKELY( !base ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));

  ulong * _rx_seq;
  if( !_fctl ) {
    FD_LOG_NOTICE(( "Unreliable mode; will not send flow control information to transmitter" ));
    _rx_seq = fd_fseq_join( fd_fseq_new( fseq_mem, 0UL ) );
  } else {
    FD_LOG_NOTICE(( "Reliable mode; joining to --fctl %s for sending flow control information to transmitter", _fctl ));
    _rx_seq = fd_fseq_join( fd_wksp_map( _fctl ) );
  }
  if( FD_UNLIKELY( !_rx_seq ) ) FD_LOG_ERR(( "join failed" ));

  ulong * _ovrn_cnt = (ulong *)fd_fseq_app_laddr( _rx_seq );

  FD_VOLATILE( _ovrn_cnt[0] ) = 0UL; /* ovrnp */
  FD_VOLATILE( _ovrn_cnt[1] ) = 0UL; /* ovrnr */

  ulong async_min = 1UL<<7;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  FD_LOG_NOTICE(( "Running --init %lu (%s)", rx_seq, _init ? "manual" : "auto" ));

  long  then      = fd_log_wallclock();
  ulong iter      = 0UL;
  ulong ovrnp_cnt = 0UL; /* Count of overruns while polling for next rx_seq */
  ulong ovrnr_cnt = 0UL; /* Count of overruns while processing rx_seq payload */

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Wait for frag rx_seq */

    ulong seq_found;
    long  diff;

#   define WAIT_STYLE 0
#   define VALIDATE   1

#   if WAIT_STYLE==0 /* Compatible with all PUBLISH_STYLE */

    fd_frag_meta_t meta[1];
    FD_MCACHE_WAIT( meta, seq_found, diff, async_rem, mcache, depth, rx_seq );

#   elif WAIT_STYLE==1 /* Compatible with all PUBLISH_STYLE */

    __m128i meta_sse0;
    __m128i meta_sse1;
    FD_MCACHE_WAIT_SSE( meta_sse0, meta_sse1, seq_found, diff, async_rem, mcache, depth, rx_seq );

#   else /* Compatible with PUBLISH_STYLE==2, requires target with atomic aligned AVX load / store */

    __m256i meta_avx;
    FD_MCACHE_WAIT_AVX( meta_avx, seq_found, diff, async_rem, mcache, depth, rx_seq );

#   endif

    /* Do housekeeping in background */

    if( FD_UNLIKELY( !async_rem ) ) {

      /* Send flow control credits */

      fd_fctl_rx_cr_return( _rx_seq, rx_seq );

      /* Send monitoring info */

      long now = fd_log_wallclock();
      fd_cnc_heartbeat( cnc, fd_log_wallclock() );

      long dt = now - then;
      if( FD_UNLIKELY( dt > (long)1e9 ) ) {
        float mfps = (1e3f*(float)iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s rx (ovrnp %lu ovrnr %lu)", (double)mfps, ovrnp_cnt, ovrnr_cnt ));
        _ovrn_cnt[0] += ovrnp_cnt;
        _ovrn_cnt[1] += ovrnr_cnt;
        then      = now;
        iter      = 0UL;
        ovrnp_cnt = 0UL;
        ovrnr_cnt = 0UL;
      }

      /* Receive command-and-control signals */

      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      async_rem = fd_async_reload( rng, async_min );
      continue;
    }

    /* Handle overrun */

    if( FD_UNLIKELY( diff ) ) {
    //FD_LOG_NOTICE(( "Overrun while polling (skipping from %lu to %lu to try to recover)", rx_seq, seq_found ));
      ovrnp_cnt++;
      rx_seq = seq_found;
#     if WAIT_STYLE!=2
      continue; /* We can't trust the metadata we just loaded, so we try again */
#     endif

      /* Note: we could also do (for any wait style)
           rx_seq = fd_mcache_seq_query( _tx_seq );
           continue;
         here to recover from the most recent seq advertised by the
         producer.  But this can create cache hotspots and the simpler
         and fast handling is often even more current in practice that
         the above. */
    }

    /* At this point, we've atomically loaded the fragment metadata for
       rx_seq (the fragment we were looking for).  Validate the metadata
       and validate the corresponding fragment in the dcache. */

#   if WAIT_STYLE==0
 
    TEST( meta->sig==rx_seq );

    ulong chunk  = (ulong)meta->chunk;
    ulong sz     = (ulong)meta->sz;
    ulong ctl    = (ulong)meta->ctl;
    ulong tsorig = (ulong)meta->tsorig;
    ulong tspub  = (ulong)meta->tspub;

#   elif WAIT_STYLE==1

    TEST( fd_frag_meta_sse0_sig( meta_sse0 )==rx_seq );

    ulong chunk  = fd_frag_meta_sse1_chunk ( meta_sse1 );
    ulong sz     = fd_frag_meta_sse1_sz    ( meta_sse1 );
    ulong ctl    = fd_frag_meta_sse1_ctl   ( meta_sse1 );
    ulong tsorig = fd_frag_meta_sse1_tsorig( meta_sse1 );
    ulong tspub  = fd_frag_meta_sse1_tspub ( meta_sse1 );

#   else

    TEST( fd_frag_meta_avx_sig( meta_avx )==rx_seq );

    ulong chunk  = fd_frag_meta_avx_chunk ( meta_avx );
    ulong sz     = fd_frag_meta_avx_sz    ( meta_avx );
    ulong ctl    = fd_frag_meta_avx_ctl   ( meta_avx );
    ulong tsorig = fd_frag_meta_avx_tsorig( meta_avx );
    ulong tspub  = fd_frag_meta_avx_tspub ( meta_avx );

#   endif

    (void)ctl;                 /* FIXME: ADD REASSEMBLY LOGIC */
    (void)tsorig; (void)tspub; /* FIXME: ADD LATENCY AND BANDWIDTH STATS */

    uchar const * p = (uchar const *)fd_chunk_to_laddr_const( base, chunk );
    __m256i avx = _mm256_set1_epi64x( (long)rx_seq );
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

    /* At this point, we've loaded the metadata and speculatively
       processed the fragment payload.  Check that we weren't overrun
       while processing.  Since fd_mcache_query is a compiler memory
       fence, this check will not execute until the speculative loads
       above are complete.  Also note that this check in normal
       operation is typically a very fast L1 cache hit on the already
       loaded metadata above (the tx is unlikely clobbered the value or
       touched the same cache or an adjacent one since). */

    seq_found = fd_mcache_query( mcache, depth, rx_seq );
    if( FD_UNLIKELY( seq_found!=rx_seq ) ) {
    //FD_LOG_NOTICE(( "Overrun while reading (skipping from %lu to %lu to try to recover)", rx_seq, seq_found ));
      ovrnr_cnt++;
      rx_seq = seq_found;
      continue;
    }

    /* Validate that the frag payload was as expected */

    int corrupt = ((mask0 & mask1 & mask2 & mask3)!=-1);
    if( FD_UNLIKELY( corrupt ) ) FD_LOG_ERR(( "Corrupt payload received" ));

    /* Wind up for the next iteration */

    rx_seq = fd_seq_inc( rx_seq, 1UL );
    iter++;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( !_fctl ) fd_wksp_delete( fd_fseq_leave( _rx_seq ) );
  else         fd_wksp_unmap ( fd_fseq_leave( _rx_seq ) );
  fd_wksp_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_rng_delete( fd_rng_leave( rng ) );

# undef TEST

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
