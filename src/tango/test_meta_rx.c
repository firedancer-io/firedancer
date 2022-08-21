#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

/* This test uses the mcache application region for holding the rx flow
   controls.  We'll use a cache line pair for each reliable rx_seq (as
   these are all written frequently by different rx's).  We store the tx
   backpressure counters in the tx's cnc app region and the rx overrun
   counters in the rx's cnc app region so all tx's and rx's (regardless
   of being reliable or not) have a remotely monitorable backpressure
   and overrun counters. */

#define RX_MAX (128UL)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  char const * _cnc    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",    NULL,                 NULL );
  char const * _mcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache", NULL,                 NULL );
  char const * _init   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--init",   NULL,                 NULL );
  ulong        rx_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-idx", NULL,            ULONG_MAX ); /* ULONG_MAX<>unrel */
  uint         seed    = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() );

  if( FD_UNLIKELY( !_cnc                                  ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache                               ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( (rx_idx!=ULONG_MAX) & (rx_idx>=RX_MAX) ) ) FD_LOG_ERR(( "--rx-idx too large for this unit-test" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join failed" ));

  FD_LOG_NOTICE(( "Joining to monitoring" ));

  ulong * _ovrn_cnt = fd_cnc_app_laddr( cnc );
  *_ovrn_cnt = 0UL;

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong         depth   = fd_mcache_depth          ( mcache );
  ulong const * _tx_seq = fd_mcache_seq_laddr_const( mcache );
  uchar *       app     = fd_mcache_app_laddr      ( mcache );
  ulong         app_sz  = fd_mcache_app_sz         ( mcache );

  ulong rx_seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( _tx_seq );

  FD_LOG_NOTICE(( "Configuring flow control for --rx-idx %lu", rx_idx ));

  ulong   local_rx_seq[1];
  ulong * _rx_seq;
  if( rx_idx==ULONG_MAX ) _rx_seq = local_rx_seq; /* Unreliable consumer ... don't need to communicate fctl so use dummy */
  else { /* Reliable consumer ... communicate fctl via appropriate cache line pair in app region */
    if( FD_UNLIKELY( (rx_idx+1UL)*128UL > app_sz ) )
      FD_LOG_ERR(( "Increase mcache app-sz to at least %lu", (rx_idx+1UL)*128UL ));
    _rx_seq = (ulong *)(app + rx_idx*128UL);
  }

  ulong async_min = 1UL<<7;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  FD_LOG_NOTICE(( "Running --init %lu (%s)", rx_seq, _init ? "manual" : "auto" ));

  long  then     = fd_log_wallclock();
  ulong iter     = 0UL;
  ulong ovrn_cnt = 0UL;

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
        FD_LOG_NOTICE(( "%7.3f Mfrag/s rx (ovrn %lu)", (double)mfps, ovrn_cnt ));
        *_ovrn_cnt += ovrn_cnt;
        then     = now;
        iter     = 0UL;
        ovrn_cnt = 0UL;
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
    //FD_LOG_NOTICE(( "Overrun (skipping from %lu to %lu to try to recover)", rx_seq, seq_found ));
      ovrn_cnt++;
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

    /* At this point, we've atomically loaded the fragment metadata
       for rx_seq (the fragment we were looking for).  Validate it.*/

#   if WAIT_STYLE==0

#   if VALIDATE /* For code implementation testing */
    TEST( meta->sig   ==        rx_seq );
    TEST( meta->chunk ==(uint  )rx_seq );
    TEST( meta->sz    ==(ushort)rx_seq );
    TEST( meta->ctl   ==(ushort)rx_seq );
    TEST( meta->tsorig==(uint  )rx_seq );
    TEST( meta->tspub ==(uint  )rx_seq );
#   else /* For hardware performance benchmarking */
    (void)meta->sig;
#   endif

#   elif WAIT_STYLE==1

#   if VALIDATE /* For code implementation testing */
    TEST( fd_frag_meta_sse0_sig   ( meta_sse0 )==               rx_seq );
    TEST( fd_frag_meta_sse1_chunk ( meta_sse1 )==(ulong)(uint  )rx_seq );
    TEST( fd_frag_meta_sse1_sz    ( meta_sse1 )==(ulong)(ushort)rx_seq );
    TEST( fd_frag_meta_sse1_ctl   ( meta_sse1 )==(ulong)(ushort)rx_seq );
    TEST( fd_frag_meta_sse1_tsorig( meta_sse1 )==(ulong)(uint  )rx_seq );
    TEST( fd_frag_meta_sse1_tspub ( meta_sse1 )==(ulong)(uint  )rx_seq );
#   else /* For hardware performance benchmarking */
    (void)meta_sse0;
    (void)meta_sse1;
#   endif

#   else

#   if VALIDATE /* For code implementation testing */
    TEST( fd_frag_meta_avx_sig   ( meta_avx )==               rx_seq );
    TEST( fd_frag_meta_avx_chunk ( meta_avx )==(ulong)(uint  )rx_seq );
    TEST( fd_frag_meta_avx_sz    ( meta_avx )==(ulong)(ushort)rx_seq );
    TEST( fd_frag_meta_avx_ctl   ( meta_avx )==(ulong)(ushort)rx_seq );
    TEST( fd_frag_meta_avx_tsorig( meta_avx )==(ulong)(uint  )rx_seq );
    TEST( fd_frag_meta_avx_tspub ( meta_avx )==(ulong)(uint  )rx_seq );
#   else /* For hardware performance benchmarking */
    (void)meta_avx;
#   endif

#   endif

    rx_seq = fd_seq_inc( rx_seq, 1UL );
    iter++;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

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
