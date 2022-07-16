#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

#define RX_MAX (FD_MCACHE_APP_FOOTPRINT/136UL)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  char const * _mcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache", NULL,      NULL );
  char const * _init   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--init",   NULL,      NULL );
  ulong        max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--max",    NULL, ULONG_MAX );
  ulong        rx_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-idx", NULL, ULONG_MAX ); /* ULONG_MAX <> unreliable rx */

  if( FD_UNLIKELY( !_mcache                               ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( (rx_idx!=ULONG_MAX) & (rx_idx>=RX_MAX) ) ) FD_LOG_ERR(( "--rx-idx too large for this unit-test" ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong poll_rem = 10000UL;

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong         depth   = fd_mcache_depth          ( mcache );
  ulong const * _tx_seq = fd_mcache_seq_laddr_const( mcache );
  ulong         rx_seq  = _init ? fd_cstr_to_ulong( _init ) : FD_VOLATILE_CONST( *_tx_seq );

  ulong   local_rx_seq[1];
  ulong * _rx_seq;
  if( rx_idx==ULONG_MAX ) _rx_seq = local_rx_seq; /* Unreliable consumer ... don't need to communicate fctl */
  else                    _rx_seq = (ulong *)(fd_mcache_app_laddr( mcache ) + 128UL*rx_idx);
  FD_VOLATILE( *_rx_seq ) = rx_seq; /* Note: this can be amortized */

  FD_LOG_NOTICE(( "Running --init %lu (%s) --max %lu --rx-idx %lu", rx_seq, _init ? "manual" : "auto", max, rx_idx ));

  ulong ovrn_cnt = 0UL; /* FIXME: PUT THIS IN A SHARED LOCATION */

# define RELOAD (100000000UL)
  ulong iter     = 0UL;
  ulong rem      = RELOAD;
  long  tic      = fd_log_wallclock();
  while( iter<max ) {

    /* Wait for frag rx_seq */

    ulong seq_found;
    long  diff;

#   define WAIT_STYLE 0
#   define VALIDATE   1

#   if WAIT_STYLE==0 /* Compatible with all PUBLISH_STYLE */

    fd_frag_meta_t meta[1];
    FD_MCACHE_WAIT( meta, seq_found, diff, poll_rem, mcache, depth, rx_seq );

#   elif WAIT_STYLE==1 /* Compatible with all PUBLISH_STYLE */

    __m128i meta_sse0;
    __m128i meta_sse1;
    FD_MCACHE_WAIT_SSE( meta_sse0, meta_sse1, seq_found, diff, poll_rem, mcache, depth, rx_seq );

#   else /* Compatible with PUBLISH_STYLE==2, requires target with atomic aligned AVX load / store */

    __m256i meta_avx;
    FD_MCACHE_WAIT_AVX( meta_avx, seq_found, diff, poll_rem, mcache, depth, rx_seq );

#   endif

    if( FD_UNLIKELY( !poll_rem ) ) {
    //FD_LOG_NOTICE(( "Timeout" ));
      poll_rem = 10000UL;
      continue;
    }

    if( FD_UNLIKELY( diff ) ) {
    //FD_LOG_NOTICE(( "Overrun (skipping from %lu to %lu to try to recover)", rx_seq, seq_found ));
      ovrn_cnt++;
      rx_seq = seq_found;
#     if WAIT_STYLE!=2
      continue; /* We can't trust the metadata we just loaded, so we try again */
#     endif

      /* Note: we could also do (for any wait style)
           rx_seq = FD_VOLATILE_CONST( *_tx_seq );
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
    FD_VOLATILE( *_rx_seq ) = rx_seq; /* Note: this can be amortized */

    /* This iteration was successful, go to the next iteration and,
       every once in a while, log some performance metrics. */

    iter++;
    rem--;
    if( FD_UNLIKELY( !rem ) ) {
      long  toc  = fd_log_wallclock();
      float mfps = (1e3f*(float)RELOAD) / (float)(toc-tic);
      FD_LOG_NOTICE(( "%11lu: %7.3f Mfrag/s rx (ovrn %lu)", iter, (double)mfps, ovrn_cnt ));
      rem      = RELOAD;
      tic      = fd_log_wallclock();
      ovrn_cnt = 0UL;
    }

  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_wksp_unmap( fd_mcache_leave( mcache ) );
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
