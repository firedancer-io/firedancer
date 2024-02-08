#include "fd_tango.h"

#if FD_HAS_HOSTED

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
  char const * _fseq   = fd_env_strip_cmdline_cstr( &argc, &argv, "--fseq",   NULL, NULL                 );
  char const * _init   = fd_env_strip_cmdline_cstr( &argc, &argv, "--init",   NULL, NULL                 );
  uint         seed    = fd_env_strip_cmdline_uint( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() );
  int          lazy    = fd_env_strip_cmdline_int ( &argc, &argv, "--lazy",   NULL, 7                    );

  if( FD_UNLIKELY( !_cnc    ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join failed" ));

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong         depth = fd_mcache_depth          ( mcache );
  ulong const * sync  = fd_mcache_seq_laddr_const( mcache );

  ulong seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( sync );

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

  ulong ovrn_cnt = 0UL;

  FD_LOG_NOTICE(( "Running --init %lu (%s) --lazy %i", seq, _init ? "manual" : "auto", lazy ));

  ulong async_min = 1UL << lazy;
  ulong async_rem = 1UL; /* Do housekeeping on first iteration */

  long  then = fd_log_wallclock();
  ulong iter = 0UL;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Wait for frag seq */

    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   diff;

#   define WAIT_STYLE -1
#   define VALIDATE    1

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

      /* Send monitoring info */
      long now = fd_log_wallclock();
      fd_cnc_heartbeat( cnc, now );

      long dt = now - then;
      if( FD_UNLIKELY( dt > (long)1e9 ) ) {
        float mfps = (1e3f*(float)iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s rx (ovrn %lu)", (double)mfps, ovrn_cnt ));
        FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = FD_VOLATILE_CONST( fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) + ovrn_cnt;
        ovrn_cnt = 0UL;
        then     = now;
        iter     = 0UL;
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
    //FD_LOG_NOTICE(( "Overrun (skipping from %lu to %lu to try to recover)", seq, seq_found ));
      ovrn_cnt++;
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
       seq (the fragment we were looking for).  Validate it.  FIXME:
       Ideally, we'd validate continuity of the sig from each origin
       here too and probably should validate SOM/EOM/ERR are set in ctl
       given how test_meta_tx generates these.  tsorig and tspub are not
       validated but could be used to do latency diagnostics. */

#   if WAIT_STYLE==-1

#   if VALIDATE /* For code implementation testing */
    FD_TEST( chunk ==(uint  )sig );
    FD_TEST( sz    ==(ushort)sig );
#   else /* For hardware performance benchmarking */
    (void)sig; (void)chunk; (void)sz;
#   endif
    (void)tspub; (void)tsorig; (void)ctl;

#   elif WAIT_STYLE==0

#   if VALIDATE /* For code implementation testing */
    ulong sig = meta->sig;
    FD_TEST( meta->chunk ==(uint  )sig );
    FD_TEST( meta->sz    ==(ushort)sig );
#   else /* For hardware performance benchmarking */
    (void)meta->sig;
#   endif

#   elif WAIT_STYLE==1

#   if VALIDATE /* For code implementation testing */
    ulong sig = fd_frag_meta_sse0_sig( meta_sse0 );
    FD_TEST( fd_frag_meta_sse1_chunk ( meta_sse1 )==(ulong)(uint  )sig );
    FD_TEST( fd_frag_meta_sse1_sz    ( meta_sse1 )==(ulong)(ushort)sig );
#   else /* For hardware performance benchmarking */
    (void)meta_sse0;
    (void)meta_sse1;
#   endif

#   else

#   if VALIDATE /* For code implementation testing */
    ulong sig = fd_frag_meta_avx_sig( meta_avx );
    FD_TEST( fd_frag_meta_avx_chunk ( meta_avx )==(ulong)(uint  )sig );
    FD_TEST( fd_frag_meta_avx_sz    ( meta_avx )==(ulong)(ushort)sig );
#   else /* For hardware performance benchmarking */
    (void)meta_avx;
#   endif

#   endif

    (void)mline; /* Don't need to do any verification as we aren't processing payloads */

    /* Wind up for the next iteration */
    seq = fd_seq_inc( seq, 1UL );
    iter++;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( !_fseq ) fd_wksp_delete( fd_fseq_leave( fseq ) );
  else         fd_wksp_unmap ( fd_fseq_leave( fseq ) );
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
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capability" ));
  fd_halt();
  return 0;
}

#endif
