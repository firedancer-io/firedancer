#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

#define RX_MAX (128UL) /* Max _reliable_ (arb unreliable) */

static uchar  fctl_mem[ FD_FCTL_FOOTPRINT( RX_MAX ) ] __attribute__((aligned(FD_FCTL_ALIGN)));
static char * _fseq[ RX_MAX ];

#define FD_CNC_DIAG_IN_BACKP   (0UL)
#define FD_CNC_DIAG_BACKP_CNT  (1UL)

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

  char const * _cnc    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",    NULL, NULL                 );
  char const * _mcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache", NULL, NULL                 );
  char const * _fseqs  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--fseqs",  NULL, ""                   );
  char const * _init   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--init",   NULL, NULL                 );
  ulong        tx_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-idx", NULL, 0UL                  );
  uint         seed    = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() );
  long         lazy    = fd_env_strip_cmdline_long ( &argc, &argv, "--lazy",   NULL, 0L                   );

  if( FD_UNLIKELY( !_cnc                         ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache                      ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( tx_idx>=FD_FRAG_META_ORIG_MAX ) ) FD_LOG_ERR(( "--tx-idx too large" ));

  ulong rx_cnt = fd_cstr_tokenize( _fseq, RX_MAX, (char *)_fseqs, ',' ); /* Note: argv isn't const to okay to cast away const */
  if( FD_UNLIKELY( rx_cnt>RX_MAX ) ) FD_LOG_ERR(( "--rx-cnt too large for this unit-test" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc                      ) ) FD_LOG_ERR(( "join failed" ));
  if( FD_UNLIKELY( fd_cnc_app_sz( cnc )<16UL ) ) FD_LOG_ERR(( "cnc app sz must be at least 16" ));

  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  int     in_backp = 1;
  FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ) = 1UL;
  FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = 0UL;

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong   depth = fd_mcache_depth    ( mcache );
  ulong * sync  = fd_mcache_seq_laddr( mcache );

  ulong seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( sync );

  FD_LOG_NOTICE(( "Configuring flow control (rx_cnt %lu)", rx_cnt ));

  fd_fctl_t * fctl = fd_fctl_join( fd_fctl_new( fctl_mem, rx_cnt ) );
  if( FD_UNLIKELY( !fctl ) ) FD_LOG_ERR(( "join failed" ));

  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {

    FD_LOG_NOTICE(( "Joining to reliable rx %lu fseq %s", rx_idx, _fseq[ rx_idx ] ));
    ulong * fseq = fd_fseq_join( fd_wksp_map( _fseq[ rx_idx ] ) );
    if( FD_UNLIKELY( !fseq ) ) FD_LOG_ERR(( "join failed" ));
    ulong * fseq_diag = (ulong *)fd_fseq_app_laddr( fseq );

    if( FD_UNLIKELY( !fd_fctl_cfg_rx_add( fctl, depth, fseq, &fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) ) )
      FD_LOG_ERR(( "fd_fctl_cfg_rx_add failed" ));

    FD_VOLATILE( fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL;
  }

  /* cr_burst is 1 because we only send at most 1 fragment metadata
     between checking cr_avail.  We use defaults for cr_max, cr_resume
     and cr_refill (consider letting user configure). */
  if( FD_UNLIKELY( !fd_fctl_cfg_done( fctl, 1UL, 0UL, 0UL, 0UL ) ) ) FD_LOG_ERR(( "fd_fctl_cfg_done failed" ));
  FD_LOG_NOTICE(( "cr_burst %lu cr_max %lu cr_resume %lu cr_refill %lu",
                  fd_fctl_cr_burst( fctl ), fd_fctl_cr_max( fctl ), fd_fctl_cr_resume( fctl ), fd_fctl_cr_refill( fctl ) ));

  ulong cr_avail = 0UL;

  lazy = fd_tempo_lazy_default( depth );
  FD_LOG_NOTICE(( "Running --tx-idx %lu --init %lu (%s) --lazy %li ns", tx_idx, seq, _init ? "manual" : "auto", lazy ));

  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  ulong async_min   = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, tick_per_ns );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  long  now  = fd_tickcount();
  long  then = now;            /* Do housekeeping on first iteration of run loop */

  long  diag_interval = (long)(1e9f*tick_per_ns);
  long  diag_last     = now;
  ulong diag_iter     = 0UL;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      long dt = now - diag_last;
      if( FD_UNLIKELY( dt>=diag_interval ) ) {
        float mfps = ((1e3f*tick_per_ns)*(float)diag_iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s tx (in_backp %lu backp_cnt %lu)", (double)mfps,
                        FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ),
                        FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) ));
        for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
          ulong * slow = fd_fctl_rx_slow_laddr( fctl, rx_idx );
          FD_LOG_NOTICE(( "slow%lu %lu", rx_idx, FD_VOLATILE_CONST( *slow ) ));
          FD_VOLATILE( *slow ) = 0UL;
        }
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = 0UL;
        diag_last = now;
        diag_iter = 0UL;
      }

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Receive flow control credits */
      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, seq );
      if( FD_UNLIKELY( in_backp ) ) {
        if( FD_LIKELY( cr_avail ) ) {
          FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP ] ) = 0UL;
          in_backp = 0;
        }
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Check if we are backpressured */
    if( FD_UNLIKELY( !cr_avail ) ) {
      if( FD_UNLIKELY( !in_backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_IN_BACKP  ] ) = 0UL;
        FD_VOLATILE( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_CNC_DIAG_BACKP_CNT ] ) + 1UL;
        in_backp = 1;
      }
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }
    
    /* We are not backpressured, so send metadata with a test pattern */
    
    ulong sig    =                seq;
    ulong chunk  = (ulong)(uint  )seq;
    ulong sz     = (ulong)(ushort)seq;
    ulong ctl    = fd_frag_meta_ctl( tx_idx,1,1,1 );

    now = fd_tickcount();
    ulong tsorig = (ulong)fd_frag_meta_ts_comp( now );
    ulong tspub  = tsorig;

#   define PUBLISH_STYLE 0

#   if PUBLISH_STYLE==0 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

#   elif PUBLISH_STYLE==1 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish_sse( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

#   else /* Compatible with all wait styles, requires target with atomic
            aligned AVX load/store support */

    fd_mcache_publish_avx( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

#   endif

    seq = fd_seq_inc( seq, 1UL );
    cr_avail--;
    diag_iter++;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  while( rx_cnt ) fd_wksp_unmap( fd_fctl_rx_seq_laddr( fctl, --rx_cnt ) );
  fd_fctl_delete( fd_fctl_leave( fctl ) );
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
