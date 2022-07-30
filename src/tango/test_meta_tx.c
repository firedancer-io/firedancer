#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

/* This test uses the mcache application region for holding the rx flow
   controls and tx backpressure counters.  We'll use a cache line pair
   for each reliable rx_seq (as these are all written frequently by
   different rx's) and the very end will hold backpressure counters for
   each reliable rx (as these are all written infrequently by the tx).
   We store the rx overrun accumulator in the rx's cnc app region so all
   rx's (regardless of being reliable or not) have a remotely
   monitorable overrun counter. */

#define RX_MAX (256UL)

static uchar __attribute__((aligned(FD_FCTL_ALIGN))) shmem[ FD_FCTL_FOOTPRINT( RX_MAX ) ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  char const * _cnc    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",    NULL,                 NULL );
  char const * _mcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache", NULL,                 NULL );
  char const * _init   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--init",   NULL,                 NULL );
  ulong        rx_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-cnt", NULL,                  0UL ); /* num rel rx */
  uint         seed    = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() );

  if( FD_UNLIKELY( !_cnc          ) ) FD_LOG_ERR(( "--cnc not specified" ));
  if( FD_UNLIKELY( !_mcache       ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( rx_cnt>=RX_MAX ) ) FD_LOG_ERR(( "--rx-cnt too large for this unit-test" ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --cnc %s", _cnc ));

  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "join failed" ));

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));

  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong   depth   = fd_mcache_depth    ( mcache );
  ulong * _tx_seq = fd_mcache_seq_laddr( mcache );
  uchar * app     = fd_mcache_app_laddr( mcache );
  ulong   app_sz  = fd_mcache_app_sz   ( mcache );

  ulong tx_seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( _tx_seq );

  FD_LOG_NOTICE(( "Configuring for --rx-cnt %lu reliable consumers", rx_cnt ));

  if( FD_UNLIKELY( rx_cnt*136UL>app_sz ) ) FD_LOG_ERR(( "increase mcache app_sz to at least %lu", rx_cnt*136UL ));

  fd_fctl_t * fctl = fd_fctl_join( fd_fctl_new( shmem, rx_cnt ) );

  uchar * fctl_top = app;
  uchar * fctl_bot = app + fd_ulong_align_dn( app_sz, 8UL );
  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
    ulong * rx_lseq  = (ulong *) fctl_top;      fctl_top += 128UL;
    ulong * rx_backp = (ulong *)(fctl_bot-8UL); fctl_bot -=   8UL;
    fd_fctl_cfg_rx_add( fctl, depth, rx_lseq, rx_backp );
    *rx_backp = 0UL;
  }
  fd_fctl_cfg_done( fctl, 0UL, 0UL, 0UL, 0UL );

  ulong async_min = 1UL<<13;
  ulong async_rem = 1UL; /* Do housekeeping on the first iteration */
  ulong cr_avail  = 0UL;

  FD_LOG_NOTICE(( "Running --init %lu (%s)", tx_seq, _init ? "manual" : "auto" ));

  long  then = fd_log_wallclock();
  ulong iter = 0UL;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeeping in the background */

    async_rem--;
    if( FD_UNLIKELY( !async_rem ) ) {

      /* Send synchronization info */

      fd_mcache_seq_update( _tx_seq, tx_seq );

      /* Send monitoring info */

      long now = fd_log_wallclock();
      fd_cnc_heartbeat( cnc, now );

      long dt = now - then;
      if( FD_UNLIKELY( dt > (long)1e9 ) ) {
        float mfps = (1e3f*(float)iter) / (float)dt;
        FD_LOG_NOTICE(( "%7.3f Mfrag/s tx", (double)mfps ));
        for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
          ulong * rx_backp = fd_fctl_rx_backp_laddr( fctl, rx_idx );
          FD_LOG_NOTICE(( "backp[%lu] %lu", rx_idx, *rx_backp ));
          *rx_backp = 0UL;
        }
        then = now;
        iter = 0UL;
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

      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, tx_seq );

      async_rem = fd_async_reload( rng, async_min );
    }

    /* Check if we are backpressured */

    if( FD_UNLIKELY( !cr_avail ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
    
    /* We are not backpressured, so send metadata with a test pattern */
    
    ulong sig    =                tx_seq;
    ulong chunk  = (ulong)(uint  )tx_seq;
    ulong sz     = (ulong)(ushort)tx_seq;
    ulong ctl    = (ulong)(ushort)tx_seq;
    ulong tsorig = (ulong)(uint  )tx_seq;
    ulong tspub  = (ulong)(uint  )tx_seq;

#   define PUBLISH_STYLE 0

#   if PUBLISH_STYLE==0 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish( mcache, depth, tx_seq, sig, chunk, sz, ctl, tsorig, tspub );

#   elif PUBLISH_STYLE==1 /* Incompatible with WAIT_STYLE==2 */

    fd_mcache_publish_sse( mcache, depth, tx_seq, sig, chunk, sz, ctl, tsorig, tspub );

#   else /* Compatible with all wait styles, requires target with atomic
            aligned AVX load/store support */

    fd_mcache_publish_avx( mcache, depth, tx_seq, sig, chunk, sz, ctl, tsorig, tspub );

#   endif

    tx_seq = fd_seq_inc( tx_seq, 1UL );
    cr_avail--;
    iter++;
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_fctl_delete( fd_fctl_leave( fctl ) );
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
