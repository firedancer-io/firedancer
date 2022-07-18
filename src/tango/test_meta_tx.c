#include "fd_tango.h"

#if FD_HAS_HOSTED && FD_HAS_AVX

/* This test uses the mcache application region for holding the rx
   flow controls and tx backpressure counters.  We'll use a cache line
   pair for each reliable rx_seq and the very end will hold backpressure
   counters. */

#define RX_MAX (256UL)

static uchar __attribute__((aligned(FD_FCTL_ALIGN))) shmem[ FD_FCTL_FOOTPRINT( RX_MAX ) ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  char const * _mcache = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache", NULL,                 NULL );
  char const * _init   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--init",   NULL,                 NULL );
  ulong        rx_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-cnt", NULL,                  0UL ); /* num rel rx */
  uint         seed    = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",   NULL, (uint)fd_tickcount() );
  ulong        max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--max",    NULL,            ULONG_MAX );

  if( FD_UNLIKELY( !_mcache       ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( rx_cnt>=RX_MAX ) ) FD_LOG_ERR(( "--rx-cnt too large for this unit-test" ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Joining to --mcache %s", _mcache ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "join failed" ));

  ulong   depth   = fd_mcache_depth    ( mcache );
  ulong * _tx_seq = fd_mcache_seq_laddr( mcache );
  uchar * app     = fd_mcache_app_laddr( mcache );
  ulong   app_sz  = fd_mcache_app_sz   ( mcache );

  if( FD_UNLIKELY( rx_cnt*136UL>app_sz ) )
    FD_LOG_ERR(( "increase mcache app_sz to at least %lu for this --rx_cnt", rx_cnt*136UL ));

  ulong tx_seq = _init ? fd_cstr_to_ulong( _init ) : fd_mcache_seq_query( _tx_seq );

  FD_LOG_NOTICE(( "Configuring for --rx-cnt %lu reliable consumers", rx_cnt ));

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
  ulong async_rem = 0UL;
  ulong cr_avail  = 0UL;

  FD_LOG_NOTICE(( "Running --init %lu (%s) --seed %u --max %lu", tx_seq, _init ? "manual" : "auto", seed, max ));

# define RELOAD (100000000UL)
  ulong iter = 0UL;
  ulong rem  = RELOAD;
  long  tic  = fd_log_wallclock();
  while( iter<max ) {

    /* Do housekeeping in the background */

    if( FD_UNLIKELY( !async_rem ) ) {
      fd_mcache_seq_update( _tx_seq, tx_seq );
      cr_avail = fd_fctl_tx_cr_update( fctl, cr_avail, tx_seq );
      async_rem = fd_async_reload( rng, async_min );
    }
    async_rem--;

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

    /* Go to the next iteration and, every once in while, log some
       performance metrics */

    iter++;
    rem--;
    if( FD_UNLIKELY( !rem ) ) {
      long  toc  = fd_log_wallclock();
      float mfps = (1e3f*(float)RELOAD) / (float)(toc-tic);
      FD_LOG_NOTICE(( "%lu: %7.3f Mfrag/s tx", iter, (double)mfps ));
      for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
        ulong * rx_backp = fd_fctl_rx_backp_laddr( fctl, rx_idx );
        FD_LOG_NOTICE(( "backp[%lu] %lu", rx_idx, *rx_backp ));
        *rx_backp = 0UL;
      }
      rem = RELOAD;
      tic = fd_log_wallclock();
    }

  }
# undef RELOAD

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_mcache_seq_update( _tx_seq, tx_seq ); /* Record where we got to */
  fd_fctl_delete( fd_fctl_leave( fctl ) );
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
