#include "../fd_tango.h"

FD_STATIC_ASSERT( 1<=FD_FCTL_RX_MAX_MAX && FD_FCTL_RX_MAX_MAX<=65535UL, unit_test );

FD_STATIC_ASSERT( FD_FCTL_ALIGN==sizeof(ulong), unit_test );

#define RX_MAX (128UL)
static uchar __attribute__((aligned(FD_FCTL_ALIGN))) shmem[ FD_FCTL_FOOTPRINT( RX_MAX ) ];
static ulong rx_seq [ RX_MAX ]; /* Init to zero */
static ulong rx_slow[ RX_MAX ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong rx_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-max",    NULL,    16UL );
  ulong rx_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-cnt",    NULL,     3UL );
  ulong rx_cr_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-cr-max", NULL, 12345UL );
  ulong cr_burst  = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-burst",  NULL,     1UL );
  ulong cr_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-max",    NULL,     0UL ); /* 0 <> use defaults */
  ulong cr_resume = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-resume", NULL,     0UL ); /* " */
  ulong cr_refill = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-refill", NULL,     0UL ); /* " */

  if( FD_UNLIKELY( rx_max>RX_MAX ) ) FD_LOG_ERR(( "Increase unit test RX_MAX to support this large --rx-max" ));

  FD_LOG_NOTICE(( "Testing --rx-max %lu --rx-cnt %lu --rx-cr-max %lu --cr-burst %lu --cr-max %lu --cr-resume %lu --cr-refill %lu",
                  rx_max, rx_cnt, rx_cr_max, cr_burst, cr_max, cr_resume, cr_refill ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_fctl_align()==FD_FCTL_ALIGN );

  FD_TEST(  fd_fctl_footprint( 0UL                    ) );
  FD_TEST(  fd_fctl_footprint( FD_FCTL_RX_MAX_MAX     ) );
  FD_TEST( !fd_fctl_footprint( FD_FCTL_RX_MAX_MAX+1UL ) );

  ulong footprint = fd_fctl_footprint( rx_max );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Bad --rx-max" ));
  FD_TEST( footprint==FD_FCTL_FOOTPRINT( rx_max ) );
  FD_TEST( footprint<=FD_FCTL_FOOTPRINT( RX_MAX ) );

  /* Test failure cases for fd_fctl_new */
  FD_TEST( fd_fctl_new( NULL,      rx_max               )==NULL ); /* null shmem       */
  FD_TEST( fd_fctl_new( shmem+1UL, rx_max               )==NULL ); /* misaligned shmem */
  FD_TEST( fd_fctl_new( shmem,     FD_FCTL_RX_MAX_MAX+1 )==NULL ); /* oversz rx_max    */

  void *      shfctl = fd_fctl_new ( shmem, rx_max ); FD_TEST( shfctl );
  fd_fctl_t * fctl   = fd_fctl_join( shfctl );        FD_TEST( fctl   );

  /* Test failure cases for fd_fctl_cfg_rx_add */
  FD_TEST( fd_fctl_cfg_rx_add( NULL, rx_cr_max, &rx_seq[ 0UL ], &rx_slow[ 0UL ] )==NULL ); /* null fctl       */
  FD_TEST( fd_fctl_cfg_rx_add( fctl, 0UL,       &rx_seq[ 0UL ], &rx_slow[ 0UL ] )==NULL ); /* zero cr_max     */
  FD_TEST( fd_fctl_cfg_rx_add( fctl, ~0UL,      &rx_seq[ 0UL ], &rx_slow[ 0UL ] )==NULL ); /* oversz cr_max   */
  FD_TEST( fd_fctl_cfg_rx_add( fctl, rx_cr_max, &rx_seq[ 0UL ], NULL            )==NULL ); /* null slow_laddr */

  /* Test failure cases for fd_fctl_cfg_done */
  FD_TEST( fd_fctl_cfg_done( NULL, cr_burst, cr_max, cr_resume, cr_refill )==NULL ); /* null fctl */

  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ )
    FD_TEST( fd_fctl_cfg_rx_add( fctl, (rx_idx+1UL)*rx_cr_max, &rx_seq[ rx_idx ], &rx_slow[ rx_idx ] ) );
  FD_TEST( fd_fctl_cfg_done( fctl, cr_burst, cr_max, cr_resume, cr_refill ) );

  FD_TEST( fd_fctl_rx_max( fctl )==rx_max );
  FD_TEST( fd_fctl_rx_cnt( fctl )==rx_cnt );

  if( !cr_burst  ) cr_burst  = fd_fctl_cr_burst ( fctl );
  if( !cr_max    ) cr_max    = fd_fctl_cr_max   ( fctl );
  if( !cr_resume ) cr_resume = fd_fctl_cr_resume( fctl );
  if( !cr_refill ) cr_refill = fd_fctl_cr_refill( fctl );

  FD_LOG_NOTICE(( "Got cr_burst %lu cr_max %lu cr_resume %lu cr_refill %lu", cr_burst, cr_max, cr_resume, cr_refill ));

  FD_TEST( fd_fctl_cr_burst ( fctl )==cr_burst  );
  FD_TEST( fd_fctl_cr_max   ( fctl )==cr_max    );
  FD_TEST( fd_fctl_cr_resume( fctl )==cr_resume );
  FD_TEST( fd_fctl_cr_refill( fctl )==cr_refill );

  ulong cr_burst_max = (ulong)LONG_MAX;
  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) cr_burst_max = fd_ulong_min( cr_burst_max, fd_fctl_rx_cr_max( fctl, rx_idx ) );

  FD_TEST(      1UL<=fd_fctl_cr_burst ( fctl ) ); FD_TEST( fd_fctl_cr_burst ( fctl )<=cr_burst_max    );
  FD_TEST( cr_burst<=fd_fctl_cr_max   ( fctl ) ); FD_TEST( fd_fctl_cr_max   ( fctl )<=(ulong)LONG_MAX );
  FD_TEST( cr_burst<=fd_fctl_cr_resume( fctl ) ); FD_TEST( fd_fctl_cr_resume( fctl )<=cr_max          );
  FD_TEST( cr_burst<=fd_fctl_cr_refill( fctl ) ); FD_TEST( fd_fctl_cr_refill( fctl )<=cr_resume       );

  for( ulong rx_idx=0UL; rx_idx<rx_cnt; rx_idx++ ) {
    FD_TEST( fd_fctl_rx_cr_max    ( fctl, rx_idx )==(rx_idx+1UL)*rx_cr_max );
    FD_TEST( fd_fctl_rx_seq_laddr ( fctl, rx_idx )==&rx_seq [ rx_idx ]     );
    FD_TEST( fd_fctl_rx_slow_laddr( fctl, rx_idx )==&rx_slow[ rx_idx ]     );
  }

  /* FIXME: MORE EXTENSIVE TESTING HERE (INCL COVERAGE OF
     FD_FCTL_RX_CR_RETURN) */
  ulong rx_idx_slow; ulong cr_avail = fd_fctl_cr_query( fctl, 0UL, &rx_idx_slow );
  FD_TEST( cr_avail<=cr_max );
  FD_TEST( (rx_idx_slow<=rx_cnt) | (rx_idx_slow==ULONG_MAX) );

  /* FIXME: TX_CR_UPDATE TESTING HERE */
  fd_fctl_tx_cr_update( fctl, 0UL, 0UL );

  FD_TEST( fd_fctl_leave ( fctl )==shfctl );
  FD_TEST( fd_fctl_delete( fctl )==shmem  );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

