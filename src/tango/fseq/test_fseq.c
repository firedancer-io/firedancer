#include "../fd_tango.h"

FD_STATIC_ASSERT( FD_FSEQ_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_FSEQ_APP_ALIGN    ==32UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_APP_FOOTPRINT==96UL, unit_test );

FD_STATIC_ASSERT( FD_FSEQ_DIAG_PUB_CNT  ==0UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_DIAG_PUB_SZ   ==1UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_DIAG_FILT_CNT ==2UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_DIAG_FILT_SZ  ==3UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_DIAG_OVRNP_CNT==4UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_DIAG_OVRNR_CNT==5UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_DIAG_SLOW_CNT ==6UL, unit_test );

static uchar shmem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong seq0 = fd_env_strip_cmdline_ulong( &argc, &argv, "--seq0", NULL, 1234UL );

  FD_LOG_NOTICE(( "Testing with --seq0 %lu", seq0 ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_fseq_align    ()==FD_FSEQ_ALIGN     );
  FD_TEST( fd_fseq_footprint()==FD_FSEQ_FOOTPRINT );

  void *  shfseq = fd_fseq_new( shmem, seq0 ); FD_TEST( shfseq );
  ulong * fseq   = fd_fseq_join( shfseq );     FD_TEST( fseq );

  uchar *       app       = fd_fseq_app_laddr      ( fseq );
  uchar const * app_const = fd_fseq_app_laddr_const( fseq );
  FD_TEST( (ulong)app==(ulong)app_const );
  FD_TEST( fd_ulong_is_aligned( (ulong)app, FD_FSEQ_APP_ALIGN ) );
  for( ulong b=0UL; b<FD_FSEQ_APP_FOOTPRINT; b++ ) FD_TEST( !app_const[b] );

  FD_TEST( fd_fseq_seq0 ( fseq )==seq0 );
  FD_TEST( fd_fseq_query( fseq )==seq0 );

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong seq = fd_rng_ulong( rng );
    fd_fseq_update( fseq, seq );
    FD_TEST( fd_fseq_seq0 ( fseq )==seq0 );
    FD_TEST( fd_fseq_query( fseq )==seq  );
  }

  FD_TEST( fd_fseq_leave ( fseq   )==shfseq );
  FD_TEST( fd_fseq_delete( shfseq )==shmem  );
  
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
