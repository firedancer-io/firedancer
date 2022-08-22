#include "../fd_tango.h"

FD_STATIC_ASSERT( FD_FSEQ_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_FSEQ_FOOTPRINT==128UL, unit_test );

static uchar shmem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong seq0 = fd_env_strip_cmdline_ulong( &argc, &argv, "--seq0", NULL, 1234UL );

  FD_LOG_NOTICE(( "Testing with --seq0 %lu", seq0 ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  TEST( fd_fseq_align    ()==FD_FSEQ_ALIGN     );
  TEST( fd_fseq_footprint()==FD_FSEQ_FOOTPRINT );

  void *  shfseq = fd_fseq_new( shmem, seq0 ); TEST( shfseq );
  ulong * fseq   = fd_fseq_join( shfseq );     TEST( fseq );

  TEST( fd_fseq_seq0 ( fseq )==seq0 );
  TEST( fd_fseq_query( fseq )==seq0 );

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong seq = fd_rng_ulong( rng );
    fd_fseq_update( fseq, seq );
    TEST( fd_fseq_seq0 ( fseq )==seq0 );
    TEST( fd_fseq_query( fseq )==seq  );
  }

  TEST( fd_fseq_leave ( fseq   )==shfseq );
  TEST( fd_fseq_delete( shfseq )==shmem  );
  
# undef TEST

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
