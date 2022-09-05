#include "fd_disco.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  TEST( fd_disco_lazy_default( 0UL       )== 9L      );
  TEST( fd_disco_lazy_default( 1UL       )== 9L      );
  TEST( fd_disco_lazy_default( 3UL       )== 9L      );
  TEST( fd_disco_lazy_default( 3UL       )== 9L      );
  TEST( fd_disco_lazy_default( 4UL       )==18L      );
  TEST( fd_disco_lazy_default( ULONG_MAX )<=LONG_MAX );

# undef TEST

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

