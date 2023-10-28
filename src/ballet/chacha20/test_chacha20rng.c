#include "../fd_ballet.h"
#include "fd_chacha20rng.h"


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Create a fd_chacha20rng */

  fd_chacha20rng_t _rng[1];
  FD_TEST( alignof( fd_chacha20rng_t )==fd_chacha20rng_align()     );
  FD_TEST( sizeof ( _rng             )==fd_chacha20rng_footprint() );

  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_MOD ) );
  FD_TEST( (ulong)rng == (ulong)_rng );

  /* Initialize it with a key */

  uchar key[ 32 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  FD_TEST( fd_chacha20rng_init( rng, key ) );

  /* Test output */

  FD_TEST( fd_chacha20rng_ulong( rng )==0x6a19c5d97d2bfd39UL );
  for( ulong i=0UL; i<100000UL; i++ )
    fd_chacha20rng_ulong( rng );
  FD_TEST( fd_chacha20rng_ulong( rng )==0xf4682b7e28eae4a7UL );

  for( ulong idx=0U; idx<2UL; idx++ ) {
    FD_LOG_NOTICE(( "Benchmarking fd_chacha20rng_ulong, run %lu", idx ));
    key[ 0 ]++;
    FD_TEST( fd_chacha20rng_init( rng, key ) );

    /* warmup */
    for( ulong rem=1000000UL; rem; rem-- ) fd_chacha20rng_ulong( rng );

    /* for real */
    ulong iter = 10000000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_chacha20rng_ulong( rng );
    dt += fd_log_wallclock();
    double gbps    = ((double)(8UL*sizeof(ulong)*iter)) / ((double)dt);
    double ulongps = ((double)iter / (double)dt) * 1000.0;
    double ns      = (double)dt / (double)iter;
    FD_LOG_NOTICE(( "  ~%6.3f Gbps            / core", gbps    ));
    FD_LOG_NOTICE(( "  ~%6.3f Mulong / second / core", ulongps ));
    FD_LOG_NOTICE(( "  ~%6.3f ns / ulong",             ns      ));
  }

  /* Clean up */

  FD_TEST( (ulong)fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) )==(ulong)_rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

