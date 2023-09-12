#include <stdio.h>
#define FD_CHACHA20RNG_DEBUG 1
#include "fd_chacha20rng.h"

int
usage( void ) {
  fprintf( stderr,
    "usage: test_chacha20rng_roll --range <ulong> --count <ulong> --key <ulong>\n"
    "\n"
    "Debug ChaCha20Rng stream of leader schedule derivation.\n"
    "\n"
    "  --range <ulong>  Exclusive upper bound of RNG range\n"
    "  --count <ulong>  Number of RNG rolls to perform\n"
    "  --key   <ulong>  First 8 bytes of ChaCha20 key, little-endian\n"
    "\n" );
  return 1;
}

static void
test_matches_rust( void ) {
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng ) );
  FD_TEST( rng );

  uchar key[ 32 ];
  memset( key, 0x41, 32UL );
  fd_chacha20rng_init( rng, key );

  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 8UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 7UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 2UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 5UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 7UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 6UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 5UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 6UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 9UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 10UL ) == 6UL );

  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 3252524226UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 3847107912UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 2388546007UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 1795840680UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 1493882641UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 2627412178UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 2509655068UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) == 2770564418UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) ==  368683988UL );
  FD_TEST( fd_chacha20rng_ulong_roll( rng, 4294967231UL ) ==  318451188UL );

}

int
main( int     argc,
      char ** argv ) {
  for( int i=1; i<argc; i++ ) if( 0==strcmp( argv[i], "--help" ) ) return usage();

  fd_boot( &argc, &argv );

  /* Use debug logging, as debug contains the interesting info */

  fd_log_level_logfile_set( 0 );
  fd_log_level_stderr_set ( 0 );

  test_matches_rust();

  /* Read command-line params */

  ulong n    = fd_env_strip_cmdline_ulong( &argc, &argv, "--range", NULL, 0UL );
  ulong c    = fd_env_strip_cmdline_ulong( &argc, &argv, "--count", NULL, 0UL );
  ulong _key = fd_env_strip_cmdline_ulong( &argc, &argv, "--key",   NULL, 0UL );

  if( FD_UNLIKELY( (!n) | (!c) ) ) return usage();

  /* Create RNG */

  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng ) );
  FD_TEST( rng );

  uchar key[ 32 ] = {0};
  memcpy( key, &_key, sizeof(ulong) );
  fd_chacha20rng_init( rng, key );

  /* Roll RNG */

  for( ulong i=0UL; i<c; i++ ) {
    /* Logs debug info */
    fd_chacha20rng_ulong_roll( rng, n );
  }

  /* Cleanup */

  FD_TEST( (ulong)fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) )==(ulong)_rng );
  fd_halt();
  return 0;
}
