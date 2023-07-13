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

int
main( int     argc,
      char ** argv ) {
  for( int i=1; i<argc; i++ ) if( 0==strcmp( argv[i], "--help" ) ) return usage();

  fd_boot( &argc, &argv );

  /* Use debug logging, as debug contains the interesting info */

  fd_log_level_logfile_set( 0 );
  fd_log_level_stderr_set ( 0 );

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
