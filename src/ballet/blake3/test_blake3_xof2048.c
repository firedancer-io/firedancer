#include "../fd_ballet.h"
#include "fd_blake3.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng_[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, 1U, 0UL ) );

  ulong acc = 0UL;
  uchar input[ 65536 ];
  uchar hash [  2048 ] __attribute__((aligned(64)));
  for( ulong sz=0UL; sz<=sizeof(input); sz++ ) {
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    for( ulong j=0UL; j<sz; j++ ) input[ j ] = fd_rng_uchar( rng );
    fd_blake3_append( blake, input, sz );
    fd_blake3_fini_2048( blake, hash );
    acc ^= fd_hash( 0UL, hash, sizeof(hash) );
  }
  FD_TEST( acc==0x79836ea1df1a342aUL );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
