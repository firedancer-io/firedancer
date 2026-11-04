#include "fd_votor_base.h"

static void
test_block_id( void ) {
  fd_block_id_t a = { .slot = 7UL };  memset( &a.hash, 0xAB, sizeof(fd_block_hash_t) );
  fd_block_id_t b = a;
  FD_TEST( fd_block_id_eq( &a, &b ) );
  b.slot = 8UL;             FD_TEST( !fd_block_id_eq( &a, &b ) );
  b = a; b.hash.uc[0] ^= 1; FD_TEST( !fd_block_id_eq( &a, &b ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_block_id();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
