#include "ag_alpenglow_base.h"

static void
test_slot_windows( void ) {

  for( ulong window=0UL; window<9UL; window++ ) {
    ulong first_slot = window*AG_ALPENGLOW_SLOTS_PER_WINDOW;
    FD_TEST( ag_alpenglow_is_start_of_window( first_slot ) );
    FD_TEST( ag_alpenglow_first_slot_in_window( first_slot )==first_slot );

    ulong last_slot      = ag_alpenglow_last_slot_in_window( first_slot );
    ulong next_first     = (window+1UL)*AG_ALPENGLOW_SLOTS_PER_WINDOW;
    FD_TEST( last_slot+1UL==next_first );
    FD_TEST( last_slot==next_first-1UL );

    for( ulong s=first_slot; s<=last_slot; s++ ) {
      FD_TEST( ag_alpenglow_first_slot_in_window( s )==first_slot );
      FD_TEST( ag_alpenglow_last_slot_in_window ( s )==last_slot  );
      FD_TEST( ag_alpenglow_is_start_of_window( s )==( s==first_slot ) );
    }
  }

  FD_TEST(  ag_alpenglow_is_genesis_window( 0UL ) );
  FD_TEST(  ag_alpenglow_is_genesis_window( AG_ALPENGLOW_SLOTS_PER_WINDOW-1UL ) );
  FD_TEST( !ag_alpenglow_is_genesis_window( AG_ALPENGLOW_SLOTS_PER_WINDOW ) );
}

static void
test_quorums( void ) {

  ulong total = 6UL;
  FD_TEST(  ag_alpenglow_is_weak_quorum  ( 3UL, total ) );
  FD_TEST( !ag_alpenglow_is_quorum       ( 3UL, total ) );
  FD_TEST(  ag_alpenglow_is_quorum       ( 4UL, total ) );
  FD_TEST( !ag_alpenglow_is_strong_quorum( 4UL, total ) );
  FD_TEST(  ag_alpenglow_is_strong_quorum( 5UL, total ) );

  total = 11UL;
  FD_TEST(  ag_alpenglow_is_weak_quorum  ( 5UL, total ) );
  FD_TEST( !ag_alpenglow_is_quorum       ( 5UL, total ) );
  FD_TEST(  ag_alpenglow_is_quorum       ( 7UL, total ) );
  FD_TEST( !ag_alpenglow_is_strong_quorum( 7UL, total ) );
  FD_TEST(  ag_alpenglow_is_strong_quorum( 9UL, total ) );

  FD_TEST( !ag_alpenglow_is_weakest_quorum( 0UL, 5UL ) );
  FD_TEST(  ag_alpenglow_is_weakest_quorum( 1UL, 5UL ) );

  FD_TEST(  ag_alpenglow_is_quorum       ( 60UL, 100UL ) );
  FD_TEST(  ag_alpenglow_is_strong_quorum( 80UL, 100UL ) );
  FD_TEST( !ag_alpenglow_is_strong_quorum( 79UL, 100UL ) );
}

static void
test_block_id( void ) {
  ag_block_id_t a = { .slot = 7UL };  memset( a.hash.uc, 0xAB, sizeof(fd_hash_t) );
  ag_block_id_t b = a;
  FD_TEST( ag_block_id_eq( &a, &b ) );
  b.slot = 8UL;            FD_TEST( !ag_block_id_eq( &a, &b ) );
  b = a; b.hash.uc[0] ^= 1; FD_TEST( !ag_block_id_eq( &a, &b ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_slot_windows();
  test_quorums();
  test_block_id();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
