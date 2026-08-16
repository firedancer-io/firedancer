#include "ag_slot.h"
#include "../../util/fd_util.h"

static void
test_slot_windows( void ) {

  for( ulong window=0UL; window<9UL; window++ ) {
    ulong first_slot = window*AG_SLOTS_PER_WINDOW;
    FD_TEST( ag_slot_is_start_of_window( first_slot ) );
    FD_TEST( ag_slot_first_slot_in_window( first_slot )==first_slot );

    ulong last_slot      = ag_slot_last_slot_in_window( first_slot );
    ulong next_first     = (window+1UL)*AG_SLOTS_PER_WINDOW;
    FD_TEST( last_slot+1UL==next_first );
    FD_TEST( last_slot==next_first-1UL );

    for( ulong s=first_slot; s<=last_slot; s++ ) {
      FD_TEST( ag_slot_first_slot_in_window( s )==first_slot );
      FD_TEST( ag_slot_last_slot_in_window ( s )==last_slot  );
      FD_TEST( ag_slot_is_start_of_window( s )==( s==first_slot ) );
    }
  }

  FD_TEST(  ag_slot_is_genesis_window( 0UL ) );
  FD_TEST(  ag_slot_is_genesis_window( AG_SLOTS_PER_WINDOW-1UL ) );
  FD_TEST( !ag_slot_is_genesis_window( AG_SLOTS_PER_WINDOW ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_slot_windows();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
