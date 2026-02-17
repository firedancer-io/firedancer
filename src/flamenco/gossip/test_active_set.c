#include "fd_active_set.h"
#include "fd_active_set_private.h"

FD_STATIC_ASSERT( FD_ACTIVE_SET_ALIGN==64UL,  unit_test );
FD_STATIC_ASSERT( FD_ACTIVE_SET_ALIGN==alignof(fd_active_set_t), unit_test );

void
test_get_stake_bucket( void ) {
  ulong buckets[] = { 0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5 };
  for( ulong i=0UL; i<16UL; i++ ) {
    FD_TEST( fd_active_set_stake_bucket( i*1000000000UL )==buckets[ i ] );
  }

  ulong stake1[] = { 4194303UL, 4194304UL, 8388607UL, 8388608UL };
  ulong buckets1[] = { 22UL, 23UL, 23UL, 24UL };
  for( ulong i=0UL; i<4UL; i++ ) {
    FD_TEST( fd_active_set_stake_bucket( stake1[ i ]*1000000000UL )==buckets1[ i ] );
  }

  FD_TEST( fd_active_set_stake_bucket( ULONG_MAX )==24UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_get_stake_bucket();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
