#include "fd_stake_pubkeys.h"
#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong footprint = fd_stake_pubkeys_footprint( 8UL, 8UL );
  FD_TEST( footprint );

  void * mem = aligned_alloc( fd_stake_pubkeys_align(), footprint );
  FD_TEST( mem );

  fd_stake_pubkeys_t * pubkeys = fd_stake_pubkeys_join(
      fd_stake_pubkeys_new( mem, 0UL, 8UL, 8UL ) );
  FD_TEST( pubkeys );

  fd_pubkey_t key0 = { .ul = { 1UL, 2UL, 3UL, 4UL } };
  fd_pubkey_t key1 = { .ul = { 5UL, 6UL, 7UL, 8UL } };

  fd_stake_pubkeys_lock( pubkeys );

  uint idx0 = fd_stake_pubkeys_acquire( pubkeys, &key0 );
  FD_TEST( fd_stake_pubkeys_acquire( pubkeys, &key0 )==idx0 );
  FD_TEST( fd_stake_pubkeys_cnt( pubkeys )==1UL );
  FD_TEST( fd_pubkey_eq( fd_stake_pubkeys_query( pubkeys, idx0 ), &key0 ) );

  fd_stake_pubkeys_release( pubkeys, idx0 );
  fd_stake_pubkeys_retain( pubkeys, idx0 );
  fd_stake_pubkeys_release( pubkeys, idx0 );
  FD_TEST( fd_stake_pubkeys_cnt( pubkeys )==1UL );
  FD_TEST( fd_pubkey_eq( fd_stake_pubkeys_query( pubkeys, idx0 ), &key0 ) );
  fd_stake_pubkeys_release( pubkeys, idx0 );
  FD_TEST( !fd_stake_pubkeys_cnt( pubkeys ) );

  fd_stake_pubkeys_fallback_enter( pubkeys, &key1 );
  FD_TEST( fd_stake_pubkeys_fallback( pubkeys ) );
  FD_TEST( fd_stake_pubkeys_cnt( pubkeys )==1UL );

  ulong cursor = 0UL;
  uint  idx1   = fd_stake_pubkeys_iter_next( pubkeys, &cursor );
  FD_TEST( idx1!=UINT_MAX );
  FD_TEST( fd_pubkey_eq( fd_stake_pubkeys_query( pubkeys, idx1 ), &key1 ) );
  FD_TEST( fd_stake_pubkeys_iter_next( pubkeys, &cursor )==UINT_MAX );

  /* Fallback mode pins every entry until refresh or reset. */
  fd_stake_pubkeys_release( pubkeys, idx1 );
  FD_TEST( fd_stake_pubkeys_cnt( pubkeys )==1UL );

  fd_stake_pubkeys_reset( pubkeys );
  FD_TEST( !fd_stake_pubkeys_cnt( pubkeys ) );
  FD_TEST( !fd_stake_pubkeys_fallback( pubkeys ) );

  idx0 = fd_stake_pubkeys_acquire( pubkeys, &key0 );
  fd_stake_pubkeys_refresh_fini( pubkeys, 1UL );
  fd_stake_pubkeys_release( pubkeys, idx0 );
  FD_TEST( !fd_stake_pubkeys_cnt( pubkeys ) );

  fd_stake_pubkeys_fallback_enter( pubkeys, &key0 );
  idx0 = fd_stake_pubkeys_acquire( pubkeys, &key0 );
  fd_stake_pubkeys_refresh_fini( pubkeys, 1UL );
  FD_TEST( !fd_stake_pubkeys_fallback( pubkeys ) );
  fd_stake_pubkeys_release( pubkeys, idx0 );
  FD_TEST( !fd_stake_pubkeys_cnt( pubkeys ) );

  fd_stake_pubkeys_unlock( pubkeys );

  free( mem );
  fd_halt();
  return 0;
}
