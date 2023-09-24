#include "fd_leaders.h"

FD_STATIC_ASSERT( alignof(fd_epoch_leaders_t)<=FD_EPOCH_LEADERS_ALIGN, alignment );

/* Import data from Mainnet-beta epoch 454, derived from the similar
   example in the Solana Specs repo.  Since the full list of the leader
   pubkey for each slot in the epoch takes several megabytes, we check
   that we match slot-for-slot for the first 10k slots, and then we
   check the rest just by index. */
FD_IMPORT_BINARY( e454_stakes,          "src/flamenco/leaders/fixtures/epoch-stakes-454.bin"      );
FD_IMPORT_BINARY( e454_leaders_pubkeys, "src/flamenco/leaders/fixtures/epoch-leaders-454.bin"     );
FD_IMPORT_BINARY( e454_leaders_idx,     "src/flamenco/leaders/fixtures/epoch-leaders-idx-454.bin" );

static uchar leaders_buf[
  FD_EPOCH_LEADERS_FOOTPRINT( 3373UL, 432000UL )
] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong pub_cnt  = e454_stakes_sz      / sizeof(fd_stake_weight_t);
  ulong slot_cnt = e454_leaders_idx_sz / sizeof(uint             );
  ulong slot0    = 196128000UL;
  FD_TEST( slot_cnt==432000UL );
  FD_TEST( pub_cnt ==  3373UL );

  fd_stake_weight_t const * stakes          = (fd_stake_weight_t const *)e454_stakes;
  fd_pubkey_t       const * leaders_pubkeys = (fd_pubkey_t       const *)e454_leaders_pubkeys;
  uint              const * leaders_idx     = (uint              const *)e454_leaders_idx;

  FD_TEST( leaders_buf == fd_epoch_leaders_new( leaders_buf, 454UL, slot0, 432000UL, pub_cnt, stakes ) );
  fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( leaders_buf );
  FD_TEST( leaders );

  for( ulong i=0UL; i<e454_leaders_pubkeys_sz/32UL; i++ ) {
    FD_TEST( !memcmp( fd_epoch_leaders_get( leaders, slot0+i ), leaders_pubkeys+i, 32UL ) );
  }
  for( ulong i=0UL; i<432000UL; i++ ) {
    FD_TEST( !memcmp( fd_epoch_leaders_get( leaders, slot0+i ), &stakes[leaders_idx[i]].key, 32UL ) );
  }

  FD_TEST( fd_epoch_leaders_get( leaders, slot0-1UL      ) == NULL );
  FD_TEST( fd_epoch_leaders_get( leaders, slot0+432000UL ) == NULL );

  fd_epoch_leaders_delete( fd_epoch_leaders_leave( leaders ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
