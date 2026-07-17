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

static void
test_leader_bits( fd_epoch_leaders_t const * leaders ) {
  ulong expected_bits[ FD_EPOCH_LEADERS_BITSET_WORD_CNT( 3373UL ) ] = {0UL};
  FD_TEST( leaders->leader_bits_word_cnt<=FD_EPOCH_LEADERS_BITSET_WORD_CNT( 3373UL ) );

  for( ulong i=0UL; i<leaders->sched_cnt; i++ ) {
    ulong idx = (ulong)leaders->sched[i];
    expected_bits[ idx>>6 ] |= (1UL<<(idx&63UL));
  }

  for( ulong i=0UL; i<leaders->leader_bits_word_cnt; i++ )
    FD_TEST( leaders->leader_bits[i]==expected_bits[i] );

  for( ulong idx=0UL; idx<=leaders->pub_cnt; idx++ ) {
    int expected = !!( expected_bits[ idx>>6 ] & (1UL<<(idx&63UL)) );
    FD_TEST( fd_epoch_leaders_is_leader_idx( leaders, idx )==expected );
  }

  FD_TEST( !fd_epoch_leaders_is_leader_idx( leaders, leaders->pub_cnt+1UL ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong pub_cnt  = e454_stakes_sz      / sizeof(fd_stake_weight_t);
  ulong slot_cnt = e454_leaders_idx_sz / sizeof(uint             );
  ulong slot0    = 196128000UL;
  FD_TEST( slot_cnt==432000UL );
  FD_TEST( pub_cnt ==  3373UL );

  fd_stake_weight_t const * id_based_e454_stakes = (fd_stake_weight_t const *)e454_stakes;
  fd_vote_stake_weight_t vote_based_e454_stakes[ 3373UL ] = { 0 };
  for( ulong i=0; i<pub_cnt; i++ ) {
    vote_based_e454_stakes[ i ].stake = id_based_e454_stakes[ i ].stake;
    memcpy( vote_based_e454_stakes[ i ].id_key.uc, id_based_e454_stakes[ i ].key.uc, sizeof(fd_pubkey_t) );
    memcpy( vote_based_e454_stakes[ i ].vote_key.uc, id_based_e454_stakes[ i ].key.uc, sizeof(fd_pubkey_t) );
  }

  fd_vote_stake_weight_t  * stakes          = vote_based_e454_stakes;
  fd_pubkey_t       const * leaders_pubkeys = (fd_pubkey_t       const *)e454_leaders_pubkeys;
  uint              const * leaders_idx     = (uint              const *)e454_leaders_idx;

  FD_TEST( leaders_buf == fd_epoch_leaders_new( leaders_buf, 454UL, slot0, 432000UL, pub_cnt, stakes, 0UL ) );
  fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( leaders_buf );
  FD_TEST( leaders );
  test_leader_bits( leaders );

  for( ulong i=0UL; i<e454_leaders_pubkeys_sz/32UL; i++ ) {
    FD_TEST( !memcmp( fd_epoch_leaders_get( leaders, slot0+i ), leaders_pubkeys+i, 32UL ) );
  }
  for( ulong i=0UL; i<432000UL; i++ ) {
    FD_TEST( !memcmp( fd_epoch_leaders_get( leaders, slot0+i ), &stakes[leaders_idx[i]].id_key, 32UL ) );
  }

  FD_TEST( fd_epoch_leaders_get( leaders, slot0-1UL      ) == NULL );
  FD_TEST( fd_epoch_leaders_get( leaders, slot0+432000UL ) == NULL );

  fd_epoch_leaders_delete( fd_epoch_leaders_leave( leaders ) );

  /* Test with last half of validators in excluded_stake */
  ulong shortlist_cnt = pub_cnt/2UL;
  ulong excluded_stake = 0UL;
  for( ulong i=shortlist_cnt; i<pub_cnt; i++ ) excluded_stake += stakes[ i ].stake;
  FD_TEST( leaders_buf == fd_epoch_leaders_new( leaders_buf, 454UL, slot0, 432000UL, shortlist_cnt, stakes, excluded_stake ) );
  leaders = fd_epoch_leaders_join( leaders_buf );
  FD_TEST( leaders );
  test_leader_bits( leaders );

  static const uchar indeterminate[32] = { FD_INDETERMINATE_LEADER };
  for( ulong i=0UL; i<432000UL; i++ ) {
    uchar const * expected = fd_ptr_if( leaders_idx[i]>=shortlist_cnt, &indeterminate[0], &stakes[leaders_idx[i]].id_key );
    FD_TEST( !memcmp( fd_epoch_leaders_get( leaders, slot0+i ), expected, 32UL ) );
  }
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( leaders ) );

  /* Test the per-rotation vote address: two vote accounts share one
     node identity, so the vote address cannot be recovered from the
     scheduled identity alone. */
  {
    fd_pubkey_t id_x; memset( id_x.uc, 0x11, 32UL );
    fd_pubkey_t id_y; memset( id_y.uc, 0x22, 32UL );
    fd_vote_stake_weight_t shared_stakes[3] = {0};
    memset( shared_stakes[0].vote_key.uc, 0xA1, 32UL );
    shared_stakes[0].id_key = id_x;
    shared_stakes[0].stake  = 3000000000UL;
    memset( shared_stakes[1].vote_key.uc, 0xA2, 32UL );
    shared_stakes[1].id_key = id_x;
    shared_stakes[1].stake  = 2000000000UL;
    memset( shared_stakes[2].vote_key.uc, 0xA3, 32UL );
    shared_stakes[2].id_key = id_y;
    shared_stakes[2].stake  = 1000000000UL;

    ulong test_slot_cnt = 1000UL;
    FD_TEST( leaders_buf == fd_epoch_leaders_new( leaders_buf, 1UL, 0UL, test_slot_cnt, 3UL, shared_stakes, 0UL ) );
    leaders = fd_epoch_leaders_join( leaders_buf );
    FD_TEST( leaders );

    int seen[3] = {0};
    for( ulong slot=0UL; slot<test_slot_cnt; slot++ ) {
      fd_pubkey_t const * id   = fd_epoch_leaders_get     ( leaders, slot );
      fd_pubkey_t const * vote = fd_epoch_leaders_get_vote( leaders, slot );
      FD_TEST( id && vote );

      ulong entry = ULONG_MAX;
      for( ulong i=0UL; i<3UL; i++ ) {
        if( !memcmp( vote->uc, shared_stakes[i].vote_key.uc, 32UL ) ) { entry = i; break; }
      }
      FD_TEST( entry!=ULONG_MAX );
      FD_TEST( !memcmp( id->uc, shared_stakes[entry].id_key.uc, 32UL ) );
      seen[entry] = 1;

      /* The vote address is constant within a rotation. */
      ulong rot0 = slot - slot%FD_EPOCH_SLOTS_PER_ROTATION;
      FD_TEST( fd_epoch_leaders_get_vote( leaders, rot0 )==vote );
    }

    /* Both vote accounts behind the shared identity are scheduled. */
    FD_TEST( seen[0] && seen[1] && seen[2] );

    FD_TEST( fd_epoch_leaders_get_vote( leaders, test_slot_cnt )==NULL );
    fd_epoch_leaders_delete( fd_epoch_leaders_leave( leaders ) );
  }

  /* Excluded stake: indeterminate rotations report the indeterminate
     leader for both the identity and the vote address. */
  {
    FD_TEST( leaders_buf == fd_epoch_leaders_new( leaders_buf, 454UL, slot0, 432000UL, shortlist_cnt, stakes, excluded_stake ) );
    leaders = fd_epoch_leaders_join( leaders_buf );
    FD_TEST( leaders );

    int saw_indeterminate = 0;
    for( ulong i=0UL; i<432000UL; i++ ) {
      fd_pubkey_t const * vote = fd_epoch_leaders_get_vote( leaders, slot0+i );
      if( leaders_idx[i]>=shortlist_cnt ) {
        FD_TEST( !memcmp( vote, &indeterminate[0], 32UL ) );
        saw_indeterminate = 1;
      } else {
        FD_TEST( !memcmp( vote, &stakes[leaders_idx[i]].vote_key, 32UL ) );
      }
    }
    FD_TEST( saw_indeterminate );
    fd_epoch_leaders_delete( fd_epoch_leaders_leave( leaders ) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
