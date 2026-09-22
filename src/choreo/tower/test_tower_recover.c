#include "fd_tower_recover.h"

static uchar tower_mem[ 1UL<<20 ] __attribute__((aligned(128)));
static void * ghost_mem;
static uchar votes_mem[ FD_TOWER_VOTE_FOOTPRINT ] __attribute__((aligned(FD_TOWER_VOTE_ALIGN)));
static ulong history_bits[ FD_SLOT_HISTORY_MAX_ENTRIES/64UL ];

static fd_hash_t
hash( ulong slot ) {
  return (fd_hash_t){ .ul = { slot } };
}

/* A rooted history covering slots 90..snapshot_slot, with 100 and 102
   optionally skipped by the cluster. */
static fd_slot_history_view_t
history( ulong snapshot_slot,
         int   skip_100,
         int   skip_102 ) {
  fd_memset( history_bits, 0, sizeof(history_bits) );
  for( ulong i=90UL; i<=snapshot_slot && i<200UL; i++ ) {
    if( (skip_100 && i==100UL) || (skip_102 && i==102UL) ) continue;
    history_bits[ i/64UL ] |= 1UL<<(i%64UL);
  }
  return (fd_slot_history_view_t){
    .bits       = (uchar const *)history_bits,
    .blocks_len = FD_SLOT_HISTORY_MAX_ENTRIES/64UL,
    .bits_len   = FD_SLOT_HISTORY_MAX_ENTRIES,
    .next_slot  = snapshot_slot+1UL,
  };
}

static fd_tower_file_t
saved_tower( void ) {
  return (fd_tower_file_t){
    .votes          = { { .slot=100UL, .conf=3UL }, { .slot=101UL, .conf=2UL }, { .slot=105UL, .conf=1UL } },
    .votes_cnt      = 3UL,
    .root           = 90UL,
    .bank_hash      = { .ul = { 105UL } },
    .block_id       = { .ul = { 105UL } },
    .timestamp_slot = 105UL,
    .timestamp      = 1000L,
  };
}

static void
test_init( void ) {
  fd_tower_file_t saved = saved_tower();
  fd_tower_recover_t recovery;
  fd_tower_recover_t expected;
  fd_memset( &recovery, 0xA5, sizeof(recovery) );
  fd_memcpy( &expected, &recovery, sizeof(expected) );

  /* The history sysvar must be usable. */
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, 102UL, NULL ) );
  fd_slot_history_view_t h = history( 101UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );
  FD_TEST( fd_memeq( &recovery, &expected, sizeof(recovery) ) );

  /* Snapshot in the middle of the tower: 100 and 101 are rooted and
     retire, 105 is newer and stays. */
  h = history( 102UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );
  FD_TEST( recovery.retained_cnt==1UL && recovery.snapshot_slot==102UL );
  FD_TEST( fd_memeq( &recovery.saved, &saved, sizeof(saved) ) );

  /* A skipped slot above the anchor is a dead fork vote and is kept as
     a lockout, as Agave keeps stray votes.  Below the anchor it is a
     diverged ancestor and refused. */
  h = history( 102UL, 0, 1 ); /* 102 missing does not matter, no vote there */
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );
  h = history( 104UL, 0, 0 );
  saved.votes[ 1 ].slot = 103UL; /* 100 found, 103 not found, 105 future */
  history_bits[ 103UL/64UL ] &= ~(1UL<<(103UL%64UL));
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 104UL, &h ) );
  FD_TEST( recovery.retained_cnt==2UL );
  saved = saved_tower();
  h = history( 102UL, 1, 0 ); /* 100 skipped below the found 101 */
  FD_TEST( FD_TOWER_RECOVER_ERR_FORK==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );

  /* The whole tower rooted needs no bank hash anchor, the snapshot can
     be arbitrarily far ahead as long as the history covers the tower. */
  h = history( 150UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 150UL, &h ) );
  FD_TEST( recovery.retained_cnt==0UL );

  /* The whole tower newer than the snapshot is kept whole, including a
     root the snapshot has not reached. */
  h = history( 89UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 89UL, &h ) );
  FD_TEST( recovery.retained_cnt==3UL );

  /* Nothing in common with the rooted history is refused. */
  h = history( 102UL, 1, 0 );
  history_bits[ 90UL/64UL ] &= ~(1UL<<(90UL%64UL));
  history_bits[ 101UL/64UL ] &= ~(1UL<<(101UL%64UL));
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );

  /* The root is checked like a vote: missing below found votes is a
     diverged ancestor, and without any root the oldest vote must be
     newer than the snapshot when nothing is found. */
  h = history( 102UL, 0, 0 );
  history_bits[ 90UL/64UL ] &= ~(1UL<<(90UL%64UL));
  FD_TEST( FD_TOWER_RECOVER_ERR_FORK==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );
  saved.root = ULONG_MAX;
  h = history( 102UL, 1, 0 );
  history_bits[ 101UL/64UL ] &= ~(1UL<<(101UL%64UL));
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );
  h = history( 99UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 99UL, &h ) );
  FD_TEST( recovery.retained_cnt==3UL );
  saved = saved_tower();

  /* A tower older than the history window is refused. */
  h = history( FD_SLOT_HISTORY_MAX_ENTRIES+200UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, FD_SLOT_HISTORY_MAX_ENTRIES+200UL, &h ) );

  h = history( 102UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );
  fd_tower_vote_t * onchain = fd_tower_vote_join( fd_tower_vote_new( votes_mem ) );
  FD_TEST( !fd_tower_recover_check_onchain( &recovery, onchain, ULONG_MAX ) );
  FD_TEST( FD_TOWER_RECOVER_ERR_STALE==fd_tower_recover_check_onchain( &recovery, onchain, 105UL ) );
  fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot=105UL, .conf=1UL } );
  FD_TEST( !fd_tower_recover_check_onchain( &recovery, onchain, 90UL ) );
  fd_tower_vote_push_tail( onchain, (fd_tower_vote_t){ .slot=106UL, .conf=1UL } );
  FD_TEST( FD_TOWER_RECOVER_ERR_STALE==fd_tower_recover_check_onchain( &recovery, onchain, 90UL ) );
}

static fd_tower_blk_t *
replay( fd_tower_t * tower,
        fd_ghost_t * ghost,
        ulong        slot,
        ulong        parent_slot,
        fd_hash_t    id ) {
  fd_hash_t parent_id = hash( parent_slot );
  fd_tower_blk_t * blk = fd_tower_blocks_insert( tower, slot, parent_slot );
  blk->replayed          = 1;
  blk->replayed_block_id = id;
  blk->bank_hash         = hash( slot );
  blk->voted             = 0;
  if( parent_slot==ULONG_MAX ) FD_TEST( fd_ghost_init( ghost, slot, slot, &id ) );
  else                        FD_TEST( fd_ghost_insert( ghost, slot, slot, &id, &parent_id ) );
  return blk;
}

static void
test_install_and_replay( void ) {
  FD_TEST( fd_tower_footprint( 16UL, 1UL )<=sizeof(tower_mem) );
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 1UL, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 32UL, 1UL, 0UL ) );
  FD_TEST( tower && ghost );
  tower->root = 99UL;
  replay( tower, ghost, 99UL, ULONG_MAX, hash( 99UL ) );

  fd_tower_file_t saved = saved_tower();
  fd_tower_recover_t recovery;
  fd_slot_history_view_t h = history( 99UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 99UL, &h ) );
  FD_TEST( recovery.retained_cnt==3UL );

  /* Installed at once, as lockouts without block identity.  The root
     90 is below the snapshot, so it does not become the consensus root. */
  fd_tower_recover_install( &recovery, tower );
  FD_TEST( fd_tower_vote_cnt( tower->votes )==3UL );
  FD_TEST( tower->saved_root==ULONG_MAX && fd_tower_consensus_root( tower )==99UL );
  FD_TEST( tower->restored_tip==105UL && fd_tower_vote_is_restored( tower, 105UL ) && !fd_tower_vote_is_restored( tower, 106UL ) );
  for( ulong i=0UL; i<3UL; i++ )
    FD_TEST( fd_memeq( fd_tower_vote_peek_index_const( tower->votes, i ), &saved.votes[ i ], sizeof(fd_tower_vote_t) ) );
  FD_TEST( !fd_tower_recover_replayed( &recovery, tower, 99UL, &(fd_hash_t){ .ul={99UL} } ) );

  /* Replay attaches block ids as it produces the voted slots.  The
     vote follows the slot, so a sibling of the saved tip binds too and
     a later replay of the recorded block does not rebind it. */
  fd_tower_blk_t * b100 = replay( tower, ghost, 100UL, 99UL, hash( 100UL ) );
  FD_TEST( fd_tower_recover_replayed( &recovery, tower, 100UL, &b100->replayed_block_id ) );
  FD_TEST( b100->voted && b100->voted_block_id.ul[ 0 ]==100UL );
  fd_tower_blk_t * b101 = replay( tower, ghost, 101UL, 100UL, hash( 101UL ) );
  FD_TEST( fd_tower_recover_replayed( &recovery, tower, 101UL, &b101->replayed_block_id ) );
  FD_TEST( b101->voted );
  fd_tower_blk_t * b105 = replay( tower, ghost, 105UL, 101UL, hash( 999UL ) );
  FD_TEST( fd_tower_recover_replayed( &recovery, tower, 105UL, &b105->replayed_block_id ) );
  FD_TEST( b105->voted && b105->voted_block_id.ul[ 0 ]==999UL );
  b105->replayed_block_id = hash( 105UL );
  FD_TEST( fd_tower_recover_replayed( &recovery, tower, 105UL, &b105->replayed_block_id ) );
  FD_TEST( b105->voted && b105->voted_block_id.ul[ 0 ]==999UL );
  FD_TEST( !fd_tower_recover_replayed( &recovery, tower, 106UL, &(fd_hash_t){ .ul={106UL} } ) );

  /* A newer snapshot retires the rooted prefix and installs only the
     retained suffix. */
  tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 1UL, 0UL ) );
  ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 32UL, 1UL, 0UL ) );
  tower->root = 102UL;
  replay( tower, ghost, 102UL, ULONG_MAX, hash( 102UL ) );
  h = history( 102UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 102UL, &h ) );
  fd_tower_recover_install( &recovery, tower );
  FD_TEST( fd_tower_vote_cnt( tower->votes )==1UL );
  FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot==105UL );
  FD_TEST( !fd_tower_recover_replayed( &recovery, tower, 100UL, &(fd_hash_t){ .ul={100UL} } ) );

  /* A snapshot older than the saved root: the whole tower is kept and
     the saved root stays the consensus root until replay catches up. */
  tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 1UL, 0UL ) );
  ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 32UL, 1UL, 0UL ) );
  tower->root = 89UL;
  replay( tower, ghost, 89UL, ULONG_MAX, hash( 89UL ) );
  h = history( 89UL, 0, 0 );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 89UL, &h ) );
  fd_tower_recover_install( &recovery, tower );
  FD_TEST( fd_tower_vote_cnt( tower->votes )==3UL );
  FD_TEST( tower->saved_root==90UL && fd_tower_consensus_root( tower )==90UL );
  FD_TEST( tower->restored_tip==105UL );
  tower->root = 95UL;
  FD_TEST( fd_tower_consensus_root( tower )==95UL );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( 4096UL, 1024UL, 0UL, "tower-recover", 0UL );
  FD_TEST( wksp );
  ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( 32UL, 1UL ), 1UL );
  FD_TEST( ghost_mem );
  test_init();
  test_install_and_replay();
  fd_wksp_free_laddr( ghost_mem );
  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass: tower recovery anchors on rooted history, keeps newer votes as lockouts and attaches blocks on replay" ));
  fd_halt();
  return 0;
}
