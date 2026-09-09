#include "fd_tower_recover.h"

static uchar tower_mem[ 1UL<<20 ] __attribute__((aligned(128)));
static void * ghost_mem;
static uchar votes_mem[ FD_TOWER_VOTE_FOOTPRINT ] __attribute__((aligned(FD_TOWER_VOTE_ALIGN)));
static ulong history_bits[ FD_SLOT_HISTORY_MAX_ENTRIES/64UL ];

static fd_hash_t
hash( ulong slot ) {
  return (fd_hash_t){ .ul = { slot } };
}

static fd_slot_history_view_t
history( ulong snapshot_slot ) {
  memset( history_bits, 0, sizeof(history_bits) );
  for( ulong i=90UL; i<=snapshot_slot && i<110UL; i++ )
    history_bits[ i/64UL ] |= 1UL<<(i%64UL);
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
  memset( &recovery, 0xA5, sizeof(recovery) );
  memcpy( &expected, &recovery, sizeof(expected) );
  fd_hash_t snapshot_hash = hash( 102UL );
  fd_slot_history_view_t h = history( 102UL );
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, 102UL, &snapshot_hash, &snapshot_hash, NULL, NULL ) );
  FD_TEST( !memcmp( &recovery, &expected, sizeof(recovery) ) );

  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_init( &recovery, &saved, 102UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  FD_TEST( recovery.rooted_cnt==2UL && recovery.snapshot_slot==102UL );
  FD_TEST( !memcmp( &recovery.saved, &saved, sizeof(saved) ) );

  /* Rooted history may retire a prefix but not a vote on a fork
     absent from that history or outside its bounded window. */
  history_bits[ 100UL/64UL ] &= ~(1UL<<(100UL%64UL));
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, 102UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  h = history( FD_SLOT_HISTORY_MAX_ENTRIES+102UL );
  FD_TEST( FD_TOWER_RECOVER_ERR_HISTORY==fd_tower_recover_init( &recovery, &saved, FD_SLOT_HISTORY_MAX_ENTRIES+102UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );

  /* A snapshot at the saved tip must match both its bank hash and
     block ID.  A same-slot sibling is not a recovery anchor. */
  h = history( 105UL );
  snapshot_hash = hash( 105UL );
  fd_hash_t sibling = hash( 999UL );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 105UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  FD_TEST( recovery.rooted_cnt==3UL );
  FD_TEST( FD_TOWER_RECOVER_ERR_HASH==fd_tower_recover_init( &recovery, &saved, 105UL, &sibling, &snapshot_hash, &h, NULL ) );
  FD_TEST( FD_TOWER_RECOVER_ERR_HASH==fd_tower_recover_init( &recovery, &saved, 105UL, &snapshot_hash, &sibling, &h, NULL ) );

  /* An older fully rooted tower also needs a bank-hash anchor, not
     just a matching slot number in SlotHistory. */
  h = history( 106UL );
  fd_slot_hash_t entries[] = { { .slot=105UL, .hash={ .ul={105UL} } } };
  fd_slot_hashes_t hashes = { .elems=entries, .cnt=1UL };
  FD_TEST( FD_TOWER_RECOVER_ERR_HASH==fd_tower_recover_init( &recovery, &saved, 106UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_init( &recovery, &saved, 106UL, &snapshot_hash, &snapshot_hash, &h, &hashes ) );
  entries[ 0 ].hash = sibling;
  FD_TEST( FD_TOWER_RECOVER_ERR_HASH==fd_tower_recover_init( &recovery, &saved, 106UL, &snapshot_hash, &snapshot_hash, &h, &hashes ) );

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
        ulong        parent_slot ) {
  fd_hash_t id = hash( slot );
  fd_hash_t parent_id = hash( parent_slot );
  fd_tower_blk_t * blk = fd_tower_blocks_insert( tower, slot, parent_slot );
  blk->replayed          = 1;
  blk->replayed_block_id = id;
  blk->bank_hash         = id;
  blk->voted             = 0;
  if( parent_slot==ULONG_MAX ) FD_TEST( fd_ghost_init( ghost, slot, slot, &id ) );
  else                        FD_TEST( fd_ghost_insert( ghost, slot, slot, &id, &parent_id ) );
  return blk;
}

static void
test_replay( void ) {
  FD_TEST( fd_tower_footprint( 16UL, 1UL )<=sizeof(tower_mem) );
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 1UL, 0UL ) );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 32UL, 1UL, 0UL ) );
  FD_TEST( tower && ghost );
  tower->root = 99UL;
  replay( tower, ghost, 99UL, ULONG_MAX );

  fd_tower_file_t saved = saved_tower();
  fd_tower_recover_t recovery;
  fd_slot_history_view_t h = history( 99UL );
  fd_hash_t snapshot_hash = hash( 99UL );
  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_init( &recovery, &saved, 99UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  ulong root_slot = 999UL;
  fd_hash_t root_id = hash( 999UL );
  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( root_slot==999UL && root_id.ul[ 0 ]==999UL );
  FD_TEST( fd_tower_vote_empty( tower->votes ) );

  replay( tower, ghost, 100UL, 99UL );
  replay( tower, ghost, 101UL, 100UL );
  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( fd_tower_vote_empty( tower->votes ) );
  FD_TEST( !memcmp( &recovery.saved, &saved, sizeof(saved) ) );

  fd_tower_blk_t * tip = replay( tower, ghost, 105UL, 101UL );
  tip->bank_hash = hash( 999UL );
  FD_TEST( FD_TOWER_RECOVER_ERR_HASH==fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( fd_tower_vote_empty( tower->votes ) );
  tip->bank_hash = hash( 105UL );

  /* Knowing the slot is not enough if replay metadata now refers to
     a different block.  Even a fully replayed prefix stays uninstalled. */
  fd_tower_blk_t * first = fd_tower_blocks_query( tower, 100UL );
  first->replayed_block_id = hash( 999UL );
  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( fd_tower_vote_empty( tower->votes ) && !tip->voted );
  first->replayed_block_id = hash( 100UL );

  FD_TEST( FD_TOWER_RECOVER_READY==fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( root_slot==99UL && root_id.ul[ 0 ]==99UL );
  FD_TEST( fd_tower_vote_cnt( tower->votes )==3UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( !memcmp( fd_tower_vote_peek_index_const( tower->votes, i ), &saved.votes[ i ], sizeof(fd_tower_vote_t) ) );
    fd_tower_blk_t * blk = fd_tower_blocks_query( tower, saved.votes[ i ].slot );
    FD_TEST( blk->voted && blk->voted_block_id.ul[ 0 ]==saved.votes[ i ].slot );
  }

  /* A newer snapshot retires only the verified rooted prefix. */
  tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 1UL, 0UL ) );
  ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 32UL, 1UL, 0UL ) );
  tower->root = 102UL;
  replay( tower, ghost, 102UL, ULONG_MAX );
  replay( tower, ghost, 105UL, 102UL );
  h = history( 102UL );
  snapshot_hash = hash( 102UL );
  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_init( &recovery, &saved, 102UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  FD_TEST( !fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( fd_tower_vote_cnt( tower->votes )==1UL );
  FD_TEST( fd_tower_vote_peek_tail_const( tower->votes )->slot==105UL );

  /* A saved root newer than the snapshot is returned for publication
     only after the exact saved tip and root ancestry are replayed. */
  tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 1UL, 0UL ) );
  ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 32UL, 1UL, 0UL ) );
  tower->root = 89UL;
  replay( tower, ghost, 89UL, ULONG_MAX );
  replay( tower, ghost, 90UL, 89UL );
  replay( tower, ghost, 100UL, 90UL );
  replay( tower, ghost, 101UL, 100UL );
  replay( tower, ghost, 105UL, 101UL );
  h = history( 89UL );
  snapshot_hash = hash( 89UL );
  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_init( &recovery, &saved, 89UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  FD_TEST( !fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( tower->root==89UL && root_slot==90UL && root_id.ul[ 0 ]==90UL );

  /* A signed tower whose retained votes do not occur on its tip's
     replayed ancestry is not repaired by substituting local blocks. */
  tower = fd_tower_join( fd_tower_new( tower_mem, 16UL, 1UL, 0UL ) );
  ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 32UL, 1UL, 0UL ) );
  tower->root = 99UL;
  replay( tower, ghost, 99UL, ULONG_MAX );
  replay( tower, ghost, 100UL, 99UL );
  replay( tower, ghost, 101UL, 99UL );
  replay( tower, ghost, 105UL, 101UL );
  h = history( 99UL );
  snapshot_hash = hash( 99UL );
  FD_TEST( FD_TOWER_RECOVER_WAIT==fd_tower_recover_init( &recovery, &saved, 99UL, &snapshot_hash, &snapshot_hash, &h, NULL ) );
  FD_TEST( FD_TOWER_RECOVER_ERR_FORK==fd_tower_recover_try( &recovery, tower, ghost, &root_slot, &root_id ) );
  FD_TEST( fd_tower_vote_empty( tower->votes ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( 4096UL, 1024UL, 0UL, "tower-recover", 0UL );
  FD_TEST( wksp );
  ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( 32UL, 1UL ), 1UL );
  FD_TEST( ghost_mem );
  test_init();
  test_replay();
  fd_wksp_free_laddr( ghost_mem );
  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass: tower recovery history, freshness, exact replay and retained lockouts" ));
  fd_halt();
  return 0;
}
