#include "fd_votes.c"

#define SCRATCH_MAX (1UL<<22)
static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

/* Register voters manually (bypassing update_voters). */

static void
register_voters( fd_votes_t * votes, fd_pubkey_t * voters, ulong cnt ) {
  for( ulong i = 0; i < cnt; i++ ) {
    vtr_t * v      = vtr_pool_ele_acquire( votes->vtr_pool );
    v->vote_acc    = voters[i];
    v->bit         = i;
    vtr_map_ele_insert( votes->vtr_map, v, votes->vtr_pool );
    vtr_dlist_ele_push_tail( votes->vtr_dlist, v, votes->vtr_pool );
  }
}

void
test_votes_simple( void ) {
  ulong slot_max = 8;
  ulong vtr_max  = 4;
  FD_TEST( fd_votes_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_votes_t * votes = fd_votes_join( fd_votes_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( votes );

  fd_pubkey_t voters[2] = { { .ul = { 1 } }, { .ul = { 2 } } };
  ulong       stakes[2] = { 10, 51 };
  register_voters( votes, voters, 2 );

  fd_votes_publish( votes, 100 );

  /* Count a vote from voter_a for slot 101. */

  fd_hash_t block_id_a = { .ul = { 200 } };
  FD_TEST( !fd_votes_count_vote( votes, &voters[0], stakes[0], 101, &block_id_a ) );
  fd_votes_blk_key_t key_a101 = { .slot = 101, .block_id = block_id_a };
  blk_t * blk = blk_map_ele_query( votes->blk_map, &key_a101, NULL, votes->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==10 );
  FD_TEST( blk->key.slot==101 );

  /* Count a vote from voter_b for same slot 101, same block_id. */

  FD_TEST( !fd_votes_count_vote( votes, &voters[1], stakes[1], 101, &block_id_a ) );
  blk = blk_map_ele_query( votes->blk_map, &key_a101, NULL, votes->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==61 );

  /* voter_a tries to vote again for slot 101 — rejected. */

  fd_hash_t block_id_b = { .ul = { 201 } };
  FD_TEST( fd_votes_count_vote( votes, &voters[0], stakes[0], 101, &block_id_b )==FD_VOTES_ERR_ALREADY_VOTED );

  /* voter_a votes for a different slot 102. */

  FD_TEST( !fd_votes_count_vote( votes, &voters[0], stakes[0], 102, &block_id_b ) );
  fd_votes_blk_key_t key_b102 = { .slot = 102, .block_id = block_id_b };
  blk = blk_map_ele_query( votes->blk_map, &key_b102, NULL, votes->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==10 );

  /* Query blk by (slot, block_id). */

  FD_TEST( blk_map_ele_query( votes->blk_map, &key_a101, NULL, votes->blk_pool ) );
  FD_TEST( blk_map_ele_query( votes->blk_map, &key_b102, NULL, votes->blk_pool ) );

  /* Publish root to 102 — slot 101 and its blks should be removed. */

  fd_votes_publish( votes, 102 );
  FD_TEST( !blk_map_ele_query( votes->blk_map, &key_a101, NULL, votes->blk_pool ) );
  FD_TEST(  blk_map_ele_query( votes->blk_map, &key_b102, NULL, votes->blk_pool ) );
  FD_TEST(  votes->root==102 );

  fd_votes_delete( fd_votes_leave( votes ) );
}

/* Stress test: attacker tries to spam many different block ids for a
   single slot.  Each voter can only vote once per slot, so an attacker
   with N sybil voters can create at most N distinct block ids for a
   given slot.  Each block id only accumulates the attacker's own stake
   (1 per sybil), so none should reach any confirmation threshold. */

void
test_votes_spam_block_ids_per_slot( void ) {
  ulong slot_max     = 8;
  ulong vtr_max      = 64;
  ulong attacker_cnt = 32;

  FD_TEST( fd_votes_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_votes_t * votes = fd_votes_join( fd_votes_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( votes );

  fd_pubkey_t voters[64];
  ulong       stakes[64];
  for( ulong i = 0; i < vtr_max; i++ ) {
    voters[i] = (fd_pubkey_t){ .ul = { i+1 } };
    stakes[i] = 1;
  }
  register_voters( votes, voters, vtr_max );
  fd_votes_publish( votes, 100 );

  ulong target_slot = 101;

  /* Each attacker votes for a DIFFERENT block_id on the same slot. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    FD_TEST( !fd_votes_count_vote( votes, &voters[i], stakes[i], target_slot, &block_id ) );
    fd_votes_blk_key_t key = { .slot = target_slot, .block_id = block_id };
    blk_t * blk = blk_map_ele_query( votes->blk_map, &key, NULL, votes->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==1 );
  }

  /* Each block_id exists but has only stake=1. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    fd_votes_blk_key_t key = { .slot = target_slot, .block_id = block_id };
    blk_t * blk = blk_map_ele_query( votes->blk_map, &key, NULL, votes->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==1 );
  }

  /* Each attacker tries to re-vote — all rejected. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 2000+i } };
    FD_TEST( fd_votes_count_vote( votes, &voters[i], stakes[i], target_slot, &block_id )==FD_VOTES_ERR_ALREADY_VOTED );
  }

  /* Honest voters vote for the real block_id.  Their stake accumulates
     correctly and is unaffected by the attacker spam. */

  fd_hash_t honest_block_id = { .ul = { 9999 } };
  for( ulong i = attacker_cnt; i < vtr_max; i++ ) {
    FD_TEST( !fd_votes_count_vote( votes, &voters[i], stakes[i], target_slot, &honest_block_id ) );
    fd_votes_blk_key_t key = { .slot = target_slot, .block_id = honest_block_id };
    blk_t * blk = blk_map_ele_query( votes->blk_map, &key, NULL, votes->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==(i - attacker_cnt + 1) );
  }

  fd_votes_blk_key_t honest_key = { .slot = target_slot, .block_id = honest_block_id };
  blk_t * honest_blk = blk_map_ele_query( votes->blk_map, &honest_key, NULL, votes->blk_pool );
  FD_TEST( honest_blk );
  FD_TEST( honest_blk->stake==(vtr_max - attacker_cnt) );

  /* Publish cleans up all block ids. */

  fd_votes_publish( votes, target_slot + 1 );
  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    fd_votes_blk_key_t key = { .slot = target_slot, .block_id = block_id };
    FD_TEST( !blk_map_ele_query( votes->blk_map, &key, NULL, votes->blk_pool ) );
  }
  FD_TEST( !blk_map_ele_query( votes->blk_map, &honest_key, NULL, votes->blk_pool ) );

  fd_votes_delete( fd_votes_leave( votes ) );
}

/* Stress test: attacker sprays votes across many slots with different
   block ids.  Votes beyond root+slot_max should be rejected.  Unknown
   voters should be rejected. */

void
test_votes_spam_many_slots( void ) {
  ulong slot_max     = 8;
  ulong vtr_max      = 16;
  ulong attacker_cnt = 8;

  FD_TEST( fd_votes_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_votes_t * votes = fd_votes_join( fd_votes_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( votes );

  fd_pubkey_t voters[16];
  ulong       stakes[16];
  for( ulong i = 0; i < vtr_max; i++ ) {
    voters[i] = (fd_pubkey_t){ .ul = { i+1 } };
    stakes[i] = 1;
  }
  register_voters( votes, voters, vtr_max );
  fd_votes_publish( votes, 100 );

  /* Each attacker votes for a different slot, unique block_id. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    ulong slot = 101 + i;
    fd_hash_t block_id = { .ul = { 3000+i } };
    int err = fd_votes_count_vote( votes, &voters[i], stakes[i], slot, &block_id );
    if( slot < 100 + slot_max ) {
      FD_TEST( !err );
      fd_votes_blk_key_t key = { .slot = slot, .block_id = block_id };
      blk_t * blk = blk_map_ele_query( votes->blk_map, &key, NULL, votes->blk_pool );
      FD_TEST( blk );
      FD_TEST( blk->stake==1 );
    } else {
      FD_TEST( err==FD_VOTES_ERR_VOTE_TOO_NEW );
    }
  }

  /* Votes for slots way ahead of root — rejected. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 5000+i } };
    FD_TEST( fd_votes_count_vote( votes, &voters[i], stakes[i], 200, &block_id )==FD_VOTES_ERR_VOTE_TOO_NEW );
  }

  /* Unknown voter — rejected. */

  fd_pubkey_t unknown = { .ul = { 999 } };
  fd_hash_t   block_id = { .ul = { 6000 } };
  FD_TEST( fd_votes_count_vote( votes, &unknown, 0UL, 101, &block_id )==FD_VOTES_ERR_UNKNOWN_VTR );

  /* Honest voters can still vote normally. */

  fd_hash_t honest_block_id = { .ul = { 7777 } };
  ulong honest_slot = 105;
  for( ulong i = attacker_cnt; i < vtr_max; i++ ) {
    FD_TEST( !fd_votes_count_vote( votes, &voters[i], stakes[i], honest_slot, &honest_block_id ) );
  }
  fd_votes_blk_key_t honest_key = { .slot = honest_slot, .block_id = honest_block_id };
  blk_t * honest_blk = blk_map_ele_query( votes->blk_map, &honest_key, NULL, votes->blk_pool );
  FD_TEST( honest_blk );
  FD_TEST( honest_blk->stake==(vtr_max - attacker_cnt) );

  fd_votes_delete( fd_votes_leave( votes ) );
}

void
test_votes_update_voters( void ) {
  ulong slot_max = 8;
  ulong vtr_max  = 4;

  FD_TEST( fd_votes_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_votes_t * votes = fd_votes_join( fd_votes_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( votes );

  fd_pubkey_t a = { .ul = { 1 } };
  fd_pubkey_t b = { .ul = { 2 } };
  fd_pubkey_t c = { .ul = { 3 } };

  /* Initial update with {a, b}. */

  fd_pubkey_t tv1[]  = { a, b };
  ulong       stk1[] = { 10, 51 };
  fd_votes_update_voters( votes, tv1, 2UL );

  FD_TEST( vtr_pool_used( votes->vtr_pool )==2 );
  FD_TEST(  vtr_map_ele_query( votes->vtr_map, &a, NULL, votes->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( votes->vtr_map, &b, NULL, votes->vtr_pool ) );

  /* Both voters can vote. */

  fd_votes_publish( votes, 100 );

  fd_hash_t block_id = { .ul = { 200 } };
  FD_TEST( !fd_votes_count_vote( votes, &a, stk1[0], 101, &block_id ) );
  FD_TEST( !fd_votes_count_vote( votes, &b, stk1[1], 101, &block_id ) );

  fd_votes_blk_key_t key = { .slot = 101, .block_id = block_id };
  blk_t * blk = blk_map_ele_query( votes->blk_map, &key, NULL, votes->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==61 );

  /* Reindex with {b, c}: a removed, c added.  b preserved with updated
     stake.  a's vote bit cleared from existing slot vtrs. */

  fd_pubkey_t tv2[]  = { b, c };
  ulong       stk2[] = { 99, 30 };
  fd_votes_update_voters( votes, tv2, 2UL );

  FD_TEST( vtr_pool_used( votes->vtr_pool )==2 );
  FD_TEST( !vtr_map_ele_query( votes->vtr_map, &a, NULL, votes->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( votes->vtr_map, &b, NULL, votes->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( votes->vtr_map, &c, NULL, votes->vtr_pool ) );

  /* c can vote; a (unknown) cannot. */

  FD_TEST( !fd_votes_count_vote( votes, &c, stk2[1], 102, &block_id ) );
  FD_TEST( fd_votes_count_vote( votes, &a, 0UL, 102, &block_id )==FD_VOTES_ERR_UNKNOWN_VTR );

  /* a's old vote bit was cleared from slot 101's vtrs, so c (who may
     have been assigned a's old bit position) can still vote on slot 101
     without a false ALREADY_VOTED. */

  FD_TEST( !fd_votes_count_vote( votes, &c, stk2[1], 101, &block_id ) );

  /* Same set is a no-op. */

  fd_pubkey_t tv3[]  = { b, c };
  fd_votes_update_voters( votes, tv3, 2UL );

  FD_TEST( vtr_pool_used( votes->vtr_pool )==2 );

  /* Empty set removes all. */

  fd_votes_update_voters( votes, NULL, 0UL );

  FD_TEST( vtr_pool_used( votes->vtr_pool )==0 );

  fd_votes_delete( fd_votes_leave( votes ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_votes_simple();
  test_votes_spam_block_ids_per_slot();
  test_votes_spam_many_slots();
  test_votes_update_voters();

  fd_halt();
  return 0;
}
