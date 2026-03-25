#include "fd_votes.c"

#define SCRATCH_MAX (1UL<<22)
static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

/* Register voters manually (bypassing update_voters which needs
   tower_stakes). */

static void
register_voters( fd_votes_t * votes, fd_pubkey_t * voters, ulong * stakes, ulong cnt ) {
  for( ulong i = 0; i < cnt; i++ ) {
    vtr_t * v      = vtr_pool_ele_acquire( votes->vtr_pool );
    v->vote_acc    = voters[i];
    v->bit         = i;
    v->stake       = stakes[i];
    vtr_map_ele_insert( votes->vtr_map, v, votes->vtr_pool );
    vtr_dlist_ele_push_tail( votes->vtr_dlist, v, votes->vtr_pool );
  }
}

void
test_votes_simple( void ) {
  ulong slot_max    = 8;
  ulong vtr_max     = 4;
  FD_TEST( fd_votes_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_votes_t * votes = fd_votes_join( fd_votes_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( votes );

  fd_pubkey_t voters[2] = { { .ul = { 1 } }, { .ul = { 2 } } };
  ulong       stakes[2] = { 10, 51 };
  register_voters( votes, voters, stakes, 2 );

  fd_votes_publish( votes, 100 );

  /* Count a vote from voter_a for slot 101. */

  fd_hash_t block_id_a = { .ul = { 200 } };
  FD_TEST( fd_votes_count_vote( votes, &voters[0], 101, &block_id_a ) );
  blk_t * blk = blk_map_ele_query( votes->blk_map, &block_id_a, NULL, votes->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==10 );
  FD_TEST( blk->slot==101 );

  /* Count a vote from voter_b for same slot 101, same block_id. */

  FD_TEST( fd_votes_count_vote( votes, &voters[1], 101, &block_id_a ) );
  blk = blk_map_ele_query( votes->blk_map, &block_id_a, NULL, votes->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==61 );

  /* voter_a tries to vote again for slot 101 — rejected. */

  fd_hash_t block_id_b = { .ul = { 201 } };
  FD_TEST( !fd_votes_count_vote( votes, &voters[0], 101, &block_id_b ) );

  /* voter_a votes for a different slot 102. */

  FD_TEST( fd_votes_count_vote( votes, &voters[0], 102, &block_id_b ) );
  blk = blk_map_ele_query( votes->blk_map, &block_id_b, NULL, votes->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==10 );

  /* Query blk by block_id. */

  FD_TEST( blk_map_ele_query( votes->blk_map, &block_id_a, NULL, votes->blk_pool ) );
  FD_TEST( blk_map_ele_query( votes->blk_map, &block_id_b, NULL, votes->blk_pool ) );

  /* Publish root to 102 — slot 101 and its blks should be removed. */

  fd_votes_publish( votes, 102 );
  FD_TEST( !blk_map_ele_query( votes->blk_map, &block_id_a, NULL, votes->blk_pool ) );
  FD_TEST(  blk_map_ele_query( votes->blk_map, &block_id_b, NULL, votes->blk_pool ) );
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
  register_voters( votes, voters, stakes, vtr_max );
  fd_votes_publish( votes, 100 );

  ulong target_slot = 101;

  /* Each attacker votes for a DIFFERENT block_id on the same slot. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    FD_TEST( fd_votes_count_vote( votes, &voters[i], target_slot, &block_id ) );
    blk_t * blk = blk_map_ele_query( votes->blk_map, &block_id, NULL, votes->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==1 );
  }

  /* Each block_id exists but has only stake=1. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    blk_t * blk = blk_map_ele_query( votes->blk_map, &block_id, NULL, votes->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==1 );
  }

  /* Each attacker tries to re-vote — all rejected. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 2000+i } };
    FD_TEST( !fd_votes_count_vote( votes, &voters[i], target_slot, &block_id ) );
  }

  /* Honest voters vote for the real block_id.  Their stake accumulates
     correctly and is unaffected by the attacker spam. */

  fd_hash_t honest_block_id = { .ul = { 9999 } };
  for( ulong i = attacker_cnt; i < vtr_max; i++ ) {
    FD_TEST( fd_votes_count_vote( votes, &voters[i], target_slot, &honest_block_id ) );
    blk_t * blk = blk_map_ele_query( votes->blk_map, &honest_block_id, NULL, votes->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==(i - attacker_cnt + 1) );
  }

  blk_t * honest_blk = blk_map_ele_query( votes->blk_map, &honest_block_id, NULL, votes->blk_pool );
  FD_TEST( honest_blk );
  FD_TEST( honest_blk->stake==(vtr_max - attacker_cnt) );

  /* Publish cleans up all block ids. */

  fd_votes_publish( votes, target_slot + 1 );
  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    FD_TEST( !blk_map_ele_query( votes->blk_map, &block_id, NULL, votes->blk_pool ) );
  }
  FD_TEST( !blk_map_ele_query( votes->blk_map, &honest_block_id, NULL, votes->blk_pool ) );

  fd_votes_delete( fd_votes_leave( votes ) );
}

/* Stress test: attacker sprays votes across many slots with different
   block ids.  Votes outside the valid range [root, root+slot_max)
   should be rejected.  Unknown voters should be rejected. */

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
  register_voters( votes, voters, stakes, vtr_max );
  fd_votes_publish( votes, 100 );

  /* Each attacker votes for a different slot, unique block_id. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    ulong slot = 101 + i;
    fd_hash_t block_id = { .ul = { 3000+i } };
    blk_t * res = fd_votes_count_vote( votes, &voters[i], slot, &block_id );
    if( slot < 100 + slot_max ) {
      FD_TEST( res );
      blk_t * blk = blk_map_ele_query( votes->blk_map, &block_id, NULL, votes->blk_pool );
      FD_TEST( blk );
      FD_TEST( blk->stake==1 );
    } else {
      FD_TEST( !res ); /* too far ahead */
    }
  }

  /* Votes for slots behind root — rejected. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 4000+i } };
    FD_TEST( !fd_votes_count_vote( votes, &voters[i], 50, &block_id ) );
  }

  /* Votes for slots way ahead of root — rejected. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 5000+i } };
    FD_TEST( !fd_votes_count_vote( votes, &voters[i], 200, &block_id ) );
  }

  /* Unknown voter — rejected. */

  fd_pubkey_t unknown = { .ul = { 999 } };
  fd_hash_t   block_id = { .ul = { 6000 } };
  FD_TEST( !fd_votes_count_vote( votes, &unknown, 101, &block_id ) );

  /* Honest voters can still vote normally. */

  fd_hash_t honest_block_id = { .ul = { 7777 } };
  ulong honest_slot = 105;
  for( ulong i = attacker_cnt; i < vtr_max; i++ ) {
    FD_TEST( fd_votes_count_vote( votes, &voters[i], honest_slot, &honest_block_id ) );
  }
  blk_t * honest_blk = blk_map_ele_query( votes->blk_map, &honest_block_id, NULL, votes->blk_pool );
  FD_TEST( honest_blk );
  FD_TEST( honest_blk->stake==(vtr_max - attacker_cnt) );

  fd_votes_delete( fd_votes_leave( votes ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_votes_simple();
  test_votes_spam_block_ids_per_slot();
  test_votes_spam_many_slots();

  fd_halt();
  return 0;
}
