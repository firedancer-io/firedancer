#include "fd_notar.c"

#define SCRATCH_MAX (1UL<<22)
static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

/* Register voters manually (bypassing update_voters which needs
   tower_stakes). */

static void
register_voters( fd_notar_t * notar, fd_pubkey_t * voters, ulong * stakes, ulong cnt ) {
  for( ulong i = 0; i < cnt; i++ ) {
    vtr_t * v      = vtr_pool_ele_acquire( notar->vtr_pool );
    v->vote_acc    = voters[i];
    v->bit         = i;
    v->stake       = stakes[i];
    vtr_map_ele_insert( notar->vtr_map, v, notar->vtr_pool );
    vtr_dlist_ele_push_tail( notar->vtr_dlist, v, notar->vtr_pool );
  }
}

void
test_notar_simple( void ) {
  ulong slot_max = 8;
  ulong vtr_max  = 4;
  FD_TEST( fd_notar_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_notar_t * notar = fd_notar_join( fd_notar_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( notar );

  fd_pubkey_t voters[2] = { { .ul = { 1 } }, { .ul = { 2 } } };
  ulong       stakes[2] = { 10, 51 };
  register_voters( notar, voters, stakes, 2 );

  fd_notar_publish( notar, 100 );

  /* Count a vote from voter_a for slot 101. */

  fd_hash_t block_id_a = { .ul = { 200 } };
  FD_TEST( !fd_notar_count_vote( notar, &voters[0], 101, &block_id_a ) );
  fd_notar_blk_key_t key_a101 = { .slot = 101, .block_id = block_id_a };
  blk_t * blk = blk_map_ele_query( notar->blk_map, &key_a101, NULL, notar->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==10 );
  FD_TEST( blk->key.slot==101 );

  /* Count a vote from voter_b for same slot 101, same block_id. */

  FD_TEST( !fd_notar_count_vote( notar, &voters[1], 101, &block_id_a ) );
  blk = blk_map_ele_query( notar->blk_map, &key_a101, NULL, notar->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==61 );

  /* voter_a tries to vote again for slot 101 — rejected. */

  fd_hash_t block_id_b = { .ul = { 201 } };
  FD_TEST( fd_notar_count_vote( notar, &voters[0], 101, &block_id_b )==FD_NOTAR_ERR_ALREADY_VOTED );

  /* voter_a votes for a different slot 102. */

  FD_TEST( !fd_notar_count_vote( notar, &voters[0], 102, &block_id_b ) );
  fd_notar_blk_key_t key_b102 = { .slot = 102, .block_id = block_id_b };
  blk = blk_map_ele_query( notar->blk_map, &key_b102, NULL, notar->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->stake==10 );

  /* Query blk by (slot, block_id). */

  FD_TEST( blk_map_ele_query( notar->blk_map, &key_a101, NULL, notar->blk_pool ) );
  FD_TEST( blk_map_ele_query( notar->blk_map, &key_b102, NULL, notar->blk_pool ) );

  /* Publish root to 102 — slot 101 and its blks should be removed. */

  fd_notar_publish( notar, 102 );
  FD_TEST( !blk_map_ele_query( notar->blk_map, &key_a101, NULL, notar->blk_pool ) );
  FD_TEST(  blk_map_ele_query( notar->blk_map, &key_b102, NULL, notar->blk_pool ) );
  FD_TEST(  notar->root==102 );

  fd_notar_delete( fd_notar_leave( notar ) );
}

/* Stress test: attacker tries to spam many different block ids for a
   single slot.  Each voter can only vote once per slot, so an attacker
   with N sybil voters can create at most N distinct block ids for a
   given slot.  Each block id only accumulates the attacker's own stake
   (1 per sybil), so none should reach any confirmation threshold. */

void
test_notar_spam_block_ids_per_slot( void ) {
  ulong slot_max     = 8;
  ulong vtr_max      = 64;
  ulong attacker_cnt = 32;

  FD_TEST( fd_notar_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_notar_t * notar = fd_notar_join( fd_notar_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( notar );

  fd_pubkey_t voters[64];
  ulong       stakes[64];
  for( ulong i = 0; i < vtr_max; i++ ) {
    voters[i] = (fd_pubkey_t){ .ul = { i+1 } };
    stakes[i] = 1;
  }
  register_voters( notar, voters, stakes, vtr_max );
  fd_notar_publish( notar, 100 );

  ulong target_slot = 101;

  /* Each attacker votes for a DIFFERENT block_id on the same slot. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    FD_TEST( !fd_notar_count_vote( notar, &voters[i], target_slot, &block_id ) );
    fd_notar_blk_key_t key = { .slot = target_slot, .block_id = block_id };
    blk_t * blk = blk_map_ele_query( notar->blk_map, &key, NULL, notar->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==1 );
  }

  /* Each block_id exists but has only stake=1. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    fd_notar_blk_key_t key = { .slot = target_slot, .block_id = block_id };
    blk_t * blk = blk_map_ele_query( notar->blk_map, &key, NULL, notar->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==1 );
  }

  /* Each attacker tries to re-vote — all rejected. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 2000+i } };
    FD_TEST( fd_notar_count_vote( notar, &voters[i], target_slot, &block_id )==FD_NOTAR_ERR_ALREADY_VOTED );
  }

  /* Honest voters vote for the real block_id.  Their stake accumulates
     correctly and is unaffected by the attacker spam. */

  fd_hash_t honest_block_id = { .ul = { 9999 } };
  for( ulong i = attacker_cnt; i < vtr_max; i++ ) {
    FD_TEST( !fd_notar_count_vote( notar, &voters[i], target_slot, &honest_block_id ) );
    fd_notar_blk_key_t key = { .slot = target_slot, .block_id = honest_block_id };
    blk_t * blk = blk_map_ele_query( notar->blk_map, &key, NULL, notar->blk_pool );
    FD_TEST( blk );
    FD_TEST( blk->stake==(i - attacker_cnt + 1) );
  }

  fd_notar_blk_key_t honest_key = { .slot = target_slot, .block_id = honest_block_id };
  blk_t * honest_blk = blk_map_ele_query( notar->blk_map, &honest_key, NULL, notar->blk_pool );
  FD_TEST( honest_blk );
  FD_TEST( honest_blk->stake==(vtr_max - attacker_cnt) );

  /* Publish cleans up all block ids. */

  fd_notar_publish( notar, target_slot + 1 );
  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 1000+i } };
    fd_notar_blk_key_t key = { .slot = target_slot, .block_id = block_id };
    FD_TEST( !blk_map_ele_query( notar->blk_map, &key, NULL, notar->blk_pool ) );
  }
  FD_TEST( !blk_map_ele_query( notar->blk_map, &honest_key, NULL, notar->blk_pool ) );

  fd_notar_delete( fd_notar_leave( notar ) );
}

/* Stress test: attacker sprays votes across many slots with different
   block ids.  Votes beyond root+slot_max should be rejected.  Unknown
   voters should be rejected. */

void
test_notar_spam_many_slots( void ) {
  ulong slot_max     = 8;
  ulong vtr_max      = 16;
  ulong attacker_cnt = 8;

  FD_TEST( fd_notar_footprint( slot_max, vtr_max ) <= SCRATCH_MAX );
  fd_notar_t * notar = fd_notar_join( fd_notar_new( scratch, slot_max, vtr_max, 0 ) );
  FD_TEST( notar );

  fd_pubkey_t voters[16];
  ulong       stakes[16];
  for( ulong i = 0; i < vtr_max; i++ ) {
    voters[i] = (fd_pubkey_t){ .ul = { i+1 } };
    stakes[i] = 1;
  }
  register_voters( notar, voters, stakes, vtr_max );
  fd_notar_publish( notar, 100 );

  /* Each attacker votes for a different slot, unique block_id. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    ulong slot = 101 + i;
    fd_hash_t block_id = { .ul = { 3000+i } };
    int err = fd_notar_count_vote( notar, &voters[i], slot, &block_id );
    if( slot < 100 + slot_max ) {
      FD_TEST( !err );
      fd_notar_blk_key_t key = { .slot = slot, .block_id = block_id };
      blk_t * blk = blk_map_ele_query( notar->blk_map, &key, NULL, notar->blk_pool );
      FD_TEST( blk );
      FD_TEST( blk->stake==1 );
    } else {
      FD_TEST( err==FD_NOTAR_ERR_VOTE_TOO_NEW );
    }
  }

  /* Votes for slots way ahead of root — rejected. */

  for( ulong i = 0; i < attacker_cnt; i++ ) {
    fd_hash_t block_id = { .ul = { 5000+i } };
    FD_TEST( fd_notar_count_vote( notar, &voters[i], 200, &block_id )==FD_NOTAR_ERR_VOTE_TOO_NEW );
  }

  /* Unknown voter — rejected. */

  fd_pubkey_t unknown = { .ul = { 999 } };
  fd_hash_t   block_id = { .ul = { 6000 } };
  FD_TEST( fd_notar_count_vote( notar, &unknown, 101, &block_id )==FD_NOTAR_ERR_UNKNOWN_VTR );

  /* Honest voters can still vote normally. */

  fd_hash_t honest_block_id = { .ul = { 7777 } };
  ulong honest_slot = 105;
  for( ulong i = attacker_cnt; i < vtr_max; i++ ) {
    FD_TEST( !fd_notar_count_vote( notar, &voters[i], honest_slot, &honest_block_id ) );
  }
  fd_notar_blk_key_t honest_key = { .slot = honest_slot, .block_id = honest_block_id };
  blk_t * honest_blk = blk_map_ele_query( notar->blk_map, &honest_key, NULL, notar->blk_pool );
  FD_TEST( honest_blk );
  FD_TEST( honest_blk->stake==(vtr_max - attacker_cnt) );

  fd_notar_delete( fd_notar_leave( notar ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_notar_simple();
  test_notar_spam_block_ids_per_slot();
  test_notar_spam_many_slots();

  fd_halt();
  return 0;
}
