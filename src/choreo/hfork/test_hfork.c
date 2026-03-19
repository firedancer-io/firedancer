#include "fd_hfork.c"

#define SCRATCH_MAX (1UL<<18)
static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

/* Helper to query bhm by (block_id, bank_hash). */
static bhm_t *
bhm_query( fd_hfork_t * hfork, fd_hash_t const * block_id, fd_hash_t const * bank_hash ) {
  bhm_key_t bhm_key = { .block_id = *block_id, .bank_hash = *bank_hash };
  return bhm_map_ele_query( hfork->bhm_map, &bhm_key, NULL, hfork->bhm_pool );
}

/* Register voters manually (since we don't have tower_voters). */
static void
register_voters( fd_hfork_t * hfork, fd_pubkey_t * voters, ulong cnt ) {
  for( ulong i = 0; i < cnt; i++ ) {
    vtr_t * vtr  = vtr_pool_ele_acquire( hfork->vtr_pool );
    vtr->addr    = voters[i];
    vtr->vte_cnt = 0;
    vtr_map_ele_insert( hfork->vtr_map, vtr, hfork->vtr_pool );
    vtr_dlist_ele_push_tail( hfork->vtr_dlist, vtr, hfork->vtr_pool );
  }
}

void
test_hfork_vote_counting( void ) {
  ulong  per_vtr_max = 8;
  ulong  vtr_max = 4;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_hash_t block_id  = { .ul = { 100 } };
  fd_hash_t bank_hash = { .ul = { 200 } };
  ulong     slot      = 1000;

  fd_pubkey_t voters[4] = {
    (fd_pubkey_t){ .ul = { 1 } },
    (fd_pubkey_t){ .ul = { 2 } },
    (fd_pubkey_t){ .ul = { 3 } },
    (fd_pubkey_t){ .ul = { 4 } },
  };
  register_voters( hfork, voters, 4 );

  /* voter[0] votes for (block_id, bank_hash) */

  fd_hfork_count_vote( hfork, &voters[0], &block_id, &bank_hash, slot, 10, 100 );
  bhm_t * bhm = bhm_query( hfork, &block_id, &bank_hash );
  FD_TEST( bhm );
  FD_TEST( bhm->stake   ==10 );
  FD_TEST( bhm->vtr_cnt ==1  );

  /* voter[1] votes for the same (block_id, bank_hash) — per-voter
     dedup allows different voters to vote for the same block_id. */

  fd_hfork_count_vote( hfork, &voters[1], &block_id, &bank_hash, slot, 51, 100 );
  FD_TEST( bhm->stake   ==61 );
  FD_TEST( bhm->vtr_cnt ==2  );

  /* voter[0] tries to vote again for the same (block_id, bank_hash)
     with a higher slot — dedup rejects because same voter, same block_id. */

  fd_hfork_count_vote( hfork, &voters[0], &block_id, &bank_hash, slot+1, 10, 100 );
  FD_TEST( bhm->stake   ==61 );
  FD_TEST( bhm->vtr_cnt ==2  );

  /* record_our_bank_hash and verify check fires when 52% match */

  blk_t * blk = blk_map_ele_query( hfork->blk_map, &block_id, NULL, hfork->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->flag ==0 );

  fd_hfork_record_our_bank_hash( hfork, &block_id, &bank_hash, 100 );
  FD_TEST( blk->flag ==1 ); /* matched */

  fd_hfork_delete( fd_hfork_leave( hfork ) );
}

void
test_hfork_multiple_bank_hashes( void ) {
  ulong  per_vtr_max = 8;
  ulong  vtr_max = 4;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_hash_t block_id   = { .ul = { 100 } };
  fd_hash_t bank_hash0 = { .ul = { 200 } };
  fd_hash_t bank_hash1 = { .ul = { 201 } };
  fd_hash_t bank_hash2 = { .ul = { 202 } };
  fd_hash_t bank_hash3 = { .ul = { 203 } };
  ulong     slot       = 1000;

  fd_pubkey_t voters[4] = {
    (fd_pubkey_t){ .ul = { 1 } },
    (fd_pubkey_t){ .ul = { 2 } },
    (fd_pubkey_t){ .ul = { 3 } },
    (fd_pubkey_t){ .ul = { 4 } },
  };
  register_voters( hfork, voters, 4 );

  /* 4 voters each report a different bank hash for the same block_id */

  fd_hfork_count_vote( hfork, &voters[0], &block_id, &bank_hash0, slot, 1,  100 );
  fd_hfork_count_vote( hfork, &voters[1], &block_id, &bank_hash1, slot, 51, 100 );
  fd_hfork_count_vote( hfork, &voters[2], &block_id, &bank_hash2, slot, 2,  100 );
  fd_hfork_count_vote( hfork, &voters[3], &block_id, &bank_hash3, slot, 3,  100 );

  FD_TEST( bhm_query( hfork, &block_id, &bank_hash0 ) );
  FD_TEST( bhm_query( hfork, &block_id, &bank_hash1 ) );
  FD_TEST( bhm_query( hfork, &block_id, &bank_hash2 ) );
  FD_TEST( bhm_query( hfork, &block_id, &bank_hash3 ) );

  fd_hfork_delete( fd_hfork_leave( hfork ) );
}

void
test_hfork_eviction( void ) {
  ulong  per_vtr_max = 3;
  ulong  vtr_max = 2;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_hash_t block_ids[5];
  fd_hash_t bank_hashes[5];
  ulong     slots[5];
  for( ulong i = 0; i < 5; i++ ) {
    block_ids[i]   = (fd_hash_t){ .ul = { 100+i } };
    bank_hashes[i] = (fd_hash_t){ .ul = { 200+i } };
    slots[i]       = 1000+i;
  }

  fd_pubkey_t voters[2] = {
    (fd_pubkey_t){ .ul = { 1 } },
    (fd_pubkey_t){ .ul = { 2 } },
  };
  register_voters( hfork, voters, 2 );

  /* voter[0] votes for 3 different blocks (reaching per_vtr_max) */

  fd_hfork_count_vote( hfork, &voters[0], &block_ids[0], &bank_hashes[0], slots[0], 10, 100 );
  fd_hfork_count_vote( hfork, &voters[0], &block_ids[1], &bank_hashes[1], slots[1], 10, 100 );
  fd_hfork_count_vote( hfork, &voters[0], &block_ids[2], &bank_hashes[2], slots[2], 10, 100 );

  FD_TEST( bhm_query( hfork, &block_ids[0], &bank_hashes[0] ) );
  FD_TEST( bhm_query( hfork, &block_ids[1], &bank_hashes[1] ) );
  FD_TEST( bhm_query( hfork, &block_ids[2], &bank_hashes[2] ) );

  /* voter[0] votes for a 4th block — oldest (block_ids[0]) is evicted.
     Since voter[0] was the only voter for block_ids[0], its bhm is
     removed and the blk is also removed. */

  fd_hfork_count_vote( hfork, &voters[0], &block_ids[3], &bank_hashes[3], slots[3], 10, 100 );

  FD_TEST( !bhm_query( hfork, &block_ids[0], &bank_hashes[0] ) );
  FD_TEST( !blk_map_ele_query_const( hfork->blk_map, &block_ids[0], NULL, hfork->blk_pool ) );
  FD_TEST(  bhm_query( hfork, &block_ids[1], &bank_hashes[1] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[2], &bank_hashes[2] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[3], &bank_hashes[3] ) );

  /* continued eviction — voter[0] votes for a 5th block, evicting
     block_ids[1].  Then verify block_ids[1] is gone and the rest
     remain. */

  fd_hfork_count_vote( hfork, &voters[0], &block_ids[4], &bank_hashes[4], slots[4], 10, 100 );

  FD_TEST( !bhm_query( hfork, &block_ids[1], &bank_hashes[1] ) );
  FD_TEST( !blk_map_ele_query_const( hfork->blk_map, &block_ids[1], NULL, hfork->blk_pool ) );
  FD_TEST(  bhm_query( hfork, &block_ids[2], &bank_hashes[2] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[3], &bank_hashes[3] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[4], &bank_hashes[4] ) );

  fd_hfork_delete( fd_hfork_leave( hfork ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_hfork_vote_counting();
  test_hfork_multiple_bank_hashes();
  test_hfork_eviction();

  fd_halt();
  return 0;
}
