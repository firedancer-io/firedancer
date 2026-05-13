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
    vtr->vote_acc = voters[i];
    vtr->vte_cnt = 0;
    vtr_map_ele_insert( hfork->vtr_map, vtr, hfork->vtr_pool );
    vtr_dlist_ele_push_tail( hfork->vtr_dlist, vtr, hfork->vtr_pool );
  }
}

void
test_count_vote( void ) {
  ulong  per_vtr_max = 8;
  ulong  vtr_max = 4;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_hash_t block_id   = { .ul = { 100 } };
  fd_hash_t bank_hash  = { .ul = { 200 } };
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

  /* Unknown voter returns ERR_UNKNOWN_VTR. */

  fd_pubkey_t unknown = { .ul = { 99 } };
  FD_TEST( fd_hfork_count_vote( hfork, &unknown, &block_id, &bank_hash, slot, 10, 100 )==FD_HFORK_ERR_UNKNOWN_VTR );

  /* voter[0] votes for (block_id, bank_hash). */

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

  /* voter[0] tries to vote again for the same block_id — ALREADY_VOTED. */

  FD_TEST( fd_hfork_count_vote( hfork, &voters[0], &block_id, &bank_hash, slot+1, 10, 100 )==FD_HFORK_ERR_ALREADY_VOTED );
  FD_TEST( bhm->stake   ==61 );
  FD_TEST( bhm->vtr_cnt ==2  );

  /* voter[0] votes for a new block_id but with an older slot — VOTE_TOO_OLD. */

  fd_hash_t block_id2 = { .ul = { 101 } };
  FD_TEST( fd_hfork_count_vote( hfork, &voters[0], &block_id2, &bank_hash, slot - 1, 10, 100 )==FD_HFORK_ERR_VOTE_TOO_OLD );

  /* 4 voters each report a different bank hash for the same block_id. */

  fd_hfork_count_vote( hfork, &voters[2], &block_id, &bank_hash2, slot, 2, 100 );
  fd_hfork_count_vote( hfork, &voters[3], &block_id, &bank_hash3, slot, 3, 100 );

  FD_TEST( bhm_query( hfork, &block_id, &bank_hash  ) );
  FD_TEST( bhm_query( hfork, &block_id, &bank_hash2 ) );
  FD_TEST( bhm_query( hfork, &block_id, &bank_hash3 ) );

  /* record_our_bank_hash and verify check fires when 52% match. */

  blk_t * blk = blk_map_ele_query( hfork->blk_map, &block_id, NULL, hfork->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->flag ==0 );

  fd_hfork_record_our_bank_hash( hfork, &block_id, &bank_hash, 100 );
  FD_TEST( blk->flag ==1 ); /* matched */

  /* Eviction: use a fresh instance with per_vtr_max=3. */

  fd_hfork_delete( fd_hfork_leave( hfork ) );

  per_vtr_max = 3;
  vtr_max     = 2;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_hash_t block_ids[5];
  fd_hash_t bank_hashes[5];
  ulong     slots[5];
  for( ulong i = 0; i < 5; i++ ) {
    block_ids[i]   = (fd_hash_t){ .ul = { 100+i } };
    bank_hashes[i] = (fd_hash_t){ .ul = { 200+i } };
    slots[i]       = 1000+i;
  }

  fd_pubkey_t voters2[2] = {
    (fd_pubkey_t){ .ul = { 1 } },
    (fd_pubkey_t){ .ul = { 2 } },
  };
  register_voters( hfork, voters2, 2 );

  /* voter[0] votes for 3 different blocks (reaching per_vtr_max). */

  fd_hfork_count_vote( hfork, &voters2[0], &block_ids[0], &bank_hashes[0], slots[0], 10, 100 );
  fd_hfork_count_vote( hfork, &voters2[0], &block_ids[1], &bank_hashes[1], slots[1], 10, 100 );
  fd_hfork_count_vote( hfork, &voters2[0], &block_ids[2], &bank_hashes[2], slots[2], 10, 100 );

  FD_TEST( bhm_query( hfork, &block_ids[0], &bank_hashes[0] ) );
  FD_TEST( bhm_query( hfork, &block_ids[1], &bank_hashes[1] ) );
  FD_TEST( bhm_query( hfork, &block_ids[2], &bank_hashes[2] ) );

  /* voter[0] votes for a 4th block — oldest (block_ids[0]) is evicted.
     Since voter[0] was the only voter for block_ids[0], its bhm is
     removed and the blk is also removed. */

  fd_hfork_count_vote( hfork, &voters2[0], &block_ids[3], &bank_hashes[3], slots[3], 10, 100 );

  FD_TEST( !bhm_query( hfork, &block_ids[0], &bank_hashes[0] ) );
  FD_TEST( !blk_map_ele_query_const( hfork->blk_map, &block_ids[0], NULL, hfork->blk_pool ) );
  FD_TEST(  bhm_query( hfork, &block_ids[1], &bank_hashes[1] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[2], &bank_hashes[2] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[3], &bank_hashes[3] ) );

  /* continued eviction — voter[0] votes for a 5th block, evicting
     block_ids[1]. */

  fd_hfork_count_vote( hfork, &voters2[0], &block_ids[4], &bank_hashes[4], slots[4], 10, 100 );

  FD_TEST( !bhm_query( hfork, &block_ids[1], &bank_hashes[1] ) );
  FD_TEST( !blk_map_ele_query_const( hfork->blk_map, &block_ids[1], NULL, hfork->blk_pool ) );
  FD_TEST(  bhm_query( hfork, &block_ids[2], &bank_hashes[2] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[3], &bank_hashes[3] ) );
  FD_TEST(  bhm_query( hfork, &block_ids[4], &bank_hashes[4] ) );

  fd_hfork_delete( fd_hfork_leave( hfork ) );

  /* Eviction where evicted bhm still has other voters (vtr_cnt > 0
     after decrement).  Two voters vote for the same block, then one
     voter evicts their vote by reaching per_vtr_max. */

  per_vtr_max = 2;
  vtr_max     = 2;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_pubkey_t voters3[2] = {
    (fd_pubkey_t){ .ul = { 1 } },
    (fd_pubkey_t){ .ul = { 2 } },
  };
  register_voters( hfork, voters3, 2 );

  fd_hash_t bid_shared = { .ul = { 500 } };
  fd_hash_t bh_shared  = { .ul = { 600 } };

  fd_hfork_count_vote( hfork, &voters3[0], &bid_shared, &bh_shared, 2000, 10, 100 );
  fd_hfork_count_vote( hfork, &voters3[1], &bid_shared, &bh_shared, 2000, 20, 100 );

  bhm_t * bhm_shared = bhm_query( hfork, &bid_shared, &bh_shared );
  FD_TEST( bhm_shared );
  FD_TEST( bhm_shared->stake==30 );
  FD_TEST( bhm_shared->vtr_cnt==2 );

  /* voter[0] votes for a second block (reaching per_vtr_max=2). */

  fd_hash_t bid_fill = { .ul = { 501 } };
  fd_hash_t bh_fill  = { .ul = { 601 } };
  fd_hfork_count_vote( hfork, &voters3[0], &bid_fill, &bh_fill, 2001, 10, 100 );

  /* voter[0] votes for a third block — evicts their oldest (bid_shared).
     The bhm for (bid_shared, bh_shared) survives with voter[1]'s stake. */

  fd_hash_t bid_evict = { .ul = { 502 } };
  fd_hash_t bh_evict  = { .ul = { 602 } };
  fd_hfork_count_vote( hfork, &voters3[0], &bid_evict, &bh_evict, 2002, 10, 100 );

  bhm_shared = bhm_query( hfork, &bid_shared, &bh_shared );
  FD_TEST( bhm_shared );
  FD_TEST( bhm_shared->stake==20 );
  FD_TEST( bhm_shared->vtr_cnt==1 );

  fd_hfork_delete( fd_hfork_leave( hfork ) );

  /* Mismatch: record our bank hash, then voter votes with a different
     bank hash at 52%+ stake — check returns -1 (mismatch). */

  per_vtr_max = 4;
  vtr_max     = 2;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_pubkey_t voter_mm = (fd_pubkey_t){ .ul = { 1 } };
  register_voters( hfork, &voter_mm, 1 );

  fd_hash_t bid_mm    = { .ul = { 700 } };
  fd_hash_t bh_ours   = { .ul = { 800 } };
  fd_hash_t bh_theirs = { .ul = { 801 } };

  fd_hfork_record_our_bank_hash( hfork, &bid_mm, &bh_ours, 100 );
  FD_TEST( fd_hfork_count_vote( hfork, &voter_mm, &bid_mm, &bh_theirs, 3000, 60, 100 )==FD_HFORK_ERR_MISMATCHED );

  fd_hfork_delete( fd_hfork_leave( hfork ) );
}

void
test_update_voters( void ) {
  ulong per_vtr_max = 8;
  ulong vtr_max     = 4;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_pubkey_t a = { .ul = { 1 } };
  fd_pubkey_t b = { .ul = { 2 } };
  fd_pubkey_t c = { .ul = { 3 } };

  /* Initial update with {a, b}. */

  fd_pubkey_t tv1[] = { a, b };
  fd_hfork_update_voters( hfork, tv1, 2UL );

  FD_TEST( vtr_pool_used( hfork->vtr_pool )==2 );
  FD_TEST(  vtr_map_ele_query( hfork->vtr_map, &a, NULL, hfork->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( hfork->vtr_map, &b, NULL, hfork->vtr_pool ) );

  /* Both voters can submit votes. */

  fd_hash_t block_id  = { .ul = { 100 } };
  fd_hash_t bank_hash = { .ul = { 200 } };

  fd_hfork_count_vote( hfork, &a, &block_id, &bank_hash, 1000, 10, 100 );
  fd_hfork_count_vote( hfork, &b, &block_id, &bank_hash, 1000, 20, 100 );

  bhm_t * bhm = bhm_query( hfork, &block_id, &bank_hash );
  FD_TEST( bhm );
  FD_TEST( bhm->stake==30 );
  FD_TEST( bhm->vtr_cnt==2 );

  vtr_t * vtr_a = vtr_map_ele_query( hfork->vtr_map, &a, NULL, hfork->vtr_pool );
  FD_TEST( vtr_a->vte_cnt==1 );

  /* Reindex with {b, c}: a removed (and its vote entries evicted),
     c added.  b's vote entries preserved. */

  fd_pubkey_t tv2[] = { b, c };
  fd_hfork_update_voters( hfork, tv2, 2UL );

  FD_TEST( vtr_pool_used( hfork->vtr_pool )==2 );
  FD_TEST( !vtr_map_ele_query( hfork->vtr_map, &a, NULL, hfork->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( hfork->vtr_map, &b, NULL, hfork->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( hfork->vtr_map, &c, NULL, hfork->vtr_pool ) );

  /* a's vote was evicted: bhm stake and vtr_cnt decreased. */

  bhm = bhm_query( hfork, &block_id, &bank_hash );
  FD_TEST( bhm );
  FD_TEST( bhm->stake==20 );
  FD_TEST( bhm->vtr_cnt==1 );

  /* b's vote entry survived. */

  vtr_t * vtr_b = vtr_map_ele_query( hfork->vtr_map, &b, NULL, hfork->vtr_pool );
  FD_TEST( vtr_b->vte_cnt==1 );

  /* c starts with zero vote entries. */

  vtr_t * vtr_c = vtr_map_ele_query( hfork->vtr_map, &c, NULL, hfork->vtr_pool );
  FD_TEST( vtr_c->vte_cnt==0 );

  /* Same set is a no-op (votes preserved). */

  fd_pubkey_t tv3[] = { b, c };
  fd_hfork_update_voters( hfork, tv3, 2UL );

  FD_TEST( vtr_pool_used( hfork->vtr_pool )==2 );
  bhm = bhm_query( hfork, &block_id, &bank_hash );
  FD_TEST( bhm );
  FD_TEST( bhm->stake==20 );
  FD_TEST( bhm->vtr_cnt==1 );

  /* record_our_bank_hash for the same block_id (blk already exists). */

  fd_hfork_record_our_bank_hash( hfork, &block_id, &bank_hash, 100 );

  blk_t * blk = blk_map_ele_query( hfork->blk_map, &block_id, NULL, hfork->blk_pool );
  FD_TEST( blk );
  FD_TEST( blk->replayed );

  /* Empty set removes all voters and their vote entries.  The blk
     is also released because its last bhm was removed. */

  fd_hfork_update_voters( hfork, NULL, 0UL );

  FD_TEST( vtr_pool_used( hfork->vtr_pool )==0 );
  FD_TEST( !bhm_query( hfork, &block_id, &bank_hash ) );
  FD_TEST( !blk_map_ele_query( hfork->blk_map, &block_id, NULL, hfork->blk_pool ) );

  fd_hfork_delete( fd_hfork_leave( hfork ) );
}

void
test_record_our_bank_hash( void ) {
  ulong per_vtr_max = 4;
  ulong vtr_max     = 2;
  ulong max         = per_vtr_max * vtr_max; /* blk_pool capacity */

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  /* record_our_bank_hash for a block with no votes — blk is in the
     dlist and survives update_voters (it's not voter-owned). */

  fd_hash_t block_id0 = { .ul = { 100 } };
  fd_hash_t bank_hash = { .ul = { 200 } };
  fd_hfork_record_our_bank_hash( hfork, &block_id0, &bank_hash, 100 );

  FD_TEST(  blk_map_ele_query( hfork->blk_map, &block_id0, NULL, hfork->blk_pool ) );
  FD_TEST( !blk_dlist_is_empty( hfork->blk_dlist, hfork->blk_pool ) );

  fd_hfork_update_voters( hfork, NULL, 0UL );
  FD_TEST( blk_map_ele_query( hfork->blk_map, &block_id0, NULL, hfork->blk_pool ) );

  /* Fill the pool with record_our_bank_hash calls. */

  for( ulong i = 1; i < max; i++ ) {
    fd_hash_t bid = { .ul = { 100+i } };
    fd_hfork_record_our_bank_hash( hfork, &bid, &bank_hash, 100 );
    FD_TEST( blk_map_ele_query( hfork->blk_map, &bid, NULL, hfork->blk_pool ) );
  }
  FD_TEST( blk_pool_free( hfork->blk_pool )==0 );

  /* One more record_our_bank_hash evicts the oldest (block_id0). */

  fd_hash_t bid_new = { .ul = { 100+max } };
  fd_hfork_record_our_bank_hash( hfork, &bid_new, &bank_hash, 100 );

  FD_TEST( !blk_map_ele_query( hfork->blk_map, &block_id0, NULL, hfork->blk_pool ) );
  FD_TEST(  blk_map_ele_query( hfork->blk_map, &bid_new,   NULL, hfork->blk_pool ) );

  /* A vote removes the blk from the dlist. */

  fd_pubkey_t a = { .ul = { 1 } };
  fd_pubkey_t tv[] = { a };
  fd_hfork_update_voters( hfork, tv, 1UL );

  fd_hash_t bid_voted = { .ul = { 101 } };
  fd_hash_t bh_voted  = { .ul = { 300 } };
  fd_hfork_count_vote( hfork, &a, &bid_voted, &bh_voted, 1000, 10, 100 );

  blk_t * blk_voted = blk_map_ele_query( hfork->blk_map, &bid_voted, NULL, hfork->blk_pool );
  FD_TEST( blk_voted );
  FD_TEST( blk_voted->bhm_cnt==1 );

  /* Removing voter evicts its bhm and blk. */

  fd_hfork_update_voters( hfork, NULL, 0UL );
  FD_TEST( !blk_map_ele_query( hfork->blk_map, &bid_voted, NULL, hfork->blk_pool ) );

  fd_hfork_delete( fd_hfork_leave( hfork ) );

  /* record_our_bank_hash with bank_hash == NULL marks the block dead.
     A vote with 52%+ stake triggers mismatch because block is dead. */

  per_vtr_max = 4;
  vtr_max     = 2;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_hash_t bid_dead = { .ul = { 900 } };
  fd_hfork_record_our_bank_hash( hfork, &bid_dead, NULL, 100 );

  blk_t * blk_dead = blk_map_ele_query( hfork->blk_map, &bid_dead, NULL, hfork->blk_pool );
  FD_TEST( blk_dead );
  FD_TEST( blk_dead->dead );
  FD_TEST( blk_dead->replayed );

  fd_pubkey_t voter_dead = (fd_pubkey_t){ .ul = { 1 } };
  register_voters( hfork, &voter_dead, 1 );

  fd_hash_t bh_dead = { .ul = { 999 } };
  FD_TEST( fd_hfork_count_vote( hfork, &voter_dead, &bid_dead, &bh_dead, 5000, 60, 100 )==FD_HFORK_ERR_MISMATCHED );

  fd_hfork_delete( fd_hfork_leave( hfork ) );

  /* Pool full with all blks having votes (dlist empty) —
     record_our_bank_hash cannot insert, returns 0. */

  per_vtr_max = 2;
  vtr_max     = 2;

  FD_TEST( fd_hfork_footprint( per_vtr_max, vtr_max ) <= SCRATCH_MAX );
  hfork = fd_hfork_join( fd_hfork_new( scratch, per_vtr_max, vtr_max, 0 ) );
  FD_TEST( hfork );

  fd_pubkey_t voters_full[2] = {
    (fd_pubkey_t){ .ul = { 1 } },
    (fd_pubkey_t){ .ul = { 2 } },
  };
  register_voters( hfork, voters_full, 2 );

  for( ulong i = 0; i < per_vtr_max * vtr_max; i++ ) {
    fd_hash_t bid = { .ul = { 1000+i } };
    fd_hash_t bh  = { .ul = { 2000+i } };
    fd_hfork_count_vote( hfork, &voters_full[i % 2], &bid, &bh, 6000+i, 10, 100 );
  }
  FD_TEST( blk_pool_free( hfork->blk_pool )==0 );
  FD_TEST( blk_dlist_is_empty( hfork->blk_dlist, hfork->blk_pool ) );

  fd_hash_t bid_nope = { .ul = { 9999 } };
  fd_hash_t bh_nope  = { .ul = { 8888 } };
  FD_TEST( fd_hfork_record_our_bank_hash( hfork, &bid_nope, &bh_nope, 100 )==0 );
  FD_TEST( !blk_map_ele_query( hfork->blk_map, &bid_nope, NULL, hfork->blk_pool ) );

  fd_hfork_delete( fd_hfork_leave( hfork ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_count_vote();
  test_record_our_bank_hash();
  test_update_voters();

  fd_halt();
  return 0;
}
