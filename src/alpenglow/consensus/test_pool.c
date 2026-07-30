#include "ag_pool.h"
#include "ag_cert.h"

#define SLOTS_PER_WINDOW AG_ALPENGLOW_SLOTS_PER_WINDOW
#define SLOTS_PER_EPOCH  AG_ALPENGLOW_SLOTS_PER_EPOCH
#define NV               (11UL)

/* Votes bind the cluster shred version; any fixed value works as long as
   the pool is built for the same one. */
#define TEST_SHRED_VERSION ((ushort)0x5a5a)

static ag_aggsig_sk_t      g_sk  [ NV ];
static ag_validator_info_t g_info[ NV ];

static fd_hash_t
genesis_hash( void ) {
  fd_hash_t h; fd_memset( h.uc, 0, sizeof(fd_hash_t) );
  return h;
}

static ulong g_hash_ctr = 0UL;

static fd_hash_t
random_hash( void ) {
  fd_hash_t h; fd_memset( h.uc, 0, sizeof(fd_hash_t) );
  h.ul[0] = 0x9000UL + (++g_hash_ctr);
  h.ul[1] = 0xc0ffee00UL ^ g_hash_ctr;
  return h;
}

static ag_block_id_t
random_block_id( ulong slot ) {
  ag_block_id_t b; b.slot = slot; b.hash = random_hash();
  return b;
}

static void
create_validators( void ) {
  for( ulong i=0UL; i<NV; i++ ) {
    fd_memset( g_sk[i].v, (int)(i*7UL+1UL), AG_AGGSIG_SECKEY_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    ag_aggsig_sk_to_pk( &g_info[i].voting_pubkey, &g_sk[i] );
  }
}

/* The pool emits PoolEvents / repair requests onto internal channels that
   the caller drains (the Rust event senders).  event_cnt / event reads the
   channel, and drain resets it -- a test drains to open a fresh
   observation window, exactly as the votor tile drains once per
   after_credit. */

static ulong
event_cnt( ag_pool_t const * pool ) {
  return ag_pool_votor_event_cnt( pool );
}

static ag_pool_event_t const *
event( ag_pool_t const * pool,
       ulong             i ) {
  return &ag_pool_votor_event_channel( pool )[ i ];
}

static ag_pool_t *
setup_pool( fd_wksp_t * wksp ) {
  create_validators();
  ulong slot_max      = 1024UL;
  ulong validator_max = 64UL;
  ulong blockid_max   = 1024UL;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    ag_pool_align(),
                                    ag_pool_footprint( slot_max, validator_max, blockid_max ),
                                    42UL );
  FD_TEST( mem );
  ag_pool_t * pool = ag_pool_join( ag_pool_new( mem, slot_max, validator_max, blockid_max,
                                                0UL, g_info, NV, TEST_SHRED_VERSION, 42UL, 0UL, NULL ) );
  FD_TEST( pool );
  return pool;
}

static void
teardown_pool( ag_pool_t * pool ) {
  fd_wksp_free_laddr( ag_pool_delete( ag_pool_leave( pool ) ) );
}

/* The add_* helpers drain after every vote so the event channel cannot
   fill up over the long vote runs some tests drive; tests that assert on
   emitted events add their votes inline instead. */

static void
add_notar_votes( ag_pool_t *       pool,
                 ulong             slot,
                 fd_hash_t const * hash,
                 ulong             lo,
                 ulong             hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot, hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    ag_pool_drain_channels( pool );
  }
}

static void
add_notar_fallback_votes( ag_pool_t *       pool,
                          ulong             slot,
                          fd_hash_t const * hash,
                          ulong             lo,
                          ulong             hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote; ag_vote_new_notar_fallback( &vote, slot, hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    ag_pool_drain_channels( pool );
  }
}

static void
add_skip_votes( ag_pool_t * pool,
                ulong       slot,
                ulong       lo,
                ulong       hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote; ag_vote_new_skip( &vote, slot, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    ag_pool_drain_channels( pool );
  }
}

static void
add_final_votes( ag_pool_t * pool,
                 ulong       slot,
                 ulong       lo,
                 ulong       hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote; ag_vote_new_final( &vote, slot, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    ag_pool_drain_channels( pool );
  }
}

static void
fast_finalize( ag_pool_t *       pool,
               ulong             slot,
               fd_hash_t const * hash ) {
  ag_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_notar_vote_new( &nv[v], slot, hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_FAST_FINAL;
  FD_TEST( ag_fast_final_cert_try_new( &c.inner.fast_final, nv, NV, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
  ag_pool_drain_channels( pool );
}

static void
test_handle_invalid_votes( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  fd_hash_t gh = genesis_hash();
  ag_vote_t vote; ag_vote_new_notar( &vote, 0UL, &gh, &g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );

  teardown_pool( pool );
}

static void
test_notarize_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  FD_TEST( !ag_pool_has_notar_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  ag_pool_has_notar_cert( pool, 0UL ) );

  FD_TEST( !ag_pool_has_notar_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 7UL );
  FD_TEST(  ag_pool_has_notar_cert( pool, 1UL ) );

  FD_TEST( !ag_pool_has_notar_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 6UL );
  FD_TEST( !ag_pool_has_notar_cert( pool, 2UL ) );

  teardown_pool( pool );
}

static void
test_skip_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  FD_TEST( !ag_pool_has_skip_cert( pool, 0UL ) );
  add_skip_votes( pool, 0UL, 0UL, 11UL );
  FD_TEST(  ag_pool_has_skip_cert( pool, 0UL ) );

  FD_TEST( !ag_pool_has_skip_cert( pool, 1UL ) );
  add_skip_votes( pool, 1UL, 0UL, 7UL );
  FD_TEST(  ag_pool_has_skip_cert( pool, 1UL ) );

  FD_TEST( !ag_pool_has_skip_cert( pool, 2UL ) );
  add_skip_votes( pool, 2UL, 0UL, 6UL );
  FD_TEST( !ag_pool_has_skip_cert( pool, 2UL ) );

  teardown_pool( pool );
}

static void
test_finalize_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  add_notar_votes( pool, slot1, &hash1, 0UL, 7UL );
  FD_TEST( !ag_pool_has_final_cert( pool, slot1 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==0UL );

  add_final_votes( pool, slot1, 0UL, 7UL );
  FD_TEST( ag_pool_has_final_cert( pool, slot1 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot1 );

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );
  FD_TEST( ag_pool_has_final_cert( pool, slot2 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot1 );

  fd_hash_t hash2 = random_hash();
  add_notar_votes( pool, slot2, &hash2, 0UL, 7UL );
  FD_TEST( ag_pool_has_final_cert( pool, slot2 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot2 );

  ulong slot3 = 3UL;
  fd_hash_t hash3 = random_hash();
  add_notar_votes( pool, slot3, &hash3, 0UL, 6UL );
  add_final_votes( pool, slot3, 0UL, 6UL );
  FD_TEST( !ag_pool_has_final_cert( pool, slot3 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot2 );

  teardown_pool( pool );
}

static void
test_fast_finalize_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  FD_TEST( !ag_pool_has_final_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  ag_pool_has_final_cert( pool, 0UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==0UL );

  FD_TEST( !ag_pool_has_final_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 9UL );
  FD_TEST(  ag_pool_has_final_cert( pool, 1UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==1UL );

  FD_TEST( !ag_pool_has_final_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 8UL );
  FD_TEST( !ag_pool_has_final_cert( pool, 2UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==1UL );

  teardown_pool( pool );
}

static void
test_simple_branch_certified( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  ag_block_id_t parent; parent.slot = slot; parent.hash = hashes[ next-1UL ];
  FD_TEST( ag_pool_is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

static void
test_branch_certified_notar_fallback( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) {
    ag_block_id_t parent; parent.slot = s; parent.hash = hashes[s];
    FD_TEST( !ag_pool_is_parent_ready( pool, s+1UL, &parent ) );
    add_notar_votes         ( pool, s, &hashes[s], 0UL, 4UL );
    add_notar_fallback_votes( pool, s, &hashes[s], 4UL, 7UL );
  }
  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  ag_block_id_t parent; parent.slot = slot; parent.hash = hashes[ next-1UL ];
  FD_TEST( ag_pool_is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

static void
test_branch_certified_out_of_order( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW;
  ulong cnt; ag_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==0UL );

  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  add_notar_votes( pool, slot1, &hash1, 0UL, 7UL );

  ag_block_id_t parent; parent.slot = slot1; parent.hash = hash1;
  FD_TEST( ag_pool_is_parent_ready( pool, next, &parent ) );
  ag_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

static void
test_branch_certified_late_cert( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW;
  ulong cnt; ag_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==0UL );

  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  ag_notar_vote_t nv[7];
  for( ulong v=0UL; v<7UL; v++ ) ag_notar_vote_new( &nv[v], slot1, &hash1, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_NOTAR;
  FD_TEST( ag_notar_cert_try_new( &c.inner.notar, nv, 7UL, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );

  ag_block_id_t parent; parent.slot = slot1; parent.hash = hash1;
  FD_TEST( ag_pool_is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

static void
test_regular_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-1UL; parent.hash = hashes[ SLOTS_PER_WINDOW-1UL ];
  FD_TEST( ag_pool_is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

static void
test_one_skip_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-1UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-2UL; parent.hash = hashes[ SLOTS_PER_WINDOW-2UL ];
  FD_TEST( ag_pool_is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

static void
test_two_skip_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-2UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-2UL, 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-3UL; parent.hash = hashes[ SLOTS_PER_WINDOW-3UL ];
  FD_TEST( ag_pool_is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

static void
test_skip_window_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  for( ulong s=SLOTS_PER_WINDOW; s<2UL*SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-1UL; parent.hash = hashes[ SLOTS_PER_WINDOW-1UL ];
  FD_TEST( ag_pool_is_parent_ready( pool, 2UL*SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

static void
test_pruning( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong total = 3UL*SLOTS_PER_WINDOW + 10UL;
  fd_hash_t hashes[ 3UL*SLOTS_PER_WINDOW + 10UL ];
  for( ulong s=0UL; s<total; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<3UL*SLOTS_PER_WINDOW; s++ ) {
    FD_TEST( !ag_pool_has_final_cert( pool, s ) );
    add_notar_votes( pool, s, &hashes[s], 0UL, 11UL );
    FD_TEST(  ag_pool_has_final_cert( pool, s ) );
  }
  ulong last_slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<last_slot; s++ ) FD_TEST( !ag_pool_contains_slot( pool, s ) );
  FD_TEST( ag_pool_contains_slot( pool, last_slot ) );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, &hashes[s], 0UL, 8UL );
    FD_TEST( !ag_pool_has_final_cert( pool, s ) );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<=10UL; s++ ) FD_TEST( ag_pool_contains_slot( pool, last_slot+s ) );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, &hashes[s], 8UL, 9UL );
    FD_TEST( ag_pool_has_final_cert( pool, s ) );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot+10UL );

  for( ulong s=0UL; s<10UL; s++ ) FD_TEST( !ag_pool_contains_slot( pool, last_slot+s ) );
  FD_TEST( ag_pool_contains_slot( pool, last_slot+10UL ) );

  teardown_pool( pool );
}

static void
test_duplicate_votes( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();
  ulong slot = 0UL;

  ag_vote_t v1; ag_vote_new_notar( &v1, slot, &gh, &g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v1 )==AG_POOL_SUCCESS );

  ag_vote_t v2; ag_vote_new_skip( &v2, slot, &g_sk[1], 1, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v2 )==AG_POOL_SUCCESS );

  FD_TEST( ag_pool_add_vote( pool, &v1 )==AG_ADD_VOTE_ERR_DUPLICATE );
  FD_TEST( ag_pool_add_vote( pool, &v2 )==AG_ADD_VOTE_ERR_DUPLICATE );

  teardown_pool( pool );
}

static void
test_duplicate_certs( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong first_slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_notar_vote_new( &nv[v], first_slot, &hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t notar; notar.kind = AG_CERT_TYPE_NOTAR;
  FD_TEST( ag_notar_cert_try_new( &notar.inner.notar, nv, NV, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &notar )==AG_POOL_SUCCESS );

  ulong second_slot = 2UL;
  ag_skip_vote_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], second_slot, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t skip; skip.kind = AG_CERT_TYPE_SKIP;
  FD_TEST( ag_skip_cert_try_new( &skip.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &skip )==AG_POOL_SUCCESS );

  FD_TEST( ag_pool_add_cert( pool, &notar )==AG_ADD_CERT_ERR_DUPLICATE );
  FD_TEST( ag_pool_add_cert( pool, &skip  )==AG_ADD_CERT_ERR_DUPLICATE );

  teardown_pool( pool );
}

static void
test_unknown_signer_votes( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();
  ulong slot = 0UL;

  ag_vote_t v1; ag_vote_new_notar( &v1, slot, &gh, &g_sk[0], (ushort)NV, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v1 )==AG_ADD_VOTE_ERR_UNKNOWN_SIGNER );

  ag_vote_t v2; ag_vote_new_skip( &v2, slot, &g_sk[0], USHORT_MAX, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v2 )==AG_ADD_VOTE_ERR_UNKNOWN_SIGNER );

  teardown_pool( pool );
}

static void
test_out_of_bounds_votes( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) add_notar_votes( pool, s, &gh, 0UL, 11UL );
  FD_TEST( ag_pool_finalized_slot( pool )==slot );
  FD_TEST( ag_pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    for( ulong v=0UL; v<11UL; v++ ) {
      ag_vote_t vote; ag_vote_new_final( &vote, s, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
      FD_TEST( ag_pool_add_vote( pool, &vote )==AG_ADD_VOTE_ERR_SLOT_OUT_OF_BOUNDS );
    }
  }

  ulong future = 5UL*SLOTS_PER_EPOCH;
  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote; ag_vote_new_final( &vote, future, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_ADD_VOTE_ERR_SLOT_OUT_OF_BOUNDS );
  }

  teardown_pool( pool );
}

static void
test_out_of_bounds_certs( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) {
    ag_notar_vote_t nv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) ag_notar_vote_new( &nv[v], s, &gh, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    ag_cert_t c; c.kind = AG_CERT_TYPE_FAST_FINAL;
    FD_TEST( ag_fast_final_cert_try_new( &c.inner.fast_final, nv, NV, g_info, NV )==AG_CERT_SUCCESS );
    FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
    ag_pool_drain_channels( pool );
  }
  FD_TEST( ag_pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    ag_skip_vote_t sv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], s, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    ag_cert_t c; c.kind = AG_CERT_TYPE_SKIP;
    FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==AG_CERT_SUCCESS );
    FD_TEST( ag_pool_add_cert( pool, &c )==AG_ADD_CERT_ERR_SLOT_OUT_OF_BOUNDS );
  }

  ulong future = 3UL*SLOTS_PER_EPOCH;
  ag_skip_vote_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], future, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_SKIP;
  FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_ADD_CERT_ERR_SLOT_OUT_OF_BOUNDS );

  teardown_pool( pool );
}

static void
test_slow_finalize_closing_gap( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong next_start     = SLOTS_PER_WINDOW;
  ulong gap_slot       = next_start - 1UL;
  ulong watermark_slot = gap_slot - 1UL;

  for( ulong s=1UL; s<gap_slot; s++ ) fast_finalize( pool, s, &gh );
  FD_TEST( ag_pool_first_unpruned_slot( pool )==watermark_slot );

  fd_hash_t gap_hash = random_hash();
  add_final_votes( pool, gap_slot, 0UL, 7UL );
  FD_TEST( ag_pool_has_final_cert( pool, gap_slot ) );
  FD_TEST( ag_pool_first_unpruned_slot( pool )==watermark_slot );

  fast_finalize( pool, next_start, &gh );
  FD_TEST( ag_pool_finalized_slot( pool )==next_start );
  FD_TEST( ag_pool_first_unpruned_slot( pool )==watermark_slot );

  add_notar_votes( pool, gap_slot, &gap_hash, 0UL, 7UL );
  FD_TEST( ag_pool_first_unpruned_slot( pool )==next_start );

  ulong cnt; ag_pool_parents_ready( pool, next_start, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

static void
test_standstill_recovery( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  add_notar_votes( pool, slot1, &hash1, 0UL, 11UL );

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );

  ulong slot3 = 3UL;
  fd_hash_t hash3 = random_hash();
  add_notar_votes( pool, slot3, &hash3, 0UL, 1UL );

  /* the add_* helpers drained, so the channel holds only what recovery emits */
  ag_cert_t certs[ 16 ]; ulong certs_cnt = 0UL;
  ag_vote_t votes[ 16 ]; ulong votes_cnt = 0UL;
  ag_pool_recover_from_standstill( pool, certs, &certs_cnt, 16UL, votes, &votes_cnt, 16UL );

  int found_standstill = 0;
  ulong ss_slot = 0UL;
  for( ulong i=0UL; i<event_cnt( pool ); i++ ) {
    if( event( pool, i )->kind==AG_POOL_EVENT_STANDSTILL ) { found_standstill = 1; ss_slot = event( pool, i )->inner.standstill; }
  }
  FD_TEST( found_standstill );
  FD_TEST( ss_slot==slot2 );

  FD_TEST( certs_cnt==2UL );
  for( ulong i=0UL; i<certs_cnt; i++ ) {
    if( certs[i].kind==AG_CERT_TYPE_FAST_FINAL )  FD_TEST( ag_cert_slot( &certs[i] )==slot1 );
    else if( certs[i].kind==AG_CERT_TYPE_FINAL )  FD_TEST( ag_cert_slot( &certs[i] )==slot2 );
    else FD_TEST( 0 );
  }

  FD_TEST( votes_cnt==2UL );
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    FD_TEST( ag_vote_signer( &votes[i] )==0UL );
    if( votes[i].kind==AG_VOTE_TYPE_FINAL )      FD_TEST( ag_vote_slot( &votes[i] )==slot2 );
    else if( votes[i].kind==AG_VOTE_TYPE_NOTAR ) FD_TEST( ag_vote_slot( &votes[i] )==slot3 );
    else FD_TEST( 0 );
  }

  /* every cert in the bundle round-trips through the V1 wire encoding */
  for( ulong i=0UL; i<certs_cnt; i++ ) {
    uchar buf[ AG_CERT_SERIALIZED_MAX ];
    ulong sz = ag_cert_serialize( &certs[i], buf, sizeof(buf), TEST_SHRED_VERSION );
    FD_TEST( sz );
    ag_cert_t rt; ulong consumed;
    FD_TEST( ag_cert_de( &rt, (uint)buf[1]-7U, buf+2UL, sz-2UL, &consumed )==AG_CERT_DE_SUCCESS );
    FD_TEST( consumed+2UL+2UL==sz );
    FD_TEST( rt.kind==certs[i].kind );
    FD_TEST( ag_cert_slot( &rt )==ag_cert_slot( &certs[i] ) );
  }

  teardown_pool( pool );
}

static void
test_parent_ready_upon_finalization( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong slot1 = SLOTS_PER_WINDOW;
  ag_block_id_t block0 = random_block_id( slot1-1UL );
  ag_block_id_t block1 = random_block_id( slot1 );
  ag_block_id_t block2 = random_block_id( slot1+1UL );

  ag_pool_drain_channels( pool );

  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, block2.slot, &block2.hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  ulong cert_created = 0UL, parent_ready_cnt = 0UL;
  for( ulong i=0UL; i<event_cnt( pool ); i++ ) {
    if( event( pool, i )->kind==AG_POOL_EVENT_CERT_CREATED ) cert_created++;
    if( event( pool, i )->kind==AG_POOL_EVENT_PARENT_READY ) parent_ready_cnt++;
  }
  FD_TEST( cert_created==3UL );
  FD_TEST( parent_ready_cnt==0UL );

  ag_pool_drain_channels( pool );
  ag_pool_add_block( pool, &block2, &block1 );
  ag_pool_add_block( pool, &block1, &block0 );

  int found = 0;
  for( ulong i=0UL; i<event_cnt( pool ); i++ ) {
    if( event( pool, i )->kind==AG_POOL_EVENT_PARENT_READY ) {
      FD_TEST( event( pool, i )->inner.parent_ready.slot==slot1 );
      FD_TEST( ag_block_id_eq( &event( pool, i )->inner.parent_ready.parent, &block0 ) );
      found = 1;
    }
  }
  FD_TEST( found );

  teardown_pool( pool );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* normal pages, like the sibling pool/votor tests: the suite must run
     without reserved huge pages */
  ulong  page_cnt  = 65536;
  char * _page_sz  = "normal";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_handle_invalid_votes          ( wksp );
  test_notarize_block                ( wksp );
  test_skip_block                    ( wksp );
  test_finalize_block                ( wksp );
  test_fast_finalize_block           ( wksp );
  test_simple_branch_certified       ( wksp );
  test_branch_certified_notar_fallback( wksp );
  test_branch_certified_out_of_order ( wksp );
  test_branch_certified_late_cert    ( wksp );
  test_regular_handover              ( wksp );
  test_one_skip_handover             ( wksp );
  test_two_skip_handover             ( wksp );
  test_skip_window_handover          ( wksp );
  test_pruning                       ( wksp );
  test_duplicate_votes               ( wksp );
  test_duplicate_certs               ( wksp );
  test_unknown_signer_votes          ( wksp );
  test_out_of_bounds_votes           ( wksp );
  test_out_of_bounds_certs           ( wksp );
  test_slow_finalize_closing_gap     ( wksp );
  test_standstill_recovery           ( wksp );
  test_parent_ready_upon_finalization( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
