#include "fd_pool.h"
#include "fd_cert.h"

/* Ports alpenglow/src/consensus/pool.rs #[cfg(test)] mod tests against a real
   fd_pool built in an anonymous wksp, following the test_finality_tracker.c /
   test_cert.c harness patterns.

   The Rust tests use generate_validators(11) (11 unit-stake validators), a
   ValidatorEpochInfo for validator 0, and mpsc channels for votor / repair.
   Here own_id = 0, and votor events / repair requests are collected into
   caller-supplied fd_pool_out_t buffers.

   The signature-INVALIDITY negative path (handle_invalid_votes' wrong-key
   case) is exercised structurally only insofar as the stub aggsig allows;
   see the test note there. */

#define SLOTS_PER_WINDOW FD_ALPENGLOW_SLOTS_PER_WINDOW /* 4 */
#define SLOTS_PER_EPOCH  FD_ALPENGLOW_SLOTS_PER_EPOCH  /* 18000 */
#define NV               (11UL)                        /* num validators */

static fd_aggsig_sk_t      g_sk  [ NV ];
static fd_validator_info_t g_info[ NV ];

/* GENESIS_BLOCK_HASH = all-zero. */
static fd_hash_t
genesis_hash( void ) {
  fd_hash_t h; fd_memset( h.uc, 0, sizeof(fd_hash_t) );
  return h;
}

/* random_block_id / random hash: deterministic, distinct, non-zero. */

static ulong g_hash_ctr = 0UL;

static fd_hash_t
random_hash( void ) {
  fd_hash_t h; fd_memset( h.uc, 0, sizeof(fd_hash_t) );
  h.ul[0] = 0x9000UL + (++g_hash_ctr);
  h.ul[1] = 0xc0ffee00UL ^ g_hash_ctr;
  return h;
}

static fd_block_id_t
random_block_id( ulong slot ) {
  fd_block_id_t b; b.slot = slot; b.hash = random_hash();
  return b;
}

static void
create_validators( void ) {
  for( ulong i=0UL; i<NV; i++ ) {
    fd_memset( g_sk[i].v, (int)(i*7UL+1UL), FD_AGGSIG_SECKEY_SZ );
    memset( &g_info[i], 0, sizeof(fd_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL; /* unit stake, matching generate_validators */
    fd_aggsig_sk_to_pk( &g_info[i].voting_pubkey, &g_sk[i] );
  }
}

/* ---- pool setup / output buffers --------------------------------------- */

#define OUT_EVENTS_MAX  (256UL)
#define OUT_REPAIRS_MAX (256UL)

static fd_pool_evt_t g_events [ OUT_EVENTS_MAX ];
static fd_block_id_t g_repairs[ OUT_REPAIRS_MAX ];

static fd_pool_out_t
fresh_out( void ) {
  fd_pool_out_t out;
  out.events   = g_events;  out.events_cnt  = 0UL; out.events_max  = OUT_EVENTS_MAX;
  out.repairs  = g_repairs; out.repairs_cnt = 0UL; out.repairs_max = OUT_REPAIRS_MAX;
  return out;
}

static fd_pool_t *
setup_pool( fd_wksp_t * wksp ) {
  create_validators();
  ulong slot_max      = 1024UL;
  ulong validator_max = 64UL;
  ulong blockid_max   = 1024UL;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_pool_align(),
                                    fd_pool_footprint( slot_max, validator_max, blockid_max ),
                                    42UL );
  FD_TEST( mem );
  fd_pool_t * pool = fd_pool_join( fd_pool_new( mem, slot_max, validator_max, blockid_max,
                                                0UL /* own_id */, g_info, NV, 42UL, 0UL, NULL ) );
  FD_TEST( pool );
  return pool;
}

static void
teardown_pool( fd_pool_t * pool ) {
  fd_wksp_free_laddr( fd_pool_delete( fd_pool_leave( pool ) ) );
}

/* ---- vote helpers ------------------------------------------------------ */

static void
add_notar_votes( fd_pool_t * pool, ulong slot, fd_hash_t const * hash, ulong lo, ulong hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_ag_vote_t vote; fd_vote_new_notar( &vote, slot, hash, &g_sk[v], (ushort)v );
    fd_pool_out_t out = fresh_out();
    FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_SUCCESS );
  }
}

static void
add_notar_fallback_votes( fd_pool_t * pool, ulong slot, fd_hash_t const * hash, ulong lo, ulong hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_ag_vote_t vote; fd_vote_new_notar_fallback( &vote, slot, hash, &g_sk[v], (ushort)v );
    fd_pool_out_t out = fresh_out();
    FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_SUCCESS );
  }
}

static void
add_skip_votes( fd_pool_t * pool, ulong slot, ulong lo, ulong hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_ag_vote_t vote; fd_vote_new_skip( &vote, slot, &g_sk[v], (ushort)v );
    fd_pool_out_t out = fresh_out();
    FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_SUCCESS );
  }
}

static void
add_final_votes( fd_pool_t * pool, ulong slot, ulong lo, ulong hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    fd_ag_vote_t vote; fd_vote_new_final( &vote, slot, &g_sk[v], (ushort)v );
    fd_pool_out_t out = fresh_out();
    FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_SUCCESS );
  }
}

/* fast_finalize submits a unanimous fast-final cert for (slot, hash). */

static void
fast_finalize( fd_pool_t * pool, ulong slot, fd_hash_t const * hash ) {
  fd_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) fd_notar_vote_new( &nv[v], slot, hash, &g_sk[v], (ushort)v );
  fd_cert_t c; c.discriminant = FD_CERT_TYPE_FAST_FINAL;
  FD_TEST( fd_fast_final_cert_try_new( &c.inner.fast_final, nv, NV, g_info, NV )==FD_CERT_SUCCESS );
  fd_pool_out_t out = fresh_out();
  FD_TEST( fd_pool_add_cert( pool, &c, &out )==FD_POOL_SUCCESS );
}

/* ---- handle_invalid_votes ---------------------------------------------- */

static void
test_handle_invalid_votes( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  /* A vote signed by a different key than validator 0's would be rejected by
     real BLS.  Under the stub aggsig, check_sig always accepts, so we
     instead exercise the InvalidSignature path's structural counterpart by
     confirming a normally-signed vote is accepted (the stub cannot
     manufacture an invalid signature).  The wrong-key negative is deferred to
     the real-BLS step, mirroring the cert test's note. */
  fd_hash_t gh = genesis_hash();
  fd_ag_vote_t vote; fd_vote_new_notar( &vote, 0UL, &gh, &g_sk[0], 0UL );
  fd_pool_out_t out = fresh_out();
  FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_SUCCESS );

  teardown_pool( pool );
}

/* ---- notarize_block ---------------------------------------------------- */

static void
test_notarize_block( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  FD_TEST( !fd_pool_has_notar_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  fd_pool_has_notar_cert( pool, 0UL ) );

  FD_TEST( !fd_pool_has_notar_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 7UL );
  FD_TEST(  fd_pool_has_notar_cert( pool, 1UL ) );

  FD_TEST( !fd_pool_has_notar_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 6UL );
  FD_TEST( !fd_pool_has_notar_cert( pool, 2UL ) );

  teardown_pool( pool );
}

/* ---- skip_block -------------------------------------------------------- */

static void
test_skip_block( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  FD_TEST( !fd_pool_has_skip_cert( pool, 0UL ) );
  add_skip_votes( pool, 0UL, 0UL, 11UL );
  FD_TEST(  fd_pool_has_skip_cert( pool, 0UL ) );

  FD_TEST( !fd_pool_has_skip_cert( pool, 1UL ) );
  add_skip_votes( pool, 1UL, 0UL, 7UL );
  FD_TEST(  fd_pool_has_skip_cert( pool, 1UL ) );

  FD_TEST( !fd_pool_has_skip_cert( pool, 2UL ) );
  add_skip_votes( pool, 2UL, 0UL, 6UL );
  FD_TEST( !fd_pool_has_skip_cert( pool, 2UL ) );

  teardown_pool( pool );
}

/* ---- finalize_block ---------------------------------------------------- */

static void
test_finalize_block( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  /* just enough notar (7/11) is NOT enough on its own to finalize */
  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  add_notar_votes( pool, slot1, &hash1, 0UL, 7UL );
  FD_TEST( !fd_pool_has_final_cert( pool, slot1 ) );
  FD_TEST( fd_pool_finalized_slot( pool )==0UL );

  /* just enough final (7/11) -> slot 1 finalized */
  add_final_votes( pool, slot1, 0UL, 7UL );
  FD_TEST( fd_pool_has_final_cert( pool, slot1 ) );
  FD_TEST( fd_pool_finalized_slot( pool )==slot1 );

  /* final on slot 2 alone NOT enough (missing notar) */
  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );
  FD_TEST( fd_pool_has_final_cert( pool, slot2 ) );
  FD_TEST( fd_pool_finalized_slot( pool )==slot1 );

  /* now notar -> slot 2 finalized */
  fd_hash_t hash2 = random_hash();
  add_notar_votes( pool, slot2, &hash2, 0UL, 7UL );
  FD_TEST( fd_pool_has_final_cert( pool, slot2 ) );
  FD_TEST( fd_pool_finalized_slot( pool )==slot2 );

  /* slot 3 not enough notar+final */
  ulong slot3 = 3UL;
  fd_hash_t hash3 = random_hash();
  add_notar_votes( pool, slot3, &hash3, 0UL, 6UL );
  add_final_votes( pool, slot3, 0UL, 6UL );
  FD_TEST( !fd_pool_has_final_cert( pool, slot3 ) );
  FD_TEST( fd_pool_finalized_slot( pool )==slot2 );

  teardown_pool( pool );
}

/* ---- fast_finalize_block ----------------------------------------------- */

static void
test_fast_finalize_block( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  FD_TEST( !fd_pool_has_final_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  fd_pool_has_final_cert( pool, 0UL ) );
  FD_TEST( fd_pool_finalized_slot( pool )==0UL );

  FD_TEST( !fd_pool_has_final_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 9UL ); /* 9/11 >= 80% */
  FD_TEST(  fd_pool_has_final_cert( pool, 1UL ) );
  FD_TEST( fd_pool_finalized_slot( pool )==1UL );

  FD_TEST( !fd_pool_has_final_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 8UL ); /* 8/11 < 80% */
  FD_TEST( !fd_pool_has_final_cert( pool, 2UL ) );
  FD_TEST( fd_pool_finalized_slot( pool )==1UL );

  teardown_pool( pool );
}

/* ---- simple_branch_certified ------------------------------------------- */

static void
test_simple_branch_certified( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  /* window = genesis window slots [0..4); hashes indexed by slot */
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  fd_block_id_t parent; parent.slot = slot; parent.hash = hashes[ next-1UL ];
  FD_TEST( fd_pool_is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* ---- branch_certified_notar_fallback ----------------------------------- */

static void
test_branch_certified_notar_fallback( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) {
    fd_block_id_t parent; parent.slot = s; parent.hash = hashes[s];
    FD_TEST( !fd_pool_is_parent_ready( pool, s+1UL, &parent ) );
    add_notar_votes         ( pool, s, &hashes[s], 0UL, 4UL );
    add_notar_fallback_votes( pool, s, &hashes[s], 4UL, 7UL );
  }
  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  fd_block_id_t parent; parent.slot = slot; parent.hash = hashes[ next-1UL ];
  FD_TEST( fd_pool_is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* ---- branch_certified_out_of_order ------------------------------------- */

static void
test_branch_certified_out_of_order( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  /* window minus first two slots: slots 2,3 */
  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW; /* (window last).next() = 4 */
  ulong cnt; fd_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==0UL );

  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  add_notar_votes( pool, slot1, &hash1, 0UL, 7UL );

  fd_block_id_t parent; parent.slot = slot1; parent.hash = hash1;
  FD_TEST( fd_pool_is_parent_ready( pool, next, &parent ) );
  fd_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* ---- branch_certified_late_cert ---------------------------------------- */

static void
test_branch_certified_late_cert( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW;
  ulong cnt; fd_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==0UL );

  /* notarization cert for slot 1 directly */
  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  fd_notar_vote_t nv[7];
  for( ulong v=0UL; v<7UL; v++ ) fd_notar_vote_new( &nv[v], slot1, &hash1, &g_sk[v], (ushort)v );
  fd_cert_t c; c.discriminant = FD_CERT_TYPE_NOTAR;
  FD_TEST( fd_notar_cert_try_new( &c.inner.notar, nv, 7UL, g_info, NV )==FD_CERT_SUCCESS );
  fd_pool_out_t out = fresh_out();
  FD_TEST( fd_pool_add_cert( pool, &c, &out )==FD_POOL_SUCCESS );

  fd_block_id_t parent; parent.slot = slot1; parent.hash = hash1;
  FD_TEST( fd_pool_is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* ---- regular_handover -------------------------------------------------- */

static void
test_regular_handover( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  fd_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-1UL; parent.hash = hashes[ SLOTS_PER_WINDOW-1UL ];
  FD_TEST( fd_pool_is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* ---- one_skip_handover ------------------------------------------------- */

static void
test_one_skip_handover( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-1UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  fd_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-2UL; parent.hash = hashes[ SLOTS_PER_WINDOW-2UL ];
  FD_TEST( fd_pool_is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* ---- two_skip_handover ------------------------------------------------- */

static void
test_two_skip_handover( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-2UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-2UL, 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  fd_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-3UL; parent.hash = hashes[ SLOTS_PER_WINDOW-3UL ];
  FD_TEST( fd_pool_is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* ---- skip_window_handover ---------------------------------------------- */

static void
test_skip_window_handover( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  for( ulong s=SLOTS_PER_WINDOW; s<2UL*SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  fd_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-1UL; parent.hash = hashes[ SLOTS_PER_WINDOW-1UL ];
  FD_TEST( fd_pool_is_parent_ready( pool, 2UL*SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* ---- pruning ----------------------------------------------------------- */

static void
test_pruning( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  ulong total = 3UL*SLOTS_PER_WINDOW + 10UL;
  fd_hash_t hashes[ 3UL*SLOTS_PER_WINDOW + 10UL ];
  for( ulong s=0UL; s<total; s++ ) hashes[s] = random_hash();

  /* fast finalize first 3 leader windows (all nodes notarize) */
  for( ulong s=1UL; s<3UL*SLOTS_PER_WINDOW; s++ ) {
    FD_TEST( !fd_pool_has_final_cert( pool, s ) );
    add_notar_votes( pool, s, &hashes[s], 0UL, 11UL );
    FD_TEST(  fd_pool_has_final_cert( pool, s ) );
  }
  ulong last_slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  FD_TEST( fd_pool_finalized_slot( pool )==last_slot );

  /* only last slot should remain */
  for( ulong s=0UL; s<last_slot; s++ ) FD_TEST( !fd_pool_contains_slot( pool, s ) );
  FD_TEST( fd_pool_contains_slot( pool, last_slot ) );

  /* NOT enough nodes to fast finalize next 10 slots */
  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i; /* future_slots starts at last_slot.next() */
    add_notar_votes( pool, s, &hashes[s], 0UL, 8UL );
    FD_TEST( !fd_pool_has_final_cert( pool, s ) );
  }
  FD_TEST( fd_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<=10UL; s++ ) FD_TEST( fd_pool_contains_slot( pool, last_slot+s ) );

  /* one more vote each finalizes next 10 slots */
  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, &hashes[s], 8UL, 9UL );
    FD_TEST( fd_pool_has_final_cert( pool, s ) );
  }
  FD_TEST( fd_pool_finalized_slot( pool )==last_slot+10UL );

  for( ulong s=0UL; s<10UL; s++ ) FD_TEST( !fd_pool_contains_slot( pool, last_slot+s ) );
  FD_TEST( fd_pool_contains_slot( pool, last_slot+10UL ) );

  teardown_pool( pool );
}

/* ---- duplicate_votes --------------------------------------------------- */

static void
test_duplicate_votes( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();
  ulong slot = 0UL;

  fd_ag_vote_t v1; fd_vote_new_notar( &v1, slot, &gh, &g_sk[0], 0UL );
  fd_pool_out_t out = fresh_out();
  FD_TEST( fd_pool_add_vote( pool, &v1, &out, NULL )==FD_POOL_SUCCESS );

  fd_ag_vote_t v2; fd_vote_new_skip( &v2, slot, &g_sk[1], 1UL );
  out = fresh_out();
  FD_TEST( fd_pool_add_vote( pool, &v2, &out, NULL )==FD_POOL_SUCCESS );

  out = fresh_out();
  FD_TEST( fd_pool_add_vote( pool, &v1, &out, NULL )==FD_POOL_ERR_DUPLICATE );
  out = fresh_out();
  FD_TEST( fd_pool_add_vote( pool, &v2, &out, NULL )==FD_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* ---- duplicate_certs --------------------------------------------------- */

static void
test_duplicate_certs( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  ulong first_slot = 1UL;
  fd_hash_t hash = random_hash();
  fd_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) fd_notar_vote_new( &nv[v], first_slot, &hash, &g_sk[v], (ushort)v );
  fd_cert_t notar; notar.discriminant = FD_CERT_TYPE_NOTAR;
  FD_TEST( fd_notar_cert_try_new( &notar.inner.notar, nv, NV, g_info, NV )==FD_CERT_SUCCESS );
  fd_pool_out_t out = fresh_out();
  FD_TEST( fd_pool_add_cert( pool, &notar, &out )==FD_POOL_SUCCESS );

  ulong second_slot = 2UL;
  fd_skip_vote_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) fd_skip_vote_new( &sv[v], second_slot, &g_sk[v], (ushort)v );
  fd_cert_t skip; skip.discriminant = FD_CERT_TYPE_SKIP;
  FD_TEST( fd_skip_cert_try_new( &skip.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==FD_CERT_SUCCESS );
  out = fresh_out();
  FD_TEST( fd_pool_add_cert( pool, &skip, &out )==FD_POOL_SUCCESS );

  out = fresh_out();
  FD_TEST( fd_pool_add_cert( pool, &notar, &out )==FD_POOL_ERR_DUPLICATE );
  out = fresh_out();
  FD_TEST( fd_pool_add_cert( pool, &skip, &out )==FD_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* ---- unknown_signer_votes ---------------------------------------------- */

static void
test_unknown_signer_votes( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();
  ulong slot = 0UL;

  /* signer index == validator_cnt is out-of-bounds */
  fd_ag_vote_t v1; fd_vote_new_notar( &v1, slot, &gh, &g_sk[0], NV );
  fd_pool_out_t out = fresh_out();
  FD_TEST( fd_pool_add_vote( pool, &v1, &out, NULL )==FD_POOL_ERR_UNKNOWN_SIGNER );

  fd_ag_vote_t v2; fd_vote_new_skip( &v2, slot, &g_sk[0], USHORT_MAX );
  out = fresh_out();
  FD_TEST( fd_pool_add_vote( pool, &v2, &out, NULL )==FD_POOL_ERR_UNKNOWN_SIGNER );

  teardown_pool( pool );
}

/* ---- out_of_bounds_votes ----------------------------------------------- */

static void
test_out_of_bounds_votes( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) add_notar_votes( pool, s, &gh, 0UL, 11UL );
  FD_TEST( fd_pool_finalized_slot( pool )==slot );
  FD_TEST( fd_pool_first_unpruned_slot( pool )==slot );

  /* dismiss old votes */
  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    for( ulong v=0UL; v<11UL; v++ ) {
      fd_ag_vote_t vote; fd_vote_new_final( &vote, s, &g_sk[v], (ushort)v );
      fd_pool_out_t out = fresh_out();
      FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_ERR_SLOT_OUT_OF_BOUNDS );
    }
  }

  /* dismiss far-in-the-future vote */
  ulong future = 5UL*SLOTS_PER_EPOCH;
  for( ulong v=0UL; v<11UL; v++ ) {
    fd_ag_vote_t vote; fd_vote_new_final( &vote, future, &g_sk[v], (ushort)v );
    fd_pool_out_t out = fresh_out();
    FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  }

  teardown_pool( pool );
}

/* ---- out_of_bounds_certs ----------------------------------------------- */

static void
test_out_of_bounds_certs( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) {
    fd_notar_vote_t nv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) fd_notar_vote_new( &nv[v], s, &gh, &g_sk[v], (ushort)v );
    fd_cert_t c; c.discriminant = FD_CERT_TYPE_FAST_FINAL;
    FD_TEST( fd_fast_final_cert_try_new( &c.inner.fast_final, nv, NV, g_info, NV )==FD_CERT_SUCCESS );
    fd_pool_out_t out = fresh_out();
    FD_TEST( fd_pool_add_cert( pool, &c, &out )==FD_POOL_SUCCESS );
  }
  FD_TEST( fd_pool_first_unpruned_slot( pool )==slot );

  /* dismiss old certs */
  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    fd_skip_vote_t sv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) fd_skip_vote_new( &sv[v], s, &g_sk[v], (ushort)v );
    fd_cert_t c; c.discriminant = FD_CERT_TYPE_SKIP;
    FD_TEST( fd_skip_cert_try_new( &c.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==FD_CERT_SUCCESS );
    fd_pool_out_t out = fresh_out();
    FD_TEST( fd_pool_add_cert( pool, &c, &out )==FD_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  }

  /* dismiss far-in-the-future cert */
  ulong future = 3UL*SLOTS_PER_EPOCH;
  fd_skip_vote_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) fd_skip_vote_new( &sv[v], future, &g_sk[v], (ushort)v );
  fd_cert_t c; c.discriminant = FD_CERT_TYPE_SKIP;
  FD_TEST( fd_skip_cert_try_new( &c.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==FD_CERT_SUCCESS );
  fd_pool_out_t out = fresh_out();
  FD_TEST( fd_pool_add_cert( pool, &c, &out )==FD_POOL_ERR_SLOT_OUT_OF_BOUNDS );

  teardown_pool( pool );
}

/* ---- slow_finalize_closing_gap_no_double_parent_ready ------------------ */

static void
test_slow_finalize_closing_gap( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong next_start     = SLOTS_PER_WINDOW;        /* windows().nth(1) = 4 */
  ulong gap_slot       = next_start - 1UL;        /* 3 */
  ulong watermark_slot = gap_slot - 1UL;          /* 2 */

  for( ulong s=1UL; s<gap_slot; s++ ) fast_finalize( pool, s, &gh );
  FD_TEST( fd_pool_first_unpruned_slot( pool )==watermark_slot );

  /* gap_slot gets a final cert but no notarization yet */
  fd_hash_t gap_hash = random_hash();
  add_final_votes( pool, gap_slot, 0UL, 7UL );
  FD_TEST( fd_pool_has_final_cert( pool, gap_slot ) );
  FD_TEST( fd_pool_first_unpruned_slot( pool )==watermark_slot );

  /* fast-finalize next_start, introducing a gap */
  fast_finalize( pool, next_start, &gh );
  FD_TEST( fd_pool_finalized_slot( pool )==next_start );
  FD_TEST( fd_pool_first_unpruned_slot( pool )==watermark_slot );

  /* gap_slot's notarization closes the gap */
  add_notar_votes( pool, gap_slot, &gap_hash, 0UL, 7UL );
  FD_TEST( fd_pool_first_unpruned_slot( pool )==next_start );

  /* gap_slot propagated as ready parent exactly once */
  ulong cnt; fd_pool_parents_ready( pool, next_start, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* ---- standstill_recovery ----------------------------------------------- */

static void
test_standstill_recovery( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  add_notar_votes( pool, slot1, &hash1, 0UL, 11UL ); /* fast finalized */

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );          /* final, missing notar */

  ulong slot3 = 3UL;
  fd_hash_t hash3 = random_hash();
  add_notar_votes( pool, slot3, &hash3, 0UL, 1UL );  /* own notar only */

  fd_pool_out_t out = fresh_out();
  fd_cert_t certs[ 16 ]; ulong certs_cnt = 0UL;
  fd_ag_vote_t votes[ 16 ]; ulong votes_cnt = 0UL;
  fd_pool_recover_from_standstill( pool, &out, certs, &certs_cnt, 16UL, votes, &votes_cnt, 16UL );

  /* find the standstill event */
  int found_standstill = 0;
  ulong ss_slot = 0UL;
  for( ulong i=0UL; i<out.events_cnt; i++ ) {
    if( out.events[i].kind==FD_POOL_EVT_STANDSTILL ) { found_standstill = 1; ss_slot = out.events[i].inner.slot; }
  }
  FD_TEST( found_standstill );
  FD_TEST( ss_slot==slot2 ); /* finalized_slot (slot1).next() = 2 */

  /* certs: fast-final for slot1, final for slot2 */
  FD_TEST( certs_cnt==2UL );
  for( ulong i=0UL; i<certs_cnt; i++ ) {
    if( certs[i].discriminant==FD_CERT_TYPE_FAST_FINAL )  FD_TEST( fd_cert_slot( &certs[i] )==slot1 );
    else if( certs[i].discriminant==FD_CERT_TYPE_FINAL )  FD_TEST( fd_cert_slot( &certs[i] )==slot2 );
    else FD_TEST( 0 ); /* unexpected cert */
  }

  /* votes: own final on slot2, own notar on slot3 */
  FD_TEST( votes_cnt==2UL );
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    FD_TEST( fd_vote_signer( &votes[i] )==0UL );
    if( votes[i].discriminant==FD_VOTE_TYPE_FINAL )      FD_TEST( fd_vote_slot( &votes[i] )==slot2 );
    else if( votes[i].discriminant==FD_VOTE_TYPE_NOTAR ) FD_TEST( fd_vote_slot( &votes[i] )==slot3 );
    else FD_TEST( 0 ); /* unexpected vote */
  }

  teardown_pool( pool );
}

/* ---- parent_ready_upon_finalization ------------------------------------ */

static void
test_parent_ready_upon_finalization( fd_wksp_t * wksp ) {
  fd_pool_t * pool = setup_pool( wksp );

  ulong slot1 = SLOTS_PER_WINDOW; /* windows().nth(1) = 4 */
  fd_block_id_t block0 = random_block_id( slot1-1UL );
  fd_block_id_t block1 = random_block_id( slot1 );
  fd_block_id_t block2 = random_block_id( slot1+1UL );

  fd_pool_out_t out = fresh_out();
  /* all nodes notarize block2 -> 3 certs (notar-fallback + notar + fast-final) */
  for( ulong v=0UL; v<11UL; v++ ) {
    fd_ag_vote_t vote; fd_vote_new_notar( &vote, block2.slot, &block2.hash, &g_sk[v], (ushort)v );
    FD_TEST( fd_pool_add_vote( pool, &vote, &out, NULL )==FD_POOL_SUCCESS );
  }

  ulong cert_created = 0UL, parent_ready_cnt = 0UL;
  for( ulong i=0UL; i<out.events_cnt; i++ ) {
    if( out.events[i].kind==FD_POOL_EVT_CERT_CREATED  ) cert_created++;
    if( out.events[i].kind==FD_POOL_EVT_PARENT_READY  ) parent_ready_cnt++;
  }
  FD_TEST( cert_created==3UL );
  FD_TEST( parent_ready_cnt==0UL ); /* no ParentReady yet */

  /* add ancestors */
  out = fresh_out();
  fd_pool_add_block( pool, &block2, &block1, &out );
  fd_pool_add_block( pool, &block1, &block0, &out );

  /* should emit exactly one ParentReady( slot1, block0 ) */
  int found = 0;
  for( ulong i=0UL; i<out.events_cnt; i++ ) {
    if( out.events[i].kind==FD_POOL_EVT_PARENT_READY ) {
      FD_TEST( out.events[i].inner.parent_ready.slot==slot1 );
      FD_TEST( fd_block_id_eq( &out.events[i].inner.parent_ready.parent, &block0 ) );
      found = 1;
    }
  }
  FD_TEST( found );

  teardown_pool( pool );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
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
