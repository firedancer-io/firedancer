#include "ag_pool.c"
#include "ag_cert_serde.h"

static int
has_notar_cert( ag_pool_t const * pool,
                ulong             slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && e->slot_state.certificates.notar.slot!=ULONG_MAX;
}

static int
has_skip_cert( ag_pool_t const * pool,
               ulong             slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && e->slot_state.certificates.skip.slot!=ULONG_MAX;
}

static int
has_final_cert( ag_pool_t const * pool,
                ulong             slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && ( e->slot_state.certificates.fast_finalize.slot!=ULONG_MAX ||
                e->slot_state.certificates.finalize.slot     !=ULONG_MAX );
}

static int
contains_slot( ag_pool_t const * pool,
               ulong             slot ) {
  return slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool )!=NULL;
}

static ag_epoch_info_t const *
epoch_info( ag_pool_t const * pool,
            ulong             slot ) {
  return fd_ptr_if( slot>=pool->next_epoch_slot, pool->next_epoch_info, pool->curr_epoch_info );
}

static ulong
pool_first_unpruned_slot( ag_pool_t const * pool ) {
  return ag_finality_tracker_first_unpruned_slot( pool->finality_tracker );
}

static ulong
min_live_slot( ag_pool_t const * pool ) {
  slot_state_map_t const * map = pool->slot_states->map;
  slot_state_ele_t const * ele = pool->slot_states->pool;
  ulong min = ULONG_MAX;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, ele );
       !slot_state_map_iter_done( iter, map, ele );
       iter = slot_state_map_iter_next( iter, map, ele ) ) {
    min = fd_ulong_min( min, slot_state_map_iter_ele_const( iter, map, ele )->slot );
  }
  return min;
}

#define FD_TEST_PRUNED_TO_WATERMARK( pool ) \
  FD_TEST( min_live_slot( pool )>=pool_first_unpruned_slot( pool ) )

static int
is_parent_ready( ag_pool_t *           pool,
                 ulong                 slot,
                 ag_block_id_t const * parent ) {
  ulong                 cnt   = 0UL;
  ag_block_id_t const * ready = ag_pool_parents_ready( pool, slot, &cnt );
  for( ulong i=0UL; i<cnt; i++ ) if( ag_block_id_eq( &ready[i], parent ) ) return 1;
  return 0;
}

static int
votor_event_pop( ag_pool_t *       pool,
                 ag_event_pool_t * out ) {
  if( FD_UNLIKELY( pool_channel_empty( pool->pool_events ) ) ) return 0;
  *out = pool_channel_pop( pool->pool_events );
  return 1;
}

static void
drain_channels( ag_pool_t * pool ) {
  pool_channel_remove_all  ( pool->pool_events   );
  repair_channel_remove_all( pool->repair_events );
}

#define SLOTS_PER_WINDOW AG_SLOTS_PER_WINDOW
#define SLOTS_PER_EPOCH  AG_SLOTS_PER_EPOCH
#define NV               (11UL)

#define TEST_SLOT_MAX    (64UL)

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

static ag_event_pool_t g_event[ TEST_SLOT_MAX ];

static ulong
take_events( ag_pool_t * pool ) {
  ulong cnt = 0UL;
  while( cnt<TEST_SLOT_MAX && votor_event_pop( pool, &g_event[ cnt ] ) ) cnt++;
  FD_TEST( pool_channel_empty( pool->pool_events ) );
  return cnt;
}

static ag_event_pool_t const *
event( ulong i ) {
  return &g_event[ i ];
}

static ag_epoch_info_t *
make_epoch_info( fd_wksp_t *                 wksp,
                 ag_validator_info_t const * info,
                 ulong                       cnt ) {
  ag_epoch_info_t * ei = fd_wksp_alloc_laddr( wksp, alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t), 42UL );
  FD_TEST( ei );
  ag_epoch_info( ei, info, cnt );
  return ei;
}

static ag_epoch_info_t * g_epoch_info = NULL;

static ag_pool_t *
setup_pool( fd_wksp_t * wksp ) {
  create_validators();
  ulong slot_max      = TEST_SLOT_MAX;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    ag_pool_align(),
                                    ag_pool_footprint( slot_max ),
                                    42UL );
  FD_TEST( mem );
  ag_pool_t * pool = ag_pool_join( ag_pool_new( mem, slot_max, 42UL ) );
  FD_TEST( pool );

  g_epoch_info = make_epoch_info( wksp, g_info, NV );
  ag_pool_advance_epoch( pool, g_epoch_info, 0UL, 0UL );
  return pool;
}

static void
teardown_pool_only( ag_pool_t * pool ) {
  fd_wksp_free_laddr( ag_pool_delete( ag_pool_leave( pool ) ) );
}

static void
teardown_pool( ag_pool_t * pool ) {
  fd_wksp_free_laddr( ag_pool_delete( ag_pool_leave( pool ) ) );
  if( FD_LIKELY( g_epoch_info ) ) {
    fd_wksp_free_laddr( g_epoch_info );
    g_epoch_info = NULL;
  }
}

static void
add_notar_votes( ag_pool_t *       pool,
                 ulong             slot,
                 fd_hash_t const * hash,
                 ulong             lo,
                 ulong             hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot, hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    drain_channels( pool );
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
    drain_channels( pool );
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
    drain_channels( pool );
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
    drain_channels( pool );
  }
}

static void
notar_cert( ag_pool_t *       pool,
            ulong             slot,
            fd_hash_t const * hash,
            ulong             signers ) {
  FD_TEST( signers<=NV );
  ag_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<signers; v++ ) ag_notar_vote_new( &nv[v], slot, hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_NOTAR;
  c.inner.notar = ag_notar_cert_construct( nv, signers, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
  drain_channels( pool );
}

static int
drained_safe_to_notar( ag_pool_t *       pool,
                       ulong             slot,
                       fd_hash_t const * hash ) {
  ulong cnt = take_events( pool );
  for( ulong i=0UL; i<cnt; i++ ) {
    ag_event_pool_t const * e = event( i );
    if( e->kind!=AG_EVENT_POOL_SAFE_TO_NOTAR ) continue;
    if( e->safe_to_notar.slot==slot &&
        !memcmp( e->safe_to_notar.hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return 1;
  }
  return 0;
}

static void
fast_finalize( ag_pool_t *       pool,
               ulong             slot,
               fd_hash_t const * hash ) {
  ag_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_notar_vote_new( &nv[v], slot, hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_FAST_FINAL;
  c.inner.fast_final = ag_fast_final_cert_construct( nv, NV, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
  drain_channels( pool );
}

/* src/consensus/pool.rs::notarize_block */

static void
test_notarize_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  FD_TEST( !has_notar_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  has_notar_cert( pool, 0UL ) );

  FD_TEST( !has_notar_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 7UL );
  FD_TEST(  has_notar_cert( pool, 1UL ) );

  FD_TEST( !has_notar_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 6UL );
  FD_TEST( !has_notar_cert( pool, 2UL ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::skip_block */

static void
test_skip_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  FD_TEST( !has_skip_cert( pool, 0UL ) );
  add_skip_votes( pool, 0UL, 0UL, 11UL );
  FD_TEST(  has_skip_cert( pool, 0UL ) );

  FD_TEST( !has_skip_cert( pool, 1UL ) );
  add_skip_votes( pool, 1UL, 0UL, 7UL );
  FD_TEST(  has_skip_cert( pool, 1UL ) );

  FD_TEST( !has_skip_cert( pool, 2UL ) );
  add_skip_votes( pool, 2UL, 0UL, 6UL );
  FD_TEST( !has_skip_cert( pool, 2UL ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::finalize_block */

static void
test_finalize_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong slot1 = 1UL;
  fd_hash_t hash1 = random_hash();
  add_notar_votes( pool, slot1, &hash1, 0UL, 7UL );
  FD_TEST( !has_final_cert( pool, slot1 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==0UL );

  add_final_votes( pool, slot1, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot1 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot1 );

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot2 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot1 );

  fd_hash_t hash2 = random_hash();
  add_notar_votes( pool, slot2, &hash2, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot2 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot2 );

  ulong slot3 = 3UL;
  fd_hash_t hash3 = random_hash();
  add_notar_votes( pool, slot3, &hash3, 0UL, 6UL );
  add_final_votes( pool, slot3, 0UL, 6UL );
  FD_TEST( !has_final_cert( pool, slot3 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot2 );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::fast_finalize_block */

static void
test_fast_finalize_block( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  FD_TEST( !has_final_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, &gh, 0UL, 11UL );
  FD_TEST(  has_final_cert( pool, 0UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==0UL );

  FD_TEST( !has_final_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, &gh, 0UL, 9UL );
  FD_TEST(  has_final_cert( pool, 1UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==1UL );

  FD_TEST( !has_final_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, &gh, 0UL, 8UL );
  FD_TEST( !has_final_cert( pool, 2UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::simple_branch_certified */

static void
test_simple_branch_certified( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  ag_block_id_t parent; parent.slot = slot; parent.hash = hashes[ next-1UL ];
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_notar_fallback */

static void
test_branch_certified_notar_fallback( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) {
    ag_block_id_t parent; parent.slot = s; parent.hash = hashes[s];
    FD_TEST( !is_parent_ready( pool, s+1UL, &parent ) );
    add_notar_votes         ( pool, s, &hashes[s], 0UL, 4UL );
    add_notar_fallback_votes( pool, s, &hashes[s], 4UL, 7UL );
  }
  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  ag_block_id_t parent; parent.slot = slot; parent.hash = hashes[ next-1UL ];
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_out_of_order */

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
  FD_TEST( is_parent_ready( pool, next, &parent ) );
  ag_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_late_cert */

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
  c.inner.notar = ag_notar_cert_construct( nv, 7UL, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );

  ag_block_id_t parent; parent.slot = slot1; parent.hash = hash1;
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::regular_handover */

static void
test_regular_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-1UL; parent.hash = hashes[ SLOTS_PER_WINDOW-1UL ];
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::one_skip_handover */

static void
test_one_skip_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-1UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-2UL; parent.hash = hashes[ SLOTS_PER_WINDOW-2UL ];
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::two_skip_handover */

static void
test_two_skip_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-2UL; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-2UL, 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-3UL; parent.hash = hashes[ SLOTS_PER_WINDOW-3UL ];
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::skip_window_handover */

static void
test_skip_window_handover( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, &hashes[s], 0UL, 7UL );
  for( ulong s=SLOTS_PER_WINDOW; s<2UL*SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ag_block_id_t parent; parent.slot = SLOTS_PER_WINDOW-1UL; parent.hash = hashes[ SLOTS_PER_WINDOW-1UL ];
  FD_TEST( is_parent_ready( pool, 2UL*SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::pruning */

static void
test_pruning( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong total = 3UL*SLOTS_PER_WINDOW + 10UL;
  fd_hash_t hashes[ 3UL*SLOTS_PER_WINDOW + 10UL ];
  for( ulong s=0UL; s<total; s++ ) hashes[s] = random_hash();

  for( ulong s=1UL; s<3UL*SLOTS_PER_WINDOW; s++ ) {
    FD_TEST( !has_final_cert( pool, s ) );
    add_notar_votes( pool, s, &hashes[s], 0UL, 11UL );
    FD_TEST(  has_final_cert( pool, s ) );
  }
  ulong last_slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<last_slot; s++ ) FD_TEST( !contains_slot( pool, s ) );
  FD_TEST( contains_slot( pool, last_slot ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, &hashes[s], 0UL, 8UL );
    FD_TEST( !has_final_cert( pool, s ) );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<=10UL; s++ ) FD_TEST( contains_slot( pool, last_slot+s ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, &hashes[s], 8UL, 9UL );
    FD_TEST( has_final_cert( pool, s ) );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot+10UL );

  for( ulong s=0UL; s<10UL; s++ ) FD_TEST( !contains_slot( pool, last_slot+s ) );
  FD_TEST( contains_slot( pool, last_slot+10UL ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::duplicate_votes */

static void
test_duplicate_votes( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();
  ulong slot = 0UL;

  ag_vote_t v1; ag_vote_new_notar( &v1, slot, &gh, &g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v1 )==AG_POOL_SUCCESS );

  ag_vote_t v2; ag_vote_new_skip( &v2, slot, &g_sk[1], 1, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v2 )==AG_POOL_SUCCESS );

  FD_TEST( ag_pool_add_vote( pool, &v1 )==AG_POOL_ERR_DUPLICATE );
  FD_TEST( ag_pool_add_vote( pool, &v2 )==AG_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::duplicate_certs */

static void
test_duplicate_certs( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong first_slot = 1UL;
  fd_hash_t hash = random_hash();
  ag_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_notar_vote_new( &nv[v], first_slot, &hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t notar; notar.kind = AG_CERT_TYPE_NOTAR;
  notar.inner.notar = ag_notar_cert_construct( nv, NV, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &notar )==AG_POOL_SUCCESS );

  ulong second_slot = 2UL;
  ag_skip_vote_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], second_slot, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t skip; skip.kind = AG_CERT_TYPE_SKIP;
  skip.inner.skip = ag_skip_cert_construct( sv, NV, NULL, 0UL, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &skip )==AG_POOL_SUCCESS );

  FD_TEST( ag_pool_add_cert( pool, &notar )==AG_POOL_ERR_DUPLICATE );
  FD_TEST( ag_pool_add_cert( pool, &skip  )==AG_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::out_of_bounds_votes */

static void
test_out_of_bounds_votes( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) add_notar_votes( pool, s, &gh, 0UL, 11UL );
  FD_TEST( ag_pool_finalized_slot( pool )==slot );
  FD_TEST( pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    for( ulong v=0UL; v<11UL; v++ ) {
      ag_vote_t vote; ag_vote_new_final( &vote, s, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
      FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
    }
  }

  ulong future = 5UL*SLOTS_PER_EPOCH;
  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote; ag_vote_new_final( &vote, future, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  }

  teardown_pool( pool );
}

/* src/consensus/pool.rs::out_of_bounds_certs */

static void
test_out_of_bounds_certs( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) {
    ag_notar_vote_t nv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) ag_notar_vote_new( &nv[v], s, &gh, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    ag_cert_t c; c.kind = AG_CERT_TYPE_FAST_FINAL;
    c.inner.fast_final = ag_fast_final_cert_construct( nv, NV, g_epoch_info );
    FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
    drain_channels( pool );
  }
  FD_TEST( pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    ag_skip_vote_t sv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], s, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    ag_cert_t c; c.kind = AG_CERT_TYPE_SKIP;
    c.inner.skip = ag_skip_cert_construct( sv, NV, NULL, 0UL, g_epoch_info );
    FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  }

  ulong future = 3UL*SLOTS_PER_EPOCH;
  ag_skip_vote_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], future, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_SKIP;
  c.inner.skip = ag_skip_cert_construct( sv, NV, NULL, 0UL, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::slow_finalize_closing_gap_no_double_parent_ready */

static void
test_slow_finalize_closing_gap_no_double_parent_ready( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();

  ulong next_start     = SLOTS_PER_WINDOW;
  ulong gap_slot       = next_start - 1UL;
  ulong watermark_slot = gap_slot - 1UL;

  for( ulong s=1UL; s<gap_slot; s++ ) fast_finalize( pool, s, &gh );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  fd_hash_t gap_hash = random_hash();
  add_final_votes( pool, gap_slot, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, gap_slot ) );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  fast_finalize( pool, next_start, &gh );
  FD_TEST( ag_pool_finalized_slot( pool )==next_start );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST( min_live_slot( pool )==watermark_slot );

  add_notar_votes( pool, gap_slot, &gap_hash, 0UL, 7UL );
  FD_TEST( pool_first_unpruned_slot( pool )==next_start );
  FD_TEST( min_live_slot( pool )==next_start );

  ulong cnt; ag_pool_parents_ready( pool, next_start, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::standstill_recovery */

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

  ag_pool_recover_from_standstill( pool );

  ag_standstill_t const * ss = NULL;
  ulong event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==AG_EVENT_POOL_STANDSTILL ) ss = &event( i )->standstill;
  }
  FD_TEST( ss );
  FD_TEST( ss->slot==slot2 );

  ag_cert_t const * certs     = ss->certs;
  ulong             certs_cnt = ss->cert_cnt;
  ag_vote_t const * votes     = ss->votes;
  ulong             votes_cnt = ss->vote_cnt;

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

  for( ulong i=0UL; i<certs_cnt; i++ ) {
    uchar buf[ sizeof(ag_cert_serde_t) + sizeof(ag_cert_bitmap_serde_t) + (AG_AGGSIG_MAX_SIGNERS+4UL)/5UL + 2UL ];
    ulong sz;
    FD_TEST( ag_cert_ser( &certs[i], TEST_SHRED_VERSION, buf, sizeof(buf), &sz )==0 );
    ag_cert_t rt; ulong consumed;
    FD_TEST( ag_cert_de( &rt, TEST_SHRED_VERSION, buf, sz, &consumed )==AG_CERT_DE_SUCCESS );
    FD_TEST( consumed==sz );
    FD_TEST( rt.kind==certs[i].kind );
    FD_TEST( ag_cert_slot( &rt )==ag_cert_slot( &certs[i] ) );

    ag_cert_t bad;
    FD_TEST( ag_cert_de( &bad, (ushort)(TEST_SHRED_VERSION+1), buf, sz,      NULL )==AG_CERT_DE_ERR_SHRED_VERSION );
    FD_TEST( ag_cert_de( &bad, TEST_SHRED_VERSION,             buf, sz-1UL,  NULL )==AG_CERT_DE_ERR_TRUNCATED     );
  }

  teardown_pool( pool );
}

/* src/consensus/pool.rs::parent_ready_upon_finalization */

static void
test_parent_ready_upon_finalization( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong slot1 = SLOTS_PER_WINDOW;
  ag_block_id_t block0 = random_block_id( slot1-1UL );
  ag_block_id_t block1 = random_block_id( slot1 );
  ag_block_id_t block2 = random_block_id( slot1+1UL );

  drain_channels( pool );

  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, block2.slot, &block2.hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  ulong cert_created = 0UL, parent_ready_cnt = 0UL;
  ulong event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==AG_EVENT_POOL_CERT_CREATED ) cert_created++;
    if( event( i )->kind==AG_EVENT_POOL_PARENT_READY ) parent_ready_cnt++;
  }
  FD_TEST( cert_created==3UL );
  FD_TEST( parent_ready_cnt==0UL );

  drain_channels( pool );
  ag_pool_add_block( pool, &block2, &block1 );
  ag_pool_add_block( pool, &block1, &block0 );

  int found = 0;
  event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==AG_EVENT_POOL_PARENT_READY ) {
      FD_TEST( event( i )->parent_ready.slot==slot1 );
      FD_TEST( ag_block_id_eq( &event( i )->parent_ready.parent, &block0 ) );
      found = 1;
    }
  }
  FD_TEST( found );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::safe_to_notar_notar_cert_only */

static void
test_safe_to_notar_notar_cert_only( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_hash_t hash1 = random_hash();
  fd_hash_t hash2 = random_hash();

  notar_cert( pool, slot1, &hash1, 7UL );

  ag_block_id_t child  = { .slot = slot2, .hash = hash2 };
  ag_block_id_t parent = { .slot = slot1, .hash = hash1 };
  ag_pool_add_block( pool, &child, &parent );
  drain_channels( pool );

  ag_vote_t skip; ag_vote_new_skip( &skip, slot2, &g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &skip )==AG_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot2, &hash2, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::safe_to_notar_fast_final_cert_only */

static void
test_safe_to_notar_fast_final_cert_only( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_hash_t hash1 = random_hash();
  fd_hash_t hash2 = random_hash();

  fast_finalize( pool, slot1, &hash1 );

  ag_block_id_t child  = { .slot = slot2, .hash = hash2 };
  ag_block_id_t parent = { .slot = slot1, .hash = hash1 };
  ag_pool_add_block( pool, &child, &parent );
  drain_channels( pool );

  ag_vote_t skip; ag_vote_new_skip( &skip, slot2, &g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &skip )==AG_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot2, &hash2, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );

  teardown_pool( pool );
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
test_hash_capacity( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  ulong slot = 0UL;

  fd_hash_t hash[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    hash[i] = random_hash();
    ag_vote_t v; ag_vote_new_notar( &v, slot, &hash[i], &g_sk[i], (ushort)i, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
    drain_channels( pool );
  }

  fd_hash_t nf[ AG_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<AG_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    nf[i] = random_hash();
    ag_vote_t v; ag_vote_new_notar_fallback( &v, slot, &nf[i], &g_sk[0], (ushort)0, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
    drain_channels( pool );
  }

  fd_hash_t past = random_hash();
  ag_vote_t v_past;
  ag_vote_new_notar_fallback( &v_past, slot, &past, &g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_past )==AG_POOL_ERR_HASH_CAPACITY );
  FD_TEST( ag_pool_add_vote( pool, &v_past )==AG_POOL_ERR_HASH_CAPACITY );

  ag_vote_t v_other;
  ag_vote_new_notar_fallback( &v_other, slot, &past, &g_sk[1], (ushort)1, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_other )==AG_POOL_SUCCESS );

  teardown_pool( pool );
}

/* src/consensus/validated_vote.rs::unknown_signer */

static void
test_unknown_signer_votes( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  fd_hash_t gh = genesis_hash();
  ulong slot = 0UL;

  ag_epoch_info_t const * epoch = epoch_info( pool, slot );
  FD_TEST( epoch );

  ag_vote_t v1; ag_vote_new_notar( &v1, slot, &gh, &g_sk[0], (ushort)NV, TEST_SHRED_VERSION );
  FD_TEST( ag_vote_signer( &v1 )>=epoch->validator_cnt );

  ag_vote_t v2; ag_vote_new_skip( &v2, slot, &g_sk[0], USHORT_MAX, TEST_SHRED_VERSION );
  FD_TEST( ag_vote_signer( &v2 )>=epoch->validator_cnt );

  teardown_pool( pool );
}

static void
test_wait_for_parent_ready( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong slot1 = SLOTS_PER_WINDOW;
  ag_block_id_t block0 = random_block_id( slot1-1UL );
  ag_block_id_t block1 = random_block_id( slot1 );
  ag_block_id_t block2 = random_block_id( slot1+1UL );

  drain_channels( pool );

  ag_block_id_t parent;
  parent = ag_pool_wait_for_parent_ready( pool, slot1 );
  FD_TEST( parent.slot==ULONG_MAX );

  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, block2.slot, &block2.hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }
  drain_channels( pool );
  ag_pool_add_block( pool, &block2, &block1 );
  ag_pool_add_block( pool, &block1, &block0 );

  parent = ag_pool_wait_for_parent_ready( pool, slot1 );
  FD_TEST( parent.slot!=ULONG_MAX );
  FD_TEST( ag_block_id_eq( &parent, &block0 ) );

  ulong                 cnt   = 0UL;
  ag_block_id_t const * ready = ag_pool_parents_ready( pool, slot1, &cnt );
  FD_TEST( cnt==1UL );
  FD_TEST( ag_block_id_eq( &ready[0], &parent ) );

  ag_block_id_t again;
  again = ag_pool_wait_for_parent_ready( pool, slot1 );
  FD_TEST( again.slot!=ULONG_MAX );
  FD_TEST( ag_block_id_eq( &again, &parent ) );

  teardown_pool( pool );
}

#define EPOCH_A_LO (0UL)
#define EPOCH_B_LO (64UL)
#define EPOCH_B_HI (127UL)

#define HEAVY_CNT   (4UL)
#define HEAVY_STAKE (3UL)

static ag_pool_t *
setup_two_epoch_pool( fd_wksp_t *        wksp,
                      ag_epoch_info_t ** out_a,
                      ag_epoch_info_t ** out_b,
                      int                install_b ) {
  create_validators();
  ulong slot_max      = TEST_SLOT_MAX;

  void * mem = fd_wksp_alloc_laddr( wksp, ag_pool_align(),
                                    ag_pool_footprint( slot_max ), 42UL );
  FD_TEST( mem );
  ag_pool_t * pool = ag_pool_join( ag_pool_new( mem, slot_max, 42UL ) );
  FD_TEST( pool );

  ag_validator_info_t heavy[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    heavy[ i ]       = g_info[ i ];
    heavy[ i ].stake = i<HEAVY_CNT ? HEAVY_STAKE : 1UL;
  }

  ag_epoch_info_t * a = make_epoch_info( wksp, g_info, NV );
  ag_epoch_info_t * b = make_epoch_info( wksp, heavy,  NV );
  FD_TEST( a->total_stake==NV );
  FD_TEST( b->total_stake==HEAVY_CNT*HEAVY_STAKE + (NV-HEAVY_CNT) );

  ag_pool_advance_epoch( pool, a, 0UL, EPOCH_A_LO );
  if( install_b ) ag_pool_advance_epoch( pool, b, 0UL, EPOCH_B_LO );

  *out_a = a; *out_b = b;
  return pool;
}

static void
test_stake_resolved_per_slot_epoch( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 1 );

  ulong     slot_a = EPOCH_A_LO + 4UL;
  ulong     slot_b = EPOCH_B_LO + 4UL;
  fd_hash_t hash_a = random_hash();
  fd_hash_t hash_b = random_hash();

  add_notar_votes( pool, slot_a, &hash_a, 0UL, HEAVY_CNT );
  FD_TEST( !has_notar_cert( pool, slot_a ) );

  add_notar_votes( pool, slot_b, &hash_b, 0UL, HEAVY_CNT );
  FD_TEST( has_notar_cert( pool, slot_b ) );

  add_notar_votes( pool, slot_a, &hash_a, HEAVY_CNT, 7UL );
  FD_TEST( has_notar_cert( pool, slot_a ) );

  teardown_pool_only( pool );
  fd_wksp_free_laddr( a ); fd_wksp_free_laddr( b );
}

static void
test_epoch_boundary_slot( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 1 );

  fd_hash_t hash_lo = random_hash();
  fd_hash_t hash_hi = random_hash();

  add_notar_votes( pool, EPOCH_B_LO-1UL, &hash_lo, 0UL, HEAVY_CNT );
  FD_TEST( !has_notar_cert( pool, EPOCH_B_LO-1UL ) );

  add_notar_votes( pool, EPOCH_B_LO, &hash_hi, 0UL, HEAVY_CNT );
  FD_TEST( has_notar_cert( pool, EPOCH_B_LO ) );

  teardown_pool_only( pool );
  fd_wksp_free_laddr( a ); fd_wksp_free_laddr( b );
}

static void
test_epoch_installed_late( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 0 );

  ulong     beyond = EPOCH_B_LO + 4UL;
  fd_hash_t hash   = random_hash();

  ag_vote_t v; ag_vote_new_notar( &v, beyond, &hash, &g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( epoch_info( pool, beyond )==a );
  FD_TEST( !contains_slot( pool, beyond ) );

  ag_pool_advance_epoch( pool, b, 0UL, EPOCH_B_LO );
  FD_TEST( epoch_info( pool, beyond         )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_LO-1UL )==a );
  FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
  FD_TEST( contains_slot( pool, beyond ) );

  teardown_pool_only( pool );
  fd_wksp_free_laddr( a ); fd_wksp_free_laddr( b );
}

static void
test_retired_epoch_already_pruned( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 1 );

  for( ulong s=EPOCH_A_LO+1UL; s<=EPOCH_B_LO; s++ ) {
    fd_hash_t hash = random_hash();
    add_notar_votes( pool, s, &hash, 0UL, NV );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==EPOCH_B_LO );

  FD_TEST( !contains_slot( pool, EPOCH_B_LO-1UL ) );
  FD_TEST(  contains_slot( pool, EPOCH_B_LO      ) );
  FD_TEST( pool_first_unpruned_slot( pool )==EPOCH_B_LO );
  FD_TEST( min_live_slot( pool )==EPOCH_B_LO );

  ag_epoch_info_t * c = make_epoch_info( wksp, g_info, NV );
  ag_pool_advance_epoch( pool, c, 0UL, EPOCH_B_HI+1UL );

  FD_TEST( epoch_info( pool, EPOCH_B_LO     )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_HI+1UL )==c );
  FD_TEST( contains_slot( pool, EPOCH_B_LO ) );

  ag_vote_t v_below; fd_hash_t h_below = random_hash();
  ag_vote_new_notar( &v_below, EPOCH_B_LO-1UL, &h_below, &g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_below )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  FD_TEST( !contains_slot( pool, EPOCH_B_LO-1UL ) );

  teardown_pool_only( pool );
  fd_wksp_free_laddr( a ); fd_wksp_free_laddr( b ); fd_wksp_free_laddr( c );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL        );
  ulong        numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t *  wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_notarize_block                                  ( wksp );
  test_skip_block                                      ( wksp );
  test_finalize_block                                  ( wksp );
  test_fast_finalize_block                             ( wksp );
  test_simple_branch_certified                         ( wksp );
  test_branch_certified_notar_fallback                 ( wksp );
  test_branch_certified_out_of_order                   ( wksp );
  test_branch_certified_late_cert                      ( wksp );
  test_regular_handover                                ( wksp );
  test_one_skip_handover                               ( wksp );
  test_two_skip_handover                               ( wksp );
  test_skip_window_handover                            ( wksp );
  test_pruning                                         ( wksp );
  test_duplicate_votes                                 ( wksp );
  test_duplicate_certs                                 ( wksp );
  test_out_of_bounds_votes                             ( wksp );
  test_out_of_bounds_certs                             ( wksp );
  test_slow_finalize_closing_gap_no_double_parent_ready( wksp );
  test_standstill_recovery                             ( wksp );
  test_parent_ready_upon_finalization                  ( wksp );
  test_safe_to_notar_notar_cert_only                   ( wksp );
  test_safe_to_notar_fast_final_cert_only              ( wksp );

  test_handle_invalid_votes                            ( wksp );
  test_hash_capacity                                   ( wksp );
  test_unknown_signer_votes                            ( wksp );
  test_wait_for_parent_ready                           ( wksp );
  test_stake_resolved_per_slot_epoch                   ( wksp );
  test_epoch_boundary_slot                             ( wksp );
  test_epoch_installed_late                            ( wksp );
  test_retired_epoch_already_pruned                    ( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
