#include "ag_pool.c"
#include "ag_cert_serde.h"

static int
has_notar_cert( ag_pool_t const * pool,
                ulong             slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && e->slot_state.certs.notar.slot!=ULONG_MAX;
}

static int
has_skip_cert( ag_pool_t const * pool,
               ulong             slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && e->slot_state.certs.skip.slot!=ULONG_MAX;
}

static int
has_final_cert( ag_pool_t const * pool,
                ulong             slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && ( e->slot_state.certs.fast_finalize.slot!=ULONG_MAX ||
                e->slot_state.certs.finalize.slot     !=ULONG_MAX );
}

static int
contains_slot( ag_pool_t const * pool,
               ulong             slot ) {
  return slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool )!=NULL;
}

static ag_block_id_t const *
s2n_waiting_child( ag_pool_t const *     pool,
                   ag_block_id_t const * parent ) {
  s2n_waiting_parent_cert_ele_t const * ele = s2n_waiting_parent_cert_map_ele_query_const( pool->s2n_waiting_parent_cert->map, parent, NULL, pool->s2n_waiting_parent_cert->pool );
  return ele ? &ele->child : NULL;
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
  if( FD_UNLIKELY( pool_events_empty( pool->pool_events ) ) ) return 0;
  *out = pool_events_pop( pool->pool_events );
  return 1;
}

static void
drain_events( ag_pool_t * pool ) {
  pool_events_remove_all  ( pool->pool_events   );
  repair_events_remove_all( pool->repair_events );
}

#define SLOTS_PER_WINDOW AG_SLOTS_PER_WINDOW
#define NV               (11UL)

#define TEST_SLOT_MAX    (64UL)

#define TEST_SHRED_VERSION ((ushort)0x5a5a)

#define SCRATCH_MAX (TEST_SLOT_MAX*sizeof(ag_slot_state_t)+(4UL<<20)) /* ~212 MiB */

static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

static ag_bls_sec_t      g_sk  [ NV ];
static ag_validator_info_t g_info[ NV ];

static void
genesis_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
}

static ulong g_hash_ctr = 0UL;

static void
random_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
  FD_STORE( ulong, out,     0x9000UL + (++g_hash_ctr) );
  FD_STORE( ulong, out+8UL, 0xc0ffee00UL ^ g_hash_ctr );
}

static ag_block_id_t
random_block_id( ulong slot ) {
  ag_block_id_t b; b.slot = slot; random_hash( b.hash );
  return b;
}

static void
create_validators( void ) {
  for( ulong i=0UL; i<NV; i++ ) {
    fd_memset( g_sk[i], (int)(i*7UL+1UL), AG_BLS_SEC_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    ag_bls_sec_to_pub( g_sk[i], g_info[i].bls_key );
  }
}

static ag_event_pool_t g_event[ TEST_SLOT_MAX ];

static ulong
take_events( ag_pool_t * pool ) {
  ulong cnt = 0UL;
  while( cnt<TEST_SLOT_MAX && votor_event_pop( pool, &g_event[ cnt ] ) ) cnt++;
  FD_TEST( pool_events_empty( pool->pool_events ) );
  return cnt;
}

static ag_event_pool_t const *
event( ulong i ) {
  return &g_event[ i ];
}

/* At most three epoch infos are live at once: a, b and c in
   test_retired_epoch_already_pruned.  They are ~281 KiB apiece and the
   tests compare them by address, so each needs its own storage. */

#define EPOCH_INFO_MAX (3UL)

static ag_epoch_info_t epoch_info_mem[ EPOCH_INFO_MAX ];

static ag_epoch_info_t *
make_epoch_info( ulong                       idx,
                 ag_validator_info_t const * info,
                 ulong                       cnt ) {
  FD_TEST( idx<EPOCH_INFO_MAX );
  ag_epoch_info_t * epoch_info = &epoch_info_mem[ idx ];
  ag_epoch_info( epoch_info, info, cnt );
  return epoch_info;
}

static ag_epoch_info_t * g_epoch_info = NULL;

static ag_pool_t *
setup_pool( void ) {
  create_validators();
  ulong slot_max = TEST_SLOT_MAX;
  FD_TEST( ag_pool_footprint( slot_max )<=sizeof(scratch) );
  ag_pool_t * pool = ag_pool_join( ag_pool_new( scratch, slot_max, 42UL ) );
  FD_TEST( pool );
  ag_pool_init( pool, 0UL );

  g_epoch_info = make_epoch_info( 0UL, g_info, NV );
  ag_pool_advance_epoch( pool, g_epoch_info, 0UL, 0UL );
  return pool;
}

static void
teardown_pool_only( ag_pool_t * pool ) {
  ag_pool_delete( ag_pool_leave( pool ) );
}

static void
teardown_pool( ag_pool_t * pool ) {
  ag_pool_delete( ag_pool_leave( pool ) );
  g_epoch_info = NULL;
}

static void
add_notar_votes( ag_pool_t *           pool,
                 ulong                 slot,
                 ag_block_hash_t const hash,
                 ulong                 lo,
                 ulong                 hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote = ag_vote_construct_notar( slot, hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
add_notar_fallback_votes( ag_pool_t *           pool,
                          ulong                 slot,
                          ag_block_hash_t const hash,
                          ulong                 lo,
                          ulong                 hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote = ag_vote_construct_notar_fallback( slot, hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
add_skip_votes( ag_pool_t * pool,
                ulong       slot,
                ulong       lo,
                ulong       hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote = ag_vote_construct_skip( slot, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
add_final_votes( ag_pool_t * pool,
                 ulong       slot,
                 ulong       lo,
                 ulong       hi ) {
  for( ulong v=lo; v<hi; v++ ) {
    ag_vote_t vote = ag_vote_construct_final( slot, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
    drain_events( pool );
  }
}

static void
notar_cert( ag_pool_t *           pool,
            ulong                 slot,
            ag_block_hash_t const hash,
            ulong                 signers ) {
  FD_TEST( signers<=NV );
  ag_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<signers; v++ ) nv[v] = ag_vote_construct_notar( slot, hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).notar;
  ag_cert_t c = ag_cert_construct_notar( nv, signers, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
  drain_events( pool );
}

static int
drained_safe_to_notar( ag_pool_t *           pool,
                       ulong                 slot,
                       ag_block_hash_t const hash ) {
  ulong cnt = take_events( pool );
  for( ulong i=0UL; i<cnt; i++ ) {
    ag_event_pool_t const * e = event( i );
    if( e->kind!=AG_EVENT_POOL_SAFE_TO_NOTAR ) continue;
    if( e->safe_to_notar.slot==slot &&
        !memcmp( e->safe_to_notar.hash, hash, sizeof(ag_block_hash_t) ) ) return 1;
  }
  return 0;
}

static void
fast_finalize( ag_pool_t *           pool,
               ulong                 slot,
               ag_block_hash_t const hash ) {
  ag_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = ag_vote_construct_notar( slot, hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).notar;
  ag_cert_t c = ag_cert_construct_fast_final( nv, NV, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
  drain_events( pool );
}

/* src/consensus/pool.rs::notarize_block */

static void
test_notarize_block( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t gh; genesis_hash( gh );

  FD_TEST( !has_notar_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, gh, 0UL, 11UL );
  FD_TEST(  has_notar_cert( pool, 0UL ) );

  FD_TEST( !has_notar_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, gh, 0UL, 7UL );
  FD_TEST(  has_notar_cert( pool, 1UL ) );

  FD_TEST( !has_notar_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, gh, 0UL, 6UL );
  FD_TEST( !has_notar_cert( pool, 2UL ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::skip_block */

static void
test_skip_block( void ) {
  ag_pool_t * pool = setup_pool();

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
test_finalize_block( void ) {
  ag_pool_t * pool = setup_pool();

  ulong slot1 = 1UL;
  ag_block_hash_t hash1; random_hash( hash1 );
  add_notar_votes( pool, slot1, hash1, 0UL, 7UL );
  FD_TEST( !has_final_cert( pool, slot1 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==0UL );

  add_final_votes( pool, slot1, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot1 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot1 );

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot2 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot1 );

  ag_block_hash_t hash2; random_hash( hash2 );
  add_notar_votes( pool, slot2, hash2, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, slot2 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot2 );

  ulong slot3 = 3UL;
  ag_block_hash_t hash3; random_hash( hash3 );
  add_notar_votes( pool, slot3, hash3, 0UL, 6UL );
  add_final_votes( pool, slot3, 0UL, 6UL );
  FD_TEST( !has_final_cert( pool, slot3 ) );
  FD_TEST( ag_pool_finalized_slot( pool )==slot2 );

  teardown_pool( pool );
}

static void
test_finalized_block_hash( void ) {
  ag_pool_t *     pool = setup_pool();
  ag_block_hash_t hash;

  FD_TEST( !ag_pool_finalized_block_hash( pool, ag_pool_finalized_slot( pool ), hash ) ); /* nothing finalized */

  ag_block_hash_t hash1; random_hash( hash1 );
  add_notar_votes( pool, 1UL, hash1, 0UL, 7UL );
  add_final_votes( pool, 1UL, 0UL, 7UL );
  FD_TEST( ag_pool_finalized_slot( pool )==1UL );
  FD_TEST( ag_pool_finalized_block_hash( pool, ag_pool_finalized_slot( pool ), hash ) );
  FD_TEST( !memcmp( hash, hash1, sizeof(ag_block_hash_t) ) );

  /* the hash tracks the finalized slot as it advances */

  ag_block_hash_t hash2; random_hash( hash2 );
  add_notar_votes( pool, 2UL, hash2, 0UL, 11UL ); /* fast finalize */
  FD_TEST( ag_pool_finalized_slot( pool )==2UL );
  FD_TEST( ag_pool_finalized_block_hash( pool, ag_pool_finalized_slot( pool ), hash ) );
  FD_TEST( !memcmp( hash, hash2, sizeof(ag_block_hash_t) ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::fast_finalize_block */

static void
test_fast_finalize_block( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t gh; genesis_hash( gh );

  FD_TEST( !has_final_cert( pool, 0UL ) );
  add_notar_votes( pool, 0UL, gh, 0UL, 11UL );
  FD_TEST(  has_final_cert( pool, 0UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==0UL );

  FD_TEST( !has_final_cert( pool, 1UL ) );
  add_notar_votes( pool, 1UL, gh, 0UL, 9UL );
  FD_TEST(  has_final_cert( pool, 1UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==1UL );

  FD_TEST( !has_final_cert( pool, 2UL ) );
  add_notar_votes( pool, 2UL, gh, 0UL, 8UL );
  FD_TEST( !has_final_cert( pool, 2UL ) );
  FD_TEST( ag_pool_finalized_slot( pool )==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::simple_branch_certified */

static void
test_simple_branch_certified( void ) {
  ag_pool_t * pool = setup_pool();

  ag_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( hashes[s] );
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, hashes[s], 0UL, 7UL );

  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  ag_block_id_t parent = ag_block_id( slot, hashes[ next-1UL ] );
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_notar_fallback */

static void
test_branch_certified_notar_fallback( void ) {
  ag_pool_t * pool = setup_pool();

  ag_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( hashes[s] );
  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) {
    ag_block_id_t parent = ag_block_id( s, hashes[s] );
    FD_TEST( !is_parent_ready( pool, s+1UL, &parent ) );
    add_notar_votes         ( pool, s, hashes[s], 0UL, 4UL );
    add_notar_fallback_votes( pool, s, hashes[s], 4UL, 7UL );
  }
  ulong slot = SLOTS_PER_WINDOW-1UL;
  ulong next = slot+1UL;
  ag_block_id_t parent = ag_block_id( slot, hashes[ next-1UL ] );
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_out_of_order */

static void
test_branch_certified_out_of_order( void ) {
  ag_pool_t * pool = setup_pool();

  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW;
  ulong cnt; ag_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==0UL );

  ulong slot1 = 1UL;
  ag_block_hash_t hash1; random_hash( hash1 );
  add_notar_votes( pool, slot1, hash1, 0UL, 7UL );

  ag_block_id_t parent = ag_block_id( slot1, hash1 );
  FD_TEST( is_parent_ready( pool, next, &parent ) );
  ag_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::branch_certified_late_cert */

static void
test_branch_certified_late_cert( void ) {
  ag_pool_t * pool = setup_pool();

  for( ulong s=2UL; s<SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ulong next = SLOTS_PER_WINDOW;
  ulong cnt; ag_pool_parents_ready( pool, next, &cnt );
  FD_TEST( cnt==0UL );

  ulong slot1 = 1UL;
  ag_block_hash_t hash1; random_hash( hash1 );
  ag_vote_notar_t nv[7];
  for( ulong v=0UL; v<7UL; v++ ) nv[v] = ag_vote_construct_notar( slot1, hash1, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).notar;
  ag_cert_t c = ag_cert_construct_notar( nv, 7UL, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );

  ag_block_id_t parent = ag_block_id( slot1, hash1 );
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::regular_handover */

static void
test_regular_handover( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, hashes[s], 0UL, 7UL );

  ag_block_id_t parent = ag_block_id( SLOTS_PER_WINDOW-1UL, hashes[ SLOTS_PER_WINDOW-1UL ] );
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::one_skip_handover */

static void
test_one_skip_handover( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-1UL; s++ ) add_notar_votes( pool, s, hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  ag_block_id_t parent = ag_block_id( SLOTS_PER_WINDOW-2UL, hashes[ SLOTS_PER_WINDOW-2UL ] );
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::two_skip_handover */

static void
test_two_skip_handover( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW-2UL; s++ ) add_notar_votes( pool, s, hashes[s], 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-2UL, 0UL, 7UL );
  add_skip_votes( pool, SLOTS_PER_WINDOW-1UL, 0UL, 7UL );

  ag_block_id_t parent = ag_block_id( SLOTS_PER_WINDOW-3UL, hashes[ SLOTS_PER_WINDOW-3UL ] );
  FD_TEST( is_parent_ready( pool, SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::skip_window_handover */

static void
test_skip_window_handover( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t hashes[ SLOTS_PER_WINDOW ];
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) random_hash( hashes[s] );

  for( ulong s=1UL; s<SLOTS_PER_WINDOW; s++ ) add_notar_votes( pool, s, hashes[s], 0UL, 7UL );
  for( ulong s=SLOTS_PER_WINDOW; s<2UL*SLOTS_PER_WINDOW; s++ ) add_skip_votes( pool, s, 0UL, 7UL );

  ag_block_id_t parent = ag_block_id( SLOTS_PER_WINDOW-1UL, hashes[ SLOTS_PER_WINDOW-1UL ] );
  FD_TEST( is_parent_ready( pool, 2UL*SLOTS_PER_WINDOW, &parent ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::pruning */

static void
test_pruning( void ) {
  ag_pool_t * pool = setup_pool();

  ulong total = 3UL*SLOTS_PER_WINDOW + 10UL;
  ag_block_hash_t hashes[ 3UL*SLOTS_PER_WINDOW + 10UL ];
  for( ulong s=0UL; s<total; s++ ) random_hash( hashes[s] );

  for( ulong s=1UL; s<3UL*SLOTS_PER_WINDOW; s++ ) {
    FD_TEST( !has_final_cert( pool, s ) );
    add_notar_votes( pool, s, hashes[s], 0UL, 11UL );
    FD_TEST(  has_final_cert( pool, s ) );
  }
  ulong last_slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<last_slot; s++ ) FD_TEST( !contains_slot( pool, s ) );
  FD_TEST( contains_slot( pool, last_slot ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, hashes[s], 0UL, 8UL );
    FD_TEST( !has_final_cert( pool, s ) );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==last_slot );

  for( ulong s=0UL; s<=10UL; s++ ) FD_TEST( contains_slot( pool, last_slot+s ) );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  for( ulong i=0UL; i<10UL; i++ ) {
    ulong s = last_slot + 1UL + i;
    add_notar_votes( pool, s, hashes[s], 8UL, 9UL );
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
test_duplicate_votes( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t gh; genesis_hash( gh );
  ulong slot = 0UL;

  ag_vote_t v1 = ag_vote_construct_notar( slot, gh, g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v1 )==AG_POOL_SUCCESS );

  ag_vote_t v2 = ag_vote_construct_skip( slot, g_sk[1], 1, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v2 )==AG_POOL_SUCCESS );

  FD_TEST( ag_pool_add_vote( pool, &v1 )==AG_POOL_ERR_DUPLICATE );
  FD_TEST( ag_pool_add_vote( pool, &v2 )==AG_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::duplicate_certs */

static void
test_duplicate_certs( void ) {
  ag_pool_t * pool = setup_pool();

  ulong first_slot = 1UL;
  ag_block_hash_t hash; random_hash( hash );
  ag_vote_notar_t nv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) nv[v] = ag_vote_construct_notar( first_slot, hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).notar;
  ag_cert_t notar = ag_cert_construct_notar( nv, NV, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &notar )==AG_POOL_SUCCESS );

  ulong second_slot = 2UL;
  ag_vote_skip_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) sv[v] = ag_vote_construct_skip( second_slot, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).skip;
  ag_cert_t skip = ag_cert_construct_skip( sv, NV, NULL, 0UL, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &skip )==AG_POOL_SUCCESS );

  FD_TEST( ag_pool_add_cert( pool, &notar )==AG_POOL_ERR_DUPLICATE );
  FD_TEST( ag_pool_add_cert( pool, &skip  )==AG_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::out_of_bounds_votes */

static void
test_out_of_bounds_votes( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t gh; genesis_hash( gh );

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) add_notar_votes( pool, s, gh, 0UL, 11UL );
  FD_TEST( ag_pool_finalized_slot( pool )==slot );
  FD_TEST( pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    for( ulong v=0UL; v<11UL; v++ ) {
      ag_vote_t vote = ag_vote_construct_final( s, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
      FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
    }
  }

  ulong future = 5UL*TEST_SLOT_MAX;
  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote = ag_vote_construct_final( future, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  }

  teardown_pool( pool );
}

/* src/consensus/pool.rs::out_of_bounds_certs */

static void
test_out_of_bounds_certs( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t gh; genesis_hash( gh );

  ulong slot = 3UL*SLOTS_PER_WINDOW - 1UL;
  for( ulong s=1UL; s<=slot; s++ ) {
    ag_vote_notar_t nv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) nv[v] = ag_vote_construct_notar( s, gh, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).notar;
    ag_cert_t c = ag_cert_construct_fast_final( nv, NV, g_epoch_info );
    FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
    drain_events( pool );
  }
  FD_TEST( pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    ag_vote_skip_t sv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) sv[v] = ag_vote_construct_skip( s, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).skip;
    ag_cert_t c = ag_cert_construct_skip( sv, NV, NULL, 0UL, g_epoch_info );
    FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  }

  ulong future = 3UL*TEST_SLOT_MAX;
  ag_vote_skip_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) sv[v] = ag_vote_construct_skip( future, g_sk[v], (ushort)v, TEST_SHRED_VERSION ).skip;
  ag_cert_t c = ag_cert_construct_skip( sv, NV, NULL, 0UL, g_epoch_info );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::slow_finalize_closing_gap_no_double_parent_ready */

static void
test_slow_finalize_closing_gap_no_double_parent_ready( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t gh; genesis_hash( gh );

  ulong next_start     = SLOTS_PER_WINDOW;
  ulong gap_slot       = next_start - 1UL;
  ulong watermark_slot = gap_slot - 1UL;

  for( ulong s=1UL; s<gap_slot; s++ ) fast_finalize( pool, s, gh );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  ag_block_hash_t gap_hash; random_hash( gap_hash );
  add_final_votes( pool, gap_slot, 0UL, 7UL );
  FD_TEST( has_final_cert( pool, gap_slot ) );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST_PRUNED_TO_WATERMARK( pool );

  fast_finalize( pool, next_start, gh );
  FD_TEST( ag_pool_finalized_slot( pool )==next_start );
  FD_TEST( pool_first_unpruned_slot( pool )==watermark_slot );
  FD_TEST( min_live_slot( pool )==watermark_slot );

  add_notar_votes( pool, gap_slot, gap_hash, 0UL, 7UL );
  FD_TEST( pool_first_unpruned_slot( pool )==next_start );
  FD_TEST( min_live_slot( pool )==next_start );

  ulong cnt; ag_pool_parents_ready( pool, next_start, &cnt );
  FD_TEST( cnt==1UL );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::standstill_recovery */

static void
test_standstill_recovery( void ) {
  ag_pool_t * pool = setup_pool();

  ulong slot1 = 1UL;
  ag_block_hash_t hash1; random_hash( hash1 );
  add_notar_votes( pool, slot1, hash1, 0UL, 11UL );

  ulong slot2 = 2UL;
  add_final_votes( pool, slot2, 0UL, 7UL );

  ulong slot3 = 3UL;
  ag_block_hash_t hash3; random_hash( hash3 );
  add_notar_votes( pool, slot3, hash3, 0UL, 1UL );

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
    if( certs[i].kind==AG_CERT_KIND_FAST_FINAL )  FD_TEST( ag_cert_slot( &certs[i] )==slot1 );
    else if( certs[i].kind==AG_CERT_KIND_FINAL )  FD_TEST( ag_cert_slot( &certs[i] )==slot2 );
    else FD_TEST( 0 );
  }

  FD_TEST( votes_cnt==2UL );
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    FD_TEST( ag_vote_rank( &votes[i] )==0UL );
    if( votes[i].kind==AG_VOTE_KIND_FINAL )      FD_TEST( ag_vote_slot( &votes[i] )==slot2 );
    else if( votes[i].kind==AG_VOTE_KIND_NOTAR ) FD_TEST( ag_vote_slot( &votes[i] )==slot3 );
    else FD_TEST( 0 );
  }

  for( ulong i=0UL; i<certs_cnt; i++ ) {
    uchar buf[ AG_CERT_SER_MAX ];
    ulong sz;
    sz = ag_cert_ser( &certs[i], TEST_SHRED_VERSION, buf );
    ag_cert_t rt;
    FD_TEST( ag_cert_de( &rt, TEST_SHRED_VERSION, buf, sz )==AG_CERT_DE_SUCCESS );
    FD_TEST( rt.kind==certs[i].kind );
    FD_TEST( ag_cert_slot( &rt )==ag_cert_slot( &certs[i] ) );

    /* Votor rebroadcasts certificates it learned from a peer, so a cert
       that came out of ag_cert_de has to reserialize to the same bytes. */

    uchar rebroadcast[ AG_CERT_SER_MAX ];
    ulong rebroadcast_sz;
    rebroadcast_sz = ag_cert_ser( &rt, TEST_SHRED_VERSION, rebroadcast );
    FD_TEST( rebroadcast_sz==sz );
    FD_TEST( !memcmp( rebroadcast, buf, sz ) );

    ag_cert_t bad;
    FD_TEST( ag_cert_de( &bad, (ushort)(TEST_SHRED_VERSION+1), buf, sz     )==AG_CERT_DE_ERR_SHRED_VERSION );
    FD_TEST( ag_cert_de( &bad, TEST_SHRED_VERSION,             buf, sz-1UL )==AG_CERT_DE_ERR_SZ     ); /* too few  */
    FD_TEST( ag_cert_de( &bad, TEST_SHRED_VERSION,             buf, sz+1UL )==AG_CERT_DE_ERR_SZ     ); /* trailing */
  }

  teardown_pool( pool );
}

/* src/consensus/pool.rs::parent_ready_upon_finalization */

static void
test_parent_ready_upon_finalization( void ) {
  ag_pool_t * pool = setup_pool();

  ulong slot1 = SLOTS_PER_WINDOW;
  ag_block_id_t block0 = random_block_id( slot1-1UL );
  ag_block_id_t block1 = random_block_id( slot1 );
  ag_block_id_t block2 = random_block_id( slot1+1UL );

  drain_events( pool );

  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote = ag_vote_construct_notar( block2.slot, block2.hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
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

  drain_events( pool );
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
test_safe_to_notar_notar_cert_only( void ) {
  ag_pool_t * pool = setup_pool();

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  ag_block_hash_t hash1; random_hash( hash1 );
  ag_block_hash_t hash2; random_hash( hash2 );

  notar_cert( pool, slot1, hash1, 7UL );

  ag_block_id_t child  = ag_block_id( slot2, hash2 );
  ag_block_id_t parent = ag_block_id( slot1, hash1 );
  ag_pool_add_block( pool, &child, &parent );
  drain_events( pool );

  ag_vote_t skip = ag_vote_construct_skip( slot2, g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &skip )==AG_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    ag_vote_t vote = ag_vote_construct_notar( slot2, hash2, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  FD_TEST( drained_safe_to_notar( pool, slot2, hash2 ) );

  teardown_pool( pool );
}

/* src/consensus/pool.rs::safe_to_notar_fast_final_cert_only */

static void
test_safe_to_notar_fast_final_cert_only( void ) {
  ag_pool_t * pool = setup_pool();

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  ag_block_hash_t hash1; random_hash( hash1 );
  ag_block_hash_t hash2; random_hash( hash2 );

  fast_finalize( pool, slot1, hash1 );

  ag_block_id_t child  = ag_block_id( slot2, hash2 );
  ag_block_id_t parent = ag_block_id( slot1, hash1 );
  ag_pool_add_block( pool, &child, &parent );
  drain_events( pool );

  ag_vote_t skip = ag_vote_construct_skip( slot2, g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &skip )==AG_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    ag_vote_t vote = ag_vote_construct_notar( slot2, hash2, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  FD_TEST( drained_safe_to_notar( pool, slot2, hash2 ) );

  teardown_pool( pool );
}

/* Firedancer-only test */

static void
test_safe_to_notar_awaiting_votes( void ) {
  ag_pool_t * pool = setup_pool();

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  ag_block_hash_t hash1; random_hash( hash1 );
  ag_block_hash_t hash2; random_hash( hash2 );

  notar_cert( pool, slot1, hash1, 7UL );

  ag_block_id_t child  = ag_block_id( slot2, hash2 );
  ag_block_id_t parent = ag_block_id( slot1, hash1 );
  ag_pool_add_block( pool, &child, &parent );

  FD_TEST( !drained_safe_to_notar( pool, slot2, hash2 ) );

  ag_block_id_t const * waiting = s2n_waiting_child( pool, &parent );
  FD_TEST( waiting && ag_block_id_eq( waiting, &child ) );

  teardown_pool( pool );
}

/* Firedancer-only test */

static void
test_safe_to_notar_not_queued_for_parent_cert( void ) {
  ag_pool_t * pool = setup_pool();

  ulong     slot1  = 1UL;
  ulong     slot2  = 2UL;
  ag_block_hash_t hash1;  random_hash( hash1  );
  ag_block_hash_t hash_a; random_hash( hash_a );
  ag_block_hash_t hash_b; random_hash( hash_b );

  notar_cert( pool, slot1, hash1, 7UL );

  /* Our own skip vote plus a weak quorum notarizing hash_a makes
     hash_a safe-to-notar the instant its parent is known certified.
     hash_b has no votes, so it is merely awaiting votes. */

  ag_vote_t skip = ag_vote_construct_skip( slot2, g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &skip )==AG_POOL_SUCCESS );
  add_notar_votes( pool, slot2, hash_a, 1UL, 6UL );
  drain_events( pool );

  ag_block_id_t parent  = ag_block_id( slot1, hash1  );
  ag_block_id_t child_a = ag_block_id( slot2, hash_a );
  ag_block_id_t child_b = ag_block_id( slot2, hash_b );
  ag_pool_add_block( pool, &child_b, &parent );
  ag_pool_add_block( pool, &child_a, &parent );

  FD_TEST( drained_safe_to_notar( pool, slot2, hash_a ) );

  ag_block_id_t const * waiting = s2n_waiting_child( pool, &parent );
  FD_TEST( waiting && ag_block_id_eq( waiting, &child_b ) );

  teardown_pool( pool );
}

static void
test_handle_invalid_votes( void ) {
  ag_pool_t * pool = setup_pool();

  ag_block_hash_t gh; genesis_hash( gh );
  ag_vote_t vote = ag_vote_construct_notar( 0UL, gh, g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );

  teardown_pool( pool );
}

static void
test_hash_capacity( void ) {
  ag_pool_t * pool = setup_pool();
  ulong slot = 0UL;

  ag_block_hash_t hash[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    random_hash( hash[i] );
    ag_vote_t v = ag_vote_construct_notar( slot, hash[i], g_sk[i], (ushort)i, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
    drain_events( pool );
  }

  ag_block_hash_t nf[ AG_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<AG_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    random_hash( nf[i] );
    ag_vote_t v = ag_vote_construct_notar_fallback( slot, nf[i], g_sk[0], (ushort)0, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
    drain_events( pool );
  }

  ag_block_hash_t past; random_hash( past );
  ag_vote_t v_past;
  v_past = ag_vote_construct_notar_fallback( slot, past, g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_past )==AG_POOL_ERR_HASH_CAPACITY );
  FD_TEST( ag_pool_add_vote( pool, &v_past )==AG_POOL_ERR_HASH_CAPACITY );

  ag_vote_t v_other;
  v_other = ag_vote_construct_notar_fallback( slot, past, g_sk[1], (ushort)1, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_other )==AG_POOL_SUCCESS );

  teardown_pool( pool );
}

/* src/consensus/validated_vote.rs::unknown_signer */

static void
test_unknown_signer_votes( void ) {
  ag_pool_t * pool = setup_pool();
  ag_block_hash_t gh; genesis_hash( gh );
  ulong slot = 0UL;

  ag_epoch_info_t const * epoch = epoch_info( pool, slot );
  FD_TEST( epoch );

  ag_vote_t v1 = ag_vote_construct_notar( slot, gh, g_sk[0], (ushort)NV, TEST_SHRED_VERSION );
  FD_TEST( ag_vote_rank( &v1 )>=epoch->validator_cnt );

  ag_vote_t v2 = ag_vote_construct_skip( slot, g_sk[0], USHORT_MAX, TEST_SHRED_VERSION );
  FD_TEST( ag_vote_rank( &v2 )>=epoch->validator_cnt );

  teardown_pool( pool );
}

static void
test_wait_for_parent_ready( void ) {
  ag_pool_t * pool = setup_pool();

  ulong slot1 = SLOTS_PER_WINDOW;
  ag_block_id_t block0 = random_block_id( slot1-1UL );
  ag_block_id_t block1 = random_block_id( slot1 );
  ag_block_id_t block2 = random_block_id( slot1+1UL );

  drain_events( pool );

  ag_block_id_t parent;
  parent = ag_pool_wait_for_parent_ready( pool, slot1 );
  FD_TEST( parent.slot==ULONG_MAX );

  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote = ag_vote_construct_notar( block2.slot, block2.hash, g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }
  drain_events( pool );
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
#define EPOCH_B_LO (32UL)
#define EPOCH_B_HI (63UL)

#define HEAVY_CNT   (4UL)
#define HEAVY_STAKE (3UL)

static ag_pool_t *
setup_two_epoch_pool( ag_epoch_info_t ** out_a,
                      ag_epoch_info_t ** out_b,
                      int                install_b ) {
  create_validators();
  ulong slot_max = TEST_SLOT_MAX;

  FD_TEST( ag_pool_footprint( slot_max )<=sizeof(scratch) );
  ag_pool_t * pool = ag_pool_join( ag_pool_new( scratch, slot_max, 42UL ) );
  FD_TEST( pool );
  ag_pool_init( pool, 0UL );

  ag_validator_info_t heavy[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    heavy[ i ]       = g_info[ i ];
    heavy[ i ].stake = i<HEAVY_CNT ? HEAVY_STAKE : 1UL;
  }

  ag_epoch_info_t * a = make_epoch_info( 0UL, g_info, NV );
  ag_epoch_info_t * b = make_epoch_info( 1UL, heavy,  NV );
  FD_TEST( a->total_stake==NV );
  FD_TEST( b->total_stake==HEAVY_CNT*HEAVY_STAKE + (NV-HEAVY_CNT) );

  ag_pool_advance_epoch( pool, a, 0UL, EPOCH_A_LO );
  if( install_b ) ag_pool_advance_epoch( pool, b, 0UL, EPOCH_B_LO );

  *out_a = a; *out_b = b;
  return pool;
}

static void
test_stake_resolved_per_slot_epoch( void ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( &a, &b, 1 );

  ulong     slot_a = EPOCH_A_LO + 4UL;
  ulong     slot_b = EPOCH_B_LO + 4UL;
  ag_block_hash_t hash_a; random_hash( hash_a );
  ag_block_hash_t hash_b; random_hash( hash_b );

  add_notar_votes( pool, slot_a, hash_a, 0UL, HEAVY_CNT );
  FD_TEST( !has_notar_cert( pool, slot_a ) );

  add_notar_votes( pool, slot_b, hash_b, 0UL, HEAVY_CNT );
  FD_TEST( has_notar_cert( pool, slot_b ) );

  add_notar_votes( pool, slot_a, hash_a, HEAVY_CNT, 7UL );
  FD_TEST( has_notar_cert( pool, slot_a ) );

  teardown_pool_only( pool );
}

static void
test_epoch_boundary_slot( void ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( &a, &b, 1 );

  ag_block_hash_t hash_lo; random_hash( hash_lo );
  ag_block_hash_t hash_hi; random_hash( hash_hi );

  add_notar_votes( pool, EPOCH_B_LO-1UL, hash_lo, 0UL, HEAVY_CNT );
  FD_TEST( !has_notar_cert( pool, EPOCH_B_LO-1UL ) );

  add_notar_votes( pool, EPOCH_B_LO, hash_hi, 0UL, HEAVY_CNT );
  FD_TEST( has_notar_cert( pool, EPOCH_B_LO ) );

  teardown_pool_only( pool );
}

static void
test_epoch_installed_late( void ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( &a, &b, 0 );

  ulong           beyond = EPOCH_B_LO + 4UL;
  ag_block_hash_t hash; random_hash( hash );

  ag_vote_t v = ag_vote_construct_notar( beyond, hash, g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( epoch_info( pool, beyond )==a );
  FD_TEST( !contains_slot( pool, beyond ) );

  ag_pool_advance_epoch( pool, b, 0UL, EPOCH_B_LO );
  FD_TEST( epoch_info( pool, beyond         )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_LO-1UL )==a );
  FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
  FD_TEST( contains_slot( pool, beyond ) );

  teardown_pool_only( pool );
}

static void
test_retired_epoch_already_pruned( void ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( &a, &b, 1 );

  for( ulong s=EPOCH_A_LO+1UL; s<=EPOCH_B_LO; s++ ) {
    ag_block_hash_t hash; random_hash( hash );
    add_notar_votes( pool, s, hash, 0UL, NV );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==EPOCH_B_LO );

  FD_TEST( !contains_slot( pool, EPOCH_B_LO-1UL ) );
  FD_TEST(  contains_slot( pool, EPOCH_B_LO      ) );
  FD_TEST( pool_first_unpruned_slot( pool )==EPOCH_B_LO );
  FD_TEST( min_live_slot( pool )==EPOCH_B_LO );

  ag_epoch_info_t * c = make_epoch_info( 2UL, g_info, NV );
  ag_pool_advance_epoch( pool, c, 0UL, EPOCH_B_HI+1UL );

  FD_TEST( epoch_info( pool, EPOCH_B_LO     )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_HI+1UL )==c );
  FD_TEST( contains_slot( pool, EPOCH_B_LO ) );

  ag_vote_t v_below; ag_block_hash_t h_below; random_hash( h_below );
  v_below = ag_vote_construct_notar( EPOCH_B_LO-1UL, h_below, g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_below )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  FD_TEST( !contains_slot( pool, EPOCH_B_LO-1UL ) );

  teardown_pool_only( pool );
}

/* Firedancer-only test.

   ag_pool_init names a finalized slot straight from the block replay
   booted on, so on snapshot boot that slot has no slot state and no
   certificate behind it -- certificates only reach the pool over the
   network or from our own votor.  Standstill recovery must emit an
   empty bundle for it rather than reach through the absent state.  The
   reference cannot hit this: it always starts at genesis and asserts a
   final cert is present. */

static void
test_standstill_recovery_no_final_cert( void ) {
  ag_pool_t * pool = setup_pool(); /* ag_pool_init( pool, 0UL ), no certs */

  FD_TEST(  ag_pool_finalized_slot( pool )==0UL );
  FD_TEST( !contains_slot( pool, 0UL ) );

  ag_pool_recover_from_standstill( pool );

  ag_standstill_t const * ss = NULL;
  ulong event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==AG_EVENT_POOL_STANDSTILL ) ss = &event( i )->standstill;
  }
  FD_TEST( ss );
  FD_TEST( ss->slot    ==1UL ); /* finalized slot + 1 */
  FD_TEST( ss->cert_cnt==0UL );
  FD_TEST( ss->vote_cnt==0UL );

  teardown_pool_only( pool );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_notarize_block();
  test_skip_block();
  test_finalize_block();
  test_fast_finalize_block();
  test_finalized_block_hash();
  test_simple_branch_certified();
  test_branch_certified_notar_fallback();
  test_branch_certified_out_of_order();
  test_branch_certified_late_cert();
  test_regular_handover();
  test_one_skip_handover();
  test_two_skip_handover();
  test_skip_window_handover();
  test_pruning();
  test_duplicate_votes();
  test_duplicate_certs();
  test_out_of_bounds_votes();
  test_out_of_bounds_certs();
  test_slow_finalize_closing_gap_no_double_parent_ready();
  test_standstill_recovery();
  test_parent_ready_upon_finalization();
  test_safe_to_notar_notar_cert_only();
  test_safe_to_notar_fast_final_cert_only();
  test_safe_to_notar_awaiting_votes();
  test_safe_to_notar_not_queued_for_parent_cert();

  test_handle_invalid_votes();
  test_hash_capacity();
  test_unknown_signer_votes();
  test_wait_for_parent_ready();
  test_stake_resolved_per_slot_epoch();
  test_epoch_boundary_slot();
  test_epoch_installed_late();
  test_retired_epoch_already_pruned();
  test_standstill_recovery_no_final_cert();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
