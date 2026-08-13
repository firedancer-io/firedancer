/* The pool's public surface is `trait Pool` plus its two output FIFOs; the
   point queries these tests assert on (does slot S hold a notar cert? is
   slot S still tracked at all?) are white-box, so they are reimplemented
   here over the pool's own slot-state map rather than exported.  Including
   the implementation is what makes that map reachable -- the same thing
   test_parent_ready_tracker.c does.  Nothing else in libag_alpenglow
   references an ag_pool_* symbol, so the archive's ag_pool.o is simply
   never pulled in. */

#include "ag_pool.c"
#include "ag_cert.h"

/* ---- white-box queries ---- */

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

/* Either flavour of finalization cert: the fast one, or the slow one. */

static int
has_final_cert( ag_pool_t const * pool,
                ulong             slot ) {
  slot_state_ele_t const * e = slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool );
  return e && ( e->slot_state.certificates.fast_finalize.slot!=ULONG_MAX ||
                e->slot_state.certificates.finalize.slot     !=ULONG_MAX );
}

/* contains_slot / pool_first_unpruned_slot observe pruning, which has no
   event of its own -- a shed slot state is simply gone. */

static int
contains_slot( ag_pool_t const * pool,
               ulong             slot ) {
  return slot_state_map_ele_query_const( pool->slot_states->map, &slot, NULL, pool->slot_states->pool )!=NULL;
}

/* The set the pool would score slot against: next's from its start slot up,
   else curr's.  The same resolution slot_state() does, which the pool no
   longer exposes -- its owner resolves off the window it installed. */

static ag_epoch_info_t const *
epoch_info( ag_pool_t const * pool,
            ulong             slot ) {
  return fd_ptr_if( slot>=pool->next_epoch_slot, pool->next_epoch_info, pool->curr_epoch_info );
}

static ulong
pool_first_unpruned_slot( ag_pool_t const * pool ) {
  return ag_finality_tracker_first_unpruned_slot( pool->finality_tracker );
}

/* The watermark is only a bound on the live slot states if pruning really
   did shed everything below it -- the property an epoch may only be
   retired on, since a state left below the window holds an
   ag_epoch_info_t the caller is about to recycle.  Nothing checks it at
   runtime, so the tests walk the map, which costs nothing here.
   ULONG_MAX when no state is live, which passes trivially. */

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

/* The invariant every pruning checkpoint below asserts: no live slot
   state sits below the watermark. */

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

/* The pool's two output FIFOs, wrapped back into the pop / discard shapes
   these tests were written against. */

static int
votor_event_pop( ag_pool_t *       pool,
                 ag_pool_event_t * out ) {
  if( FD_UNLIKELY( votor_event_channel_empty( pool->votor_event_channel ) ) ) return 0;
  *out = votor_event_channel_pop( pool->votor_event_channel );
  return 1;
}

static void
drain_channels( ag_pool_t * pool ) {
  votor_event_channel_remove_all( pool->votor_event_channel );
  repair_channel_remove_all     ( pool->repair_channel      );
}

#define SLOTS_PER_WINDOW AG_SLOTS_PER_WINDOW
#define SLOTS_PER_EPOCH  AG_SLOTS_PER_EPOCH
#define NV               (11UL)

/* A slot state is ~3 MiB, so the pools these tests build are kept small;
   64 live slots is ample for every case here. */
#define TEST_SLOT_MAX    (64UL)

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

/* The pool emits events / repair requests onto internal FIFOs that the
   caller drains.  The queue is pop-only, so take_events empties it into
   g_event and returns the count; event( i ) then reads the snapshot as
   many times as a test likes.  drain_channels discards instead,
   opening a fresh observation window -- exactly as the votor tile leaves
   the queues empty after each after_credit. */

/* g_event takes a whole drain at once, so it is sized the way the pool
   sizes the channel itself, at the slot_max these tests build with. */

#define TEST_EVENT_MAX (AG_POOL_EVENTS_PER_SLOT*TEST_SLOT_MAX)

static ag_pool_event_t g_event[ TEST_EVENT_MAX ];

static ulong
take_events( ag_pool_t * pool ) {
  ulong cnt = 0UL;
  while( cnt<TEST_EVENT_MAX && votor_event_pop( pool, &g_event[ cnt ] ) ) cnt++;
  FD_TEST( votor_event_channel_empty( pool->votor_event_channel ) ); /* g_event held the whole drain */
  return cnt;
}

static ag_pool_event_t const *
event( ulong i ) {
  return &g_event[ i ];
}

/* The pool holds caller-owned ag_epoch_info_t, one per epoch in its
   window; make_epoch_info formats one in the wksp from a validator set.
   Callers keep the pointer alive for as long as it stays installed. */

static ag_epoch_info_t *
make_epoch_info( fd_wksp_t *                 wksp,
                 ag_validator_info_t const * info,
                 ulong                       cnt ) {
  ag_epoch_info_t * ei = fd_wksp_alloc_laddr( wksp, alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t), 42UL );
  FD_TEST( ei );
  ag_epoch_info_init( ei, info, cnt );
  return ei;
}

/* The default single-epoch window: one epoch spanning every slot the
   tests touch, so existing cases behave exactly as they did when the
   pool carried one global validator set. */

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
  ag_pool_set_root( pool, 0UL, NULL );

  g_epoch_info = make_epoch_info( wksp, g_info, NV );
  ag_pool_set_epoch( pool, g_epoch_info, 0UL, 0UL ); /* curr, and with no next it answers for every slot the tests touch */
  return pool;
}

/* Frees the pool but not any epoch info; for tests that own their own
   epoch window. */

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

/* notar_cert / drained_safe_to_notar have no ag_pool counterpart -- they
   are the reference's test-context methods of the same names, which exist
   only in its #[cfg(test)] impl. */

static void
notar_cert( ag_pool_t *       pool,
            ulong             slot,
            fd_hash_t const * hash,
            ulong             signers ) {
  FD_TEST( signers<=NV );
  ag_notar_vote_t nv[ NV ];
  for( ulong v=0UL; v<signers; v++ ) ag_notar_vote_new( &nv[v], slot, hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_NOTAR;
  FD_TEST( ag_notar_cert_try_new( &c.inner.notar, nv, signers, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
  drain_channels( pool );
}

static int
drained_safe_to_notar( ag_pool_t *       pool,
                       ulong             slot,
                       fd_hash_t const * hash ) {
  ulong cnt = take_events( pool );
  for( ulong i=0UL; i<cnt; i++ ) {
    ag_pool_event_t const * e = event( i );
    if( e->kind!=AG_POOL_EVENT_SAFE_TO_NOTAR ) continue;
    if( e->inner.safe_to_notar.slot==slot &&
        !memcmp( e->inner.safe_to_notar.hash.uc, hash->uc, sizeof(fd_hash_t) ) ) return 1;
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
  FD_TEST( ag_fast_final_cert_try_new( &c.inner.fast_final, nv, NV, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_SUCCESS );
  drain_channels( pool );
}

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
  FD_TEST( is_parent_ready( pool, next, &parent ) );

  teardown_pool( pool );
}

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

  /* Undecided slots pile up ABOVE the watermark, which must not move. */
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

  FD_TEST( ag_pool_add_cert( pool, &notar )==AG_POOL_ERR_DUPLICATE );
  FD_TEST( ag_pool_add_cert( pool, &skip  )==AG_POOL_ERR_DUPLICATE );

  teardown_pool( pool );
}

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
    drain_channels( pool );
  }
  FD_TEST( pool_first_unpruned_slot( pool )==slot );

  for( ulong s=0UL; s<3UL*SLOTS_PER_WINDOW-1UL; s++ ) {
    ag_skip_vote_t sv[ NV ];
    for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], s, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    ag_cert_t c; c.kind = AG_CERT_TYPE_SKIP;
    FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==AG_CERT_SUCCESS );
    FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  }

  ulong future = 3UL*SLOTS_PER_EPOCH;
  ag_skip_vote_t sv[ NV ];
  for( ulong v=0UL; v<NV; v++ ) ag_skip_vote_new( &sv[v], future, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
  ag_cert_t c; c.kind = AG_CERT_TYPE_SKIP;
  FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, NV, NULL, 0UL, g_info, NV )==AG_CERT_SUCCESS );
  FD_TEST( ag_pool_add_cert( pool, &c )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );

  teardown_pool( pool );
}

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

  /* The finalized slot has run ahead of the watermark the gap pins down.
     Pruning must follow the watermark, not the finalized slot: the states
     between them are still needed. */
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
  ulong event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==AG_POOL_EVENT_STANDSTILL ) { found_standstill = 1; ss_slot = event( i )->inner.standstill; }
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

  drain_channels( pool );

  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, block2.slot, &block2.hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  ulong cert_created = 0UL, parent_ready_cnt = 0UL;
  ulong event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==AG_POOL_EVENT_CERT_CREATED ) cert_created++;
    if( event( i )->kind==AG_POOL_EVENT_PARENT_READY ) parent_ready_cnt++;
  }
  FD_TEST( cert_created==3UL );
  FD_TEST( parent_ready_cnt==0UL );

  drain_channels( pool );
  ag_pool_add_block( pool, &block2, &block1 );
  ag_pool_add_block( pool, &block1, &block0 );

  int found = 0;
  event_cnt = take_events( pool );
  for( ulong i=0UL; i<event_cnt; i++ ) {
    if( event( i )->kind==AG_POOL_EVENT_PARENT_READY ) {
      FD_TEST( event( i )->inner.parent_ready.slot==slot1 );
      FD_TEST( ag_block_id_eq( &event( i )->inner.parent_ready.parent, &block0 ) );
      found = 1;
    }
  }
  FD_TEST( found );

  teardown_pool( pool );
}

/* The two cases below drive safe-to-notar through a parent whose only
   evidence is a RECEIVED cert -- no votes for the parent ever reach the
   pool -- so they cover the add_cert -> s2n_waiting_parent_cert ->
   notify_parent_certified path end to end, which the slot-state tests only
   reach one level down.

   The child's votes are added inline rather than through add_skip_votes /
   add_notar_votes: those drain after every vote, which would discard the
   very event being asserted on. */

static void
test_safe_to_notar_notar_cert_only( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_hash_t hash1 = random_hash();
  fd_hash_t hash2 = random_hash();

  /* parent (slot1) is notarized only via a received notar cert */
  notar_cert( pool, slot1, &hash1, 7UL );

  /* register the child block */
  ag_block_id_t child  = { .slot = slot2, .hash = hash2 };
  ag_block_id_t parent = { .slot = slot1, .hash = hash1 };
  ag_pool_add_block( pool, &child, &parent );
  drain_channels( pool );

  /* we skip slot2, but 40% of others notarize the child */
  ag_vote_t skip; ag_vote_new_skip( &skip, slot2, &g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &skip )==AG_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot2, &hash2, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  /* child should now be safe-to-notar */
  FD_TEST( drained_safe_to_notar( pool, slot2, &hash2 ) );

  teardown_pool( pool );
}

static void
test_safe_to_notar_fast_final_cert_only( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong     slot1 = 1UL;
  ulong     slot2 = 2UL;
  fd_hash_t hash1 = random_hash();
  fd_hash_t hash2 = random_hash();

  /* parent (slot1) is fast-finalized only via a received cert.  The
     reference signs this one with 9 of 11; fast_finalize signs with all
     of them, and both clear the strong quorum this test needs. */
  fast_finalize( pool, slot1, &hash1 );

  /* register the child block */
  ag_block_id_t child  = { .slot = slot2, .hash = hash2 };
  ag_block_id_t parent = { .slot = slot1, .hash = hash1 };
  ag_pool_add_block( pool, &child, &parent );
  drain_channels( pool );

  /* we skip slot2, but 40% of others notarize the child */
  ag_vote_t skip; ag_vote_new_skip( &skip, slot2, &g_sk[0], 0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &skip )==AG_POOL_SUCCESS );
  for( ulong v=1UL; v<6UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, slot2, &hash2, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }

  /* child should now be safe-to-notar */
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

/* A slot's per-hash stake tallies have room for every vote it can admit --
   a notar vote per rank, AG_NOTAR_FALLBACK_VOTE_MAX notar-fallback votes
   per rank -- so a distinct hash in every vote does NOT exhaust them.
   What a vote can hit is the per-rank notar-fallback cap, and that is the
   one way HASH_CAPACITY reaches a caller. */

static void
test_hash_capacity( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );
  ulong slot = 0UL;

  /* Every rank names a hash of its own: NV entries in the notar tally,
     all admitted. */
  fd_hash_t hash[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    hash[i] = random_hash();
    ag_vote_t v; ag_vote_new_notar( &v, slot, &hash[i], &g_sk[i], (ushort)i, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
    drain_channels( pool );
  }

  /* Rank 0 spends its notar-fallback votes, again on hashes of its own. */
  fd_hash_t nf[ AG_NOTAR_FALLBACK_VOTE_MAX ];
  for( ulong i=0UL; i<AG_NOTAR_FALLBACK_VOTE_MAX; i++ ) {
    nf[i] = random_hash();
    ag_vote_t v; ag_vote_new_notar_fallback( &v, slot, &nf[i], &g_sk[0], (ushort)0, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
    drain_channels( pool );
  }

  /* One past its cap: rejected, and rejected before any mutation, so a
     re-submission is still a capacity miss and not a duplicate. */
  fd_hash_t past = random_hash();
  ag_vote_t v_past;
  ag_vote_new_notar_fallback( &v_past, slot, &past, &g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_past )==AG_POOL_ERR_HASH_CAPACITY );
  FD_TEST( ag_pool_add_vote( pool, &v_past )==AG_POOL_ERR_HASH_CAPACITY );

  /* The cap is the rank's, not the slot's: another rank still gets in,
     with the very hash rank 0 was turned away for. */
  ag_vote_t v_other;
  ag_vote_new_notar_fallback( &v_other, slot, &past, &g_sk[1], (ushort)1, TEST_SHRED_VERSION );
  FD_TEST( ag_pool_add_vote( pool, &v_other )==AG_POOL_SUCCESS );

  teardown_pool( pool );
}

/* An out-of-range signer is the CALLER's to reject -- validated_vote in
   fd_votor_tile.c, the ValidatedVote::try_new analogue.  ag_pool_add_vote
   indexes the validator set with no bounds check, so handing it either of
   these would be a fault, not an error return.  Assert the gate's
   predicate instead. */

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

/* wait_for_parent_ready is the ParentReady event's other face: nothing to
   report until the parent lands, then the one parent to build on. */

static void
test_wait_for_parent_ready( fd_wksp_t * wksp ) {
  ag_pool_t * pool = setup_pool( wksp );

  ulong slot1 = SLOTS_PER_WINDOW;
  ag_block_id_t block0 = random_block_id( slot1-1UL );
  ag_block_id_t block1 = random_block_id( slot1 );
  ag_block_id_t block2 = random_block_id( slot1+1UL );

  drain_channels( pool );

  /* Nothing has notarized below the window, so there is no parent yet and
     the caller has to fall back on the event. */
  ag_block_id_t parent;
  FD_TEST( !ag_pool_wait_for_parent_ready( pool, slot1, &parent ) );

  for( ulong v=0UL; v<11UL; v++ ) {
    ag_vote_t vote; ag_vote_new_notar( &vote, block2.slot, &block2.hash, &g_sk[v], (ushort)v, TEST_SHRED_VERSION );
    FD_TEST( ag_pool_add_vote( pool, &vote )==AG_POOL_SUCCESS );
  }
  drain_channels( pool );
  ag_pool_add_block( pool, &block2, &block1 );
  ag_pool_add_block( pool, &block1, &block0 );

  /* Same answer the ParentReady event carried, and the same one
     parents_ready lists -- it is the pick, not a second source. */
  FD_TEST( ag_pool_wait_for_parent_ready( pool, slot1, &parent ) );
  FD_TEST( ag_block_id_eq( &parent, &block0 ) );

  ulong                 cnt   = 0UL;
  ag_block_id_t const * ready = ag_pool_parents_ready( pool, slot1, &cnt );
  FD_TEST( cnt==1UL );
  FD_TEST( ag_block_id_eq( &ready[0], &parent ) );

  /* Asking registers nothing, so asking again gives the same answer. */
  ag_block_id_t again;
  FD_TEST( ag_pool_wait_for_parent_ready( pool, slot1, &again ) );
  FD_TEST( ag_block_id_eq( &again, &parent ) );

  teardown_pool( pool );
}

/* ---- per-slot epoch resolution ----

   The pool must score a vote against the epoch containing THAT VOTE'S
   SLOT (Agave: Bank::epoch_stakes_from_slot), not against one globally
   current set.  These build a curr/next window whose two epochs share
   the rank->validator mapping but NOT the stake distribution, which is
   the case that fails silently if resolution is global: the BLS
   signature verifies either way, so a mis-resolved vote is counted
   rather than rejected. */

/* Start slots only: A runs [0,64), B runs [64,128), and B's start slot
   is what ends A. */

#define EPOCH_A_LO (0UL)
#define EPOCH_B_LO (64UL)
#define EPOCH_B_HI (127UL)

/* Both epochs hold the same 11 ranks, so any vote's signature verifies
   against either set -- only the stake weights differ:

     epoch A  all ranks stake 1            total 11, quorum needs >=6.6
     epoch B  ranks 0-3 stake 3, rest 1    total 19, quorum needs >=11.4

   So notar votes from ranks 0..3 are 12/19 (a quorum) in B and 4/11
   (not even a weak quorum) in A. */

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
  ag_pool_set_root( pool, 0UL, NULL );

  ag_validator_info_t heavy[ NV ];
  for( ulong i=0UL; i<NV; i++ ) {
    heavy[ i ]       = g_info[ i ];
    heavy[ i ].stake = i<HEAVY_CNT ? HEAVY_STAKE : 1UL;
  }

  ag_epoch_info_t * a = make_epoch_info( wksp, g_info, NV );
  ag_epoch_info_t * b = make_epoch_info( wksp, heavy,  NV );
  FD_TEST( a->total_stake==NV );
  FD_TEST( b->total_stake==HEAVY_CNT*HEAVY_STAKE + (NV-HEAVY_CNT) ); /* 19 */

  /* A is the bottom of the window.  Without B there is no upper bound on
     it, so an install_b=0 pool answers for B's slots with A's set. */
  ag_pool_set_epoch( pool, a, 0UL, EPOCH_A_LO );
  if( install_b ) ag_pool_set_epoch( pool, b, 0UL, EPOCH_B_LO );

  *out_a = a; *out_b = b;
  return pool;
}

/* The same four ranks clear the quorum in epoch B and fall well short in
   epoch A.  Both slots live in one pool instance, so the only thing that
   can distinguish them is the slot -> epoch resolution. */

static void
test_stake_resolved_per_slot_epoch( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 1 );

  ulong     slot_a = EPOCH_A_LO + 4UL;
  ulong     slot_b = EPOCH_B_LO + 4UL;
  fd_hash_t hash_a = random_hash();
  fd_hash_t hash_b = random_hash();

  /* 4/11 in epoch A: no cert. */
  add_notar_votes( pool, slot_a, &hash_a, 0UL, HEAVY_CNT );
  FD_TEST( !has_notar_cert( pool, slot_a ) );

  /* The same four ranks are 12/19 in epoch B: cert.  Resolving globally
     would make this slot agree with slot_a, whichever set won. */
  add_notar_votes( pool, slot_b, &hash_b, 0UL, HEAVY_CNT );
  FD_TEST( has_notar_cert( pool, slot_b ) );

  /* Converse: epoch A reaches its own quorum at 7/11, a count that is
     still short of epoch B's 11.4. */
  add_notar_votes( pool, slot_a, &hash_a, HEAVY_CNT, 7UL );
  FD_TEST( has_notar_cert( pool, slot_a ) );

  teardown_pool_only( pool );
  fd_wksp_free_laddr( a ); fd_wksp_free_laddr( b );
}

/* The two start slots partition the window: the slot just below
   next_epoch_slot is curr's, the slot at it is next's.  The same four
   ranks straddle the quorum across that single-slot step. */

static void
test_epoch_boundary_slot( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 1 );

  fd_hash_t hash_lo = random_hash();
  fd_hash_t hash_hi = random_hash();

  add_notar_votes( pool, EPOCH_B_LO-1UL, &hash_lo, 0UL, HEAVY_CNT ); /* 4/11 in A */
  FD_TEST( !has_notar_cert( pool, EPOCH_B_LO-1UL ) );

  add_notar_votes( pool, EPOCH_B_LO, &hash_hi, 0UL, HEAVY_CNT );     /* 12/19 in B */
  FD_TEST( has_notar_cert( pool, EPOCH_B_LO ) );

  teardown_pool_only( pool );
  fd_wksp_free_laddr( a ); fd_wksp_free_laddr( b );
}

/* An epoch installed after the one below it takes its slots over from
   that moment on.  Until it lands there is nothing bounding curr from
   above -- a next is only ever named together with its set -- so curr
   answers for those slots in the meantime. */

static void
test_epoch_installed_late( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 0 );

  ulong     beyond = EPOCH_B_LO + 4UL;
  fd_hash_t hash   = random_hash();

  /* A curr-only window has no upper bound, so B's slots are A's. */
  ag_vote_t v; ag_vote_new_notar( &v, beyond, &hash, &g_sk[0], (ushort)0, TEST_SHRED_VERSION );
  FD_TEST( epoch_info( pool, beyond )==a );
  FD_TEST( !contains_slot( pool, beyond ) );

  /* Installing B takes the window's empty next and, with it, every slot
     from B's start up.  A keeps everything below. */
  ag_pool_set_epoch( pool, b, 0UL, EPOCH_B_LO );
  FD_TEST( epoch_info( pool, beyond         )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_LO-1UL )==a );
  FD_TEST( ag_pool_add_vote( pool, &v )==AG_POOL_SUCCESS );
  FD_TEST( contains_slot( pool, beyond ) );

  teardown_pool_only( pool );
  fd_wksp_free_laddr( a ); fd_wksp_free_laddr( b );
}

/* Retiring an epoch is legal only once finalization has pruned past it --
   set_epoch asserts that rather than shedding whatever is left, see the
   precondition on it.  Finalizing straight through B's start slot is what
   makes the rotation below legal: it sheds every A slot and leaves a
   single live state, B's own. */

static void
test_retired_epoch_already_pruned( fd_wksp_t * wksp ) {
  ag_epoch_info_t * a; ag_epoch_info_t * b;
  ag_pool_t * pool = setup_two_epoch_pool( wksp, &a, &b, 1 );

  /* Unanimous notar votes fast-finalize each slot as it is added, so the
     finalized slot tracks the loop and pruning follows it up.  Slots from
     EPOCH_B_LO on resolve to B, where these same 11 ranks carry all 19
     stake. */
  for( ulong s=EPOCH_A_LO+1UL; s<=EPOCH_B_LO; s++ ) {
    fd_hash_t hash = random_hash();
    add_notar_votes( pool, s, &hash, 0UL, NV );
  }
  FD_TEST( ag_pool_finalized_slot( pool )==EPOCH_B_LO );

  /* Pruning keeps the finalized slot itself and nothing below it, so the
     one surviving state is B's -- which is what makes retiring A legal. */
  FD_TEST( !contains_slot( pool, EPOCH_B_LO-1UL ) );
  FD_TEST(  contains_slot( pool, EPOCH_B_LO      ) );
  FD_TEST( pool_first_unpruned_slot( pool )==EPOCH_B_LO );
  FD_TEST( min_live_slot( pool )==EPOCH_B_LO );

  /* Advance the window to {B, C}, retiring A: B rotates out of next and
     into curr, and C lands in the next it vacated.  Legal precisely
     because A has no slot state left for the rotation to strand. */
  ag_epoch_info_t * c = make_epoch_info( wksp, g_info, NV );
  ag_pool_set_epoch( pool, c, 0UL, EPOCH_B_HI+1UL );

  FD_TEST( epoch_info( pool, EPOCH_B_LO     )==b );
  FD_TEST( epoch_info( pool, EPOCH_B_HI+1UL )==c );
  FD_TEST( contains_slot( pool, EPOCH_B_LO ) );

  /* A is out of the window, so its info is free to be recycled -- and
     nothing can bring one of its slots back: the watermark, not the epoch
     resolution, is what turns a vote for one away. */
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

  /* normal pages, like the sibling pool/votor tests: the suite must run
     without reserved huge pages */
  ulong  page_cnt  = 131072;
  char * _page_sz  = "normal";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* pool.rs, in its order */
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

  /* no reference counterpart */
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
