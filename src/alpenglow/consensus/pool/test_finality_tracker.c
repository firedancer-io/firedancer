#include "fd_finality_tracker.h"

/* Ports the alpenglow/src/consensus/pool/finality_tracker.rs
   #[cfg(test)] mod tests cases (basic, no_duplicates, prune,
   prune_keeps_unresolved_gap, ignores_add_parent_below_watermark,
   no_reemit_when_parent_pruned_late) against a real fd_finality_tracker
   built in an anonymous wksp, following the test_ghost.c harness pattern. */

/* random_block_id mirrors test_utils::random_block_id(slot): a block id
   with the given slot and a pseudo-random, non-zero hash (distinct from
   the all-zero genesis hash).  We make it deterministic for reproducible
   tests. */

static fd_block_id_t
random_block_id( ulong slot ) {
  static ulong ctr = 0UL;
  fd_block_id_t b;
  b.slot = slot;
  fd_memset( &b.hash, 0, sizeof(fd_hash_t) );
  /* fill with a non-zero, unique pattern */
  b.hash.ul[0] = 0x1000UL + (++ctr);
  b.hash.ul[1] = slot ^ 0xa5a5a5a5a5a5a5a5UL;
  return b;
}

static fd_block_id_t
genesis_block_id( void ) {
  fd_block_id_t b;
  b.slot = 0UL;
  fd_memset( &b.hash, 0, sizeof(fd_hash_t) ); /* GENESIS_BLOCK_HASH = all-zero */
  return b;
}

static int
block_id_eq( fd_block_id_t const * a, fd_block_id_t const * b ) {
  return a->slot==b->slot && 0==memcmp( a->hash.uc, b->hash.uc, sizeof(fd_hash_t) );
}

/* event assertion helpers */

static void
assert_event_default( fd_finalization_event_t const * ev ) {
  FD_TEST( !ev->has_finalized );
  FD_TEST( ev->if_cnt==0UL );
  FD_TEST( ev->is_cnt==0UL );
}

static void
assert_finalized( fd_finalization_event_t const * ev, fd_block_id_t const * expected ) {
  FD_TEST( ev->has_finalized );
  FD_TEST( block_id_eq( &ev->finalized, expected ) );
}

static fd_finality_tracker_t *
setup_tracker( fd_wksp_t * wksp ) {
  ulong slot_max    = 256UL;
  ulong blockid_max = 256UL;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_finality_tracker_align(),
                                    fd_finality_tracker_footprint( slot_max, blockid_max ),
                                    42UL );
  FD_TEST( mem );
  fd_finality_tracker_t * t = fd_finality_tracker_join( fd_finality_tracker_new( mem, slot_max, blockid_max, 42UL ) );
  FD_TEST( t );
  return t;
}

static void
teardown_tracker( fd_finality_tracker_t * t ) {
  fd_wksp_free_laddr( fd_finality_tracker_delete( fd_finality_tracker_leave( t ) ) );
}

/* ---- basic --------------------------------------------------------- */

static void
test_basic( fd_wksp_t * wksp ) {
  fd_finality_tracker_t * t = setup_tracker( wksp );
  fd_finalization_event_t ev[1];

  /* slow finalize a block */
  fd_block_id_t b1 = random_block_id( 1UL );        /* genesis().next() = 1 */
  fd_finality_tracker_mark_notarized( t, &b1, ev );
  assert_event_default( ev );
  fd_finality_tracker_mark_finalized( t, b1.slot, ev );
  assert_finalized( ev, &b1 );
  FD_TEST( ev->if_cnt==0UL );
  FD_TEST( ev->is_cnt==0UL );

  /* fast finalize a block */
  fd_block_id_t b2 = random_block_id( 2UL );        /* slot1.next() = 2 */
  fd_finality_tracker_mark_fast_finalized( t, &b2, ev );
  assert_finalized( ev, &b2 );
  FD_TEST( ev->if_cnt==0UL );
  FD_TEST( ev->is_cnt==0UL );

  /* implicitly finalize a block WITHOUT skips */
  fd_block_id_t b3 = random_block_id( 3UL );        /* slot2.next() = 3 */
  fd_block_id_t b4 = random_block_id( 4UL );        /* slot3.next() = 4 */
  fd_finality_tracker_add_parent( t, &b4, &b3, ev );
  assert_event_default( ev );
  fd_finality_tracker_mark_fast_finalized( t, &b4, ev );
  assert_finalized( ev, &b4 );
  FD_TEST( ev->if_cnt==1UL && block_id_eq( &ev->implicitly_finalized[0], &b3 ) );
  FD_TEST( ev->is_cnt==0UL );

  /* implicitly finalize a block WITH skips */
  fd_block_id_t b7 = random_block_id( 7UL );        /* slot4.next().next().next() = 7 */
  fd_block_id_t b5 = random_block_id( 5UL );        /* slot7.prev().prev() = 5 */
  fd_finality_tracker_add_parent( t, &b7, &b5, ev );
  assert_event_default( ev );
  fd_finality_tracker_mark_fast_finalized( t, &b7, ev );
  assert_finalized( ev, &b7 );
  FD_TEST( ev->if_cnt==1UL && block_id_eq( &ev->implicitly_finalized[0], &b5 ) );
  FD_TEST( ev->is_cnt==1UL && ev->implicitly_skipped[0]==6UL ); /* slot7.prev() = 6 */

  teardown_tracker( t );
}

/* ---- no_duplicates ------------------------------------------------- */

static void
test_no_duplicates( fd_wksp_t * wksp ) {
  fd_finality_tracker_t * t = setup_tracker( wksp );
  fd_finalization_event_t ev[1];

  /* slow finalize + fast finalize a block */
  fd_block_id_t b1 = random_block_id( 1UL );
  fd_finality_tracker_mark_finalized( t, b1.slot, ev );
  assert_event_default( ev );
  fd_finality_tracker_mark_notarized( t, &b1, ev );
  assert_finalized( ev, &b1 );
  FD_TEST( ev->if_cnt==0UL && ev->is_cnt==0UL );
  fd_finality_tracker_mark_fast_finalized( t, &b1, ev );
  assert_event_default( ev );

  /* do NOT implicitly finalize parent, that is already directly finalized */
  fd_block_id_t b2 = random_block_id( 2UL );
  fd_block_id_t b1_parent = { .slot=1UL, .hash=b1.hash }; /* (slot2.prev(), hash1) */
  fd_finality_tracker_add_parent( t, &b2, &b1_parent, ev );
  assert_event_default( ev );
  fd_finality_tracker_mark_fast_finalized( t, &b2, ev );
  assert_finalized( ev, &b2 );
  FD_TEST( ev->if_cnt==0UL && ev->is_cnt==0UL );

  /* implicitly finalize a block WITHOUT skips */
  fd_block_id_t b4 = random_block_id( 4UL );        /* slot2.next().next() = 4 */
  fd_block_id_t b3 = random_block_id( 3UL );        /* slot4.prev() = 3 */
  fd_finality_tracker_add_parent( t, &b4, &b3, ev );
  assert_event_default( ev );
  fd_finality_tracker_mark_fast_finalized( t, &b4, ev );
  assert_finalized( ev, &b4 );
  FD_TEST( ev->if_cnt==1UL && block_id_eq( &ev->implicitly_finalized[0], &b3 ) );
  FD_TEST( ev->is_cnt==0UL );

  /* do NOT implicitly finalize parent again when adding parent again */
  fd_finality_tracker_add_parent( t, &b4, &b3, ev );
  assert_event_default( ev );

  teardown_tracker( t );
}

/* ---- prune --------------------------------------------------------- */

static void
test_prune( fd_wksp_t * wksp ) {
  fd_finality_tracker_t * t = setup_tracker( wksp );
  fd_finalization_event_t ev[1];

  /* notarize and connect (with parent relation) a chain of blocks */
  fd_block_id_t prev = genesis_block_id();
  for( ulong s=1UL; s<=6UL; s++ ) {
    fd_block_id_t block = random_block_id( s );
    fd_finality_tracker_mark_notarized( t, &block, ev );
    fd_finality_tracker_add_parent( t, &block, &prev, ev );
    prev = block;
  }

  /* finalize slot 5, implicitly finalizing its ancestors */
  ulong root = 5UL;
  fd_finality_tracker_mark_finalized( t, root, ev );
  /* this moves the watermark to slot 5 */
  FD_TEST( fd_finality_tracker_first_unpruned_slot( t )==root );

  /* only slots at or above the watermark remain */
  FD_TEST( fd_finality_tracker_status( t, root, NULL )>=0 );        /* contains root */
  FD_TEST( fd_finality_tracker_status( t, 4UL, NULL )==-1 );        /* slot 4 dropped */
  for( ulong s=0UL; s<root; s++ ) {
    FD_TEST( fd_finality_tracker_status( t, s, NULL )==-1 );        /* all below root dropped */
  }

  teardown_tracker( t );
}

/* ---- prune_keeps_unresolved_gap ------------------------------------ */

static void
test_prune_keeps_unresolved_gap( fd_wksp_t * wksp ) {
  fd_finality_tracker_t * t = setup_tracker( wksp );
  fd_finalization_event_t ev[1];

  fd_block_id_t b1 = random_block_id( 1UL );
  fd_block_id_t b2 = random_block_id( 2UL );

  /* finality cert for slot 1 without block hash */
  fd_finality_tracker_mark_finalized( t, b1.slot, ev );
  assert_event_default( ev );

  /* slot 2 receives full finalization (final + notar) */
  fd_finality_tracker_mark_notarized( t, &b2, ev );
  fd_finality_tracker_mark_finalized( t, b2.slot, ev );
  assert_finalized( ev, &b2 );
  /* cannot prune slot 1 yet */
  FD_TEST( fd_finality_tracker_highest_finalized_slot( t )==b2.slot );
  FD_TEST( fd_finality_tracker_first_unpruned_slot( t )==0UL ); /* genesis */
  FD_TEST( fd_finality_tracker_status( t, b1.slot, NULL )>=0 ); /* still contains slot 1 */

  /* can catch up once continuous chain is fully finalized */
  fd_block_id_t gen = genesis_block_id();
  fd_finality_tracker_add_parent( t, &b1, &gen, ev );
  fd_finality_tracker_mark_notarized( t, &b1, ev );
  assert_finalized( ev, &b1 );
  FD_TEST( fd_finality_tracker_first_unpruned_slot( t )==b2.slot );

  teardown_tracker( t );
}

/* ---- ignores_add_parent_below_watermark ---------------------------- */

static void
test_ignores_add_parent_below_watermark( fd_wksp_t * wksp ) {
  fd_finality_tracker_t * t = setup_tracker( wksp );
  fd_finalization_event_t ev[1];

  /* build and finalize a chain up to slot 5 to advance the watermark */
  fd_block_id_t prev = genesis_block_id();
  for( ulong s=1UL; s<=5UL; s++ ) {
    fd_block_id_t block = random_block_id( s );
    fd_finality_tracker_mark_notarized( t, &block, ev );
    fd_finality_tracker_add_parent( t, &block, &prev, ev );
    prev = block;
  }
  fd_finality_tracker_mark_finalized( t, 5UL, ev );
  FD_TEST( fd_finality_tracker_first_unpruned_slot( t )==5UL );

  /* a late block for an already-pruned slot is ignored, leaving no trace */
  fd_block_id_t stale  = random_block_id( 2UL );
  fd_block_id_t block1 = random_block_id( 1UL );
  fd_finality_tracker_add_parent( t, &stale, &block1, ev );
  assert_event_default( ev );
  FD_TEST( !fd_finality_tracker_has_parent( t, &stale ) );

  teardown_tracker( t );
}

/* ---- no_reemit_when_parent_pruned_late ----------------------------- */

static void
test_no_reemit_when_parent_pruned_late( fd_wksp_t * wksp ) {
  fd_finality_tracker_t * t = setup_tracker( wksp );
  fd_finalization_event_t ev[1];

  fd_block_id_t b0 = genesis_block_id();
  fd_block_id_t b1 = random_block_id( 1UL );
  fd_block_id_t b2 = random_block_id( 2UL );

  /* finalize slot 1 (with its parent chain) */
  fd_finality_tracker_add_parent( t, &b1, &b0, ev );
  fd_finality_tracker_mark_notarized( t, &b1, ev );
  fd_finality_tracker_mark_finalized( t, b1.slot, ev );
  assert_finalized( ev, &b1 );
  /* keeps the watermark at slot 1 */
  FD_TEST( fd_finality_tracker_first_unpruned_slot( t )==b1.slot );

  /* finalize slot 2 before its parent edge is known */
  fd_finality_tracker_mark_notarized( t, &b2, ev );
  fd_finality_tracker_mark_finalized( t, b2.slot, ev );
  assert_finalized( ev, &b2 );
  /* this prunes slot 1 */
  FD_TEST( fd_finality_tracker_first_unpruned_slot( t )==b2.slot );

  /* late parent edge must NOT re-finalize (already-pruned) slot 1 */
  fd_finality_tracker_add_parent( t, &b2, &b1, ev );
  assert_event_default( ev );

  teardown_tracker( t );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_basic( wksp );
  test_no_duplicates( wksp );
  test_prune( wksp );
  test_prune_keeps_unresolved_gap( wksp );
  test_ignores_add_parent_below_watermark( wksp );
  test_no_reemit_when_parent_pruned_late( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
