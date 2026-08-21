#include "ag_finality_tracker.h"

#define SCRATCH_MAX (1UL<<18) /* 256 KiB */

static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

static ag_block_id_t
random_block_id( ulong slot ) {
  static ulong ctr = 0UL;
  ag_block_id_t b;
  b.slot = slot;
  fd_memset( b.hash, 0, sizeof(ag_block_hash_t) );

  FD_STORE( ulong, b.hash,     0x1000UL + (++ctr) );
  FD_STORE( ulong, b.hash+8UL, slot ^ 0xa5a5a5a5a5a5a5a5UL );
  return b;
}

static ag_block_id_t
genesis_block_id( void ) {
  ag_block_id_t b;
  b.slot = 0UL;
  fd_memset( b.hash, 0, sizeof(ag_block_hash_t) );
  return b;
}

static int
block_id_eq( ag_block_id_t const * a,
             ag_block_id_t const * b ) {
  return a->slot==b->slot && 0==memcmp( a->hash, b->hash, sizeof(ag_block_hash_t) );
}

static void
assert_event_default( ag_finalization_event_t const * ev ) {
  FD_TEST( ev->finalized.slot==ULONG_MAX );
  FD_TEST( ev->implicitly_finalized_cnt==0UL );
  FD_TEST( ev->implicitly_skipped_cnt==0UL );
}

static void
assert_finalized( ag_finalization_event_t const * ev,
                  ag_block_id_t const *           expected ) {
  FD_TEST( ev->finalized.slot!=ULONG_MAX );
  FD_TEST( block_id_eq( &ev->finalized, expected ) );
}

static ag_finality_tracker_t *
setup_tracker( void ) {
  ulong slot_max = 256UL;
  FD_TEST( ag_finality_tracker_footprint( slot_max )<=sizeof(scratch) );
  ag_finality_tracker_t * t = ag_finality_tracker_join( ag_finality_tracker_new( scratch, slot_max, 42UL ) );
  FD_TEST( t );
  return t;
}

static void
teardown_tracker( ag_finality_tracker_t * t ) {
  ag_finality_tracker_delete( ag_finality_tracker_leave( t ) );
}

/* src/consensus/pool/finality_tracker.rs::basic */

static void
test_basic( void ) {
  ag_finality_tracker_t * t = setup_tracker();
  ag_finalization_event_t event;

  ag_block_id_t b1 = random_block_id( 1UL );
  event = ag_finality_tracker_mark_notarized( t, &b1 );
  assert_event_default( &event );
  event = ag_finality_tracker_mark_finalized( t, b1.slot );
  assert_finalized( &event, &b1 );
  FD_TEST( event.implicitly_finalized_cnt==0UL );
  FD_TEST( event.implicitly_skipped_cnt==0UL );

  ag_block_id_t b2 = random_block_id( 2UL );
  event = ag_finality_tracker_mark_fast_finalized( t, &b2 );
  assert_finalized( &event, &b2 );
  FD_TEST( event.implicitly_finalized_cnt==0UL );
  FD_TEST( event.implicitly_skipped_cnt==0UL );

  ag_block_id_t b3 = random_block_id( 3UL );
  ag_block_id_t b4 = random_block_id( 4UL );
  event = ag_finality_tracker_add_parent( t, &b4, &b3 );
  assert_event_default( &event );
  event = ag_finality_tracker_mark_fast_finalized( t, &b4 );
  assert_finalized( &event, &b4 );
  FD_TEST( event.implicitly_finalized_cnt==1UL && block_id_eq( &event.implicitly_finalized[0], &b3 ) );
  FD_TEST( event.implicitly_skipped_cnt==0UL );

  ag_block_id_t b7 = random_block_id( 7UL );
  ag_block_id_t b5 = random_block_id( 5UL );
  event = ag_finality_tracker_add_parent( t, &b7, &b5 );
  assert_event_default( &event );
  event = ag_finality_tracker_mark_fast_finalized( t, &b7 );
  assert_finalized( &event, &b7 );
  FD_TEST( event.implicitly_finalized_cnt==1UL && block_id_eq( &event.implicitly_finalized[0], &b5 ) );
  FD_TEST( event.implicitly_skipped_cnt==1UL && event.implicitly_skipped[0]==6UL );

  teardown_tracker( t );
}

/* src/consensus/pool/finality_tracker.rs::no_duplicates */

static void
test_no_duplicates( void ) {
  ag_finality_tracker_t * t = setup_tracker();
  ag_finalization_event_t event;

  ag_block_id_t b1 = random_block_id( 1UL );
  event = ag_finality_tracker_mark_finalized( t, b1.slot );
  assert_event_default( &event );
  event = ag_finality_tracker_mark_notarized( t, &b1 );
  assert_finalized( &event, &b1 );
  FD_TEST( event.implicitly_finalized_cnt==0UL && event.implicitly_skipped_cnt==0UL );
  event = ag_finality_tracker_mark_fast_finalized( t, &b1 );
  assert_event_default( &event );

  ag_block_id_t b2 = random_block_id( 2UL );
  ag_block_id_t b1_parent = ag_block_id( 1UL, b1.hash );
  event = ag_finality_tracker_add_parent( t, &b2, &b1_parent );
  assert_event_default( &event );
  event = ag_finality_tracker_mark_fast_finalized( t, &b2 );
  assert_finalized( &event, &b2 );
  FD_TEST( event.implicitly_finalized_cnt==0UL && event.implicitly_skipped_cnt==0UL );

  ag_block_id_t b4 = random_block_id( 4UL );
  ag_block_id_t b3 = random_block_id( 3UL );
  event = ag_finality_tracker_add_parent( t, &b4, &b3 );
  assert_event_default( &event );
  event = ag_finality_tracker_mark_fast_finalized( t, &b4 );
  assert_finalized( &event, &b4 );
  FD_TEST( event.implicitly_finalized_cnt==1UL && block_id_eq( &event.implicitly_finalized[0], &b3 ) );
  FD_TEST( event.implicitly_skipped_cnt==0UL );

  event = ag_finality_tracker_add_parent( t, &b4, &b3 );
  assert_event_default( &event );

  teardown_tracker( t );
}

/* src/consensus/pool/finality_tracker.rs::prune */

static void
test_prune( void ) {
  ag_finality_tracker_t * t = setup_tracker();

  ag_block_id_t prev = genesis_block_id();
  for( ulong s=1UL; s<=6UL; s++ ) {
    ag_block_id_t block = random_block_id( s );
    ag_finality_tracker_mark_notarized( t, &block );
    ag_finality_tracker_add_parent( t, &block, &prev );
    prev = block;
  }

  ulong root = 5UL;
  ag_finality_tracker_mark_finalized( t, root );

  FD_TEST( ag_finality_tracker_first_unpruned_slot( t )==root );

  FD_TEST( ag_finality_tracker_status( t, root, NULL )>=0 );
  FD_TEST( ag_finality_tracker_status( t, 4UL, NULL )==-1 );
  for( ulong s=0UL; s<root; s++ ) {
    FD_TEST( ag_finality_tracker_status( t, s, NULL )==-1 );
  }

  teardown_tracker( t );
}

/* src/consensus/pool/finality_tracker.rs::prune_keeps_unresolved_gap */

static void
test_prune_keeps_unresolved_gap( void ) {
  ag_finality_tracker_t * t = setup_tracker();
  ag_finalization_event_t event;

  ag_block_id_t b1 = random_block_id( 1UL );
  ag_block_id_t b2 = random_block_id( 2UL );

  event = ag_finality_tracker_mark_finalized( t, b1.slot );
  assert_event_default( &event );

  ag_finality_tracker_mark_notarized( t, &b2 );
  event = ag_finality_tracker_mark_finalized( t, b2.slot );
  assert_finalized( &event, &b2 );

  FD_TEST( ag_finality_tracker_highest_finalized_slot( t )==b2.slot );
  FD_TEST( ag_finality_tracker_first_unpruned_slot( t )==0UL );
  FD_TEST( ag_finality_tracker_status( t, b1.slot, NULL )>=0 );

  ag_block_id_t gen = genesis_block_id();
  ag_finality_tracker_add_parent( t, &b1, &gen );
  event = ag_finality_tracker_mark_notarized( t, &b1 );
  assert_finalized( &event, &b1 );
  FD_TEST( ag_finality_tracker_first_unpruned_slot( t )==b2.slot );

  teardown_tracker( t );
}

/* src/consensus/pool/finality_tracker.rs::ignores_add_parent_below_watermark */

static void
test_ignores_add_parent_below_watermark( void ) {
  ag_finality_tracker_t * t = setup_tracker();
  ag_finalization_event_t event;

  ag_block_id_t prev = genesis_block_id();
  for( ulong s=1UL; s<=5UL; s++ ) {
    ag_block_id_t block = random_block_id( s );
    ag_finality_tracker_mark_notarized( t, &block );
    ag_finality_tracker_add_parent( t, &block, &prev );
    prev = block;
  }
  ag_finality_tracker_mark_finalized( t, 5UL );
  FD_TEST( ag_finality_tracker_first_unpruned_slot( t )==5UL );

  ag_block_id_t stale  = random_block_id( 2UL );
  ag_block_id_t block1 = random_block_id( 1UL );
  event = ag_finality_tracker_add_parent( t, &stale, &block1 );
  assert_event_default( &event );
  FD_TEST( !ag_finality_tracker_has_parent( t, &stale ) );

  teardown_tracker( t );
}

/* src/consensus/pool/finality_tracker.rs::no_reemit_when_parent_pruned_late */

static void
test_no_reemit_when_parent_pruned_late( void ) {
  ag_finality_tracker_t * t = setup_tracker();
  ag_finalization_event_t event;

  ag_block_id_t b0 = genesis_block_id();
  ag_block_id_t b1 = random_block_id( 1UL );
  ag_block_id_t b2 = random_block_id( 2UL );

  ag_finality_tracker_add_parent( t, &b1, &b0 );
  ag_finality_tracker_mark_notarized( t, &b1 );
  event = ag_finality_tracker_mark_finalized( t, b1.slot );
  assert_finalized( &event, &b1 );

  FD_TEST( ag_finality_tracker_first_unpruned_slot( t )==b1.slot );

  ag_finality_tracker_mark_notarized( t, &b2 );
  event = ag_finality_tracker_mark_finalized( t, b2.slot );
  assert_finalized( &event, &b2 );

  FD_TEST( ag_finality_tracker_first_unpruned_slot( t )==b2.slot );

  event = ag_finality_tracker_add_parent( t, &b2, &b1 );
  assert_event_default( &event );

  teardown_tracker( t );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_basic();
  test_no_duplicates();
  test_prune();
  test_prune_keeps_unresolved_gap();
  test_ignores_add_parent_below_watermark();
  test_no_reemit_when_parent_pruned_late();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
