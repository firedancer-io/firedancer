#include "ag_parent_ready_tracker.c"

#define SCRATCH_MAX (1UL<<18) /* 256 KiB */

#define TEST_SLOT_MAX (256UL)

#define SLOTS_PER_WINDOW AG_SLOTS_PER_WINDOW

static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

FD_FN_CONST static inline ulong
last_slot_in_window( ulong slot ) {
  return ag_first_slot_in_window( slot ) + AG_SLOTS_PER_WINDOW - 1UL;
}

static ag_block_id_t
random_block_id( ulong slot ) {
  ag_block_id_t id;
  id.slot = slot;
  fd_memset( id.hash, (int)( ( slot & 0xffUL ) | 0x40UL ), sizeof(ag_block_hash_t) );
  return id;
}

static ag_block_id_t
genesis_block_id( void ) {
  ag_block_id_t id;
  id.slot = 0UL;
  fd_memset( id.hash, 0, sizeof(ag_block_hash_t) );
  return id;
}

static void
state_init( ag_parent_ready_state_t * state,
            ulong                     slot ) {
  state->slot                = slot;
  state->skip                = 0;
  state->notar_fallbacks_cnt = (uchar)0;
  state->is_ready            = 0;
  state->ready_id_cnt        = 0UL;
}

static ag_parent_ready_tracker_t *
setup_tracker( ulong slot_max ) {
  FD_TEST( ag_parent_ready_tracker_footprint( slot_max )<=sizeof(scratch) );
  ag_parent_ready_tracker_t * tracker = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( scratch, slot_max, 42UL ) );
  FD_TEST( tracker );

  ag_parent_ready_state_t * genesis = ag_parent_ready_state_pool_ele_acquire( tracker->states.pool );
  state_init( genesis, 0UL );
  fd_memset( genesis->notar_fallbacks[0], 0, sizeof(ag_block_hash_t) );
  genesis->notar_fallbacks_cnt = (uchar)1;
  ag_parent_ready_state_map_ele_insert( tracker->states.map, genesis, tracker->states.pool );
  tracker->root = 0UL;

  return tracker;
}

static void
teardown_tracker( ag_parent_ready_tracker_t * tracker ) {
  ag_parent_ready_tracker_delete( ag_parent_ready_tracker_leave( tracker ) );
}

static int
out_contains( ag_parent_ready_t const * out,
              ulong                     cnt,
              ulong                     slot,
              ag_block_id_t const *     id ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( out[i].slot==slot && ag_block_id_eq( &out[i].parent, id ) ) return 1;
  }
  return 0;
}

/* src/types/slot.rs::basic */

static void
test_slot_windows( void ) {
  for( ulong window=0UL; window<9UL; window++ ) {
    ulong first_slot = window*AG_SLOTS_PER_WINDOW;
    FD_TEST( ag_is_start_of_window( first_slot ) );
    FD_TEST( ag_first_slot_in_window( first_slot )==first_slot );

    ulong last_slot  = last_slot_in_window( first_slot );
    ulong next_first = (window+1UL)*AG_SLOTS_PER_WINDOW;
    FD_TEST( last_slot+1UL==next_first );
    FD_TEST( last_slot==next_first-1UL );

    for( ulong s=first_slot; s<=last_slot; s++ ) {
      FD_TEST( ag_first_slot_in_window( s )==first_slot );
      FD_TEST( last_slot_in_window ( s )==last_slot  );
      FD_TEST( ag_is_start_of_window( s )==( s==first_slot ) );
    }
  }
}

/* src/consensus/pool/parent_ready_tracker/parent_ready_state.rs::wait_for_parent_ready_no_blocking */

static void
test_state_wait_no_blocking( void ) {
  ag_parent_ready_state_t state[1];
  state_init( state, 1UL );

  ulong cnt;
  cnt = state->ready_id_cnt;
  FD_TEST( cnt==0UL );

  ag_block_id_t block_id = random_block_id( 1UL );
  add_to_ready( state, &block_id );

  ag_block_id_t recv = wait_for_parent_ready( state );
  FD_TEST( recv.slot!=ULONG_MAX );
  FD_TEST( ag_block_id_eq( &recv, &block_id ) );

  cnt = state->ready_id_cnt;
  FD_TEST( cnt==1UL );
}

/* src/consensus/pool/parent_ready_tracker/parent_ready_state.rs::wait_for_parent_ready_blocking */

static void
test_state_wait_blocking_sync( void ) {
  ag_parent_ready_state_t state[1];
  state_init( state, 1UL );

  ulong cnt;
  cnt = state->ready_id_cnt;
  FD_TEST( cnt==0UL );

  ag_block_id_t recv = wait_for_parent_ready( state );
  FD_TEST( recv.slot==ULONG_MAX );

  ag_block_id_t block_id = random_block_id( 1UL );
  add_to_ready( state, &block_id );

  recv = wait_for_parent_ready( state );
  FD_TEST( recv.slot!=ULONG_MAX );
  FD_TEST( ag_block_id_eq( &recv, &block_id ) );

  cnt = state->ready_id_cnt;
  FD_TEST( cnt==1UL );
}

/* src/consensus/pool/parent_ready_tracker.rs::basic */

static void
test_basic( void ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  for( ulong s=1UL; s<=2UL*SLOTS_PER_WINDOW; s++ ) {
    ag_block_id_t block = random_block_id( s );
    ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
    if( s==last_slot_in_window( s ) ) {
      FD_TEST( out_contains( out, out_cnt, s+1UL, &block ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::genesis */

static void
test_genesis( void ) {
  ag_block_id_t genesis = genesis_block_id();
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  for( ulong slot=0UL; slot<SLOTS_PER_WINDOW; slot++ ) {
    ag_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
    if( slot==last_slot_in_window( slot ) ) {
      FD_TEST( out_contains( out, out_cnt, slot+1UL, &genesis ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::skips */

static void
test_skips( void ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  ag_block_id_t block   = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) {
    ag_parent_ready_tracker_mark_skipped( tracker, s, out, &out_cnt );
    if( s==last_slot_in_window( s ) ) {
      FD_TEST( out_contains( out, out_cnt, s+1UL, &block   ) );
      FD_TEST( out_contains( out, out_cnt, s+1UL, &genesis ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::out_of_order_skips */

static void
test_out_of_order_skips( void ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  ag_block_id_t block   = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  ag_parent_ready_tracker_mark_skipped( tracker, 3UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  ag_parent_ready_tracker_mark_skipped( tracker, 2UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block ) );

  ag_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &genesis ) );

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::out_of_order_notars */

static void
test_out_of_order_notars( void ) {
  ag_block_id_t block1 = random_block_id( 1UL );
  ag_block_id_t block2 = random_block_id( 2UL );
  ag_block_id_t block3 = random_block_id( 3UL );
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block2, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block3, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block3 ) );

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block1, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::no_double_counting_skip_chain */

static void
test_no_double_counting_skip_chain( void ) {
  ulong         slot  = 1UL;
  ag_block_id_t block = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  ag_parent_ready_tracker_mark_skipped( tracker, 2UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  ag_parent_ready_tracker_mark_skipped( tracker, 3UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block ) );

  ag_parent_ready_tracker_mark_skipped( tracker, 4UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  ag_parent_ready_tracker_mark_skipped( tracker, 5UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  ag_parent_ready_tracker_mark_skipped( tracker, 6UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  ag_parent_ready_tracker_mark_skipped( tracker, 7UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==8UL && ag_block_id_eq( &out[0].parent, &block ) );

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::no_double_counting_notar_and_skip */

static void
test_no_double_counting_notar_and_skip( void ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  ag_block_id_t block   = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  ag_parent_ready_tracker_mark_skipped( tracker, 2UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  ag_parent_ready_tracker_mark_skipped( tracker, 3UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block ) );

  ag_parent_ready_tracker_mark_skipped( tracker, 1UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &genesis ) );

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::wait_for_parent_ready */

static void
test_wait_for_parent_ready( void ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong window1 = 0UL;
  ulong window2 = 1UL*SLOTS_PER_WINDOW;
  ulong window3 = 2UL*SLOTS_PER_WINDOW;
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong             out_cnt;

  for( ulong slot=window1; slot<window1+SLOTS_PER_WINDOW; slot++ ) {
    if( slot==0UL ) continue;
    ag_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  }

  ag_block_id_t got;
  got = ag_parent_ready_tracker_wait_for_parent_ready( tracker, window2 );
  FD_TEST( got.slot!=ULONG_MAX );
  FD_TEST( ag_block_id_eq( &got, &genesis ) );

  got = ag_parent_ready_tracker_wait_for_parent_ready( tracker, window3 );
  FD_TEST( got.slot==ULONG_MAX );

  for( ulong slot=window2; slot<window2+SLOTS_PER_WINDOW; slot++ ) {
    ag_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  }

  got = ag_parent_ready_tracker_wait_for_parent_ready( tracker, window3 );
  FD_TEST( got.slot!=ULONG_MAX );
  FD_TEST( ag_block_id_eq( &got, &genesis ) );

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::parent_ready_finalized */

static void
test_parent_ready_finalized( void ) {
  ulong window2 = 1UL*SLOTS_PER_WINDOW;
  ulong window3 = 2UL*SLOTS_PER_WINDOW;
  ulong window4 = 3UL*SLOTS_PER_WINDOW;
  ulong window5 = 4UL*SLOTS_PER_WINDOW;
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  {
    ag_block_id_t block  = random_block_id( window2 );
    ag_block_id_t parent = random_block_id( block.slot-1UL );

    ag_block_id_t implicitly_finalized[1] = { parent };

    ag_finalization_event_t ev = { .finalized = block,
                                   .implicitly_finalized_cnt = 1UL, .implicitly_finalized = implicitly_finalized };

    ag_parent_ready_t readys[ TEST_SLOT_MAX ]; ulong readys_cnt;
    ag_parent_ready_t out = ag_parent_ready_tracker_handle_finalization( tracker, &ev, readys, &readys_cnt );
    FD_TEST( out.slot==block.slot );
    FD_TEST( ag_block_id_eq( &out.parent, &parent ) );
  }

  {
    ag_block_id_t block  = random_block_id( window4 );
    ag_block_id_t parent = random_block_id( window3-1UL );

    ag_block_id_t implicitly_finalized[1] = { parent };
    ulong         implicitly_skipped[ SLOTS_PER_WINDOW ];
    for( ulong i=0UL; i<SLOTS_PER_WINDOW; i++ ) implicitly_skipped[i] = window3+i;

    ag_finalization_event_t ev = { .finalized = block,
                                   .implicitly_finalized_cnt = 1UL,              .implicitly_finalized = implicitly_finalized,
                                   .implicitly_skipped_cnt   = SLOTS_PER_WINDOW, .implicitly_skipped   = implicitly_skipped };

    ag_parent_ready_t readys[ TEST_SLOT_MAX ]; ulong readys_cnt;
    ag_parent_ready_t out = ag_parent_ready_tracker_handle_finalization( tracker, &ev, readys, &readys_cnt );
    FD_TEST( out.slot==block.slot );
    FD_TEST( ag_block_id_eq( &out.parent, &parent ) );
  }

  {
    ag_block_id_t block         = random_block_id( window5+1UL );
    ag_block_id_t parent        = random_block_id( block.slot-1UL );
    ag_block_id_t parent_parent = random_block_id( parent.slot-1UL );

    ag_block_id_t implicitly_finalized[2] = { parent, parent_parent };

    ag_finalization_event_t ev = { .finalized = block,
                                   .implicitly_finalized_cnt = 2UL, .implicitly_finalized = implicitly_finalized };

    ag_parent_ready_t readys[ TEST_SLOT_MAX ]; ulong readys_cnt;
    ag_parent_ready_t out = ag_parent_ready_tracker_handle_finalization( tracker, &ev, readys, &readys_cnt );
    FD_TEST( out.slot==parent.slot );
    FD_TEST( ag_block_id_eq( &out.parent, &parent_parent ) );
  }

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::prune */

static void
test_prune( void ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong             out_cnt;

  for( ulong slot=1UL; slot<=2UL*SLOTS_PER_WINDOW; slot++ ) {
    ag_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  }

  ulong new_root = SLOTS_PER_WINDOW;

  int below = 0, at = 0;
  {
    ag_parent_ready_state_map_t *             map  = tracker->states.map;
    ag_parent_ready_state_t * pool = tracker->states.pool;
    for( ag_parent_ready_state_map_iter_t iter = ag_parent_ready_state_map_iter_init( map, pool );
                                                !ag_parent_ready_state_map_iter_done( iter, map, pool );
                                          iter = ag_parent_ready_state_map_iter_next( iter, map, pool ) ) {
      ag_parent_ready_state_t const * ele = ag_parent_ready_state_map_iter_ele_const( iter, map, pool );
      if( ele->slot <  new_root ) below = 1;
      if( ele->slot == new_root ) at    = 1;
    }
  }
  FD_TEST( below );
  FD_TEST( at    );

  ag_parent_ready_tracker_prune( tracker, new_root );

  int all_ge = 1; at = 0;
  {
    ag_parent_ready_state_map_t *             map  = tracker->states.map;
    ag_parent_ready_state_t * pool = tracker->states.pool;
    for( ag_parent_ready_state_map_iter_t iter = ag_parent_ready_state_map_iter_init( map, pool );
                                                !ag_parent_ready_state_map_iter_done( iter, map, pool );
                                          iter = ag_parent_ready_state_map_iter_next( iter, map, pool ) ) {
      ag_parent_ready_state_t const * ele = ag_parent_ready_state_map_iter_ele_const( iter, map, pool );
      if( ele->slot <  new_root ) all_ge = 0;
      if( ele->slot == new_root ) at     = 1;
    }
  }
  FD_TEST( all_ge );
  FD_TEST( at     );
  FD_TEST( tracker->root==new_root );

  teardown_tracker( tracker );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_slot_windows();
  test_state_wait_no_blocking();
  test_state_wait_blocking_sync();

  test_basic();
  test_genesis();
  test_skips();
  test_out_of_order_skips();
  test_out_of_order_notars();
  test_no_double_counting_skip_chain();
  test_no_double_counting_notar_and_skip();
  test_wait_for_parent_ready();
  test_parent_ready_finalized();
  test_prune();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
