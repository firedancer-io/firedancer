#include "ag_parent_ready_tracker.c"

#define SLOTS_PER_WINDOW AG_SLOTS_PER_WINDOW

static ag_block_id_t
random_block_id( ulong slot ) {
  ag_block_id_t id;
  id.slot = slot;
  fd_memset( id.hash.uc, (int)( ( slot & 0xffUL ) | 0x40UL ), sizeof(fd_hash_t) );
  return id;
}

static ag_block_id_t
genesis_block_id( void ) {
  ag_block_id_t id;
  id.slot = 0UL;
  fd_memset( id.hash.uc, 0, sizeof(fd_hash_t) );
  return id;
}

static ag_parent_ready_tracker_t *
setup_tracker( fd_wksp_t * wksp,
               ulong       slot_max ) {
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    ag_parent_ready_tracker_align(),
                                    ag_parent_ready_tracker_footprint( slot_max ),
                                    42UL );
  FD_TEST( mem );
  ag_parent_ready_tracker_t * tracker = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( mem, slot_max, 42UL ) );
  FD_TEST( tracker );

  /* Seed the window at genesis, the way the tracker's owner does: the
     state goes in through the public pool and map. */
  ag_parent_ready_state_t * genesis = ag_parent_ready_state_pool_ele_acquire( tracker->states.pool );
  ag_parent_ready_state_genesis( genesis, 0UL );
  ag_parent_ready_state_map_ele_insert( tracker->states.map, genesis, tracker->states.pool );
  tracker->root = 0UL;

  return tracker;
}

static void
teardown_tracker( ag_parent_ready_tracker_t * tracker ) {
  fd_wksp_free_laddr( ag_parent_ready_tracker_delete( ag_parent_ready_tracker_leave( tracker ) ) );
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

static void
test_state_wait_no_blocking( void ) {
  ag_parent_ready_state_t state[1];
  ag_parent_ready_state_init( state, 1UL );

  ulong cnt;
  ag_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==0UL );

  ag_block_id_t block_id = random_block_id( 1UL );
  ag_parent_ready_state_add_to_ready( state, &block_id );

  ag_block_id_t recv;
  FD_TEST( ag_parent_ready_state_wait_for_parent_ready( state, &recv ) );
  FD_TEST( ag_block_id_eq( &recv, &block_id ) );

  ag_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==1UL );
}

static void
test_state_wait_blocking_sync( void ) {
  ag_parent_ready_state_t state[1];
  ag_parent_ready_state_init( state, 1UL );

  ulong cnt;
  ag_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==0UL );

  ag_block_id_t recv;
  FD_TEST( !ag_parent_ready_state_wait_for_parent_ready( state, &recv ) );

  ag_block_id_t block_id = random_block_id( 1UL );
  ag_parent_ready_state_add_to_ready( state, &block_id );

  FD_TEST( ag_parent_ready_state_wait_for_parent_ready( state, &recv ) );
  FD_TEST( ag_block_id_eq( &recv, &block_id ) );

  ag_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==1UL );
}

static void
test_basic( fd_wksp_t * wksp ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ag_parent_ready_t const * out;
  ulong out_cnt;

  for( ulong s=1UL; s<=2UL*SLOTS_PER_WINDOW; s++ ) {
    ag_block_id_t block = random_block_id( s );
    out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, &out_cnt );
    if( s==ag_slot_last_slot_in_window( s ) ) {
      FD_TEST( out_contains( out, out_cnt, s+1UL, &block ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

static void
test_genesis( fd_wksp_t * wksp ) {
  ag_block_id_t genesis = genesis_block_id();
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ag_parent_ready_t const * out;
  ulong out_cnt;

  for( ulong slot=0UL; slot<SLOTS_PER_WINDOW; slot++ ) {
    out = ag_parent_ready_tracker_mark_skipped( tracker, slot, &out_cnt );
    if( slot==ag_slot_last_slot_in_window( slot ) ) {
      FD_TEST( out_contains( out, out_cnt, slot+1UL, &genesis ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

static void
test_skips( fd_wksp_t * wksp ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  ag_block_id_t block   = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ag_parent_ready_t const * out;
  ulong out_cnt;

  out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, &out_cnt );
  FD_TEST( out_cnt==0UL );

  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) {
    out = ag_parent_ready_tracker_mark_skipped( tracker, s, &out_cnt );
    if( s==ag_slot_last_slot_in_window( s ) ) {
      FD_TEST( out_contains( out, out_cnt, s+1UL, &block   ) );
      FD_TEST( out_contains( out, out_cnt, s+1UL, &genesis ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

static void
test_out_of_order_skips( fd_wksp_t * wksp ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  ag_block_id_t block   = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ag_parent_ready_t const * out;
  ulong out_cnt;

  out = ag_parent_ready_tracker_mark_skipped( tracker, 3UL, &out_cnt );
  FD_TEST( out_cnt==0UL );
  out = ag_parent_ready_tracker_mark_skipped( tracker, 2UL, &out_cnt );
  FD_TEST( out_cnt==0UL );

  out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block ) );

  ag_parent_ready_tracker_mark_skipped( tracker, slot, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &genesis ) );

  teardown_tracker( tracker );
}

static void
test_out_of_order_notars( fd_wksp_t * wksp ) {
  ag_block_id_t block1 = random_block_id( 1UL );
  ag_block_id_t block2 = random_block_id( 2UL );
  ag_block_id_t block3 = random_block_id( 3UL );
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ag_parent_ready_t const * out;
  ulong out_cnt;

  out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block2, &out_cnt );
  FD_TEST( out_cnt==0UL );

  out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block3, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block3 ) );

  out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block1, &out_cnt );
  FD_TEST( out_cnt==0UL );

  teardown_tracker( tracker );
}

static void
test_no_double_counting_skip_chain( fd_wksp_t * wksp ) {
  ulong         slot  = 1UL;
  ag_block_id_t block = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ag_parent_ready_t const * out;
  ulong out_cnt;

  out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, &out_cnt );
  FD_TEST( out_cnt==0UL );

  out = ag_parent_ready_tracker_mark_skipped( tracker, 2UL, &out_cnt );
  FD_TEST( out_cnt==0UL );

  out = ag_parent_ready_tracker_mark_skipped( tracker, 3UL, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block ) );

  out = ag_parent_ready_tracker_mark_skipped( tracker, 4UL, &out_cnt );
  FD_TEST( out_cnt==0UL );
  out = ag_parent_ready_tracker_mark_skipped( tracker, 5UL, &out_cnt );
  FD_TEST( out_cnt==0UL );
  out = ag_parent_ready_tracker_mark_skipped( tracker, 6UL, &out_cnt );
  FD_TEST( out_cnt==0UL );

  out = ag_parent_ready_tracker_mark_skipped( tracker, 7UL, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==8UL && ag_block_id_eq( &out[0].parent, &block ) );

  teardown_tracker( tracker );
}

static void
test_no_double_counting_notar_and_skip( fd_wksp_t * wksp ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  ag_block_id_t block   = random_block_id( slot );
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ag_parent_ready_t const * out;
  ulong out_cnt;

  out = ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, &out_cnt );
  FD_TEST( out_cnt==0UL );

  out = ag_parent_ready_tracker_mark_skipped( tracker, 2UL, &out_cnt );
  FD_TEST( out_cnt==0UL );

  out = ag_parent_ready_tracker_mark_skipped( tracker, 3UL, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &block ) );

  out = ag_parent_ready_tracker_mark_skipped( tracker, 1UL, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &genesis ) );

  teardown_tracker( tracker );
}

static void
test_wait_for_parent_ready( fd_wksp_t * wksp ) {
  ag_block_id_t genesis = genesis_block_id();
  ulong window1 = 0UL;
  ulong window2 = 1UL*SLOTS_PER_WINDOW;
  ulong window3 = 2UL*SLOTS_PER_WINDOW;
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ulong out_cnt;

  for( ulong slot=window1; slot<window1+SLOTS_PER_WINDOW; slot++ ) {
    if( slot==0UL ) continue;
    ag_parent_ready_tracker_mark_skipped( tracker, slot, &out_cnt );
  }

  ag_block_id_t got;
  FD_TEST( ag_parent_ready_tracker_wait_for_parent_ready( tracker, window2, &got ) );
  FD_TEST( ag_block_id_eq( &got, &genesis ) );

  FD_TEST( !ag_parent_ready_tracker_wait_for_parent_ready( tracker, window3, &got ) );

  for( ulong slot=window2; slot<window2+SLOTS_PER_WINDOW; slot++ ) {
    ag_parent_ready_tracker_mark_skipped( tracker, slot, &out_cnt );
  }

  FD_TEST( ag_parent_ready_tracker_wait_for_parent_ready( tracker, window3, &got ) );
  FD_TEST( ag_block_id_eq( &got, &genesis ) );

  teardown_tracker( tracker );
}

static void
test_parent_ready_finalized( fd_wksp_t * wksp ) {
  ulong window2 = 1UL*SLOTS_PER_WINDOW;
  ulong window3 = 2UL*SLOTS_PER_WINDOW;
  ulong window4 = 3UL*SLOTS_PER_WINDOW;
  ulong window5 = 4UL*SLOTS_PER_WINDOW;
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  {
    ag_block_id_t block  = random_block_id( window2 );
    ag_block_id_t parent = random_block_id( block.slot-1UL );

    /* The event borrows its two lists, so a synthetic one points at
       storage the case owns. */
    ag_block_id_t implicitly_finalized[1] = { parent };

    ag_finalization_event_t ev = { .finalized = block,
                                   .implicitly_finalized_cnt = 1UL, .implicitly_finalized = implicitly_finalized };

    ag_parent_ready_t out = ag_parent_ready_tracker_handle_finalization( tracker, &ev );
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

    ag_parent_ready_t out = ag_parent_ready_tracker_handle_finalization( tracker, &ev );
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

    ag_parent_ready_t out = ag_parent_ready_tracker_handle_finalization( tracker, &ev );
    FD_TEST( out.slot==parent.slot );
    FD_TEST( ag_block_id_eq( &out.parent, &parent_parent ) );
  }

  teardown_tracker( tracker );
}

static void
test_prune( fd_wksp_t * wksp ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  ulong out_cnt;

  for( ulong slot=1UL; slot<=2UL*SLOTS_PER_WINDOW; slot++ ) {
    ag_parent_ready_tracker_mark_skipped( tracker, slot, &out_cnt );
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

  ulong       page_cnt = 16384;
  char *      _page_sz = "normal";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_state_wait_no_blocking();
  test_state_wait_blocking_sync();

  test_basic( wksp );
  test_genesis( wksp );
  test_skips( wksp );
  test_out_of_order_skips( wksp );
  test_out_of_order_notars( wksp );
  test_no_double_counting_skip_chain( wksp );
  test_no_double_counting_notar_and_skip( wksp );
  test_wait_for_parent_ready( wksp );
  test_parent_ready_finalized( wksp );
  test_prune( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
