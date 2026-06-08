#include "fd_parent_ready_tracker.c"

/* Ports alpenglow/src/consensus/pool/parent_ready_tracker.rs mod tests
   (and the parent_ready_state.rs synchronous wait test), converting the
   async wait_for_parent_ready test to its synchronous form. */

#define SLOTS_PER_WINDOW FD_ALPENGLOW_SLOTS_PER_WINDOW /* 4 */

/* random_block_id synthesizes a deterministic fd_block_id_t for slot:
   { slot, hash = memset to a slot-derived byte pattern }.  Distinct
   slots therefore yield distinct hashes, mirroring the uniqueness the
   Rust test_utils::random_block_id relies on. */

static fd_block_id_t
random_block_id( ulong slot ) {
  fd_block_id_t id;
  id.slot = slot;
  fd_memset( id.hash.uc, (int)( ( slot & 0xffUL ) | 0x40UL ), sizeof(fd_hash_t) );
  return id;
}

/* genesis_block_id = (0, all-zero hash) */

static fd_block_id_t
genesis_block_id( void ) {
  fd_block_id_t id;
  id.slot = 0UL;
  fd_memset( id.hash.uc, 0, sizeof(fd_hash_t) );
  return id;
}

static fd_parent_ready_tracker_t *
setup_tracker( fd_wksp_t * wksp, ulong slot_max ) {
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_parent_ready_tracker_align(),
                                    fd_parent_ready_tracker_footprint( slot_max ),
                                    42UL );
  FD_TEST( mem );
  fd_parent_ready_tracker_t * tracker = fd_parent_ready_tracker_join( fd_parent_ready_tracker_new( mem, slot_max, 42UL ) );
  FD_TEST( tracker );
  fd_parent_ready_tracker_default( tracker );
  return tracker;
}

static void
teardown_tracker( fd_parent_ready_tracker_t * tracker ) {
  fd_wksp_free_laddr( fd_parent_ready_tracker_delete( fd_parent_ready_tracker_leave( tracker ) ) );
}

/* out_contains returns 1 iff out[0,cnt) contains an entry == (slot, id). */

static int
out_contains( fd_parent_ready_t const * out, ulong cnt, ulong slot, fd_block_id_t const * id ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( out[i].slot==slot && fd_block_id_eq( &out[i].parent, id ) ) return 1;
  }
  return 0;
}

/* ---- ParentReadyState synchronous wait test --------------------------- */

static void
test_state_wait_no_blocking( void ) {
  fd_parent_ready_state_t state[1];
  fd_parent_ready_state_init( state, 1UL );

  ulong cnt;
  fd_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==0UL );

  fd_block_id_t block_id = random_block_id( 1UL );
  fd_parent_ready_state_add_to_ready( state, &block_id );

  fd_block_id_t recv;
  FD_TEST( fd_parent_ready_state_wait_for_parent_ready( state, &recv ) );
  FD_TEST( fd_block_id_eq( &recv, &block_id ) );

  fd_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==1UL );
}

/* The async wait_for_parent_ready_blocking test becomes: before
   add_to_ready, wait returns 0; after, it returns the parent. */

static void
test_state_wait_blocking_sync( void ) {
  fd_parent_ready_state_t state[1];
  fd_parent_ready_state_init( state, 1UL );

  ulong cnt;
  fd_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==0UL );

  fd_block_id_t recv;
  FD_TEST( !fd_parent_ready_state_wait_for_parent_ready( state, &recv ) ); /* not ready yet */

  fd_block_id_t block_id = random_block_id( 1UL );
  fd_parent_ready_state_add_to_ready( state, &block_id );

  FD_TEST( fd_parent_ready_state_wait_for_parent_ready( state, &recv ) );
  FD_TEST( fd_block_id_eq( &recv, &block_id ) );

  fd_parent_ready_state_ready_block_ids( state, &cnt );
  FD_TEST( cnt==1UL );
}

/* ---- ParentReadyTracker tests ---------------------------------------- */

static void
test_basic( fd_wksp_t * wksp ) {
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  for( ulong s=1UL; s<=2UL*SLOTS_PER_WINDOW; s++ ) {
    fd_block_id_t block = random_block_id( s );
    fd_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
    if( s==fd_alpenglow_last_slot_in_window( s ) ) {
      FD_TEST( out_contains( out, out_cnt, s+1UL, &block ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

static void
test_genesis( fd_wksp_t * wksp ) {
  fd_block_id_t genesis = genesis_block_id();
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  /* slots_in_window for genesis = [0,4) */
  for( ulong slot=0UL; slot<SLOTS_PER_WINDOW; slot++ ) {
    fd_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
    if( slot==fd_alpenglow_last_slot_in_window( slot ) ) {
      FD_TEST( out_contains( out, out_cnt, slot+1UL, &genesis ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

static void
test_skips( fd_wksp_t * wksp ) {
  fd_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL; /* genesis.next() */
  fd_block_id_t block   = random_block_id( slot );
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  fd_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  /* slots_in_window for slot 1 = [0,4) */
  for( ulong s=0UL; s<SLOTS_PER_WINDOW; s++ ) {
    fd_parent_ready_tracker_mark_skipped( tracker, s, out, &out_cnt );
    if( s==fd_alpenglow_last_slot_in_window( s ) ) {
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
  fd_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  fd_block_id_t block   = random_block_id( slot );
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  fd_parent_ready_tracker_mark_skipped( tracker, 3UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  fd_parent_ready_tracker_mark_skipped( tracker, 2UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  fd_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && fd_block_id_eq( &out[0].parent, &block ) );

  fd_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && fd_block_id_eq( &out[0].parent, &genesis ) );

  teardown_tracker( tracker );
}

static void
test_out_of_order_notars( fd_wksp_t * wksp ) {
  fd_block_id_t block1 = random_block_id( 1UL );
  fd_block_id_t block2 = random_block_id( 2UL );
  fd_block_id_t block3 = random_block_id( 3UL );
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  fd_parent_ready_tracker_mark_notar_fallback( tracker, &block2, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  fd_parent_ready_tracker_mark_notar_fallback( tracker, &block3, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && fd_block_id_eq( &out[0].parent, &block3 ) );

  fd_parent_ready_tracker_mark_notar_fallback( tracker, &block1, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  teardown_tracker( tracker );
}

static void
test_no_double_counting_skip_chain( fd_wksp_t * wksp ) {
  ulong         slot  = 1UL;
  fd_block_id_t block = random_block_id( slot );
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  fd_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  fd_parent_ready_tracker_mark_skipped( tracker, 2UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  fd_parent_ready_tracker_mark_skipped( tracker, 3UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && fd_block_id_eq( &out[0].parent, &block ) );

  fd_parent_ready_tracker_mark_skipped( tracker, 4UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  fd_parent_ready_tracker_mark_skipped( tracker, 5UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  fd_parent_ready_tracker_mark_skipped( tracker, 6UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  fd_parent_ready_tracker_mark_skipped( tracker, 7UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==8UL && fd_block_id_eq( &out[0].parent, &block ) );

  teardown_tracker( tracker );
}

static void
test_no_double_counting_notar_and_skip( fd_wksp_t * wksp ) {
  fd_block_id_t genesis = genesis_block_id();
  ulong         slot    = 1UL;
  fd_block_id_t block   = random_block_id( slot );
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  fd_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  fd_parent_ready_tracker_mark_skipped( tracker, 2UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );

  fd_parent_ready_tracker_mark_skipped( tracker, 3UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && fd_block_id_eq( &out[0].parent, &block ) );

  /* notably this does not re-issue a ParentReady for `block` */
  fd_parent_ready_tracker_mark_skipped( tracker, 1UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && fd_block_id_eq( &out[0].parent, &genesis ) );

  teardown_tracker( tracker );
}

/* converted from the async wait_for_parent_ready test */

static void
test_wait_for_parent_ready( fd_wksp_t * wksp ) {
  fd_block_id_t genesis = genesis_block_id();
  ulong window1 = 0UL;                  /* windows().next()        */
  ulong window2 = 1UL*SLOTS_PER_WINDOW; /* windows().nth(1)        */
  ulong window3 = 2UL*SLOTS_PER_WINDOW; /* windows().nth(2)        */
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  /* skip non-genesis slots in first window */
  for( ulong slot=window1; slot<window1+SLOTS_PER_WINDOW; slot++ ) {
    if( slot==0UL ) continue;
    fd_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  }

  /* genesis should be valid parent for 2nd window */
  fd_block_id_t got;
  FD_TEST( fd_parent_ready_tracker_wait_for_parent_ready( tracker, window2, &got ) );
  FD_TEST( fd_block_id_eq( &got, &genesis ) );

  /* parent should not yet be ready for 3rd window */
  FD_TEST( !fd_parent_ready_tracker_wait_for_parent_ready( tracker, window3, &got ) );

  /* skip slots in second window */
  for( ulong slot=window2; slot<window2+SLOTS_PER_WINDOW; slot++ ) {
    fd_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  }

  /* now genesis should be a valid parent for the 3rd window */
  FD_TEST( fd_parent_ready_tracker_wait_for_parent_ready( tracker, window3, &got ) );
  FD_TEST( fd_block_id_eq( &got, &genesis ) );

  teardown_tracker( tracker );
}

static void
test_parent_ready_finalized( fd_wksp_t * wksp ) {
  ulong window2 = 1UL*SLOTS_PER_WINDOW;
  ulong window3 = 2UL*SLOTS_PER_WINDOW;
  ulong window4 = 3UL*SLOTS_PER_WINDOW;
  ulong window5 = 4UL*SLOTS_PER_WINDOW;
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  /* basic case where finalized slot is first in its window */
  {
    fd_block_id_t block  = random_block_id( window2 );        /* first_slot_in_window */
    fd_block_id_t parent = random_block_id( block.slot-1UL ); /* block.0.prev() */
    fd_parent_ready_tracker_handle_finalization( tracker,
        1, &block,
        &parent, 1UL,
        NULL, 0UL,
        out, &out_cnt );
    FD_TEST( out_cnt==1UL );
    FD_TEST( out[0].slot==block.slot );
    FD_TEST( fd_block_id_eq( &out[0].parent, &parent ) );
  }

  /* case where an entire window is skipped between parent and finalized block */
  {
    fd_block_id_t block  = random_block_id( window4 );
    fd_block_id_t parent = random_block_id( window3-1UL ); /* window3.first.prev() */
    ulong skipped[ SLOTS_PER_WINDOW ];
    for( ulong i=0UL; i<SLOTS_PER_WINDOW; i++ ) skipped[i] = window3+i; /* window3.slots_in_window() */
    fd_parent_ready_tracker_handle_finalization( tracker,
        1, &block,
        &parent, 1UL,
        skipped, SLOTS_PER_WINDOW,
        out, &out_cnt );
    FD_TEST( out_cnt==1UL );
    FD_TEST( out[0].slot==block.slot );
    FD_TEST( fd_block_id_eq( &out[0].parent, &parent ) );
  }

  /* case where finalized slot is NOT first in its window */
  {
    fd_block_id_t block        = random_block_id( window5+1UL );      /* first.next() */
    fd_block_id_t parent       = random_block_id( block.slot-1UL );   /* block.0.prev() */
    fd_block_id_t parent_parent= random_block_id( parent.slot-1UL );  /* parent.0.prev() */
    fd_block_id_t impl_fin[2]  = { parent, parent_parent };
    fd_parent_ready_tracker_handle_finalization( tracker,
        1, &block,
        impl_fin, 2UL,
        NULL, 0UL,
        out, &out_cnt );
    FD_TEST( out_cnt==1UL );
    FD_TEST( out[0].slot==parent.slot );
    FD_TEST( fd_block_id_eq( &out[0].parent, &parent_parent ) );
  }

  teardown_tracker( tracker );
}

static void
test_prune( fd_wksp_t * wksp ) {
  fd_parent_ready_tracker_t * tracker = setup_tracker( wksp, 256 );

  fd_parent_ready_t out[ FD_PARENT_READY_OUT_MAX ];
  ulong             out_cnt;

  /* populate per-slot state across the first two windows */
  for( ulong slot=1UL; slot<=2UL*SLOTS_PER_WINDOW; slot++ ) {
    fd_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
  }

  ulong new_root = SLOTS_PER_WINDOW;

  /* before, there is state both before and at the future root */
  int below = 0, at = 0;
  {
    state_map_t  * map  = state_map ( tracker );
    state_pool_t * pool = state_pool( tracker );
    for( state_map_iter_t iter = state_map_iter_init( map, pool );
         !state_map_iter_done( iter, map, pool );
         iter = state_map_iter_next( iter, map, pool ) ) {
      fd_parent_ready_state_t const * ele = state_map_iter_ele_const( iter, map, pool );
      if( ele->slot <  new_root ) below = 1;
      if( ele->slot == new_root ) at    = 1;
    }
  }
  FD_TEST( below );
  FD_TEST( at    );

  fd_parent_ready_tracker_prune( tracker, new_root );

  /* state strictly below the new root is gone, root state retained */
  int all_ge = 1; at = 0;
  {
    state_map_t  * map  = state_map ( tracker );
    state_pool_t * pool = state_pool( tracker );
    for( state_map_iter_t iter = state_map_iter_init( map, pool );
         !state_map_iter_done( iter, map, pool );
         iter = state_map_iter_next( iter, map, pool ) ) {
      fd_parent_ready_state_t const * ele = state_map_iter_ele_const( iter, map, pool );
      if( ele->slot <  new_root ) all_ge = 0;
      if( ele->slot == new_root ) at     = 1;
    }
  }
  FD_TEST( all_ge );
  FD_TEST( at     );
  FD_TEST( fd_parent_ready_tracker_root( tracker )==new_root );

  teardown_tracker( tracker );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1;
  char *      _page_sz = "gigantic";
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
