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

static ag_parent_ready_tracker_t *
setup_tracker( ulong slot_max ) {
  FD_TEST( ag_parent_ready_tracker_footprint( slot_max )<=sizeof(scratch) );
  ag_parent_ready_tracker_t * tracker = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( scratch, slot_max, 42UL ) );
  FD_TEST( tracker );

  ag_parent_ready_state_t * genesis = slot_state( tracker, 0UL );
  fd_memset( genesis->notar_fallbacks[0], 0, sizeof(ag_block_hash_t) );
  genesis->notar_fallbacks_cnt = (uchar)1;
  tracker->root = 0UL;

  return tracker;
}

static void
teardown_tracker( ag_parent_ready_tracker_t * tracker ) {
  ag_parent_ready_tracker_delete( ag_parent_ready_tracker_leave( tracker ) );
}

/* deliver acks every ParentReady in out, as ag_pool_poll_pool_event
   does when votor takes it. */

static void
deliver( ag_parent_ready_tracker_t * tracker,
         ag_parent_ready_t const *   out,
         ulong                       cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) ag_parent_ready_tracker_delivered( tracker, out[i].slot );
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

/* src/consensus/pool/parent_ready_tracker/parent_ready_state.rs::wait_for_parent_ready_blocking */

static void
test_wait_blocking_sync( void ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  FD_TEST( ag_parent_ready_tracker_wait_for_parent_ready( tracker, 4UL ).slot==ULONG_MAX );

  ag_block_id_t block_id = random_block_id( 3UL );
  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block_id, out, &out_cnt );
  FD_TEST( out_cnt==1UL );

  ag_block_id_t recv = ag_parent_ready_tracker_wait_for_parent_ready( tracker, 4UL );
  FD_TEST( ag_block_id_eq( &recv, &block_id ) );
  FD_TEST( ag_parent_ready_tracker_is_parent_ready( tracker, 4UL, &block_id ) );

  teardown_tracker( tracker );
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
    deliver( tracker, out, out_cnt );
    if( s==last_slot_in_window( s ) ) {
      FD_TEST( out_cnt==1UL && out_contains( out, out_cnt, s+1UL, &block ) );
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
    deliver( tracker, out, out_cnt );
    if( slot==last_slot_in_window( slot ) ) {
      FD_TEST( out_cnt==1UL && out_contains( out, out_cnt, slot+1UL, &genesis ) );
    } else {
      FD_TEST( out_cnt==0UL );
    }
  }

  teardown_tracker( tracker );
}

/* src/consensus/pool/parent_ready_tracker.rs::skips.  One ParentReady
   per window start, both parents ready, the lower one reported. */

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
    deliver( tracker, out, out_cnt );
    if( s==last_slot_in_window( s ) ) {
      FD_TEST( out_cnt==1UL && out_contains( out, out_cnt, s+1UL, &genesis ) );
      FD_TEST( ag_parent_ready_tracker_is_parent_ready( tracker, s+1UL, &block   ) );
      FD_TEST( ag_parent_ready_tracker_is_parent_ready( tracker, s+1UL, &genesis ) );
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
  deliver( tracker, out, out_cnt );

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
  deliver( tracker, out, out_cnt );

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block1, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  FD_TEST( !ag_parent_ready_tracker_is_parent_ready( tracker, 4UL, &block1 ) );
  FD_TEST( !ag_parent_ready_tracker_is_parent_ready( tracker, 4UL, &block2 ) );

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
  deliver( tracker, out, out_cnt );

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
  deliver( tracker, out, out_cnt );

  ag_parent_ready_tracker_mark_skipped( tracker, 1UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].slot==4UL && ag_block_id_eq( &out[0].parent, &genesis ) );

  teardown_tracker( tracker );
}

/* An undelivered ParentReady absorbs later gains for the same window
   start, the queue holds at most one per window start. */

static void
test_undelivered_coalesces( void ) {
  ag_block_id_t genesis = genesis_block_id();
  ag_block_id_t block   = random_block_id( 1UL );
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong out_cnt;

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &block, out, &out_cnt );
  ag_parent_ready_tracker_mark_skipped( tracker, 2UL, out, &out_cnt );
  ag_parent_ready_tracker_mark_skipped( tracker, 3UL, out, &out_cnt );
  FD_TEST( out_cnt==1UL && out[0].slot==4UL );

  ag_parent_ready_tracker_mark_skipped( tracker, 1UL, out, &out_cnt );
  FD_TEST( out_cnt==0UL );
  FD_TEST( ag_parent_ready_tracker_is_parent_ready( tracker, 4UL, &genesis ) );
  ag_block_id_t min = ag_parent_ready_tracker_wait_for_parent_ready( tracker, 4UL );
  FD_TEST( ag_block_id_eq( &min, &genesis ) );

  ag_parent_ready_tracker_delivered( tracker, 4UL );
  ag_block_id_t nf3 = random_block_id( 3UL );
  ag_parent_ready_tracker_mark_notar_fallback( tracker, &nf3, out, &out_cnt );
  FD_TEST( out_cnt==1UL && out[0].slot==4UL );

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

/* On a slot tie the lowest hash wins, matching agave's
   parents_ready.iter().min() over Block{slot,block_id}. */

static void
test_wait_tie_break( void ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong             out_cnt;

  ag_block_id_t hi    = { .slot = 7UL }; fd_memset( hi.hash,    0xee, sizeof(ag_block_hash_t) );
  ag_block_id_t lo    = { .slot = 7UL }; fd_memset( lo.hash,    0x11, sizeof(ag_block_hash_t) );
  ag_block_id_t older = { .slot = 4UL }; fd_memset( older.hash, 0xff, sizeof(ag_block_hash_t) );

  ag_parent_ready_tracker_mark_notar_fallback( tracker, &hi, out, &out_cnt );
  ag_block_id_t min = ag_parent_ready_tracker_wait_for_parent_ready( tracker, 8UL );
  FD_TEST( ag_block_id_eq( &min, &hi ) );
  ag_parent_ready_tracker_mark_notar_fallback( tracker, &lo, out, &out_cnt );
  FD_TEST( !memcmp( ag_parent_ready_tracker_wait_for_parent_ready( tracker, 8UL ).hash, lo.hash, sizeof(ag_block_hash_t) ) );

  /* a lower slot still wins regardless of hash */
  for( ulong s=5UL; s<=7UL; s++ ) ag_parent_ready_tracker_mark_skipped( tracker, s, out, &out_cnt );
  ag_parent_ready_tracker_mark_notar_fallback( tracker, &older, out, &out_cnt );
  FD_TEST( ag_parent_ready_tracker_wait_for_parent_ready( tracker, 8UL ).slot==4UL );
  FD_TEST( ag_parent_ready_tracker_is_parent_ready( tracker, 8UL, &hi ) );

  teardown_tracker( tracker );
}

/* Queries of an unseen slot must not acquire a pool element. */

static void
test_wait_does_not_allocate( void ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( TEST_SLOT_MAX );

  ulong free_before = ag_parent_ready_state_pool_free( tracker->states.pool );
  ag_block_id_t p = random_block_id( 12340UL );
  FD_TEST( ag_parent_ready_tracker_wait_for_parent_ready( tracker, 12345UL ).slot==ULONG_MAX );
  FD_TEST( !ag_parent_ready_tracker_is_parent_ready( tracker, 12344UL, &p ) );
  ag_parent_ready_tracker_delivered( tracker, 12344UL );
  FD_TEST( ag_parent_ready_state_pool_free( tracker->states.pool )==free_before );

  teardown_tracker( tracker );
}

/* Skip certified windows whose every slot holds AG_NOTAR_FALLBACK_CERT_MAX
   notar fallbacks make every one of them a ready parent, far more than a
   window holds, without any per window start list. */

static void
test_many_parents( void ) {
  ag_parent_ready_tracker_t * tracker = setup_tracker( 256 );

  ag_parent_ready_t out[ TEST_SLOT_MAX ];
  ulong             out_cnt;

  ulong const end = 5UL*SLOTS_PER_WINDOW;
  for( ulong slot=1UL; slot<end; slot++ ) {
    for( ulong j=0UL; j<AG_NOTAR_FALLBACK_CERT_MAX; j++ ) {
      ag_block_id_t id = random_block_id( slot ); id.hash[0] = (uchar)j;
      ag_parent_ready_tracker_mark_notar_fallback( tracker, &id, out, &out_cnt );
      deliver( tracker, out, out_cnt );
    }
  }
  for( ulong slot=end-1UL; slot>=1UL; slot-- ) {
    ag_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
    FD_TEST( out_cnt<=end/SLOTS_PER_WINDOW );
    deliver( tracker, out, out_cnt );
  }

  ulong ready_cnt = 0UL;
  for( ulong slot=1UL; slot<end; slot++ ) {
    for( ulong j=0UL; j<AG_NOTAR_FALLBACK_CERT_MAX; j++ ) {
      ag_block_id_t id = random_block_id( slot ); id.hash[0] = (uchar)j;
      ready_cnt += (ulong)ag_parent_ready_tracker_is_parent_ready( tracker, end, &id );
    }
  }
  FD_TEST( ready_cnt==(end-1UL)*AG_NOTAR_FALLBACK_CERT_MAX );
  ag_block_id_t genesis = genesis_block_id();
  FD_TEST( ag_parent_ready_tracker_is_parent_ready( tracker, end, &genesis ) );
  FD_TEST( ag_parent_ready_tracker_wait_for_parent_ready( tracker, end ).slot==0UL );

  teardown_tracker( tracker );
}

/* Brute force Definition 15 against the tracker: random notar
   fallbacks and skips in random order over SLOTS slots.  After every
   mark, every (window start, parent) answer and every lowest parent
   must equal the definition, and a ParentReady must be output for
   exactly the window starts whose ready set grew. */

#define BF_SLOTS (48UL)
#define BF_NF    (AG_NOTAR_FALLBACK_CERT_MAX)

static int  bf_skip[ BF_SLOTS ];
static int  bf_nf  [ BF_SLOTS ][ BF_NF ];

static int
bf_ready( ulong w,
          ulong p,
          ulong j ) {
  if( !ag_is_start_of_window( w ) || p>=w || !bf_nf[ p ][ j ] ) return 0;
  for( ulong s=p+1UL; s<w; s++ ) if( !bf_skip[ s ] ) return 0;
  return 1;
}

static ag_block_id_t
bf_id( ulong slot,
       ulong j ) {
  ag_block_id_t id = random_block_id( slot ); id.hash[0] = (uchar)j; return id;
}

static void
test_brute_force( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );

  for( ulong iter=0UL; iter<2000UL; iter++ ) {
    ag_parent_ready_tracker_t * tracker = ag_parent_ready_tracker_join( ag_parent_ready_tracker_new( scratch, 256UL, iter ) );
    tracker->root = 0UL;
    fd_memset( bf_skip, 0, sizeof(bf_skip) );
    fd_memset( bf_nf,   0, sizeof(bf_nf)   );

    ulong ops = BF_SLOTS*2UL;
    for( ulong op=0UL; op<ops; op++ ) {
      ulong slot = fd_rng_ulong_roll( rng, BF_SLOTS );
      int   skip = fd_rng_uint_roll( rng, 3U )==0U;
      ulong j    = fd_rng_ulong_roll( rng, fd_rng_uint_roll( rng, 4U )==0U ? BF_NF : 1UL );

      int before[ BF_SLOTS ][ BF_SLOTS ][ BF_NF ];
      for( ulong w=0UL; w<BF_SLOTS; w+=AG_SLOTS_PER_WINDOW ) for( ulong p=0UL; p<w; p++ ) for( ulong k=0UL; k<BF_NF; k++ ) before[w][p][k] = bf_ready( w, p, k );

      ag_parent_ready_t out[ TEST_SLOT_MAX ];
      ulong             out_cnt;
      if( skip ) {
        bf_skip[ slot ] = 1;
        ag_parent_ready_tracker_mark_skipped( tracker, slot, out, &out_cnt );
      } else {
        bf_nf[ slot ][ j ] = 1;
        ag_block_id_t id = bf_id( slot, j );
        ag_parent_ready_tracker_mark_notar_fallback( tracker, &id, out, &out_cnt );
      }

      for( ulong w=0UL; w<BF_SLOTS; w+=AG_SLOTS_PER_WINDOW ) {
        int           grew = 0;
        ag_block_id_t min  = { .slot = ULONG_MAX };
        for( ulong p=0UL; p<w; p++ ) for( ulong k=0UL; k<BF_NF; k++ ) {
          ag_block_id_t id = bf_id( p, k );
          int r = bf_ready( w, p, k );
          FD_TEST( ag_parent_ready_tracker_is_parent_ready( tracker, w, &id )==r );
          grew |= r && !before[w][p][k];
          if( r && ( min.slot==ULONG_MAX || block_id_lt( &id, &min ) ) ) min = id;
        }
        ag_block_id_t got = ag_parent_ready_tracker_wait_for_parent_ready( tracker, w );
        FD_TEST( got.slot==min.slot && ( min.slot==ULONG_MAX || ag_block_id_eq( &got, &min ) ) );

        int emitted = 0;
        for( ulong i=0UL; i<out_cnt; i++ ) emitted |= out[i].slot==w;
        FD_TEST( emitted==grew );
      }
      for( ulong i=0UL; i<out_cnt; i++ ) FD_TEST( ag_is_start_of_window( out[i].slot ) );
      deliver( tracker, out, out_cnt );
    }

    ag_parent_ready_tracker_delete( ag_parent_ready_tracker_leave( tracker ) );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_slot_windows();
  test_wait_blocking_sync();

  test_basic();
  test_genesis();
  test_skips();
  test_out_of_order_skips();
  test_out_of_order_notars();
  test_no_double_counting_skip_chain();
  test_no_double_counting_notar_and_skip();
  test_undelivered_coalesces();
  test_wait_for_parent_ready();
  test_wait_tie_break();
  test_wait_does_not_allocate();
  test_prune();
  test_many_parents();
  test_brute_force();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
