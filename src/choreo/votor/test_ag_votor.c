#include "ag_votor.c"
#include "ag_vote_history_file.h"
#include "test_ag_cert_builder.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#define NV                 (2UL)
#define TEST_SLOT_MAX      (64UL)
#define TEST_SHRED_VERSION ((ushort)0x5a5a)

/* Long enough for every timeout of a leader window to come due. */

#define TEST_NS_PER_SLOT       (400000000L)
#define TEST_WINDOW_ELAPSED_NS (AG_DELTA_TIMEOUT_NS + (long)(AG_SLOTS_PER_WINDOW+1UL)*TEST_NS_PER_SLOT)

#define FD_TEST_NO_MSG( votor ) do {           \
    ag_vote_t unused_;                         \
    FD_TEST( !try_recv( (votor), &unused_ ) ); \
  } while( 0 )

#define SCRATCH_MAX (1UL<<21) /* 2 MiB */

static uchar scratch[ SCRATCH_MAX ] __attribute__((aligned(128)));

static fd_bls_sec_t      g_sk  [ NV ];
static uchar             g_bls_selector[ NV ][ FD_BLS_PUB_COMPRESSED_SZ ];
static ag_validator_info_t g_info[ NV ];
static ulong               g_hash_ctr = 0UL;
static uchar               g_last_bls_selector[ FD_BLS_PUB_COMPRESSED_SZ ];

static void
capture_sign_fn( void *         ctx,
                 fd_bls_sig_t * sig,
                 uchar const *  public_key,
                 uchar const *  msg,
                 ulong          msg_sz ) {
  (void)ctx;
  memcpy( g_last_bls_selector, public_key, FD_BLS_PUB_COMPRESSED_SZ );
  for( ulong i=0UL; i<NV; i++ ) {
    if( FD_LIKELY( !memcmp( public_key, g_bls_selector[i], FD_BLS_PUB_COMPRESSED_SZ ) ) ) {
      fd_bls_sec_sign( &g_sk[i], msg, msg_sz, sig );
      return;
    }
  }
  FD_LOG_CRIT(( "unknown test BLS selector" ));
}

static void
genesis_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
}

static void
random_hash( ag_block_hash_t out ) {
  fd_memset( out, 0, sizeof(ag_block_hash_t) );
  FD_STORE( ulong, out,     0x9000UL + (++g_hash_ctr) );
  FD_STORE( ulong, out+8UL, 0xc0ffee00UL ^ g_hash_ctr );
}

static ag_block_id_t
genesis_block_id( void ) {
  ag_block_id_t b; b.slot = 0UL; genesis_hash( b.hash );
  return b;
}

static ag_block_id_t
random_block_id( ulong slot ) {
  ag_block_id_t b; b.slot = slot; random_hash( b.hash );
  return b;
}

static void
create_validators( void ) {
  for( ulong i=0UL; i<NV; i++ ) {
    fd_memset( &g_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    bls_key_from_sec( g_info[i].bls_key, &g_sk[i] );
    memcpy( g_bls_selector[i], g_info[i].bls_key, FD_BLS_PUB_COMPRESSED_SZ );
  }
}

static int
contains_slot( ag_votor_t const * votor,
               ulong              slot ) {
  return slot_state_map_ele_query_const( votor->slot_states->map, &slot, NULL, votor->slot_states->pool )!=NULL;
}

static ulong
min_live_slot( ag_votor_t const * votor ) {
  slot_state_map_t const * map = votor->slot_states->map;
  slot_state_ele_t const * ele = votor->slot_states->pool;
  ulong min = ULONG_MAX;
  for( slot_state_map_iter_t iter = slot_state_map_iter_init( map, ele );
                                   !slot_state_map_iter_done( iter, map, ele );
                             iter = slot_state_map_iter_next( iter, map, ele ) ) {
    min = fd_ulong_min( min, slot_state_map_iter_ele_const( iter, map, ele )->slot );
  }
  return min;
}

/* The Rust reference drives a second All2All instance and awaits
   messages on it.  Here the votor's outbound vote stream is drained
   instead: recv insists on a vote, try_recv does not.  Certs travel on
   their own stream now, so everything these tests await is a vote. */

static int
try_recv( ag_votor_t * votor,
          ag_vote_t *  out ) {
  uchar reason;
  return ag_votor_poll_vote( votor, out, &reason );
}

static ag_vote_t
recv( ag_votor_t * votor ) {
  ag_vote_t vote;
  FD_TEST( try_recv( votor, &vote ) );
  return vote;
}

/* Timeouts used to be fired in bulk by advancing the clock.  The votor
   now hands them out one at a time, so drain everything due at now. */

static void
handle_timeouts( ag_votor_t * votor,
                 long         now ) {
  ulong slot;
  while( ag_votor_poll_skip_timeout( votor, now, &slot ) ) ag_votor_handle_skip_timeout( votor, slot );
}

/* The epoch info is nearly 300 KiB, too big for the stack, and only one
   is ever live, so it gets its own file static rather than a slice of
   the scratch. */

static ag_epoch_info_t   epoch_info_mem;
static ag_epoch_info_t * g_epoch_info = NULL;

/* Creates a fresh fully wired-up votor instance. */

static ag_votor_t *
setup_votor( long now ) {
  create_validators();
  FD_TEST( ag_votor_footprint( TEST_SLOT_MAX )<=sizeof(scratch) );
  ag_votor_t * votor = ag_votor_join( ag_votor_new( scratch, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( votor );
  memset( g_last_bls_selector, 0, sizeof(g_last_bls_selector) );
  ag_block_id_t root = genesis_block_id();
  ag_votor_init         ( votor, &root, now, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, capture_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 0UL, g_bls_selector[0] );

  g_epoch_info = &epoch_info_mem;
  epoch_info_build( g_epoch_info, g_info, NV );
  return votor;
}

/* parent_ready delivers what ag_pool emits once parent is a ready parent
   of window start slot: the ParentReady, then its notar-fallback cert. */

static void
parent_ready( ag_votor_t *          votor,
              ulong                 slot,
              ag_block_id_t const * parent ) {
  ag_vote_t       vote = ag_vote_construct_notar( sec_sign_fn, &g_sk[0], test_bls_public_key, parent->slot, parent->hash, 0, TEST_SHRED_VERSION );
  ag_pool_event_t ready = { .kind = AG_POOL_EVENT_PARENT_READY, .parent_ready = { .slot = slot, .parent = *parent } };
  ag_pool_event_t cert  = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_notar_fallback( &vote.notar, 1UL, NULL, 0UL, g_epoch_info ) };
  ag_votor_handle_pool_event( votor, &ready, 0L );
  ag_votor_handle_pool_event( votor, &cert,  0L );
}

static void
teardown_votor( ag_votor_t * votor ) {
  ag_votor_delete( ag_votor_leave( votor ) );
  g_epoch_info = NULL;
}

/* Notifies the votor of a new block and returns the resulting notar
   vote. */

static ag_vote_t
send_block_and_expect_notar( ag_votor_t *          votor,
                             ulong                 slot,
                             ag_block_id_t const * parent ) {
  ag_block_info_t block = {0};
  random_hash( block.hash );
  block.parent = *parent;
  ag_votor_process_replay( votor, slot, &block );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR );
  FD_TEST( ag_vote_slot( &msg )==slot );
  return msg;
}

/* src/consensus/votor.rs::timeouts */

static void
test_timeouts( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  /* next_timeout is the earliest pending timer (the root's, first in
     the window), none is due before it, and it moves out as they fire */
  long first = AG_DELTA_TIMEOUT_NS+TEST_NS_PER_SLOT;
  FD_TEST( ag_votor_next_skip_timeout( votor )==first );
  ulong slot;
  FD_TEST( !ag_votor_poll_skip_timeout( votor, first-1L, &slot ) );
  FD_TEST(  ag_votor_poll_skip_timeout( votor, first,    &slot ) );
  FD_TEST( ag_votor_next_skip_timeout( votor )==first+TEST_NS_PER_SLOT );

  /* should vote skip for all slots */
  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );
  FD_TEST( ag_votor_next_skip_timeout( votor )==LONG_MAX );

  ulong skipped_slots[ AG_SLOTS_PER_WINDOW ];
  ulong skipped_cnt = 0UL;
  for( ulong s=1UL; s<AG_SLOTS_PER_WINDOW; s++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_SKIP );
    skipped_slots[ skipped_cnt++ ] = ag_vote_slot( &msg );
  }
  FD_TEST( skipped_cnt==AG_SLOTS_PER_WINDOW-1UL );
  for( ulong i=0UL; i<skipped_cnt; i++ ) FD_TEST( skipped_slots[i]==i+1UL );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
}

/* Windows armed half a slot apart interleave: window 4's first slot is
   due before window 0's second.  Timers pop earliest first, a later
   re-arm keeps the earlier deadlines, and a re-arm after the clock
   steps back moves them ahead of window 0's in every position. */

static void
check_timeout_order( ag_votor_t *  votor,
                     ulong const * slots,
                     long const *  due ) { /* in half slots, past AG_DELTA_TIMEOUT_NS */
  for( ulong i=0UL; i<8UL; i++ ) {
    ulong slot;
    FD_TEST( ag_votor_next_skip_timeout( votor )==AG_DELTA_TIMEOUT_NS+due[ i ]*(TEST_NS_PER_SLOT/2L) );
    FD_TEST( ag_votor_poll_skip_timeout( votor, LONG_MAX-1L, &slot ) );
    FD_TEST( slot==slots[ i ] );
  }
  FD_TEST( ag_votor_next_skip_timeout( votor )==LONG_MAX );
}

static void
arm_window_4( ag_votor_t * votor,
              long         now ) {
  ag_block_id_t   parent       = { .slot = 3UL }; memset( parent.hash, 1, sizeof(ag_block_hash_t) );
  ag_pool_event_t parent_ready = { .kind = AG_POOL_EVENT_PARENT_READY };
  parent_ready.parent_ready.slot   = 4UL;
  parent_ready.parent_ready.parent = parent;
  ag_votor_handle_pool_event( votor, &parent_ready, now );
}

static void
test_timeouts_interleaved( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  arm_window_4( votor, TEST_NS_PER_SLOT/2L );
  arm_window_4( votor, 2L*TEST_NS_PER_SLOT );
  check_timeout_order( votor, (ulong[]){ 0, 4, 1, 5, 2, 6, 3, 7 }, (long[]){ 2, 3, 4, 5, 6, 7, 8, 9 } );
  teardown_votor( votor );

  votor = setup_votor( 0L );
  arm_window_4( votor, TEST_NS_PER_SLOT/2L );
  arm_window_4( votor, -TEST_NS_PER_SLOT/2L );
  check_timeout_order( votor, (ulong[]){ 4, 0, 5, 1, 6, 2, 7, 3 }, (long[]){ 1, 2, 3, 4, 5, 6, 7, 8 } );
  teardown_votor( votor );
}

/* Booting mid-window must not skip the slots below the boot slot */

static void
test_boot_mid_window( void ) {
  create_validators();
  ag_votor_t * votor = ag_votor_join( ag_votor_new( scratch, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( votor );
  ag_block_id_t root = random_block_id( 2UL );
  ag_votor_init         ( votor, &root, 0L, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 0UL, g_bls_selector[0] );

  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_SKIP );
  FD_TEST( ag_vote_slot( &msg )==3UL );
  FD_TEST_NO_MSG( votor );

  ag_votor_delete( ag_votor_leave( votor ) );
}

/* Booting mid-window, the next block in the window builds on the root
   and gets a notar vote. */

static void
test_boot_mid_window_notar_child( void ) {
  create_validators();
  ag_votor_t * votor = ag_votor_join( ag_votor_new( scratch, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( votor );
  ag_block_id_t root = random_block_id( 2UL );
  ag_votor_init         ( votor, &root, 0L, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 0UL, g_bls_selector[0] );
  g_epoch_info = &epoch_info_mem;
  epoch_info_build( g_epoch_info, g_info, NV );

  send_block_and_expect_notar( votor, 3UL, &root );

  ag_votor_delete( ag_votor_leave( votor ) );
}

/* src/consensus/votor.rs::notar_and_final */

static void
test_notar_and_final( void ) {
  ag_votor_t *  votor  = setup_votor( 0L );
  ulong         slot   = 1UL;
  ag_block_id_t parent = genesis_block_id();

  /* vote notar after seeing block */
  ag_vote_t vote = send_block_and_expect_notar( votor, slot, &parent );

  /* vote finalize after seeing branch-certified */
  ag_cert_t cert = cert_build_notar( &vote.notar, 1UL, g_epoch_info );
  ag_pool_event_t event = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert };
  ag_votor_handle_pool_event( votor, &event, 0L );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_FINAL );
  FD_TEST( ag_vote_slot( &msg )==slot );

  teardown_votor( votor );
}

/* src/consensus/votor.rs::notar_out_of_order */

static void
test_notar_out_of_order( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ulong slot1 = 1UL;       ag_block_hash_t hash1; random_hash( hash1 );
  ulong slot2 = slot1+1UL; ag_block_hash_t hash2; random_hash( hash2 );

  /* give later block to votor first */
  ag_block_info_t block = {0};
  block.parent = ag_block_id( slot1, hash1 );
  memcpy( block.hash, hash2, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( votor, slot2, &block );

  /* should not vote yet */
  FD_TEST_NO_MSG( votor );

  /* now notify votor of earlier block */
  block.parent = genesis_block_id();
  memcpy( block.hash, hash1, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( votor, slot1, &block );

  /* should now see notar votes */
  for( ulong i=0UL; i<2UL; i++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR );
    ulong slot = ag_vote_slot( &msg );
    FD_TEST( slot==slot1 || slot==slot2 );
  }

  teardown_votor( votor );
}

/* src/consensus/votor.rs::pending_block_not_notarized_after_skip */

static void
test_pending_block_not_notarized_after_skip( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  /* first slot of the second leader window; its parent is not ready yet */
  ulong slot = AG_SLOTS_PER_WINDOW;
  FD_TEST( ag_is_start_of_window( slot ) );
  ag_block_id_t parent = { .slot = slot-1UL }; random_hash( parent.hash );

  /* block reconstructs before its parent is ready: stashed as pending, no
     vote yet (parent not in parents_ready) */
  ag_block_info_t block = {0};
  random_hash( block.hash );
  block.parent = parent;
  ag_votor_process_replay( votor, slot, &block );

  /* window times out: we vote skip for every slot in the window */
  ag_votor_handle_skip_timeout( votor, slot );

  /* parent becomes ready late: re-checks pending blocks */
  parent_ready( votor, slot, &parent );

  /* collect every vote broadcast for slot */
  int                    voted_skip  = 0;
  int                    voted_notar = 0;
  ag_vote_t msg;
  while( try_recv( votor, &msg ) ) {
    if( ag_vote_slot( &msg )!=slot   ) continue;
    if( msg.kind==AG_VOTE_KIND_SKIP  ) voted_skip  = 1;
    if( msg.kind==AG_VOTE_KIND_NOTAR ) voted_notar = 1;
  }

  /* must not notarize slot, which we already voted skip for */
  FD_TEST(  voted_skip  ); /* expected a skip vote for slot */
  FD_TEST( !voted_notar ); /* slot notarized after voting skip (slashable skip-and-notarize) */

  teardown_votor( votor );
}

/* src/consensus/votor.rs::safe_to_notar */

static void
test_safe_to_notar( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ulong        slot  = 1UL;

  /* wait for skip votes */
  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );
  for( ulong s=1UL; s<AG_SLOTS_PER_WINDOW; s++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_SKIP );
  }

  /* vote notar-fallback after safe-to-notar */
  ag_block_id_t   block = random_block_id( slot );
  ag_pool_event_t event = { .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = block };
  ag_votor_handle_pool_event( votor, &event, 0L );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR_FALLBACK );
  FD_TEST( ag_vote_slot( &msg )==block.slot );
  FD_TEST( !memcmp( msg.notar_fallback.block_hash, block.hash, sizeof(ag_block_hash_t) ) );

  teardown_votor( votor );
}

/* src/consensus/votor.rs::safe_to_skip */

static void
test_safe_to_skip( void ) {
  ag_votor_t *  votor  = setup_votor( 0L );
  ulong         slot   = 1UL;
  ag_block_id_t parent = genesis_block_id();

  /* vote notar after seeing block */
  send_block_and_expect_notar( votor, slot, &parent );

  /* vote skip-fallback after safe-to-skip */
  ag_pool_event_t event = { .kind = AG_POOL_EVENT_SAFE_TO_SKIP, .safe_to_skip = slot };
  ag_votor_handle_pool_event( votor, &event, 0L );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_SKIP_FALLBACK );
  FD_TEST( ag_vote_slot( &msg )==slot );

  teardown_votor( votor );
}

static void
test_bls_selector_rotates_with_epoch( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  uchar bls_pubkey[ FD_BLS_PUB_COMPRESSED_SZ ];
  memcpy( bls_pubkey, g_bls_selector[1], sizeof(bls_pubkey) );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 1UL, 2UL, bls_pubkey );
  memset( bls_pubkey, 0, sizeof(bls_pubkey) );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 4UL, g_bls_selector[0] );

  ag_block_id_t parent = genesis_block_id();
  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==0UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[0], FD_BLS_PUB_COMPRESSED_SZ ) );

  parent = ag_block_id( 1UL, vote.notar.block_hash );
  vote = send_block_and_expect_notar( votor, 2UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==1UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[1], FD_BLS_PUB_COMPRESSED_SZ ) );

  parent = ag_block_id( 2UL, vote.notar.block_hash );
  vote = send_block_and_expect_notar( votor, 3UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==1UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[1], FD_BLS_PUB_COMPRESSED_SZ ) );

  parent = ag_block_id( 3UL, vote.notar.block_hash );
  parent_ready( votor, 4UL, &parent );
  vote = send_block_and_expect_notar( votor, 4UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==0UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[0], FD_BLS_PUB_COMPRESSED_SZ ) );

  teardown_votor( votor );
}

static void
test_missing_bls_selector_disables_voting( void ) {
  for( ulong advances=0UL; advances<3UL; advances++ ) {
    ag_votor_t * votor = setup_votor( 0L );
    ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 2UL, NULL );

    ag_block_id_t parent = genesis_block_id();
    ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );

    /* The epoch without a key moves from next to current to previous. */
    if( advances>0UL ) ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 4UL, g_bls_selector[0] );
    if( advances>1UL ) ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 1UL, 6UL, g_bls_selector[1] );

    ag_block_info_t block = {0};
    block.parent = ag_block_id( 1UL, vote.notar.block_hash );
    random_hash( block.hash );
    ag_votor_process_replay( votor, 2UL, &block );
    FD_TEST_NO_MSG( votor );

    teardown_votor( votor );
  }
}

static void
test_set_bls_pubkey( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 1UL, 2UL, NULL );
  ag_votor_set_bls_key( votor, 2UL, g_bls_selector[1] );

  ag_block_id_t parent = genesis_block_id();
  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );
  parent = ag_block_id( 1UL, vote.notar.block_hash );
  vote = send_block_and_expect_notar( votor, 2UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==1UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[1], FD_BLS_PUB_COMPRESSED_SZ ) );

  ag_votor_set_bls_key( votor, 2UL, NULL );
  ag_block_info_t block = {0};
  block.parent = ag_block_id( 2UL, vote.notar.block_hash );
  random_hash( block.hash );
  ag_votor_process_replay( votor, 3UL, &block );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
}

/* A notar vote made without a key still counts as cast: setting the key
   later never sends it, and the next block builds on it. */

static void
test_missing_bls_selector_records_notar( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 1UL, 2UL, NULL );

  ag_block_id_t parent = genesis_block_id();
  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );

  ag_block_info_t block = {0};
  block.parent = ag_block_id( 1UL, vote.notar.block_hash );
  random_hash( block.hash );
  ag_votor_process_replay( votor, 2UL, &block );
  FD_TEST_NO_MSG( votor );

  ag_votor_set_bls_key( votor, 2UL, g_bls_selector[1] );
  FD_TEST_NO_MSG( votor );

  parent = ag_block_id( 2UL, block.hash );
  vote   = send_block_and_expect_notar( votor, 3UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==1UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[1], FD_BLS_PUB_COMPRESSED_SZ ) );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
}

/* A final vote made without a key still retires the slot. */

static void
test_missing_bls_selector_records_final( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 1UL, 2UL, NULL );

  ag_block_id_t parent = genesis_block_id();
  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );

  ag_block_info_t block = {0};
  block.parent = ag_block_id( 1UL, vote.notar.block_hash );
  random_hash( block.hash );
  ag_votor_process_replay( votor, 2UL, &block );

  ag_vote_t       notar = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, 2UL, block.hash, (ushort)1, TEST_SHRED_VERSION );
  ag_pool_event_t event = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_notar( &notar.notar, 1UL, g_epoch_info ) };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST_NO_MSG( votor );
  FD_TEST( is_retired( votor, 2UL ) );

  teardown_votor( votor );
}

static void
test_set_rank( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ag_votor_advance_epoch ( votor, TEST_NS_PER_SLOT, 0UL, 2UL, g_bls_selector[0] );
  ag_votor_set_rank      ( votor, 0UL, 1UL );
  ag_votor_set_bls_key( votor, 0UL, g_bls_selector[1] );

  ag_block_id_t parent = genesis_block_id();
  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==1UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[1], FD_BLS_PUB_COMPRESSED_SZ ) );

  parent = ag_block_id( 1UL, vote.notar.block_hash );
  vote = send_block_and_expect_notar( votor, 2UL, &parent );
  FD_TEST( ag_vote_rank( &vote )==0UL );
  FD_TEST( !memcmp( g_last_bls_selector, g_bls_selector[0], FD_BLS_PUB_COMPRESSED_SZ ) );

  teardown_votor( votor );
}

/* After an identity switch votor signs nothing more in a window it
   already voted in, not even a final vote, since the new identity may
   have skipped the rest of that window on another machine.  It votes
   again from the next window. */

static void
test_wait_to_vote( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  ag_block_id_t parent = genesis_block_id();
  ag_vote_t     vote   = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_votor_wait_to_vote( votor, 0UL );

  ag_pool_event_t event = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_notar( &vote.notar, 1UL, g_epoch_info ) };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST_NO_MSG( votor );

  parent = ag_block_id( 1UL, vote.notar.block_hash );
  for( ulong slot=2UL; slot<AG_SLOTS_PER_WINDOW; slot++ ) {
    ag_block_info_t block = {0};
    block.parent = parent;
    random_hash( block.hash );
    ag_votor_process_replay( votor, slot, &block );
    FD_TEST_NO_MSG( votor );
    parent = ag_block_id( slot, block.hash );
  }

  parent_ready( votor, AG_SLOTS_PER_WINDOW, &parent );
  send_block_and_expect_notar( votor, AG_SLOTS_PER_WINDOW, &parent );

  teardown_votor( votor );
}

/* The new identity's vote history file gives the slot it can vote from.
   Votor signs nothing below it, even in a window it never voted in. */

static void
test_wait_to_vote_slot( void ) {
  ag_votor_t * votor = setup_votor( 0L );
  ag_votor_wait_to_vote( votor, 2UL*AG_SLOTS_PER_WINDOW );

  ag_block_id_t parent = random_block_id( AG_SLOTS_PER_WINDOW-1UL );
  parent_ready( votor, AG_SLOTS_PER_WINDOW, &parent );
  ag_block_info_t block = {0};
  block.parent = parent;
  random_hash( block.hash );
  ag_votor_process_replay( votor, AG_SLOTS_PER_WINDOW, &block );
  FD_TEST_NO_MSG( votor );

  parent = random_block_id( 2UL*AG_SLOTS_PER_WINDOW-1UL );
  parent_ready( votor, 2UL*AG_SLOTS_PER_WINDOW, &parent );
  send_block_and_expect_notar( votor, 2UL*AG_SLOTS_PER_WINDOW, &parent );

  teardown_votor( votor );
}

static void
test_missing_bls_selector_still_skips_other_epoch( void ) {
  for( int notar=0; notar<2; notar++ ) {
    ag_votor_t * votor = setup_votor( 0L );
    ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 2UL, NULL );

    ag_pool_event_t event = { .kind = AG_POOL_EVENT_SAFE_TO_SKIP, .safe_to_skip = 2UL };
    if( notar ) {
      event.kind          = AG_POOL_EVENT_SAFE_TO_NOTAR;
      event.safe_to_notar = random_block_id( 2UL );
    }
    ag_votor_handle_pool_event( votor, &event, 0L );

    ag_vote_t vote;
    uchar     reason;
    FD_TEST( ag_votor_poll_vote( votor, &vote, &reason ) );
    FD_TEST( vote.kind==AG_VOTE_KIND_SKIP );
    FD_TEST( ag_vote_slot( &vote )==1UL );
    FD_TEST( reason==( notar ? AG_VOTOR_REASON_SAFE_TO_NOTAR : AG_VOTOR_REASON_SAFE_TO_SKIP ) );
    FD_TEST_NO_MSG( votor );
    ulong slot = 2UL;
    slot_state_ele_t const * state = slot_state_map_ele_query_const( votor->slot_states->map, &slot, NULL, votor->slot_states->pool );
    FD_TEST( state && state->voted && state->bad_window );

    teardown_votor( votor );
  }
}

/* src/consensus/votor.rs::prunes_to_finalized_window */

static void
test_prunes_to_finalized_window( void ) {
  ag_votor_t * votor = setup_votor( 0L );

  /* finalize a slot that is NOT first in its window and isn't in the
     genesis window */
  ulong finalized    = AG_SLOTS_PER_WINDOW + 1UL;
  ulong window_start = ag_first_slot_in_window( finalized );
  FD_TEST( window_start>0UL       );
  FD_TEST( window_start<finalized );

  /* populate per-slot state across the previous window and into the next
     one */
  ulong highest = 2UL*AG_SLOTS_PER_WINDOW;
  for( ulong i=1UL; i<=highest; i++ ) state_mut( votor, i );
  for( ulong i=0UL; i<=highest; i++ ) FD_TEST( contains_slot( votor, i ) );

  /* finalizing a mid-window slot should drop only the slots before its
     window */
  ag_vote_t fv; fv = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, finalized, (ushort)1, TEST_SHRED_VERSION );
  ag_cert_t cert = cert_build_final( &fv.final, 1UL, g_epoch_info );
  ag_pool_event_t event = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST( votor->highest_final_cert_slot==finalized );

  /* the finalized window and the reward buffer before it are kept */
  ulong kept_start = ag_first_slot_in_window( fd_ulong_sat_sub( finalized, AG_REWARD_SLOT_DELTA ) );
  FD_TEST( min_live_slot( votor )>=kept_start );
  for( ulong slot=window_start; slot<window_start+AG_SLOTS_PER_WINDOW; slot++ ) {
    FD_TEST( contains_slot( votor, slot ) );
  }

  /* earlier windows are dropped */
  for( ulong slot=0UL; slot<kept_start; slot++ ) FD_TEST( !contains_slot( votor, slot ) );
  for( ulong slot=kept_start; slot<=highest; slot++ ) FD_TEST( contains_slot( votor, slot ) );

  teardown_votor( votor );
}

/* A final cert 8 slots ahead moves first_unpruned_slot to window start
   8, whose parents are in the window below.  A block at 8 that replays
   after that still gets its notar vote, both when the parent's cert
   came first and when it arrives last, just below first_unpruned_slot. */

static void
test_window_start_at_first_unpruned( void ) {
  for( int cert_last=0; cert_last<2; cert_last++ ) {
    ag_votor_t * votor = setup_votor( 0L );

    ag_block_id_t parent = random_block_id( 7UL );
    ag_vote_t     nv     = ag_vote_construct_notar( sec_sign_fn, &g_sk[1], test_bls_public_key, parent.slot, parent.hash, (ushort)1, TEST_SHRED_VERSION );
    ag_pool_event_t nf_cert = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_notar_fallback( &nv.notar, 1UL, NULL, 0UL, g_epoch_info ) };
    if( !cert_last ) ag_votor_handle_pool_event( votor, &nf_cert, 0L );

    ag_vote_t       fv    = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, 16UL, (ushort)1, TEST_SHRED_VERSION );
    ag_pool_event_t final = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_final( &fv.final, 1UL, g_epoch_info ) };
    ag_votor_handle_pool_event( votor, &final, 0L );
    FD_TEST( first_unpruned_slot( votor )==8UL );

    ag_block_info_t block = {0};
    random_hash( block.hash );
    block.parent = parent;
    ag_votor_process_replay( votor, 8UL, &block );
    if( cert_last ) {
      FD_TEST_NO_MSG( votor );
      ag_votor_handle_pool_event( votor, &nf_cert, 0L );
    }

    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR && ag_vote_slot( &msg )==8UL );

    teardown_votor( votor );
  }
}

/* A timeout at or below the highest final cert slot but still in its
   reward window casts skip votes for the unvoted slots of its window. */

static void
test_timeout_below_final( void ) {
  create_validators();
  ag_votor_t * votor = ag_votor_join( ag_votor_new( scratch, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( votor );
  ag_block_id_t root = random_block_id( 10UL );
  ag_votor_init         ( votor, &root, 0L, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 0UL, g_bls_selector[0] );
  g_epoch_info = &epoch_info_mem;
  epoch_info_build( g_epoch_info, g_info, NV );

  ulong           w     = ag_first_slot_in_window( root.slot ) + AG_SLOTS_PER_WINDOW;
  ag_vote_t       fv    = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, w+4UL, (ushort)1, TEST_SHRED_VERSION );
  ag_pool_event_t final = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_final( &fv.final, 1UL, g_epoch_info ) };
  ag_votor_handle_pool_event( votor, &final, 0L );
  for( ulong slot=0UL; slot<first_unpruned_slot( votor ); slot++ ) FD_TEST( !contains_slot( votor, slot ) );

  ag_votor_handle_skip_timeout( votor, w+3UL );
  for( ulong slot=w; slot<w+AG_SLOTS_PER_WINDOW; slot++ ) {
    ag_vote_t msg = recv( votor );
    FD_TEST( msg.kind==AG_VOTE_KIND_SKIP && ag_vote_slot( &msg )==slot );
  }
  FD_TEST_NO_MSG( votor );

  ag_votor_handle_skip_timeout( votor, w+2UL );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
}

/* ag_votor_vote_history gives votor's VoteHistory, which
   ag_vote_history_file_ser encodes: the votes cast since root and the
   sets Agave derives from them, the notarized blocks and the ready
   parents. */

static void
test_vote_history_ser( void ) {
  ag_votor_t *  votor  = setup_votor( 0L );
  ag_block_id_t parent = genesis_block_id();

  /* notar and final in slot 1 */

  ag_vote_t       notar = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_pool_event_t event = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_notar( &notar.notar, 1UL, g_epoch_info ) };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST( recv( votor ).kind==AG_VOTE_KIND_FINAL );

  /* skips in slots 2 and 3, then both fallbacks in slot 2 */

  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );
  for( ulong s=2UL; s<AG_SLOTS_PER_WINDOW; s++ ) FD_TEST( recv( votor ).kind==AG_VOTE_KIND_SKIP );
  ag_block_id_t nf = random_block_id( 2UL );
  event = (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = nf };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST( recv( votor ).kind==AG_VOTE_KIND_NOTAR_FALLBACK );
  event = (ag_pool_event_t){ .kind = AG_POOL_EVENT_SAFE_TO_SKIP, .safe_to_skip = 2UL };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST( recv( votor ).kind==AG_VOTE_KIND_SKIP_FALLBACK );

  /* slot 3 is a ready parent of window start 4 */

  ag_block_id_t ready = random_block_id( 3UL );
  parent_ready( votor, 4UL, &ready );
  FD_TEST_NO_MSG( votor );

  uchar       keypair[ 64 ];
  fd_sha512_t sha[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  memset( keypair, 7, 32UL );
  fd_ed25519_public_from_private( keypair+32UL, keypair, sha );

  static uchar                  buf[ AG_VOTE_HISTORY_FILE_MAX ];
  static ag_vote_history_file_t vh;
  static ag_vote_history_file_t out;
  FD_TEST( ag_votor_vote_history( votor, &vh )==AG_VOTE_HISTORY_FILE_SUCCESS );
  ulong sz = ag_vote_history_file_ser( &vh, keypair+32UL, buf, sizeof(buf) );
  FD_TEST( sz );
  FD_TEST( !ag_vote_history_file_ser( &vh, keypair+32UL, buf, sz-1UL ) );
  FD_TEST( ag_vote_history_file_ser( &vh, keypair+32UL, buf, sz )==sz );
  fd_ed25519_sign( buf+AG_VOTE_HISTORY_FILE_SIG_OFF, buf+AG_VOTE_HISTORY_FILE_DATA_OFF, sz-AG_VOTE_HISTORY_FILE_DATA_OFF, keypair+32UL, keypair, sha );
  FD_TEST( ag_vote_history_file_de( buf, sz, keypair+32UL, &out )==AG_VOTE_HISTORY_FILE_SUCCESS );

  FD_TEST( out.root==0UL );
  FD_TEST( out.voted_cnt==3UL && out.voted[ 0 ]==1UL && out.voted[ 1 ]==2UL && out.voted[ 2 ]==3UL );
  FD_TEST( out.voted_notar_cnt==1UL && out.voted_notar[ 0 ].slot==1UL && !memcmp( out.voted_notar[ 0 ].hash, notar.notar.block_hash, 32UL ) );
  FD_TEST( out.voted_notar_fallback_cnt==1UL && out.voted_notar_fallback[ 0 ].slot==2UL && !memcmp( out.voted_notar_fallback[ 0 ].hash, nf.hash, 32UL ) );
  FD_TEST( out.voted_skip_fallback_cnt==1UL && out.voted_skip_fallback[ 0 ]==2UL );
  FD_TEST( out.skipped_cnt==2UL && out.skipped[ 0 ]==2UL && out.skipped[ 1 ]==3UL );
  FD_TEST( out.its_over_cnt==1UL && out.its_over[ 0 ]==1UL );
  uint  const kind[ 6 ] = { AG_VOTE_HISTORY_KIND_NOTAR, AG_VOTE_HISTORY_KIND_FINAL, AG_VOTE_HISTORY_KIND_SKIP, AG_VOTE_HISTORY_KIND_NOTAR_FALLBACK, AG_VOTE_HISTORY_KIND_SKIP_FALLBACK, AG_VOTE_HISTORY_KIND_SKIP };
  ulong const slot[ 6 ] = { 1UL, 1UL, 2UL, 2UL, 2UL, 3UL };
  FD_TEST( out.votes_cast_cnt==6UL );
  for( ulong i=0UL; i<6UL; i++ ) FD_TEST( out.votes_cast[ i ].kind==kind[ i ] && out.votes_cast[ i ].block.slot==slot[ i ] && !out.votes_cast[ i ].shred_version );
  FD_TEST( !memcmp( out.votes_cast[ 3 ].block.hash, nf.hash, 32UL ) );
  FD_TEST( out.notarized_blocks_cnt==2UL && out.notarized_blocks[ 0 ].slot==0UL && out.notarized_blocks[ 1 ].slot==1UL );
  FD_TEST( out.parent_ready_cnt==1UL && out.parent_ready[ 0 ].slot==4UL && out.parent_ready[ 0 ].block.slot==3UL && !memcmp( out.parent_ready[ 0 ].block.hash, ready.hash, 32UL ) );

  /* a final cert for slot 16 makes it the root, and prunes everything
     below window start 8 */

  ag_vote_t fv = ag_vote_construct_final( sec_sign_fn, &g_sk[1], test_bls_public_key, 16UL, (ushort)1, TEST_SHRED_VERSION );
  event = (ag_pool_event_t){ .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = cert_build_final( &fv.final, 1UL, g_epoch_info ) };
  ag_votor_handle_pool_event( votor, &event, 0L );
  FD_TEST( ag_votor_vote_history( votor, &vh )==AG_VOTE_HISTORY_FILE_SUCCESS );
  sz = ag_vote_history_file_ser( &vh, keypair+32UL, buf, sizeof(buf) );
  fd_ed25519_sign( buf+AG_VOTE_HISTORY_FILE_SIG_OFF, buf+AG_VOTE_HISTORY_FILE_DATA_OFF, sz-AG_VOTE_HISTORY_FILE_DATA_OFF, keypair+32UL, keypair, sha );
  FD_TEST( ag_vote_history_file_de( buf, sz, keypair+32UL, &out )==AG_VOTE_HISTORY_FILE_SUCCESS );
  FD_TEST( out.root==16UL && !out.voted_cnt && !out.votes_cast_cnt && !out.notarized_blocks_cnt && !out.parent_ready_cnt );

  teardown_votor( votor );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_timeouts();
  test_timeouts_interleaved();
  test_boot_mid_window();
  test_notar_and_final();
  test_notar_out_of_order();
  test_pending_block_not_notarized_after_skip();
  test_safe_to_notar();
  test_safe_to_skip();
  test_bls_selector_rotates_with_epoch();
  test_missing_bls_selector_disables_voting();
  test_set_bls_pubkey();
  test_missing_bls_selector_records_notar();
  test_missing_bls_selector_records_final();
  test_set_rank();
  test_wait_to_vote();
  test_wait_to_vote_slot();
  test_window_start_at_first_unpruned();
  test_boot_mid_window_notar_child();
  test_missing_bls_selector_still_skips_other_epoch();
  test_prunes_to_finalized_window();
  test_timeout_below_final();
  test_vote_history_ser();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
