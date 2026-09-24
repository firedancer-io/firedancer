#include "ag_votor.c"
#include "ag_pool.h"
#include "test_ag_cert_builder.h"

/* Failover moves one Alpenglow identity between two votors.  This
   covers the pieces that keep that safe, exporting and adopting the
   vote history, moving the finality anchor without a cert and swapping
   the rank, on the votor and on the pool. */

#define NV                 (2UL)
#define TEST_SLOT_MAX      (256UL) /* test_export_truncates_by_window votes 164 slots */
#define TEST_POOL_SLOT_MAX (64UL)
#define TEST_SHRED_VERSION ((ushort)0x5a5a)

/* Long enough for every timeout of a leader window to come due. */

#define TEST_NS_PER_SLOT       (400000000L)
#define TEST_WINDOW_ELAPSED_NS (AG_DELTA_TIMEOUT_NS + (long)(AG_SLOTS_PER_WINDOW+1UL)*TEST_NS_PER_SLOT)

#define FD_TEST_NO_MSG( votor ) do {           \
    ag_vote_t unused_;                         \
    FD_TEST( !try_recv( (votor), &unused_ ) ); \
  } while( 0 )

/* Two votors are live at once when a history moves from one to the
   other, so each gets its own scratch. */

#define SCRATCH_MAX (1UL<<23) /* 8 MiB */

static uchar scratch_a[ SCRATCH_MAX ] __attribute__((aligned(128)));
static uchar scratch_b[ SCRATCH_MAX ] __attribute__((aligned(128)));

/* The pool is nearly all slot state, same sizing as test_ag_pool.c. */

#define POOL_SCRATCH_MAX (TEST_POOL_SLOT_MAX*sizeof(ag_slot_state_t)+(4UL<<20))

static uchar pool_scratch[ POOL_SCRATCH_MAX ] __attribute__((aligned(128)));

static fd_bls_sec_t        g_sk  [ NV ];
static ag_validator_info_t g_info[ NV ];
static ulong               g_hash_ctr = 0UL;
static fd_bls_set_t        bad[ fd_bls_set_word_cnt ];

/* The epoch info is nearly 300 KiB, too big for the stack. */

static ag_epoch_info_t epoch_info_mem;

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
    fd_memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    fd_bls_sec_to_pub( &g_sk[i], &g_info[i].bls_key );
  }
}

static slot_state_ele_t const *
state_of( ag_votor_t const * votor,
          ulong              slot ) {
  return slot_state_map_ele_query_const( votor->slot_states->map, &slot, NULL, votor->slot_states->pool );
}

static int
contains_slot( ag_votor_t const * votor,
               ulong              slot ) {
  return state_of( votor, slot )!=NULL;
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

/* The votor's outbound vote stream is drained directly, recv insists
   on a vote and try_recv does not. */

static int
try_recv( ag_votor_t * votor,
          ag_vote_t *  out ) {
  ag_event_vote_t event;
  if( FD_UNLIKELY( !ag_votor_poll_vote_event( votor, &event ) ) ) return 0;
  *out = event.vote;
  return 1;
}

static ag_vote_t
recv( ag_votor_t * votor ) {
  ag_vote_t vote;
  FD_TEST( try_recv( votor, &vote ) );
  return vote;
}

/* Fires every timeout due at now, one at a time like the tile does. */

static void
handle_timeouts( ag_votor_t * votor,
                 long         now ) {
  ag_event_timeout_t event;
  while( ag_votor_poll_timeout_event( votor, now, &event ) ) ag_votor_handle_timeout_event( votor, &event );
}

/* Creates a fresh fully wired-up votor at slot 0 in mem. */

static ag_votor_t *
setup_votor( void * mem,
             long   now ) {
  create_validators();
  FD_TEST( ag_votor_footprint( TEST_SLOT_MAX )<=SCRATCH_MAX );
  ag_votor_t * votor = ag_votor_join( ag_votor_new( mem, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( votor );
  ag_votor_init         ( votor, 0UL, now, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 0UL );
  return votor;
}

static void
teardown_votor( ag_votor_t * votor ) {
  ag_votor_delete( ag_votor_leave( votor ) );
}

/* Notifies the votor of a new block and returns the resulting notar
   vote. */

static ag_vote_t
send_block_and_expect_notar( ag_votor_t *          votor,
                             ulong                 slot,
                             ag_block_id_t const * parent ) {
  ag_event_block_t first_shred = { .kind = AG_EVENT_BLOCK_FIRST_SHRED, .slot = slot };
  ag_votor_handle_block_event ( votor, &first_shred );

  ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED };
  block.slot              = slot;
  random_hash( block.block_info.hash );
  block.block_info.parent = *parent;
  ag_votor_handle_replay_event( votor, &block );

  ag_vote_t msg = recv( votor );
  FD_TEST( msg.kind==AG_VOTE_KIND_NOTAR );
  FD_TEST( ag_vote_slot( &msg )==slot );
  return msg;
}

/* Checks one history record, notar_hash may be NULL when the record
   has none. */

static void
expect_rec( ag_hist_t const * hist,
            ulong             idx,
            ulong             slot,
            uint              flags,
            uchar const *     notar_hash ) {
  FD_TEST( idx<hist->rec_cnt );
  ag_hist_rec_t const * rec = &hist->rec[ idx ];
  FD_TEST( rec->slot ==slot         );
  FD_TEST( rec->flags==(uchar)flags );
  if( notar_hash ) FD_TEST( fd_memeq( rec->notar_hash, notar_hash, sizeof(ag_block_hash_t) ) );
}

/* Serializes hist, decodes it back and checks every field survived. */

static void
round_trip( ag_hist_t const * hist ) {
  uchar buf[ AG_HIST_SER_MAX ];
  ulong sz = 0UL;
  FD_TEST( !ag_hist_ser( hist, buf, sizeof(buf), &sz ) );

  ag_hist_t out; fd_memset( &out, 0xAA, sizeof(ag_hist_t) );
  FD_TEST( !ag_hist_de( buf, sz, &out ) );
  FD_TEST( out.anchor          ==hist->anchor           );
  FD_TEST( out.last_leader_slot==hist->last_leader_slot );
  FD_TEST( out.rec_cnt         ==hist->rec_cnt          );
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    FD_TEST( out.rec[ i ].slot ==hist->rec[ i ].slot  );
    FD_TEST( out.rec[ i ].flags==hist->rec[ i ].flags );
    if( hist->rec[ i ].flags & AG_HIST_FLAG_VOTED_NOTAR ) FD_TEST( fd_memeq( out.rec[ i ].notar_hash, hist->rec[ i ].notar_hash, sizeof(ag_block_hash_t) ) );
  }
}

/* test_export_shape: the export is the init slot plus every voted slot
   in ascending order, notar votes keep their hash, skipped slots show
   as bad window, the frame round trips through the wire format and a
   votor that never ran init exports nothing. */

static void
test_export_shape( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();

  /* notar votes on 1, 2 and 3, each block on top of the last */
  ag_block_hash_t hash[ 4 ];
  genesis_hash( hash[ 0 ] );
  for( ulong s=1UL; s<=3UL; s++ ) {
    ag_vote_t vote = send_block_and_expect_notar( votor, s, &parent );
    fd_memcpy( hash[ s ], vote.notar.block_hash, sizeof(ag_block_hash_t) );
    parent = ag_block_id( s, hash[ s ] );
  }
  FD_TEST_NO_MSG( votor );

  ag_hist_t hist;
  FD_TEST( !ag_votor_hist_export( votor, 42UL, &hist ) );
  FD_TEST( hist.anchor          ==0UL  ); /* the init slot is the highest final cert slot */
  FD_TEST( hist.last_leader_slot==42UL );
  FD_TEST( hist.rec_cnt         ==4UL  );
  expect_rec( &hist, 0UL, 0UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR|AG_HIST_FLAG_RETIRED, hash[ 0 ] );
  for( ulong s=1UL; s<=3UL; s++ ) expect_rec( &hist, s, s, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR, hash[ s ] );
  round_trip( &hist );

  /* next window, notar on 4 then let the rest of the window time out */
  ag_event_pool_t parent_ready = { .kind = AG_EVENT_POOL_PARENT_READY };
  parent_ready.parent_ready.slot   = 4UL;
  parent_ready.parent_ready.parent = parent;
  ag_votor_handle_pool_event( votor, &parent_ready, 0L );
  ag_vote_t vote4 = send_block_and_expect_notar( votor, 4UL, &parent );
  handle_timeouts( votor, TEST_WINDOW_ELAPSED_NS );
  for( ulong s=5UL; s<8UL; s++ ) {
    ag_vote_t skip = recv( votor );
    FD_TEST( skip.kind==AG_VOTE_KIND_SKIP );
    FD_TEST( ag_vote_slot( &skip )==s );
  }
  FD_TEST_NO_MSG( votor );

  FD_TEST( !ag_votor_hist_export( votor, 42UL, &hist ) );
  FD_TEST( hist.anchor ==0UL );
  FD_TEST( hist.rec_cnt==8UL );
  expect_rec( &hist, 4UL, 4UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR, vote4.notar.block_hash );
  for( ulong s=5UL; s<8UL; s++ ) expect_rec( &hist, s, s, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW, NULL );
  round_trip( &hist );

  /* a votor that never ran init has nothing to say */
  ag_votor_t * fresh = ag_votor_join( ag_votor_new( scratch_b, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( fresh );
  FD_TEST( ag_votor_highest_final_cert_slot( fresh )==ULONG_MAX );
  fd_memset( &hist, 0xAA, sizeof(ag_hist_t) );
  FD_TEST( !ag_votor_hist_export( fresh, 7UL, &hist ) );
  FD_TEST( hist.anchor          ==0UL );
  FD_TEST( hist.rec_cnt         ==0UL );
  FD_TEST( hist.last_leader_slot==7UL );
  teardown_votor( fresh );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: export_shape" ));
}

/* test_export_truncates_by_window: more voted slots than a history
   holds, so the export drops whole windows from the bottom, lifts the
   anchor to cover the first kept window, and a peer that adopts the
   frame stays quiet below that window. */

static void
test_export_truncates_by_window( void ) {
  ag_votor_t * votor = setup_votor( scratch_a, 0L );

  /* no finality at all, just skip every slot of 41 windows */
  ulong window_cnt = 41UL;
  ulong voted_cnt  = window_cnt*AG_SLOTS_PER_WINDOW;
  FD_TEST( voted_cnt>AG_HIST_MAX );
  FD_TEST( voted_cnt<TEST_SLOT_MAX );
  long now = 0L;
  for( ulong w=0UL; w<window_cnt; w++ ) {
    ulong start = w*AG_SLOTS_PER_WINDOW;

    /* arms the window's timeouts, window 0 was armed by init and its
       slot is retired so this one is ignored there */
    ag_event_pool_t parent_ready = { .kind = AG_EVENT_POOL_PARENT_READY };
    parent_ready.parent_ready.slot   = start;
    parent_ready.parent_ready.parent = random_block_id( fd_ulong_sat_sub( start, 1UL ) );
    ag_votor_handle_pool_event( votor, &parent_ready, now );

    now += TEST_WINDOW_ELAPSED_NS;
    handle_timeouts( votor, now );
    ag_vote_t vote;
    while( try_recv( votor, &vote ) ) {
      FD_TEST( vote.kind==AG_VOTE_KIND_SKIP );
      FD_TEST( ag_first_slot_in_window( ag_vote_slot( &vote ) )==start );
    }
    for( ulong s=start; s<start+AG_SLOTS_PER_WINDOW; s++ ) FD_TEST( ag_votor_has_voted( votor, s ) );
  }
  FD_TEST( ag_votor_highest_final_cert_slot( votor )==0UL );

  ag_hist_t hist;
  FD_TEST( ag_votor_hist_export( votor, ULONG_MAX, &hist )==1 );
  FD_TEST( hist.rec_cnt>0UL          );
  FD_TEST( hist.rec_cnt<=AG_HIST_MAX );
  ulong lowest = hist.rec[ 0 ].slot;
  FD_TEST( ag_is_start_of_window( lowest ) );
  FD_TEST( hist.anchor==lowest+AG_REWARD_SLOT_DELTA ); /* 0 is below that, so the anchor lifts */
  FD_TEST( ag_hist_first_slot( hist.anchor )==lowest );
  for( ulong i=0UL; i<hist.rec_cnt; i++ ) {
    FD_TEST( hist.rec[ i ].slot>=lowest );
    FD_TEST( hist.rec[ i ].flags==(AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW) );
  }
  /* 164 voted and 128 kept are both whole windows, so the cut lands
     exactly on the capacity */
  FD_TEST( hist.rec_cnt==AG_HIST_MAX );
  FD_TEST( lowest==voted_cnt-AG_HIST_MAX );
  round_trip( &hist );

  /* a peer at slot 0 adopts it and moves up to the frame */
  ag_votor_t * peer = setup_votor( scratch_b, 0L );
  FD_TEST( ag_votor_highest_final_cert_slot( peer )==0UL );
  FD_TEST( ag_votor_hist_adopt( peer, &hist )==0UL );
  FD_TEST( ag_votor_highest_final_cert_slot( peer )==hist.anchor );
  FD_TEST( ag_votor_first_unpruned_slot( peer )==lowest );
  FD_TEST( !contains_slot( peer, 0UL ) );
  for( ulong i=0UL; i<hist.rec_cnt; i++ ) FD_TEST( ag_votor_has_voted( peer, hist.rec[ i ].slot ) );

  /* nothing below the first kept window draws a vote */
  ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = lowest-1UL };
  random_hash( block.block_info.hash );
  block.block_info.parent = random_block_id( lowest-2UL );
  ag_votor_handle_replay_event( peer, &block );
  FD_TEST_NO_MSG( peer );
  FD_TEST( !contains_slot( peer, lowest-1UL ) );

  ag_event_timeout_t timeout = { .kind = AG_EVENT_TIMEOUT, .slot = lowest-1UL };
  ag_votor_handle_timeout_event( peer, &timeout );
  FD_TEST_NO_MSG( peer );

  teardown_votor( peer );
  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: export_truncates_by_window" ));
}

/* test_advance_root: moving the anchor without a cert prunes below
   the reward window the way a final cert does, never moves backwards
   and does nothing before init. */

static void
test_advance_root( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();
  for( ulong s=1UL; s<=3UL; s++ ) {
    ag_vote_t vote = send_block_and_expect_notar( votor, s, &parent );
    parent = ag_block_id( s, vote.notar.block_hash );
  }
  for( ulong s=0UL; s<=3UL; s++ ) FD_TEST( contains_slot( votor, s ) );

  ag_votor_advance_root( votor, 20UL );
  FD_TEST( ag_votor_highest_final_cert_slot( votor )==20UL );
  FD_TEST( ag_votor_first_unpruned_slot( votor )==ag_first_slot_in_window( 20UL-AG_REWARD_SLOT_DELTA ) );
  FD_TEST( ag_votor_first_unpruned_slot( votor )==12UL );
  for( ulong s=0UL; s<=3UL; s++ ) FD_TEST( !contains_slot( votor, s ) );
  FD_TEST( min_live_slot( votor )>=12UL );
  FD_TEST_NO_MSG( votor );

  /* a block below the new root is ignored outright */
  ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = 3UL };
  random_hash( block.block_info.hash );
  block.block_info.parent = random_block_id( 2UL );
  ag_votor_handle_replay_event( votor, &block );
  FD_TEST_NO_MSG( votor );
  FD_TEST( !contains_slot( votor, 3UL ) );

  /* older or equal roots are no-ops */
  ag_votor_advance_root( votor, 5UL );
  FD_TEST( ag_votor_highest_final_cert_slot( votor )==20UL );
  ag_votor_advance_root( votor, 20UL );
  FD_TEST( ag_votor_highest_final_cert_slot( votor )==20UL );
  FD_TEST( ag_votor_first_unpruned_slot( votor )==12UL );

  /* so is a root on a votor that never ran init */
  ag_votor_t * fresh = ag_votor_join( ag_votor_new( scratch_b, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( fresh );
  ag_votor_advance_root( fresh, 20UL );
  FD_TEST( ag_votor_highest_final_cert_slot( fresh )==ULONG_MAX );
  FD_TEST( min_live_slot( fresh )==ULONG_MAX );
  teardown_votor( fresh );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: advance_root" ));
}

/* test_adopt_union: adopting ORs the peer's marks into ours, a notar
   hash disagreement counts as a conflict and theirs wins, adopted
   slots refuse a later block, and a block parked as pending stops
   being pending once the peer says the slot was voted. */

static void
test_adopt_union( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();

  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_block_hash_t h1; fd_memcpy( h1, vote.notar.block_hash, sizeof(ag_block_hash_t) );

  /* slot 2 gets its skip mark from a peer history rather than a vote */
  ag_hist_t skip2 = { .anchor = 0UL, .last_leader_slot = ULONG_MAX, .rec_cnt = 1UL };
  skip2.rec[ 0 ].slot  = 2UL;
  skip2.rec[ 0 ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW;
  FD_TEST( ag_votor_hist_adopt( votor, &skip2 )==0UL );
  slot_state_ele_t const * s2 = state_of( votor, 2UL );
  FD_TEST( s2 && s2->voted && s2->bad_window && !s2->voted_notar );
  FD_TEST_NO_MSG( votor );

  /* the peer notarised a different block on 1, skipped 2 like us and
     finalised 3 */
  ag_block_hash_t h2; random_hash( h2 );
  ag_block_hash_t h3; random_hash( h3 );
  FD_TEST( !fd_memeq( h1, h2, sizeof(ag_block_hash_t) ) );
  ag_hist_t hist = { .anchor = 0UL, .last_leader_slot = ULONG_MAX, .rec_cnt = 3UL };
  hist.rec[ 0 ].slot  = 1UL;
  hist.rec[ 0 ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR;
  fd_memcpy( hist.rec[ 0 ].notar_hash, h2, sizeof(ag_block_hash_t) );
  hist.rec[ 1 ].slot  = 2UL;
  hist.rec[ 1 ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW;
  hist.rec[ 2 ].slot  = 3UL;
  hist.rec[ 2 ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR|AG_HIST_FLAG_RETIRED;
  fd_memcpy( hist.rec[ 2 ].notar_hash, h3, sizeof(ag_block_hash_t) );
  FD_TEST( ag_votor_hist_adopt( votor, &hist )==1UL ); /* h1 against h2 on slot 1 */

  slot_state_ele_t const * s1 = state_of( votor, 1UL );
  FD_TEST( s1 && s1->voted && s1->voted_notar && !s1->bad_window );
  FD_TEST( fd_memeq( s1->voted_notar_hash, h2, sizeof(ag_block_hash_t) ) );
  FD_TEST( s2->voted && s2->bad_window && !s2->voted_notar );
  slot_state_ele_t const * s3 = state_of( votor, 3UL );
  FD_TEST( s3 && s3->voted && s3->voted_notar && s3->retired && !s3->bad_window );
  FD_TEST( fd_memeq( s3->voted_notar_hash, h3, sizeof(ag_block_hash_t) ) );
  FD_TEST( ag_votor_has_voted( votor, 2UL ) );
  FD_TEST( ag_votor_has_voted( votor, 3UL ) );
  FD_TEST_NO_MSG( votor );

  /* blocks for the adopted slots draw no vote */
  for( ulong s=2UL; s<=3UL; s++ ) {
    ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = s };
    random_hash( block.block_info.hash );
    block.block_info.parent = random_block_id( s-1UL );
    ag_votor_handle_replay_event( votor, &block );
    FD_TEST_NO_MSG( votor );
  }

  /* a block with no parent ready for its window gets parked, then a
     peer record for the slot closes it without a vote */
  ag_event_replay_t late = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = 4UL };
  random_hash( late.block_info.hash );
  late.block_info.parent = ag_block_id( 3UL, h3 );
  ag_votor_handle_replay_event( votor, &late );
  FD_TEST_NO_MSG( votor );
  slot_state_ele_t const * s4 = state_of( votor, 4UL );
  FD_TEST( s4 && s4->pending_block && !s4->voted );
  FD_TEST( !pending_dlist_is_empty( votor->pending_dlist, votor->slot_states->pool ) );

  ag_hist_t hist4 = { .anchor = 0UL, .last_leader_slot = ULONG_MAX, .rec_cnt = 1UL };
  hist4.rec[ 0 ].slot  = 4UL;
  hist4.rec[ 0 ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW;
  FD_TEST( ag_votor_hist_adopt( votor, &hist4 )==0UL );
  FD_TEST( s4->voted && s4->bad_window && !s4->pending_block );
  FD_TEST( pending_dlist_is_empty( votor->pending_dlist, votor->slot_states->pool ) );
  FD_TEST_NO_MSG( votor );

  /* the parent turning up late does not revive it */
  ag_event_pool_t parent_ready = { .kind = AG_EVENT_POOL_PARENT_READY };
  parent_ready.parent_ready.slot   = 4UL;
  parent_ready.parent_ready.parent = late.block_info.parent;
  ag_votor_handle_pool_event( votor, &parent_ready, 0L );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: adopt_union" ));
}

/* test_pool_advance_root: the pool takes finality from replay without
   a cert, its slot bounds follow the new root, an older root is
   ignored and a rank swap reaches slot states that already exist. */

static void
test_pool_advance_root( void ) {
  create_validators();
  epoch_info_build( &epoch_info_mem, g_info, NV );

  FD_TEST( ag_pool_footprint( TEST_POOL_SLOT_MAX )<=POOL_SCRATCH_MAX );
  ag_pool_t * pool = ag_pool_join( ag_pool_new( pool_scratch, TEST_POOL_SLOT_MAX, 42UL ) );
  FD_TEST( pool );
  ag_pool_init( pool, 0UL );
  ag_pool_advance_epoch( pool, &epoch_info_mem, 0UL, 0UL );
  FD_TEST( ag_pool_finalized_slot( pool )==0UL );

  /* a chain of 12 blocks on genesis */
  ag_block_id_t chain[ 13 ];
  chain[ 0 ] = genesis_block_id();
  for( ulong s=1UL; s<=12UL; s++ ) {
    chain[ s ] = random_block_id( s );
    FD_TEST( ag_pool_add_block( pool, &chain[ s ], &chain[ s-1UL ], bad )==AG_POOL_SUCCESS );
  }
  FD_TEST( ag_pool_slot_state( pool, 5UL ) );
  FD_TEST( ag_pool_slot_state( pool, 5UL )->own_rank==0UL );

  /* with the root at 0 the far bound is slot_max-8, so neither of
     these fits yet */
  ulong         far_slot    = 12UL+TEST_POOL_SLOT_MAX-AG_REWARD_SLOT_DELTA+1UL;
  ag_block_id_t far_block   = random_block_id( far_slot     );
  ag_block_id_t far_parent  = random_block_id( far_slot-1UL );
  ulong         near_slot   = TEST_POOL_SLOT_MAX-AG_REWARD_SLOT_DELTA+4UL;
  ag_block_id_t near_block  = random_block_id( near_slot     );
  ag_block_id_t near_parent = random_block_id( near_slot-1UL );
  FD_TEST( ag_pool_add_block( pool, &far_block,  &far_parent,  bad )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  FD_TEST( ag_pool_add_block( pool, &near_block, &near_parent, bad )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );

  ag_pool_advance_root( pool, &chain[ 12 ] );
  FD_TEST( ag_pool_finalized_slot( pool )==12UL );
  FD_TEST( ag_pool_finalized_block_hash( pool ) );
  FD_TEST( fd_memeq( ag_pool_finalized_block_hash( pool ), chain[ 12 ].hash, sizeof(ag_block_hash_t) ) );

  /* the bounds moved up with the root, 13 and the near block fit, the
     far block still does not and a block below the root is out */
  ag_block_id_t block13 = random_block_id( 13UL );
  FD_TEST( ag_pool_add_block( pool, &block13,    &chain[ 12 ], bad )==AG_POOL_SUCCESS                );
  FD_TEST( ag_pool_add_block( pool, &near_block, &near_parent, bad )==AG_POOL_SUCCESS                );
  FD_TEST( ag_pool_add_block( pool, &far_block,  &far_parent,  bad )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  ag_block_id_t block11 = random_block_id( 11UL );
  FD_TEST( ag_pool_add_block( pool, &block11,    &chain[ 10 ], bad )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );

  /* older or equal roots are no-ops */
  ag_pool_advance_root( pool, &chain[ 5 ] );
  FD_TEST( ag_pool_finalized_slot( pool )==12UL );
  ag_pool_advance_root( pool, &chain[ 12 ] );
  FD_TEST( ag_pool_finalized_slot( pool )==12UL );

  /* the rank swap rewrites states created under the old rank, and a
     state made after it is born with the new one */
  ag_slot_state_t const * s5 = ag_pool_slot_state( pool, 5UL );
  FD_TEST( s5 && s5->own_rank==0UL );
  ag_pool_set_ranks( pool, 3UL, 3UL, 3UL );
  FD_TEST( ag_pool_slot_state( pool,  5UL )->own_rank==3UL );
  FD_TEST( ag_pool_slot_state( pool, 13UL )->own_rank==3UL );
  ag_pool_set_ranks( pool, USHORT_MAX, USHORT_MAX, USHORT_MAX );
  FD_TEST( ag_pool_slot_state( pool,  5UL )->own_rank==(ulong)USHORT_MAX );
  FD_TEST( ag_pool_slot_state( pool, 13UL )->own_rank==(ulong)USHORT_MAX );
  ag_block_id_t block14 = random_block_id( 14UL );
  FD_TEST( ag_pool_add_block( pool, &block14, &block13, bad )==AG_POOL_SUCCESS );
  FD_TEST( ag_pool_slot_state( pool, 14UL )->own_rank==(ulong)USHORT_MAX );

  ag_pool_delete( ag_pool_leave( pool ) );
  FD_LOG_NOTICE(( "pass: pool_advance_root" ));
}

/* test_set_ranks_votor: the three ranks land on their epochs, own_rank
   picks by the slot's epoch and the next vote signs with the new
   rank. */

static void
test_set_ranks_votor( void ) {
  ag_votor_t * votor = setup_votor( scratch_a, 0L ); /* curr epoch at slot 0, rank 0 */
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 100UL ); /* fills next */
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 200UL ); /* rolls, prev 0, curr 100, next 200 */
  FD_TEST( votor->prev_epoch_slot==  0UL );
  FD_TEST( votor->curr_epoch_slot==100UL );
  FD_TEST( votor->next_epoch_slot==200UL );
  FD_TEST( own_rank( votor, 50UL )==(ushort)0 );

  ag_votor_set_ranks( votor, 1UL, 2UL, 3UL );
  FD_TEST( votor->prev_epoch_rank==1UL );
  FD_TEST( votor->curr_epoch_rank==2UL );
  FD_TEST( votor->next_epoch_rank==3UL );
  FD_TEST( own_rank( votor,   0UL )==(ushort)1 );
  FD_TEST( own_rank( votor,  99UL )==(ushort)1 );
  FD_TEST( own_rank( votor, 100UL )==(ushort)2 );
  FD_TEST( own_rank( votor, 199UL )==(ushort)2 );
  FD_TEST( own_rank( votor, 200UL )==(ushort)3 );
  FD_TEST( own_rank( votor, ULONG_MAX-1UL )==(ushort)3 );

  /* the rank shows up in the next vote */
  ag_block_id_t parent = genesis_block_id();
  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );
  FD_TEST( vote.notar.rank==(ushort)1 );

  /* and unranked again */
  ag_votor_set_ranks( votor, USHORT_MAX, USHORT_MAX, USHORT_MAX );
  FD_TEST( own_rank( votor,   1UL )==USHORT_MAX );
  FD_TEST( own_rank( votor, 150UL )==USHORT_MAX );
  FD_TEST( own_rank( votor, 250UL )==USHORT_MAX );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: set_ranks_votor" ));
}

/* test_mark_unsent_notar: a dropped notar loses its notar mark so it
   cannot become the parent of a later notar, while a dropped skip
   leaves the notar mark and its hash in place. */

static void
test_mark_unsent_notar( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();

  /* notar on slot 1, a non window start slot so it sets a notar hash */
  ag_vote_t notar = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_block_hash_t h1; fd_memcpy( h1, notar.notar.block_hash, sizeof(ag_block_hash_t) );
  FD_TEST_NO_MSG( votor );

  /* dropping the notar keeps voted and bad window and clears the mark */
  ag_votor_mark_unsent( votor, &notar );

  ag_block_hash_t zero; fd_memset( zero, 0, sizeof(ag_block_hash_t) );
  ag_hist_t hist;
  FD_TEST( !ag_votor_hist_export( votor, 42UL, &hist ) );
  expect_rec( &hist, 1UL, 1UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW, zero );

  /* slot 1 with no notar mark cannot parent a notar on slot 2 */
  ag_event_replay_t block = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = 2UL };
  random_hash( block.block_info.hash );
  block.block_info.parent = ag_block_id( 1UL, h1 );
  ag_votor_handle_replay_event( votor, &block );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );

  /* a dropped skip on a notarised slot leaves the notar mark in place */
  ag_votor_t *  keep    = setup_votor( scratch_b, 0L );
  ag_block_id_t kparent = genesis_block_id();
  ag_vote_t     knotar  = send_block_and_expect_notar( keep, 1UL, &kparent );
  ag_block_hash_t hk; fd_memcpy( hk, knotar.notar.block_hash, sizeof(ag_block_hash_t) );

  ag_vote_t skip; fd_memset( &skip, 0, sizeof(ag_vote_t) );
  skip.kind      = AG_VOTE_KIND_SKIP;
  skip.skip.slot = 1UL;
  ag_votor_mark_unsent( keep, &skip );

  slot_state_ele_t const * s1 = state_of( keep, 1UL );
  FD_TEST( s1 && s1->voted && s1->voted_notar && s1->bad_window );
  FD_TEST( fd_memeq( s1->voted_notar_hash, hk, sizeof(ag_block_hash_t) ) );

  ag_hist_t khist;
  FD_TEST( !ag_votor_hist_export( keep, 42UL, &khist ) );
  expect_rec( &khist, 1UL, 1UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR|AG_HIST_FLAG_BAD_WINDOW, hk );

  teardown_votor( keep );
  FD_LOG_NOTICE(( "pass: mark_unsent_notar" ));
}

/* test_export_hash_truncation: the export writes a notar hash only for
   notar records, so through the wire format a notar record keeps its 32
   bytes and a plain voted record comes back with a zero hash. */

static void
test_export_hash_truncation( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();

  /* a notar with a real hash on slot 1, a plain bad window on slot 2 */
  ag_vote_t notar = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_block_hash_t h1; fd_memcpy( h1, notar.notar.block_hash, sizeof(ag_block_hash_t) );
  ag_vote_t skip; fd_memset( &skip, 0, sizeof(ag_vote_t) );
  skip.kind      = AG_VOTE_KIND_SKIP;
  skip.skip.slot = 2UL;
  ag_votor_mark_unsent( votor, &skip );

  ag_hist_t hist;
  FD_TEST( !ag_votor_hist_export( votor, 42UL, &hist ) );
  FD_TEST( hist.rec_cnt==3UL );
  expect_rec( &hist, 1UL, 1UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR, h1   );
  expect_rec( &hist, 2UL, 2UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW,  NULL );

  uchar buf[ AG_HIST_SER_MAX ];
  ulong sz = 0UL;
  FD_TEST( !ag_hist_ser( &hist, buf, sizeof(buf), &sz ) );
  ag_hist_t out; fd_memset( &out, 0xAA, sizeof(ag_hist_t) );
  FD_TEST( !ag_hist_de( buf, sz, &out ) );
  FD_TEST( out.rec_cnt==3UL );

  /* the notar hash survives the wire, the plain record comes back zero */
  ag_block_hash_t zero; fd_memset( zero, 0, sizeof(ag_block_hash_t) );
  FD_TEST(  ( out.rec[ 1 ].flags & AG_HIST_FLAG_VOTED_NOTAR ) );
  FD_TEST(  fd_memeq( out.rec[ 1 ].notar_hash, h1,   sizeof(ag_block_hash_t) ) );
  FD_TEST( !( out.rec[ 2 ].flags & AG_HIST_FLAG_VOTED_NOTAR ) );
  FD_TEST(  fd_memeq( out.rec[ 2 ].notar_hash, zero, sizeof(ag_block_hash_t) ) );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: export_hash_truncation" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_export_shape();
  test_export_truncates_by_window();
  test_advance_root();
  test_adopt_union();
  test_pool_advance_root();
  test_set_ranks_votor();
  test_mark_unsent_notar();
  test_export_hash_truncation();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
