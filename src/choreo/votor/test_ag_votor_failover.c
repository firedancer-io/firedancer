#include "ag_votor.c"
#include "test_ag_cert_builder.h"

/* Failover moves one Alpenglow identity between two votors.  This
   covers the pieces that keep that safe, exporting and adopting the
   vote history, moving the anchor up to an adopted history's and
   swapping the rank. */

#define NV                 (2UL)
#define TEST_SLOT_MAX      (256UL) /* test_export_truncates_by_window votes 164 slots */
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

static fd_bls_sec_t g_sk[ NV ];
static ulong        g_hash_ctr = 0UL;

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
  for( ulong i=0UL; i<NV; i++ ) fd_memset( &g_sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
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
  ag_bls_key_t bls_key; bls_key_from_sec( bls_key, &g_sk[0] );
  ag_votor_init         ( votor, 0UL, now, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, sec_sign_fn, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 0UL, bls_key );
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
  ag_event_replay_t block = {0};
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
  FD_TEST( out.vote_bound      ==hist->vote_bound       );
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
  FD_TEST( hist.vote_bound      ==ULONG_MAX );
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
  ag_event_replay_t block = { .slot = lowest-1UL };
  random_hash( block.block_info.hash );
  block.block_info.parent = random_block_id( lowest-2UL );
  ag_votor_handle_replay_event( peer, &block );
  FD_TEST_NO_MSG( peer );
  FD_TEST( !contains_slot( peer, lowest-1UL ) );

  ag_event_timeout_t timeout = { .slot = lowest-1UL };
  ag_votor_handle_timeout_event( peer, &timeout );
  FD_TEST_NO_MSG( peer );

  teardown_votor( peer );
  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: export_truncates_by_window" ));
}

/* test_advance_root: moving the anchor to an adopted history's prunes
   below the reward window the way a final cert does, never moves
   backwards and does nothing before init. */

static void
test_advance_root( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();
  for( ulong s=1UL; s<=3UL; s++ ) {
    ag_vote_t vote = send_block_and_expect_notar( votor, s, &parent );
    parent = ag_block_id( s, vote.notar.block_hash );
  }
  for( ulong s=0UL; s<=3UL; s++ ) FD_TEST( contains_slot( votor, s ) );

  advance_root( votor, 20UL );
  FD_TEST( ag_votor_highest_final_cert_slot( votor )==20UL );
  FD_TEST( ag_votor_first_unpruned_slot( votor )==ag_first_slot_in_window( 20UL-AG_REWARD_SLOT_DELTA ) );
  FD_TEST( ag_votor_first_unpruned_slot( votor )==12UL );
  for( ulong s=0UL; s<=3UL; s++ ) FD_TEST( !contains_slot( votor, s ) );
  FD_TEST( min_live_slot( votor )>=12UL );
  FD_TEST_NO_MSG( votor );

  /* a block below the new root is ignored outright */
  ag_event_replay_t block = { .slot = 3UL };
  random_hash( block.block_info.hash );
  block.block_info.parent = random_block_id( 2UL );
  ag_votor_handle_replay_event( votor, &block );
  FD_TEST_NO_MSG( votor );
  FD_TEST( !contains_slot( votor, 3UL ) );

  /* older or equal roots are no-ops */
  advance_root( votor, 5UL );
  FD_TEST( ag_votor_highest_final_cert_slot( votor )==20UL );
  advance_root( votor, 20UL );
  FD_TEST( ag_votor_highest_final_cert_slot( votor )==20UL );
  FD_TEST( ag_votor_first_unpruned_slot( votor )==12UL );

  /* so is a root on a votor that never ran init */
  ag_votor_t * fresh = ag_votor_join( ag_votor_new( scratch_b, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( fresh );
  advance_root( fresh, 20UL );
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
    ag_event_replay_t block = { .slot = s };
    random_hash( block.block_info.hash );
    block.block_info.parent = random_block_id( s-1UL );
    ag_votor_handle_replay_event( votor, &block );
    FD_TEST_NO_MSG( votor );
  }

  /* a block with no parent ready for its window gets parked, then a
     peer record for the slot closes it without a vote */
  ag_event_replay_t late = { .slot = 4UL };
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

/* test_set_keys_votor: the three ranks land on their epochs, the epoch
   of a slot picks the rank and the next vote signs with it.  An epoch
   without a key casts nothing. */

static void
test_set_keys_votor( void ) {
  ag_votor_t * votor = setup_votor( scratch_a, 0L ); /* curr epoch at slot 0, rank 0 */
  ag_bls_key_t bls_key; bls_key_from_sec( bls_key, &g_sk[0] );
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 100UL, bls_key ); /* fills next */
  ag_votor_advance_epoch( votor, TEST_NS_PER_SLOT, 0UL, 200UL, bls_key ); /* rolls, prev 0, curr 100, next 200 */
  FD_TEST( votor->prev_epoch.start_slot==  0UL );
  FD_TEST( votor->curr_epoch.start_slot==100UL );
  FD_TEST( votor->next_epoch.start_slot==200UL );
  FD_TEST( own_epoch( votor, 50UL )->rank==0UL );

  ag_votor_set_keys( votor, 1UL, bls_key, 2UL, bls_key, 3UL, bls_key );
  FD_TEST( votor->prev_epoch.rank==1UL && votor->prev_epoch.start_slot==  0UL );
  FD_TEST( votor->curr_epoch.rank==2UL && votor->curr_epoch.start_slot==100UL );
  FD_TEST( votor->next_epoch.rank==3UL && votor->next_epoch.start_slot==200UL );
  FD_TEST( own_epoch( votor,   0UL )->rank==1UL );
  FD_TEST( own_epoch( votor,  99UL )->rank==1UL );
  FD_TEST( own_epoch( votor, 100UL )->rank==2UL );
  FD_TEST( own_epoch( votor, 199UL )->rank==2UL );
  FD_TEST( own_epoch( votor, 200UL )->rank==3UL );
  FD_TEST( own_epoch( votor, ULONG_MAX-1UL )->rank==3UL );

  /* the rank shows up in the next vote */
  ag_block_id_t parent = genesis_block_id();
  ag_vote_t vote = send_block_and_expect_notar( votor, 1UL, &parent );
  FD_TEST( vote.notar.rank==(ushort)1 );

  /* unranked and without keys, the next block draws no vote */
  ag_votor_set_keys( votor, USHORT_MAX, NULL, USHORT_MAX, NULL, USHORT_MAX, NULL );
  FD_TEST( own_epoch( votor,   1UL )->rank==USHORT_MAX && !own_epoch( votor,   1UL )->has_bls_pubkey );
  FD_TEST( own_epoch( votor, 150UL )->rank==USHORT_MAX && !own_epoch( votor, 150UL )->has_bls_pubkey );
  FD_TEST( own_epoch( votor, 250UL )->rank==USHORT_MAX && !own_epoch( votor, 250UL )->has_bls_pubkey );
  ag_event_replay_t block = { .slot = 2UL };
  random_hash( block.block_info.hash );
  block.block_info.parent = ag_block_id( 1UL, vote.notar.block_hash );
  ag_votor_handle_replay_event( votor, &block );
  FD_TEST_NO_MSG( votor );
  FD_TEST( !ag_votor_has_voted( votor, 2UL ) );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: set_keys_votor" ));
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
  ag_event_replay_t block = { .slot = 2UL };
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

/* The bound a votor holds goes out with its history, and the adopter
   casts nothing at or below it even where the adopted records would
   allow a vote. */

static void
test_bound_travels( void ) {
  ag_votor_t *  a      = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();
  ag_vote_t     notar  = send_block_and_expect_notar( a, 1UL, &parent );
  ag_block_id_t tip    = ag_block_id( 1UL, notar.notar.block_hash );
  FD_TEST_NO_MSG( a );

  ag_hist_t plain;
  FD_TEST( !ag_votor_hist_export( a, ULONG_MAX, &plain ) );
  FD_TEST( plain.vote_bound==ULONG_MAX );
  ag_votor_set_vote_bound( a, 5UL );
  ag_hist_t bounded;
  FD_TEST( !ag_votor_hist_export( a, ULONG_MAX, &bounded ) );
  FD_TEST( bounded.vote_bound==5UL );
  round_trip( &bounded );
  teardown_votor( a );

  /* Without a bound the adopted notar on slot 1 lets slot 2 vote. */
  ag_votor_t * b = setup_votor( scratch_b, 0L );
  FD_TEST( !ag_votor_hist_adopt( b, &plain ) );
  FD_TEST( ag_votor_vote_bound( b )==ULONG_MAX );
  send_block_and_expect_notar( b, 2UL, &tip );
  teardown_votor( b );

  b = setup_votor( scratch_b, 0L );
  FD_TEST( !ag_votor_hist_adopt( b, &bounded ) );
  FD_TEST( ag_votor_vote_bound( b )==5UL );
  ag_event_replay_t block = { .slot = 2UL };
  random_hash( block.block_info.hash );
  block.block_info.parent = tip;
  ag_votor_handle_replay_event( b, &block );
  FD_TEST_NO_MSG( b );

  /* A lower bound from a later history never lowers ours. */
  bounded.vote_bound = 3UL;
  ag_votor_hist_adopt( b, &bounded );
  FD_TEST( ag_votor_vote_bound( b )==5UL );
  teardown_votor( b );

  FD_LOG_NOTICE(( "pass: bound_travels" ));
}

/* test_mark_unsent_adopted_notar: the standby's notar still queued at
   an adoption is dropped after it.  The adopted notar mark stays, so the
   export keeps it, the window goes on from it and a notar cert draws the
   final. */

static void
test_mark_unsent_adopted_notar( void ) {
  ag_votor_t *  votor  = setup_votor( scratch_a, 0L );
  ag_block_id_t parent = genesis_block_id();

  /* the standby's own notar on slot 1, still queued when the history
     arrives */
  ag_vote_t standby = send_block_and_expect_notar( votor, 1UL, &parent );
  ag_block_hash_t h1; fd_memcpy( h1, standby.notar.block_hash, sizeof(ag_block_hash_t) );

  /* the old active sent a notar on the same block, the usual case */
  ag_hist_t hist = { .anchor = 0UL, .last_leader_slot = ULONG_MAX, .rec_cnt = 1UL };
  hist.rec[ 0 ].slot  = 1UL;
  hist.rec[ 0 ].flags = AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR;
  fd_memcpy( hist.rec[ 0 ].notar_hash, h1, sizeof(ag_block_hash_t) );
  FD_TEST( ag_votor_hist_adopt( votor, &hist )==0UL );

  /* the tile polls it after the adoption and drops it as unsent */
  ag_votor_mark_unsent( votor, &standby );

  slot_state_ele_t const * s1 = state_of( votor, 1UL );
  FD_TEST( s1 && s1->voted && s1->voted_notar && !s1->bad_window );
  FD_TEST( fd_memeq( s1->voted_notar_hash, h1, sizeof(ag_block_hash_t) ) );
  ag_hist_t out;
  FD_TEST( !ag_votor_hist_export( votor, 42UL, &out ) );
  expect_rec( &out, 1UL, 1UL, AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR, h1 );

  /* block 2 on block 1 draws a notar */
  ag_block_id_t block1 = ag_block_id( 1UL, h1 );
  send_block_and_expect_notar( votor, 2UL, &block1 );

  /* a notar cert on block 1 draws the final */
  ag_cert_t cert; fd_memset( &cert, 0, sizeof(ag_cert_t) );
  cert.kind       = AG_CERT_KIND_NOTAR;
  cert.notar.slot = 1UL;
  fd_memcpy( cert.notar.block_hash, h1, sizeof(ag_block_hash_t) );
  ag_event_pool_t event = { .kind = AG_EVENT_POOL_CERT_CREATED, .cert_created = cert };
  ag_votor_handle_pool_event( votor, &event, 0L );
  ag_vote_t final = recv( votor );
  FD_TEST( final.kind==AG_VOTE_KIND_FINAL && ag_vote_slot( &final )==1UL );
  FD_TEST_NO_MSG( votor );

  teardown_votor( votor );
  FD_LOG_NOTICE(( "pass: mark_unsent_adopted_notar" ));
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
  test_set_keys_votor();
  test_mark_unsent_notar();
  test_bound_travels();
  test_mark_unsent_adopted_notar();
  test_export_hash_truncation();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
