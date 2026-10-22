#include "fd_rotor_strat.h"

static uchar mem[ 16UL<<20 ] __attribute__((aligned(128UL)));

static fd_pubkey_t
key( uchar b ) {
  fd_pubkey_t k; memset( k.uc, b, sizeof(fd_pubkey_t) );
  return k;
}

/* Slots follow stake with unstaked peers last; the fastest bucket wins;
   slow or jittery replies demote a peer until fast ones bring it back;
   banned and failed peers are skipped. */

static void
test_order( void ) {
  FD_TEST( fd_rotor_strat_footprint()<=sizeof(mem) );
  fd_rotor_strat_t * strat = fd_rotor_strat_join( fd_rotor_strat_new( mem, 42UL ) );

  fd_pubkey_t u = key( 9 ), a = key( 1 ), b = key( 2 );
  fd_rotor_strat_contact_info_updated( strat, &u, 1U, 1 ); /* before any epoch: unstaked */
  fd_rotor_strat_contact_info_updated( strat, &a, 2U, 1 );
  fd_rotor_strat_contact_info_updated( strat, &b, 3U, 1 );

  fd_stake_weight_t ids[2] = { { .key = b, .stake = 20UL }, { .key = a, .stake = 10UL } };
  fd_rotor_strat_epoch_advanced( strat, ids, 2UL );
  FD_TEST( fd_rotor_strat_query( strat, &b )==&strat->cur.peers[ 0 ] );
  FD_TEST( fd_rotor_strat_query( strat, &a )==&strat->cur.peers[ 1 ] );
  FD_TEST( fd_rotor_strat_query( strat, &u )==&strat->cur.peers[ 2 ] );

  for( ulong i=0UL; i<32UL; i++ ) {
    fd_rotor_strat_peer_t * peer = fd_rotor_strat_pick( strat, 0L, 1, ULONG_MAX );
    FD_TEST( peer && peer!=fd_rotor_strat_query( strat, &u ) ); /* staked only */
    fd_rotor_strat_request_done( strat, &peer->id_key, 150L*1000000L, 0 );
  }

  /* A fast unstaked peer beats slow staked ones. */

  fd_rotor_strat_request_done( strat, &u, 10L*1000000L, 0 );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_25MS );
  FD_TEST( fd_rotor_strat_pick( strat, 0L, 0, ULONG_MAX )==fd_rotor_strat_query( strat, &u ) );
  fd_rotor_strat_request_done( strat, &u, 10L*1000000L, 0 );

  /* One slow reply demotes it, its jitter counting against it as in
     its hedge, repeated ones more.  Fast replies bring it back. */

  fd_rotor_strat_request_done( strat, &u, 1000L*1000000L, 0 );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_200MS );
  for( ulong i=0UL; i<2UL; i++ ) fd_rotor_strat_request_done( strat, &u, 1000L*1000000L, 0 );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_SLOW );
  for( ulong i=0UL; i<32UL; i++ ) fd_rotor_strat_request_done( strat, &u, 10L*1000000L, 0 );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_25MS );

  /* A jittery peer ranks slower than its mean. */

  for( ulong i=0UL; i<32UL; i++ ) fd_rotor_strat_request_done( strat, &u, fd_long_if( i&1UL, 190L, 10L )*1000000L, 0 );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_200MS );
  for( ulong i=0UL; i<32UL; i++ ) fd_rotor_strat_request_done( strat, &u, 1000L*1000000L, 0 );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_SLOW );

  /* Of two peers in a bucket, the one with fewer requests in flight. */

  FD_TEST( fd_rotor_strat_query( strat, &a )->bucket==fd_rotor_strat_query( strat, &b )->bucket );
  fd_rotor_strat_query( strat, &b )->out_cnt = 5U;
  for( ulong i=0UL; i<4UL; i++ ) {
    FD_TEST( fd_rotor_strat_pick( strat, 0L, 1, ULONG_MAX )==fd_rotor_strat_query( strat, &a ) );
    fd_rotor_strat_request_done( strat, &a, 150L*1000000L, 0 );
  }

  /* A failed reply bans without an rtt sample. */

  long srtt = fd_rotor_strat_query( strat, &a )->srtt_ns;
  fd_rotor_strat_request_failed( strat, &a, 100L );
  fd_rotor_strat_request_failed( strat, &b, 100L );
  FD_TEST( fd_rotor_strat_query( strat, &a )->srtt_ns==srtt );
  FD_TEST( !fd_rotor_strat_pick( strat, 50L, 1, ULONG_MAX ) );
  FD_TEST(  fd_rotor_strat_pick( strat, 100L, 1, ULONG_MAX ) );

  /* A shorter ban, eg. an expiry after a verify failure, keeps the
     longer one. */

  fd_rotor_strat_request_failed( strat, &a, 200L );
  fd_rotor_strat_request_failed( strat, &a, 150L );
  FD_TEST( fd_rotor_strat_query( strat, &a )->ban_ts==200L );

  FD_TEST( fd_rotor_strat_hedge_ns( fd_rotor_strat_query( strat, &a ) )==srtt+4L*fd_rotor_strat_query( strat, &a )->rttvar_ns );
}

/* A peer at the in-flight cap leaves its bucket until a request ends;
   removing a contact info frees an unstaked slot but keeps a staked or
   banned one; an unmeasured peer hedges after the default. */

static void
test_inflight_and_remove( void ) {
  fd_rotor_strat_t * strat = fd_rotor_strat_join( fd_rotor_strat_new( mem, 42UL ) );
  fd_pubkey_t a = key( 1 ), u = key( 9 );
  fd_stake_weight_t ids[1] = { { .key = a, .stake = 10UL } };
  fd_rotor_strat_epoch_advanced( strat, ids, 1UL );
  fd_rotor_strat_contact_info_updated( strat, &a, 2U, 1 );
  FD_TEST( fd_rotor_strat_hedge_ns( fd_rotor_strat_query( strat, &a ) )==FD_ROTOR_STRAT_HEDGE_NS );

  for( uint i=0U; i<FD_ROTOR_STRAT_INFLIGHT_MAX; i++ ) FD_TEST( fd_rotor_strat_pick( strat, 0L, 0, ULONG_MAX )==fd_rotor_strat_query( strat, &a ) );
  FD_TEST( !fd_rotor_strat_pick( strat, 0L, 0, ULONG_MAX ) );
  fd_rotor_strat_request_done( strat, &a, 1000000L, 0 );
  FD_TEST( fd_rotor_strat_pick( strat, 0L, 0, ULONG_MAX )==fd_rotor_strat_query( strat, &a ) );

  fd_rotor_strat_contact_info_removed( strat, &a );
  FD_TEST( fd_rotor_strat_query( strat, &a )==&strat->cur.peers[ 0 ] && !strat->cur.peers[ 0 ].ip4 );
  FD_TEST( !fd_rotor_strat_pick( strat, 0L, 0, ULONG_MAX ) );

  ulong free_cnt = strat->free_cnt;
  fd_rotor_strat_contact_info_updated( strat, &u, 3U, 1 );
  FD_TEST( strat->free_cnt==free_cnt-1UL );
  fd_rotor_strat_contact_info_removed( strat, &u );
  FD_TEST( strat->free_cnt==free_cnt && !fd_rotor_strat_query( strat, &u ) );

  /* A banned unstaked peer frees its slot too. */

  fd_rotor_strat_contact_info_updated( strat, &u, 3U, 1 );
  FD_TEST( fd_rotor_strat_pick( strat, 0L, 0, ULONG_MAX )==fd_rotor_strat_query( strat, &u ) );
  fd_rotor_strat_request_failed( strat, &u, 100L );
  fd_rotor_strat_contact_info_removed( strat, &u );
  FD_TEST( strat->free_cnt==free_cnt && !fd_rotor_strat_query( strat, &u ) );
}

/* The eager wait is the max until turbine is measured, then follows
   all leaders until a leader has its own samples, which survive an
   address change and an epoch re-sort; it stays within the clamp. */

static void
test_turbine( void ) {
  fd_rotor_strat_t * strat = fd_rotor_strat_join( fd_rotor_strat_new( mem, 42UL ) );
  fd_pubkey_t a = key( 1 ), b = key( 2 );
  fd_stake_weight_t ids[2] = { { .key = a, .stake = 20UL }, { .key = b, .stake = 10UL } };
  fd_rotor_strat_epoch_advanced( strat, ids, 2UL );
  FD_TEST( fd_rotor_strat_eager_ns( strat, &a  )==FD_ROTOR_STRAT_EAGER_MAX_NS );
  FD_TEST( fd_rotor_strat_eager_ns( strat, NULL )==FD_ROTOR_STRAT_EAGER_MAX_NS );

  for( ulong i=0UL; i<FD_ROTOR_STRAT_TURBINE_MIN-1UL; i++ ) fd_rotor_strat_turbine_done( strat, &a, 100L*1000000L );
  FD_TEST( fd_rotor_strat_eager_ns( strat, &a )==fd_rotor_strat_eager_ns( strat, NULL ) ); /* not enough of its own */
  fd_rotor_strat_turbine_done( strat, &b, 200L*1000000L );
  FD_TEST( fd_rotor_strat_eager_ns( strat, &a )==fd_rotor_strat_eager_ns( strat, NULL ) );

  fd_rotor_strat_turbine_done( strat, &a, 100L*1000000L );
  long own = fd_rotor_strat_eager_ns( strat, &a );
  FD_TEST( own==fd_rotor_strat_query( strat, &a )->turbine_srtt+4L*fd_rotor_strat_query( strat, &a )->turbine_rttvar );
  FD_TEST( own<fd_rotor_strat_eager_ns( strat, NULL ) );

  fd_rotor_strat_contact_info_updated( strat, &a, 2U, 1 );
  fd_rotor_strat_epoch_advanced( strat, ids, 2UL );
  FD_TEST( fd_rotor_strat_eager_ns( strat, &a )==own );

  for( ulong i=0UL; i<64UL; i++ ) fd_rotor_strat_turbine_done( strat, &a, 1000L );
  FD_TEST( fd_rotor_strat_eager_ns( strat, &a )==FD_ROTOR_STRAT_EAGER_MIN_NS );
  for( ulong i=0UL; i<64UL; i++ ) fd_rotor_strat_turbine_done( strat, &a, 2000L*1000000L );
  FD_TEST( fd_rotor_strat_eager_ns( strat, &a )==FD_ROTOR_STRAT_EAGER_MAX_NS );
}

/* Retries of one request reach every peer of a stable, even-sized
   bucket, and never the peer just asked while another is available. */

static void
test_retry_spread( void ) {
  fd_rotor_strat_t * strat = fd_rotor_strat_join( fd_rotor_strat_new( mem, 42UL ) );
  fd_stake_weight_t ids[4];
  for( uchar i=0; i<4; i++ ) {
    ids[ i ] = (fd_stake_weight_t){ .key = key( (uchar)(i+1) ), .stake = 40UL-i };
    fd_rotor_strat_contact_info_updated( strat, &ids[ i ].key, 2U+i, 1 );
  }
  fd_rotor_strat_epoch_advanced( strat, ids, 4UL );
  for( ulong i=0UL; i<4UL; i++ ) fd_rotor_strat_request_done( strat, &ids[ i ].key, 10L*1000000L, 0 );

  ulong seen = 0UL;
  ulong last = ULONG_MAX;
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_rotor_strat_peer_t * peer = fd_rotor_strat_pick( strat, 0L, 1, last );
    ulong                   slot = (ulong)( peer-strat->cur.peers );
    FD_TEST( slot!=last );
    seen |= 1UL<<slot;
    last  = slot;
    fd_rotor_strat_request_failed( strat, &peer->id_key, 0L ); /* never answered */
  }
  FD_TEST( seen==0xfUL );

  /* With unequal rtts the cursor still moves one peer a pick when the
     avoided peer is next, so the winners are not a fixed pair. */

  for( ulong i=0UL; i<4UL; i++ ) {
    fd_rotor_strat_peer_t * peer = fd_rotor_strat_query( strat, &ids[ i ].key );
    peer->srtt_ns = 0L; peer->rttvar_ns = 0L;
    fd_rotor_strat_request_done( strat, &ids[ i ].key, (long)( 151UL-(i&1UL)*2UL+(i>>1)*2UL )*1000000L, 0 ); /* 151, 149, 153, 151 ms */
  }
  ulong b = fd_rotor_strat_query( strat, &ids[ 0 ].key )->bucket;
  strat->cursor[ b ] = FD_ROTOR_STRAT_PEER_MAX-1UL; /* the next pick starts at slot 0 */
  seen = 0UL;
  last = ULONG_MAX;
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_rotor_strat_peer_t * peer = fd_rotor_strat_pick( strat, 0L, 1, last );
    FD_TEST( strat->cursor[ b ]==i%4UL );
    last  = (ulong)( peer-strat->cur.peers );
    seen |= 1UL<<last;
    fd_rotor_strat_request_failed( strat, &peer->id_key, 0L );
  }
  FD_TEST( fd_ulong_popcnt( seen )>=3 );

  /* The only available peer is still picked. */

  for( ulong i=1UL; i<4UL; i++ ) fd_rotor_strat_request_failed( strat, &ids[ i ].key, 100L );
  FD_TEST( fd_rotor_strat_pick( strat, 0L, 1, 0UL )==&strat->cur.peers[ 0 ] );

  /* A re-sort that swaps two peers remaps a saved slot to its peer, and
     a peer that left maps to none. */

  fd_stake_weight_t swap = ids[ 0 ]; ids[ 0 ] = ids[ 1 ]; ids[ 1 ] = swap;
  fd_rotor_strat_epoch_advanced( strat, ids, 3UL );
  FD_TEST( fd_rotor_strat_slot_remap( strat, 0UL )==1UL );
  FD_TEST( fd_rotor_strat_slot_remap( strat, 1UL )==0UL );
  FD_TEST( fd_rotor_strat_slot_remap( strat, 2UL )==2UL );
  FD_TEST( fd_rotor_strat_slot_remap( strat, 3UL )==3UL ); /* unstaked now, keeps its address */
  FD_TEST( fd_rotor_strat_slot_remap( strat, ULONG_MAX )==ULONG_MAX );
  fd_rotor_strat_contact_info_removed( strat, &ids[ 3 ].key );
  fd_rotor_strat_epoch_advanced( strat, ids, 3UL );
  FD_TEST( fd_rotor_strat_slot_remap( strat, 3UL )==ULONG_MAX );
}

/* By-id expiries ban a peer after FD_ROTOR_STRAT_BYID_MAX in a row
   even while it answers positional requests; a by-id reply resets the
   run.  The stuck pick draws only available staked peers, never avoid. */

static void
test_byid_and_stuck( void ) {
  fd_rotor_strat_t * strat = fd_rotor_strat_join( fd_rotor_strat_new( mem, 42UL ) );
  fd_stake_weight_t ids[4];
  for( uchar i=0; i<4; i++ ) {
    ids[ i ] = (fd_stake_weight_t){ .key = key( (uchar)(i+1) ), .stake = 40UL-i };
    fd_rotor_strat_contact_info_updated( strat, &ids[ i ].key, 2U+i, 1 );
  }
  fd_stake_weight_t u = { .key = key( 9 ) };
  fd_rotor_strat_contact_info_updated( strat, &u.key, 9U, 1 ); /* unstaked */
  fd_rotor_strat_epoch_advanced( strat, ids, 4UL );
  fd_rotor_strat_peer_t * a = fd_rotor_strat_query( strat, &ids[ 0 ].key );

  for( uint i=0U; i<FD_ROTOR_STRAT_BYID_MAX-1U; i++ ) {
    FD_TEST( !fd_rotor_strat_request_expired( strat, &a->id_key, 100L, 1 ) );
    fd_rotor_strat_request_done( strat, &a->id_key, 1000000L, 0 ); /* positional replies do not reset it */
  }
  FD_TEST( fd_rotor_strat_request_expired( strat, &a->id_key, 100L, 1 )==1 );
  FD_TEST( a->ban_ts==100L && !a->byid_expired_cnt );

  /* A by-id expiry that ends a run of any kind is not a by-id ban. */

  fd_rotor_strat_peer_t * b = fd_rotor_strat_query( strat, &ids[ 1 ].key );
  for( uint i=0U; i<FD_ROTOR_STRAT_EXPIRED_MAX-1U; i++ ) FD_TEST( !fd_rotor_strat_request_expired( strat, &b->id_key, 100L, 0 ) );
  FD_TEST( fd_rotor_strat_request_expired( strat, &b->id_key, 100L, 1 )==-1 );
  b->ban_ts = 0L;

  for( uint i=0U; i<FD_ROTOR_STRAT_BYID_MAX-1U; i++ ) FD_TEST( !fd_rotor_strat_request_expired( strat, &a->id_key, 200L, 1 ) );
  fd_rotor_strat_request_done( strat, &a->id_key, 1000000L, 1 );
  FD_TEST( !fd_rotor_strat_request_expired( strat, &a->id_key, 200L, 1 ) );
  FD_TEST( a->ban_ts==100L );

  /* Many draws: only staked, available and not avoided; high stake
     drawn more often. */

  fd_rotor_strat_request_failed( strat, &ids[ 3 ].key, 1000L ); /* banned */
  ulong hit[ 4 ] = {0};
  for( ulong i=0UL; i<4000UL; i++ ) {
    fd_rotor_strat_peer_t * peer = fd_rotor_strat_pick_staked( strat, 200L, 1UL, fd_ulong_hash( i ) );
    ulong slot = (ulong)( peer-strat->cur.peers );
    FD_TEST( peer && slot<4UL && slot!=1UL && slot!=3UL );
    hit[ slot ]++;
    fd_rotor_strat_request_failed( strat, &peer->id_key, 0L );
  }
  FD_TEST( hit[ 0 ]>hit[ 2 ] );

  /* With the top rank avoided and the lowest banned, the higher of the
     two left is still drawn more often. */

  hit[ 1 ] = hit[ 2 ] = 0UL;
  for( ulong i=0UL; i<4000UL; i++ ) {
    fd_rotor_strat_peer_t * peer = fd_rotor_strat_pick_staked( strat, 200L, 0UL, fd_ulong_hash( i ) );
    ulong slot = (ulong)( peer-strat->cur.peers );
    FD_TEST( slot==1UL || slot==2UL );
    hit[ slot ]++;
    fd_rotor_strat_request_failed( strat, &peer->id_key, 0L );
  }
  FD_TEST( hit[ 1 ]>hit[ 2 ] );
  for( ulong i=0UL; i<3UL; i++ ) fd_rotor_strat_request_failed( strat, &ids[ i ].key, 1000L );
  FD_TEST( !fd_rotor_strat_pick_staked( strat, 200L, ULONG_MAX, 7UL ) ); /* the unstaked peer is never drawn */
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_order();
  test_inflight_and_remove();
  test_turbine();
  test_retry_spread();
  test_byid_and_stuck();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
