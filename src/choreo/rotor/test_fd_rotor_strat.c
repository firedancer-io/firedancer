#include "fd_rotor_strat.h"

static uchar mem[ 16UL<<20 ] __attribute__((aligned(128UL)));

static fd_pubkey_t
key( uchar b ) {
  fd_pubkey_t k; memset( k.uc, b, sizeof(fd_pubkey_t) );
  return k;
}

/* Slots follow stake with unstaked peers last; the fastest bucket wins;
   one timeout does not demote a peer but repeated ones do; banned and
   failed peers are skipped. */

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
    fd_rotor_strat_peer_t * peer = fd_rotor_strat_pick( strat, 0L, 1 );
    FD_TEST( peer && peer!=fd_rotor_strat_query( strat, &u ) ); /* staked only */
    fd_rotor_strat_request_done( strat, &peer->id_key, 150L*1000000L );
  }

  /* A fast unstaked peer beats slow staked ones. */

  fd_rotor_strat_request_done( strat, &u, 10L*1000000L );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_25MS );
  FD_TEST( fd_rotor_strat_pick( strat, 0L, 0 )==fd_rotor_strat_query( strat, &u ) );
  fd_rotor_strat_request_done( strat, &u, 10L*1000000L );

  /* One slow reply leaves it in its bucket, repeated ones demote it. */

  fd_rotor_strat_request_done( strat, &u, 1000L*1000000L );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_25MS );
  for( ulong i=0UL; i<32UL; i++ ) fd_rotor_strat_request_done( strat, &u, 1000L*1000000L );
  FD_TEST( fd_rotor_strat_query( strat, &u )->bucket==FD_ROTOR_STRAT_BUCKET_SLOW );

  /* Of two peers in a bucket, the one with fewer requests in flight. */

  fd_rotor_strat_query( strat, &b )->inflight = 5U;
  for( ulong i=0UL; i<4UL; i++ ) {
    FD_TEST( fd_rotor_strat_pick( strat, 0L, 1 )==fd_rotor_strat_query( strat, &a ) );
    fd_rotor_strat_request_done( strat, &a, 150L*1000000L );
  }

  /* A failed reply bans without an rtt sample. */

  long srtt = fd_rotor_strat_query( strat, &a )->srtt;
  fd_rotor_strat_request_failed( strat, &a, 100L );
  fd_rotor_strat_request_failed( strat, &b, 100L );
  FD_TEST( fd_rotor_strat_query( strat, &a )->srtt==srtt );
  FD_TEST( !fd_rotor_strat_pick( strat, 50L, 1 ) );
  FD_TEST(  fd_rotor_strat_pick( strat, 100L, 1 ) );

  /* A shorter ban, eg. an expiry after a verify failure, keeps the
     longer one. */

  fd_rotor_strat_request_failed( strat, &a, 200L );
  fd_rotor_strat_request_failed( strat, &a, 150L );
  FD_TEST( fd_rotor_strat_query( strat, &a )->ban_ts==200L );

  FD_TEST( fd_rotor_strat_hedge_ns( fd_rotor_strat_query( strat, &a ) )==srtt+4L*fd_rotor_strat_query( strat, &a )->rttvar );
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

  for( uint i=0U; i<FD_ROTOR_STRAT_INFLIGHT_MAX; i++ ) FD_TEST( fd_rotor_strat_pick( strat, 0L, 0 )==fd_rotor_strat_query( strat, &a ) );
  FD_TEST( !fd_rotor_strat_pick( strat, 0L, 0 ) );
  fd_rotor_strat_request_done( strat, &a, 1000000L );
  FD_TEST( fd_rotor_strat_pick( strat, 0L, 0 )==fd_rotor_strat_query( strat, &a ) );

  fd_rotor_strat_contact_info_removed( strat, &a );
  FD_TEST( fd_rotor_strat_query( strat, &a )==&strat->cur.peers[ 0 ] && !strat->cur.peers[ 0 ].ip4 );
  FD_TEST( !fd_rotor_strat_pick( strat, 0L, 0 ) );

  ulong free_cnt = strat->free_cnt;
  fd_rotor_strat_contact_info_updated( strat, &u, 3U, 1 );
  FD_TEST( strat->free_cnt==free_cnt-1UL );
  fd_rotor_strat_contact_info_removed( strat, &u );
  FD_TEST( strat->free_cnt==free_cnt && !fd_rotor_strat_query( strat, &u ) );

  /* A banned unstaked peer frees its slot too. */

  fd_rotor_strat_contact_info_updated( strat, &u, 3U, 1 );
  FD_TEST( fd_rotor_strat_pick( strat, 0L, 0 )==fd_rotor_strat_query( strat, &u ) );
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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_order();
  test_inflight_and_remove();
  test_turbine();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
