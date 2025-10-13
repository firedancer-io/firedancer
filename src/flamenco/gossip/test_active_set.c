#include "fd_active_set.h"
#include "fd_active_set_private.h"
#include "fd_gossip_types.h"
#include "crds/fd_crds.h"

#include "../../util/fd_util.h"

#include "test_crds_utils.c"

FD_STATIC_ASSERT( FD_ACTIVE_SET_ALIGN==128UL, unit_test );

/* Helper to generate a random pubkey */
static void
generate_random_pubkey( fd_rng_t * rng, uchar pubkey[ static 32UL ] ) {
  for( ulong i=0UL; i<32UL; i++ ) pubkey[ i ] = fd_rng_uchar( rng );
}

static ulong
generate_stake_for_bucket( ulong bucket ){
  return bucket==0UL ? 1UL : (1UL<<(bucket-1))*1000000000UL;
}

/* Test basic initialization and join */
void
test_basic_init( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  free( bytes );
}

/* Test peer insertion and removal */
void
test_peer_lifecycle( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  /* Insert a peer */
  ulong test_idx = 100UL;
  ulong test_stake = 1000000000UL;
  fd_active_set_peer_insert( active_set, test_idx, test_stake );

  /* Remove the peer */
  fd_active_set_push_state_t evicted_states[ FD_ACTIVE_SET_STAKE_BUCKETS ];
  ulong flush_cnt = fd_active_set_peer_remove( active_set, test_idx, evicted_states );

  /* Should have no evicted states since peer was never rotated into active set */
  FD_TEST( flush_cnt == 0UL );

  free( bytes );
}

/* Test stake bucket calculation */
void
test_stake_buckets( void ) {
  /* Test stake bucket boundaries */
  FD_TEST( fd_active_set_stake_bucket(          0UL ) == 0UL );
  FD_TEST( fd_active_set_stake_bucket(  999999999UL ) == 0UL );
  FD_TEST( fd_active_set_stake_bucket( 1000000000UL ) == 1UL );
  FD_TEST( fd_active_set_stake_bucket( 2000000000UL ) == 2UL );
  FD_TEST( fd_active_set_stake_bucket(    1UL << 40 ) == 11UL );
  FD_TEST( fd_active_set_stake_bucket(    1UL << 50 ) == 21UL );
  FD_TEST( fd_active_set_stake_bucket(    ULONG_MAX ) == 24UL );
}

/* Test rotation with CRDS */
void
test_rotation( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  /* Create CRDS with test peers */
  fd_crds_t * crds = create_test_crds_with_ci( rng, 10UL );
  FD_TEST( crds );

  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  long now = fd_log_wallclock();

  /* Insert peers into active set */
  for( ulong i=0UL; i<10UL; i++ ) {
    ulong stake = 1000000000UL * (i + 1UL);
    fd_active_set_peer_insert( active_set, i, stake );
  }

  /* Perform rotations */
  for( ulong i=0UL; i<100UL; i++ ) {
    fd_active_set_push_state_t maybe_flush;
    fd_active_set_rotate( active_set, crds, now, &maybe_flush );

    /* If a peer was flushed, verify the state */
    if( maybe_flush.txbuild != NULL ) {
      FD_TEST( maybe_flush.crds_idx<10UL );
    }
  }

  free_test_crds( crds );
  free( bytes );
}

void
test_single_peer( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  /* Create CRDS with test peers */
  fd_crds_t * crds = create_test_crds_with_ci( rng, 1UL );
  FD_TEST( crds );

  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  long now = fd_log_wallclock();

  /* Insert a single peer into active set */
  fd_active_set_peer_insert( active_set, 0UL, 1000000000UL );

  /* Perform multiple rotations */
  for( ulong i=0UL; i<10UL; i++ ) {
    fd_active_set_push_state_t maybe_flush;
    fd_active_set_rotate( active_set, crds, now, &maybe_flush );
  }
  uchar identity_pubkey[ 32UL ];
  uchar origin_pubkey[ 32UL ];
  generate_random_pubkey( rng, identity_pubkey );
  generate_random_pubkey( rng, origin_pubkey );
  fd_active_set_push_state_t out_push_states[ FD_ACTIVE_SET_PEERS_PER_BUCKET ];

  /* Check across all bucket levels */
  ulong num_send = 0UL;

  for( ulong i=0UL; i<FD_ACTIVE_SET_STAKE_BUCKETS; i++ ) {
    ulong stake = generate_stake_for_bucket( i );
    FD_TEST( fd_active_set_stake_bucket( stake ) == i );
    ulong this_send = fd_active_set_nodes( active_set, identity_pubkey, stake,
                                     origin_pubkey, stake, 0, now, out_push_states );
    if( this_send!=0UL ) {
      FD_TEST( this_send == 1UL );
      FD_TEST( out_push_states[0].crds_idx == 0UL );
    }
    num_send += this_send;
  }
  FD_TEST( num_send!=0UL );

  /* Remove peer */
  fd_active_set_push_state_t evicted_states[ FD_ACTIVE_SET_STAKE_BUCKETS ];
  ulong flush_cnt = fd_active_set_peer_remove( active_set, 0UL, evicted_states );
  FD_TEST( flush_cnt<=FD_ACTIVE_SET_STAKE_BUCKETS );

  /* Now should get no nodes back across all buckets */
  num_send = 0UL;
  for( ulong i=0UL; i<FD_ACTIVE_SET_STAKE_BUCKETS; i++ ) {
    ulong stake = generate_stake_for_bucket( i );
    FD_TEST( fd_active_set_stake_bucket( stake ) == i );
    num_send += fd_active_set_nodes( active_set, identity_pubkey, stake,
                                     origin_pubkey, stake, 0, now, out_push_states );
  }
  FD_TEST( num_send==0UL );

  free_test_crds( crds );
  free( bytes );
}

void
test_nodes_with_prunes( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_crds_t * crds = create_test_crds_with_ci( rng, 20UL );
  FD_TEST( crds );

  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  long now = fd_log_wallclock();

  /* Insert and rotate peers into active set */
  for( ulong i=0UL; i<20UL; i++ ) {
    ulong stake = 1000000000UL * (i + 1UL);
    fd_active_set_peer_insert( active_set, i, stake );
  }

  /* Rotate to populate buckets */
  for( ulong i=0UL; i<50UL; i++ ) {
    fd_active_set_push_state_t maybe_flush;
    fd_active_set_rotate( active_set, crds, now, &maybe_flush );
  }

  /* Test getting nodes */
  uchar identity_pubkey[ 32UL ];
  uchar origin_pubkey[ 32UL ];
  generate_random_pubkey( rng, identity_pubkey );
  generate_random_pubkey( rng, origin_pubkey );

  for( ulong i=0UL; i<FD_ACTIVE_SET_STAKE_BUCKETS; i++ ) {
    ulong stake = generate_stake_for_bucket( i );
    FD_TEST( fd_active_set_stake_bucket( stake ) == i );

    fd_active_set_push_state_t out_push_states[ FD_ACTIVE_SET_PEERS_PER_BUCKET ];
    ulong node_cnt = fd_active_set_nodes( active_set, identity_pubkey, stake,
                                          origin_pubkey, stake, 0, now, out_push_states );
    /* Should get some nodes back */
    if( node_cnt==0UL ) continue;
    FD_TEST( node_cnt <= FD_ACTIVE_SET_PEERS_PER_BUCKET );

    /* Now prune the origin from one of the returned peers */
    ulong crds_idx = out_push_states[0].crds_idx;
    fd_contact_info_t const * ci = fd_crds_contact_info_idx_lookup( crds, crds_idx );
    FD_TEST( ci );
    fd_active_set_prune( active_set, ci->pubkey.uc, origin_pubkey, stake,
                        identity_pubkey, stake );

    ulong node_cnt2 = fd_active_set_nodes( active_set, identity_pubkey, stake,
                                          origin_pubkey, stake, 0, now, out_push_states );
    FD_TEST( node_cnt2==node_cnt-1UL );
    for( ulong j=0UL; j<node_cnt2; j++ ) {
      FD_TEST( out_push_states[j].crds_idx!=crds_idx );
    }
  }

  free_test_crds( crds );
  free( bytes );
}

void
test_node_remove( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_crds_t * crds = create_test_crds_with_ci( rng, 20UL );
  FD_TEST( crds );

  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  long now = fd_log_wallclock();

  /* Insert and rotate peers into active set */
  for( ulong i=0UL; i<20UL; i++ ) {
    ulong stake = 1000000000UL * (i + 1UL);
    fd_active_set_peer_insert( active_set, i, stake );
  }

  /* Rotate to populate buckets */
  for( ulong i=0UL; i<50UL; i++ ) {
    fd_active_set_push_state_t maybe_flush;
    fd_active_set_rotate( active_set, crds, now, &maybe_flush );
  }

  /* Test getting nodes */
  uchar identity_pubkey[ 32UL ];
  uchar origin_pubkey[ 32UL ];
  generate_random_pubkey( rng, identity_pubkey );
  generate_random_pubkey( rng, origin_pubkey );

  ulong remove_idx = ULONG_MAX;
  for( ulong i=0UL; i<FD_ACTIVE_SET_STAKE_BUCKETS; i++ ) {
    ulong stake = generate_stake_for_bucket( i );
    FD_TEST( fd_active_set_stake_bucket( stake ) == i );

    fd_active_set_push_state_t out_push_states[ FD_ACTIVE_SET_PEERS_PER_BUCKET ];
    ulong node_cnt = fd_active_set_nodes( active_set, identity_pubkey, stake,
                                          origin_pubkey, stake, 0, now, out_push_states );

    if( node_cnt==0UL ) continue;
    FD_TEST( node_cnt <= FD_ACTIVE_SET_PEERS_PER_BUCKET );
    remove_idx = out_push_states[0].crds_idx;
    break;
  }
  FD_TEST( remove_idx!=ULONG_MAX ); /* Should have found a peer to remove */

  /* Remove the peer */
  fd_active_set_push_state_t evicted_states[ FD_ACTIVE_SET_STAKE_BUCKETS ];
  ulong flush_cnt = fd_active_set_peer_remove( active_set, remove_idx, evicted_states );
  FD_TEST( flush_cnt!=0UL );

  /* Now should get no nodes back across all buckets */
  for( ulong i=0UL; i<FD_ACTIVE_SET_STAKE_BUCKETS; i++ ) {
    ulong stake = generate_stake_for_bucket( i );
    FD_TEST( fd_active_set_stake_bucket( stake ) == i );
    fd_active_set_push_state_t out_push_states[ FD_ACTIVE_SET_PEERS_PER_BUCKET ];
    ulong node_cnt = fd_active_set_nodes( active_set, identity_pubkey, stake,
                                          origin_pubkey, stake, 0, now, out_push_states );
    for( ulong j=0UL; j<node_cnt; j++ ) {
      FD_TEST( out_push_states[j].crds_idx!=remove_idx );
    }
  }

  free_test_crds( crds );
  free( bytes );
}


/* Test flush stale advance */
void
test_flush_stale( void ) {
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  fd_crds_t * crds = create_test_crds_with_ci( rng, FD_ACTIVE_SET_PEERS_PER_BUCKET );
  FD_TEST( crds );

  void * bytes = aligned_alloc( fd_active_set_align(), fd_active_set_footprint() );
  FD_TEST( bytes );

  fd_active_set_t * active_set = fd_active_set_join( fd_active_set_new( bytes, rng ) );
  FD_TEST( active_set );

  long now = fd_log_wallclock();

  /* Insert peers */
  for( ulong i=0UL; i<FD_ACTIVE_SET_PEERS_PER_BUCKET; i++ ) {
    ulong stake = 1000000000UL * (i + 1UL);
    fd_active_set_peer_insert( active_set, i, stake );
  }

  /* Rotate to populate buckets */
  for( ulong i=0UL; i<FD_ACTIVE_SET_PEERS_PER_BUCKET; i++ ) {
    fd_active_set_push_state_t maybe_flush;
    fd_active_set_rotate( active_set, crds, now, &maybe_flush );
  }

  /* No stale entries yet */
  fd_active_set_push_state_t maybe_flush;
  int has_stale = fd_active_set_flush_stale_advance( active_set, now - 1000000000L, now, &maybe_flush );
  FD_TEST( !has_stale );

  /* Advance time and check for stale entries. There should be
     FD_ACTIVE_SET_PEERS_PER_BUCKET stale entries since any bucket
     can never be full with only FD_ACTIVE_SET_PEERS_PER_BUCKET
     rotations total. */
  long future = now + 10000000000L;
  for( ulong i=0UL; i<FD_ACTIVE_SET_PEERS_PER_BUCKET; i++ ) {
    fd_active_set_push_state_t maybe_flush;
    has_stale = fd_active_set_flush_stale_advance( active_set, future, future, &maybe_flush );
    FD_TEST( has_stale );
    /* Should find stale entries since we advanced time significantly */
    FD_TEST( maybe_flush.txbuild != NULL );
    FD_TEST( maybe_flush.crds_idx != ULONG_MAX );
  }

  free_test_crds( crds );
  free( bytes );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_basic_init();
  FD_LOG_NOTICE(( "test_basic_init() passed" ));

  test_peer_lifecycle();
  FD_LOG_NOTICE(( "test_peer_lifecycle() passed" ));

  test_stake_buckets();
  FD_LOG_NOTICE(( "test_stake_buckets() passed" ));

  test_rotation();
  FD_LOG_NOTICE(( "test_rotation() passed" ));

  test_nodes_with_prunes();
  FD_LOG_NOTICE(( "test_nodes_with_prunes() passed" ));

  test_single_peer();
  FD_LOG_NOTICE(( "test_single_peer() passed" ));

  test_node_remove();
  FD_LOG_NOTICE(( "test_node_remove() passed" ));

  test_flush_stale();
  FD_LOG_NOTICE(( "test_flush_stale() passed" ));

  FD_LOG_NOTICE(( "All tests passed!" ));
  return 0;
}
