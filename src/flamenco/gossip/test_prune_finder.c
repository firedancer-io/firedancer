#include "../../util/fd_util.h"
#include "fd_prune_finder.h"
#include "test_crds_utils.c"

typedef struct test_peer {
  uchar pubkey[32UL];
  ulong stake;
} test_peer_t;

test_peer_t
generate_random_peer( fd_rng_t * rng ) {
  test_peer_t p = {0};
  for( ulong i=0UL; i<32UL; i++ ) p.pubkey[i] = fd_rng_uchar( rng );
  p.stake = fd_rng_ulong_roll( rng, 1000000000UL );
  return p;
}

void
test_basic( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  /* Test metrics are initially zero */
  fd_prune_finder_metrics_t const * metrics = fd_prune_finder_metrics( pf );
  FD_TEST( metrics );
  FD_TEST( metrics->origin_relayer_evicted_cnt == 0UL );

  free( bytes );
}

void
test_record_single_origin( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  test_peer_t relayer1 = generate_random_peer( rng );
  test_peer_t relayer2 = generate_random_peer( rng );

  /* Record messages from different relayers for the same origin */
  fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer1.pubkey, relayer1.stake, 0UL );
  fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer2.pubkey, relayer2.stake, 1UL );
  fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer1.pubkey, relayer1.stake, 0UL );

  /* Metrics should still be zero since no evictions occurred */
  fd_prune_finder_metrics_t const * metrics = fd_prune_finder_metrics( pf );
  FD_TEST( metrics->origin_relayer_evicted_cnt == 0UL );

  free( bytes );
}

void
test_get_prunes_insufficient_upserts( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  test_peer_t relayer = generate_random_peer( rng );

  /* Record fewer than PRUNE_MIN_UPSERTS (20) messages */
  for( ulong i=0UL; i<10UL; i++ ) {
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer.pubkey, relayer.stake, 0UL );
  }

  uchar const * origins[1] = { origin.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );

  /* Should not generate any prunes due to insufficient upserts */
  FD_TEST( out_prunes_len == 0UL );

  free( bytes );
}

void
test_get_prunes_insufficient_ingress_nodes( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  test_peer_t relayer1 = generate_random_peer( rng );
  test_peer_t relayer2 = generate_random_peer( rng );

  /* Record enough upserts but only from two relayers (need at least PRUNE_MIN_INGRESS_NODES=2, but get_prunes skips first 2) */
  for( ulong i=0UL; i<25UL; i++ ) {
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer1.pubkey, relayer1.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer2.pubkey, relayer2.stake, 0UL );
  }

  uchar const * origins[1] = { origin.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );

  /* Should not generate any prunes due to insufficient ingress nodes */
  FD_TEST( out_prunes_len == 0UL );

  free( bytes );
}

void
test_get_prunes_basic( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  test_peer_t good_relayer_1 = generate_random_peer( rng );
  test_peer_t good_relayer_2 = generate_random_peer( rng );
  test_peer_t bad_relayer = generate_random_peer( rng );

  /* Set origin stake to low so that min ingress stake threshold never applies */
  origin.stake = 100UL;
  /* Set stakes so good_relayer has higher stake */
  good_relayer_1.stake = 1000000UL;
  good_relayer_2.stake = 1000000UL;
  bad_relayer.stake = 100UL;

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<25UL; i++ ) {
    /* Good relayers gets messages earlier */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_2.pubkey, good_relayer_2.stake, 0UL );
    /* Bad relayer gets duplicates (num_dups=2) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, 1UL );
  }

  /* add extra record for one of the good relayers since to avoid tiebreaker */
  fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );

  uchar const * origins[1] = { origin.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );

  /* Should generate prunes for the bad relayer */
  FD_TEST( out_prunes_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( out_prunes[0].prune_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].prunes[0].uc, origin.pubkey, 32UL ) );

  free( bytes );
}

void
test_get_prunes_tiebreaker( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin    = generate_random_peer( rng );
  test_peer_t relayer_1 = generate_random_peer( rng );
  test_peer_t relayer_2 = generate_random_peer( rng );
  test_peer_t relayer_3 = generate_random_peer( rng );

  /* Set origin stake to low so that min ingress stake threshold never applies */
  origin.stake = 100UL;

  relayer_1.stake = 100002UL;
  relayer_2.stake = 100001UL;
  relayer_3.stake = 100000UL;

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<25UL; i++ ) {
    /* All relayers get same number of hits */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer_1.pubkey, relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer_2.pubkey, relayer_2.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer_3.pubkey, relayer_3.stake, 0UL );
  }

  uchar const * origins[1] = { origin.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );

  /* Should generate prunes for one of the relayers (tiebreaker by stake) */
  FD_TEST( out_prunes_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].relayer_pubkey.uc, relayer_3.pubkey, 32UL ) );
  free( bytes );
}

void
test_get_prunes_reset_origin( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  test_peer_t good_relayer_1 = generate_random_peer( rng );
  test_peer_t good_relayer_2 = generate_random_peer( rng );
  test_peer_t bad_relayer    = generate_random_peer( rng );

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<25UL; i++ ) {
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_2.pubkey, good_relayer_2.stake, 0UL );
    /* Bad relayer gets duplicates (num_dups=2) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, 1UL );
  }

  uchar const * origins[1] = { origin.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );

  /* Should generate prunes for the bad relayer */
  FD_TEST( out_prunes_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( out_prunes[0].prune_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].prunes[0].uc, origin.pubkey, 32UL ) );

  /* Call get_prunes again - should not generate any prunes since state reset */
  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );
  FD_TEST( out_prunes_len == 0UL );

  /* Reproduce earlier state and try again */
  for( ulong i=0UL; i<25UL; i++ ) {
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_2.pubkey, good_relayer_2.stake, 0UL );
    /* Bad relayer gets duplicates (num_dups=2) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, 1UL );
  }
  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );
  FD_TEST( out_prunes_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( out_prunes[0].prune_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].prunes[0].uc, origin.pubkey, 32UL ) );

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );
  FD_TEST( out_prunes_len == 0UL );


  free( bytes );
}

void
test_get_prunes_duplicate_origins( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  test_peer_t good_relayer_1 = generate_random_peer( rng );
  test_peer_t good_relayer_2 = generate_random_peer( rng );
  test_peer_t bad_relayer    = generate_random_peer( rng );

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<25UL; i++ ) {
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_2.pubkey, good_relayer_2.stake, 0UL );
    /* Bad relayer gets duplicates (num_dups=2) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, 1UL );
  }

  /* add extra record for one of the good relayers since to avoid tiebreaker */
  fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );

  /* Pass in duplicate origins */
  uchar const * origins[3] = { origin.pubkey, origin.pubkey, origin.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 3UL, &out_prunes, &out_prunes_len );
  /* Should generate prunes for the bad relayer */
  FD_TEST( out_prunes_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( out_prunes[0].prune_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].prunes[0].uc, origin.pubkey, 32UL ) );

  free( bytes );
}

void
test_relayer_eviction( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 4UL; /* Small to force evictions */

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );

  /* Add more relayers than the limit to force evictions */
  for( ulong i=0UL; i<relayer_max_per_origin + 2UL; i++ ) {
    test_peer_t relayer = generate_random_peer( rng );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer.pubkey, relayer.stake, 0UL );
  }

  /* Check that evictions occurred */
  fd_prune_finder_metrics_t const * metrics = fd_prune_finder_metrics( pf );
  FD_TEST( metrics->origin_relayer_evicted_cnt == 2UL );

  free( bytes );
}

void
test_origin_eviction( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 4UL; /* Small to force evictions */
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t relayer = generate_random_peer( rng );

  /* Add more origins than the limit to force evictions */
  for( ulong i=0UL; i<origin_max + 2UL; i++ ) {
    test_peer_t origin = generate_random_peer( rng );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer.pubkey, relayer.stake, 0UL );
  }
  fd_prune_finder_metrics_t const * metrics = fd_prune_finder_metrics( pf );
  FD_TEST( metrics->origin_evicted_cnt == 2UL );

  free( bytes );
}

void
test_multiple_origins( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin1        = generate_random_peer( rng );
  test_peer_t origin2        = generate_random_peer( rng );
  test_peer_t good_relayer_1 = generate_random_peer( rng );
  test_peer_t good_relayer_2 = generate_random_peer( rng );
  test_peer_t bad_relayer    = generate_random_peer( rng );

  origin1.stake        = 100UL;
  origin2.stake        = 100UL;
  good_relayer_1.stake = 1000000UL;
  good_relayer_2.stake = 1000000UL;
  bad_relayer.stake    = 1000000UL;

  /* Record messages for both origins */
  for( ulong i=0UL; i<25UL; i++ ) {
    fd_prune_finder_record( pf, origin1.pubkey, origin1.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin1.pubkey, origin1.stake, good_relayer_2.pubkey, good_relayer_2.stake, 1UL );
    fd_prune_finder_record( pf, origin1.pubkey, origin1.stake, bad_relayer.pubkey,    bad_relayer.stake,    2UL );

    fd_prune_finder_record( pf, origin2.pubkey, origin2.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin2.pubkey, origin2.stake, good_relayer_2.pubkey, good_relayer_2.stake, 1UL );
    fd_prune_finder_record( pf, origin2.pubkey, origin2.stake, bad_relayer.pubkey,    bad_relayer.stake,    2UL );
  }

  uchar const * origins[2] = { origin1.pubkey, origin2.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 2UL, &out_prunes, &out_prunes_len );

  /* Should generate one prune entry for bad_relayer with both origins */
  FD_TEST( out_prunes_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( out_prunes[0].prune_len == 2UL );

  /* Check that both origins are in the prune list */
  int found_origin1 = 0, found_origin2 = 0;
  for( ulong i=0UL; i<out_prunes[0].prune_len; i++ ) {
    if( !memcmp( out_prunes[0].prunes[i].uc, origin1.pubkey, 32UL ) ) found_origin1 = 1;
    if( !memcmp( out_prunes[0].prunes[i].uc, origin2.pubkey, 32UL ) ) found_origin2 = 1;
  }
  FD_TEST( found_origin1 && found_origin2 );

  free( bytes );
}

void
test_stake_threshold_with_pruning( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  origin.stake = 1000000UL; /* x0.15 to get minimum cumulative threshold = 150000*/

  test_peer_t high_stake_relayer_1  = generate_random_peer( rng );
  test_peer_t high_stake_relayer_2  = generate_random_peer( rng );
  test_peer_t within_thresh_relayer = generate_random_peer( rng );
  test_peer_t beyond_thresh_relayer = generate_random_peer( rng );

  high_stake_relayer_1.stake  = 200000UL;
  high_stake_relayer_2.stake  = 200000UL;
  within_thresh_relayer.stake = 140000UL;  /* Below 15% cumulative threshold */
  beyond_thresh_relayer.stake = 16000UL;   /* 140000+16000=156000, which is above minimum threshold of 150000 */

  /* Record messages from all relayers */
  for( ulong i=0UL; i<25UL; i++ ) {
    /* First two relayers (skipped due to minimum node count) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, high_stake_relayer_1.pubkey, high_stake_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, high_stake_relayer_2.pubkey, high_stake_relayer_2.stake, 1UL );
    /* Third relayer (skipped due to stake threshold) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, within_thresh_relayer.pubkey, within_thresh_relayer.stake, 2UL );
    /* Fourth relayer (should be pruned due to exceeding stake) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, beyond_thresh_relayer.pubkey, beyond_thresh_relayer.stake, 3UL );
  }

  uchar const * origins[1] = { origin.pubkey };
  fd_prune_finder_prune_t const * out_prunes;
  ulong out_prunes_len;

  fd_prune_finder_get_prunes( pf, 1000000UL, origins, 1UL, &out_prunes, &out_prunes_len );

  /* Should prune the 4th relayer since first 3 are skipped */
  FD_TEST( out_prunes_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].relayer_pubkey.uc, beyond_thresh_relayer.pubkey, 32UL ) );
  FD_TEST( out_prunes[0].prune_len == 1UL );
  FD_TEST( !memcmp( out_prunes[0].prunes[0].uc, origin.pubkey, 32UL ) );

  free( bytes );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_basic();
  FD_LOG_NOTICE(( "test_basic() passed" ));

  test_record_single_origin();
  FD_LOG_NOTICE(( "test_record_single_origin() passed" ));

  test_get_prunes_insufficient_upserts();
  FD_LOG_NOTICE(( "test_get_prunes_insufficient_upserts() passed" ));

  test_get_prunes_insufficient_ingress_nodes();
  FD_LOG_NOTICE(( "test_get_prunes_insufficient_ingress_nodes() passed" ));

  test_get_prunes_basic();
  FD_LOG_NOTICE(( "test_get_prunes_basic() passed" ));

  test_get_prunes_reset_origin();
  FD_LOG_NOTICE(( "test_get_prunes_reset_origin() passed" ));

  test_get_prunes_tiebreaker();
  FD_LOG_NOTICE(( "test_get_prunes_tiebreaker() passed" ));

  test_get_prunes_duplicate_origins();
  FD_LOG_NOTICE(( "test_get_prunes_duplicate_origins() passed" ));

  test_relayer_eviction();
  FD_LOG_NOTICE(( "test_relayer_eviction() passed" ));

  test_origin_eviction();
  FD_LOG_NOTICE(( "test_origin_eviction() passed" ));

  test_multiple_origins();
  FD_LOG_NOTICE(( "test_multiple_origins() passed" ));

  test_stake_threshold_with_pruning();
  FD_LOG_NOTICE(( "test_stake_threshold_with_pruning() passed" ));

  FD_LOG_NOTICE(( "All tests passed!" ));
  return 0;
}
