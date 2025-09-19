#include "../../util/fd_util.h"
#include "fd_prune_finder.h"
#include "test_crds_utils.c"
#include <math.h>

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

  test_peer_t origin   = generate_random_peer( rng );
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

  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS-1; i++ ) {
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayer.pubkey, relayer.stake, 0UL );
  }

  uchar const * origins[1] = { origin.pubkey };

  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 100UL, origins, 1UL );
  /* Should not generate any prunes due to insufficient upserts */
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

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
  test_peer_t relayers[ FD_PRUNE_MIN_INGRESS_NODES ];
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) relayers[i] = generate_random_peer( rng );

  /* Record enough upserts but only from two relayers (need at least PRUNE_MIN_INGRESS_NODES=2, but get_prunes skips first 2) */
  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS; i++ ) {
    for( ulong j=0UL; j<FD_PRUNE_MIN_INGRESS_NODES; j++ ) {
      fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayers[j].pubkey, relayers[j].stake, 0UL );
    }
  }

  uchar const * origins[1] = { origin.pubkey };

  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 1UL );

  /* Should not generate any prunes due to insufficient ingress nodes */
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

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
  test_peer_t good_relayers[ FD_PRUNE_MIN_INGRESS_NODES ];
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) good_relayers[i] = generate_random_peer( rng );
  test_peer_t bad_relayer = generate_random_peer( rng );

  /* Set origin stake to low so that min ingress stake threshold never applies */
  origin.stake = 100UL;
  /* Set stakes so good_relayer has higher stake */
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) good_relayers[i].stake = 1000UL + i;
  bad_relayer.stake = 100UL;

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<25UL; i++ ) {
    /* Good relayers gets messages earlier */
    for( ulong j=0UL; j<FD_PRUNE_MIN_INGRESS_NODES; j++ ) {
      fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayers[j].pubkey, good_relayers[j].stake, j );
    }
    /* Bad relayer gets duplicates (num_dups=2) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, FD_PRUNE_MIN_INGRESS_NODES );
  }

  uchar const * origins[1] = { origin.pubkey };

  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 1UL );

  /* Should generate prunes for the bad relayer */
  fd_relayer_prune_data_t const * prune = fd_prune_finder_relayer_prune_data_iter_ele( pf, prunes_iter );

  FD_TEST( !memcmp( prune->relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( prune->prune_len == 1UL );
  FD_TEST( !memcmp( prune->prunes[0].uc, origin.pubkey, 32UL ) );

  prunes_iter = fd_prune_finder_relayer_prune_data_iter_next( pf, prunes_iter );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

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


  test_peer_t relayers[ FD_PRUNE_MIN_INGRESS_NODES + 1UL ];
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES + 1UL; i++ ) relayers[i] = generate_random_peer( rng );


  /* Set origin stake to low so that min ingress stake threshold never applies */
  origin.stake = 100UL;

  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES + 1UL; i++ ) relayers[i].stake = 1000UL + i; /* Last entry will be pruned */

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS; i++ ) {
    /* All relayers have the same hit count */
    for( ulong j=0UL; j<FD_PRUNE_MIN_INGRESS_NODES + 1UL; j++ ) {
      fd_prune_finder_record( pf, origin.pubkey, origin.stake, relayers[j].pubkey, relayers[j].stake, j );
    }
  }

  uchar const * origins[1] = { origin.pubkey };

  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 1UL );

  /* Should generate prunes for one of the relayers (tiebreaker by stake) */
  fd_relayer_prune_data_t const * prune = fd_prune_finder_relayer_prune_data_iter_ele( pf, prunes_iter );
  FD_TEST( !memcmp( prune->relayer_pubkey.uc, relayers[FD_PRUNE_MIN_INGRESS_NODES].pubkey, 32UL ) );

  prunes_iter = fd_prune_finder_relayer_prune_data_iter_next( pf, prunes_iter );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );
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
  test_peer_t good_relayers[ FD_PRUNE_MIN_INGRESS_NODES ];
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) good_relayers[i] = generate_random_peer( rng );
  test_peer_t bad_relayer    = generate_random_peer( rng );

  /* Set deterministic stakes to avoid threshold variability */
  origin.stake = 100UL;
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) good_relayers[i].stake = 1000UL + i;
  bad_relayer.stake = 100UL;

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS; i++ ) {
    for( ulong j=0UL; j<FD_PRUNE_MIN_INGRESS_NODES; j++ ) {
      fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayers[j].pubkey, good_relayers[j].stake, j );
    }
    /* Bad relayer gets duplicates (num_dups=FD_PRUNE_MIN_INGRESS_NODES) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, FD_PRUNE_MIN_INGRESS_NODES );
  }

  uchar const * origins[1] = { origin.pubkey };

  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 1UL );

  /* Should generate prunes for the bad relayer */
  fd_relayer_prune_data_t const * prune = fd_prune_finder_relayer_prune_data_iter_ele( pf, prunes_iter );
  FD_TEST( !memcmp( prune->relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( prune->prune_len == 1UL );
  FD_TEST( !memcmp( prune->prunes[0].uc, origin.pubkey, 32UL ) );

  prunes_iter = fd_prune_finder_relayer_prune_data_iter_next( pf, prunes_iter );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

  /* Call get_prunes again - should not generate any prunes since state reset */
  prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 1UL );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

  /* Reproduce earlier state and try again */
  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS; i++ ) {
    for( ulong j=0UL; j<FD_PRUNE_MIN_INGRESS_NODES; j++ ) {
      fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayers[j].pubkey, good_relayers[j].stake, j );
    }
    /* Bad relayer gets duplicates (num_dups=2) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, FD_PRUNE_MIN_INGRESS_NODES );
  }
  prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 1UL );

  prune = fd_prune_finder_relayer_prune_data_iter_ele( pf, prunes_iter );
  FD_TEST( !memcmp( prune->relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( prune->prune_len == 1UL );
  FD_TEST( !memcmp( prune->prunes[0].uc, origin.pubkey, 32UL ) );

  prunes_iter = fd_prune_finder_relayer_prune_data_iter_next( pf, prunes_iter );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

  prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 1UL );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );


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
  test_peer_t good_relayers[ FD_PRUNE_MIN_INGRESS_NODES ];
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) good_relayers[i] = generate_random_peer( rng );
  test_peer_t bad_relayer    = generate_random_peer( rng );

  /* Set deterministic stakes to avoid threshold variability */
  origin.stake = 100UL;
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) good_relayers[i].stake = 1000UL + i;
  bad_relayer.stake = 100UL;

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS; i++ ) {
    for( ulong j=0UL; j<FD_PRUNE_MIN_INGRESS_NODES; j++ ) {
      fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayers[j].pubkey, good_relayers[j].stake, j );
    }
    /* Bad relayer gets duplicates (num_dups=2) */
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, bad_relayer.pubkey, bad_relayer.stake, FD_PRUNE_MIN_INGRESS_NODES );
  }

  /* Pass in duplicate origins */
  uchar const * origins[3] = { origin.pubkey, origin.pubkey, origin.pubkey };

  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 3UL );
  /* Should generate prunes for the bad relayer */
  fd_relayer_prune_data_t const * prune = fd_prune_finder_relayer_prune_data_iter_ele( pf, prunes_iter );
  FD_TEST( !memcmp( prune->relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( prune->prune_len == 1UL );
  FD_TEST( !memcmp( prune->prunes[0].uc, origin.pubkey, 32UL ) );

  prunes_iter = fd_prune_finder_relayer_prune_data_iter_next( pf, prunes_iter );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

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
  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS; i++ ) {
    fd_prune_finder_record( pf, origin1.pubkey, origin1.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin1.pubkey, origin1.stake, good_relayer_2.pubkey, good_relayer_2.stake, 1UL );
    fd_prune_finder_record( pf, origin1.pubkey, origin1.stake, bad_relayer.pubkey,    bad_relayer.stake,    2UL );

    fd_prune_finder_record( pf, origin2.pubkey, origin2.stake, good_relayer_1.pubkey, good_relayer_1.stake, 0UL );
    fd_prune_finder_record( pf, origin2.pubkey, origin2.stake, good_relayer_2.pubkey, good_relayer_2.stake, 1UL );
    fd_prune_finder_record( pf, origin2.pubkey, origin2.stake, bad_relayer.pubkey,    bad_relayer.stake,    2UL );
  }

  uchar const * origins[2] = { origin1.pubkey, origin2.pubkey };

  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 1000000UL, origins, 2UL );

  /* Should generate one prune entry for bad_relayer with both origins */
  fd_relayer_prune_data_t const * prune = fd_prune_finder_relayer_prune_data_iter_ele( pf, prunes_iter );
  FD_TEST( !memcmp( prune->relayer_pubkey.uc, bad_relayer.pubkey, 32UL ) );
  FD_TEST( prune->prune_len == 2UL );

  /* Check that both origins are in the prune list */
  int found_origin1 = 0, found_origin2 = 0;
  for( ulong i=0UL; i<prune->prune_len; i++ ) {
    if( !memcmp( prune->prunes[i].uc, origin1.pubkey, 32UL ) ) found_origin1 = 1;
    if( !memcmp( prune->prunes[i].uc, origin2.pubkey, 32UL ) ) found_origin2 = 1;
  }
  FD_TEST( found_origin1 && found_origin2 );

  prunes_iter = fd_prune_finder_relayer_prune_data_iter_next( pf, prunes_iter );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );

  free( bytes );
}

void
test_get_prunes_min_ingress_stake( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong origin_max = 16UL;
  ulong relayer_max_per_origin = 8UL;

  void * bytes = aligned_alloc( fd_prune_finder_align(), fd_prune_finder_footprint( origin_max, relayer_max_per_origin ) );
  FD_TEST( bytes );

  fd_prune_finder_t * pf = fd_prune_finder_join( fd_prune_finder_new( bytes, origin_max, relayer_max_per_origin, rng ) );
  FD_TEST( pf );

  test_peer_t origin = generate_random_peer( rng );
  test_peer_t good_relayers[ FD_PRUNE_MIN_INGRESS_NODES ];
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ) good_relayers[i] = generate_random_peer( rng );

  test_peer_t in_stake_thresh  = generate_random_peer( rng );
  test_peer_t out_stake_thresh = generate_random_peer( rng );


  ulong total_good_ingress_stake = 0UL;
  for( ulong i=0UL; i<FD_PRUNE_MIN_INGRESS_NODES; i++ ){
    good_relayers[i].stake = 25UL; total_good_ingress_stake += good_relayers[i].stake;
  }
  in_stake_thresh.stake = 100UL; total_good_ingress_stake += in_stake_thresh.stake;
  origin.stake = (ulong)floor( (double)total_good_ingress_stake/FD_PRUNE_STAKE_THRESHOLD_PCT );

  out_stake_thresh.stake = 1UL; /* Exceeds*/

  /* Record enough messages to trigger pruning */
  for( ulong i=0UL; i<FD_PRUNE_MIN_UPSERTS; i++ ) {
    /* All relayers get same number of hits */
    for( ulong j=0UL; j<FD_PRUNE_MIN_INGRESS_NODES; j++ ) {
      fd_prune_finder_record( pf, origin.pubkey, origin.stake, good_relayers[j].pubkey, good_relayers[j].stake, 0UL );
    }
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, in_stake_thresh.pubkey, in_stake_thresh.stake, FD_PRUNE_MIN_INGRESS_NODES );
    fd_prune_finder_record( pf, origin.pubkey, origin.stake, out_stake_thresh.pubkey, out_stake_thresh.stake, FD_PRUNE_MIN_INGRESS_NODES );
  }

  uchar const * origins[1] = { origin.pubkey };

  /* Set min ingress stake high enough so that only one relayer is skipped */
  fd_prune_data_iter_t prunes_iter = fd_prune_finder_gen_prunes( pf, 250001UL, origins, 1UL );

  fd_relayer_prune_data_t const * prune = fd_prune_finder_relayer_prune_data_iter_ele( pf, prunes_iter );
  FD_TEST( !memcmp( prune->relayer_pubkey.uc, out_stake_thresh.pubkey, 32UL ) );
  FD_TEST( prune->prune_len == 1UL );

  prunes_iter = fd_prune_finder_relayer_prune_data_iter_next( pf, prunes_iter );
  FD_TEST( fd_prune_finder_relayer_prune_data_iter_done( pf, prunes_iter ) );
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

  test_get_prunes_min_ingress_stake();
  FD_LOG_NOTICE(( "test_get_prunes_min_ingress_stake() passed" ));

  FD_LOG_NOTICE(( "All tests passed!" ));
  return 0;
}
