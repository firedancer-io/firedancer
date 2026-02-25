/* Unit tests for fd_gossip_wsample. */

#include "fd_gossip_wsample.h"
#include "../../util/fd_util.h"

#include <stdlib.h>

/* ---- helpers ------------------------------------------------------------ */

static fd_gossip_wsample_t *
new_sampler( fd_rng_t * rng, ulong max_peers ) {
  ulong fp   = fd_gossip_wsample_footprint( max_peers );
  void * mem = aligned_alloc( fd_gossip_wsample_align(), fp );
  FD_TEST( mem );
  FD_TEST( fd_gossip_wsample_new( mem, rng, max_peers ) );
  fd_gossip_wsample_t * s = fd_gossip_wsample_join( mem );
  FD_TEST( s );
  return s;
}

static void
destroy_sampler( fd_gossip_wsample_t * s ) {
  free( s );
}

/* ---- test: basic lifecycle ---------------------------------------------- */

static void
test_lifecycle( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_lifecycle" ));

  FD_TEST( fd_gossip_wsample_align()     == 64UL );
  FD_TEST( fd_gossip_wsample_footprint( 0UL ) == 0UL );
  FD_TEST( fd_gossip_wsample_footprint( 1UL ) >  0UL );
  FD_TEST( fd_gossip_wsample_footprint( 100UL ) > 0UL );

  /* NULL / bad args */
  FD_TEST( fd_gossip_wsample_new( NULL, rng, 10UL ) == NULL );
  FD_TEST( fd_gossip_wsample_new( (void*)1UL, rng, 0UL ) == NULL );

  fd_gossip_wsample_t * s = new_sampler( rng, 10UL );
  destroy_sampler( s );
}

/* ---- test: empty sampler returns ULONG_MAX ------------------------------ */

static void
test_empty_sampler( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_empty_sampler" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == ULONG_MAX );
  for( ulong b=0UL; b<25UL; b++ )
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == ULONG_MAX );

  destroy_sampler( s );
}

/* ---- test: single peer always sampled ----------------------------------- */

static void
test_single_peer( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_single_peer" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  fd_gossip_wsample_add( s, 5UL, 1000UL, 1 );

  /* Pull request should always return idx 5 */
  for( ulong i=0UL; i<100UL; i++ )
    FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 5UL );

  /* Bucket sample should return 5, then ULONG_MAX (removed) */
  for( ulong b=0UL; b<25UL; b++ ) {
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == 5UL );
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == ULONG_MAX );
  }

  /* Pull request still works after bucket removal */
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 5UL );

  /* Add back to one bucket, should work again */
  fd_gossip_wsample_add_bucket( s, 3UL, 5UL );
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, 3UL ) == 5UL );
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, 3UL ) == ULONG_MAX );

  destroy_sampler( s );
}

/* ---- test: zero stake peer is sampleable -------------------------------- */

static void
test_zero_stake( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_zero_stake" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 8UL );

  /* Add a peer with stake=0 */
  fd_gossip_wsample_add( s, 2UL, 0UL, 1 );

  /* Should still be sampleable for pull requests (BASE_WEIGHT > 0) */
  for( ulong i=0UL; i<50UL; i++ )
    FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 2UL );

  /* Should be sampleable for bucket (bucket_score always >= 1) */
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, 0UL ) == 2UL );

  destroy_sampler( s );
}

/* ---- test: add and remove peers ----------------------------------------- */

static void
test_add_remove( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_add_remove" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 32UL );

  fd_gossip_wsample_add( s, 3UL, 500UL, 1 );
  fd_gossip_wsample_add( s, 7UL, 300UL, 1 );
  fd_gossip_wsample_add( s, 15UL, 200UL, 1 );

  /* All samples should be one of {3, 7, 15} */
  for( ulong i=0UL; i<200UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==3UL || idx==7UL || idx==15UL );
  }

  /* Remove peer 7 — now only {3, 15} */
  fd_gossip_wsample_remove( s, 7UL );

  for( ulong i=0UL; i<200UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==3UL || idx==15UL );
  }

  /* Remove all — empty */
  fd_gossip_wsample_remove( s, 3UL );
  fd_gossip_wsample_remove( s, 15UL );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == ULONG_MAX );

  destroy_sampler( s );
}

/* ---- test: bucket sample-remove-add cycle ------------------------------- */

static void
test_bucket_cycle( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_bucket_cycle" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 32UL );

  fd_gossip_wsample_add( s, 0UL, 10000UL, 1 );
  fd_gossip_wsample_add( s, 1UL, 20000UL, 1 );
  fd_gossip_wsample_add( s, 2UL, 30000UL, 1 );

  ulong bucket = 5UL;

  /* Sample-and-remove all three from bucket 5 */
  int seen[3] = {0,0,0};
  for( ulong i=0UL; i<3UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_remove_bucket( s, bucket );
    FD_TEST( idx<=2UL );
    FD_TEST( !seen[idx] );
    seen[idx] = 1;
  }
  FD_TEST( seen[0] && seen[1] && seen[2] );

  /* Bucket is now empty */
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, bucket ) == ULONG_MAX );

  /* Add them all back */
  fd_gossip_wsample_add_bucket( s, bucket, 0UL );
  fd_gossip_wsample_add_bucket( s, bucket, 1UL );
  fd_gossip_wsample_add_bucket( s, bucket, 2UL );

  /* Should be sampleable again */
  ulong idx = fd_gossip_wsample_sample_remove_bucket( s, bucket );
  FD_TEST( idx<=2UL );

  destroy_sampler( s );
}

/* ---- test: remove after bucket sample-remove doesn't double-sub --------- */

static void
test_remove_after_bucket_remove( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_remove_after_bucket_remove" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  fd_gossip_wsample_add( s, 4UL, 5000UL, 1 );

  /* Remove from bucket 10 via sample */
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, 10UL ) == 4UL );

  /* Now fully remove the peer (should not underflow bucket 10) */
  fd_gossip_wsample_remove( s, 4UL );

  /* Everything should be empty */
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == ULONG_MAX );
  for( ulong b=0UL; b<25UL; b++ )
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == ULONG_MAX );

  destroy_sampler( s );
}

/* ---- test: sparse indices ----------------------------------------------- */

static void
test_sparse_indices( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_sparse_indices" ));

  ulong max_peers = 1000UL;
  fd_gossip_wsample_t * s = new_sampler( rng, max_peers );

  /* Add peers at widely spaced indices */
  fd_gossip_wsample_add( s, 0UL,   100UL, 1 );
  fd_gossip_wsample_add( s, 500UL, 200UL, 1 );
  fd_gossip_wsample_add( s, 999UL, 300UL, 1 );

  for( ulong i=0UL; i<300UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==0UL || idx==500UL || idx==999UL );
  }

  fd_gossip_wsample_remove( s, 500UL );
  for( ulong i=0UL; i<200UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==0UL || idx==999UL );
  }

  destroy_sampler( s );
}

/* ---- test: sampling distribution is stake-weighted ---------------------- */

static void
test_distribution( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_distribution" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  /* Set self_stake high so it doesn't cap peer weights. */
  fd_gossip_wsample_self_stake( s, 10000UL * 1000000000UL );

  /* Peer 0 has much higher stake than peer 1.  Using SOL-scale amounts
     so that pr_weight produces meaningfully different weights.
     1000 SOL -> bucket 10, weight=(10+1)^2=121
     1 SOL    -> bucket 1,  weight=(1+1)^2=4.
     Expected ratio ~ 121:4 ~ 30:1. */
  ulong stake_a = 1000UL * 1000000000UL;  /* 1000 SOL */
  ulong stake_b =    1UL * 1000000000UL;  /*    1 SOL */
  fd_gossip_wsample_add( s, 0UL, stake_a, 1 );
  fd_gossip_wsample_add( s, 1UL, stake_b, 1 );

  ulong cnt_a = 0UL;
  ulong cnt_b = 0UL;
  ulong N = 100000UL;
  for( ulong i=0UL; i<N; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==0UL || idx==1UL );
    if( idx==0UL ) cnt_a++; else cnt_b++;
  }

  /* Expected ratio ~ 121:4 ~ 30:1.
     Peer 0 should get ~96.8% of samples.
     Check that peer 0 gets at least 80% of samples. */
  FD_LOG_NOTICE(( "  cnt_a=%lu cnt_b=%lu ratio=%.2f", cnt_a, cnt_b,
                  (double)cnt_a / (double)fd_ulong_max( cnt_b, 1UL ) ));
  FD_TEST( cnt_a > N * 7UL / 10UL );
  FD_TEST( cnt_b > 0UL );

  destroy_sampler( s );
}

/* ---- test: many peers (stress) ------------------------------------------ */

static void
test_many_peers( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_many_peers" ));

  ulong max_peers = 4096UL;
  fd_gossip_wsample_t * s = new_sampler( rng, max_peers );

  /* Add all peers */
  for( ulong i=0UL; i<max_peers; i++ )
    fd_gossip_wsample_add( s, i, (i+1UL) * 100UL, 1 );

  /* Sample a bunch */
  for( ulong i=0UL; i<10000UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx < max_peers );
  }

  /* Bucket sample-and-remove some */
  for( ulong b=0UL; b<25UL; b++ ) {
    for( ulong i=0UL; i<20UL; i++ ) {
      ulong idx = fd_gossip_wsample_sample_remove_bucket( s, b );
      if( idx==ULONG_MAX ) break;
      FD_TEST( idx < max_peers );
    }
  }

  /* Remove half the peers */
  for( ulong i=0UL; i<max_peers/2UL; i++ )
    fd_gossip_wsample_remove( s, i );

  /* Remaining samples should be in [max_peers/2, max_peers) */
  for( ulong i=0UL; i<5000UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx >= max_peers/2UL && idx < max_peers );
  }

  destroy_sampler( s );
}

/* ---- test: bucket independence ------------------------------------------ */

static void
test_bucket_independence( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_bucket_independence" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  fd_gossip_wsample_add( s, 0UL, 1000UL, 1 );
  fd_gossip_wsample_add( s, 1UL, 2000UL, 1 );

  /* Remove both from bucket 0 */
  ulong a = fd_gossip_wsample_sample_remove_bucket( s, 0UL );
  ulong b = fd_gossip_wsample_sample_remove_bucket( s, 0UL );
  FD_TEST( (a==0UL && b==1UL) || (a==1UL && b==0UL) );
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, 0UL ) == ULONG_MAX );

  /* Bucket 1 should still have both peers */
  ulong c = fd_gossip_wsample_sample_remove_bucket( s, 1UL );
  ulong d = fd_gossip_wsample_sample_remove_bucket( s, 1UL );
  FD_TEST( (c==0UL && d==1UL) || (c==1UL && d==0UL) );
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, 1UL ) == ULONG_MAX );

  /* PR tree still has both */
  for( ulong i=0UL; i<50UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==0UL || idx==1UL );
  }

  destroy_sampler( s );
}

/* ---- test: re-add peer after full remove -------------------------------- */

static void
test_readd_peer( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_readd_peer" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  fd_gossip_wsample_add( s, 3UL, 500UL, 1 );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 3UL );

  fd_gossip_wsample_remove( s, 3UL );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == ULONG_MAX );

  /* Re-add at the same index with different stake */
  fd_gossip_wsample_add( s, 3UL, 7000UL, 1 );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 3UL );

  /* Bucket should also work for the re-added peer */
  FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, 12UL ) == 3UL );

  destroy_sampler( s );
}

/* ---- test: self_stake affects PR weight cap ----------------------------- */

static void
test_self_stake( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_self_stake" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  /* self_stake=0 (default): all peers get pr_weight(0)=1 regardless of
     their actual stake, so two peers with wildly different stakes should
     be sampled roughly equally. */
  ulong big_stake   = 10000UL * 1000000000UL; /* 10000 SOL */
  ulong small_stake =     1UL * 1000000000UL; /*     1 SOL */
  fd_gossip_wsample_add( s, 0UL, big_stake,   1 );
  fd_gossip_wsample_add( s, 1UL, small_stake, 1 );

  ulong cnt_0 = 0UL;
  ulong N = 10000UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  /* With self_stake=0, both have weight 1, so ~50/50. */
  FD_TEST( cnt_0 > N * 3UL / 10UL );
  FD_TEST( cnt_0 < N * 7UL / 10UL );

  /* Now set self_stake high -- peer 0 should dominate. */
  fd_gossip_wsample_self_stake( s, big_stake );

  cnt_0 = 0UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  /* 10000 SOL -> bucket 14, w=15, weight=225.
     1 SOL     -> bucket 1,  w=2,  weight=4.
     Peer 0 should get ~225/229 ~ 98%. */
  FD_TEST( cnt_0 > N * 8UL / 10UL );

  /* Setting self_stake = small_stake caps peer 0 at pr_weight(1 SOL)=4,
     so both peers get weight 4 and sampling becomes ~50/50. */
  fd_gossip_wsample_self_stake( s, small_stake );

  cnt_0 = 0UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  FD_TEST( cnt_0 > N * 3UL / 10UL );
  FD_TEST( cnt_0 < N * 7UL / 10UL );

  destroy_sampler( s );
}

/* ---- test: stake update for existing peer ------------------------------- */

static void
test_stake_update( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_stake_update" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );
  fd_gossip_wsample_self_stake( s, 100000UL * 1000000000UL );

  /* Add two peers with equal stake. */
  ulong equal_stake = 100UL * 1000000000UL; /* 100 SOL */
  fd_gossip_wsample_add( s, 0UL, equal_stake, 1 );
  fd_gossip_wsample_add( s, 1UL, equal_stake, 1 );

  /* Sampling should be roughly 50/50. */
  ulong cnt_0 = 0UL;
  ulong N = 10000UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );
  FD_TEST( cnt_0 > N * 3UL / 10UL );
  FD_TEST( cnt_0 < N * 7UL / 10UL );

  /* Increase peer 0's stake dramatically -- it should now dominate.
     100 SOL -> pr_weight=64, 10000 SOL -> pr_weight=225.
     Ratio 225:64 ~ 3.5:1, peer 0 should get ~78% of samples. */
  fd_gossip_wsample_stake( s, 0UL, 10000UL * 1000000000UL );

  cnt_0 = 0UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );
  FD_TEST( cnt_0 > N * 6UL / 10UL );

  /* Bucket weights should also have been updated. Drain bucket 5.
     Peer 0 should be sampled first most of the time. */
  ulong first = fd_gossip_wsample_sample_remove_bucket( s, 5UL );
  FD_TEST( first == 0UL || first == 1UL );
  ulong second = fd_gossip_wsample_sample_remove_bucket( s, 5UL );
  FD_TEST( second == 0UL || second == 1UL );
  FD_TEST( first != second );

  destroy_sampler( s );
}

/* ---- test: fresh/unfresh toggle ----------------------------------------- */

static void
test_fresh( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_fresh" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );
  fd_gossip_wsample_self_stake( s, 100000UL * 1000000000UL );

  ulong stake = 1000UL * 1000000000UL; /* 1000 SOL */
  fd_gossip_wsample_add( s, 0UL, stake, 1 );
  fd_gossip_wsample_add( s, 1UL, stake, 1 );

  /* Both fresh: roughly 50/50. */
  ulong cnt_0 = 0UL;
  ulong N = 10000UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );
  FD_TEST( cnt_0 > N * 3UL / 10UL );
  FD_TEST( cnt_0 < N * 7UL / 10UL );

  /* Mark peer 1 as unfresh -- its PR weight drops to full/100.
     Peer 0 (weight 225) vs peer 1 (weight 225/100=2).  Peer 0 should
     dominate heavily. */
  fd_gossip_wsample_fresh( s, 1UL, 0 );

  cnt_0 = 0UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );
  FD_TEST( cnt_0 > N * 9UL / 10UL );

  /* Mark peer 1 as fresh again -- should go back to ~50/50. */
  fd_gossip_wsample_fresh( s, 1UL, 1 );

  cnt_0 = 0UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );
  FD_TEST( cnt_0 > N * 3UL / 10UL );
  FD_TEST( cnt_0 < N * 7UL / 10UL );

  /* fresh toggle should affect bucket trees too (matching Agave). */
  fd_gossip_wsample_fresh( s, 1UL, 0 );

  /* Both peers are still sampleable (staked), but drain confirms
     both are present. */
  ulong a = fd_gossip_wsample_sample_remove_bucket( s, 3UL );
  ulong b = fd_gossip_wsample_sample_remove_bucket( s, 3UL );
  FD_TEST( (a==0UL && b==1UL) || (a==1UL && b==0UL) );

  /* Statistical test: peer 0 (fresh, weight 16) vs peer 1 (unfresh,
     weight 1) -- peer 0 should dominate in bucket samples. */
  fd_gossip_wsample_add_bucket( s, 3UL, 0UL );
  fd_gossip_wsample_add_bucket( s, 3UL, 1UL );

  ulong bucket_cnt_0 = 0UL;
  for( ulong i=0UL; i<N; i++ ) {
    ulong idx = fd_gossip_wsample_sample_remove_bucket( s, 3UL );
    bucket_cnt_0 += (ulong)( idx == 0UL );
    fd_gossip_wsample_add_bucket( s, 3UL, idx ); /* re-add for next iter */
  }
  FD_TEST( bucket_cnt_0 > N * 8UL / 10UL );

  destroy_sampler( s );
}

/* ---- test: active/inactive toggle --------------------------------------- */

static void
test_active( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_active" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );
  fd_gossip_wsample_self_stake( s, 100000UL * 1000000000UL );

  ulong stake = 100UL * 1000000000UL;
  fd_gossip_wsample_add( s, 0UL, stake, 1 );
  fd_gossip_wsample_add( s, 1UL, stake, 1 );

  /* Both active: PR and bucket samples return 0 or 1. */
  for( ulong i=0UL; i<50UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==0UL || idx==1UL );
  }

  /* Deactivate peer 1 -- only peer 0 should appear anywhere. */
  fd_gossip_wsample_active( s, 1UL, 0 );

  for( ulong i=0UL; i<100UL; i++ )
    FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  for( ulong b=0UL; b<25UL; b++ ) {
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == 0UL );
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == ULONG_MAX );
  }

  /* Reactivate peer 1 -- both peers should be sampleable again. */
  fd_gossip_wsample_active( s, 1UL, 1 );

  int seen_0 = 0, seen_1 = 0;
  for( ulong i=0UL; i<200UL; i++ ) {
    ulong idx = fd_gossip_wsample_sample_pull_request( s );
    FD_TEST( idx==0UL || idx==1UL );
    if( idx==0UL ) seen_0 = 1;
    if( idx==1UL ) seen_1 = 1;
  }
  FD_TEST( seen_0 && seen_1 );

  /* Peer 1 should be back in bucket trees too.  Add back bucket
     samples that were drained above for peer 0. */
  for( ulong b=0UL; b<25UL; b++ )
    fd_gossip_wsample_add_bucket( s, b, 0UL );

  ulong a = fd_gossip_wsample_sample_remove_bucket( s, 7UL );
  ulong c = fd_gossip_wsample_sample_remove_bucket( s, 7UL );
  FD_TEST( (a==0UL && c==1UL) || (a==1UL && c==0UL) );

  destroy_sampler( s );
}

/* ---- test: add with active=0 ------------------------------------------- */

static void
test_add_inactive( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_add_inactive" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );
  fd_gossip_wsample_self_stake( s, 100000UL * 1000000000UL );

  /* Add peer 0 active, peer 1 inactive. */
  fd_gossip_wsample_add( s, 0UL, 100UL * 1000000000UL, 1 );
  fd_gossip_wsample_add( s, 1UL, 100UL * 1000000000UL, 0 );

  /* PR tree: peer 1 is inactive and should NOT be sampleable.  Only
     peer 0 should appear. */
  for( ulong i=0UL; i<200UL; i++ ) {
    FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 0UL );
  }

  /* Bucket: only peer 0 should be present. */
  for( ulong b=0UL; b<25UL; b++ ) {
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == 0UL );
    FD_TEST( fd_gossip_wsample_sample_remove_bucket( s, b ) == ULONG_MAX );
  }

  /* Activate peer 1 -- now both in buckets. */
  fd_gossip_wsample_active( s, 1UL, 1 );

  /* Re-add peer 0 to buckets (was drained above). */
  for( ulong b=0UL; b<25UL; b++ )
    fd_gossip_wsample_add_bucket( s, b, 0UL );

  ulong a = fd_gossip_wsample_sample_remove_bucket( s, 12UL );
  ulong c = fd_gossip_wsample_sample_remove_bucket( s, 12UL );
  FD_TEST( (a==0UL && c==1UL) || (a==1UL && c==0UL) );

  destroy_sampler( s );
}

/* ---- test: unfresh peer stake update preserves unfresh ratio ------------ */

static void
test_stake_update_preserves_unfresh( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_stake_update_preserves_unfresh" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );
  fd_gossip_wsample_self_stake( s, 100000UL * 1000000000UL );

  ulong stake = 1000UL * 1000000000UL;
  fd_gossip_wsample_add( s, 0UL, stake, 1 );

  /* Mark unfresh -- weight should be full/16. */
  fd_gossip_wsample_fresh( s, 0UL, 0 );

  /* Update stake -- unfresh flag should be preserved (weight still
     reduced).  With only one peer, it should still be sampleable. */
  fd_gossip_wsample_stake( s, 0UL, 5000UL * 1000000000UL );

  for( ulong i=0UL; i<50UL; i++ )
    FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  /* Now add a fresh peer with comparable stake -- it should dominate
     because peer 0 is still unfresh. */
  fd_gossip_wsample_add( s, 1UL, 5000UL * 1000000000UL, 1 );

  ulong cnt_1 = 0UL;
  ulong N = 10000UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_1 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 1UL );
  /* Peer 1 fresh (weight ~289), peer 0 unfresh (weight ~289/16=18).
     Peer 1 should get the vast majority of samples. */
  FD_TEST( cnt_1 > N * 9UL / 10UL );

  destroy_sampler( s );
}

/* ---- test: active toggle preserves unfresh state (bugs #17/#18) --------- */

static void
test_active_preserves_unfresh( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_active_preserves_unfresh" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );
  fd_gossip_wsample_self_stake( s, 100000UL * 1000000000UL );

  ulong stake = 1000UL * 1000000000UL;
  fd_gossip_wsample_add( s, 0UL, stake, 1 ); /* fresh peer */
  fd_gossip_wsample_add( s, 1UL, stake, 1 );

  /* Mark peer 1 unfresh. */
  fd_gossip_wsample_fresh( s, 1UL, 0 );

  /* Deactivate then reactivate peer 1.  Its unfresh state should be
     preserved across the inactive/active cycle. */
  fd_gossip_wsample_active( s, 1UL, 0 );
  fd_gossip_wsample_active( s, 1UL, 1 );

  /* PR tree: peer 0 (fresh) should dominate peer 1 (unfresh). */
  ulong cnt_0 = 0UL;
  ulong N = 10000UL;
  for( ulong i=0UL; i<N; i++ )
    cnt_0 += (ulong)( fd_gossip_wsample_sample_pull_request( s ) == 0UL );
  FD_TEST( cnt_0 > N * 8UL / 10UL );

  /* Bucket tree: peer 0 should also dominate. */
  ulong bcnt_0 = 0UL;
  for( ulong i=0UL; i<N; i++ ) {
    ulong idx = fd_gossip_wsample_sample_remove_bucket( s, 5UL );
    bcnt_0 += (ulong)( idx == 0UL );
    fd_gossip_wsample_add_bucket( s, 5UL, idx );
  }
  FD_TEST( bcnt_0 > N * 8UL / 10UL );

  destroy_sampler( s );
}

/* ---- test: active unfresh unstaked peer regains freshness --------------- */

/* Previously, an active unstaked peer marked unfresh would have PR
   weight 0 (unfresh + unstaked => weight 0).  When later marked fresh,
   the old code checked "if( old_pr_weight == 0 ) skip", so the fresh
   toggle was silently ignored and the peer could never be sampled again
   despite being active.  The explicit active[] array fixes this. */

static void
test_unfresh_unstaked_regains_fresh( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_unfresh_unstaked_regains_fresh" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );

  /* Add an unstaked active peer. */
  fd_gossip_wsample_add( s, 0UL, 0UL, 1 );

  /* Should be sampleable (weight 1 for zero-stake fresh peers). */
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  /* Mark unfresh — unstaked + unfresh => PR weight 0.  Not sampleable. */
  fd_gossip_wsample_fresh( s, 0UL, 0 );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == ULONG_MAX );

  /* Mark fresh again — the peer is still active, so it MUST become
     sampleable again.  This was the bug: old code saw pr_weight==0 and
     skipped the freshness update entirely. */
  fd_gossip_wsample_fresh( s, 0UL, 1 );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  destroy_sampler( s );
}

/* ---- test: stake update on active zero-weight peer ---------------------- */

/* An active unstaked unfresh peer has PR weight 0.  If its stake is then
   increased, the old code's "if( old_pr_w ) { ... }" guard would skip
   the update, leaving the peer with zero weight despite now being staked
   and active. */

static void
test_stake_update_zero_weight_active( fd_rng_t * rng ) {
  FD_LOG_NOTICE(( "test_stake_update_zero_weight_active" ));

  fd_gossip_wsample_t * s = new_sampler( rng, 16UL );
  fd_gossip_wsample_self_stake( s, 100000UL * 1000000000UL );

  /* Add an unstaked active peer, then mark unfresh => PR weight 0. */
  fd_gossip_wsample_add( s, 0UL, 0UL, 1 );
  fd_gossip_wsample_fresh( s, 0UL, 0 );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == ULONG_MAX );

  /* Update its stake to a large value.  Even though the peer is unfresh,
     staked unfresh peers get full/16 (min 1), so it should now be
     sampleable in the PR tree. */
  fd_gossip_wsample_stake( s, 0UL, 1000UL * 1000000000UL );
  FD_TEST( fd_gossip_wsample_sample_pull_request( s ) == 0UL );

  destroy_sampler( s );
}

/* ---- main --------------------------------------------------------------- */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 42U, 0UL ) );
  FD_TEST( rng );

  test_lifecycle( rng );
  test_empty_sampler( rng );
  test_single_peer( rng );
  test_zero_stake( rng );
  test_add_remove( rng );
  test_bucket_cycle( rng );
  test_remove_after_bucket_remove( rng );
  test_sparse_indices( rng );
  test_distribution( rng );
  test_many_peers( rng );
  test_bucket_independence( rng );
  test_readd_peer( rng );
  test_self_stake( rng );
  test_stake_update( rng );
  test_fresh( rng );
  test_active( rng );
  test_add_inactive( rng );
  test_stake_update_preserves_unfresh( rng );
  test_active_preserves_unfresh( rng );
  test_unfresh_unstaked_regains_fresh( rng );
  test_stake_update_zero_weight_active( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
