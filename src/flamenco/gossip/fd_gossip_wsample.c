/* fd_gossip_wsample implements stake-weighted peer sampling for gossip.

   Internally, the sampler maintains 26 independent 9-ary left-sum trees
   (1 for pull-request sampling + 25 for bucket sampling).  Each tree
   supports O(log_9 n) weight updates and O(log_9 n) sampling.  See
   src/ballet/wsample/fd_wsample.c for a detailed explanation of the
   9-ary left-sum tree data structure.

   The bucket scoring formula (bucket_score) and bucket count (25) match
   the active-set rotation logic in fd_active_set. */

#include "fd_gossip_wsample.h"
#include "fd_active_set.h"
#include "../../util/log/fd_log.h"

#define R           (9UL)  /* Radix of the sampling trees. */
#define BUCKET_CNT  (25UL) /* Number of active-set buckets (stake tiers). */
#define TREE_CNT    (1UL+BUCKET_CNT) /* Total number of trees: 1 pull-request tree + BUCKET_CNT bucket trees. */
#define PR_TREE_IDX (0UL) /* Index of the pull-request tree among the TREE_CNT trees. */

/* Computes the pull-request tree weight for a peer with the given
   stake.  Matches Agave's formula:

     stake_sol  = stake / LAMPORTS_PER_SOL
     bucket     = floor(log2(stake_sol)) + 1   (0 when stake_sol==0)
     weight     = (bucket + 1)^2

   This gives a logarithmic compression so that high-stake nodes are
   preferred but not overwhelmingly so.  Zero-stake peers get weight 1. */

static inline ulong
pr_weight( ulong stake ) {
  ulong stake_sol = stake / 1000000000UL;
  ulong bucket    = stake_sol ? ( 64UL - (ulong)__builtin_clzl( stake_sol ) ) : 0UL;
  ulong w         = bucket + 1UL;
  return w * w;
}

/* 9-ary tree node.  Each internal node stores the cumulative weight of
   its first R-1 subtrees (see fd_wsample.c for the algorithm). */

struct gossip_wsample_tree_ele {
  ulong left_sum[ R-1UL ];
};

typedef struct gossip_wsample_tree_ele tree_ele_t;

struct fd_gossip_wsample_private {
  fd_rng_t *   rng;           /* borrowed; not owned                          */
  ulong        max_peers;     /* capacity (max sparse peer idx + 1)           */
  ulong        internal_cnt;  /* number of internal tree nodes per tree       */
  ulong        height;        /* tree height (levels above the implicit
                                 leaves; 0 when max_peers<=1)                 */
  ulong *      stakes;        /* per-peer stake amounts                       */
  int *        exists;        /* per-peer existence flags (for quick validity checks) */
  int *        fresh;         /* per-peer freshness flags                     */
  int *        ping_tracked;  /* per-peer ping-tracked flag                   */
  int *        is_entrypoint; /* per-peer is-entrypoint flag                  */
  int **       is_removed;    /* per-peer per-bucket is-removed flag */
  tree_ele_t * trees;         /* TREE_CNT * internal_cnt tree nodes           */
  ulong        self_stake;    /* our own stake; PR weights are capped at this */
  ulong        self_ci_idx;   /* our own contact info index, or ULONG_MAX if none */
  ulong        pr_total_weight;
  ulong        bucket_total_weight[ BUCKET_CNT ];
};

/* Given a leaf count, computes the tree height and the number of
   internal nodes.  height = ceil(log_R(leaf_cnt)); internal_cnt =
   sum_{i=0}^{height-1} R^i = (R^height - 1)/(R - 1).  When
   leaf_cnt<=1, height and internal_cnt are both 0. */

static inline void
compute_height( ulong   leaf_cnt,
                ulong * out_height,
                ulong * out_internal_cnt ) {
  ulong height   = 0UL;
  ulong internal = 0UL;
  ulong pow_r    = 1UL; /* R^height */
  while( leaf_cnt>pow_r ) {
    internal += pow_r;
    pow_r    *= R;
    height++;
  }
  *out_height       = height;
  *out_internal_cnt = internal;
}

/* Computes the weight of a peer with the given stake in the given
   bucket tree.  Always returns >= 1 (even when stake is 0). */

static inline ulong
bucket_score( ulong stake,
              ulong bucket ) {
  ulong peer_bucket = fd_active_set_stake_bucket( stake );
  ulong score       = fd_ulong_min( bucket, peer_bucket ) + 1UL;
  return score * score;
}

/* Compute the target PR tree weight for a peer, accounting for
   freshness.  Matches Agave's get_gossip_nodes logic: fresh peers get
   full weight, unfresh unstaked peers get 0, unfresh staked peers get
   full/16 (min 1). */

static inline ulong
adjusted_pr_weight( ulong stake,
                    ulong self_stake,
                    int   is_fresh ) {
  ulong full = pr_weight( fd_ulong_min( stake, self_stake ) );
  if( FD_LIKELY( is_fresh ) ) return full;
  if( FD_UNLIKELY( !stake ) ) return 0UL;
  ulong w = full/16UL;
  return w ? w : 1UL;
}

/* Compute the target bucket tree weight for a peer, accounting for
   freshness.  In Agave, get_gossip_nodes filters stale peers before
   push active-set rotation, so unfresh peers should be downweighted in
   bucket trees too (unstaked excluded, staked 1/16). */

static inline ulong
adjusted_bucket_weight( ulong stake,
                        ulong bucket,
                        int   is_fresh ) {
  ulong full = bucket_score( stake, bucket );
  if( FD_LIKELY( is_fresh ) ) return full;
  if( FD_UNLIKELY( !stake ) ) return 0UL;
  ulong w = full/16UL;
  return w ? w : 1UL;
}

/* Add delta weight to the leaf at leaf_idx, propagating the update up
   to root.  Uses branchless inner loop (see fd_wsample.c). */

static void
tree_add_weight( tree_ele_t * tree,
                 ulong        height,
                 ulong        internal_cnt,
                 ulong        leaf_idx,
                 ulong        delta ) {
  ulong cursor = leaf_idx + internal_cnt;
  for( ulong h=0UL; h<height; h++ ) {
    ulong parent    = (cursor-1UL) / R;
    ulong child_idx = cursor-1UL - R*parent;
    for( ulong k=0UL; k<R-1UL; k++ ) {
      tree[ parent ].left_sum[ k ] += (ulong)(((long)(child_idx-k-1UL))>>63) & delta;
    }
    cursor = parent;
  }
}

/* Subtract delta weight from the leaf at leaf_idx, propagating the
   update up to root. */

static void
tree_sub_weight( tree_ele_t * tree,
                 ulong        height,
                 ulong        internal_cnt,
                 ulong        leaf_idx,
                 ulong        delta ) {
  ulong cursor = leaf_idx + internal_cnt;
  for( ulong h=0UL; h<height; h++ ) {
    ulong parent    = (cursor-1UL) / R;
    ulong child_idx = cursor-1UL - R*parent;
    for( ulong k=0UL; k<R-1UL; k++ ) {
      tree[ parent ].left_sum[ k ] -= (ulong)(((long)(child_idx-k-1UL))>>63) & delta;
    }
    cursor = parent;
  }
}

/* Weighted sample from a tree.  Returns (leaf_idx, leaf_weight).
   Returns (.idx=ULONG_MAX, .weight=0) when total_weight==0. */

typedef struct { ulong idx; ulong weight; } sample_result_t;

static inline sample_result_t
tree_sample( tree_ele_t const * tree,
             ulong              height,
             ulong              internal_cnt,
             ulong              total_weight,
             fd_rng_t *         rng ) {
  if( FD_UNLIKELY( !total_weight ) ) {
    sample_result_t empty = { .idx = ULONG_MAX, .weight = 0UL };
    return empty;
  }

  ulong query  = fd_rng_ulong_roll( rng, total_weight );
  ulong cursor = 0UL;
  ulong S      = total_weight;

  for( ulong h=0UL; h<height; h++ ) {
    tree_ele_t const * e = tree + cursor;

    /* Branchless child selection: count how many left_sum entries are
       <= the query value. */
    ulong child_idx = 0UL;
    for( ulong i=0UL; i<R-1UL; i++ ) child_idx += (ulong)( e->left_sum[ i ]<=query );

    ulong lm1 = child_idx > 0UL   ? e->left_sum[ child_idx-1UL] : 0UL;
    ulong li  = child_idx < R-1UL ? e->left_sum[ child_idx ]    : S;

    query -= lm1;
    S      = li - lm1;
    cursor = R*cursor+child_idx+1UL;
  }

  sample_result_t result = { .idx = cursor - internal_cnt, .weight = S };
  return result;
}

FD_FN_CONST ulong
fd_gossip_wsample_align( void ) {
  return 64UL;
}

FD_FN_CONST ulong
fd_gossip_wsample_footprint( ulong max_peers ) {
  if( FD_UNLIKELY( !max_peers ) ) return 0UL;

  ulong height;
  ulong internal_cnt;
  compute_height( max_peers, &height, &internal_cnt );
  (void)height;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, 64UL, sizeof(struct fd_gossip_wsample_private) );
  l = FD_LAYOUT_APPEND( l,  8UL, max_peers*sizeof(ulong)                  ); /* stakes  */
  l = FD_LAYOUT_APPEND( l,  4UL, max_peers*sizeof(int)                    ); /* exists  */
  l = FD_LAYOUT_APPEND( l,  4UL, max_peers*sizeof(int)                    ); /* fresh   */
  l = FD_LAYOUT_APPEND( l,  4UL, max_peers*sizeof(int)                    ); /* ping_tracked  */
  l = FD_LAYOUT_APPEND( l,  4UL, max_peers*sizeof(int)                    ); /* is_entrypoint */
  l = FD_LAYOUT_APPEND( l,  8UL, max_peers*sizeof(int *)                  ); /* is_removed */
  l = FD_LAYOUT_APPEND( l,  4UL, max_peers*BUCKET_CNT*sizeof(int)         ); /* removed */
  l = FD_LAYOUT_APPEND( l, 64UL, TREE_CNT*internal_cnt*sizeof(tree_ele_t) );
  return FD_LAYOUT_FINI( l, 64UL );
}

void *
fd_gossip_wsample_new( void *     shmem,
                       fd_rng_t * rng,
                       ulong      max_peers ) {
  if( FD_UNLIKELY( !shmem     ) ) return NULL;
  if( FD_UNLIKELY( !rng       ) ) return NULL;
  if( FD_UNLIKELY( !max_peers ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_wsample_align() ) ) ) return NULL;

  ulong height;
  ulong internal_cnt;
  compute_height( max_peers, &height, &internal_cnt );

  fd_gossip_wsample_t * s = (fd_gossip_wsample_t *)shmem;

  s->rng          = rng;
  s->max_peers    = max_peers;
  s->internal_cnt = internal_cnt;
  s->height       = height;

  /* Compute trailing-array pointers. */
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /*              */ FD_SCRATCH_ALLOC_APPEND( l, 64UL,           sizeof(struct fd_gossip_wsample_private) );
  s->stakes        = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), max_peers*sizeof(ulong)                  );
  s->exists        = FD_SCRATCH_ALLOC_APPEND( l, alignof(int),   max_peers*sizeof(int)                    );
  s->fresh         = FD_SCRATCH_ALLOC_APPEND( l, alignof(int),   max_peers*sizeof(int)                    );
  s->ping_tracked  = FD_SCRATCH_ALLOC_APPEND( l, alignof(int),   max_peers*sizeof(int)                    );
  s->is_entrypoint = FD_SCRATCH_ALLOC_APPEND( l, alignof(int),   max_peers*sizeof(int)                    );
  s->is_removed    = FD_SCRATCH_ALLOC_APPEND( l, alignof(int *), max_peers*sizeof(int *)                  );
  int * is_removed = FD_SCRATCH_ALLOC_APPEND( l, alignof(int),   max_peers*BUCKET_CNT*sizeof(int)         );
  s->trees         = FD_SCRATCH_ALLOC_APPEND( l, 64UL,           TREE_CNT*internal_cnt*sizeof(tree_ele_t) );

  /* Zero-initialize stakes, fresh flags, and trees. */
  fd_memset( s->stakes,        0, max_peers * sizeof(ulong) );
  fd_memset( s->exists,        0, max_peers * sizeof(int) );
  fd_memset( s->fresh,         0, max_peers * sizeof(int) );
  fd_memset( s->ping_tracked,  0, max_peers * sizeof(int) );
  fd_memset( s->is_entrypoint, 0, max_peers * sizeof(int) );
  fd_memset( is_removed,       0, max_peers * BUCKET_CNT*sizeof(int) );
  if( FD_LIKELY( internal_cnt ) ) fd_memset( s->trees, 0, TREE_CNT*internal_cnt*sizeof(tree_ele_t) );

  /* Zero-initialize total weights and self stake. */
  s->self_stake      = 0UL;
  s->self_ci_idx     = ULONG_MAX;
  s->pr_total_weight = 0UL;
  for( ulong b=0UL; b<BUCKET_CNT; b++ ) s->bucket_total_weight[ b ] = 0UL;

  for( ulong i=0UL; i<max_peers; i++ ) s->is_removed[ i ] = is_removed + i*BUCKET_CNT;

  return shmem;
}

fd_gossip_wsample_t *
fd_gossip_wsample_join( void * shwsample ) {
  return (fd_gossip_wsample_t *)shwsample;
}

static inline int
is_active( ulong stake,
           int   ping_tracked,
           int   is_entrypoint ) {
  /* 1. If the node is an entrypoint, it is active */
  if( FD_UNLIKELY( is_entrypoint ) ) return 1;

  /* 2. If the node has more than 1 sol staked, it is active */
  if( FD_UNLIKELY( stake>=1000000000UL ) ) return 1;

  /* 3. If the node has actively ponged a ping, it is active */
  if( FD_UNLIKELY( ping_tracked ) ) return 1;

  return 0;
}

void
fd_gossip_wsample_add( fd_gossip_wsample_t * sampler,
                       ulong                 ci_idx,
                       ulong                 stake,
                       int                   ping_tracked,
                       int                   is_entrypoint,
                       int                   is_me ) {
  FD_TEST( !sampler->exists[ ci_idx ] );

  sampler->exists[ ci_idx ] = 1;
  sampler->stakes[ ci_idx ] = stake;
  sampler->fresh[ ci_idx ]  = 1; /* newly added peers are fresh */
  sampler->ping_tracked[ ci_idx ] = ping_tracked;
  sampler->is_entrypoint[ ci_idx ] = is_entrypoint;
  fd_memset( sampler->is_removed[ ci_idx ], 0, BUCKET_CNT*sizeof(int) );

  if( FD_UNLIKELY( is_me ) ) {
    FD_TEST( sampler->self_ci_idx==ULONG_MAX );
    sampler->self_ci_idx = ci_idx;
    return;
  }

  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  /* Only active peers get weight in any sampler tree.  Inactive
     peers (e.g. un-pinged, or our own identity) are tracked by stake
     but remain unsampleable until they become active. */
  if( FD_LIKELY( is_active( stake, ping_tracked, is_entrypoint ) ) ) {
    /* Pull-request tree: log-squared weight matching Agave, with the
       peer's stake capped at our own stake. */
    ulong pr_w = pr_weight( fd_ulong_min( stake, sampler->self_stake ) );
    tree_add_weight( sampler->trees+PR_TREE_IDX*internal_cnt, height, internal_cnt, ci_idx, pr_w );
    sampler->pr_total_weight += pr_w;

    /* Bucket trees. */
    for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
      ulong bw = adjusted_bucket_weight( stake, b, 1 /* is_fresh */ );
      tree_add_weight( sampler->trees+(1UL+b)*internal_cnt, height, internal_cnt, ci_idx, bw );
      sampler->bucket_total_weight[ b ] += bw;
    }
  }
}

void
fd_gossip_wsample_remove( fd_gossip_wsample_t * sampler,
                          ulong                 ci_idx ) {
  FD_TEST( sampler->exists[ ci_idx ] );

  sampler->exists[ ci_idx ] = 0;
  if( FD_UNLIKELY( sampler->self_ci_idx==ci_idx ) ) {
    sampler->self_ci_idx = ULONG_MAX;
    return;
  }

  int active = is_active( sampler->stakes[ ci_idx ], sampler->ping_tracked[ ci_idx ], sampler->is_entrypoint[ ci_idx ] );
  if( FD_UNLIKELY( !active ) ) return;

  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  ulong pr_w = adjusted_pr_weight( sampler->stakes[ ci_idx ], sampler->self_stake, sampler->fresh[ ci_idx ] );
  tree_sub_weight( sampler->trees+PR_TREE_IDX*internal_cnt, height, internal_cnt, ci_idx, pr_w );
  sampler->pr_total_weight -= pr_w;

  for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
    if( FD_UNLIKELY( sampler->is_removed[ ci_idx ][ b ] ) ) continue; /* Peer was already sample-removed from this bucket, so no weight to remove. */

    ulong bw = adjusted_bucket_weight( sampler->stakes[ ci_idx ], b, sampler->fresh[ ci_idx ] );
    tree_sub_weight( sampler->trees+(1UL+b)*internal_cnt, height, internal_cnt, ci_idx, bw );
    sampler->bucket_total_weight[ b ] -= bw;
  }
}

ulong
fd_gossip_wsample_sample_pull_request( fd_gossip_wsample_t * sampler ) {
  sample_result_t r = tree_sample( sampler->trees + PR_TREE_IDX*sampler->internal_cnt,
                                   sampler->height,
                                   sampler->internal_cnt,
                                   sampler->pr_total_weight,
                                   sampler->rng );
  return r.idx;
}

ulong
fd_gossip_wsample_sample_remove_bucket( fd_gossip_wsample_t * sampler,
                                        ulong                 bucket ) {
  tree_ele_t * bt = sampler->trees + (1UL+bucket)*sampler->internal_cnt;

  sample_result_t r = tree_sample( bt,
                                   sampler->height,
                                   sampler->internal_cnt,
                                   sampler->bucket_total_weight[bucket],
                                   sampler->rng );
  if( FD_UNLIKELY( r.idx==ULONG_MAX ) ) return ULONG_MAX;

  /* Remove the sampled peer from this bucket tree so it cannot be
     sampled again until re-added with fd_gossip_wsample_add_bucket. */
  FD_TEST( sampler->exists[ r.idx ] );
  int active = is_active( sampler->stakes[ r.idx ], sampler->ping_tracked[ r.idx ], sampler->is_entrypoint[ r.idx ] );
  ulong weight = fd_ulong_if( active, adjusted_bucket_weight( sampler->stakes[ r.idx ], bucket, sampler->fresh[ r.idx ] ), 0UL );
  FD_TEST( r.weight==weight );
  FD_TEST( !sampler->is_removed[ r.idx ][ bucket ] );
  FD_TEST( sampler->self_ci_idx!=r.idx );
  tree_sub_weight( bt, sampler->height, sampler->internal_cnt, r.idx, r.weight );
  sampler->bucket_total_weight[ bucket ] -= r.weight;
  sampler->is_removed[ r.idx ][ bucket ] = 1;

  return r.idx;
}

void
fd_gossip_wsample_add_bucket( fd_gossip_wsample_t * sampler,
                              ulong                 bucket,
                              ulong                 ci_idx ) {
  FD_TEST( sampler->exists[ ci_idx ] );
  FD_TEST( sampler->is_removed[ ci_idx ][ bucket ] );
  FD_TEST( sampler->self_ci_idx!=ci_idx );

  ulong stake    = sampler->stakes[ ci_idx ];
  int   is_fresh = sampler->fresh[ ci_idx ];
  int   active   = is_active( stake, sampler->ping_tracked[ ci_idx ], sampler->is_entrypoint[ ci_idx ] );
  ulong bw       = fd_ulong_if( active, adjusted_bucket_weight( stake, bucket, is_fresh ), 0UL );

  tree_add_weight( sampler->trees + (1UL+bucket)*sampler->internal_cnt, sampler->height, sampler->internal_cnt, ci_idx, bw );
  sampler->bucket_total_weight[ bucket ] += bw;
  sampler->is_removed[ ci_idx ][ bucket ] = 0;
}

static void
recompute( fd_gossip_wsample_t * sampler,
           ulong                 ci_idx,
           ulong                 old_stake,
           int                   old_fresh,
           int                   old_ping_tracked,
           int                   old_is_entrypoint,
           int                   old_is_me ) {
  FD_TEST( sampler->exists[ ci_idx ] );

  int old_active = is_active( old_stake, old_ping_tracked, old_is_entrypoint );
  int new_active = is_active( sampler->stakes[ ci_idx ], sampler->ping_tracked[ ci_idx ], sampler->is_entrypoint[ ci_idx ] );

  int   is_fresh     = sampler->fresh[ ci_idx ];
  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  /* Update pull-request tree weight. */
  tree_ele_t * pr = sampler->trees + PR_TREE_IDX*internal_cnt;
  ulong old_pr_w = fd_ulong_if( old_active, adjusted_pr_weight( old_stake, sampler->self_stake, old_fresh ), 0UL );
  if( FD_UNLIKELY( old_is_me ) ) old_pr_w = 0UL;
  ulong new_pr_w = fd_ulong_if( new_active, adjusted_pr_weight( sampler->stakes[ ci_idx ], sampler->self_stake, is_fresh ), 0UL );
  if( FD_UNLIKELY( sampler->self_ci_idx==ci_idx ) ) new_pr_w = 0UL;

  if( FD_LIKELY( new_pr_w>old_pr_w ) ){
    ulong delta = new_pr_w-old_pr_w;
    tree_add_weight( pr, height, internal_cnt, ci_idx, delta );
    sampler->pr_total_weight += delta;
  } else if( FD_LIKELY( new_pr_w<old_pr_w ) ) {
    ulong delta = old_pr_w-new_pr_w;
    tree_sub_weight( pr, height, internal_cnt, ci_idx, delta );
    sampler->pr_total_weight -= delta;
  }

  /* Update bucket trees.  Only update buckets where the peer currently
     has weight (may have been sample-removed from individual buckets). */
  for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
    tree_ele_t * bt = sampler->trees + (1UL+b)*internal_cnt;
    if( FD_UNLIKELY( sampler->is_removed[ ci_idx ][ b ] ) ) continue; /* Peer is currently sample-removed from this bucket, so has no weight to update. */

    ulong old_bw = fd_ulong_if( old_active, adjusted_bucket_weight( old_stake, b, old_fresh ), 0UL );
    if( FD_UNLIKELY( old_is_me ) ) old_bw = 0UL;
    ulong new_bw = fd_ulong_if( new_active, adjusted_bucket_weight( sampler->stakes[ ci_idx ], b, is_fresh ), 0UL );
    if( FD_UNLIKELY( sampler->self_ci_idx==ci_idx ) ) new_bw = 0UL;

    if( FD_LIKELY( new_bw>old_bw ) ) {
      ulong delta = new_bw-old_bw;
      tree_add_weight( bt, height, internal_cnt, ci_idx, delta );
      sampler->bucket_total_weight[ b ] += delta;
    } else if( FD_LIKELY( new_bw < old_bw ) ) {
      ulong delta = old_bw-new_bw;
      tree_sub_weight( bt, height, internal_cnt, ci_idx, delta );
      sampler->bucket_total_weight[ b ] -= delta;
    }
  }
}

void
fd_gossip_wsample_stake( fd_gossip_wsample_t * sampler,
                         ulong                 ci_idx,
                         ulong                 new_stake ) {
  FD_TEST( sampler->exists[ ci_idx ] );

  if( FD_UNLIKELY( sampler->stakes[ ci_idx ]==new_stake ) ) return;
  ulong old_stake = sampler->stakes[ ci_idx ];
  sampler->stakes[ ci_idx ] = new_stake;
  recompute( sampler, ci_idx, old_stake, sampler->fresh[ ci_idx ], sampler->ping_tracked[ ci_idx ], sampler->is_entrypoint[ ci_idx ], sampler->self_ci_idx==ci_idx );
}

void
fd_gossip_wsample_fresh( fd_gossip_wsample_t * sampler,
                         ulong                 ci_idx,
                         int                   fresh ) {
  FD_TEST( sampler->exists[ ci_idx ] );

  if( FD_UNLIKELY( sampler->fresh[ ci_idx ]==fresh ) ) return;
  sampler->fresh[ ci_idx ] = fresh;
  recompute( sampler, ci_idx, sampler->stakes[ ci_idx ], !fresh, sampler->ping_tracked[ ci_idx ], sampler->is_entrypoint[ ci_idx ], sampler->self_ci_idx==ci_idx );
}

void
fd_gossip_wsample_ping_tracked( fd_gossip_wsample_t * sampler,
                                ulong                 ci_idx,
                                int                   ping_tracked ) {
  FD_TEST( sampler->exists[ ci_idx ] );

  if( FD_UNLIKELY( sampler->ping_tracked[ ci_idx ]==ping_tracked ) ) return;
  sampler->ping_tracked[ ci_idx ] = ping_tracked;
  recompute( sampler, ci_idx, sampler->stakes[ ci_idx ], sampler->fresh[ ci_idx ], !ping_tracked, sampler->is_entrypoint[ ci_idx ], sampler->self_ci_idx==ci_idx );
}

void
fd_gossip_wsample_is_entrypoint( fd_gossip_wsample_t * sampler,
                                 ulong                 ci_idx,
                                 int                   is_entrypoint ) {
  FD_TEST( sampler->exists[ ci_idx ] );

  if( FD_UNLIKELY( sampler->is_entrypoint[ ci_idx ]==is_entrypoint ) ) return;
  sampler->is_entrypoint[ ci_idx ] = is_entrypoint;
  recompute( sampler, ci_idx, sampler->stakes[ ci_idx ], sampler->fresh[ ci_idx ], sampler->ping_tracked[ ci_idx ], !is_entrypoint, sampler->self_ci_idx==ci_idx );
}

void
fd_gossip_wsample_is_me( fd_gossip_wsample_t * sampler,
                         ulong                 ci_idx,
                         int                   is_me ) {
  FD_TEST( sampler->exists[ ci_idx ] );
  if( FD_LIKELY( !is_me ) ) {
    FD_TEST( sampler->self_ci_idx!=ci_idx );
    return;
  }

  FD_TEST( sampler->self_ci_idx==ci_idx || sampler->self_ci_idx==ULONG_MAX );
  if( FD_LIKELY( sampler->self_ci_idx==ci_idx ) ) return;
  sampler->self_ci_idx = ci_idx;
  recompute( sampler, ci_idx, sampler->stakes[ ci_idx ], sampler->fresh[ ci_idx ], sampler->ping_tracked[ ci_idx ], sampler->is_entrypoint[ ci_idx ], 0 );
}

void
fd_gossip_wsample_set_identity( fd_gossip_wsample_t * sampler,
                                ulong                 ci_idx ) {
  FD_TEST( sampler->self_ci_idx==ULONG_MAX || sampler->exists[ sampler->self_ci_idx ] );
  FD_TEST( ci_idx==ULONG_MAX || sampler->exists[ ci_idx ] );
  if( FD_UNLIKELY( sampler->self_ci_idx==ci_idx ) ) return;

  ulong old_ci_idx = sampler->self_ci_idx;
  sampler->self_ci_idx = ci_idx;

  if( FD_LIKELY( old_ci_idx!=ULONG_MAX ) ) {
    recompute( sampler, old_ci_idx, sampler->stakes[ old_ci_idx ], sampler->fresh[ old_ci_idx ], sampler->ping_tracked[ old_ci_idx ], sampler->is_entrypoint[ old_ci_idx ], 1 );
  }

  if( FD_LIKELY( ci_idx!=ULONG_MAX ) ) {
    recompute( sampler, ci_idx, sampler->stakes[ ci_idx ], sampler->fresh[ ci_idx ], sampler->ping_tracked[ ci_idx ], sampler->is_entrypoint[ ci_idx ], 0 );
  }
}

void
fd_gossip_wsample_self_stake( fd_gossip_wsample_t * sampler,
                              ulong                 self_stake ) {
  if( FD_UNLIKELY( sampler->self_stake==self_stake ) ) return;

  ulong old_self_stake = sampler->self_stake;
  sampler->self_stake  = self_stake;

  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;
  tree_ele_t * pr    = sampler->trees + PR_TREE_IDX*internal_cnt;
  ulong * stakes     = sampler->stakes;
  int * fresh_flags  = sampler->fresh;

  for( ulong i=0UL; i<sampler->max_peers; i++ ) {
    if( FD_UNLIKELY( !sampler->exists[ i ] ) ) continue;

    int active = is_active( stakes[ i ], sampler->ping_tracked[ i ], sampler->is_entrypoint[ i ] );
    ulong old_w = fd_ulong_if( active, adjusted_pr_weight( stakes[ i ], old_self_stake, fresh_flags[ i ] ), 0UL );
    if( FD_UNLIKELY( sampler->self_ci_idx==i ) ) old_w = 0UL;
    ulong new_w = fd_ulong_if( active, adjusted_pr_weight( stakes[ i ], self_stake, fresh_flags[ i ] ), 0UL );
    if( FD_UNLIKELY( sampler->self_ci_idx==i ) ) new_w = 0UL;

    if( FD_LIKELY( new_w>old_w ) ) {
      ulong delta = new_w-old_w;
      tree_add_weight( pr, height, internal_cnt, i, delta );
      sampler->pr_total_weight += delta;
    } else if( FD_LIKELY( new_w<old_w ) ) {
      ulong delta = old_w-new_w;
      tree_sub_weight( pr, height, internal_cnt, i, delta );
      sampler->pr_total_weight -= delta;
    }
  }
}
