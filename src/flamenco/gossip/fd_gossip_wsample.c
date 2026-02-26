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
  uchar *      fresh;         /* per-peer freshness flags                     */
  uchar *      active;        /* per-peer active flags                        */
  tree_ele_t * trees;         /* TREE_CNT * internal_cnt tree nodes           */
  ulong        self_stake;    /* our own stake; PR weights are capped at this */
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
  while( leaf_cnt > pow_r ) {
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
  ulong w = full / 16UL;
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
  ulong w = full / 16UL;
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
    ulong parent    = (cursor - 1UL) / R;
    ulong child_idx = cursor - 1UL - R * parent;
    for( ulong k=0UL; k<R-1UL; k++ )
      tree[parent].left_sum[k] +=
        (ulong)(((long)(child_idx - k - 1UL))>>63) & delta;
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
    ulong parent    = (cursor - 1UL) / R;
    ulong child_idx = cursor - 1UL - R * parent;
    for( ulong k=0UL; k<R-1UL; k++ )
      tree[parent].left_sum[k] -=
        (ulong)(((long)(child_idx - k - 1UL))>>63) & delta;
    cursor = parent;
  }
}

/* Returns the current weight of the leaf at leaf_idx by walking from
   the leaf up to the root (adapted from fd_wsample_find_weight). */

static ulong
tree_find_weight( tree_ele_t const * tree,
                  ulong              height,
                  ulong              internal_cnt,
                  ulong              total_weight,
                  ulong              leaf_idx ) {
  ulong cursor = leaf_idx + internal_cnt;
  ulong lm1    = 0UL;
  ulong li     = total_weight;

  for( ulong h=0UL; h<height; h++ ) {
    ulong parent    = (cursor - 1UL) / R;
    ulong child_idx = cursor - 1UL - R * parent;

    lm1 += child_idx > 0UL ? tree[parent].left_sum[child_idx - 1UL] : 0UL;
    if( FD_LIKELY( child_idx < R-1UL ) ) {
      li = tree[parent].left_sum[child_idx];
      break;
    }
    cursor = parent;
  }

  return li - lm1;
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
    for( ulong i=0UL; i<R-1UL; i++ )
      child_idx += (ulong)( e->left_sum[i] <= query );

    ulong lm1 = child_idx > 0UL   ? e->left_sum[child_idx - 1UL] : 0UL;
    ulong li  = child_idx < R-1UL ? e->left_sum[child_idx]        : S;

    query -= lm1;
    S      = li - lm1;
    cursor = R * cursor + child_idx + 1UL;
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
  l = FD_LAYOUT_APPEND( l, 64UL, sizeof(struct fd_gossip_wsample_private)     );
  l = FD_LAYOUT_APPEND( l,  8UL, max_peers * sizeof(ulong)                    ); /* stakes  */
  l = FD_LAYOUT_APPEND( l,  1UL, max_peers * sizeof(uchar)                    ); /* fresh   */
  l = FD_LAYOUT_APPEND( l,  1UL, max_peers * sizeof(uchar)                    ); /* active  */
  l = FD_LAYOUT_APPEND( l, 64UL, TREE_CNT * internal_cnt * sizeof(tree_ele_t) );
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
  /*          */ FD_SCRATCH_ALLOC_APPEND( l, 64UL,           sizeof(struct fd_gossip_wsample_private)     );
  s->stakes    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), max_peers * sizeof(ulong)                    );
  s->fresh     = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar), max_peers * sizeof(uchar)                    );
  s->active    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar), max_peers * sizeof(uchar)                    );
  s->trees     = FD_SCRATCH_ALLOC_APPEND( l, 64UL,           TREE_CNT * internal_cnt * sizeof(tree_ele_t) );

  /* Zero-initialize stakes, fresh flags, and trees. */
  fd_memset( s->stakes, 0, max_peers * sizeof(ulong) );
  fd_memset( s->fresh,  0, max_peers * sizeof(uchar) );
  fd_memset( s->active, 0, max_peers * sizeof(uchar) );
  if( internal_cnt )
    fd_memset( s->trees, 0, TREE_CNT * internal_cnt * sizeof(tree_ele_t) );

  /* Zero-initialize total weights and self stake. */
  s->self_stake      = 0UL;
  s->pr_total_weight = 0UL;
  for( ulong b=0UL; b<BUCKET_CNT; b++ ) s->bucket_total_weight[b] = 0UL;

  return shmem;
}

fd_gossip_wsample_t *
fd_gossip_wsample_join( void * shwsample ) {
  return (fd_gossip_wsample_t *)shwsample;
}

void
fd_gossip_wsample_add( fd_gossip_wsample_t * sampler,
                       ulong                 ci_idx,
                       ulong                 stake,
                       int                   active ) {
  sampler->stakes[ci_idx] = stake;
  sampler->fresh[ci_idx]  = 1; /* newly added peers are fresh */
  sampler->active[ci_idx] = (uchar)active;

  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  /* Only active peers get weight in any sampler tree.  Inactive
     peers (e.g. un-pinged, or our own identity) are tracked by stake
     but remain unsampleable until fd_gossip_wsample_active(1). */
  if( FD_LIKELY( active ) ) {
    /* Pull-request tree: log-squared weight matching Agave, with the
       peer's stake capped at our own stake. */
    ulong pr_w = pr_weight( fd_ulong_min( stake, sampler->self_stake ) );
    tree_add_weight( sampler->trees + PR_TREE_IDX * internal_cnt,
                     height, internal_cnt, ci_idx, pr_w );
    sampler->pr_total_weight += pr_w;

    /* Bucket trees. */
    for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
      ulong bw = bucket_score( stake, b );
      tree_add_weight( sampler->trees + (1UL+b) * internal_cnt,
                       height, internal_cnt, ci_idx, bw );
      sampler->bucket_total_weight[b] += bw;
    }
  }
}

void
fd_gossip_wsample_remove( fd_gossip_wsample_t * sampler,
                          ulong                 ci_idx ) {
  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  /* Pull-request tree: the weight may have been modified by
     fd_gossip_wsample_fresh (unfresh downweighting), so look up
     the actual current weight rather than recomputing it. */
  tree_ele_t * pr = sampler->trees + PR_TREE_IDX * internal_cnt;
  ulong pr_w = tree_find_weight( (tree_ele_t const *)pr, height,
                                 internal_cnt,
                                 sampler->pr_total_weight, ci_idx );
  if( pr_w ) {
    tree_sub_weight( pr, height, internal_cnt, ci_idx, pr_w );
    sampler->pr_total_weight -= pr_w;
  }

  /* Bucket trees: the peer may have been removed from some buckets via
     sample_remove_bucket, so look up the actual current weight rather
     than recomputing it. */
  for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
    tree_ele_t * bt = sampler->trees + (1UL+b) * internal_cnt;
    ulong bw = tree_find_weight( bt, height, internal_cnt,
                                 sampler->bucket_total_weight[b], ci_idx );
    if( bw ) {
      tree_sub_weight( bt, height, internal_cnt, ci_idx, bw );
      sampler->bucket_total_weight[b] -= bw;
    }
  }

  sampler->stakes[ci_idx] = 0UL;
  sampler->fresh[ci_idx]  = 0;
  sampler->active[ci_idx] = 0;
}

ulong
fd_gossip_wsample_sample_pull_request( fd_gossip_wsample_t * sampler ) {
  sample_result_t r = tree_sample( sampler->trees + PR_TREE_IDX * sampler->internal_cnt,
                                   sampler->height,
                                   sampler->internal_cnt,
                                   sampler->pr_total_weight,
                                   sampler->rng );
  return r.idx;
}

ulong
fd_gossip_wsample_sample_remove_bucket( fd_gossip_wsample_t * sampler,
                                        ulong                 bucket ) {
  tree_ele_t * bt = sampler->trees + (1UL + bucket) * sampler->internal_cnt;

  sample_result_t r = tree_sample( bt,
                                   sampler->height,
                                   sampler->internal_cnt,
                                   sampler->bucket_total_weight[bucket],
                                   sampler->rng );
  if( FD_UNLIKELY( r.idx==ULONG_MAX ) ) return ULONG_MAX;

  /* Remove the sampled peer from this bucket tree so it cannot be
     sampled again until re-added with fd_gossip_wsample_add_bucket. */
  tree_sub_weight( bt, sampler->height, sampler->internal_cnt,
                   r.idx, r.weight );
  sampler->bucket_total_weight[bucket] -= r.weight;

  return r.idx;
}

void
fd_gossip_wsample_stake( fd_gossip_wsample_t * sampler,
                         ulong                 ci_idx,
                         ulong                 new_stake ) {
  sampler->stakes[ci_idx] = new_stake;
  if( FD_UNLIKELY( !sampler->active[ci_idx] ) ) return;

  int   is_fresh     = (int)sampler->fresh[ci_idx];
  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  /* Update pull-request tree weight. */
  tree_ele_t * pr = sampler->trees + PR_TREE_IDX * internal_cnt;
  ulong old_pr_w = tree_find_weight( (tree_ele_t const *)pr, height,
                                     internal_cnt,
                                     sampler->pr_total_weight, ci_idx );
  ulong new_pr_w = adjusted_pr_weight( new_stake, sampler->self_stake, is_fresh );

  if( new_pr_w > old_pr_w ) {
    ulong delta = new_pr_w - old_pr_w;
    tree_add_weight( pr, height, internal_cnt, ci_idx, delta );
    sampler->pr_total_weight += delta;
  } else if( new_pr_w < old_pr_w ) {
    ulong delta = old_pr_w - new_pr_w;
    tree_sub_weight( pr, height, internal_cnt, ci_idx, delta );
    sampler->pr_total_weight -= delta;
  }

  /* Update bucket trees.  Only update buckets where the peer currently
     has weight (may have been sample-removed from individual buckets). */
  for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
    tree_ele_t * bt = sampler->trees + (1UL+b) * internal_cnt;
    ulong cur = tree_find_weight( (tree_ele_t const *)bt, height,
                                  internal_cnt,
                                  sampler->bucket_total_weight[b], ci_idx );
    if( !cur ) continue; /* Peer was sample-removed from this bucket. */
    ulong bw = adjusted_bucket_weight( new_stake, b, is_fresh );
    if( bw > cur ) {
      ulong delta = bw - cur;
      tree_add_weight( bt, height, internal_cnt, ci_idx, delta );
      sampler->bucket_total_weight[b] += delta;
    } else if( bw < cur ) {
      ulong delta = cur - bw;
      tree_sub_weight( bt, height, internal_cnt, ci_idx, delta );
      sampler->bucket_total_weight[b] -= delta;
    }
  }
}

void
fd_gossip_wsample_fresh( fd_gossip_wsample_t * sampler,
                         ulong                 ci_idx,
                         int                   fresh ) {
  sampler->fresh[ci_idx] = (uchar)fresh;
  if( FD_UNLIKELY( !sampler->active[ci_idx] ) ) return;

  ulong stake        = sampler->stakes[ci_idx];
  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  /* --- PR tree --- */
  tree_ele_t * pr = sampler->trees + PR_TREE_IDX * internal_cnt;
  ulong old_pr = tree_find_weight( (tree_ele_t const *)pr, height,
                                   internal_cnt,
                                   sampler->pr_total_weight, ci_idx );
  ulong new_pr = adjusted_pr_weight( stake, sampler->self_stake, fresh );
  if( new_pr > old_pr ) {
    ulong delta = new_pr - old_pr;
    tree_add_weight( pr, height, internal_cnt, ci_idx, delta );
    sampler->pr_total_weight += delta;
  } else if( new_pr < old_pr ) {
    ulong delta = old_pr - new_pr;
    tree_sub_weight( pr, height, internal_cnt, ci_idx, delta );
    sampler->pr_total_weight -= delta;
  }

  /* --- Bucket trees --- */
  for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
    tree_ele_t * bt = sampler->trees + (1UL+b) * internal_cnt;
    ulong cur = tree_find_weight( (tree_ele_t const *)bt, height,
                                  internal_cnt,
                                  sampler->bucket_total_weight[b], ci_idx );
    if( !cur ) continue; /* Peer was sample-removed from this bucket. */
    ulong target = adjusted_bucket_weight( stake, b, fresh );
    if( target > cur ) {
      ulong delta = target - cur;
      tree_add_weight( bt, height, internal_cnt, ci_idx, delta );
      sampler->bucket_total_weight[b] += delta;
    } else if( target < cur ) {
      ulong delta = cur - target;
      tree_sub_weight( bt, height, internal_cnt, ci_idx, delta );
      sampler->bucket_total_weight[b] -= delta;
    }
  }
}

void
fd_gossip_wsample_active( fd_gossip_wsample_t * sampler,
                          ulong                 ci_idx,
                          int                   active ) {
  sampler->active[ci_idx] = (uchar)active;

  ulong stake        = sampler->stakes[ci_idx];
  int   is_fresh     = (int)sampler->fresh[ci_idx];
  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;

  if( active ) {
    /* Re-add weight to PR tree, respecting current freshness. */
    tree_ele_t * pr = sampler->trees + PR_TREE_IDX * internal_cnt;
    ulong cur_pr = tree_find_weight( (tree_ele_t const *)pr, height,
                                     internal_cnt,
                                     sampler->pr_total_weight, ci_idx );
    ulong target_pr = adjusted_pr_weight( stake, sampler->self_stake, is_fresh );
    if( target_pr > cur_pr ) {
      ulong delta = target_pr - cur_pr;
      tree_add_weight( pr, height, internal_cnt, ci_idx, delta );
      sampler->pr_total_weight += delta;
    }

    /* Re-add weight to all bucket trees, respecting freshness. */
    for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
      tree_ele_t * bt = sampler->trees + (1UL+b) * internal_cnt;
      ulong cur = tree_find_weight( (tree_ele_t const *)bt, height,
                                    internal_cnt,
                                    sampler->bucket_total_weight[b], ci_idx );
      ulong bw  = adjusted_bucket_weight( stake, b, is_fresh );
      if( bw > cur ) {
        ulong delta = bw - cur;
        tree_add_weight( bt, height, internal_cnt, ci_idx, delta );
        sampler->bucket_total_weight[b] += delta;
      }
    }
  } else {
    /* Remove weight from PR tree. */
    tree_ele_t * pr = sampler->trees + PR_TREE_IDX * internal_cnt;
    ulong pr_w = tree_find_weight( (tree_ele_t const *)pr, height,
                                   internal_cnt,
                                   sampler->pr_total_weight, ci_idx );
    if( pr_w ) {
      tree_sub_weight( pr, height, internal_cnt, ci_idx, pr_w );
      sampler->pr_total_weight -= pr_w;
    }

    /* Remove weight from all bucket trees. */
    for( ulong b=0UL; b<BUCKET_CNT; b++ ) {
      tree_ele_t * bt = sampler->trees + (1UL+b) * internal_cnt;
      ulong bw = tree_find_weight( (tree_ele_t const *)bt, height,
                                   internal_cnt,
                                   sampler->bucket_total_weight[b], ci_idx );
      if( bw ) {
        tree_sub_weight( bt, height, internal_cnt, ci_idx, bw );
        sampler->bucket_total_weight[b] -= bw;
      }
    }
  }
}

void
fd_gossip_wsample_self_stake( fd_gossip_wsample_t * sampler,
                              ulong                 self_stake ) {
  ulong old_self_stake = sampler->self_stake;
  sampler->self_stake  = self_stake;

  if( old_self_stake == self_stake ) return;

  ulong height       = sampler->height;
  ulong internal_cnt = sampler->internal_cnt;
  tree_ele_t * pr    = sampler->trees + PR_TREE_IDX * internal_cnt;
  ulong * stakes      = sampler->stakes;
  uchar * fresh_flags  = sampler->fresh;
  uchar * active_flags = sampler->active;

  /* Re-weight all active peers in the PR tree. */
  for( ulong i=0UL; i<sampler->max_peers; i++ ) {
    if( !active_flags[i] ) continue; /* Skip inactive peers. */
    ulong old_w = tree_find_weight( (tree_ele_t const *)pr, height,
                                    internal_cnt,
                                    sampler->pr_total_weight, i );

    ulong new_w = adjusted_pr_weight( stakes[i], self_stake, (int)fresh_flags[i] );

    if( new_w > old_w ) {
      ulong delta = new_w - old_w;
      tree_add_weight( pr, height, internal_cnt, i, delta );
      sampler->pr_total_weight += delta;
    } else if( new_w < old_w ) {
      ulong delta = old_w - new_w;
      tree_sub_weight( pr, height, internal_cnt, i, delta );
      sampler->pr_total_weight -= delta;
    }
  }
}

void
fd_gossip_wsample_add_bucket( fd_gossip_wsample_t * sampler,
                              ulong                 bucket,
                              ulong                 ci_idx ) {
  ulong stake    = sampler->stakes[ci_idx];
  int   is_fresh = (int)sampler->fresh[ci_idx];
  ulong bw       = adjusted_bucket_weight( stake, bucket, is_fresh );

  tree_add_weight( sampler->trees + (1UL + bucket) * sampler->internal_cnt,
                   sampler->height, sampler->internal_cnt, ci_idx, bw );
  sampler->bucket_total_weight[bucket] += bw;
}
