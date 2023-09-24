#include "fd_wsample.h"
#include <math.h> /* For sqrt */

/* This sampling problem is an interesting one from a performance
   perspective.  There are lots of interesting approaches.  The
   header/implementation split is designed to give lots of flexibility
   for future optimization.  The current implementation uses a treap. */

struct __attribute__((aligned(32UL))) treap_ele {
  uint parent, left, right, prio;

  ulong weight;
  ulong left_sum; /* Total sum of this node's left subtree */
};
typedef struct treap_ele treap_ele_t;

#define TREAP_IDX_T      uint      /* Make the struct 32B for better cache behavior */
#define TREAP_NAME       treap
#define TREAP_T          treap_ele_t
#define TREAP_QUERY_T    void *                                         /* Not used */
#define TREAP_CMP(q, e)  (__extension__({ (void)(q); (void)(e); -1; })) /* Not used */
#define TREAP_LT(e0, e1) (e0<e1)                      /* They get inserted in order */


#include "../../util/tmpl/fd_treap.c"

struct __attribute__((aligned(32UL))) fd_wsample_private {
  ulong              total_weight;
  ulong              undeleted_cnt;
  ulong              undeleted_weight;
  int                undelete_enabled;
  /* 4 byte padding */

  fd_chacha20rng_t * rng;

  treap_t            treap[1];

  /* pool: Actually logically two pools.  Elements [0, ele_cnt) are the
     pool used for the treap.  Elements [ele_cnt, 2*ele_cnt) are a copy
     of the pool after construction but before any sampling so that we
     can implement undelete as a memcpy. */
  treap_ele_t        pool[];
};

typedef struct fd_wsample_private fd_wsample_t;


FD_FN_CONST ulong
fd_wsample_align( void ) {
  return 32UL;
}

FD_FN_CONST ulong
fd_wsample_footprint( ulong ele_cnt, int undelete_enabled ) {
  if( FD_UNLIKELY( ele_cnt >= UINT_MAX ) ) return 0UL;
  return sizeof(fd_wsample_t) + (undelete_enabled?2UL:1UL)*ele_cnt*sizeof(treap_ele_t);
}

fd_wsample_t *
fd_wsample_join( void * shmem  ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_wsample_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  return (fd_wsample_t *)shmem;
}

/* If we assume the probability of querying node i is proportional to
   1/i, then observe that the midpoint of the probability mass in the
   continuous approximation is the solution to (in Mathematica syntax):

        Integrate[ 1/i, {i, lo, hi}] = 2*Integrate[ 1/i, {i, lo, mid} ]

   which gives mid = sqrt(lo*hi).  This is in contrast to when the
   integrand is a constant, which gives the normal binary search rule:
   mid=(lo+hi)/2.

   We want the treap search to follow this modified binary search then,
   since that'll approximately split the stake weight/probability mass
   in half at each step.  We can control the level of each node with the
   prio field, where higher prio means closer to the root.

   This rule is almost as nice to work with mathematically as the normal
   binary search rule.  The jth entry from the left at level k is the
   region [ N^((1/2^k)*j), N^((1/2^k)*(j+1)) ).  We're basically doing
   binary search in the log domain.

   Rather than trying to compute these transcendental functions, this
   simple recursive implementation sets the right priorities.  We do
   want to be careful to ensure that the recursion is tightly bounded.
   From a continuous perspective, that's not a problem: the widest
   interval at level k is the last one, and we break when the interval's
   width is less than 1.  Solving 1=N-N^(1-(1/2^k)) for k yields
   k=-lg(1-log(N-1)/log(N)).  k is monotonically increasing as a
   function of N, which means that for all N,
           k <= -lg(1-log(N_max-1)/log(N_max)) < 37
   since N_max=2^32-1.

   The math is more complicated with rounding and finite precision, but
   sqrt(lo*hi) is very different from lo and hi unless lo and hi are
   approximately the same.  In that case, lo<mid and mid<hi ensures that
   both intervals are strictly smaller than the interval they came from,
   which prevents an infinite loop. */
static inline void
seed_recursive( treap_ele_t * pool,
                uint lo,
                uint hi,
                uint prio ) {
  uint mid = (uint)(sqrtf( (float)lo*(float)hi ) + 0.5f);
  if( (lo<mid) & (mid<hi) ) {
    /* since we start with lo=1, shift by 1 */
    pool[mid-1U].prio = prio;
    seed_recursive( pool, lo,  mid, prio-1U );
    seed_recursive( pool, mid, hi,  prio-1U );
  }

}


void *
fd_wsample_new( void             * shmem,
                fd_chacha20rng_t * rng,
                ulong            * weights,
                ulong              ele_cnt,
                int                undelete_enabled,
                int                opt_hint ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_wsample_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( ele_cnt>=UINT_MAX ) ) {
    FD_LOG_WARNING(( "ele_cnt too large" ));
    return NULL;
  }

  fd_wsample_t * tree = (fd_wsample_t *)shmem;
  tree->total_weight      = 0UL;
  tree->undeleted_cnt     = ele_cnt;
  tree->undeleted_weight  = 0UL;
  tree->undelete_enabled  = undelete_enabled;
  tree->rng               = rng;

  treap_join( treap_new( (void *)tree->treap, ele_cnt ) );
  /* Invariant: treap_ele_max( tree->treap ) is always the value of
     ele_cnt passed to _new. */

  if( FD_UNLIKELY( ele_cnt==0UL ) ) return shmem;

  treap_ele_t * pool = tree->pool;

  /* 100 is fine as a starting prio.  See note above. */
  if( opt_hint==FD_WSAMPLE_HINT_POWERLAW_NODELETE ) seed_recursive( pool, 1U, (uint)ele_cnt, 100U               );
  else                                              treap_seed    ( pool,           ele_cnt, ele_cnt^0xBADF00DU );

  ulong weight_sum = 0UL;
  for( ulong i=0UL; i<ele_cnt; i++ ) {
    ulong w = weights[i];

    if( FD_UNLIKELY( w==0UL ) ) {
      FD_LOG_WARNING(( "zero weight entry found" ));
      return NULL;
    }
    if( FD_UNLIKELY( weight_sum+w<w ) ) {
      FD_LOG_WARNING(( "total weight too large" ));
      return NULL;
    }

    weight_sum    += w;
    pool[i].weight = w;
    treap_idx_insert( tree->treap, i, pool );
  }

  /* Populate left_sum values */

  ulong nodesum = 0UL; /* Tracks sum of current node and all its children */

  /* The algorithm to populate left_sum is a lot easier to think about
     recursively, but this simple policy calculates everything iteratively:
     When we traverse a parent->child link, we reset nodesum=0.
     When we traverse a left-child  -> parent link, we copy nodesum to
         the parent's left_sum.
     When we traverse a right-child -> parent link, we increase nodesum
         by the parent's left_sum and weight.
     If a node does not have a right child, increase nodesum by that
         node's weight.

     Traverse each link in both directions in the normal order. */
  uint i = (uint)treap_idx_null();
  uint j = tree->treap->root;
  /* Start from left-most node */
  while( FD_LIKELY( !treap_idx_is_null( j ) ) ) { i = j; j = pool[ j ].left; }
  pool[ i ].left_sum = 0UL; /* No left child, so left_sum==0 */

  for(;;) {
    uint r = pool[ i ].right;

    if( treap_idx_is_null( r ) ) { /* No right child */
      nodesum += pool[ i ].weight;
      uint p = pool[ i ].parent;
      while( !treap_idx_is_null( p ) ) {
        if( i==pool[ p ].left ) {
          /* left child -> parent */
          pool[ p ].left_sum = nodesum;
          break;
        }
        /* right child -> parent */
        i = p;
        nodesum += pool[i].left_sum + pool[i].weight;
        p = pool[ p ].parent;
      }
      if( treap_idx_is_null( p ) ) break; /* Back at the root */

      i = p;
      continue;
    }

    nodesum = 0UL;

    i = r;
    for(;;) {
      uint l = pool[ i ].left;
      if( treap_idx_is_null( l ) ) { pool[i].left_sum = 0UL; break; }
      i = l;
    }
  }

  tree->total_weight     = nodesum;
  tree->undeleted_weight = nodesum;

  if( undelete_enabled ) {
    /* Copy the tree to make undelete fast. */
    fd_memcpy( pool+ele_cnt, pool, ele_cnt*sizeof(treap_ele_t) );
  }

  return (void *)tree;
}

void *
fd_wsample_leave( fd_wsample_t * tree ) {
  if( FD_UNLIKELY( !tree ) ) {
    FD_LOG_WARNING(( "NULL tree" ));
    return NULL;
  }

  return (void *)tree;
}

void *
fd_wsample_delete( void * shmem  ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_wsample_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  return shmem;
}



fd_chacha20rng_t * fd_wsample_get_rng( fd_wsample_t * tree ) { return tree->rng; }


/* TODO: Should this function exist at all? */
void
fd_wsample_seed_rng( fd_chacha20rng_t * rng,
                     uchar seed[static 32] ) {
  fd_chacha20rng_init( rng, seed );
}


fd_wsample_t *
fd_wsample_undelete_all( fd_wsample_t * tree ) {
  if( FD_UNLIKELY( !tree->undelete_enabled ) )  return NULL;

  ulong ele_cnt = treap_ele_max( tree->treap );
  tree->undeleted_weight = tree->total_weight;
  tree->undeleted_cnt    = ele_cnt;

  fd_memcpy( tree->pool, tree->pool + ele_cnt, ele_cnt*sizeof(treap_ele_t) );
  return tree;
}

/* Helper methods for sampling functions */
uint
//static inline uint
fd_wsample_map_sample( fd_wsample_t * tree,
                       ulong         query ) {
  treap_ele_t * pool = tree->pool;
  uint          root = tree->treap->root;
  for(;;) {
    if( FD_LIKELY( query < pool[root].left_sum ) ) root = pool[root].left;
    else {
      query -= pool[root].left_sum;
      if( FD_UNLIKELY( query<pool[root].weight ) ) return root;
      query -= pool[root].weight;
      root = pool[root].right;
    }
  }
}


static inline void
fd_stake_weight_remove( fd_wsample_t * tree,
                        uint idx ) {
  /* TODO: Actually remove the node from the treap so that it doesn't
     get junked up with a bunch of zero-weight nodes. */
  treap_ele_t * pool = tree->pool;

  ulong weight = pool[idx].weight;
  pool[idx].weight = 0UL;

  uint i = idx;
  uint p = pool[i].parent;

  while( !treap_idx_is_null( p ) ) {
    if( pool[p].left==i ) pool[p].left_sum -= weight;
    i = p;
    p = pool[p].parent;
  }

  tree->undeleted_cnt--;
  tree->undeleted_weight -= weight;
}

/* For now, implement the _many functions as loops over the single
   sample functions.  It is possible to do better though. */

void
fd_wsample_sample_many( fd_wsample_t * tree,
                        ulong        * idxs,
                        ulong          cnt  ) {
  for( ulong i=0UL; i<cnt; i++ ) idxs[i] = fd_wsample_sample( tree );
}

void
fd_wsample_sample_and_delete_many( fd_wsample_t * tree,
                                   ulong        * idxs,
                                   ulong          cnt   ) {
  for( ulong i=0UL; i<cnt; i++ ) idxs[i] = fd_wsample_sample_and_delete( tree );
}



ulong
fd_wsample_sample( fd_wsample_t * tree ) {
  if( FD_UNLIKELY( !tree->undeleted_weight ) ) return FD_WSAMPLE_EMPTY;
  ulong unif = fd_chacha20rng_ulong_roll( tree->rng, tree->undeleted_weight );
  return (ulong)fd_wsample_map_sample( tree, unif );
}

ulong
fd_wsample_sample_and_delete( fd_wsample_t * tree ) {
  if( FD_UNLIKELY( !tree->undeleted_weight ) ) return FD_WSAMPLE_EMPTY;
  ulong unif = fd_chacha20rng_ulong_roll( tree->rng, tree->undeleted_weight );
  uint idx = fd_wsample_map_sample( tree, unif );
  fd_stake_weight_remove( tree, idx );
  return (ulong)idx;
}
