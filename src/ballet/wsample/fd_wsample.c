#include "fd_wsample.h"
#include <math.h> /* For sqrt */
#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
#endif

#define R 9
/* This sampling problem is an interesting one from a performance
   perspective.  There are lots of interesting approaches.  The
   header/implementation split is designed to give lots of flexibility
   for future optimization.  The current implementation uses radix 9
   tree with all the leaves on the bottom. */

/* I'm not sure exactly how to classify the tree that this
   implementation uses, but it's something like a B-tree with some
   tricks from binary heaps.  In particular, like a B-tree, each node
   stores several keys, where the keys are the cumulative sums of
   subtrees, called left sums below.  Like a binary heap, it is
   pointer-free, and it is stored implicitly in a flat array.  the
   typical way that a binary heap is stored.  Specifically, the root is
   at index 0, and node i's children are at Ri+1, Ri+2, ... Ri+R, where
   R is the radix.  The leaves are all at the same level, at the bottom,
   stored implicitly, which means that a search can be done with almost
   no branch mispredictions.

   As an example, suppose R=5 and our tree contains weights 100, 80, 50,
   31, 27, 14, and 6.  Because that is 7 nodes, the height is set to
   ceil(log_5(7))=2.

                          Root (0)
                          /        \
                   Child (1)      Child (2)     -- -- --
               /  /   |  \   \     |  \
            100, 80, 50, 31, 27   14, 6

   The first child of the root, node 1, has left_sum values
   |100|180|230|261|.  Note that we only store R-1 values, and so the
   last child, 27, does not feature in the sums; the search process
   handles it implicitly, as we'll see.  The second child of the root,
   node 2, has left sum values |14|20|20|20|.  Then the root node, node
   0, has left sum values |288|308|308|308|.

   The total sum is 308, so we start by drawing a random values in the
   range [0, 308).  We see which child that falls under, adjust our
   random value, and repeat, until we reach a leaf.

   In general, if a node has children (left to right) with subtree
   weights a, b, c, d, e.  Then the left sums are |a|a+b|a+b+c|a+b+c+d|
   and the full sum S=a+b+c+d+e.  For a query value of x in [0, S), we
   want to pick:
      child 0   if             x < a
      child 1   if   a      <= x < a+b
      child 2   if   a+b    <= x < a+b+c
      child 3   if   a+b+c  <= x < a+b+c+d
      child 4   if   a+b+c+d<= x

   Which is equivalent to choosing child
          (a<=x) + (a+b<=x) + (a+b+c<=x) + (a+b+c+d<=x)
   which can be computed branchlessly.  The value of e only comes into
   play in the restriction that x is in [0, S), and e is inlcuded in the
   value of S.

   There are two details left to discuss in order to search recursively.
   First, in order to remove an element for sampling without
   replacement, we need to know the weight of the element we're
   removing.  As with e above, the weights may not be stored explicitly,
   but as long as we keep track of the weight of the current subtree as
   we search recursively, we can obtain the weight without much work.
   Thus, we need to know the sum S' of the chosen subtree, i in [0, R).
   For j in [-1, R), define
                            /  0             if j==-1
                    l[j] =  | left_sum[ j ]  if j in [0, R-1)
                            \  S             if j==R-1
   Essentially, we're computing the natural extension values for
   left_sum on the left and right side.  Then observe that S' = l[i] -
   l[i-1].

   Secondly, in order to search recursively, we need to adjust the query
   value to put it into [0, S').  Specifically, we need to subtract off
   the sum of all the children to the left of the child we've chosen.
   If we've chosen child i, then that's just l[i-1].

   All the above extends easily to any radix, but 3, 5, and 9 = 1+2^n
   are the natural ones.  I only tried 5 and 9, and 9 was substantially
   faster.

   It's worth noting that storing left sums means that you have to do
   the most work when you update the left-most child.  Because we
   typically store the weights largest to smallest, the left-most child
   is the one we delete the most frequently, so now our most common case
   (probability-wise) and our worst case (performance-wise) are the
   same, which seems bad.  I initially implemented this using right sums
   instead of left to address this problem.  They're less intuitive, but
   also work.  However, I found that having an unpredictable loop in the
   deletion method was far worse than just updating each element, which
   means that the "less work" advantage of right sums went away. */

struct __attribute__((aligned(8UL*(R-1UL)))) tree_ele {
  /* left_sum stores the cumulative weight of the subtrees at this
     node.  See the long note above for more information. */
  ulong left_sum[ R-1 ];
};
typedef struct tree_ele tree_ele_t;

struct __attribute__((aligned(64UL))) fd_wsample_private {
  ulong              total_cnt;
  ulong              total_weight;
  ulong              unremoved_cnt;
  ulong              unremoved_weight; /* Initial value for S explained above */

  /* internal_node_cnt and height are both determined by the number of
     leaves in the original tree, via the following formulas:
     height = ceil(log_r(leaf_cnt))
     internal_node_cnt = sum_{i=0}^{height-1} R^i
     height and internal_node_cnt both exclude the leaves, which are
     only implicit.

     All the math seems to disallow leaf_cnt==0, but for conveniece, we
     do allow it. height==internal_node_cnt==0 in that case. */
  ulong              internal_node_cnt;
  ulong              height;
  int                restore_enabled;

  /* 4 bytes of padding here */
  fd_chacha20rng_t * rng;

  /* tree: Here's where the actual tree is stored, at indices [0,
     internal_node_cnt).  The indexing scheme is explained in the long
     comment above.

     If restore_enabled==1, then indices [internal_node_cnt+1,
     2*internal_node_cnt+1) store a copy of the tree after construction
     but before any deletion so that restoring deleted elements can be
     implemented as a memcpy.

     The tree iteself is surrounded by two dummy elements, dummy, and
     tree[internal_node_cnt], that aren't actually used.  This is
     because searching the tree branchlessly involves some out of bounds
     reads, and although the value is immediately discarded, it's better
     to know where exactly those reads might go. */
  tree_ele_t        dummy;
  tree_ele_t        tree[];
};

typedef struct fd_wsample_private fd_wsample_t;


FD_FN_CONST ulong
fd_wsample_align( void ) {
  return 64UL;
}

/* Returns -1 on failure */
static inline int
compute_height( ulong   leaf_cnt,
                ulong * out_height,
                ulong * out_internal_cnt ) {
  /* This max is a bit conservative.  The actual max is height <= 25,
     and leaf_cnt < 5^25 approx 2^58.  A tree that large would take an
     astronomical amount of memory, so we just retain this max for the
     moment. */
  if( FD_UNLIKELY( leaf_cnt >= UINT_MAX ) ) return -1;

  ulong height   = 0;
  ulong internal = 0UL;
  ulong powRh    = 1UL; /* = R^height */
  while( leaf_cnt>powRh ) {
    internal += powRh;
    powRh    *= R;
    height++;
  }
  *out_height       = height;
  *out_internal_cnt = internal;
  return 0;
}

FD_FN_CONST ulong
fd_wsample_footprint( ulong ele_cnt, int restore_enabled ) {
  ulong height;
  ulong internal_cnt;
  /* Computing the closed form of the sum in compute_height, we get
     internal_cnt = 1/8 * (9^ceil(log_9( ele_cnt ) ) - 1)
                 x <= ceil( x ) < x+1
     1/8 * ele_cnt - 1/8 <= internal_cnt < 9/8 * ele_cnt - 1/8
  */
  if( FD_UNLIKELY( compute_height( ele_cnt, &height, &internal_cnt ) ) ) return 0UL;
  return sizeof(fd_wsample_t) + ((restore_enabled?2UL:1UL)*internal_cnt + 1UL)*sizeof(tree_ele_t);
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

/* Note: The following optimization insights are not used in this
   high radix implmentation.  Performance in the deletion case is much
   more important than in the non-deletion case, and it's not clear how
   to translate this.  I'm leaving the code and comment because it is a
   useful and non-trivial insight. */
#if 0
/* If we assume the probability of querying node i is proportional to
   1/i, then observe that the midpoint of the probability mass in the
   continuous approximation is the solution to (in Mathematica syntax):

        Integrate[ 1/i, {i, lo, hi}] = 2*Integrate[ 1/i, {i, lo, mid} ]

   which gives mid = sqrt(lo*hi).  This is in contrast to when the
   integrand is a constant, which gives the normal binary search rule:
   mid=(lo+hi)/2.

   Thus, we want the search to follow this modified binary search rule,
   since that'll approximately split the stake weight/probability mass
   in half at each step.

   This is almost as nice to work with mathematically as the normal
   binary search rule.  The jth entry from the left at level k is the
   region [ N^((1/2^k)*j), N^((1/2^k)*(j+1)) ).  We're basically doing
   binary search in the log domain.

   Rather than trying to compute these transcendental functions, this
   simple recursive implementation gives the treap the right shape by
   setting prio very carefully, since higher prio means closer to the
   root.  This may be a slight abuse of a treap, but it's easier than
   implementing a whole custom tree for just this purpose.

   We want to be careful to ensure that the recursion is tightly
   bounded.  From a continuous perspective, that's not a problem: the
   widest interval at level k is the last one, and we break when the
   interval's width is less than 1.  Solving 1=N-N^(1-(1/2^k)) for k
   yields k=-lg(1-log(N-1)/log(N)).  k is monotonically increasing as a
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
#endif


void *
fd_wsample_new_init( void             * shmem,
                     fd_chacha20rng_t * rng,
                     ulong              ele_cnt,
                     int                restore_enabled,
                     int                opt_hint ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_wsample_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong height;
  ulong internal_cnt;
  if( FD_UNLIKELY( compute_height( ele_cnt, &height, &internal_cnt ) ) ) {
    FD_LOG_WARNING(( "bad ele_cnt" ));
    return NULL;
  }

  fd_wsample_t *  sampler = (fd_wsample_t *)shmem;

  sampler->total_weight      = 0UL;
  sampler->unremoved_cnt     = 0UL;
  sampler->unremoved_weight  = 0UL;
  sampler->internal_node_cnt = internal_cnt;
  sampler->height            = height;
  sampler->restore_enabled   = restore_enabled;
  sampler->rng               = rng;

  fd_memset( sampler->tree, (char)0, internal_cnt*sizeof(tree_ele_t) );

  (void)opt_hint; /* Not used at the moment */

  return shmem;
}

void *
fd_wsample_new_add( void * shmem,
                    ulong  weight ) {
  fd_wsample_t *  sampler = (fd_wsample_t *)shmem;
  if( FD_UNLIKELY( !sampler ) ) return NULL;

  if( FD_UNLIKELY( weight==0UL ) ) {
    FD_LOG_WARNING(( "zero weight entry found" ));
    return NULL;
  }
  if( FD_UNLIKELY( sampler->total_weight+weight<weight ) ) {
    FD_LOG_WARNING(( "total weight too large" ));
    return NULL;
  }

  tree_ele_t * tree = sampler->tree;
  ulong i = sampler->internal_node_cnt + sampler->unremoved_cnt;

  for( ulong h=0UL; h<sampler->height; h++ ) {
    ulong parent = (i-1UL)/R;
    ulong child_idx = i-1UL - R*parent; /* in [0, R) */
    for( ulong k=child_idx; k<R-1UL; k++ )  tree[ parent ].left_sum[ k ] += weight;
    i = parent;
  }

  sampler->unremoved_cnt++;
  sampler->total_cnt++;
  sampler->unremoved_weight += weight;
  sampler->total_weight     += weight;

  return shmem;
}

void *
fd_wsample_new_fini( void * shmem ) {
  fd_wsample_t *  sampler = (fd_wsample_t *)shmem;
  if( FD_UNLIKELY( !sampler ) ) return NULL;

  if( sampler->restore_enabled ) {
    /* Copy the sampler to make restore fast. */
    fd_memcpy( sampler->tree+sampler->internal_node_cnt+1UL, sampler->tree, sampler->internal_node_cnt*sizeof(tree_ele_t) );
  }

  return (void *)sampler;
}

void *
fd_wsample_leave( fd_wsample_t * sampler ) {
  if( FD_UNLIKELY( !sampler ) ) {
    FD_LOG_WARNING(( "NULL sampler" ));
    return NULL;
  }

  return (void *)sampler;
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



fd_chacha20rng_t * fd_wsample_get_rng( fd_wsample_t * sampler ) { return sampler->rng; }


/* TODO: Should this function exist at all? */
void
fd_wsample_seed_rng( fd_chacha20rng_t * rng,
                     uchar seed[static 32] ) {
  fd_chacha20rng_init( rng, seed );
}


fd_wsample_t *
fd_wsample_restore_all( fd_wsample_t * sampler ) {
  if( FD_UNLIKELY( !sampler->restore_enabled ) )  return NULL;

  sampler->unremoved_weight = sampler->total_weight;
  sampler->unremoved_cnt    = sampler->total_cnt;

  fd_memcpy( sampler->tree, sampler->tree+sampler->internal_node_cnt+1UL, sampler->internal_node_cnt*sizeof(tree_ele_t) );
  return sampler;
}

#define fd_ulong_if_force( c, t, f ) (__extension__({ \
      ulong result;                                   \
      __asm__( "testl  %1, %1; \n\t"                  \
               "movq   %3, %0; \n\t"                  \
               "cmovne %2, %0; \n\t"                  \
               : "=&r"(result)                        \
               : "r"(c), "rm"(t), "rmi"(f)            \
               : "cc" );                              \
      result;                                         \
      }))

/* Helper methods for sampling functions */
typedef struct { ulong idx; ulong weight; } idxw_pair_t; /* idx in [0, total_cnt) */

/* Assumes query in [0, unremoved_weight), which implies
   unremoved_weight>0, so the tree can't be empty. */
static inline idxw_pair_t
fd_wsample_map_sample_i( fd_wsample_t const * sampler,
                         ulong                query ) {
  tree_ele_t const * tree = sampler->tree;

  ulong cursor = 0UL;
  ulong S      = sampler->unremoved_weight;
  for( ulong h=0UL; h<sampler->height; h++ ) {
    tree_ele_t const * e = tree+cursor;
    ulong x = query;
    ulong child_idx = 0UL;

#if FD_HAS_AVX512 && R==9
    __mmask8 mask = _mm512_cmple_epu64_mask( wwv_ld( e->left_sum ), wwv_bcast( x ) );
    child_idx = (ulong)fd_uchar_popcnt( mask );
#else
    for( ulong i=0UL; i<R-1UL; i++ ) child_idx += (ulong)(e->left_sum[ i ]<=x);
#endif

    /* See the note at the top of this file for the explanation of l[i]
       and l[i-1].  Because this is fd_ulong_if and not a ternary, these
       can read/write out of what you would think the appropriate bounds
       are.  The dummy elements, as described along with tree makes this
       safe. */
#if 0
    ulong li  = fd_ulong_if( child_idx<R-1UL, e->left_sum[ child_idx     ], S   );
    ulong lm1 = fd_ulong_if( child_idx>0UL,   e->left_sum[ child_idx-1UL ], 0UL );
#elif 0
    ulong li  = fd_ulong_if_force( child_idx<R-1UL, e->left_sum[ child_idx     ], S   );
    ulong lm1 = fd_ulong_if_force( child_idx>0UL,   e->left_sum[ child_idx-1UL ], 0UL );
#else
    ulong * temp = (ulong *)e->left_sum;
    ulong orig_m1 = temp[ -1 ];    ulong orig_Rm1 = temp[ R-1UL ];
    temp[ -1 ] = 0UL;              temp[ R-1UL ] = S;
    ulong li  = temp[ child_idx     ];
    ulong lm1 = temp[ child_idx-1UL ];
    temp[ -1 ] = orig_m1;          temp[ R-1UL ] = orig_Rm1;
#endif

    query -= lm1;
    S = li - lm1;
    cursor = R*cursor + child_idx + 1UL;
  }
  idxw_pair_t to_return = { .idx = cursor - sampler->internal_node_cnt, .weight = S };
  return to_return;
}

ulong
fd_wsample_map_sample( fd_wsample_t * sampler,
                       ulong          query ) {
  return fd_wsample_map_sample_i( sampler, query ).idx;
}



/* Also requires the tree to be non-empty */
static inline void
fd_wsample_remove( fd_wsample_t * sampler,
                   idxw_pair_t    to_remove ) {
  ulong cursor = to_remove.idx + sampler->internal_node_cnt;
  tree_ele_t * tree = sampler->tree;

  for( ulong h=0UL; h<sampler->height; h++ ) {
    ulong parent = (cursor-1UL)/R;
    ulong child_idx = cursor-1UL - R*parent; /* in [0, R) */
#if FD_HAS_AVX512 && R==9
    wwv_t weight = wwv_bcast( to_remove.weight );
    wwv_t left_sum = wwv_ld( tree[ parent ].left_sum );
    __m128i _child_idx = _mm_set1_epi16( (short) child_idx );
    __mmask8 mask = _mm_cmplt_epi16_mask( _child_idx, _mm_setr_epi16( 1, 2, 3, 4, 5, 6, 7, 8 ) );
    left_sum = _mm512_mask_sub_epi64( left_sum, mask, left_sum, weight );
    wwv_st( tree[ parent ].left_sum, left_sum );
#elif 0
    for( ulong k=0UL; k<R-1UL; k++ ) tree[ parent ].left_sum[ k ] -= fd_ulong_if( child_idx<=k, to_remove.weight, 0UL );
#elif 0
    for( ulong k=0UL; k<R-1UL; k++ ) tree[ parent ].left_sum[ k ] -= fd_ulong_if_force( child_idx<=k, to_remove.weight, 0UL );
#elif 1
    /* The compiler loves inserting a difficult to predict branch for
       fd_ulong_if, but this forces it not to do that. */
    for( ulong k=0UL; k<R-1UL; k++ ) tree[ parent ].left_sum[ k ] -= (ulong)(((long)(child_idx - k - 1UL))>>63) & to_remove.weight;
#else
    /* This version does the least work, but has a hard-to-predict
       branch.  The branchless versions are normally substantially
       faster. */
    for( ulong k=child_idx; k<R-1UL; k++ )  tree[ parent ].left_sum[ k ] -= to_remove.weight;
#endif
    cursor = parent;
  }
  sampler->unremoved_cnt--;
  sampler->unremoved_weight -= to_remove.weight;
}

static inline ulong
fd_wsample_find_weight( fd_wsample_t const * sampler,
                        ulong                idx /* in [0, total_cnt) */) {
  /* The fact we don't store the weights explicitly makes this function
     more complicated, but this is not used very frequently. */
  tree_ele_t const * tree = sampler->tree;
  ulong cursor = idx + sampler->internal_node_cnt;

  /* Initialize to the 0 height case */
  ulong lm1 = 0UL;
  ulong li  = sampler->unremoved_weight;

  for( ulong h=0UL; h<sampler->height; h++ ) {
    ulong parent = (cursor-1UL)/R;
    ulong child_idx = cursor-1UL - R*parent; /* in [0, R) */

    /* If child_idx < R-1, we can compute the weight easily.  If
       child_idx==R-1, the computation is S - left_sum[ R-2 ], but we
       don't know S, so we need to continue up the tree. */
    lm1  += fd_ulong_if( child_idx>0UL, tree[ parent ].left_sum[ child_idx-1UL ], 0UL );
    if( FD_LIKELY( child_idx<R-1UL ) ) {
      li = tree[ parent ].left_sum[ child_idx ];
      break;
    }

    cursor = parent;
  }

  return li - lm1;
}

void
fd_wsample_remove_idx( fd_wsample_t * sampler,
                       ulong          idx ) {

  ulong weight = fd_wsample_find_weight( sampler, idx );
  idxw_pair_t r = { .idx = idx, .weight = weight };
  fd_wsample_remove( sampler, r );
}

/* For now, implement the _many functions as loops over the single
   sample functions.  It is possible to do better though. */

void
fd_wsample_sample_many( fd_wsample_t * sampler,
                        ulong        * idxs,
                        ulong          cnt  ) {
  for( ulong i=0UL; i<cnt; i++ ) idxs[i] = fd_wsample_sample( sampler );
}

void
fd_wsample_sample_and_remove_many( fd_wsample_t * sampler,
                                   ulong        * idxs,
                                   ulong          cnt   ) {
  /* The compiler doesn't seem to like inlining the call to
     fd_wsample_sample_and_remove, which hurts performance by a few
     percent because it triggers worse behavior in the CPUs front end.
     To address this, we manually inline it here. */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !sampler->unremoved_weight ) ) { idxs[ i ] = FD_WSAMPLE_EMPTY; continue; }
    ulong unif = fd_chacha20rng_ulong_roll( sampler->rng, sampler->unremoved_weight );
    idxw_pair_t p = fd_wsample_map_sample_i( sampler, unif );
    fd_wsample_remove( sampler, p );
    idxs[ i ] = p.idx;
  }
}



ulong
fd_wsample_sample( fd_wsample_t * sampler ) {
  if( FD_UNLIKELY( !sampler->unremoved_weight ) ) return FD_WSAMPLE_EMPTY;
  ulong unif = fd_chacha20rng_ulong_roll( sampler->rng, sampler->unremoved_weight );
  return (ulong)fd_wsample_map_sample( sampler, unif );
}

ulong
fd_wsample_sample_and_remove( fd_wsample_t * sampler ) {
  if( FD_UNLIKELY( !sampler->unremoved_weight ) ) return FD_WSAMPLE_EMPTY;
  ulong unif = fd_chacha20rng_ulong_roll( sampler->rng, sampler->unremoved_weight );
  idxw_pair_t p = fd_wsample_map_sample_i( sampler, unif );
  fd_wsample_remove( sampler, p );
  return p.idx;
}
