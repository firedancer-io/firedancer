/* Declares a family of functions useful for single threaded sorting of
   POD types in high performance contexts.  Example usage:

     #define SORT_NAME        sort_double_descend
     #define SORT_KEY_T       double
     #define SORT_BEFORE(a,b) (a)>(b)
     #include "util/tmpl/fd_sort.c"

   will create the following API for use in the local compile unit:

     // Sort key[i] for i in [0,cnt) stable in place in a best / average
     // worst case of O(N) / O(N^2) / O(N^2) operations.

     double *
     sort_double_descend_insert( double * key,
                                 ulong    cnt );

     // Return 1 if cnt is a sensible value for the stable sorting APIs
     // (i.e. cnt*sizeof(double)+alignof(double)-1 will not overflow).

     int sort_double_descend_stable_cnt_valid( ulong cnt );

     // Return the alignment and footprint required for a scratch region
     // adequate for sorting up to cnt elements.  The results will be
     // standard allocator and standard declaration friendly.  (E.g. a
     // declaration "double scratch[ cnt ];" will be fine as a scratch
     // region.)

     ulong sort_double_descend_stable_scratch_align    ( void      );
     ulong sort_double_descend_stable_scratch_footprint( ulong cnt );

     // Sort key[i] for i in [0,cnt) stable in best / average / worst
     // case of O(N lg N) / O(N lg N) / O(N lg N) operations.  Scratch
     // is a scratch workspace of suitable alignment and footprint.
     // Returns where the sorted values ended up.  Will be at either key
     // or (double *)scratch.

     double *
     sort_double_descend_stable_fast( double * key,
                                      ulong    cnt,
                                      void   * scratch );

     // Same as above but does additional copying if necessary such that
     // the final result ends up in key.  Returns key.

     double *
     sort_double_descend_stable( double * key,
                                 ulong    cnt,
                                 void *   scratch );

     // Sort key[i] for i in [0,cnt) inplace in best / average / worst
     // case of O(N lg N) / O(N lg N) / O(N^2) operations.  Returns key.

     double *
     sort_double_inplace( double * key,
                          ulong    cnt );

     // Partially sort key[i] such that key[rnk] holds rnk and return
     // key[rnk] in best / average / worst of O(N) / O(N) / O(N^2)
     // operations.  Returns key.  Assumes key is non-NULL, cnt is valid
     // and positive and rnk is in [0,cnt)

     double *
     sort_double_select( double * key,
                         ulong    cnt,
                         ulong    rnk );

     // Binary search for element equal-or-greater than key in a sorted
     // list.  Return value is an index into sorted in [0,cnt].  If
     // return value > 0 then it is the largest index where
     // SORT_BEFORE(sorted[index-1],query)==1.   Returns 0 if
     // SORT_BEFORE(query,elem)==1 for all elements in sorted.  Assumes
     // SORT_BEFORE defines a total order over sorted, and each element
     // in sorted is less-or-equal than its successor.  (Returns
     // incorrect result otherwise!)   Robust if cnt==0 (in that case,
     // returns 0 and ignores pointer to sorted).

     ulong
     sort_double_search_geq( double const * sorted,
                             ulong          cnt,
                             double         query );

   It is fine to include this template multiple times in a compilation
   unit.  Just provide the specification before each inclusion.  Various
   additional options to tune the methods are described below. */

#include "../bits/fd_bits.h"

/* SORT_NAME gives the name of the function to declare (and the base
   name of auxiliary and/or variant functions). */

#ifndef SORT_NAME
#error "SORT_NAME must be defined"
#endif

/* SORT_KEY_T gives the POD datatype to sort. */

#ifndef SORT_KEY_T
#error "SORT_KEY_T must be defined"
#endif

/* SORT_IDX_T gives the data type used to index the arrays */

#ifndef SORT_IDX_T
#define SORT_IDX_T ulong
#endif

/* SORT_BEFORE(a,b) evaluates to 1 if a<b is strictly true.  SAFETY TIP:
   This is not a 3-way comparison function! */

#ifndef SORT_BEFORE
#define SORT_BEFORE(a,b) (a)<(b)
#endif

/* SORT_MERGE_THRESH / SORT_QUICK_THRESH give largest merge/quick
   partition size where insertion sort will be used.  Should be at least
   2 (and probably larger than one might expect to get optimal
   performance). */

#ifndef SORT_MERGE_THRESH
#define SORT_MERGE_THRESH 32
#endif

#ifndef SORT_QUICK_THRESH
#define SORT_QUICK_THRESH 32
#endif

/* SORT_QUICK_ORDER_STYLE selects the method used for ordering two keys.
   Roughly, say 1 for floating point keys (see quick method for
   details). */

#ifndef SORT_QUICK_ORDER_STYLE
#define SORT_QUICK_ORDER_STYLE 0
#endif

/* SORT_QUICK_SWAP_MINIMIZE indicates that quick sort should eat the
   non-deterministic branch cost to avoid no-op swaps.  This is useful
   if the key_t has a large memory footprint such that the no-op is
   actually a larger cost than a branch mispredict. */

#ifndef SORT_QUICK_SWAP_MINIMIZE
#define SORT_QUICK_SWAP_MINIMIZE 0
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef SORT_IMPL_STYLE
#define SORT_IMPL_STYLE 0
#endif

/* SORT_IDX_IF(c,t,f) returns sort_idx t if c is non-zero and sort_idx f o.w. */

#ifndef SORT_IDX_IF
#define SORT_IDX_IF(c,t,f) ((SORT_IDX_T)fd_ulong_if( (c), (ulong)(t), (ulong)(f) ))
#endif

/**********************************************************************/

#define SORT_(x)FD_EXPAND_THEN_CONCAT3(SORT_NAME,_,x)

#if SORT_IMPL_STYLE==1 /* need prototypes */

SORT_KEY_T *
SORT_(private_merge)( SORT_KEY_T * key,
                      SORT_IDX_T   cnt,
                      SORT_KEY_T * tmp );

SORT_KEY_T *
SORT_(private_quick)( SORT_KEY_T * key,
                      SORT_IDX_T   cnt );

SORT_KEY_T *
SORT_(private_select)( SORT_KEY_T * key,
                       SORT_IDX_T   cnt,
                       SORT_IDX_T   rnk );

#else /* need implementations */

#if SORT_IMPL_STYLE==0 /* local only */
#define SORT_IMPL_STATIC static
#else
#define SORT_IMPL_STATIC
#endif

static SORT_KEY_T *
SORT_(insert)( SORT_KEY_T * key,
               SORT_IDX_T   cnt ) {
  for( SORT_IDX_T i=((SORT_IDX_T)1); i<cnt; i++ ) {
    SORT_KEY_T key_i = key[i];
    SORT_IDX_T j = i;
    while( j ) {
      SORT_IDX_T k = j - ((SORT_IDX_T)1);
      SORT_KEY_T key_j = key[k]; if( !(SORT_BEFORE( key_i, key_j )) ) break;
      key[j] = key_j;
      j = k;
    }
    key[j] = key_i;
  }
  return key;
}

/* FIXME: USE IMPLICIT RECURSION ALA QUICK BELOW? */

SORT_IMPL_STATIC SORT_KEY_T *
SORT_(private_merge)( SORT_KEY_T * key,
                      SORT_IDX_T   cnt,
                      SORT_KEY_T * tmp ) {

  /* If below threshold, use insertion sort */

  if( cnt<=((SORT_IDX_T)(SORT_MERGE_THRESH)) ) return SORT_(insert)( key, cnt );

  /* Otherwise, break input in half and sort the halves */

  SORT_KEY_T * key_left  = key;
  SORT_KEY_T * tmp_left  = tmp;
  SORT_IDX_T   cnt_left  = cnt >> 1;
  SORT_KEY_T * out_left  = SORT_(private_merge)( key_left,  cnt_left,  tmp_left  );

  SORT_KEY_T * key_right = key + cnt_left;
  SORT_KEY_T * tmp_right = tmp + cnt_left;
  SORT_IDX_T   cnt_right = cnt - cnt_left;
  SORT_KEY_T * out_right = SORT_(private_merge)( key_right, cnt_right, tmp_right );

  /* Merge out_left / out_right */

  if( out_left==key ) key = tmp; /* If out_left overlaps with key, merge into tmp.  Otherwise, merge into key */

  /* Note that out_left does not overlap with the location for merge
     output at this point.  out_right might overlap (with the right
     half) with the location for merge output but this will still work
     in that case.  */

  SORT_IDX_T i = ((SORT_IDX_T)0);
  SORT_IDX_T j = ((SORT_IDX_T)0);
  SORT_IDX_T k = ((SORT_IDX_T)0);
# if 1 /* Minimal C language operations */
  for(;;) { /* Note that cnt_left>0 and cnt_right>0 as cnt > SORT_MERGE_THRESH >= 1 at this point */
    if( SORT_BEFORE( out_right[k], out_left[j] ) ) {
      key[i++] = out_right[k++];
      if( k>=cnt_right ) {
        do key[i++] = out_left [j++]; while( j<cnt_left  ); /* append left  stragglers (at least one) */
        break;
      }
    } else {
      key[i++] = out_left [j++];
      if( j>=cnt_left  ) {
        do key[i++] = out_right[k++]; while( k<cnt_right ); /* append right stragglers (at least one) */
        break;
      }
    }
  }
# else /* Branch free variant (Pyth investigations suggested the above is better) */
  for(;;) { /* Note that cnt_left>0 and cnt_right>0 as cnt > SORT_MERGE_THRESH >= 1 at this point */
    SORT_KEY_T out_j = out_left [j];
    SORT_KEY_T out_k = out_right[k];
    int from_right = (SORT_BEFORE( out_k, out_j ));
    key[i++] = from_right ? out_k : out_j; FD_COMPILER_FORGET( from_right );
    j += (SORT_IDX_T)(from_right^1);       FD_COMPILER_FORGET( from_right );
    k += (SORT_IDX_T) from_right;
    int c = (j<cnt_left) & (k<cnt_right); FD_COMPILER_FORGET( c ); /* prevent compiler from branch nesting the compares */
    if( !c ) break;
  }
  for( ; j<cnt_left;  j++ ) key[i++] = out_left [j];
  for( ; k<cnt_right; k++ ) key[i++] = out_right[k];
# endif

  return key;
}

/* This uses a dual pivot quick sort for better theoretical and
   practical mojo. */

SORT_IMPL_STATIC SORT_KEY_T *
SORT_(private_quick)( SORT_KEY_T * key,
                      SORT_IDX_T   cnt ) {
  SORT_IDX_T stack[ 4UL*8UL*sizeof(SORT_IDX_T) ]; /* See note below on sizing */
  ulong      stack_cnt = 0UL;

  stack[ stack_cnt++ ] = (SORT_IDX_T)0;
  stack[ stack_cnt++ ] = cnt;
  for(;;) {

    /* Pop the next partition to process */

    if( !stack_cnt ) return key; /* All done */
    SORT_IDX_T h = stack[ --stack_cnt ];
    SORT_IDX_T l = stack[ --stack_cnt ];

    /* [l,h) is the partition we are sorting.  If this partition is
       small enough, sort it via insertion sort. */

    SORT_IDX_T n = h-l;
    if( FD_LIKELY( n <= ((SORT_IDX_T)(SORT_QUICK_THRESH)) ) ) {
      SORT_(insert)( key+l, n );
      continue;
    }

    /* This partition is too large to insertion sort.  Pick two pivots,
       sort the partition into a left, center and right partition and
       then recursively sort those partitions.  We initially use a
       simple choice of pivots that is ideal for nearly sorted data (in
       either direction) with a little extra sampling to improve the
       partitioning for randomly ordered data.  There is a possibility
       that this deterministic choice of pivots will not succeed in
       making two or more non-empty partitions; we detect and correct
       that below. */

    /* Initial pivot selection */

    SORT_KEY_T p1;
    SORT_KEY_T p2;
    do {
      SORT_IDX_T n3 = n / (SORT_IDX_T)3; /* magic multiply under the hood typically */
      SORT_IDX_T h1 = h - (SORT_IDX_T)1;
      SORT_KEY_T p0 = key[ l       ];
      /**/       p1 = key[ l  + n3 ];
      /**/       p2 = key[ h1 - n3 ];
      SORT_KEY_T p3 = key[ h1      ];
#     if SORT_QUICK_ORDER_STYLE==0
      /* Generates better code for integral types (branchless via stack) */
      SORT_KEY_T _k[2]; ulong _c;
#     define ORDER(k0,k1) _k[0] = k0; _k[1] = k1; _c = (ulong)(SORT_BEFORE(k1,k0)); k0 = _k[_c]; k1 = _k[_c^1UL];
#     else
      /* Generates much better code for floating point types (branchless
         via min / max floating point instructions) */
      SORT_KEY_T _k0; SORT_KEY_T _k1; int _c;
#     define ORDER(k0,k1) _c = (SORT_BEFORE(k1,k0)); _k0 = _c ? k1 : k0; _k1 = _c ? k0 : k1; k0 = _k0; k1 = _k1;
#     endif

      ORDER(p0,p2); ORDER(p1,p3);
      ORDER(p0,p1); ORDER(p2,p3);
      ORDER(p1,p2);
#     undef ORDER
    } while(0);

  retry: /* Three way partitioning (silly language restriction) */;
    SORT_IDX_T i = l;
    SORT_IDX_T j = l;
    SORT_IDX_T k = h-(SORT_IDX_T)1;
    do { /* Note [j,k] is non-empty (look ma ... no branches!) */

      /* At this point, p1 <= p2 and:
         - keys [l,i) are before p1 (left partition)
         - keys [i,j) are in [p1,p2] (center partition)
         - keys [j,k] are not yet partitioned (region is non-empty)
         - keys (k,h) are after p2 (right partition)
         Decide where key j should be moved. */

      SORT_KEY_T kj = key[j];

      int to_left  = (SORT_BEFORE( kj, p1 ));
      int to_right = (SORT_BEFORE( p2, kj ));
      SORT_IDX_T m = SORT_IDX_IF( to_right, k, SORT_IDX_IF( to_left, i, j ) );

#     if SORT_QUICK_SWAP_MINIMIZE
      if( FD_LIKELY( j!=h ) ) { key[j] = key[m]; key[m] = kj; } /* ~2/3 prob */
#     else
      /**/                      key[j] = key[m]; key[m] = kj;
#     endif

      i += (SORT_IDX_T) to_left;
      j += (SORT_IDX_T)(to_right^1); /* to_left_or_to_center <=> !to_right */
      k -= (SORT_IDX_T) to_right;
    } while( j<=k );

    /* Schedule recursion */

    if( FD_UNLIKELY( (j-i)==n ) ) {

      /* All the keys ended up in the center partition.  If p1<p2, we
         had an unlucky choice of pivots such that p1==min(key[i]) and
         p2==max(key[i]) for i in [l,h).  Since we picked the keys
         deterministically above, we would have the same bad luck the
         next time we processed this partition.  But, because there are
         at least two distinct elements in the partition, there is a
         choice of pivots that will make a non-trivial partition, so we
         need to redo this partition with different pivots.

         Randomly picking a new pivot pair in [l,h) has probability
         between ~50% and ~100%.  The worst case is half the keys in
         the partition equal to p1 and the other half equal to p2; the
         best case exactly one key is equal to p1 / p2 and all other
         keys are in (p1,p2] / [p1,p2).

         The optimal handling of the worst case though is just to set
         p1=p2 (p2=p1).  This will pull the keys equal to p1 (p2) into
         the left (right) partition and the remaining keys into the
         center partition; the right (left) partition will be empty.
         Thus, this is guaranteed to yield a non-trivial partition of
         the center partition but may not yield as load balanced set of
         partitions as random for the next iteration.  We go with the
         deterministic option for simplicity below. */

      if( FD_UNLIKELY( (SORT_BEFORE( p1, p2 )) ) ) { p1 = p2; goto retry; }

      /* p1==p2 here ... all keys in this partition are the same
         We don't need to recurse further in this partition. */

    } else {

      /* Between [1,n-1] keys ended up in the center partition such that
         at least 1 key ended up in another partition.  We push all
         three partitions onto the partition stack for recursion.  The
         order of the pushes is important to bound the maximum stack
         usage.  Below, we push the center partition followed by the
         larger of the left and right partitions then followed by the
         smaller of the left and right partitions (such that we process
         the smallest next iteration).  For this, the same O(log_2 cnt)
         max recursion depth applies as quicksort even this does a three
         way partitioning.  That is, let fl/fc/fr be the fraction of
         keys in the left, center, right partitions.  At this point, fl
         is in [0,1), fc is in (0,1) and fr is in [0,1) and fl+fc+fr=1.
         The smaller of the left or right partition is what process next
         and, as the smaller of the left or right, it fraction of the
         keys is at most 0.5(1-fc)<=0.5.  We do push up to two
         partitions onto the stack (four SORT_IDX_T) each level of
         recursion though instead of one like normal quick sort though. */

      int left_larger = (i-l) > (h-j); /* True if the left partition should go on the stack */
      SORT_IDX_T l_larger  = SORT_IDX_IF( left_larger, l, j );
      SORT_IDX_T h_larger  = SORT_IDX_IF( left_larger, i, h );
      SORT_IDX_T l_smaller = SORT_IDX_IF( left_larger, j, l );
      SORT_IDX_T h_smaller = SORT_IDX_IF( left_larger, h, i );

      /* Immediately process empty partitions */
      ulong push_smaller = (ulong)(l_smaller<h_smaller); FD_COMPILER_FORGET( push_smaller );

      /* Immediately process partitions where all keys are the same */
      ulong push_center  = (ulong)(SORT_BEFORE( p1, p2 )); FD_COMPILER_FORGET( push_center );

      /* Guaranteed non-empty (larger of left or right have at least 1 key) */
      ulong push_larger  = 1UL;

      stack[ stack_cnt ] = l_larger;  stack_cnt += push_larger;
      stack[ stack_cnt ] = h_larger;  stack_cnt += push_larger;
      stack[ stack_cnt ] = i;         stack_cnt += push_center;
      stack[ stack_cnt ] = j;         stack_cnt += push_center;
      stack[ stack_cnt ] = l_smaller; stack_cnt += push_smaller;
      stack[ stack_cnt ] = h_smaller; stack_cnt += push_smaller;
    }
  }
  /* never get here */
}

SORT_IMPL_STATIC SORT_KEY_T *
SORT_(private_select)( SORT_KEY_T * key,
                       SORT_IDX_T   cnt,
                       SORT_IDX_T   rnk ) {
  SORT_IDX_T l = (SORT_IDX_T)0;
  SORT_IDX_T h = cnt;
  for(;;) {

    /* The partition [l,h) contains rnk.  If this partition is small
       enough, sort it via insertion sort. */

    SORT_IDX_T n = h-l;
    if( FD_LIKELY( n <= ((SORT_IDX_T)(SORT_QUICK_THRESH)) ) ) { SORT_(insert)( key+l, n ); return key; }

    /* This partition is too large to insertion sort.  Pick two pivots,
       sort the partition into a left, center and right partition and
       then recursive on the partition holding rnk.  We initially use a
       simple choice of pivots that is ideal for nearly sorted data (in
       either direction) with a little extra sampling to improve the
       partitioning for randomly ordered data.  There is a possibility
       that this deterministic choice of pivots will not succeed in
       making two or more non-empty partitions; we detect and correct
       that below. */

    /* Initial pivot selection */

    SORT_KEY_T p1;
    SORT_KEY_T p2;
    do {
      SORT_IDX_T n3 = n / (SORT_IDX_T)3; /* magic multiply under the hood typically */
      SORT_IDX_T h1 = h - (SORT_IDX_T)1;
      SORT_KEY_T p0 = key[ l       ];
      /**/       p1 = key[ l  + n3 ];
      /**/       p2 = key[ h1 - n3 ];
      SORT_KEY_T p3 = key[ h1      ];
#     if SORT_QUICK_ORDER_STYLE==0
      /* Generates better code for integral types (branchless via stack) */
      SORT_KEY_T _k[2]; ulong _c;
#     define ORDER(k0,k1) _k[0] = k0; _k[1] = k1; _c = (ulong)(SORT_BEFORE(k1,k0)); k0 = _k[_c]; k1 = _k[_c^1UL];
#     else
      /* Generates much better code for floating point types (branchless
         via min / max floating point instructions) */
      SORT_KEY_T _k0; SORT_KEY_T _k1; int _c;
#     define ORDER(k0,k1) _c = (SORT_BEFORE(k1,k0)); _k0 = _c ? k1 : k0; _k1 = _c ? k0 : k1; k0 = _k0; k1 = _k1;
#     endif

      ORDER(p0,p2); ORDER(p1,p3);
      ORDER(p0,p1); ORDER(p2,p3);
      ORDER(p1,p2);
#     undef ORDER
    } while(0);

  retry: /* Three way partitioning (silly language restriction) */;
    SORT_IDX_T i = l;
    SORT_IDX_T j = l;
    SORT_IDX_T k = h-(SORT_IDX_T)1;
    do { /* Note [j,k] is non-empty (look ma ... no branches!) */

      /* At this point, p1 <= p2 and:
         - keys [l,i) are before p1 (left partition)
         - keys [i,j) are in [p1,p2] (center partition)
         - keys [j,k] are not yet partitioned (region is non-empty)
         - keys (k,h) are after p2 (right partition)
         Decide where key j should be moved. */

      SORT_KEY_T kj = key[j];

      int to_left  = (SORT_BEFORE( kj, p1 ));
      int to_right = (SORT_BEFORE( p2, kj ));
      SORT_IDX_T m = SORT_IDX_IF( to_right, k, SORT_IDX_IF( to_left, i, j ) );

#     if SORT_QUICK_SWAP_MINIMIZE
      if( FD_LIKELY( j!=h ) ) { key[j] = key[m]; key[m] = kj; } /* ~2/3 prob */
#     else
      /**/                   key[j] = key[m]; key[m] = kj;
#     endif

      i += (SORT_IDX_T) to_left;
      j += (SORT_IDX_T)(to_right^1); /* to_left_or_to_center <=> !to_right */
      k -= (SORT_IDX_T) to_right;
    } while( j<=k );

    if( FD_UNLIKELY( (j-i)==n ) ) {

      /* All the keys ended up in the center partition.  If p1<p2, we
         had an unlucky choice of pivots such that p1==min(key[i]) and
         p2==max(key[i]) for i in [l,h).  Since we picked the keys
         deterministically above, we would have the same bad luck the
         next time we processed this partition.  But, because there are
         at least two distinct elements in the partition, there is a
         choice of pivots that will make a non-trivial partition, so we
         need to redo this partition with different pivots.

         Randomly picking a new pivot pair in [l,h) has probability
         between ~50% and ~100%.  The worst case is half the keys in
         the partition equal to p1 and the other half equal to p2; the
         best case exactly one key is equal to p1 / p2 and all other
         keys are in (p1,p2] / [p1,p2).

         The optimal handling of the worst case though is just to set
         p1=p2 (p2=p1).  This will pull the keys equal to p1 (p2) into
         the left (right) partition and the remaining keys into the
         center partition; the right (left) partition will be empty.
         Thus, this is guaranteed to yield a non-trivial partition of
         the center partition but may not yield as load balanced set of
         partitions as random for the next iteration.  We go with the
         deterministic option for simplicity below. */

      if( FD_UNLIKELY( (SORT_BEFORE( p1, p2 )) ) ) { p1 = p2; goto retry; }

      /* p1==p2 here ... all keys in this partition are the same.  We
         don't need to recurse further in this partition as all keys
         would do here. */

      return key;
    }

    /* At this point:
       - [l,i) is the left partition,
       - [i,j) is the center partition
       - [j,h) is the right partition
       Between [1,n-1] keys ended up in the center partition such that
       at least 1 key ended up in another partition.  Recurse on the
       partition that contains rnk.  As this is typically used in median
       finding, we assume that the center partition is the most likely
       in the below selection (this can also be done branchlessly). */

    SORT_IDX_T l_next = i; SORT_IDX_T h_next = j;
    if( FD_UNLIKELY( rnk< i   ) ) l_next = l, h_next = i;
    if( FD_UNLIKELY( j  <=rnk ) ) l_next = j, h_next = h;
    l = l_next; h = h_next;
  }
  /* never get here */
}

#undef SORT_IMPL_STATIC

#endif

#if SORT_IMPL_STYLE==0 || SORT_IMPL_STYLE==1 /* need interface */

FD_FN_CONST static inline int SORT_(stable_cnt_valid)( SORT_IDX_T cnt ) {
  /* Written funny for supporting different signed idx types without
     generating compiler warnings */
  SORT_IDX_T max = (SORT_IDX_T)fd_ulong_min( (-alignof(SORT_KEY_T))/sizeof(SORT_KEY_T), /* ==floor( (2^64-align-1)/sz ) */
                                             (ulong)(SORT_IDX_T)((~0UL)>>1) );          /* ==SORT_IDX_MAX as ulong */
  return (!cnt) | ((((SORT_IDX_T)0)<cnt) & (cnt<max)) | (cnt==max);
}

FD_FN_CONST static inline ulong SORT_(stable_scratch_align)    ( void )           { return alignof(SORT_KEY_T); }
FD_FN_CONST static inline ulong SORT_(stable_scratch_footprint)( SORT_IDX_T cnt ) { return sizeof (SORT_KEY_T)*(ulong)cnt; }

static inline SORT_KEY_T *
SORT_(stable_fast)( SORT_KEY_T * key,
                    SORT_IDX_T   cnt,
                    void *       scratch ) {
  SORT_KEY_T * tmp = (SORT_KEY_T *)scratch;
  return SORT_(private_merge)( key, cnt, tmp );
}

FD_FN_UNUSED static SORT_KEY_T * /* Work around -Winline */
SORT_(stable)( SORT_KEY_T * key,
               SORT_IDX_T   cnt,
               void *       scratch ) {
  SORT_KEY_T * tmp = (SORT_KEY_T *)scratch;
  if( SORT_(private_merge)( key, cnt, tmp )==tmp ) for( SORT_IDX_T i=((SORT_IDX_T)0); i<cnt; i++ ) key[i] = tmp[i];
  return key;
}

static inline SORT_KEY_T *
SORT_(inplace)( SORT_KEY_T * key,
                SORT_IDX_T   cnt ) {
  return SORT_(private_quick)( key, cnt );
}

static inline SORT_KEY_T *
SORT_(select)( SORT_KEY_T * key,
               SORT_IDX_T   cnt,
               SORT_IDX_T   rnk ) {
  return SORT_(private_select)( key, cnt, rnk );
}

static inline SORT_IDX_T
SORT_(search_geq)( SORT_KEY_T const * sorted,
                   SORT_IDX_T         cnt,
                   SORT_KEY_T         query ) {
  SORT_IDX_T j = (SORT_IDX_T)0;
  SORT_IDX_T n = (SORT_IDX_T)cnt;
  while( n>((SORT_IDX_T)1) ) {
    /* At this point the j corresponding to k is in [j,j+n) */
    SORT_IDX_T j_left  = j;          SORT_IDX_T n_left  = n >> 1;
    SORT_IDX_T j_right = j + n_left; SORT_IDX_T n_right = n - n_left;
    int  go_left = SORT_BEFORE( query, sorted[ j_right ] );
    j = go_left ? j_left : j_right; /* branchless */
    n = go_left ? n_left : n_right; /* branchless */
  }
  return j;
}

#endif

#undef SORT_

#undef SORT_IDX_IF
#undef SORT_IMPL_STYLE
#undef SORT_QUICK_SWAP_MINIMIZE
#undef SORT_QUICK_ORDER_STYLE
#undef SORT_QUICK_THRESH
#undef SORT_MERGE_THRESH
#undef SORT_BEFORE
#undef SORT_IDX_T
#undef SORT_KEY_T
#undef SORT_NAME

