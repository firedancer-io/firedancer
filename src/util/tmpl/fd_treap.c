/* Generate prototypes, inlines and implementations for ultra high
   performance treaps.  A treap hybrid of a binary search tree and heap
   such that it will well-balanced on average statistically.

   It is not as well-balanced theoretically as more complex
   non-randomized balancing tree algorithms (e.g. red-black trees, AVL
   trees, etc).  But it is often better in practice as it is much
   simpler (i.e. amenable for ultra high performance and small code
   footprint implementation) and very adaptable (e.g. easy to tweak to
   support adaptive queries like a splay tree, etc).  Additionally,
   there are a bunch of tricks in the below to optimize this much
   further than textbook implementations (those tend to miss a lot of
   practical opportunities including eliminating the cost of random
   number generation during operations).

   This API is designed for ultra tight coupling with pools, maps, other
   treaps, etc.  Likewise, a treap can be persisted beyond the lifetime
   of creating process, used concurrently in many common operations,
   used inter-process, relocated in memory, naively
   serialized/deserialized, moved between hosts, supports index
   compression for cache and memory bandwidth efficiency, etc.

   Typical usage:

     struct myele {

       ... Each field below can be located arbitrarily in the struct

       ulong parent; // Technically "TREAP_IDX_T TREAP_PARENT;" (default is ulong parent), similarly for left, right, and prio.
       ulong left;   // parent, left and right managed by the treap when a myele is in the treap.  prio is constant while in a
       ulong right;  // treap.  Further, all these can be used arbitrarily when not in treap (this includes perhaps using an
       ulong prio;   // anonymous union and/or bit fields for even more flexibility).  Additional considerations for prio below.

       // if TREAP_OPTIMIZE_ITERATION is set to 1, the following two
       // fields are also needed:
       ulong next;  // Similarly to above, technically TREAP_IDX_T TREAP_NEXT, TREAP_PREV.  These fields are treap-managed when
       ulong prev;  // a myele is in the treap and can be used arbitrarily when not.


       ... Generally speaking, this treap implement is agnostic to how
       ... the user manages treap priorities.  The algorithmic costs
       ... below assume that priorities are random though.

       ... For stock usage cases, the most optimal handling of prio is
       ... to initialize the prio field exactly once when the myele
       ... storage is first created with random values and then leave it
       ... unchanged thereafter (and potentially reused by other APIs
       ... needing similar randomization).  This eliminates all
       ... overheads associated with random number generation during
       ... operation.  But this also means that prio field is not
       ... available for use when a myele is not in the treap.

       ... In other situations, the user might chose to generate random
       ... priorities dynamically (as it done in textbook
       ... implementations) and/or adjust element priorities on the fly
       ... to splay-tree-like adaptively optimize treap queries.

       ... To support potential future bulk operations (e.g. fast treap
       ... splits / joins), it is recommended that these random values
       ... exclude the largest possible value but this is not strictly
       ... required currently.

       ... Note that other kinds of objects can use these fields for
       ... their metadata needs to keep element metadata / cache
       ... footprint overheads minimal.  The only restriction is that
       ... they cannot concurrently use the same field.  E.g. a pool
       ... could use the "parent" field for its next pointer while
       ... multiple other _disjoint_ treaps of myele_t from the same
       ... pool can all use the same treap fields.

       ... Note that fields could be made into narrow bit fields if
       ... useful for additional memory, bandwidth and cache efficiency.
       ... In particular, for priorities, unbiased pseudo random coin
       ... flipping is used to break ties (a little priority can go a
       ... very long way practically).

       ... Arbitrary application fields mixed in here.  Power-of-2
       ... element sizes have good cache and indexing Feng Shui.

       char key[ KEY_MAX ]; // For demonstration purposes

     };

     typedef struct myele myele_t;

     #define TREAP_NAME      mytreap
     #define TREAP_T         myele_t
     #define TREAP_QUERY_T   char const *
     #define TREAP_CMP(q,e)  strcmp( q, e->key )
     #define TREAP_LT(e0,e1) (strcmp( e0->key, e1->key )<0)
     #include "fd_treap.c"

   will declare the following APIs as a header-only style library in the
   compilation unit:

     int mytreap_cmp( char const *    q,  myele_t const * e  ); // Provides TREAP_CMP
     int mytreap_lt ( myele_t const * e0, myele_t const * e1 ); // Provides TREAP_LT

     // mytreap_idx_null returns the element index used to represent
     // NULL, infinite lifetime.  mytreap_ele_null returns NULL,
     // infinite lifetime, for completeness, mytreap_ele_null_const is a
     // const-correct version, also for completeness.

     ulong           mytreap_idx_null      ( void );
     myele_t *       mytreap_ele_null      ( void );
     myele_t const * mytreap_ele_null_const( void );

     // mytreap_{idx,ele}_is_null returns i==mytreap_idx_null() / !e

     int mytreap_idx_is_null( ulong           i );
     int mytreap_ele_is_null( myele_t const * e );

     // mytreap_idx returns e's index.  Assumes e is a pointer in the
     // caller's local address space to a pool element or is NULL.
     // Return will be in [0,ele_max) or mytreap_idx_null().  Lifetime
     // is the element storage lifetime.  mytreap_idx_fast is the same
     // assumes e is not NULL.  pool is a pointer in the caller's
     // address space to the ele_max linearly addressable storage region
     // backing the treap.

     ulong mytreap_idx     ( myele_t const * e, myele_t const * pool );
     ulong mytreap_idx_fast( myele_t const * e, myele_t const * pool );

     // mytreap_ele returns a pointer in the caller's address space to
     // element idx.  Assumes idx is in [0,ele_max) or is
     // mytreap_idx_null().  Return pointer lifetime is ele's local
     // lifetime.  mytreap_ele_fast is the same but assumes idx is not
     // mytreap_idx_null().  mytreap_ele[_fast]_const is a const correct
     // version.  pool is a pointer in the caller's address space to the
     // ele_max linearly addressable storage region backing the treap.

     myele_t * mytreap_ele     ( ulong i, myele_t * pool );
     myele_t * mytreap_ele_fast( ulong i, myele_t * pool );

     myele_t const * mytreap_ele_const     ( ulong i, myele_t const * pool );
     myele_t const * mytreap_ele_fast_const( ulong i, myele_t const * pool );

     // mytreap_seed is a helper that sets pool[i].prio for i in
     // [0,ele_max) to a random value in [0,PRIO_MAX) (yes half-open)
     // where PRIO_MAX is the largest possible value representable in
     // the prio field.  Uses seed (arbitrary) to select a simple hash
     // based random number of sequence for prio.
     //
     // If an application wants to set this as optimally and securely as
     // possible, it should seed pool[i].prio with a cryptographic
     // secure uniform random permutation of [0,ele_max) and/or
     // dynamically manage the prio field as described above.

     void mytreap_seed( myele_t * pool, ulong ele_max, ulong seed );

     // mytreap_{align,footprint} returns the alignment and footprint
     // needed for a memory region to hold the state of a mytreap of
     // elements from a linearly addressable ele_max element storage.
     // align will be an integer power-of-two and footprint will be a
     // multiple of align.  footprint will non-zero on a success and 0
     // on failure (silent) (e.g. ele_max too large for the specified
     // TREAP_IDX_T).  mytreap_t is stack declaration, data segment
     // declaration, heap allocation and stack allocation friendly.
     // Even though footprint is passed ele_max, the footprint is a
     // small O(1) spatial overhead.
     //
     // mytreap_new formats a memory region with the appropriate
     // alignment and footprint whose first byte in the caller's address
     // space is pointed to by shmem as a mytreap for elements from a
     // linearly addressable ele_max element storage.  Returns shmem on
     // success and NULL on failure (log details, e.g. ele_max is too
     // large for the width of the TREAP_IDX_T specified).  Caller is
     // not joined on return.  The treap will be empty.
     //
     // mytreap_join joins a mytreap.  Assumes shtreap points at a
     // memory region formatted as a mytreap in the caller's address
     // space.  Returns a handle to the caller's local join on success
     // and NULL on failure (logs details).
     //
     // mytreap_leave leaves a mytreap.  Assumes join points to a
     // current local join.  Returns shtreap used on join and NULL on
     // failure (logs details).
     //
     // mytreap_delete unformats a memory region used as a mytreap.
     // Assumes shtreap points to a memory region in the caller's local
     // address space formatted as a mytreap, that there are no joins to
     // the mytreap and that any application side cleanups have been
     // done.  Returns shtreap on success and NULL on failure (logs
     // details).

     ulong       mytreap_align    ( void                              );
     ulong       mytreap_footprint( ulong       ele_max               );
     void *      mytreap_new      ( void *      shmem,  ulong ele_max );
     mytreap_t * mytreap_join     ( void *      shtreap               );
     void *      mytreap_leave    ( mytreap_t * treap                 );
     void *      mytreap_delete   ( void *      shtreap               );

     // mytreap_{ele_max,ele_cnt} gives the maximum number of elements
     // the treap can support / the current number of elements in the
     // treap.  Assumes treap is a current local join.  These might be
     // deprecated in the future.

     ulong mytreap_ele_max( mytreap_t const * treap );
     ulong mytreap_ele_cnt( mytreap_t const * treap );

     // mytreap_idx_query finds where q is stored in the treap.  Assumes
     // treap is a current local join and pool points in the caller's
     // address space to the ele_max element storage containing the
     // treap elements.  Returns [0,ele_max) on success and
     // mytreap_idx_null() on failure.  Lifetime of the returned idx is
     // the lesser of until it is removed or the underlying element
     // storage.  mytreap_ele_query is the same but returns the location
     // in the caller's address space of the found element on success
     // and NULL on failure (lifetime of the returned pointer is until
     // ele is removed or ele's local lifetime).
     // mytreap_ele_query_const is a const correct version.
     //
     // These operations have HPC implementations and are O(lg N)
     // average with an ultra high probability of having a small
     // coefficient (i.e. close to algorithmically optimal trees).

     ulong           mytreap_idx_query      ( mytreap_t const * treap, char const * q, myele_t const * pool );
     myele_t *       mytreap_ele_query      ( mytreap_t *       treap, char const * q, myele_t *       pool );
     myele_t const * mytreap_ele_query_const( mytreap_t const * treap, char const * q, myele_t const * pool );

     // mytreap_idx_{insert,remove} inserts / removes element n/d into
     // the treap and returns treap.  Assumes treap is a current local
     // join, pool points in the caller's address space to the ele_max
     // element storage used for treap elements, n/d are in [0,ele_max),
     // n/d are currently out of / in the treap.  Insert further assumes
     // that n's queries are not in the treap (n's queries are the set
     // of queries that are covered by n).  Given these assumptions,
     // these cannot fail.
     //
     // For insert, n's query and prio fields should already be
     // populated (i.e. MYTREAP_LT( ele+n, ele+i ) should return valid
     // results before this is called and prio should be a suitable
     // value as described above.  On return, n and n's queries will be
     // in the treap.  n's left, right, parent, prio and/or queries
     // should not be modified while n is in the treap.  Further, the
     // caller should not assume n's left, right or parent values are
     // stable while n is in the treap.  The treap does not care about
     // any other fields and these can be modified by the user as
     // necessary.
     //
     // For remove, on return d and d's queries are no longer in the
     // treap.  The caller is free to modify all fields of d as
     // necessary.
     //
     // mytreap_ele_{insert,remove} are the same but n and d point in
     // the caller's local address space the element to insert / remove.
     //
     // These operations have HPC implementations and are O(lg N)
     // average with an ultra high probability of having a small
     // coefficient (i.e. close to algorithmically optimal trees).

     mytreap_t * mytreap_idx_insert( mytreap_t * treap, ulong     n, myele_t * pool );
     mytreap_t * mytreap_idx_remove( mytreap_t * treap, ulong     d, myele_t * pool );

     mytreap_t * mytreap_ele_insert( mytreap_t * treap, myele_t * n, myele_t * pool );
     mytreap_t * mytreap_ele_remove( mytreap_t * treap, myele_t * d, myele_t * pool );

     // mytreap_fwd_iter_{init,done,next,idx,ele,ele_const} provide an
     // in-order iterator from smallest to largest value.  Typical
     // usage:
     //
     //  for( mytreap_fwd_iter_t iter = mytreap_fwd_iter_init( treap, pool );
     //       !mytreap_fwd_iter_done( iter );
     //       iter = mytreap_fwd_iter_next( iter, pool ) ) {
     //     ulong i = mytreap_fwd_iter_idx( iter );
     //     ... or myele_t *       e = mytreap_fwd_iter_ele      ( iter, pool );
     //     ... or myele_t const * e = mytreap_fwd_iter_ele_const( iter, pool );
     //
     //     ... process i (or e) here
     //
     //     ... Do not remove the element the iterator is currently
     //     ... pointing to, and do not change the element's parent,
     //     ... left, right, prio or queries here.  It is fine to run
     //     ... queries and other iterations concurrently.  Other fields
     //     ... are free to modify (from the treap's POV, the
     //     ... application manages concurrency for other fields).
     //  }
     //
     // pool is a pointer in the caller's address space to the ele_max
     // linearly addressable storage region backing the treap.

     typedef ... mytreap_fwd_iter_t;

     mytreap_fwd_iter_t mytreap_fwd_iter_init     ( mytreap_t const * treap, myele_t const * pool );
     int                mytreap_fwd_iter_done     ( mytreap_fwd_iter_t iter                       );
     mytreap_fwd_iter_t mytreap_fwd_iter_next     ( mytreap_fwd_iter_t iter, myele_t const * pool );
     ulong              mytreap_fwd_iter_idx      ( mytreap_fwd_iter_t iter                       );
     myele_t *          mytreap_fwd_iter_ele      ( mytreap_fwd_iter_t iter, myele_t *       pool );
     myele_t const *    mytreap_fwd_iter_ele_const( mytreap_fwd_iter_t iter, myele_t const * pool );

     // mytreap_rev_iter_{init,done,next,idx,ele,ele_const} is the same
     // but used when iterating from largest to smallest.

     typedef ... mytreap_rev_iter_t;

     mytreap_rev_iter_t mytreap_rev_iter_init     ( mytreap_t const * treap, myele_t const * pool );
     int                mytreap_rev_iter_done     ( mytreap_rev_iter_t iter                       );
     mytreap_rev_iter_t mytreap_rev_iter_next     ( mytreap_rev_iter_t iter, myele_t const * pool );
     ulong              mytreap_rev_iter_idx      ( mytreap_rev_iter_t iter                       );
     myele_t *          mytreap_rev_iter_ele      ( mytreap_rev_iter_t iter, myele_t *       pool );
     myele_t const *    mytreap_rev_iter_ele_const( mytreap_rev_iter_t iter, myele_t const * pool );

     // mytreap_merge merges two treaps backed by the same pool into a
     // single treap.  Merge is equivalent to removing each element from
     // treap_b and inserting it into treap_a, but merging the heaps is
     // asymptotically slightly better.  Returns treap_a, which now
     // additionally contains the elements from treap_b.  Requires that
     // the treap does not use the maximum priority element (see the
     // note above about PRIO_MAX).  Assumes the A and B treaps contain
     // no common keys.

     mytreap * mytreap_merge( mytreap * treap_a, mytreap * treap_b, myele_t * pool );

     // mytreap_verify returns 0 if the mytreap is not obviously corrupt
     // or a -1 (i.e. ERR_INVAL) if it is (logs details).  treap is
     // current local join to a mytreap.  pool is a pointer in the
     // caller's address space to the ele_max linearly addressable
     // storage region backing the treap.

     int mytreap_verify( mytreap_t const * treap, myele_t const * pool );

     // IMPORTANT SAFETY TIP!  queries and iteration can be done
     // concurrently by multiple threads distributed arbitrarily over
     // multiple processes provided there are no concurrent insert /
     // remove operations on the treap and the application manages
     // concurrency for fields not managed by the treap.

   You can do this as often as you like within a compilation unit to get
   different types of treaps.  Variants exist for making separate headers
   and implementations for doing libraries and handling multiple
   compilation units.  Additional options exist as detailed below. */

/* TREAP_NAME gives the API prefix to use */

#ifndef TREAP_NAME
#error "Define TREAP_NAME"
#endif

/* TREAP_T is the treap element type */

#ifndef TREAP_T
#error "Define TREAP_T"
#endif

/* TREAP_QUERY_T is the type that is passed to the query function */

#ifndef TREAP_QUERY_T
#error "Define TREAP_QUERY_T"
#endif

/* TREAP_CMP compares a TREAP_QUERY_T q with an element e's query
   fields and returns a negative/zero/positive int if q is less
   than/equal/greater than element e's query fields.  Should be a pure
   function. */

#ifndef TREAP_CMP
#error "Define TREAP_CMP"
#endif

/* TREAP_LT returns 1 if the element e0's query fields are strictly less
   element e1's query fields and 0 otherwise.  Should be a pure
   function. */

#ifndef TREAP_LT
#error "Define TREAP_LT"
#endif

/* TREAP_IDX_T is the type used for the fields in the TREAP_T.  Should
   be a primitive unsigned integer type.  Defaults to ulong.  A treap
   can't use element memory regions that contain more than the maximum
   value that can be represented by a TREAP_IDX_T. */

#ifndef TREAP_IDX_T
#define TREAP_IDX_T ulong
#endif

/* TREAP_{PARENT,LEFT,RIGHT,PRIO} is the name the treap element parent /
   left / right / prio fields.  Defaults to parent / left / right /
   prio. */

#ifndef TREAP_PARENT
#define TREAP_PARENT parent
#endif

#ifndef TREAP_LEFT
#define TREAP_LEFT left
#endif

#ifndef TREAP_RIGHT
#define TREAP_RIGHT right
#endif

#ifndef TREAP_PRIO
#define TREAP_PRIO prio
#endif

/* TREAP_OPTIMIZE_ITERATION controls a space/time tradeoff: when
   TREAP_OPTIMIZE_ITERATION is set to 1, each element has two additional
   fields and insert and delete take slightly longer.  However, in
   return, iteration in either direction is substantially faster.  This
   works by essentially threading a doubly-linked list through elements
   in iteration order. The default is sets this to 0, meaning that the
   next and prev fields are not required. */
#ifndef TREAP_OPTIMIZE_ITERATION
#define TREAP_OPTIMIZE_ITERATION 0
#endif

#if TREAP_OPTIMIZE_ITERATION
# ifndef  TREAP_NEXT
#  define TREAP_NEXT next
# endif

# ifndef  TREAP_PREV
#  define TREAP_PREV prev
# endif
#endif

/* TREAP_IMPL_STYLE controls what this template should emit.
   0 - local use only
   1 - library header
   2 - library implementation */

#ifndef TREAP_IMPL_STYLE
#define TREAP_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

#if TREAP_IMPL_STYLE==0
#define TREAP_STATIC static FD_FN_UNUSED
#else
#define TREAP_STATIC
#endif

#define TREAP_IDX_NULL           ((ulong)(TREAP_IDX_T)(~0UL))
#define TREAP_IDX_IS_NULL( idx ) ((idx)==TREAP_IDX_NULL)

#define TREAP_(n) FD_EXPAND_THEN_CONCAT3(TREAP_NAME,_,n)

/* Verification logs details on failure.  The rest only needs fd_bits.h
   (consider making logging a compile time option). */

#include "../log/fd_log.h"

#if TREAP_IMPL_STYLE!=2 /* need structures, prototypes and inlines */

/* structures */

/* TODO: consider eliminating ele_cnt and maybe ele_max fields (less overhead,
   faster bulk ops, concurrency options, simpler constructors, etc) */

struct TREAP_(private) {
  ulong       ele_max; /* Maximum number of elements in treap, in [0,TREAP_IDX_NULL] */
  ulong       ele_cnt; /* Current number of elements in treap, in [0,ele_max] */
#if TREAP_OPTIMIZE_ITERATION
  TREAP_IDX_T first;   /* Index of the left-most treap element, in [0,ele_max) or TREAP_IDX_NULL */
  TREAP_IDX_T last;    /* Index of the right-most treap element, in [0,ele_max) or TREAP_IDX_NULL */
#endif
  TREAP_IDX_T root;    /* Index of the root treap element, in [0,ele_max) or TREAP_IDX_NULL */
};

typedef struct TREAP_(private) TREAP_(t);

typedef ulong TREAP_(fwd_iter_t);
typedef ulong TREAP_(rev_iter_t);

FD_PROTOTYPES_BEGIN

/* prototypes */

TREAP_STATIC void TREAP_(seed)( TREAP_T * pool, ulong ele_max, ulong seed );

TREAP_STATIC FD_FN_CONST ulong       TREAP_(align)    ( void                              );
TREAP_STATIC FD_FN_CONST ulong       TREAP_(footprint)( ulong       ele_max               );
TREAP_STATIC /**/        void *      TREAP_(new)      ( void *      shmem,  ulong ele_max );
TREAP_STATIC /**/        TREAP_(t) * TREAP_(join)     ( void *      shtreap               );
TREAP_STATIC /**/        void *      TREAP_(leave)    ( TREAP_(t) * treap                 );
TREAP_STATIC /**/        void *      TREAP_(delete)   ( void *      shtreap               );

TREAP_STATIC FD_FN_PURE ulong TREAP_(idx_query)( TREAP_(t) const * treap, TREAP_QUERY_T q, TREAP_T const * pool );

TREAP_STATIC TREAP_(t) * TREAP_(idx_insert)( TREAP_(t) * treap, ulong n, TREAP_T * pool );
TREAP_STATIC TREAP_(t) * TREAP_(idx_remove)( TREAP_(t) * treap, ulong d, TREAP_T * pool );

TREAP_STATIC FD_FN_PURE TREAP_(fwd_iter_t) TREAP_(fwd_iter_init)( TREAP_(t) const * treap, TREAP_T const * pool );
TREAP_STATIC FD_FN_PURE TREAP_(rev_iter_t) TREAP_(rev_iter_init)( TREAP_(t) const * treap, TREAP_T const * pool );

TREAP_STATIC FD_FN_PURE TREAP_(fwd_iter_t) TREAP_(fwd_iter_next)( TREAP_(fwd_iter_t) i, TREAP_T const * pool );
TREAP_STATIC FD_FN_PURE TREAP_(rev_iter_t) TREAP_(rev_iter_next)( TREAP_(rev_iter_t) i, TREAP_T const * pool );

TREAP_STATIC TREAP_(t) * TREAP_(merge)( TREAP_(t) * treap_a, TREAP_(t) * treap_b, TREAP_T * pool );

TREAP_STATIC FD_FN_PURE int TREAP_(verify)( TREAP_(t) const * treap, TREAP_T const * pool );

/* inlines */

FD_FN_PURE static inline int TREAP_(cmp)( TREAP_QUERY_T   q,  TREAP_T const * e  ) { return TREAP_CMP( q, e );  }
FD_FN_PURE static inline int TREAP_(lt) ( TREAP_T const * e0, TREAP_T const * e1 ) { return TREAP_LT( e0, e1 ); }

FD_FN_CONST static inline ulong           TREAP_(idx_null)      ( void ) { return TREAP_IDX_NULL; }
FD_FN_CONST static inline TREAP_T *       TREAP_(ele_null)      ( void ) { return NULL;           }
FD_FN_CONST static inline TREAP_T const * TREAP_(ele_null_const)( void ) { return NULL;           }

FD_FN_CONST static inline int TREAP_(idx_is_null)( ulong           i ) { return TREAP_IDX_IS_NULL( i ); }
FD_FN_CONST static inline int TREAP_(ele_is_null)( TREAP_T const * e ) { return !e;                     }

FD_FN_CONST static inline ulong
TREAP_(idx)( TREAP_T const * e,
             TREAP_T const * pool ) {
  return fd_ulong_if( !!e, (ulong)(e - pool), TREAP_IDX_NULL );
}

FD_FN_CONST static inline TREAP_T *
TREAP_(ele)( ulong     i,
             TREAP_T * pool ) {
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), pool + i, NULL );
}

FD_FN_CONST static inline TREAP_T const *
TREAP_(ele_const)( ulong           i,
                   TREAP_T const * pool ) {
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), pool + i, NULL );
}

FD_FN_CONST static inline ulong
TREAP_(idx_fast)( TREAP_T const * e,
                  TREAP_T const * pool ) {
  return (ulong)(e - pool);
}

FD_FN_CONST static inline TREAP_T *       TREAP_(ele_fast)      ( ulong i, TREAP_T *       pool ) { return pool + i; }
FD_FN_CONST static inline TREAP_T const * TREAP_(ele_fast_const)( ulong i, TREAP_T const * pool ) { return pool + i; }

FD_FN_PURE static inline ulong TREAP_(ele_max)( TREAP_(t) const * treap ) { return treap->ele_max; }
FD_FN_PURE static inline ulong TREAP_(ele_cnt)( TREAP_(t) const * treap ) { return treap->ele_cnt; }

FD_FN_PURE static inline TREAP_T *
TREAP_(ele_query)( TREAP_(t) const * treap,
                   TREAP_QUERY_T     q,
                   TREAP_T *         pool ) {
  ulong i = TREAP_(idx_query)( treap, q, pool );
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), pool + i, NULL );
}

FD_FN_PURE static inline TREAP_T const *
TREAP_(ele_query_const)( TREAP_(t) const * treap,
                         TREAP_QUERY_T     q,
                         TREAP_T const *   pool ) {
  ulong i = TREAP_(idx_query)( treap, q, pool );
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), pool + i, NULL );
}

static inline TREAP_(t) *
TREAP_(ele_insert)( TREAP_(t) * treap,
                    TREAP_T *   e,
                    TREAP_T *   pool ) {
  return TREAP_(idx_insert)( treap, (ulong)(e - pool), pool );
}

static inline TREAP_(t) *
TREAP_(ele_remove)( TREAP_(t) * treap,
                    TREAP_T *   e,
                    TREAP_T *   pool ) {
  return TREAP_(idx_remove)( treap, (ulong)(e - pool), pool );
}

FD_FN_CONST static inline int             TREAP_(fwd_iter_done)     ( TREAP_(fwd_iter_t) i ) { return TREAP_IDX_IS_NULL( i ); }
FD_FN_CONST static inline ulong           TREAP_(fwd_iter_idx)      ( TREAP_(fwd_iter_t) i                       ) { return i;        }
FD_FN_CONST static inline TREAP_T *       TREAP_(fwd_iter_ele)      ( TREAP_(fwd_iter_t) i, TREAP_T *       pool ) { return pool + i; }
FD_FN_CONST static inline TREAP_T const * TREAP_(fwd_iter_ele_const)( TREAP_(fwd_iter_t) i, TREAP_T const * pool ) { return pool + i; }

FD_FN_CONST static inline int             TREAP_(rev_iter_done)     ( TREAP_(rev_iter_t) i ) { return TREAP_IDX_IS_NULL( i ); }
FD_FN_CONST static inline ulong           TREAP_(rev_iter_idx)      ( TREAP_(rev_iter_t) i                       ) { return i;        }
FD_FN_CONST static inline TREAP_T *       TREAP_(rev_iter_ele)      ( TREAP_(rev_iter_t) i, TREAP_T *       pool ) { return pool + i; }
FD_FN_CONST static inline TREAP_T const * TREAP_(rev_iter_ele_const)( TREAP_(rev_iter_t) i, TREAP_T const * pool ) { return pool + i; }

FD_PROTOTYPES_END

#endif

#if TREAP_IMPL_STYLE!=1 /* need implementations */

TREAP_STATIC void
TREAP_(seed)( TREAP_T * pool,
              ulong     ele_max,
              ulong     seed ) {
  for( ulong ele_idx=0UL; ele_idx<ele_max; ele_idx++ ) {
    ulong r = fd_ulong_hash( ele_idx ^ seed ) & TREAP_IDX_NULL;
    pool[ ele_idx ].TREAP_PRIO = (TREAP_IDX_T)(r - (ulong)(r==TREAP_IDX_NULL));
  }
}

TREAP_STATIC FD_FN_CONST ulong
TREAP_(align)( void ) {
  return alignof(TREAP_(t));
}

TREAP_STATIC FD_FN_CONST ulong
TREAP_(footprint)( ulong ele_max ) {
  if( FD_UNLIKELY( ele_max>TREAP_IDX_NULL ) ) return 0UL;
  return sizeof(TREAP_(t));
}

TREAP_STATIC void *
TREAP_(new)( void * shmem,
             ulong  ele_max ) {
  if( !shmem ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, TREAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( ele_max>TREAP_IDX_NULL ) ) {
    FD_LOG_WARNING(( "ele_max too large" ));
    return NULL;
  }

  TREAP_(t) * treap = (TREAP_(t) *)shmem;

  treap->ele_max = ele_max;
  treap->ele_cnt = 0UL;
  treap->root    = (TREAP_IDX_T)TREAP_IDX_NULL;

#if TREAP_OPTIMIZE_ITERATION
  treap->first   = (TREAP_IDX_T)TREAP_IDX_NULL;
  treap->last    = (TREAP_IDX_T)TREAP_IDX_NULL;
#endif

  return treap;
}

TREAP_STATIC TREAP_(t) *
TREAP_(join)( void * shtreap ) {
  if( FD_UNLIKELY( !shtreap ) ) {
    FD_LOG_WARNING(( "NULL shtreap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtreap, TREAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtreap" ));
    return NULL;
  }

  return (TREAP_(t) *)shtreap;
}

TREAP_STATIC void *
TREAP_(leave)( TREAP_(t) * treap ) {
  if( FD_UNLIKELY( !treap ) ) {
    FD_LOG_WARNING(( "NULL treap" ));
    return NULL;
  }

  return (void *)treap;
}

TREAP_STATIC void *
TREAP_(delete)( void * shtreap ) {
  if( FD_UNLIKELY( !shtreap ) ) {
    FD_LOG_WARNING(( "NULL shtreap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtreap, TREAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtreap" ));
    return NULL;
  }

  return shtreap;
}

TREAP_STATIC ulong
TREAP_(idx_query)( TREAP_(t) const * treap,
                   TREAP_QUERY_T     q,
                   TREAP_T const *   pool ) {
  ulong i = (ulong)treap->root;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( i ) ) ) { /* Optimize for found */
    ulong l = (ulong)pool[ i ].TREAP_LEFT;
    ulong r = (ulong)pool[ i ].TREAP_RIGHT;
    int   c = TREAP_(cmp)( q, pool + i );
    if( FD_UNLIKELY( !c ) ) break; /* Optimize for larger treaps */
    i = fd_ulong_if( c<0, l, r );
  }
  return i;
}

TREAP_STATIC TREAP_(t) *
TREAP_(idx_insert)( TREAP_(t) * treap,
                    ulong       n,
                    TREAP_T *   pool ) {

  /* Find leaf where to insert n */

  TREAP_IDX_T * _p_child = &treap->root;
#if TREAP_OPTIMIZE_ITERATION
  TREAP_IDX_T * _p_pnext = &treap->first; /* pointer to prev node's next idx */
  TREAP_IDX_T * _p_nprev = &treap->last;  /* pointer to next node's prev idx */
#endif

  ulong i = TREAP_IDX_NULL;
  for(;;) {
    ulong j = (ulong)*_p_child;
    if( FD_UNLIKELY( TREAP_IDX_IS_NULL( j ) ) ) break; /* Optimize for large treap */
    i = j;
    int lt = TREAP_(lt)( pool + n, pool + i );
    _p_child = fd_ptr_if( lt, &pool[ i ].TREAP_LEFT, &pool[ i ].TREAP_RIGHT );
#if TREAP_OPTIMIZE_ITERATION
    _p_pnext = fd_ptr_if( lt, _p_pnext,              &pool[ i ].TREAP_NEXT  );
    _p_nprev = fd_ptr_if( lt, &pool[ i ].TREAP_PREV, _p_nprev               );
#endif
  }

  /* Insert n.  This might momentarily break the heap property. */

  pool[ n ].TREAP_PARENT = (TREAP_IDX_T)i;
  pool[ n ].TREAP_LEFT   = (TREAP_IDX_T)TREAP_IDX_NULL;
  pool[ n ].TREAP_RIGHT  = (TREAP_IDX_T)TREAP_IDX_NULL;
  *_p_child = (TREAP_IDX_T)n;

#if TREAP_OPTIMIZE_ITERATION
  pool[ n ].TREAP_PREV = *_p_nprev;
  pool[ n ].TREAP_NEXT = *_p_pnext;
  *_p_nprev = (TREAP_IDX_T)n;
  *_p_pnext = (TREAP_IDX_T)n;
#endif

  /* Bubble n up until the heap property is restored. */

  ulong n_prio = (ulong)pool[ n ].TREAP_PRIO;
  while( !TREAP_IDX_IS_NULL( i ) ) {
    ulong i_prio = (ulong)pool[ i ].TREAP_PRIO;

    int heap_intact = (n_prio<i_prio) | ((n_prio==i_prio) & (!((n ^ i) & 1UL))); /* Flip coin on equal priority */
    if( heap_intact ) break;

    /* Get i's parent (if any) and parent's link to i (tree root link if no parent) */

    ulong p = (ulong)pool[ i ].TREAP_PARENT;

    TREAP_IDX_T * _t0      = fd_ptr_if( TREAP_IDX_IS_NULL( p ), &treap->root, &pool[ p ].TREAP_LEFT  );
    /**/          _p_child = fd_ptr_if( i==(ulong)*_t0,         _t0,          &pool[ p ].TREAP_RIGHT );

    /* Get n's child (if any) that will become i's child */

    int           n_is_left_child = (n==(ulong)pool[ i ].TREAP_LEFT);
    TREAP_IDX_T * _n_child        = fd_ptr_if( n_is_left_child, &pool[ n ].TREAP_RIGHT, &pool[ n ].TREAP_LEFT );
    ulong         j               = (ulong)*_n_child;

    /* Make n child of p (or the root if no parent) */

    *_p_child              = (TREAP_IDX_T)n;
    pool[ n ].TREAP_PARENT = (TREAP_IDX_T)p;

    /* Make i child of n */

    *_n_child              = (TREAP_IDX_T)i;
    pool[ i ].TREAP_PARENT = (TREAP_IDX_T)n;

    /* Make j (if present) child of i */

    TREAP_IDX_T dummy;
    *fd_ptr_if( n_is_left_child,        &pool[ i ].TREAP_LEFT, &pool[ i ].TREAP_RIGHT  ) = (TREAP_IDX_T)j;
    *fd_ptr_if( TREAP_IDX_IS_NULL( j ), &dummy,                &pool[ j ].TREAP_PARENT ) = (TREAP_IDX_T)i;

    /* Keep bubbling up */

    i = p;
  }

  treap->ele_cnt++;
  return treap;
}

TREAP_(t) *
TREAP_(idx_remove)( TREAP_(t) * treap,
                    ulong       d,
                    TREAP_T *   pool ) {

  /* Make a hole at d */

  ulong p = (ulong)pool[ d ].TREAP_PARENT;
  ulong l = (ulong)pool[ d ].TREAP_LEFT;
  ulong r = (ulong)pool[ d ].TREAP_RIGHT;

  TREAP_IDX_T * _t0      = fd_ptr_if( TREAP_IDX_IS_NULL( p ), &treap->root, &pool[ p ].TREAP_LEFT  );
  TREAP_IDX_T * _p_child = fd_ptr_if( d==(ulong)*_t0,         _t0,          &pool[ p ].TREAP_RIGHT );

#if TREAP_OPTIMIZE_ITERATION
  TREAP_IDX_T prev = pool[ d ].TREAP_PREV;
  TREAP_IDX_T next = pool[ d ].TREAP_NEXT;
  TREAP_IDX_T * _pnext = fd_ptr_if( TREAP_IDX_IS_NULL( prev ), &treap->first, &pool[ prev ].TREAP_NEXT );
  TREAP_IDX_T * _nprev = fd_ptr_if( TREAP_IDX_IS_NULL( next ), &treap->last,  &pool[ next ].TREAP_PREV );
  *_pnext = next;
  *_nprev = prev;
#endif

  for(;;) {

    /* At this point, we have a hole to fill at d:

       p is the hole's parent (if any)
       l is the hole's left subtree (if any)
       r is the hole's right subtree (if any)

       p_child points to the link from p to hole (if the hole has a
       parent) and to the treap root link otherwise.

       If there is neither a left subtree nor a right subtree, we are
       done.  If there is a left/right subtree, we fill the hole with
       the right/left subtree and we are done. */

    int is_null_left  = TREAP_IDX_IS_NULL( l );
    int is_null_right = TREAP_IDX_IS_NULL( r );
    if( FD_LIKELY( is_null_left | is_null_right ) ) { /* Most nodes near bottom */
      TREAP_IDX_T dummy;
      *_p_child = (TREAP_IDX_T)fd_ulong_if( !is_null_left, l, r );
      *( fd_ptr_if( !is_null_left,  &pool[ l ].TREAP_PARENT,
         fd_ptr_if( !is_null_right, &pool[ r ].TREAP_PARENT, &dummy ) ) ) = (TREAP_IDX_T)p;
      break;
    }

    /* The hole has two subtrees.  We bubble the hole down one, fill the
       hole with the root of the subtree that will preserve the heap
       priority up to the hole (flipping a coin on ties).  Note we don't
       need to update any links to/from d as we will be getting rid of
       all links / from d. */

    ulong l_prio = (ulong)pool[ l ].TREAP_PRIO;
    ulong r_prio = (ulong)pool[ r ].TREAP_PRIO;

    int promote_left = (l_prio>r_prio) | ((l_prio==r_prio) & (!((p ^ d) & 1UL)));

    ulong c = fd_ulong_if( promote_left, l, r );

    *_p_child = (TREAP_IDX_T)c;
    pool[ c ].TREAP_PARENT = (TREAP_IDX_T)p;

    _p_child = fd_ptr_if  ( promote_left, &pool[ l ].TREAP_RIGHT, &pool[ r ].TREAP_LEFT  );
    p        = c;
    l        = fd_ulong_if( promote_left,  pool[ l ].TREAP_RIGHT,        l               );
    r        = fd_ulong_if( promote_left,        r,                pool[ r ].TREAP_LEFT  );

  }

  treap->ele_cnt--;
  return treap;
}

static inline void
TREAP_(private_split)( TREAP_IDX_T   idx_node,         /* Tree to split */
                       TREAP_T *     key,              /* Element whose key is not in the treap rooted at idx_node */
                       TREAP_IDX_T * _idx_left,        /* Where to store the left tree root */
                       TREAP_IDX_T * _idx_right,       /* Where to store the right tree root */
                       TREAP_IDX_T * _idx_last_left,   /* Where to store the last (in BST order) element of the new left tree */
                       TREAP_IDX_T * _idx_first_right, /* Where to store the first(in BST order) element in the new right tree */
                       TREAP_T *     pool ) {          /* Underlying pool */

  TREAP_IDX_T idx_parent_left  = TREAP_IDX_NULL;
  TREAP_IDX_T idx_parent_right = TREAP_IDX_NULL;
  *_idx_last_left   = TREAP_IDX_NULL;
  *_idx_first_right = TREAP_IDX_NULL;

  while( !TREAP_IDX_IS_NULL( idx_node ) ) {

    /* At this point we have a non-empty subtree to split whose root is
       node and we should attach the left and right split trees at
       idx_parent_left / *_idx_left and idx_parent_right / *_idx_right.
       (On the first attach, idx_parent_left/right will be idx_null and
       *_idx_left / *_idx_right are locations where to store the output
       split treaps.) */

    if( TREAP_LT( &pool[ idx_node ], key ) ) {

      /* node is left of key which, by the BST property, means all
         elements in node's left subtree are also left of key.  We don't
         know if node's right subtree contains any elements left of key.
         If it does, these elements should be attached to node's right
         subtree to preserve the BST property of the left split.

         As such, we attach node and node's left subtree to the
         left split, update the attach point for the left split to
         node's right subtree and then recurse on the node's right
         subtree.

         Note that this operation does not do any reordering of
         priorities (e.g. if element B was a descendant of element A
         before the split and both B and A belong on the left split, B
         will still be a descendant of A). */

      /* Attach node and node's left subtree to the left split */
      pool[ idx_node ].TREAP_PARENT = idx_parent_left;
      *_idx_left = idx_node;

      /* The next left split attach is node's right child */
      idx_parent_left = idx_node;
      _idx_left = &pool[ idx_node ].TREAP_RIGHT;

      /* If everything in the right subtree is to the right of the key,
         this is the last node on the left. */
      *_idx_last_left = idx_node;

      /* Recurse on the right subtree */
      idx_node = pool[ idx_node ].TREAP_RIGHT;

    } else { /* Mirror image of the above */

      pool[ idx_node ].TREAP_PARENT = idx_parent_right;
      *_idx_right = idx_node;

      idx_parent_right = idx_node;
      _idx_right = &pool[ idx_node ].TREAP_LEFT;

      *_idx_first_right = idx_node;

      idx_node = pool[ idx_node ].TREAP_LEFT;

    }
  }

  /* At this point, we have an empty tree to split */

  *_idx_left  = TREAP_IDX_NULL;
  *_idx_right = TREAP_IDX_NULL;
}

#if !TREAP_OPTIMIZE_ITERATION
static inline void
TREAP_(private_join)( TREAP_IDX_T    idx_left,  /* Root of the left treap */
                      TREAP_IDX_T    idx_right, /* Root of the right treap, keys in left treap < keys in right treap */
                      TREAP_IDX_T *  _idx_join, /* Where to store root of joined treaps */
                      TREAP_T     *  pool ) {   /* Underlying pool */

  TREAP_IDX_T idx_join_parent = TREAP_IDX_NULL;

  for(;;) {

    /* TODO: consolidate these cases into a single branch. */

    if( TREAP_IDX_IS_NULL( idx_left ) ) { /* Left treap empty */
      /* join is the right treap (or empty if both left and right empty) */
      if( !TREAP_IDX_IS_NULL( idx_right ) ) pool[ idx_right ].TREAP_PARENT = idx_join_parent;
      *_idx_join = idx_right;
      break;
    }

    if( TREAP_IDX_IS_NULL( idx_right ) ) { /* Right treap empty */
      /* join is the left treap */
      pool[ idx_left ].TREAP_PARENT = idx_join_parent;
      *_idx_join = idx_left;
      break;
    }

    /* At this point, we have two non empty treaps to join and elements
       in the left treap have keys before elements in the right treap. */

    ulong prio_left  = (ulong)pool[ idx_left  ].TREAP_PRIO;
    ulong prio_right = (ulong)pool[ idx_right ].TREAP_PRIO;
    if( (prio_left>prio_right) | ((prio_left==prio_right) & (int)(idx_left^idx_right)) ) {

      /* At this point, the left treap root has higher priority than the
         right treap root.  So we attach the left treap root and left
         treap left subtree to the join to preserve the heap property.
         We know that the left treap right subtree is to the right of
         these and that the right treap is to the right of that.  So our
         next join attachment point should be at the left treap right
         subtree and we should recurse on the left treap right subtree
         and the right treap. */

      /* Attach left's root and left's left subtree to the join */
      pool[ idx_left ].TREAP_PARENT = idx_join_parent;
      *_idx_join = idx_left;

      /* The next join attach should be left's right subtree */
      idx_join_parent = idx_left;
      _idx_join = &pool[ idx_left ].TREAP_LEFT;

      /* Recurse on left's right subtree and right treap */
      idx_left = pool[ idx_left ].TREAP_RIGHT;

    } else { /* Mirror image of the above */

      pool[ idx_right ].TREAP_PARENT = idx_join_parent;
      *_idx_join = idx_right;

      idx_join_parent = idx_right;
      _idx_join = &pool[ idx_right ].TREAP_RIGHT;

      idx_right = pool[ idx_right ].TREAP_LEFT;

    }
  }
}
#endif

TREAP_(t) *
TREAP_(merge)( TREAP_(t) * treap_a,
               TREAP_(t) * treap_b,
               TREAP_T *   pool ) {

  TREAP_IDX_T   idx_a      = treap_a->root;
  TREAP_IDX_T   idx_b      = treap_b->root;
  TREAP_IDX_T   new_root   = TREAP_IDX_NULL;
  TREAP_IDX_T * _idx_merge = &new_root;

# if TREAP_OPTIMIZE_ITERATION
  /* Invariant: idx_{a,b}_{first,last} is the index of the first/last
     node in key order in the subtree rooted at idx_a/idx_b. */
  TREAP_IDX_T  idx_a_first = treap_a->first;
  TREAP_IDX_T  idx_a_last  = treap_a->last;
  TREAP_IDX_T  idx_b_first = treap_b->first;
  TREAP_IDX_T  idx_b_last  = treap_b->last;

  /* merged_{prev,next} are the nodes immediately before/after the
     merged subtree.  If these are IDX_NULL, then treap_a->first/last
     should be updated instead. */
  TREAP_IDX_T  merged_prev   = TREAP_IDX_NULL;
  TREAP_IDX_T  merged_next   = TREAP_IDX_NULL;
# endif

# define STACK_MAX (128UL)

  struct { TREAP_IDX_T idx_merge_parent; TREAP_IDX_T * _idx_merge; TREAP_IDX_T idx_a; TREAP_IDX_T idx_b;
#   if TREAP_OPTIMIZE_ITERATION
    TREAP_IDX_T idx_a_first, idx_a_last, idx_b_first, idx_b_last;
    TREAP_IDX_T merged_prev, merged_next;
#   endif
  } stack[ STACK_MAX ];
  ulong stack_top = 0UL;

# define STACK_IS_EMPTY (!stack_top)
# define STACK_IS_FULL  (stack_top>=STACK_MAX)

#if TREAP_OPTIMIZE_ITERATION
# define STACK_PUSH( imp, im, ia, ib, iaf, ial, ibf, ibl, mp, mn ) do { \
    stack[ stack_top ].idx_merge_parent = (imp);                        \
    stack[ stack_top ]._idx_merge       = (im);                         \
    stack[ stack_top ].idx_a            = (ia);                         \
    stack[ stack_top ].idx_b            = (ib);                         \
    stack[ stack_top ].idx_a_first      = (iaf);                        \
    stack[ stack_top ].idx_a_last       = (ial);                        \
    stack[ stack_top ].idx_b_first      = (ibf);                        \
    stack[ stack_top ].idx_b_last       = (ibl);                        \
    stack[ stack_top ].merged_prev      = (mp);                         \
    stack[ stack_top ].merged_next      = (mn);                         \
    stack_top++;                                                        \
  } while(0)
# define STACK_POP( imp, im, ia, ib, iaf, ial, ibf, ibl, mp, mn ) do {  \
    stack_top--;                                 \
    (imp) = stack[ stack_top ].idx_merge_parent; \
    (im)  = stack[ stack_top ]._idx_merge;       \
    (ia)  = stack[ stack_top ].idx_a;            \
    (ib)  = stack[ stack_top ].idx_b;            \
    (iaf) = stack[ stack_top ].idx_a_first;      \
    (ial) = stack[ stack_top ].idx_a_last;       \
    (ibf) = stack[ stack_top ].idx_b_first;      \
    (ibl) = stack[ stack_top ].idx_b_last;       \
    (mp)  = stack[ stack_top ].merged_prev;      \
    (mn)  = stack[ stack_top ].merged_next;      \
  } while(0)
#else
# define STACK_PUSH( imp, im, ia, ib ) do {      \
    stack[ stack_top ].idx_merge_parent = (imp); \
    stack[ stack_top ]._idx_merge       = (im);  \
    stack[ stack_top ].idx_a            = (ia);  \
    stack[ stack_top ].idx_b            = (ib);  \
    stack_top++;                                 \
  } while(0)
# define STACK_POP( imp, im, ia, ib ) do {       \
    stack_top--;                                 \
    (imp) = stack[ stack_top ].idx_merge_parent; \
    (im)  = stack[ stack_top ]._idx_merge;       \
    (ia)  = stack[ stack_top ].idx_a;            \
    (ib)  = stack[ stack_top ].idx_b;            \
  } while(0)
#endif

  TREAP_IDX_T idx_merge_parent = TREAP_IDX_NULL;

  for(;;) {

    /* At this point, we are to merge the treaps rooted at idx_a and
       idx_b.  The result should be attached to the output treap at node
       idx_merge_parent via the link *idx_merge.  (On the first
       iteration, the idx_merge_parent will be idx_null and *_idx_merge
       will be where to store the root of the output treap.) */

    int idx_a_is_null = TREAP_IDX_IS_NULL( idx_a );
    int idx_b_is_null = TREAP_IDX_IS_NULL( idx_b );
    if( idx_a_is_null | idx_b_is_null ) {

      /* At this point, at least one of the treaps to merge is empty.
         Attach the non-empty treap (if any) accordingly.  If both are
         empty, we attach NULL and there is no parent field to update. */

      TREAP_IDX_T idx_tmp;
      *fd_ptr_if( idx_b_is_null, fd_ptr_if( idx_a_is_null, &idx_tmp,
                                                           &pool[ idx_a ].TREAP_PARENT ),
                                                           &pool[ idx_b ].TREAP_PARENT ) = idx_merge_parent;
      *_idx_merge = (TREAP_IDX_T)fd_ulong_if( idx_b_is_null, (ulong)idx_a, (ulong)idx_b );

#     if TREAP_OPTIMIZE_ITERATION
      /* Update the four pointers to insert the range
         idx_a_first and idx_a_last (or b if a is the empty subtree)
         between merged_prev and merged_next.  If both are the empty
         subtree, then merged_prev connects directly to merged_next. */
      *fd_ptr_if( TREAP_IDX_IS_NULL( merged_prev ), &treap_a->first, &pool[ merged_prev ].TREAP_NEXT ) =
                                        (TREAP_IDX_T)fd_ulong_if( idx_b_is_null, fd_ulong_if( idx_a_is_null, (ulong)merged_next,
                                                                                                             (ulong)idx_a_first ),
                                                                                                             (ulong)idx_b_first );
      *fd_ptr_if( TREAP_IDX_IS_NULL( merged_next ), &treap_a->last , &pool[ merged_next ].TREAP_PREV ) =
                                        (TREAP_IDX_T)fd_ulong_if( idx_b_is_null, fd_ulong_if( idx_a_is_null, (ulong)merged_prev,
                                                                                                             (ulong)idx_a_last  ),
                                                                                                             (ulong)idx_b_last  );
      *fd_ptr_if( idx_b_is_null, fd_ptr_if( idx_a_is_null, &idx_tmp,
                                                           &pool[ idx_a_first ].TREAP_PREV ),
                                                           &pool[ idx_b_first ].TREAP_PREV ) = merged_prev;
      *fd_ptr_if( idx_b_is_null, fd_ptr_if( idx_a_is_null, &idx_tmp,
                                                           &pool[ idx_a_last ].TREAP_NEXT ),
                                                           &pool[ idx_b_last ].TREAP_NEXT ) = merged_next;

#     endif
      /* Pop the stack to get the next merge to do.  If the stack is
         empty, we are done. */

      if( STACK_IS_EMPTY ) break;
#     if TREAP_OPTIMIZE_ITERATION
      STACK_POP( idx_merge_parent, _idx_merge, idx_a, idx_b, idx_a_first, idx_a_last, idx_b_first, idx_b_last, merged_prev, merged_next );
#     else
      STACK_POP( idx_merge_parent, _idx_merge, idx_a, idx_b );
#     endif
      continue;
    }

    /* If the stack is full, it appears we have exceedingly poorly
       balanced treaps to merge.  To mitigate stack overflow risk from
       the recursion, we fall back on a marginally less efficient brute
       force non-recursive algorithm for the merge.  FIXME: consider
       doing this post swap for statistical reasons (i.e. the treap with
       the higher root priority is likely to be the larger treap and
       such might have some performance implications for the below
       loop). */

    if( FD_UNLIKELY( STACK_IS_FULL ) ) {

      /* Remove elements from B one-by-one and insert them into A.
         O(B lg B) for the removes, O(B lg(A + B)) for the inserts. */

#     if TREAP_OPTIMIZE_ITERATION
      TREAP_(t) temp_treap_a = { .ele_max = treap_a->ele_max, .ele_cnt = 0UL, .root = idx_a, .first=idx_a_first, .last=idx_a_last };
      TREAP_(t) temp_treap_b = { .ele_max = treap_b->ele_max, .ele_cnt = 0UL, .root = idx_b, .first=idx_b_first, .last=idx_b_last };
#     else
      TREAP_(t) temp_treap_a = { .ele_max = treap_a->ele_max, .ele_cnt = 0UL, .root = idx_a };
      TREAP_(t) temp_treap_b = { .ele_max = treap_b->ele_max, .ele_cnt = 0UL, .root = idx_b };
#     endif
      pool[ idx_a ].TREAP_PARENT = TREAP_IDX_NULL;
      pool[ idx_b ].TREAP_PARENT = TREAP_IDX_NULL;
      do {
        TREAP_IDX_T idx_tmp = temp_treap_b.root;
        TREAP_(idx_remove)( &temp_treap_b, idx_tmp, pool );
        TREAP_(idx_insert)( &temp_treap_a, idx_tmp, pool );
      } while( !TREAP_IDX_IS_NULL( temp_treap_b.root ) );

      idx_b = TREAP_IDX_NULL;
      idx_a = temp_treap_a.root;

      /* Attach the merged treap to the output */

      pool[ idx_a ].TREAP_PARENT = idx_merge_parent;
      *_idx_merge = idx_a;

#     if TREAP_OPTIMIZE_ITERATION
      *fd_ptr_if( TREAP_IDX_IS_NULL( merged_prev ), &treap_a->first, &pool[ merged_prev ].TREAP_NEXT ) = temp_treap_a.first;
      *fd_ptr_if( TREAP_IDX_IS_NULL( merged_next ), &treap_a->last,  &pool[ merged_next ].TREAP_PREV ) = temp_treap_a.last;
      pool[ temp_treap_a.first ].TREAP_PREV = merged_prev;
      pool[ temp_treap_a.last  ].TREAP_NEXT = merged_next;
#     endif

      /* Pop the stack to get the next merge to do.  If the stack is
         empty, we are done. */

      if( STACK_IS_EMPTY ) break;
#     if TREAP_OPTIMIZE_ITERATION
      STACK_POP( idx_merge_parent, _idx_merge, idx_a, idx_b,
          idx_a_first, idx_a_last, idx_b_first, idx_b_last, merged_prev, merged_next );
#     else
      STACK_POP( idx_merge_parent, _idx_merge, idx_a, idx_b );
#     endif
      continue;
    }

    /* At this point, we have two non-empty treaps A and B to merge and
       we have stack space so we can use a fast recursive algorithm.  If
       A's root priority is below B's root priority, swap A and B. */

    TREAP_IDX_T prio_a = pool[ idx_a ].TREAP_PRIO;
    TREAP_IDX_T prio_b = pool[ idx_b ].TREAP_PRIO;
    int swap = (prio_a<prio_b) | ((prio_a==prio_b) & (int)(idx_a ^ idx_b));
    fd_swap_if( swap, idx_a,       idx_b       );
#   if TREAP_OPTIMIZE_ITERATION
    fd_swap_if( swap, idx_a_first, idx_b_first );
    fd_swap_if( swap, idx_a_last,  idx_b_last  );
#   endif

    /* At this point, we have two non-empty treaps to merge and A's root
       priority is higher than B's root priority.  So, we know the root
       of the merged treaps is A's root and can attach it to the output
       treap accordingly. */

    pool[ idx_a ].TREAP_PARENT = idx_merge_parent;
    *_idx_merge = idx_a;

    /* Get A's left and right subtrees */

    TREAP_IDX_T idx_a_left  = pool[ idx_a ].TREAP_LEFT;
    TREAP_IDX_T idx_a_right = pool[ idx_a ].TREAP_RIGHT;

    /* Split B by A's root key */

    TREAP_IDX_T idx_b_left;
    TREAP_IDX_T idx_b_right;
    TREAP_IDX_T idx_b_left_last;
    TREAP_IDX_T idx_b_right_first;
    TREAP_(private_split)( idx_b, &pool[ idx_a ], &idx_b_left, &idx_b_right, &idx_b_left_last, &idx_b_right_first, pool );

#   if TREAP_OPTIMIZE_ITERATION
    /* Split the iteration order links in B as well */
    TREAP_IDX_T dummy;
    *fd_ptr_if( TREAP_IDX_IS_NULL( idx_b_left_last   ), &dummy, &pool[ idx_b_left_last   ].TREAP_NEXT ) = TREAP_IDX_NULL;
    *fd_ptr_if( TREAP_IDX_IS_NULL( idx_b_right_first ), &dummy, &pool[ idx_b_right_first ].TREAP_PREV ) = TREAP_IDX_NULL;

    /* The first node in B's left subtree is the first node in B unless
       it is empty.  Similarly for B's right subtree. */
    TREAP_IDX_T idx_b_left_first = (TREAP_IDX_T)fd_ulong_if( TREAP_IDX_IS_NULL( idx_b_left  ), TREAP_IDX_NULL, idx_b_first );
    TREAP_IDX_T idx_b_right_last = (TREAP_IDX_T)fd_ulong_if( TREAP_IDX_IS_NULL( idx_b_right ), TREAP_IDX_NULL, idx_b_last  );
#   endif

    /* At this point, A's left subtree and B's left split are all keys
       to the left of A's root and A's right subtree.  Similarly, B's
       right split are all keys to the right of A's root and A's left
       subtree.  We can't do a fast join on A's left/right subtree and B's
       left/right split though as theses are not guaranteed to already
       have their keys distributed as required by join.  We instead
       recursively merge the left side and right side.  We do the left
       side first and the right side later (making this a cache oblivious
       algorithm too). */

#   if TREAP_OPTIMIZE_ITERATION
    STACK_PUSH( idx_a, &pool[ idx_a ].TREAP_RIGHT, idx_a_right, idx_b_right,
                pool[ idx_a ].TREAP_NEXT, idx_a_last, idx_b_right_first, idx_b_right_last, idx_a, merged_next );
#   else
    STACK_PUSH( idx_a, &pool[ idx_a ].TREAP_RIGHT, idx_a_right, idx_b_right );
#   endif

    idx_merge_parent = idx_a;
    _idx_merge       = &pool[ idx_a ].TREAP_LEFT;
#   if TREAP_OPTIMIZE_ITERATION
    idx_a_last       = pool[ idx_a ].TREAP_PREV;
    idx_b_first      = idx_b_left_first;
    idx_b_last       = idx_b_left_last;
    merged_next      = idx_a;
#   endif
    idx_a            = idx_a_left;
    idx_b            = idx_b_left;
  }

  treap_a->root     = new_root;
  treap_b->root     = TREAP_IDX_NULL;
  treap_a->ele_cnt += treap_b->ele_cnt;
  treap_b->ele_cnt  = 0UL;
# if TREAP_OPTIMIZE_ITERATION
  treap_b->first    = TREAP_IDX_NULL;
  treap_b->last     = TREAP_IDX_NULL;
# endif

  return treap_a;

# undef STACK_POP
# undef STACK_PUSH
# undef STACK_IS_FULL
# undef STACK_IS_EMPTY
# undef STACK_MAX
}

TREAP_STATIC TREAP_(fwd_iter_t)
TREAP_(fwd_iter_init)( TREAP_(t) const * treap,
                       TREAP_T const *   pool ) {
#if TREAP_OPTIMIZE_ITERATION
  (void)pool;
  return treap->first;
#else
  ulong i = TREAP_IDX_NULL;
  ulong j = (ulong)treap->root;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( j ) ) ) { i = j; j = (ulong)pool[ j ].TREAP_LEFT; }
  return i;
#endif
}

TREAP_STATIC TREAP_(rev_iter_t)
TREAP_(rev_iter_init)( TREAP_(t) const * treap,
                       TREAP_T const *   pool ) {
#if TREAP_OPTIMIZE_ITERATION
  (void)pool;
  return treap->last;
#else
  ulong i = TREAP_IDX_NULL;
  ulong j = (ulong)treap->root;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( j ) ) ) { i = j; j = (ulong)pool[ j ].TREAP_RIGHT; }
  return i;
#endif
}

TREAP_STATIC TREAP_(fwd_iter_t)
TREAP_(fwd_iter_next)( TREAP_(fwd_iter_t) i,
                       TREAP_T const *    pool ) {
#if TREAP_OPTIMIZE_ITERATION
  return pool[ i ].TREAP_NEXT;
#else
  ulong r = (ulong)pool[ i ].TREAP_RIGHT;

  if( TREAP_IDX_IS_NULL( r ) ) {
    ulong p = (ulong)pool[ i ].TREAP_PARENT;
    while( !TREAP_IDX_IS_NULL( p ) ) {
      if( i==(ulong)pool[ p ].TREAP_LEFT ) break;
      i = p;
      p = (ulong)pool[ p ].TREAP_PARENT;
    }
    return p;
  }

  i = r;
  for(;;) {
    ulong l = (ulong)pool[ i ].TREAP_LEFT;
    if( TREAP_IDX_IS_NULL( l ) ) break;
    i = l;
  }

  return i;
#endif
}

TREAP_STATIC TREAP_(rev_iter_t)
TREAP_(rev_iter_next)( TREAP_(rev_iter_t) i,
                       TREAP_T const *    pool ) {
#if TREAP_OPTIMIZE_ITERATION
  return pool[ i ].TREAP_PREV;
#else
  ulong l = (ulong)pool[ i ].TREAP_LEFT;

  if( TREAP_IDX_IS_NULL( l ) ) {
    ulong p = (ulong)pool[ i ].TREAP_PARENT;
    while( !TREAP_IDX_IS_NULL( p ) ) {
      if( i==(ulong)pool[ p ].TREAP_RIGHT ) break;
      i = p;
      p = (ulong)pool[ p ].TREAP_PARENT;
    }
    return p;
  }

  i = l;
  for(;;) {
    ulong r = (ulong)pool[ i ].TREAP_RIGHT;
    if( TREAP_IDX_IS_NULL( r ) ) break;
    i = r;
  }

  return i;
#endif
}

TREAP_STATIC int
TREAP_(verify)( TREAP_(t) const * treap,
                TREAP_T const *   pool ) {

# define TREAP_TEST( c ) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return -1; } } while(0)

  TREAP_TEST( treap ); /* Validate local join */

  ulong ele_max = treap->ele_max; TREAP_TEST( ele_max<=TREAP_IDX_NULL ); /* Validate ele_max */
  ulong ele_cnt = treap->ele_cnt; TREAP_TEST( ele_cnt<=ele_max        ); /* Validate ele_cnt */
  if( ele_max ) TREAP_TEST( pool );                                      /* Validate ele storage */

  /* Find leftmost */

  ulong i = TREAP_IDX_NULL;
  ulong l = (ulong)treap->root;

  ulong loop_cnt = 0UL;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( l ) ) ) {
    TREAP_TEST( loop_cnt<ele_cnt ); /* Make sure no cycles */
    TREAP_TEST( l       <ele_max ); /* Make sure valid index */
    i = l;
    l = (ulong)pool[ l ].TREAP_LEFT;
    loop_cnt++;
  }
#if TREAP_OPTIMIZE_ITERATION
  TREAP_TEST( treap->first==i );
#endif

  /* In-order traverse the treap starting from the leftmost */

  ulong cnt = 0UL; /* Number of elements we've visited so far */
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( i ) ) ) {
    TREAP_TEST( cnt<ele_cnt ); /* Make sure no cycles */

    /* At this point, we are visiting element i.  We've already visited
       all elements less than i and l is the last element we visited (or
       NULL if i is the first element we are visiting. */

    if( FD_LIKELY( !TREAP_IDX_IS_NULL( l ) ) ) TREAP_TEST( !TREAP_(lt)( pool + i, pool + l ) ); /* Make sure ordering valid */
#if TREAP_OPTIMIZE_ITERATION
    /* Check the l <-> i link */
    if( FD_LIKELY( !TREAP_IDX_IS_NULL( l ) ) ) TREAP_TEST( pool[ l ].TREAP_NEXT==i );
    if( FD_LIKELY( !TREAP_IDX_IS_NULL( i ) ) ) TREAP_TEST( pool[ i ].TREAP_PREV==l );
#endif


    ulong p = (ulong)pool[ i ].TREAP_PARENT;
    if( FD_LIKELY( !TREAP_IDX_IS_NULL( p ) ) ) {
      TREAP_TEST( p < ele_max );                                                /* Make sure valid index */
      TREAP_TEST( (ulong)pool[ p ].TREAP_PRIO >= (ulong)pool[ i ].TREAP_PRIO ); /* Make sure heap property valid */
    }

    /* Done visiting i, advance to i's successor */

    cnt++;

    l = i;

    ulong r = (ulong)pool[ i ].TREAP_RIGHT;
    if( TREAP_IDX_IS_NULL( r ) ) {

      /* i has no right subtree.  Look for first ancestor of i that we
         haven't visited (this will be the first ancestor for which i is
         in the ancestor's left subtree).  If there is no such ancestor,
         we are at the rightmost and we are done. */

      loop_cnt = 0UL;
      while( !TREAP_IDX_IS_NULL( p ) ) {
        TREAP_TEST( loop_cnt<ele_cnt ); /* Make sure no cycles */
        TREAP_TEST( p       <ele_max ); /* Make sure valid index */
        if( i==(ulong)pool[ p ].TREAP_LEFT ) break;
        i = p;
        p = (ulong)pool[ p ].TREAP_PARENT;
        loop_cnt++;
      }

      i = p;

    } else {

      /* i has a right subtree.  Find the leftmost in this subtree. */

      i = r;

      loop_cnt = 0UL;
      for(;;) {
        TREAP_TEST( loop_cnt<ele_cnt ); /* Make sure no cycles */
        TREAP_TEST( i       <ele_max ); /* Make sure valid index */
        ulong ll = (ulong)pool[ i ].TREAP_LEFT;
        if( TREAP_IDX_IS_NULL( ll ) ) break;
        i = ll;
        loop_cnt++;
      }

    }

  }

#if TREAP_OPTIMIZE_ITERATION
  TREAP_TEST( treap->last==l );
#endif

  TREAP_TEST( cnt==ele_cnt ); /* Make sure we visited correct number of elements */

# undef TREAP_TEST

  return 0;
}

#endif

#undef TREAP_IDX_IS_NULL
#undef TREAP_IDX_NULL
#undef TREAP_STATIC

#undef TREAP_IMPL_STYLE
#undef TREAP_NEXT
#undef TREAP_PREV
#undef TREAP_OPTIMIZE_ITERATION
#undef TREAP_PRIO
#undef TREAP_RIGHT
#undef TREAP_LEFT
#undef TREAP_PARENT
#undef TREAP_IDX_T
#undef TREAP_LT
#undef TREAP_CMP
#undef TREAP_QUERY_T
#undef TREAP_T
#undef TREAP_NAME

