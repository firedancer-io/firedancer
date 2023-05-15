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
   compresson for cache and memory bandwidth efficiency, etc.

   Typical usage:

     struct myele {

       ... Each field below can be located arbitrarily in the struct

       ulong parent; // Technically "TREAP_IDX_T TREAP_PARENT;" (default is ulong parent), similarly for left, right, and prio.
       ulong left;   // parent, left and right managed by the treap when a myele is in the treap.  prio is constant while in a
       ulong right;  // treap.  Further, all these can be used arbitrarily when not in treap (this includes perhaps using an
       ulong prio;   // anonymous union and/or bit fields for even more flexibility).  Additional considerations for prio below.

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
       ... avaiable for use when a myele is not in the treap.

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

     #define   TREAP_NAME      mytreap
     #define   TREAP_T         myele_t
     #define   TREAP_QUERY_T   char const *
     #define   TREAP_CMP(q,e)  strcmp( q, e->key )
     #define   TREAP_LT(e0,e1) (strcmp( e0->key, e1->key )<0)
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

     // mytreap_idx returns e's index.  Assumes e in ele or is NULL.
     // Return will be in [0,ele_max) or mytreap_idx_null().  Lifetime
     // is the element storage lifetime.  mytreap_idx_fast is the same
     // but assumes e is not NULL.  mytreap_ele returns a pointer in the
     // caller's address space to element idx.  Assumes idx is in
     // [0,ele_max) or is mytreap_idx_null().  Return pointer lifetime
     // is ele's local lifetime.  mytreap_ele_fast is the same but
     // assumes idx is not mytreap_idx_null().  mytreap_ele[_fast]_const
     // is a const correct version.

     ulong           mytreap_idx           ( myele_t const * e, myele_t const * ele );
     ulong           mytreap_idx_fast      ( myele_t const * e, myele_t const * ele );
     myele_t *       mytreap_ele           ( ulong           i, myele_t *       ele );
     myele_t *       mytreap_ele_fast      ( ulong           i, myele_t *       ele );
     myele_t const * mytreap_ele_const     ( ulong           i, myele_t const * ele );
     myele_t const * mytreap_ele_fast_const( ulong           i, myele_t const * ele );

     // mytreap_seed is a helper that sets ele[i].prio for i in
     // [0,ele_max) to a random value in [0,PRIO_MAX) (yes half-open)
     // where PRIO_MAX is the largest possible value representable in
     // the prio field.  Uses seed (arbitrary) to select a simple hash
     // based random number of sequence for prio.
     //
     // If an application wants to set this as optimally and securely as
     // possible, it should seed ele[i].prio with a cryptographic secure
     // uniform random permutation of [0,ele_max) and/or dynamically
     // manage the prio field as described above.

     void mytreap_seed( myele_t * ele, ulong ele_max, ulong seed );

     // mytreap_{align,footprint} returns the alignment and footprint
     // needed for a memory region to hold the state of a mytreap of
     // elements from an ele_max element storage.  align will be an
     // integer power-of-two and footprint will be a multiple of align.
     // footprint will non-zero on a success and 0 on failure (silent)
     // (e.g. ele_max too large for the specified TREAP_IDX_T).
     // mytreap_t is stack declaration, data segment declaration, heap
     // allocation and stack allocation friendly.  Even though footprint
     // is passed ele_max, the footprint is a small O(1) spatial
     // overhead.
     //
     // mytreap_new formats a memory region with the appropriate
     // alignment and footprint whose first byte in the caller's address
     // space is pointed to by shmem as a mytreap for elements from an
     // ele_max element storage.  Returns shmem on success and NULL on
     // failure (log details, e.g. ele_max is too large for the width of
     // the TREAP_IDX_T specified).  Caller is not joined on return.
     // The treap will be empty.
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
     // treap is a current local join and ele points in the caller's
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

     ulong           mytreap_idx_query      ( mytreap_t const * treap, char const * q, myele_t const * ele );
     myele_t *       mytreap_ele_query      ( mytreap_t *       treap, char const * q, myele_t *       ele );
     myele_t const * mytreap_ele_query_const( mytreap_t const * treap, char const * q, myele_t const * ele );

     // mytreap_idx_{insert,remove} inserts / removes element n/d into
     // the treap and returns treap.  Assumes treap is a current local
     // join, ele points in the caller's address space to the ele_max
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

     mytreap_t * mytreap_idx_insert( mytreap_t * treap, ulong     n, myele_t * ele );
     mytreap_t * mytreap_idx_remove( mytreap_t * treap, ulong     d, myele_t * ele );

     mytreap_t * mytreap_ele_insert( mytreap_t * treap, myele_t * n, myele_t * ele );
     mytreap_t * mytreap_ele_remove( mytreap_t * treap, myele_t * d, myele_t * ele );

     // mytreap_fwd_iter_{init,done,next,idx,ele,ele_const} provide an
     // in-order iterator from smallest to largest value.  Typical
     // usage:
     //
     //  for( mytreap_fwd_iter_t iter = mytreap_fwd_iter_init( treap, ele );
     //       !mytreap_fwd_iter_done( iter );
     //       iter = mytreap_fwd_iter_next( iter, ele ) ) {
     //     ulong i = mytreap_fwd_iter_idx( iter );
     //     ... or myele_t *       e = mytreap_fwd_iter_ele      ( iter, ele );
     //     ... or myele_t const * e = mytreap_fwd_iter_ele_const( iter, ele );
     //
     //     ... process i (or e) here
     //
     //     ... Do not insert / remove any elements from treap and do
     //     ... not change the element's parent, left, right, prio or
     //     ... queries here.  It is fine to run queries and other
     //     ... iterations concurrently.  Other fields are free to
     //     ... modify (from the treap's POV, the application manages
     //     ... concurrency for other fields).
     //  }

     typedef ... mytreap_fwd_iter_t;

     mytreap_fwd_iter_t mytreap_fwd_iter_init     ( mytreap_t const * treap, myele_t const * ele );
     int                mytreap_fwd_iter_done     ( mytreap_fwd_iter_t iter                      );
     mytreap_fwd_iter_t mytreap_fwd_iter_next     ( mytreap_fwd_iter_t iter, myele_t const * ele );
     ulong              mytreap_fwd_iter_idx      ( mytreap_fwd_iter_t iter                      );
     myele_t *          mytreap_fwd_iter_ele      ( mytreap_fwd_iter_t iter, myele_t *       ele );
     myele_t const *    mytreap_fwd_iter_ele_const( mytreap_fwd_iter_t iter, myele_t const * ele );

     // mytreap_rev_iter_{init,done,next,idx,ele,ele_const} is the same
     // but used when interating from largest to smallest.

     typedef ... mytreap_rev_iter_t;

     mytreap_rev_iter_t mytreap_rev_iter_init     ( mytreap_t const * treap, myele_t const * ele );
     int                mytreap_rev_iter_done     ( mytreap_rev_iter_t iter                      );
     mytreap_rev_iter_t mytreap_rev_iter_next     ( mytreap_rev_iter_t iter, myele_t const * ele );
     ulong              mytreap_rev_iter_idx      ( mytreap_rev_iter_t iter                      );
     myele_t *          mytreap_rev_iter_ele      ( mytreap_rev_iter_t iter, myele_t *       ele );
     myele_t const *    mytreap_rev_iter_ele_const( mytreap_rev_iter_t iter, myele_t const * ele );

     // mytreap_verify returns 0 if the mytreap is not obviously corrupt
     // or a -1 (i.e. ERR_INVAL) if it is (logs details).  treap is
     // current local join to a mytreap.

     int mytreap_verify( mytreap_t const * treap, myele_t const * ele );

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
   fields and returns a negatve/zero/positive int if q is less
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
  TREAP_IDX_T root;    /* Index of the root treap element, in [0,ele_max) or TREAP_IDX_NULL */
};

typedef struct TREAP_(private) TREAP_(t);

typedef ulong TREAP_(fwd_iter_t);
typedef ulong TREAP_(rev_iter_t);

FD_PROTOTYPES_BEGIN

/* prototypes */

TREAP_STATIC void TREAP_(seed)( TREAP_T * ele, ulong ele_max, ulong seed );

TREAP_STATIC FD_FN_CONST ulong       TREAP_(align)    ( void                              );
TREAP_STATIC FD_FN_CONST ulong       TREAP_(footprint)( ulong       ele_max               );
TREAP_STATIC /**/        void *      TREAP_(new)      ( void *      shmem,  ulong ele_max );
TREAP_STATIC /**/        TREAP_(t) * TREAP_(join)     ( void *      shtreap               );
TREAP_STATIC /**/        void *      TREAP_(leave)    ( TREAP_(t) * treap                 );
TREAP_STATIC /**/        void *      TREAP_(delete)   ( void *      shtreap               );

TREAP_STATIC FD_FN_PURE ulong TREAP_(idx_query)( TREAP_(t) const * treap, TREAP_QUERY_T q, TREAP_T const * ele );

TREAP_STATIC TREAP_(t) * TREAP_(idx_insert)( TREAP_(t) * treap, ulong n, TREAP_T * ele );
TREAP_STATIC TREAP_(t) * TREAP_(idx_remove)( TREAP_(t) * treap, ulong d, TREAP_T * ele );

TREAP_STATIC FD_FN_PURE TREAP_(fwd_iter_t) TREAP_(fwd_iter_init)( TREAP_(t) const * treap, TREAP_T const * ele ); 
TREAP_STATIC FD_FN_PURE TREAP_(rev_iter_t) TREAP_(rev_iter_init)( TREAP_(t) const * treap, TREAP_T const * ele );

TREAP_STATIC FD_FN_PURE TREAP_(fwd_iter_t) TREAP_(fwd_iter_next)( TREAP_(fwd_iter_t) i, TREAP_T const * ele );
TREAP_STATIC FD_FN_PURE TREAP_(rev_iter_t) TREAP_(rev_iter_next)( TREAP_(rev_iter_t) i, TREAP_T const * ele );

TREAP_STATIC FD_FN_PURE int TREAP_(verify)( TREAP_(t) const * treap, TREAP_T const * ele );

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
             TREAP_T const * ele ) {
  return fd_ulong_if( !!e, (ulong)(e-ele), TREAP_IDX_NULL );
}

FD_FN_CONST static inline TREAP_T *
TREAP_(ele)( ulong     i,
             TREAP_T * ele ) {
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), ele+i, NULL );
}

FD_FN_CONST static inline TREAP_T const *
TREAP_(ele_const)( ulong           i,
                   TREAP_T const * ele ) {
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), ele+i, NULL );
}

FD_FN_CONST static inline ulong
TREAP_(idx_fast)( TREAP_T const * e,
                  TREAP_T const * ele ) {
  return (ulong)(e-ele);
}

FD_FN_CONST static inline TREAP_T *       TREAP_(ele_fast)      ( ulong i, TREAP_T *       ele ) { return ele+i; }
FD_FN_CONST static inline TREAP_T const * TREAP_(ele_fast_const)( ulong i, TREAP_T const * ele ) { return ele+i; }

FD_FN_PURE static inline ulong TREAP_(ele_max)( TREAP_(t) const * treap ) { return treap->ele_max; }
FD_FN_PURE static inline ulong TREAP_(ele_cnt)( TREAP_(t) const * treap ) { return treap->ele_cnt; }

FD_FN_PURE static inline TREAP_T *
TREAP_(ele_query)( TREAP_(t) const * treap,
                   TREAP_QUERY_T     q,
                   TREAP_T *         ele ) {
  ulong i = TREAP_(idx_query)( treap, q, ele );
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), ele + i, NULL );
}

FD_FN_PURE static inline TREAP_T const *
TREAP_(ele_query_const)( TREAP_(t) const * treap,
                         TREAP_QUERY_T     q,
                         TREAP_T const *   ele ) {
  ulong i = TREAP_(idx_query)( treap, q, ele );
  return fd_ptr_if( !TREAP_IDX_IS_NULL( i ), ele + i, NULL );
}

static inline TREAP_(t) *
TREAP_(ele_insert)( TREAP_(t) * treap,
                    TREAP_T *   e,
                    TREAP_T *   ele ) {
  TREAP_(idx_insert)( treap, (ulong)(e-ele), ele );
  return treap;
}

static inline TREAP_(t) *
TREAP_(ele_remove)( TREAP_(t) * treap,
                    TREAP_T *   e,
                    TREAP_T *   ele ) {
  TREAP_(idx_remove)( treap, (ulong)(e-ele), ele );
  return treap;
}

FD_FN_CONST static inline int             TREAP_(fwd_iter_done)     ( TREAP_(fwd_iter_t) i ) { return TREAP_IDX_IS_NULL( i ); }
FD_FN_CONST static inline ulong           TREAP_(fwd_iter_idx)      ( TREAP_(fwd_iter_t) i                      ) { return i;     }
FD_FN_CONST static inline TREAP_T *       TREAP_(fwd_iter_ele)      ( TREAP_(fwd_iter_t) i, TREAP_T *       ele ) { return ele+i; }
FD_FN_CONST static inline TREAP_T const * TREAP_(fwd_iter_ele_const)( TREAP_(fwd_iter_t) i, TREAP_T const * ele ) { return ele+i; }

FD_FN_CONST static inline int             TREAP_(rev_iter_done)     ( TREAP_(rev_iter_t) i ) { return TREAP_IDX_IS_NULL( i ); }
FD_FN_CONST static inline ulong           TREAP_(rev_iter_idx)      ( TREAP_(rev_iter_t) i                      ) { return i;     }
FD_FN_CONST static inline TREAP_T *       TREAP_(rev_iter_ele)      ( TREAP_(rev_iter_t) i, TREAP_T *       ele ) { return ele+i; }
FD_FN_CONST static inline TREAP_T const * TREAP_(rev_iter_ele_const)( TREAP_(rev_iter_t) i, TREAP_T const * ele ) { return ele+i; }

FD_PROTOTYPES_END

#endif

#if TREAP_IMPL_STYLE!=1 /* need implementations */

TREAP_STATIC void
TREAP_(seed)( TREAP_T * ele,
              ulong     ele_max,
              ulong     seed ) {
  for( ulong ele_idx=0UL; ele_idx<ele_max; ele_idx++ ) {
    ulong r = fd_ulong_hash( ele_idx ^ seed ) & TREAP_IDX_NULL;
    ele[ ele_idx ].TREAP_PRIO = (TREAP_IDX_T)(r - (ulong)(r==TREAP_IDX_NULL));
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
                   TREAP_T const *   ele ) {
  ulong i = (ulong)treap->root;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( i ) ) ) { /* Optimize for found */
    ulong l = (ulong)ele[ i ].TREAP_LEFT;
    ulong r = (ulong)ele[ i ].TREAP_RIGHT;
    int   c = TREAP_(cmp)( q, ele + i );
    if( FD_UNLIKELY( !c ) ) break; /* Optimize for larger treaps */
    i = fd_ulong_if( c<0, l, r );
  }
  return i;
}

TREAP_STATIC TREAP_(t) *
TREAP_(idx_insert)( TREAP_(t) * treap,
                    ulong       n,
                    TREAP_T *   ele ) {

  /* Find leaf where to insert n */

  TREAP_IDX_T * _p_child = &treap->root;

  ulong i = TREAP_IDX_NULL;
  for(;;) {
    ulong j = (ulong)*_p_child;
    if( FD_UNLIKELY( TREAP_IDX_IS_NULL( j ) ) ) break; /* Optimize for large treap */
    i = j;
    _p_child = fd_ptr_if( TREAP_(lt)( ele + n, ele + i ), &ele[ i ].TREAP_LEFT, &ele[ i ].TREAP_RIGHT );
  }

  /* Insert n.  This might momentarily break the heap property. */

  ele[ n ].TREAP_PARENT = (TREAP_IDX_T)i;
  ele[ n ].TREAP_LEFT   = (TREAP_IDX_T)TREAP_IDX_NULL;
  ele[ n ].TREAP_RIGHT  = (TREAP_IDX_T)TREAP_IDX_NULL;
  *_p_child = (TREAP_IDX_T)n;

  /* Bubble n up until the heap property is restored. */

  ulong n_prio = (ulong)ele[ n ].TREAP_PRIO;
  while( !TREAP_IDX_IS_NULL( i ) ) {
    ulong i_prio = (ulong)ele[ i ].TREAP_PRIO;

    int heap_intact = (n_prio<i_prio) | ((n_prio==i_prio) & (!((n ^ i) & 1UL))); /* Flip coin on equal priority */
    if( heap_intact ) break;

    /* Get i's parent (if any) and parent's link to i (tree root link if no parent) */

    ulong p = (ulong)ele[ i ].TREAP_PARENT;

    TREAP_IDX_T * _t0      = fd_ptr_if( TREAP_IDX_IS_NULL( p ), &treap->root, &ele[ p ].TREAP_LEFT  );
    /**/          _p_child = fd_ptr_if( i==(ulong)*_t0,         _t0,          &ele[ p ].TREAP_RIGHT );

    /* Get n's child (if any) that will become i's child */

    int           n_is_left_child = (n==(ulong)ele[ i ].TREAP_LEFT);
    TREAP_IDX_T * _n_child        = fd_ptr_if( n_is_left_child, &ele[ n ].TREAP_RIGHT, &ele[ n ].TREAP_LEFT );
    ulong         j               = (ulong)*_n_child;

    /* Make n child of p (or the root if no parent) */

    *_p_child             = (TREAP_IDX_T)n;
    ele[ n ].TREAP_PARENT = (TREAP_IDX_T)p;

    /* Make i child of n */

    *_n_child             = (TREAP_IDX_T)i;
    ele[ i ].TREAP_PARENT = (TREAP_IDX_T)n;

    /* Make j (if present) child of i */

    TREAP_IDX_T dummy;
    *fd_ptr_if( n_is_left_child,        &ele[ i ].TREAP_LEFT, &ele[ i ].TREAP_RIGHT  ) = (TREAP_IDX_T)j;
    *fd_ptr_if( TREAP_IDX_IS_NULL( j ), &dummy,               &ele[ j ].TREAP_PARENT ) = (TREAP_IDX_T)i;

    /* Keep bubbling up */

    i = p;
  }

  treap->ele_cnt++;
  return treap;
}

TREAP_(t) *
TREAP_(idx_remove)( TREAP_(t) * treap,
                    ulong       d,
                    TREAP_T *   ele ) {

  /* Make a hole at d */

  ulong p = (ulong)ele[ d ].TREAP_PARENT;
  ulong l = (ulong)ele[ d ].TREAP_LEFT;
  ulong r = (ulong)ele[ d ].TREAP_RIGHT;

  TREAP_IDX_T * _t0      = fd_ptr_if( TREAP_IDX_IS_NULL( p ), &treap->root, &ele[ p ].TREAP_LEFT  );
  TREAP_IDX_T * _p_child = fd_ptr_if( d==(ulong)*_t0,         _t0,          &ele[ p ].TREAP_RIGHT );

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
      *( fd_ptr_if( !is_null_left,  &ele[ l ].TREAP_PARENT,
         fd_ptr_if( !is_null_right, &ele[ r ].TREAP_PARENT, &dummy ) ) ) = (TREAP_IDX_T)p;
      break;
    }

    /* The hole has two subtrees.  We bubble the hole down one, fill the
       hole with the root of the subtree that will preserve the heap
       priority up to the hole (flipping a coin on ties).  Note we don't
       need to update any links to/from d as we will be getting rid of
       all links / from d. */

    ulong l_prio = (ulong)ele[ l ].TREAP_PRIO;
    ulong r_prio = (ulong)ele[ r ].TREAP_PRIO;

    int promote_left = (l_prio>r_prio) | ((l_prio==r_prio) & (!((p ^ d) & 1UL)));

    ulong c = fd_ulong_if( promote_left, l, r );

    *_p_child = (TREAP_IDX_T)c;
    ele[ c ].TREAP_PARENT = (TREAP_IDX_T)p;

    _p_child = fd_ptr_if  ( promote_left, &ele[ l ].TREAP_RIGHT, &ele[ r ].TREAP_LEFT  );
    p        = c;
    l        = fd_ulong_if( promote_left,  ele[ l ].TREAP_RIGHT,  l                    );
    r        = fd_ulong_if( promote_left,  r,                     ele[ r ].TREAP_LEFT  );

  }

  treap->ele_cnt--;
  return treap;
}

TREAP_STATIC TREAP_(fwd_iter_t)
TREAP_(fwd_iter_init)( TREAP_(t) const * treap,
                       TREAP_T const *   ele ) {
  ulong i = TREAP_IDX_NULL;
  ulong j = (ulong)treap->root;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( j ) ) ) { i = j; j = (ulong)ele[ j ].TREAP_LEFT; }
  return i;
}

TREAP_STATIC TREAP_(rev_iter_t)
TREAP_(rev_iter_init)( TREAP_(t) const * treap,
                       TREAP_T const *   ele ) {
  ulong i = TREAP_IDX_NULL;
  ulong j = (ulong)treap->root;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( j ) ) ) { i = j; j = (ulong)ele[ j ].TREAP_RIGHT; }
  return i;
}

TREAP_STATIC TREAP_(fwd_iter_t)
TREAP_(fwd_iter_next)( TREAP_(fwd_iter_t) i,
                       TREAP_T const *    ele ) {
  ulong r = (ulong)ele[ i ].TREAP_RIGHT;

  if( TREAP_IDX_IS_NULL( r ) ) {
    ulong p = (ulong)ele[ i ].TREAP_PARENT;
    while( !TREAP_IDX_IS_NULL( p ) ) {
      if( i==(ulong)ele[ p ].TREAP_LEFT ) break;
      i = p;
      p = (ulong)ele[ p ].TREAP_PARENT;
    }
    return p;
  }

  i = r;
  for(;;) {
    ulong l = (ulong)ele[ i ].TREAP_LEFT;
    if( TREAP_IDX_IS_NULL( l ) ) break;
    i = l;
  }

  return i;
}

TREAP_STATIC TREAP_(rev_iter_t)
TREAP_(rev_iter_next)( TREAP_(rev_iter_t) i,
                       TREAP_T const *    ele ) {
  ulong l = (ulong)ele[ i ].TREAP_LEFT;

  if( TREAP_IDX_IS_NULL( l ) ) {
    ulong p = (ulong)ele[ i ].TREAP_PARENT;
    while( !TREAP_IDX_IS_NULL( p ) ) {
      if( i==(ulong)ele[ p ].TREAP_RIGHT ) break;
      i = p;
      p = (ulong)ele[ p ].TREAP_PARENT;
    }
    return p;
  }

  i = l;
  for(;;) {
    ulong r = (ulong)ele[ i ].TREAP_RIGHT; 
    if( TREAP_IDX_IS_NULL( r ) ) break;
    i = r;
  }

  return i;
}

TREAP_STATIC int
TREAP_(verify)( TREAP_(t) const * treap,
                TREAP_T const *   ele ) {

# define TREAP_TEST( c ) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return -1; } } while(0)

  TREAP_TEST( treap ); /* Validate local join */

  ulong ele_max = treap->ele_max; TREAP_TEST( ele_max<=TREAP_IDX_NULL ); /* Validate ele_max */
  ulong ele_cnt = treap->ele_cnt; TREAP_TEST( ele_cnt<=ele_max        ); /* Validate ele_cnt */
  if( ele_max ) TREAP_TEST( ele );                                       /* Validate ele storage */

  /* Find leftmost */

  ulong i = TREAP_IDX_NULL;
  ulong l = (ulong)treap->root;

  ulong loop_cnt = 0UL;
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( l ) ) ) {
    TREAP_TEST( loop_cnt<ele_cnt ); /* Make sure no cycles */
    TREAP_TEST( l       <ele_max ); /* Make sure valid index */
    i = l;
    l = (ulong)ele[ l ].TREAP_LEFT;
    loop_cnt++;
  }

  /* In-order traverse the treap starting from the leftmost */

  ulong cnt = 0UL; /* Number of elements we've visited so far */
  while( FD_LIKELY( !TREAP_IDX_IS_NULL( i ) ) ) {
    TREAP_TEST( cnt<ele_cnt ); /* Make sure no cycles */

    /* At this point, we are visiting element i.  We've already visited
       all elements less than i and l is the last element we visited (or
       NULL if i is the first element we are visiting. */

    if( FD_LIKELY( !TREAP_IDX_IS_NULL( l ) ) ) TREAP_TEST( TREAP_(lt)( ele + l, ele + i ) ); /* Make sure ordering valid */

    ulong p = (ulong)ele[ i ].TREAP_PARENT;
    if( FD_LIKELY( !TREAP_IDX_IS_NULL( p ) ) ) {
      TREAP_TEST( p < ele_max );                                              /* Make sure valid index */
      TREAP_TEST( (ulong)ele[ p ].TREAP_PRIO >= (ulong)ele[ i ].TREAP_PRIO ); /* Make sure heap property valid */
    }

    /* Done visiting i, advance to i's successor */

    cnt++;

    l = i;

    ulong r = (ulong)ele[ i ].TREAP_RIGHT;
    if( TREAP_IDX_IS_NULL( r ) ) {

      /* i has no right subtree.  Look for first ancestor of i that we
         haven't visited (this will be the first ancestor for which i is
         in the ancestor's left subtree).  If there is no such ancestor,
         we are at the rightmost and we are done. */

      loop_cnt = 0UL;
      while( !TREAP_IDX_IS_NULL( p ) ) {
        TREAP_TEST( loop_cnt<ele_cnt ); /* Make sure no cycles */
        TREAP_TEST( p       <ele_max ); /* Make sure valid index */
        if( i==(ulong)ele[ p ].TREAP_LEFT ) break;
        i = p;
        p = (ulong)ele[ p ].TREAP_PARENT;
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
        l = (ulong)ele[ i ].TREAP_LEFT;
        if( TREAP_IDX_IS_NULL( l ) ) break;
        i = l;
        loop_cnt++;
      }

    }

  }

  TREAP_TEST( cnt==ele_cnt ); /* Make sure we visited correct number of elements */

# undef TREAP_TEST

  return 0;
}

#endif

#undef TREAP_IDX_IS_NULL
#undef TREAP_IDX_NULL
#undef TREAP_STATIC

#undef TREAP_IMPL_STYLE
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

