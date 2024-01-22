/* Generate prototypes, inlines and implementations for ultra high
   performance zero copy heaps for use in situations where the heap
   elements are not stored sequentially in memory (textbook heap
   algorithms, including prq, assume the heap elements will be stored in
   an array such that the root, parent, left/right children and next
   heap element to use are all implied by the element cnt and array
   indices ... also worth noting that this API does assume that heap
   elements themselves are embedded in a linear addressable storage
   region such as a fd_pool for persistence and relocatability though).

   This API is designed for ultra tight coupling with pools, maps, other
   heaps, etc.  Likewise, a heap can be persisted beyond the lifetime of
   creating process, used concurrently in many common operations, used
   inter-process, relocated in memory, naively serialized/deserialized,
   moved between hosts, supports index compression for cache and memory
   bandwidth efficiency, etc.

   Typical usage:

     struct myele {

       ... Each field below can be located arbitrarily in the struct

       ulong left;  // Technically "HEAP_IDX_T HEAP_LEFT;" (default is ulong left), similarly for right.
       ulong right; // These are managed by the heap when a myele is in the heap.

       ... Note that other kinds of objects can use these fields for
       ... their metadata needs to keep element metadata / cache
       ... footprint overheads minimal.  The only restriction is that
       ... they cannot concurrently use the same field.

       ... Note that fields could be in an anonymous union and/or made
       ... into narrow bit fields if useful for additional layout,
       ... memory, bandwidth and cache efficiency.

       ... Arbitrary application fields mixed in here.  Power-of-2
       ... element sizes have good cache and indexing Feng Shui.

       char key[ KEY_MAX ]; // For demonstration purposes

     };

     typedef struct myele myele_t;

     #define HEAP_NAME      myheap
     #define HEAP_T         myele_t
     #define HEAP_LT(e0,e1) (strcmp( e0->key, e1->key )<0)
     #include "fd_heap.c"

   will declare the following APIs as a header-only style library in the
   compilation unit:

     int myheap_lt( myele_t const * e0, myele_t const * e1 ); // Provides HEAP_LT

     // myheap_idx_null returns the element index used to represent
     // NULL, infinite lifetime.  myheap_ele_null returns NULL, infinite
     // lifetime, for completeness, myheap_ele_null_const is a
     // const-correct version, also for completeness.

     ulong           myheap_idx_null      ( void );
     myele_t *       myheap_ele_null      ( void );
     myele_t const * myheap_ele_null_const( void );

     // myheap_{idx,ele}_is_null returns i==myheap_idx_null() / !e

     int myheap_idx_is_null( ulong           i );
     int myheap_ele_is_null( myele_t const * e );

     // myheap_idx returns e's index.  Assumes e is a pointer in the
     // caller's local address space to a pool element or is NULL.
     // Return will be in [0,ele_max) or myheap_idx_null().  Lifetime is
     // the element storage lifetime.  myheap_idx_fast is the same but
     // assumes e is not NULL.  pool is a pointer in the caller's
     // address space to the ele_max linearly addressable storage region
     // backing the heap.

     ulong myheap_idx     ( myele_t const * e, myele_t const * pool );
     ulong myheap_idx_fast( myele_t const * e, myele_t const * pool );

     // myheap_ele returns a pointer in the caller's address space to
     // element idx.  Assumes idx is in [0,ele_max) or is
     // myheap_idx_null().  Return pointer lifetime is ele's local
     // lifetime.  myheap_ele_fast is the same but assumes idx is not
     // myheap_idx_null().  myheap_ele[_fast]_const is a const correct
     // version.  pool is a pointer in the caller's address space to the
     // ele_max linearly addressable storage region backing the heap.

     myele_t * myheap_ele     ( ulong i, myele_t * pool );
     myele_t * myheap_ele_fast( ulong i, myele_t * pool );

     myele_t const * myheap_ele_const     ( ulong i, myele_t const * pool );
     myele_t const * myheap_ele_fast_const( ulong i, myele_t const * pool );

     // myheap_{align,footprint} returns the alignment and footprint
     // needed for a memory region to hold the state of a myheap of
     // elements from an ele_max element storage.  align will be an
     // integer power-of-two and footprint will be a multiple of align.
     // footprint will non-zero on a success and 0 on failure (silent)
     // (e.g. ele_max too large for the specified HEAP_IDX_T).  myheap_t
     // is stack declaration, data segment declaration, heap allocation
     // and stack allocation friendly.  Even though footprint is passed
     // ele_max, the footprint is a small O(1) spatial overhead.
     //
     // myheap_new formats a memory region with the appropriate
     // alignment and footprint whose first byte in the caller's address
     // space is pointed to by shmem as a myheap for elements from an
     // ele_max element storage.  Returns shmem on success and NULL on
     // failure (log details, e.g. ele_max is too large for the width of
     // the HEAP_IDX_T specified).  Caller is not joined on return.  The
     // heap will be empty.
     //
     // myheap_join joins a myheap.  Assumes shheap points at a memory
     // region formatted as a myheap in the caller's address space.
     // Returns a handle to the caller's local join on success and NULL
     // on failure (logs details).
     //
     // myheap_leave leaves a myheap.  Assumes join points to a current
     // local join.  Returns shheap used on join and NULL on failure
     // (logs details).
     //
     // myheap_delete unformats a memory region used as a myheap.
     // Assumes shheap points to a memory region in the caller's local
     // address space formatted as a myheap, that there are no joins to
     // the myheap and that any application side cleanups have been
     // done.  Returns shheap on success and NULL on failure (logs
     // details).

     ulong      myheap_align    ( void                             );
     ulong      myheap_footprint( ulong      ele_max               );
     void *     myheap_new      ( void *     shmem,  ulong ele_max );
     myheap_t * myheap_join     ( void *     shheap                );
     void *     myheap_leave    ( myheap_t * heap                  );
     void *     myheap_delete   ( void *     shheap                );

     // myheap_{ele_max,ele_cnt} gives the maximum number of elements
     // the heap can support / the current number of elements in the
     // heap.  Assumes heap is a current local join.  These might be
     // deprecated in the future.

     ulong myheap_ele_max( myheap_t const * heap );
     ulong myheap_ele_cnt( myheap_t const * heap );

     // myheap_idx_peek_min returns the index where the minimum element
     // is on the heap.  Returns [0,ele_max) on success and
     // myheap_idx_null() if the heap is empty.  Lifetime of the
     // returned idx is the lesser of until the min element is removed
     // or the underlying element storage lifetime.  myheap_ele_peek_min
     // is the same but returns the location in the caller's address
     // space of the found element on success and NULL on failure
     // (lifetime of the returned pointer is until the min element is
     // removed or ele's local lifetime).  myheap_ele_peek_min_const is
     // a const correct version.  These operations are a fast O(1).
     // pool is a pointer in the caller's address space to the ele_max
     // linearly addressable storage region backing the heap.

     ulong           myheap_idx_peek_min      ( myheap_t const * heap, char const * q, myele_t const * pool );
     myele_t *       myheap_ele_peek_min      ( myheap_t *       heap, char const * q, myele_t *       pool );
     myele_t const * myheap_ele_peek_min_const( myheap_t const * heap, char const * q, myele_t const * pool );

     // myheap_idx_insert inserts element n into the heap and returns
     // heap.  Assumes heap is a current local join, ele points in the
     // caller's address space to the ele_max element storage used for
     // heap elements, n is in [0,ele_max), n is currently not in the
     // heap, and n's queries are not in the heap (n's queries are the
     // set of queries that are covered by n).  pool is a pointer in the
     // caller's address space to the ele_max linearly addressable
     // storage region backing the heap.  Given these assumptions, this
     // cannot fail.
     //
     // n's query fields should already be populated (i.e.
     // MYHEAP_LT(ele+n,ele+i) should return valid results before this
     // is called).  On return, n and n's queries will be in the heap.
     // n's left and right should not be modified while n is in the
     // heap.  Further, the caller should not assume n's left and right
     // values are stable while n is in the heap.  The heap does not
     // care about any other fields and these can be modified by the
     // user as necessary.
     //
     // myheap_ele_insert is the same but n points in the caller's local
     // address space the element to insert / remove.
     //
     // These operations have HPC implementations and are O(lg N)
     // average with an ultra high probability of having a small
     // coefficient.

     myheap_t * myheap_idx_insert( myheap_t * heap, ulong     n, myele_t * pool );
     myheap_t * myheap_ele_insert( myheap_t * heap, myele_t * n, myele_t * pool );

     // myheap_idx_remove_min removes the min element from the heap and
     // returns heap.  Assumes heap is a current local join, ele points
     // in the caller's address space to the ele_max element storage
     // used for heap elements and the heap has at least one element.
     // pool is a pointer in the caller's address space to the ele_max
     // linearly addressable storage region backing the heap.  Given
     // these assumptions, this cannot fail.
     //
     // On return the min element and the min element's queries are no
     // longer in the heap.  Use peek before calling this to get the
     // location of the min element to be removed.  The fields of the
     // removed element can be freely modified on return.
     //
     // myheap_ele_remove_min is the same and just for naming
     // consistency.
     //
     // These operations have HPC implementations and are O(lg N)
     // average with an ultra high probability of having a small
     // coefficient (i.e. close to algorithmically optimal trees).

     myheap_t * myheap_idx_remove_min( myheap_t * heap, myele_t * pool );
     myheap_t * myheap_ele_remove_min( myheap_t * heap, myele_t * pool );

     // myheap_verify returns 0 if the myheap is not obviously corrupt
     // or a -1 (i.e. ERR_INVAL) if it is (logs details).  heap is a
     // current local join to a myheap.  pool is a pointer in the
     // caller's address space to the ele_max linearly addressable
     // storage region backing the heap.

     int myheap_verify( myheap_t const * heap, myele_t const * pool );

   You can do this as often as you like within a compilation unit to get
   different types of heaps.  Variants exist for making separate headers
   and implementations for doing libraries and handling multiple
   compilation units.  Additional options exist as detailed below. */

/* HEAP_NAME gives the API prefix to use */

#ifndef HEAP_NAME
#error "Define HEAP_NAME"
#endif

/* HEAP_T is the heap element type */

#ifndef HEAP_T
#error "Define HEAP_T"
#endif

/* HEAP_LT returns 1 if the element e0's query fields are strictly less
   element e1's query fields and 0 otherwise.  Should be a pure
   function. */

#ifndef HEAP_LT
#error "Define HEAP_LT"
#endif

/* HEAP_IDX_T is the type used for the HEAP_T fields.  Should be a
   primitive unsigned integer type.  Defaults to ulong.  A heap can't
   use element memory regions that contain more than the maximum value
   that can be represented by a HEAP_IDX_T. */

#ifndef HEAP_IDX_T
#define HEAP_IDX_T ulong
#endif

/* HEAP_{LEFT,RIGHT} is the name of the heap element left / right
   fields.  Defaults to left / right. */

#ifndef HEAP_LEFT
#define HEAP_LEFT left
#endif

#ifndef HEAP_RIGHT
#define HEAP_RIGHT right
#endif

/* HEAP_IMPL_STYLE controls what this template should emit.
   0 - local use only
   1 - library header
   2 - library implementation */

#ifndef HEAP_IMPL_STYLE
#define HEAP_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

#if HEAP_IMPL_STYLE==0
#define HEAP_STATIC static FD_FN_UNUSED
#else
#define HEAP_STATIC
#endif

#define HEAP_IDX_NULL           ((ulong)(HEAP_IDX_T)(~0UL))
#define HEAP_IDX_IS_NULL( idx ) ((idx)==HEAP_IDX_NULL)

#define HEAP_(n) FD_EXPAND_THEN_CONCAT3(HEAP_NAME,_,n)

/* Verification logs details on failure.  The rest only needs fd_bits.h
   (consider making logging a compile time option). */

#include "../log/fd_log.h"

#if HEAP_IMPL_STYLE!=2 /* need structures, prototypes and inlines */

/* structures */

/* TODO: consider eliminating ele_cnt and maybe ele_max fields (less overhead,
   faster bulk ops, concurrency options, simpler constructors, etc) */

struct HEAP_(private) {
  ulong      ele_max; /* Maximum number of elements in heap, in [0,HEAP_IDX_NULL] */
  ulong      ele_cnt; /* Current number of elements in heap, in [0,ele_max] */
  HEAP_IDX_T root;    /* Index of the root heap element, in [0,ele_max) or HEAP_IDX_NULL */
};

typedef struct HEAP_(private) HEAP_(t);

FD_PROTOTYPES_BEGIN

/* prototypes */

HEAP_STATIC FD_FN_CONST ulong      HEAP_(align)    ( void                             );
HEAP_STATIC FD_FN_CONST ulong      HEAP_(footprint)( ulong      ele_max               );
HEAP_STATIC /**/        void *     HEAP_(new)      ( void *     shmem,  ulong ele_max );
HEAP_STATIC /**/        HEAP_(t) * HEAP_(join)     ( void *     shheap                );
HEAP_STATIC /**/        void *     HEAP_(leave)    ( HEAP_(t) * heap                  );
HEAP_STATIC /**/        void *     HEAP_(delete)   ( void *     shheap                );

HEAP_STATIC HEAP_(t) * HEAP_(idx_insert)( HEAP_(t) * heap, ulong n, HEAP_T * pool );

HEAP_STATIC HEAP_(t) * HEAP_(idx_remove_min)( HEAP_(t) * heap, HEAP_T * pool );

HEAP_STATIC FD_FN_PURE int HEAP_(verify)( HEAP_(t) const * heap, HEAP_T const * pool );

/* inlines */

FD_FN_PURE static inline int HEAP_(lt) ( HEAP_T const * e0, HEAP_T const * e1 ) { return HEAP_LT( e0, e1 ); }

FD_FN_CONST static inline ulong          HEAP_(idx_null)      ( void ) { return HEAP_IDX_NULL; }
FD_FN_CONST static inline HEAP_T *       HEAP_(ele_null)      ( void ) { return NULL;          }
FD_FN_CONST static inline HEAP_T const * HEAP_(ele_null_const)( void ) { return NULL;          }

FD_FN_CONST static inline int HEAP_(idx_is_null)( ulong          i ) { return HEAP_IDX_IS_NULL( i ); }
FD_FN_CONST static inline int HEAP_(ele_is_null)( HEAP_T const * e ) { return !e;                    }

FD_FN_CONST static inline ulong
HEAP_(idx)( HEAP_T const * e,
            HEAP_T const * pool ) {
  return fd_ulong_if( !!e, (ulong)(e-pool), HEAP_IDX_NULL );
}

FD_FN_CONST static inline HEAP_T *
HEAP_(ele)( ulong    i,
            HEAP_T * pool ) {
  return fd_ptr_if( !HEAP_IDX_IS_NULL( i ), pool + i, NULL );
}

FD_FN_CONST static inline HEAP_T const *
HEAP_(ele_const)( ulong          i,
                  HEAP_T const * pool ) {
  return fd_ptr_if( !HEAP_IDX_IS_NULL( i ), pool + i, NULL );
}

FD_FN_CONST static inline ulong          HEAP_(idx_fast)      ( HEAP_T const * e, HEAP_T const * pool ) { return (ulong)(e - pool); }
FD_FN_CONST static inline HEAP_T *       HEAP_(ele_fast)      ( ulong i,          HEAP_T *       pool ) { return pool + i; }
FD_FN_CONST static inline HEAP_T const * HEAP_(ele_fast_const)( ulong i,          HEAP_T const * pool ) { return pool + i; }

FD_FN_PURE static inline ulong HEAP_(ele_max)( HEAP_(t) const * heap ) { return heap->ele_max; }
FD_FN_PURE static inline ulong HEAP_(ele_cnt)( HEAP_(t) const * heap ) { return heap->ele_cnt; }

FD_FN_PURE static inline ulong HEAP_(idx_peek_min)( HEAP_(t) const * heap ) { return (ulong)heap->root; }

FD_FN_PURE static inline HEAP_T *
HEAP_(ele_peek_min)( HEAP_(t) const * heap,
                     HEAP_T *         pool ) {
  ulong i = (ulong)heap->root;
  return fd_ptr_if( !HEAP_IDX_IS_NULL( i ), pool + i, NULL );
}

FD_FN_PURE static inline HEAP_T const *
HEAP_(ele_peek_min_const)( HEAP_(t) const * heap,
                           HEAP_T const *   pool ) {
  ulong i = (ulong)heap->root;
  return fd_ptr_if( !HEAP_IDX_IS_NULL( i ), pool + i, NULL );
}

static inline HEAP_(t) *
HEAP_(ele_insert)( HEAP_(t) * heap,
                   HEAP_T *   e,
                   HEAP_T *   pool ) {
  return HEAP_(idx_insert)( heap, (ulong)(e - pool), pool );
}

static inline HEAP_(t) *
HEAP_(ele_remove_min)( HEAP_(t) * heap,
                       HEAP_T *   pool ) {
  return HEAP_(idx_remove_min)( heap, pool );
}

FD_PROTOTYPES_END

#endif

#if HEAP_IMPL_STYLE!=1 /* need implementations */

HEAP_STATIC FD_FN_CONST ulong
HEAP_(align)( void ) {
  return alignof(HEAP_(t));
}

HEAP_STATIC FD_FN_CONST ulong
HEAP_(footprint)( ulong ele_max ) {
  if( FD_UNLIKELY( ele_max>HEAP_IDX_NULL ) ) return 0UL;
  return sizeof(HEAP_(t));
}

HEAP_STATIC void *
HEAP_(new)( void * shmem,
            ulong  ele_max ) {
  if( !shmem ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, HEAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( ele_max>HEAP_IDX_NULL ) ) {
    FD_LOG_WARNING(( "ele_max too large" ));
    return NULL;
  }

  HEAP_(t) * heap = (HEAP_(t) *)shmem;

  heap->ele_max = ele_max;
  heap->ele_cnt = 0UL;
  heap->root    = (HEAP_IDX_T)HEAP_IDX_NULL;

  return heap;
}

HEAP_STATIC HEAP_(t) *
HEAP_(join)( void * shheap ) {
  if( FD_UNLIKELY( !shheap ) ) {
    FD_LOG_WARNING(( "NULL shheap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shheap, HEAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shheap" ));
    return NULL;
  }

  return (HEAP_(t) *)shheap;
}

HEAP_STATIC void *
HEAP_(leave)( HEAP_(t) * heap ) {
  if( FD_UNLIKELY( !heap ) ) {
    FD_LOG_WARNING(( "NULL heap" ));
    return NULL;
  }

  return (void *)heap;
}

HEAP_STATIC void *
HEAP_(delete)( void * shheap ) {
  if( FD_UNLIKELY( !shheap ) ) {
    FD_LOG_WARNING(( "NULL shheap" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shheap, HEAP_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shheap" ));
    return NULL;
  }

  return shheap;
}

HEAP_STATIC HEAP_(t) *
HEAP_(idx_insert)( HEAP_(t) * heap,
                   ulong      n,
                   HEAP_T *   pool ) {

  HEAP_IDX_T * _p_child = &heap->root;

  ulong i = (ulong)*_p_child;

  if( FD_UNLIKELY( HEAP_IDX_IS_NULL( i ) ) ) { /* Heap was empty, make n the root, opt for larger heaps */
    pool[ n ].HEAP_LEFT  = (HEAP_IDX_T)HEAP_IDX_NULL;
    pool[ n ].HEAP_RIGHT = (HEAP_IDX_T)HEAP_IDX_NULL;
    *_p_child            = (HEAP_IDX_T)n;
    heap->ele_cnt++;
    return heap;
  }

  ulong rbits_cnt = 0UL;
  ulong rbits     = 0UL;

  for(;;) {
    ulong l = (ulong)pool[ i ].HEAP_LEFT;
    ulong r = (ulong)pool[ i ].HEAP_RIGHT;

    /* At this point, i's ancestors are less than n.  If n is before i,
       displace i with n. */

    if( FD_UNLIKELY( HEAP_(lt)( pool + n, pool + i ) ) ) { /* Opt for larger heaps and IID rank inserts */
      pool[ n ].HEAP_LEFT  = (HEAP_IDX_T)l;
      pool[ n ].HEAP_RIGHT = (HEAP_IDX_T)r;
      *_p_child = (HEAP_IDX_T)n;
      ulong swap_tmp = i; i = n; n = swap_tmp;
    }

    /* At this point i < n.  If there is neither a left subheap nor a
       right subheap, make n i's left child.  If there is no left/right
       subheap, make n i's left/right child. */

    int is_null_left  = HEAP_IDX_IS_NULL( l );
    int is_null_right = HEAP_IDX_IS_NULL( r );
    if( FD_UNLIKELY( (is_null_left | is_null_right) ) ) { /* Opt for larger heaps */
      pool[ n ].HEAP_LEFT  = (HEAP_IDX_T)HEAP_IDX_NULL;
      pool[ n ].HEAP_RIGHT = (HEAP_IDX_T)HEAP_IDX_NULL;
      *fd_ptr_if( is_null_left, &pool[ i ].HEAP_LEFT, &pool[ i ].HEAP_RIGHT ) = (HEAP_IDX_T)n;
      break;
    }

    /* At this point, i has a left and right subheap.  We need to pick one
       to insert n into.  Ideally we'd pick the smaller one.  But since
       we don't know this (might be possible to be clever here using the
       cnt of items in the heap on the assumption that heap has been
       optimally constructed thus far though this would probably only
       work in pure heapsort like cases), we pseudo randomly pick one
       instead. */

    if( FD_UNLIKELY( !rbits_cnt ) ) {
      rbits     = fd_ulong_hash( (                      i       ^ fd_ulong_rotate_left( n, 16 )) ^
                                 (fd_ulong_rotate_left( l, 32 ) ^ fd_ulong_rotate_left( r, 48 )) );
      rbits_cnt = 64UL; /* TODO: consider using fraction to mix up further? */
    }
    int go_left = (int)(rbits & 1UL);
    rbits >>= 1;
    rbits_cnt--;

    _p_child = fd_ptr_if  ( go_left, &pool[ i ].HEAP_LEFT, &pool[ i ].HEAP_RIGHT );
    i        = fd_ulong_if( go_left, l,                    r                     );
  }

  heap->ele_cnt++;
  return heap;
}

HEAP_STATIC HEAP_(t) *
HEAP_(idx_remove_min)( HEAP_(t) * heap,
                       HEAP_T *   pool ) {
  ulong d = (ulong)heap->root;

  HEAP_IDX_T * _p_child = &heap->root;
  ulong        l        = (ulong)pool[ d ].HEAP_LEFT;
  ulong        r        = (ulong)pool[ d ].HEAP_RIGHT;

  for(;;) {

    /* At this point, we have a hole to fill at d.

       l is the hole's left subheap (if any)
       r is the hole's right subheap (if any)

       p_child points to the link from the d's parent to d (if d has a
       parent) and to the heap root link otherwise.

       If there is neither a left subheap nor a right subheap, we are
       done.  If there is a left/right subheap, we fill the hole with
       the right/left subheap and we are done. */

    int is_null_left  = HEAP_IDX_IS_NULL( l );
    int is_null_right = HEAP_IDX_IS_NULL( r );
    if( FD_UNLIKELY( is_null_left | is_null_right ) ) { /* Opt for larger heaps */
      *_p_child = (HEAP_IDX_T)fd_ulong_if( is_null_left, r, l );
      break;
    }

    /* d has two subheaps.  We fill the hole with the smaller root element
       (preserving the heap property).  This bubbles d down one layer
       toward the subheap with the smaller root.  We fill that hole the
       next iteration.  Note we don't need to update any links to/from d
       as we will be getting rid of all links to/from d. */

    int promote_left = HEAP_(lt)( pool + l, pool + r );

    ulong c     = fd_ulong_if( promote_left, l, r );
    ulong l_nxt = (ulong)pool[ c ].HEAP_LEFT;
    ulong r_nxt = (ulong)pool[ c ].HEAP_RIGHT;

    *_p_child = (HEAP_IDX_T)c;

    *fd_ptr_if( promote_left, &pool[ l ].HEAP_RIGHT, &pool[ r ].HEAP_LEFT ) = (HEAP_IDX_T)fd_ulong_if( promote_left, r, l );

    _p_child = fd_ptr_if( promote_left, &pool[ l ].HEAP_LEFT, &pool[ r ].HEAP_RIGHT );
    l        = l_nxt;
    r        = r_nxt;
  }

  heap->ele_cnt--;
  return heap;
}

HEAP_STATIC int
HEAP_(verify)( HEAP_(t) const * heap,
               HEAP_T const *   pool ) {

# define HEAP_TEST( c ) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return -1; } } while(0)

  HEAP_TEST( heap ); /* Validate local join */

  ulong ele_max = heap->ele_max;
  ulong ele_cnt = heap->ele_cnt;
  HEAP_TEST( ele_max<=HEAP_IDX_NULL ); /* Validate ele_max */
  HEAP_TEST( ele_cnt<=ele_max       ); /* Validate ele_cnt */
  if( ele_max ) HEAP_TEST( pool );     /* Validate ele storage */

  ulong stack[ 512 ];
  ulong stack_cnt = 0UL;
  ulong stack_max = 512UL; /* Should be impossibly large if heap is statistically well balanced */

  ulong visit_cnt = 0UL;

  ulong i = (ulong)heap->root;
  if( !HEAP_IDX_IS_NULL( i ) ) {      /* Schedule first visit */
    HEAP_TEST( i<ele_max );           /* Make sure inbounds */
    HEAP_TEST( stack_cnt<stack_max ); /* Make sure no stack overflow */
    stack[ stack_cnt++ ] = i;         /* Push i to stack */
  }

  while( stack_cnt ) { /* While still nodes to visit */
    HEAP_TEST( visit_cnt<ele_cnt ); /* Make sure no cycles */

    i = stack[ --stack_cnt ]; /* Pop the stack to get next visit (value was validated on push) */

    /* visit i and schedule visits to i's children */

    ulong r = (ulong)pool[ i ].HEAP_RIGHT;
    if( !HEAP_IDX_IS_NULL( r ) ) {
      HEAP_TEST( HEAP_(lt)( pool + i, pool + r ) ); /* Make sure heap property satisfied */
      HEAP_TEST( r<ele_max );                       /* Make sure inbounds */
      HEAP_TEST( stack_cnt<stack_max );             /* Make sure no stack overflow */
      stack[ stack_cnt++ ] = r;                     /* Push r to stack */
    }

    ulong l = (ulong)pool[ i ].HEAP_LEFT;
    if( !HEAP_IDX_IS_NULL( l ) ) {
      HEAP_TEST( HEAP_(lt)( pool + i, pool + l ) ); /* Make sure heap property satisfied */
      HEAP_TEST( l<ele_max );                       /* Make sure inbounds */
      HEAP_TEST( stack_cnt<stack_max );             /* Make sure no stack overflow */
      stack[ stack_cnt++ ] = l;                     /* Push l to stack */
    }

    visit_cnt++; /* update the number visited */
  }

  HEAP_TEST( visit_cnt==ele_cnt ); /* Make sure visit count matches */
  return 0;
}

#endif

#undef HEAP_IDX_IS_NULL
#undef HEAP_IDX_NULL
#undef HEAP_STATIC

#undef HEAP_IMPL_STYLE
#undef HEAP_RIGHT
#undef HEAP_LEFT
#undef HEAP_IDX_T
#undef HEAP_LT
#undef HEAP_T
#undef HEAP_NAME

