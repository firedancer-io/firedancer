/* Declare API for object pools of bounded run-time maximum size
   suitable for non-concurrent high performance persistent IPC usage.
   Typical usage:

     struct myele {
       ulong next; // Technically POOL_IDX_T POOL_NEXT, can go anywhere in struct,
                   // can be repurposed while acquired
                   // will be clobbered while in pool though
       ... user data ...
       ... structures with power-of-2 sizes have particularly good HPC
       ... Feng Shui
     }

     typedef struct myele myele_t;

     #define POOL_NAME mypool
     #define POOL_T    myele_t
     #include "tmpl/fd_pool.c"

   This will declare the following static inline APIs as a header only
   style library in the compilation unit:

     // align/footprint - Return the alignment/footprint required for a
     // memory region to be used as mypool that can hold up to max
     // elements.  footprint returns 0 if max is invalid (e.g. so large
     // that footprint would overflow ULONG_MAX or zero if mypool is
     // supposed to have a sentinel).
     //
     // new - Format a memory region pointed to by shmem into a mypool.
     // Assumes shmem points to a region with the required alignment and
     // footprint not in use by anything else.  Caller is not joined on
     // return.  Returns shmem on success or NULL on failure (e.g. shmem
     // or max are obviously bad).
     //
     // join - Join a mypool.  Assumes shpool points at a memory region
     // formatted as an mypool.  Returns a pointer in the caller's
     // address space to a memory region indexed [0,max) on success and
     // NULL on failure (e.g. shmem is obviously bad).  THIS IS NOT JUST
     // A SIMPLE CAST OF SHPOOL.
     //
     // leave - Leave a mypool.  Assumes join points to a current local
     // join.  Returns a pointer to the shared memory region the join on
     // success and NULL on failure.  THIS IS NOT JUST A SIMPLE CAST OF
     // JOIN.
     //
     // delete - Unformat a memory region used as mypool.  Assumes
     // shpool points to a formatted region with no current / future
     // joins.  Returns a pointer to the unformatted memory region.

     ulong     mypool_align    ( void      );
     ulong     mypool_footprint( ulong max );
     void *    mypool_new      ( void *    shmem, ulong max );
     myele_t * mypool_join     ( void *    shpool );
     void *    mypool_leave    ( myele_t * join   );
     void *    mypool_delete   ( void *    shpool );

     // Special values

     // All these assume join is a current local join to a mypool.  The
     // sentinel APIs are only created if POOL_SENTINEL is requested.

     ulong           mypool_idx_null          ( myele_t const * join ); // Index of the null element (not accessible)
                                                                        // infinite lifetime, ==(ulong)(POOL_IDX_T)~0UL
     myele_t *       mypool_ele_null          ( myele_t *       join ); // Location of the null element in the caller's address
                                                                        // space, infinite lifetime, ==NULL
     myele_t const * mypool_ele_null_const    ( myele_t const * join ); // Const correct version of above

     ulong           mypool_idx_sentinel      ( myele_t const * join ); // Index of the sentinel element (==0)
                                                                        // lifetime is the pool lifetime
     myele_t *       mypool_ele_sentinel      ( myele_t *       join ); // Location of the sentinel element in the caller's address
                                                                        // space, lifetime is the join lifetime (==join)
     myele_t const * mypool_ele_sentinel_const( myele_t const * join ); // Const correct version of above

     // Address space conversions

     int             mypool_idx_test ( myele_t const * join, ulong           idx ); // Returns 1 if idx is in [0,max) or is
                                                                                    // mypool_idx_null.  Returns zero otherwise.
     int             mypool_ele_test ( myele_t const * join, myele_t const * ele ); // Returns 1 if ele points to a pool ele or is
                                                                                    // NULL.  Returns zero otherwise.

     ulong           mypool_idx      ( myele_t const * join, myele_t const * ele ); // Returns idx associated with ele
                                                                                    // Assumes mypool_ele_test is 1
     myele_t *       mypool_ele      ( myele_t *       join, ulong           idx ); // Returns ele associated with idx
                                                                                    // Assumes mypool_ele_test is 1
                                                                                    // Lifetime is the local join
     myele_t const * mypool_ele_const( myele_t const * join, ulong           idx ); // Const correct version of above

     // Accessors

     ulong mypool_max ( myele_t const * join ); // Max elements in pool in [0,IDX_NULL], [1,IDX_NULL] if POOL_SENTINEL requested
     ulong mypool_free( myele_t const * join ); // Number of elements free, in [0,max]
     ulong mypool_used( myele_t const * join ); // Number of elements currently in use / acquired, in [0,max], includes sentinel
                                                // if applicable, pool_free + pool_used == pool_max

     // Operations

     ulong     mypool_idx_acquire( myele_t * join                ); // Acquire an element from pool, assumes at least 1 free
                                                                    // Returns index of element, in [0,max) and, if applicable, not
                                                                    // sentinel index.  Lifetime is lesser of pool lifetime and
                                                                    // acquired element is released.  Will not return a currently
                                                                    // acquired element.
     void      mypool_idx_release( myele_t * join, ulong idx     ); // Release an element to pool by element idx, assumes element
                                                                    // currently acquired (e.g. not null index and, if applicable,
                                                                    // not sentinel index).  Element not acquired on return.

     myele_t * mypool_ele_acquire( myele_t * join                ); // Acquire an element from pool, assumes at least 1 free
                                                                    // Returns a pointer to element in caller's address space, not
                                                                    // NULL and, if applicable, not sentinel.  Lifetime is lesser
                                                                    // of join lifetime and acquired element is released.  Will not
                                                                    // return a currently acquired element
     void      mypool_ele_release( myele_t * join, myele_t * ele ); // Release an element to pool by local pointer, assumes element
                                                                    // currently acquired (e.g. not NULL and, if applicable, not
                                                                    // sentinel).  Element not acquired on return.

     You can do this as often as you like in a compilation unit to get
     different types of pools.  Since it is all static inline, it is
     fine to do this in a header too.  Additional options to fine tune
     this are detailed below. */

#include "../bits/fd_bits.h"

#ifndef POOL_NAME
#define "Define POOL_NAME"
#endif

/* A POOL_T should be something something reasonable to shallow copy
   with the fields described above. */

#ifndef POOL_T
#define "Define POOL_T"
#endif

/* POOL_NEXT is the name of the field the pool will clobber for
   elements currently not allocated. */

#ifndef POOL_NEXT
#define POOL_NEXT next
#endif

/* POOL_IDX_T is the type of the POOL_NEXT field.  Should be an unsigned
   integer type.  The maximum value this type can have is also the
   maximum number of elements that can be in a pool. */

#ifndef POOL_IDX_T
#define POOL_IDX_T ulong
#endif

/* If POOL_SENTINEL is non-zero, the pool will reserve element idx
   0 as a sentinel element (will be considered as always allocated).
   Setting this also implies that the max for a pool should be at least
   1. */

#ifndef POOL_SENTINEL
#define POOL_SENTINEL 0
#endif

/* POOL_MAGIC is the magic number that should be used to identify
   pools of this type in shared memory.  Should be non-zero. */

#ifndef POOL_MAGIC
#define POOL_MAGIC (0xF17EDA2CE7900100UL) /* Firedancer pool ver 0 */
#endif

/* Implementation *****************************************************/

#define POOL_(n) FD_EXPAND_THEN_CONCAT3(POOL_NAME,_,n)

#define POOL_IDX_NULL ((ulong)((POOL_IDX_T)~0UL))

struct POOL_(private) {

  /* This point is POOL_ALIGN aligned */
  ulong magic;    /* ==POOL_MAGIC */
  ulong max;      /* Max elements in pool, in [POOL_SENTINEL,POOL_IDX_NULL] */
  ulong free;     /* Num elements in pool available, in [0,max] */
  ulong free_top; /* Free stack top, POOL_IDX_NULL no elements currently in pool */

  /* Padding to POOL_ALIGN here */

  /* max POOL_T elements here, join points to element 0 */
  /* element 0 will be the sentinel if POOL_SENTINEL is true */

  /* Padding to POOL_ALIGN here */
};

typedef struct POOL_(private) POOL_(private_t);

FD_PROTOTYPES_BEGIN

/* Private APIs *******************************************************/

/* pool_private_meta_footprint returns the number of bytes used by a
   pool metadata region */

FD_FN_CONST static inline ulong
POOL_(private_meta_footprint)( void ) {
  return fd_ulong_align_up( sizeof(POOL_(private_t)), fd_ulong_max( alignof(POOL_T), 128UL )  );
}

/* pool_private_meta returns a pointer in the caller's address space to
   a pool metadata region.  pool_private_meta_const is a const correct
   version. */

FD_FN_CONST static inline POOL_(private_t) *
POOL_(private_meta)( POOL_T * join ) {
  return (POOL_(private_t) *)(((ulong)join) - POOL_(private_meta_footprint)());
}

FD_FN_CONST static inline POOL_(private_t) const *
POOL_(private_meta_const)( POOL_T const * join ) {
  return (POOL_(private_t) const *)(((ulong)join) - POOL_(private_meta_footprint)());
}

/* Public APIS ********************************************************/

FD_FN_CONST static inline ulong
POOL_(max_for_footprint)( ulong footprint ) {
  ulong meta_footprint = POOL_(private_meta_footprint)();
  if( FD_UNLIKELY( footprint <= meta_footprint ) ) return 0UL;
  return fd_ulong_min( (footprint - meta_footprint) / sizeof(POOL_T), POOL_IDX_NULL );
}

FD_FN_CONST static inline ulong
POOL_(align)( void ) {
  return fd_ulong_max( alignof(POOL_T), 128UL );
}

FD_FN_CONST static inline ulong
POOL_(footprint)( ulong max ) {
# if POOL_SENTINEL
  if( FD_UNLIKELY( !max ) ) return 0UL;
# endif
  ulong align          = POOL_(align)();
  ulong meta_footprint = POOL_(private_meta_footprint)(); /* Multiple of align */
  ulong data_footprint = fd_ulong_align_up( sizeof(POOL_T)*max, align );
  ulong thresh         = fd_ulong_min( (ULONG_MAX - align - meta_footprint + 1UL) / sizeof(POOL_T), POOL_IDX_NULL );
  return fd_ulong_if( max > thresh, 0UL, meta_footprint + data_footprint );
}

FD_FN_UNUSED static void * /* Work around -Winline */
POOL_(new)( void * shmem,
            ulong  max ) {

  if( FD_UNLIKELY( !shmem )                                               ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, POOL_(align)() ) ) ) return NULL;
  if( FD_UNLIKELY( !POOL_(footprint)( max ) )                             ) return NULL;

  POOL_T *           join = (POOL_T *)(((ulong)shmem) + POOL_(private_meta_footprint)());
  POOL_(private_t) * meta = POOL_(private_meta)( join );

  meta->max  = max;
  meta->free = max;

  if( FD_UNLIKELY( !max ) ) meta->free_top = POOL_IDX_NULL; /* Not reachable if POOL_SENTINEL set (footprint test above fails) */
  else {
    meta->free_top = 0UL;
    for( ulong idx=1UL; idx<max; idx++ ) join[ idx-1UL ].POOL_NEXT = (POOL_IDX_T)idx;
    join[ max-1UL ].POOL_NEXT = (POOL_IDX_T)POOL_IDX_NULL;

#   if POOL_SENTINEL
    meta->free_top = 1UL;
    meta->free--;
    join[ 0 ].POOL_NEXT = (POOL_IDX_T)POOL_IDX_NULL;
#   endif
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( meta->magic ) = (POOL_MAGIC);
  FD_COMPILER_MFENCE();

  return shmem;
}

static inline POOL_T *
POOL_(join)( void * shpool ) {
  if( FD_UNLIKELY( !shpool                                               ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shpool, POOL_(align)() ) ) ) return NULL;

  POOL_T *           join = (POOL_T *)(((ulong)shpool) + POOL_(private_meta_footprint)());
  POOL_(private_t) * meta = POOL_(private_meta)( join );

  if( FD_UNLIKELY( FD_VOLATILE_CONST( meta->magic )!=(POOL_MAGIC) ) ) return NULL;

  return join;
}

FD_FN_CONST static inline void *
POOL_(leave)( POOL_T * join ) {
  if( FD_UNLIKELY( !join ) ) return NULL;
  return (void *)(((ulong)join) - POOL_(private_meta_footprint)());
}

static inline void *
POOL_(delete)( void * shpool ) {
  if( FD_UNLIKELY( !shpool ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shpool, POOL_(align)() ) ) ) return NULL;

  POOL_T *           join = (POOL_T *)(((ulong)shpool) + POOL_(private_meta_footprint)());
  POOL_(private_t) * meta = POOL_(private_meta)( join );

  if( FD_UNLIKELY( FD_VOLATILE_CONST( meta->magic )!=(POOL_MAGIC) ) ) return NULL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( meta->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shpool;
}

/* Special values */

FD_FN_CONST static inline ulong          POOL_(idx_null)          ( POOL_T const * join ) { (void)join; return POOL_IDX_NULL; }
FD_FN_CONST static inline POOL_T *       POOL_(ele_null)          ( POOL_T       * join ) { (void)join; return NULL;          }
FD_FN_CONST static inline POOL_T const * POOL_(ele_null_const)    ( POOL_T const * join ) { (void)join; return NULL;          }

#if POOL_SENTINEL
FD_FN_CONST static inline ulong          POOL_(idx_sentinel)      ( POOL_T const * join ) { (void)join; return 0UL;  }
FD_FN_CONST static inline POOL_T *       POOL_(ele_sentinel)      ( POOL_T *       join ) { return join; }
FD_FN_CONST static inline POOL_T const * POOL_(ele_sentinel_const)( POOL_T const * join ) { return join; }
#endif

/* Address space conversion */

FD_FN_PURE static inline int
POOL_(idx_test)( POOL_T const * join,
                 ulong          idx ) {
  ulong max = POOL_(private_meta_const)( join )->max;
  return (idx<max) | (idx==POOL_IDX_NULL);
}

FD_FN_PURE static inline int
POOL_(ele_test)( POOL_T const * join,
                 POOL_T const * ele ) {
  ulong max = POOL_(private_meta_const)( join )->max;
  ulong idx = (ulong)(ele - join);
  FD_COMPILER_FORGET( idx ); /* prevent compiler from optimizing out alignment test */
  return (!ele) | ((idx<max) & ((ulong)ele==((ulong)join+(idx*sizeof(POOL_T))))); /* last test checks alignment */
}

FD_FN_CONST static inline ulong
POOL_(idx)( POOL_T const * join,
            POOL_T const * ele ) {
  return ele ? (ulong)(ele-join) : POOL_IDX_NULL;
}

FD_FN_CONST static inline POOL_T *
POOL_(ele)( POOL_T *   join,
            ulong      idx ) {
  return (idx==POOL_IDX_NULL) ? NULL : (join + idx);
}

FD_FN_CONST static inline POOL_T const *
POOL_(ele_const)( POOL_T const *   join,
                  ulong            idx ) {
  return (idx==POOL_IDX_NULL) ? NULL : (join + idx);
}

/* Accessors */

FD_FN_PURE static inline ulong POOL_(max) ( POOL_T const * join ) { return POOL_(private_meta_const)( join )->max;  }
FD_FN_PURE static inline ulong POOL_(free)( POOL_T const * join ) { return POOL_(private_meta_const)( join )->free; }

FD_FN_PURE static inline ulong
POOL_(used)( POOL_T const * join ) {
  POOL_(private_t) const * meta = POOL_(private_meta_const)( join );
  return meta->max - meta->free;
}

/* Operations */

static inline ulong
POOL_(idx_acquire)( POOL_T * join ) {
  POOL_(private_t) * meta = POOL_(private_meta)( join );
  ulong idx = meta->free_top;
  meta->free_top = (ulong)join[ idx ].POOL_NEXT;
  meta->free--;
  return idx;
}

static inline void
POOL_(idx_release)( POOL_T * join,
                    ulong    idx ) {
  POOL_(private_t) * meta = POOL_(private_meta)( join );
  join[ idx ].POOL_NEXT = (POOL_IDX_T)meta->free_top;
  meta->free_top = idx;
  meta->free++;
}

static inline POOL_T * POOL_(ele_acquire)( POOL_T * join               ) { return join + POOL_(idx_acquire)( join ); }
static inline void     POOL_(ele_release)( POOL_T * join, POOL_T * ele ) { POOL_(idx_release)( join, (ulong)(ele - join) );   }

/* TODO: consider zeroing out pool mem on new? */

/* TODO: consider providing element size and alignment as metadata? */

/* TODO: consider lockfree concurrent version with ABA tagged free_top? */

/* TODO: consider a verify and rebuild that work via most sig bit of
   POOL_NEXT for element marking (the POOL_NEXT field in the structure
   would have to become dedicated to the pool though). */

FD_PROTOTYPES_END

#undef POOL_IDX_NULL
#undef POOL_

#undef POOL_MAGIC
#undef POOL_SENTINEL
#undef POOL_IDX_T
#undef POOL_NEXT
#undef POOL_T
#undef POOL_NAME
