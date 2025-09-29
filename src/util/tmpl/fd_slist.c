/* Generate prototypes, inlines and/or implementations for HPC slingly
   linked lists.  A slist can store a practically unbounded number of
   elements.  Typical slist operations are generally a fast O(1) time
   and slist element memory overhead is a small O(1) space.

   This API is designed for ultra tight coupling with pools, treaps,
   heaps, maps, dlists, etc.  Likewise, a slist can be persisted beyond
   the lifetime of the creating process, used concurrently in many
   common operations, used inter-process, relocated in memory, naively
   serialized/deserialized, moved between hosts, supports index
   compression for cache and memory bandwidth efficiency, etc.

   Memory efficiency and flexible footprint are prioritized.

   Typical usage:

     struct myele {
       ulong next; // Technically "SLIST_IDX_T SLIST_NEXT" (default is ulong next), do not modify while element is in the slist
       ... next can be located arbitrarily in the element and can be
       ... reused for other purposes when the element is not in a slist.
       ... An element should not be moved / released while an element is
       ... in a slist
     };

     typedef struct myele myele_t;

     #define SLIST_NAME  myslist
     #define SLIST_ELE_T myele_t
     #include "tmpl/fd_slist.c"

   will declare the following APIs as a header only style library in the
   compilation unit:

     // myslist_ele_max returns the theoretical maximum number of
     // elements that can be held in a myslist.

     ulong myslist_ele_max( void );

     // myslist_{align,footprint} returns the alignment and footprint
     // needed for a memory region to be used as a myslist.  align will
     // be an integer power-of-two and footprint will be a multiple of
     // align.  The values will be compile-time declaration friendly
     // (e.g. "myslist_t mem[1];" will have the correct alignment and
     // footprint and not be larger than 4096).
     //
     // myslist_new formats a memory region with the appropriate
     // alignment and footprint whose first byte in the caller's address
     // space is pointed to by shmem as a myslist.  Returns shmem on
     // success and NULL on failure (logs details).  Caller is not
     // joined on return.  The slist will be empty.
     //
     // myslist_join joins a myslist.  Assumes shslist points at a
     // memory region formatted as a myslist in the caller's address
     // space.  Returns a handle to the caller's local join on success
     // and NULL on failure (logs details).  Do not assume this is a
     // simple cast of shslist!
     //
     // myslist_leave leaves a myslist.  Assumes join points to a
     // current local join.  Returns shslist used on join.  Do not
     // assume this is a simple cast of join!
     //
     // myslist_delete unformats a memory region used as a myslist.
     // Assumes shslist points to a memory region in the caller's local
     // address space formatted as a myslist, that there are no joins to
     // the myslist and that any application cleanup of the entries has
     // already been done.  Returns shslist on success and NULL on
     // failure.

     ulong       myslist_align    ( void );
     ulong       myslist_footprint( void );
     void *      myslist_new      ( void *      shmem   );
     myslist_t * myslist_join     ( void *      shslist );
     void *      myslist_leave    ( myslist_t * join    );
     void *      myslist_delete   ( void *      shslist );

     // The below APIs assume join is a current local join to a myslist
     // and pool is a current local join to the element storage backing
     // the slist.
     //
     // myslist_is_empty returns 1 if the slist is empty and 0
     // otherwise.
     //
     // myslist_idx_peek_{head,tail} returns the pool index of the
     // slist's {head,tail}.  Assumes slist is not empty.

     int myslist_is_empty( myslist_t const * join, myele_t const * pool );

     ulong myslist_idx_peek_head( myslist_t const * join, myele_t const * pool );
     ulong myslist_idx_peek_tail( myslist_t const * join, myele_t const * pool );

     // myslist_idx_push_{head,tail} pushes the pool element whose index
     // is ele_idx to the slist's {head,tail} and returns join.  Assumes
     // ele_idx valid and not already in the slist.
     /
     // myslist_idx_pop_head pops the pool element at the slist's head
     // and returns its pool index.  Assumes slist is not empty.
     //
     // myslist_idx_insert_after inserts the pool element whose index is
     // ele_idx into the slist immediately after the pool element whose
     // index is prev_idx and returns join.  Assumes ele_idx is valid
     // and not already in the slist and prev_idx is already in the
     // slist.

     myslist_t * myslist_idx_push_head    ( myslist_t * join, ulong ele_idx,                 myele_t * pool );
     myslist_t * myslist_idx_push_tail    ( myslist_t * join, ulong ele_idx,                 myele_t * pool );
     ulong       myslist_idx_pop_head     ( myslist_t * join,                                myele_t * pool );
     myslist_t * myslist_idx_insert_after ( myslist_t * join, ulong ele_idx, ulong prev_idx, myele_t * pool );

     // myslist_remove_all removes all elements from the slist and
     // returns join.  It is the caller's responsibility to release all
     // elements to the pool as might be necessary.

     myslist_t * myslist_remove_all( myslist_t * join, myele_t * pool );

     // myslist_iter_* support fast ordered forward (head to tail)
     // iteration over all the elements in a slist.  Example usage:
     //
     //   for( myslist_iter_t iter = myslist_iter_init( join, pool );
     //        !myslist_iter_done( iter, join, pool );
     //        iter = myslist_iter_next( iter, join, pool ) ) {
     //     ulong ele_idx = myslist_iter_idx( iter, join, pool );
     //
     //     ... process element here
     //
     //     ... IMPORTANT!  It is generally safe to insert elements
     //     ... here (though they might not be covered by this
     //     ... iteration).  It is also generally safe to remove any
     //     ... element but the current element here (the removed
     //     ... element might have already been iterated over).  It is
     //     ... straightforward to make a variant of this iterator
     //     ... that would support removing the current element here
     //     ... if desired.
     //   }

     struct myslist_iter_private { ... internal use only ... };
     typedef struct myslist_iter_private myslist_iter_t;

     myslist_iter_t  myslist_iter_fwd_init(                      myslist_t const * join, myele_t const * pool );
     int             myslist_iter_done    ( myslist_iter_t iter, myslist_t const * join, myele_t const * pool );
     myslist_iter_t  myslist_iter_fwd_next( myslist_iter_t iter, myslist_t const * join, myele_t const * pool ); // assumes !done
     ulong           myslist_iter_idx     ( myslist_iter_t iter, myslist_t const * join, myele_t const * pool ); // assumes !done

     // myslist_verify returns 0 if the myslist is not obviously corrupt
     // or -1 (i.e. ERR_INVAL) otherwise (logs details).

     int
     myslist_verify( myslist_t const * join,    // Current local join to a myslist.
                     ulong             ele_cnt, // Element storage size, in [0,myslist_ele_max()]
                     myele_t const *   pool );  // Current local join to element storage, indexed [0,ele_cnt)

     // The above APIs have helpers that operate purely in the caller's
     // local address space when applicable.  The various elements
     // passed to / returned from these functions should be / will be
     // from the slist's underlying pool.

     myele_t * myslist_ele_peek_head( myslist_t const * join, myele_t * pool );
     myele_t * myslist_ele_peek_tail( myslist_t const * join, myele_t * pool );

     myslist_t * myslist_ele_push_head    ( myslist_t * join, myele_t * ele,                 myele_t * pool );
     myslist_t * myslist_ele_push_tail    ( myslist_t * join, myele_t * ele,                 myele_t * pool );
     myele_t *   myslist_ele_pop_head     ( myslist_t * join,                                myele_t * pool );
     myslist_t * myslist_ele_insert_after ( myslist_t * join, myele_t * ele, myele_t * prev, myele_t * pool );

     myele_t * myslist_iter_ele( myslist_iter_t iter, myslist_t const * join, myele_t * pool );

     // ... and const correct helpers when applicable

     myele_t const * myslist_ele_peek_head_const( myslist_t const * join, myele_t const * pool );
     myele_t const * myslist_ele_peek_tail_const( myslist_t const * join, myele_t const * pool );

     myele_t const * myslist_iter_ele_const( myslist_iter_t iter, myslist_t const * join, myele_t const * pool );

   You can do this as often as you like in a compilation unit to get
   different types of slists.  Variants exist for making header
   prototypes only and/or implementations only if making a library for
   use across multiple compilation units.  Further, options exist to use
   different hashing functions, comparison functions, etc as detailed
   below. */

/* TODO: DOC CONCURRENCY REQUIREMENTS */

/* SLIST_NAME gives the API prefix to use for a slist */

#ifndef SLIST_NAME
#error "Define SLIST_NAME"
#endif

/* SLIST_ELE_T is the slist element type. */

#ifndef SLIST_ELE_T
#error "Define SLIST_ELE_T"
#endif

/* SLIST_IDX_T is the type used for the prev and next fields in the
   SLIST_ELE_T.  Should be a primitive unsigned integer type.  Defaults
   to ulong.  A slist can't use element memory regions with more
   elements than the maximum value that can be represented by a
   SLIST_IDX_T.  (E.g. if ushort, the maximum size element store
   supported by the slist is 65535 elements.) */

#ifndef SLIST_IDX_T
#define SLIST_IDX_T ulong
#endif

/* SLIST_NEXT is the SLIST_ELE_T next field */

#ifndef SLIST_NEXT
#define SLIST_NEXT next
#endif

/* SLIST_MAGIC is the magic number to use for the structure to aid in
   persistent and/or IPC usage. */

#ifndef SLIST_MAGIC
#define SLIST_MAGIC (0xf17eda2c37371570UL) /* firedancer slist version 0 */
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef SLIST_IMPL_STYLE
#define SLIST_IMPL_STYLE 0
#endif

#if FD_TMPL_USE_HANDHOLDING
#include "../log/fd_log.h"
#endif

/* Implementation *****************************************************/

/* Constructors and verification log details on failure (rest only needs
   fd_bits.h, consider making logging a compile time option). */

#define SLIST_(n) FD_EXPAND_THEN_CONCAT3(SLIST_NAME,_,n)

#if SLIST_IMPL_STYLE==0 || SLIST_IMPL_STYLE==1 /* need structures and inlines */

struct SLIST_(private) {

  /* join points here */

  ulong       magic; /* == SLIST_MAGIC */
  SLIST_IDX_T head;  /* index of first list element (or idx_null if empty list) */
  SLIST_IDX_T tail;  /* index of last  list element (or idx_null if empty list) */
};

typedef struct SLIST_(private) SLIST_(private_t);

typedef SLIST_(private_t) SLIST_(t);

typedef ulong SLIST_(iter_t);

FD_PROTOTYPES_BEGIN

/* slist_private returns the location of the slist header for a current
   local join.  Assumes join is a current local join.
   slist_private_const is a const correct version. */

FD_FN_CONST static inline SLIST_(private_t) *
SLIST_(private)( SLIST_(t) * join ) {
  return (SLIST_(private_t) *)join;
}

FD_FN_CONST static inline SLIST_(private_t) const *
SLIST_(private_const)( SLIST_(t) const * join ) {
  return (SLIST_(private_t) const *)join;
}

/* slist_private_{cidx,idx} compress / decompress 64-bit in-register
   indices to/from their in-memory representations. */

FD_FN_CONST static inline SLIST_IDX_T SLIST_(private_cidx)( ulong       idx  ) { return (SLIST_IDX_T)idx;  }
FD_FN_CONST static inline ulong       SLIST_(private_idx) ( SLIST_IDX_T cidx ) { return (ulong)      cidx; }

/* slist_private_idx_null returns the element storage index that
   represents NULL. */

FD_FN_CONST static inline ulong SLIST_(private_idx_null)( void ) { return (ulong)(SLIST_IDX_T)~0UL; }

/* slist_private_idx_is_null returns 1 if idx is the NULL slist index
   and 0 otherwise. */

FD_FN_CONST static inline int SLIST_(private_idx_is_null)( ulong idx ) { return idx==(ulong)(SLIST_IDX_T)~0UL; }

FD_FN_CONST static inline ulong SLIST_(ele_max)( void ) { return (ulong)(SLIST_IDX_T)~0UL; }

FD_FN_PURE static inline int
SLIST_(is_empty)( SLIST_(t) const *   join,
                  SLIST_ELE_T const * pool ) {
  (void)pool;
  return SLIST_(private_idx_is_null)( SLIST_(private_idx)( SLIST_(private_const)( join )->head ) );
}

FD_FN_PURE static inline ulong
SLIST_(idx_peek_head)( SLIST_(t) const *   join,
                       SLIST_ELE_T const * pool ) {
  (void)pool;
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( SLIST_(is_empty)( join, pool ) ) ) FD_LOG_CRIT(( "cannot peek on empty slist" ));
# endif
  return SLIST_(private_idx)( SLIST_(private_const)( join )->head );
}

FD_FN_PURE static inline ulong
SLIST_(idx_peek_tail)( SLIST_(t) const *   join,
                       SLIST_ELE_T const * pool ) {
  (void)pool;
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( SLIST_(is_empty)( join, pool ) ) ) FD_LOG_CRIT(( "cannot peek on empty slist" ));
# endif
  return SLIST_(private_idx)( SLIST_(private_const)( join )->tail );
}

static inline SLIST_(t) *
SLIST_(idx_push_head)( SLIST_(t) *   join,
                       ulong         ele_idx,
                       SLIST_ELE_T * pool ) {
  SLIST_(private_t) * slist = SLIST_(private)( join );

  ulong head_idx = SLIST_(private_idx)( slist->head );

  pool[ ele_idx ].SLIST_NEXT = SLIST_(private_cidx)( head_idx );

  SLIST_IDX_T dummy[1];
  *fd_ptr_if( !SLIST_(private_idx_is_null)( head_idx ), dummy+0, &slist->tail ) =
    SLIST_(private_cidx)( ele_idx );

  slist->head = SLIST_(private_cidx)( ele_idx );
  return join;
}

static inline SLIST_(t) *
SLIST_(idx_push_tail)( SLIST_(t) *   join,
                       ulong         ele_idx,
                       SLIST_ELE_T * pool ) {
  SLIST_(private_t) * slist = SLIST_(private)( join );

  ulong tail_idx = SLIST_(private_idx)( slist->tail );

  pool[ ele_idx ].SLIST_NEXT = SLIST_(private_cidx)( SLIST_(private_idx_null)() );

  *fd_ptr_if( !SLIST_(private_idx_is_null)( tail_idx ), &pool[ tail_idx ].SLIST_NEXT, &slist->head ) =
    SLIST_(private_cidx)( ele_idx );

  slist->tail = SLIST_(private_cidx)( ele_idx );
  return join;
}

static inline ulong
SLIST_(idx_pop_head)( SLIST_(t) *   join,
                      SLIST_ELE_T * pool ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( SLIST_(is_empty)( join, pool ) ) ) FD_LOG_CRIT(( "cannot pop from empty slist" ));
# endif
  SLIST_(private_t) * slist = SLIST_(private)( join );

  ulong ele_idx  = SLIST_(private_idx)( slist->head ); /* Not NULL as per contract */
  ulong next_idx = SLIST_(private_idx)( pool[ ele_idx ].SLIST_NEXT );

  SLIST_IDX_T dummy[1];
  *fd_ptr_if( !SLIST_(private_idx_is_null)( next_idx ), dummy+0, &slist->tail ) =
    SLIST_(private_cidx)( SLIST_(private_idx_null)() );

  slist->head = SLIST_(private_cidx)( next_idx );
  return ele_idx;
}

static inline SLIST_(t) *
SLIST_(idx_insert_after)( SLIST_(t) *   join,
                          ulong         ele_idx,
                          ulong         prev_idx,
                          SLIST_ELE_T * pool ) {
  ulong next_idx = SLIST_(private_idx)( pool[ prev_idx ].SLIST_NEXT );

  pool[ ele_idx ].SLIST_NEXT = SLIST_(private_cidx)( next_idx );

  pool[ prev_idx ].SLIST_NEXT = SLIST_(private_cidx)( ele_idx );

  SLIST_IDX_T dummy[1];
  *fd_ptr_if( !SLIST_(private_idx_is_null)( next_idx ), dummy+0, &SLIST_(private)( join )->tail ) =
    SLIST_(private_cidx)( ele_idx );

  return join;
}

static inline SLIST_(t) *
SLIST_(remove_all)( SLIST_(t) *   join,
                    SLIST_ELE_T * pool ) {
  (void)pool;
  SLIST_(private_t) * slist = SLIST_(private)( join );
  slist->head = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  slist->tail = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  return join;
}

FD_FN_PURE static inline SLIST_(iter_t)
SLIST_(iter_init)( SLIST_(t) const *   join,
                       SLIST_ELE_T const * pool ) {
  (void)pool;
  return SLIST_(private_idx)( SLIST_(private_const)( join )->head );
}

FD_FN_CONST static inline int
SLIST_(iter_done)( SLIST_(iter_t)      iter,
                   SLIST_(t) const *   join,
                   SLIST_ELE_T const * pool ) {
  (void)join; (void)pool;
  return SLIST_(private_idx_is_null)( iter );
}

FD_FN_PURE static inline SLIST_(iter_t)
SLIST_(iter_next)( SLIST_(iter_t)      iter,
                       SLIST_(t) const *   join,
                       SLIST_ELE_T const * pool ) {
  (void)join;
  return SLIST_(private_idx)( pool[ iter ].SLIST_NEXT );
}

FD_FN_CONST static inline ulong
SLIST_(iter_idx)( SLIST_(iter_t)      iter,
                  SLIST_(t) const *   join,
                  SLIST_ELE_T const * pool ) {
  (void)join; (void)pool;
  return iter;
}

FD_FN_PURE static inline SLIST_ELE_T *
SLIST_(ele_peek_head)( SLIST_(t) const * join,
                       SLIST_ELE_T *     pool ) {
  return pool + SLIST_(idx_peek_head)( join, pool );
}

FD_FN_PURE static inline SLIST_ELE_T const *
SLIST_(ele_peek_head_const)( SLIST_(t) const *   join,
                             SLIST_ELE_T const * pool ) {
  return pool + SLIST_(idx_peek_head)( join, pool );
}

FD_FN_PURE static inline SLIST_ELE_T *
SLIST_(ele_peek_tail)( SLIST_(t) const * join,
                       SLIST_ELE_T *     pool ) {
  return pool + SLIST_(idx_peek_tail)( join, pool );
}

FD_FN_PURE static inline SLIST_ELE_T const *
SLIST_(ele_peek_tail_const)( SLIST_(t) const *   join,
                             SLIST_ELE_T const * pool ) {
  return pool + SLIST_(idx_peek_tail)( join, pool );
}

static inline SLIST_(t) *
SLIST_(ele_push_head)( SLIST_(t) *   join,
                       SLIST_ELE_T * ele,
                       SLIST_ELE_T * pool ) {
  return SLIST_(idx_push_head)( join, (ulong)(ele-pool), pool );
}

static inline SLIST_(t) *
SLIST_(ele_push_tail)( SLIST_(t) *   join,
                       SLIST_ELE_T * ele,
                       SLIST_ELE_T * pool ) {
  return SLIST_(idx_push_tail)( join, (ulong)(ele-pool), pool );
}

static inline SLIST_ELE_T *
SLIST_(ele_pop_head)( SLIST_(t) *   join,
                      SLIST_ELE_T * pool ) {
  return pool + SLIST_(idx_pop_head)( join, pool );
}

static inline SLIST_(t) *
SLIST_(ele_insert_after)( SLIST_(t) *   join,
                          SLIST_ELE_T * ele,
                          SLIST_ELE_T * prev,
                          SLIST_ELE_T * pool ) {
  return SLIST_(idx_insert_after)( join, (ulong)(ele-pool), (ulong)(prev-pool), pool );
}

FD_FN_CONST static inline SLIST_ELE_T *
SLIST_(iter_ele)( SLIST_(iter_t)    iter,
                  SLIST_(t) const * join,
                  SLIST_ELE_T *     pool ) {
  (void)join;
  return pool + iter;
}

FD_FN_CONST static inline SLIST_ELE_T const *
SLIST_(iter_ele_const)( SLIST_(iter_t)      iter,
                        SLIST_(t) const *   join,
                        SLIST_ELE_T const * pool ) {
  (void)join;
  return pool + iter;
}

FD_PROTOTYPES_END

#endif

#if SLIST_IMPL_STYLE==1 /* need prototypes */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong SLIST_(align)    ( void                );
FD_FN_CONST ulong SLIST_(footprint)( void                );
void *            SLIST_(new)      ( void *      shmem   );
SLIST_(t) *       SLIST_(join)     ( void *      shslist );
void *            SLIST_(leave)    ( SLIST_(t) * join    );
void *            SLIST_(delete)   ( void *      shslist );

int
SLIST_(verify)( SLIST_(t) const *   join,
                ulong               ele_cnt,
                SLIST_ELE_T const * pool );

FD_PROTOTYPES_END

#else /* need implementations */

#if SLIST_IMPL_STYLE==0 /* local only */
#define SLIST_IMPL_STATIC FD_FN_UNUSED static
#else
#define SLIST_IMPL_STATIC
#endif

FD_PROTOTYPES_BEGIN

FD_FN_CONST SLIST_IMPL_STATIC ulong SLIST_(align)    ( void ) { return alignof(SLIST_(t)); }
FD_FN_CONST SLIST_IMPL_STATIC ulong SLIST_(footprint)( void ) { return sizeof( SLIST_(t)); }

SLIST_IMPL_STATIC void *
SLIST_(new)( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, SLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  // Note: Guaranteed non-zero and not otherwise used
//ulong footprint = SLIST_(footprint)();
//if( FD_UNLIKELY( !footprint ) ) {
//  FD_LOG_WARNING(( "bad footprint" ));
//  return NULL;
//}

  SLIST_(private_t) * slist = (SLIST_(private_t) *)shmem;

  slist->head = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  slist->tail = SLIST_(private_cidx)( SLIST_(private_idx_null)() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( slist->magic ) = SLIST_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

SLIST_IMPL_STATIC SLIST_(t) *
SLIST_(join)( void * shslist ) {
  SLIST_(private_t) * slist = (SLIST_(private_t) *)shslist;

  if( FD_UNLIKELY( !slist ) ) {
    FD_LOG_WARNING(( "NULL shslist" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)slist, SLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shslist" ));
    return NULL;
  }

  if( FD_UNLIKELY( slist->magic!=SLIST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (SLIST_(t) *)slist;
}

SLIST_IMPL_STATIC void *
SLIST_(leave)( SLIST_(t) * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

SLIST_IMPL_STATIC void *
SLIST_(delete)( void * shslist ) {
  SLIST_(private_t) * slist = (SLIST_(private_t) *)shslist;

  if( FD_UNLIKELY( !slist ) ) {
    FD_LOG_WARNING(( "NULL shslist" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)slist, SLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shslist" ));
    return NULL;
  }

  if( FD_UNLIKELY( slist->magic!=SLIST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( slist->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shslist;
}

SLIST_IMPL_STATIC int
SLIST_(verify)( SLIST_(t) const *   join,
                ulong               ele_cnt,
                SLIST_ELE_T const * pool ) {

# define SLIST_TEST(c) do {                                                      \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  /* Validate input args */

  SLIST_TEST( join                       );
  SLIST_TEST( ele_cnt<=SLIST_(ele_max)() );
  SLIST_TEST( (!!pool) | (!ele_cnt)      );

  /* Iterate forward through the slist, validating as we go */

  SLIST_(private_t) const * slist = SLIST_(private_const)( join );

  SLIST_TEST( slist->magic==SLIST_MAGIC );

  ulong rem      = ele_cnt;
  ulong prev_idx = SLIST_(private_idx_null)();
  ulong ele_idx  = SLIST_(private_idx)( slist->head );
  while( !SLIST_(private_idx_is_null)( ele_idx ) ) {

    /* Visit ele_idx */

    SLIST_TEST( rem ); rem--;                                                  /* Test for cycles */
    SLIST_TEST( ele_idx<ele_cnt );                                             /* Test valid ele_idx */

    /* Advance to next element */

    prev_idx = ele_idx;
    ele_idx  = SLIST_(private_idx)( pool[ ele_idx ].SLIST_NEXT );
  }

  SLIST_TEST( SLIST_(private_idx)( slist->tail )==prev_idx );

# undef SLIST_TEST

  return 0;
}

FD_PROTOTYPES_END

#undef SLIST_IMPL_STATIC

#endif

#undef SLIST_

#undef SLIST_IMPL_STYLE
#undef SLIST_MAGIC
#undef SLIST_NEXT
#undef SLIST_IDX_T
#undef SLIST_ELE_T
#undef SLIST_NAME
