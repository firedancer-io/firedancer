/* Generate prototypes and inlines for a singly linked list.

   This API is designed for ultra tight coupling with pools, treaps,
   maps, other lists, etc.  Likewise, a list can be persisted beyond
   the lifetime of the creating process, used concurrently in many
   common operations, used inter-process, relocated in memory, naively
   serialized/deserialized, moved between hosts, supports index
   compression for cache and memory bandwidth efficiency, etc.

   Memory efficiency and flexible footprint are prioritized.

   Typical usage:

     struct mele {
       ulong next; // Technically "LIST_IDX_T SLIST_NEXT" (default is ulong next), do not modify while element is in the list
       ... next can be located arbitrarily in the element and can be
       ... reused for other purposes when the element is not in a list.
       ... An element should not be moved / released while an element
       ... is in a list.
     };

     typedef struct myele myele_t

     #define SLIST_NAME  myslist
     #define SLIST_ELE_T myele_t
     #include "templ/fd_slist.c"

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

     ulong       myslist_align    ( void );
     ulong       myslist_footprint( void );
     void *      myslist_new      ( void *      shmem  );
     myslist_t * myslist_join     ( void *      shlist );
     void *      myslist_leave    ( myslist_t * join   );
     void *      myslist_delete   ( void *      shlist );

     // The below APIs assume join is a current local join to a slist
     // and pool is a current local join to the element storage backing
     // the slist.
     //
     // myslist_is_empty returns 1 if the list is empty and 0 otherwise.
     //
     // myslist_idx_peek_{head,tail} returns the pool index of the
     // list's {head,tail}.  Assumes list is not empty.

     int myslist_is_empty( myslist_t const * join );

     ulong myslist_idx_peek_head( myslist_t const * join );
     ulong myslist_idx_peek_tail( myslist_t const * join );

     // myslist_idx_push_{head,tail} pushes the pool element whose index
     // is ele_idx to the list's {head,tail} and returns join.  Assumes
     // ele_idx is valid and not already in the list.
     //
     // myslist_idx_pop_head pops the pool element at the list's head
     // and returns its pool index.  Assumes list is not empty.

     myslist_t * myslist_idx_push_head( myslist_t * join, ulong ele_idx, myele_t * pool );
     myslist_t * myslist_idx_push_tail( myslist_t * join, ulong ele_idx, myele_t * pool );
     ulong       myslist_idx_pop_head ( myslist_t * join,                myele_t * pool );

     // myslist_remove_all removes all elements from the list and
     // returns join.  It is the caller's responsibility to release all
     // elements to the pool as might be necessary.

     myslist_t * myslist_remove_all( myslist_t * join );

     // myslist_merge_head prepends other to the head of list.
     // myslist_merge_tail appends other to the tail of list.
     // Returns list.  On return, other is empty.  U.B. if list and
     // other share an element in the pool.

     myslist_t * mylist_merge_head( myslist_t * list, myslist_t * other, myele_t const * pool );
     myslist_t * mylist_merge_tail( myslist_t * list, myslist_t * other, myele_t const * pool );

     // myslist_iter_* support fast ordered forward (head to tail)
     // iteration over all the elements in a list.  Example usage:
     //
     //   for( myslist_iter_t iter = myslist_iter_fwd_init( join, pool );
     //        !myslist_iter_done( iter, join, pool );
     //        iter = mydlist_iter_fwd_next( iter, join, pool ) ) {
     //     ulong ele_idx = mydlist_iter_idx( iter, join, pool );
     //
     //     ... process element here
     //
     //     ... IMPORTANT!  It is generally safe to insert elements
     //     ... here (though they might not be covered by this
     //     ... iteration).  It is also generally safe to remove any
     //     ... element but the current element here (the removed
     //     ... element might have already be iterated over).
     //   }

     struct mydlist_iter_private { ... internal use only ... };
     typedef struct mydlist_iter_private mydlist_iter_t;

     mydlist_iter_t  mydlist_iter_fwd_init(                      mydlist_t const * join, myele_t const * pool );
     int             mydlist_iter_done    ( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool );
     mydlist_iter_t  mydlist_iter_fwd_next( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool ); // assumes !done
     ulong           mydlist_iter_idx     ( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool ); // assumes !done

     // myslist_verify returns 0 if the myslist is not obviously corrupt
     // or -1 (i.e. ERR_INVAL) otherwise (logs details).

     int
     myslist_verify( myslist_t const * join,    // Current local join to a myslist.
                     ulong             ele_cnt, // Element storage size, in [0,myslist_ele_max()]
                     myele_t const *   pool );  // Current local join to element storage, indexed [0,ele_cnt)

     // The above APIs have helpers that operate purely in the caller's
     // local address space when applicable.  The various elements
     // passed to / returned from these functions should be / will be
     // from the list's underlying pool.

     myele_t * myslist_ele_peek_head( myslist_t const * join, myele_t * pool );
     myele_t * myslist_ele_peek_tail( myslist_t const * join, myele_t * pool );

     myslist_t * myslist_ele_push_head( myslist_t * join, myele_t * ele, myele_t * pool );
     myslist_t * myslist_ele_push_tail( myslist_t * join, myele_t * ele, myele_t * pool );
     myele_t *   myslist_ele_pop_head ( myslist_t * join,                myele_t * pool );

     myele_t * mydlist_iter_ele( mydlist_iter_t iter, mydlist_t const * join, myele_t * pool );

   You can do this as often as you like in a compilation unit to get
   different types of lists.  Variants exist for making header
   prototypes only and/or implementations only if making a library for
   use across multiple compilation units.  Further, options exist to use
   different list link types, names, etc as detailed below. */

/* TODO: DOC CONCURRENCY REQUIREMENTS */

/* SLIST_NAME gives the API prefix to use for a slist */

#ifndef SLIST_NAME
#error "Define SLIST_NAME"
#endif

/* SLIST_ELE_T is the list element type */

#ifndef SLIST_ELE_T
#error "Define SLIST_ELE_T"
#endif

/* SLIST_IDX_T is the type used for the next field in the SLIST_ELE_T.
   Should be a primitive unsigned integer type.  Defaults to a ulong.
   A list can't use element memory regions with more elements than the
   maximum value that can be represented by a SLIST_IDX_T.  (E.g. if
   ushort, the maximum element store supported by the list is 65535
   elements.)*/

#ifndef SLIST_IDX_T
#define SLIST_IDX_T ulong
#endif

/* SLIST_NEXT is the SLIST_ELE_T next field */

#ifndef SLIST_NEXT
#define SLIST_NEXT next
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef SLIST_IMPL_STYLE
#define SLIST_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

/* Constructors and verification log details on failure (rest only needs
   fd_bits.h, consider making logging a compile time option). */

#include "../log/fd_log.h"

#define SLIST_(n) FD_EXPAND_THEN_CONCAT3(SLIST_NAME,_,n)

#if SLIST_IMPL_STYLE==0 || SLIST_IMPL_STYLE==1 /* need structures and inlines */

struct __attribute__((aligned(8))) SLIST_(private) {

  /* join points here */

  SLIST_IDX_T head;
  SLIST_IDX_T tail;
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

/* list_private_{cidx,idx} compress / decompress 64-bit in-register
   indices to/from their in-memory representations. */

FD_FN_CONST static inline SLIST_IDX_T SLIST_(private_cidx)( ulong      idx   ) { return (SLIST_IDX_T)idx;  }
FD_FN_CONST static inline ulong       SLIST_(private_idx) ( SLIST_IDX_T cidx ) { return (ulong)     cidx; }

/* list_private_idx_null returns the element storage index that
   represents NULL. */

FD_FN_CONST static inline ulong SLIST_(private_idx_null)( void ) { return (ulong)(SLIST_IDX_T)~0UL; }

/* list_private_idx_is_null returns 1 if idx is the NULL list index
   and 0 otherwise. */

FD_FN_CONST static inline int SLIST_(private_idx_is_null)( ulong idx ) { return idx==(ulong)(SLIST_IDX_T)~0UL; }

FD_FN_CONST static ulong SLIST_(ele_max)( void ) { return (ulong)(SLIST_IDX_T)~0UL; }

FD_FN_PURE static inline int
SLIST_(is_empty)( SLIST_(t) const * join ) {
  return SLIST_(private_idx_is_null)( SLIST_(private_idx)( SLIST_(private_const)( join )->head ) );
}

FD_FN_PURE static inline ulong
SLIST_(idx_peek_head)( SLIST_(t) const * join ) {
  return SLIST_(private_idx)( SLIST_(private_const)( join )->head );
}

FD_FN_PURE static inline ulong
SLIST_(idx_peek_tail)( SLIST_(t) const * join ) {
  return SLIST_(private_idx)( SLIST_(private_const)( join )->tail );
}

static inline SLIST_(t) *
SLIST_(idx_push_head)( SLIST_(t) *   join,
                       ulong         ele_idx,
                       SLIST_ELE_T * pool ) {
  SLIST_(private_t) * list = SLIST_(private)( join );

  ulong head_idx = SLIST_(private_idx)( list->head );

  pool[ ele_idx ].SLIST_NEXT = SLIST_(private_cidx)( head_idx );

  if( SLIST_(private_idx_is_null)( head_idx ) ) {
    list->tail = SLIST_(private_cidx)( ele_idx );
  }

  list->head = SLIST_(private_cidx)( ele_idx );
  return join;
}

static inline SLIST_(t) *
SLIST_(idx_push_tail)( SLIST_(t) *   join,
                       ulong         ele_idx,
                       SLIST_ELE_T * pool ) {
  SLIST_(private_t) * list = SLIST_(private)( join );

  ulong tail_idx = SLIST_(private_idx)( list->tail );

  pool[ ele_idx ].SLIST_NEXT = SLIST_(private_cidx)( SLIST_(private_idx_null)() );

  *fd_ptr_if( !SLIST_(private_idx_is_null)( tail_idx ), &pool[ tail_idx ].SLIST_NEXT, &list->head ) =
    SLIST_(private_cidx)( ele_idx );

  list->tail = SLIST_(private_cidx)( ele_idx );
  return join;
}

static inline ulong
SLIST_(idx_pop_head)( SLIST_(t) *   join,
                      SLIST_ELE_T * pool ) {
  SLIST_(private_t) * list = SLIST_(private)( join );

  ulong ele_idx  = SLIST_(private_idx)( list->head ); /* Not NULL as per contract */
  ulong next_idx = SLIST_(private_idx)( pool[ ele_idx ].SLIST_NEXT );

  if( SLIST_(private_idx_is_null)( next_idx ) ) {
    list->tail = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  }

  list->head = SLIST_(private_cidx)( next_idx );
  return ele_idx;
}

static inline ulong
SLIST_(idx_remove)( SLIST_(t) *   join,
                    ulong         idx,
                    ulong         prior,
                    SLIST_ELE_T * pool ) {
  SLIST_(private_t) * list = SLIST_(private)( join );
  if( SLIST_(private_idx_is_null)( prior ) ) {
    return SLIST_(idx_pop_head)( join, pool );
  }
  ulong next_idx = SLIST_(private_idx)( pool[ idx ].SLIST_NEXT );
  pool[ prior ].SLIST_NEXT = SLIST_(private_cidx)( next_idx );
  if( SLIST_(private_idx_is_null)( next_idx ) ) {
    list->tail = SLIST_(private_cidx)( prior );
  }
  return idx;
}

static inline SLIST_(t) *
SLIST_(remove_all)( SLIST_(t) * join ) {
  SLIST_(private_t) * list = SLIST_(private)( join );
  list->head = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  list->tail = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  return join;
}

FD_FN_PURE static inline SLIST_(iter_t)
SLIST_(iter_fwd_init)( SLIST_(t) const *   join,
                       SLIST_ELE_T const * pool ) {
  (void)pool;
  return SLIST_(private_idx)( SLIST_(private_const)( join )->head );
}

FD_FN_PURE static inline SLIST_(iter_t)
SLIST_(iter_rev_init)( SLIST_(t) const *   join,
                       SLIST_ELE_T const * pool ) {
  (void)pool;
  return SLIST_(private_idx)( SLIST_(private_const)( join )->tail );
}

FD_FN_CONST static inline int
SLIST_(iter_done)( SLIST_(iter_t)      iter,
                   SLIST_(t) const *   join,
                   SLIST_ELE_T const * pool ) {
  (void)join; (void)pool;
  return SLIST_(private_idx_is_null)( iter );
}

FD_FN_PURE static inline SLIST_(iter_t)
SLIST_(iter_fwd_next)( SLIST_(iter_t)      iter,
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
  return pool + SLIST_(idx_peek_head)( join );
}

FD_FN_PURE static inline SLIST_ELE_T const *
SLIST_(ele_peek_head_const)( SLIST_(t) const *   join,
                             SLIST_ELE_T const * pool ) {
  return pool + SLIST_(idx_peek_head)( join );
}

FD_FN_PURE static inline SLIST_ELE_T *
SLIST_(ele_peek_tail)( SLIST_(t) const * join,
                       SLIST_ELE_T *     pool ) {
  return pool + SLIST_(idx_peek_tail)( join );
}

FD_FN_PURE static inline SLIST_ELE_T const *
SLIST_(ele_peek_tail_const)( SLIST_(t) const *   join,
                             SLIST_ELE_T const * pool ) {
  return pool + SLIST_(idx_peek_tail)( join );
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

static inline SLIST_ELE_T *
SLIST_(ele_remove)( SLIST_(t) *   join,
                    SLIST_ELE_T * ele,
                    SLIST_ELE_T * prior,
                    SLIST_ELE_T * pool ) {
  SLIST_(private_t) * list = SLIST_(private)( join );
  if( prior==NULL ) {
    return SLIST_(ele_pop_head)( join, pool );
  }
  prior->SLIST_NEXT = ele->SLIST_NEXT;
  if( SLIST_(private_idx_is_null)( prior->SLIST_NEXT ) ) {
    list->tail = SLIST_(private_cidx)( (ulong)(prior-pool) );
  }
  return ele;
}

FD_FN_CONST static inline SLIST_ELE_T *
SLIST_(iter_ele)( SLIST_(iter_t)    iter,
                  SLIST_(t) const * join,
                  SLIST_ELE_T *     pool ) {
  (void)join; (void)pool;
  return pool + iter;
}

static inline SLIST_(t) *
SLIST_(merge_head)( SLIST_(t) *   list,
                    SLIST_(t) *   other,
                    SLIST_ELE_T * pool ) {

  SLIST_(private_t) * dst = SLIST_(private)( list  );
  SLIST_(private_t) * src = SLIST_(private)( other );

  ulong head_idx    = src->head;
  ulong merge_l_idx = src->tail;
  ulong merge_r_idx = dst->head;

  if( SLIST_(private_idx_is_null)( merge_r_idx ) ) {
    dst->tail = SLIST_(private_cidx)( merge_l_idx );
  }
  if( !SLIST_(private_idx_is_null)( merge_l_idx ) ) {
    pool[ merge_l_idx ].SLIST_NEXT = SLIST_(private_cidx)( merge_r_idx );
    dst->head                      = SLIST_(private_cidx)( head_idx   );
  }

  src->head = src->tail = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  return list;
}

FD_PROTOTYPES_END

#endif

#if SLIST_IMPL_STYLE==1 /* need prototypes */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong SLIST_(align)    ( void              );
FD_FN_CONST ulong SLIST_(footprint)( void              );
void *            SLIST_(new)      ( void *     shmem  );
SLIST_(t) *       SLIST_(join)     ( void *     shlist );
void *            SLIST_(leave)    ( SLIST_(t) * join  );
void *            SLIST_(delete)   ( void *     shlist );

FD_FN_PURE int
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

  SLIST_(private_t) * list = (SLIST_(private_t) *)shmem;

  list->head = SLIST_(private_cidx)( SLIST_(private_idx_null)() );
  list->tail = SLIST_(private_cidx)( SLIST_(private_idx_null)() );

  return shmem;
}

SLIST_IMPL_STATIC SLIST_(t) *
SLIST_(join)( void * shlist ) {
  SLIST_(private_t) * list = (SLIST_(private_t) *)shlist;

  if( FD_UNLIKELY( !list ) ) {
    FD_LOG_WARNING(( "NULL shlist" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)list, SLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shlist" ));
    return NULL;
  }

  return (SLIST_(t) *)list;
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
SLIST_(delete)( void * shlist ) {
  SLIST_(private_t) * list = (SLIST_(private_t) *)shlist;

  if( FD_UNLIKELY( !list ) ) {
    FD_LOG_WARNING(( "NULL shlist" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)list, SLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shlist" ));
    return NULL;
  }

  return shlist;
}

FD_FN_PURE SLIST_IMPL_STATIC int
SLIST_(verify)( SLIST_(t) const *   join,
                ulong               ele_cnt,
                SLIST_ELE_T const * pool ) {

# define SLIST_TEST(c) do {                                                      \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  /* Validate input args */

  SLIST_TEST( join                      );
  SLIST_TEST( ele_cnt<=SLIST_(ele_max)() );
  SLIST_TEST( (!!pool) | (!ele_cnt)     );

  /* Iterate forward through the list, validating as we go */

  SLIST_(private_t) const * list = SLIST_(private_const)( join );

  ulong rem      = ele_cnt;
  ulong prev_idx = SLIST_(private_idx_null)();
  ulong ele_idx  = SLIST_(private_idx)( list->head );
  while( !SLIST_(private_idx_is_null)( ele_idx ) ) {

    /* Visit ele_idx */

    SLIST_TEST( rem ); rem--;      /* Test for cycles */
    SLIST_TEST( ele_idx<ele_cnt ); /* Test valid ele_idx */

    /* Advance to next element */

    prev_idx = ele_idx;
    ele_idx  = SLIST_(private_idx)( pool[ ele_idx ].SLIST_NEXT );
  }

  SLIST_TEST( SLIST_(private_idx)( list->tail )==prev_idx );

# undef SLIST_TEST

  return 0;
}

FD_PROTOTYPES_END

#undef SLIST_IMPL_STATIC

#endif

#undef SLIST_

#undef SLIST_IMPL_STYLE
#undef SLIST_NEXT
#undef SLIST_IDX_T
#undef SLIST_ELE_T
#undef SLIST_NAME
