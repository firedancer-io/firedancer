/* Generate prototypes, inlines and/or implementations for HPC doubly
   linked lists.  A dlist can store a practically unbounded number of
   elements.  Typical dlist operations are generally a fast O(1) time
   and dlist element memory overhead is a small O(1) space.

   This API is designed for ultra tight coupling with pools, treaps,
   heaps, maps, other dlists, etc.  Likewise, a dlist can be persisted
   beyond the lifetime of the creating process, used concurrently in
   many common operations, used inter-process, relocated in memory,
   naively serialized/deserialized, moved between hosts, supports index
   compresson for cache and memory bandwidth efficiency, etc.

   Memory efficiency and flexible footprint are prioritized.

   Typical usage:

     struct myele {
       ulong prev; // Technically "DLIST_IDX_T DLIST_PREV" (default is ulong prev), do not modify while element is in the dlist
       ulong next; // Technically "DLIST_IDX_T DLIST_NEXT" (default is ulong next), do not modify while element is in the dlist
       ... prev and next can be located arbitrarily in the element and
       ... can be reused for other purposes when the element is not a in
       ... dlist.  An element should not be moved / released while an
       ... element is in a dlist
     };

     typedef struct myele myele_t;

     #define DLIST_NAME  mydlist
     #define DLIST_ELE_T myele_t
     #include "tmpl/fd_dlist.c"

   will declare the following APIs as a header only style library in the
   compilation unit:

     // mydlist_ele_max returns the theoretical maximum number of
     // elements that can be held in a mydlist.

     ulong mydlist_ele_max( void );

     // mydlist_{align,footprint} returns the alignment and footprint
     // needed for a memory region to be used as a mydlist.  align will
     // be an integer power-of-two and footprint will be a multiple of
     // align.  The values will be compile-time declaration friendly
     // (e.g. "mydlist_t mem[1];" will have the correct alignment and
     // footprint and not be larger than 4096).
     //
     // mydlist_new formats a memory region with the appropriate
     // alignment and footprint whose first byte in the caller's address
     // space is pointed to by shmem as a mydlist.  Returns shmem on
     // success and NULL on failure (logs details).  Caller is not
     // joined on return.  The dlist will be empty.
     //
     // mydlist_join joins a mydlist.  Assumes shdlist points at a
     // memory region formatted as a mydlist in the caller's address
     // space.  Returns a handle to the caller's local join on success
     // and NULL on failure (logs details).  Do not assume this is a
     // simple cast of shdlist!
     //
     // mydlist_leave leaves a mydlist.  Assumes join points to a
     // current local join.  Returns shdlist used on join.  Do not
     // assume this is a simple cast of join!
     //
     // mydlist_delete unformats a memory region used as a mydlist.
     // Assumes shdlist points to a memory region in the caller's local
     // address space formatted as a mydlist, that there are no joins to
     // the mydlist and that any application cleanup of the entries has
     // already been done.  Returns shdlist on success and NULL on
     // failure.

     ulong       mydlist_align    ( void );
     ulong       mydlist_footprint( void );
     void *      mydlist_new      ( void *      shmem   );
     mydlist_t * mydlist_join     ( void *      shdlist );
     void *      mydlist_leave    ( mydlist_t * join    );
     void *      mydlist_delete   ( void *      shdlist );

     // The below APIs assume join is a current local join to a mydlist
     // and pool is a current local join to the element storage backing
     // the dlist.
     //
     // mydlist_is_empty returns 1 if the dlist is empty and 0
     // otherwise.
     //
     // mydlist_idx_peek_{head,tail} returns the pool index of the
     // dlist's {head,tail}.  Assumes dlist is not empty.

     int mydlist_is_empty( mydlist_t const * join, myele_t const * pool );

     ulong mydlist_idx_peek_head( mydlist_t const * join, myele_t const * pool );
     ulong mydlist_idx_peek_tail( mydlist_t const * join, myele_t const * pool );

     // mydlist_idx_push_{head,tail} pushes the pool element whose index
     // is ele_idx to the dlist's {head,tail} and returns join.  Assumes
     // ele_idx valid and not already in the dlist.
     /
     // mydlist_idx_pop_{head,tail} pops the pool element at the dlist's
     // {head,tail} and returns its pool index.  Assumes dlist is not
     // empty.
     //
     // mydlist_idx_insert_{before,after} inserts the pool element whose
     // index is ele_idx into the dlist immediately {before,after} the
     // pool element whose index is {next_idx,prev_idx} and returns
     // join.  Assumes ele_idx is valid and not already in the dlist and
     // {next_idx,prev_idx} are already in the dlist.
     //
     // mydlist_idx_remove removes the pool element whose index is
     // ele_idx from the dlist and returns join.  Assumes ele_idx is in
     // the dlist already.
     //
     // mydlist_idx_replace replaces the pool element whose index is
     // old_idx with the pool element whose index is ele_idx in the
     // dlist and returns join.  Assumes ele_idx is not in the dlist and
     // old_idx is in the dlist already.

     mydlist_t * mydlist_idx_push_head    ( mydlist_t * join, ulong ele_idx,                 myele_t * pool );
     mydlist_t * mydlist_idx_push_tail    ( mydlist_t * join, ulong ele_idx,                 myele_t * pool );
     ulong       mydlist_idx_pop_head     ( mydlist_t * join,                                myele_t * pool );
     ulong       mydlist_idx_pop_tail     ( mydlist_t * join,                                myele_t * pool );
     mydlist_t * mydlist_idx_insert_before( mydlist_t * join, ulong ele_idx, ulong next_idx, myele_t * pool );
     mydlist_t * mydlist_idx_insert_after ( mydlist_t * join, ulong ele_idx, ulong prev_idx, myele_t * pool );
     mydlist_t * mydlist_idx_remove       ( mydlist_t * join, ulong ele_idx,                 myele_t * pool );
     mydlist_t * mydlist_idx_replace      ( mydlist_t * join, ulong ele_idx, ulong old_idx,  myele_t * pool );

     // mydlist_remove_all removes all elements from the dlist and
     // returns join.  It is the caller's responsibility to release all
     // elements to the pool as might be necessary.

     mydlist_t * mydlist_remove_all( mydlist_t * join, myele_t * pool );

     // mydlist_iter_* support fast ordered forward (head to tail) and
     // reverse (tail to head) iteration over all the elements in a
     // dlist.  Example usage:
     //
     //   for( mydlist_iter_t iter = mydlist_iter_rev_init( join, pool );
     //        !mydlist_iter_done( iter, join, pool );
     //        iter = mydlist_iter_rev_next( iter, join, pool ) ) {
     //     ulong ele_idx = mydlist_iter_idx( iter, join, pool );
     //
     //     ... process element here
     //
     //     ... IMPORTANT!  It is generally safe to insert elements
     //     ... here (though they might not be covered by this
     //     ... iteration).  It is also generally safe to remove any
     //     ... element but the current element here (the removed
     //     ... element might have already be iterated over).  It is
     //     ... straightforward to make a variant of this iterator
     //     ... that would support removing the current element here
     //     ... if desired.
     //   }

     struct mydlist_iter_private { ... internal use only ... };
     typedef struct mydlist_iter_private mydlist_iter_t;

     mydlist_iter_t  mydlist_iter_fwd_init(                      mydlist_t const * join, myele_t const * pool );
     mydlist_iter_t  mydlist_iter_rev_init(                      mydlist_t const * join, myele_t const * pool );
     int             mydlist_iter_done    ( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool );
     mydlist_iter_t  mydlist_iter_fwd_next( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool ); // assumes !done
     mydlist_iter_t  mydlist_iter_rev_next( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool ); // assumes !done
     ulong           mydlist_iter_idx     ( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool ); // assumes !done

     // mydlist_verify returns 0 if the mydlist is not obviously corrupt
     // or -1 (i.e. ERR_INVAL) otherwise (logs details).

     int
     mydlist_verify( mydlist_t const * join,    // Current local join to a mydlist.  
                     ulong             ele_cnt, // Element storage size, in [0,mydlist_ele_max()]
                     myele_t const *   pool );  // Current local join to element storage, indexed [0,ele_cnt)

     // The above APIs have helpers that operate purely in the caller's
     // local address space when applicable.  The various elements
     // passed to / returned from these functions should be / will be
     // from the dlist's underlying pool.

     myele_t * mydlist_ele_peek_head( mydlist_t const * join, myele_t * pool );
     myele_t * mydlist_ele_peek_tail( mydlist_t const * join, myele_t * pool );

     mydlist_t * mydlist_ele_push_head    ( mydlist_t * join, myele_t * ele,                 myele_t * pool );
     mydlist_t * mydlist_ele_push_tail    ( mydlist_t * join, myele_t * ele,                 myele_t * pool );
     myele_t *   mydlist_ele_pop_head     ( mydlist_t * join,                                myele_t * pool );
     myele_t *   mydlist_ele_pop_tail     ( mydlist_t * join,                                myele_t * pool );
     mydlist_t * mydlist_ele_insert_before( mydlist_t * join, myele_t * ele, myele_t * next, myele_t * pool );
     mydlist_t * mydlist_ele_insert_after ( mydlist_t * join, myele_t * ele, myele_t * prev, myele_t * pool );
     mydlist_t * mydlist_ele_replace      ( mydlist_t * join, myele_t * ele, myele_t * old,  myele_t * pool );
     mydlist_t * mydlist_ele_remove       ( mydlist_t * join, myele_t * ele,                 myele_t * pool );

     myele_t * mydlist_iter_ele( mydlist_iter_t iter, mydlist_t const * join, myele_t * pool );

     // ... and const correct helpers when applicable

     myele_t const * mydlist_ele_peek_head_const( mydlist_t const * join, myele_t const * pool );
     myele_t const * mydlist_ele_peek_tail_const( mydlist_t const * join, myele_t const * pool );

     myele_t const * mydlist_iter_ele_const( mydlist_iter_t iter, mydlist_t const * join, myele_t const * pool );

   You can do this as often as you like in a compilation unit to get
   different types of dlists.  Variants exist for making header
   prototypes only and/or implementations only if making a library for
   use across multiple compilation units.  Further, options exist to use
   different hashing functions, comparison functions, etc as detailed
   below. */

/* TODO: DOC CONCURRENCY REQUIREMENTS */

/* DLIST_NAME gives the API prefix to use for a dlist */

#ifndef DLIST_NAME
#error "Define DLIST_NAME"
#endif

/* DLIST_ELE_T is the dlist element type. */

#ifndef DLIST_ELE_T
#error "Define DLIST_ELE_T"
#endif

/* DLIST_IDX_T is the type used for the prev and next fields in the
   DLIST_ELE_T.  Should be a primitive unsigned integer type.  Defaults
   to ulong.  A dlist can't use element memory regions with more
   elements than the maximum value that can be represented by a
   DLIST_IDX_T.  (E.g. if ushort, the maximum size element store
   supported by the dlist is 65535 elements.) */

#ifndef DLIST_IDX_T
#define DLIST_IDX_T ulong
#endif

/* DLIST_PREV is the DLIST_ELE_T prev field */

#ifndef DLIST_PREV
#define DLIST_PREV prev
#endif

/* DLIST_NEXT is the DLIST_ELE_T next field */

#ifndef DLIST_NEXT
#define DLIST_NEXT next
#endif

/* DLIST_MAGIC is the magic number to use for the structure to aid in
   persistent and/or IPC usage. */

#ifndef DLIST_MAGIC
#define DLIST_MAGIC (0xf17eda2c37d71570UL) /* firedancer dlist version 0 */
#endif

/* 0 - local use only
   1 - library header declaration
   2 - library implementation */

#ifndef DLIST_IMPL_STYLE
#define DLIST_IMPL_STYLE 0
#endif

/* Implementation *****************************************************/

/* Constructors and verification log details on failure (rest only needs
   fd_bits.h, consider making logging a compile time option). */

#include "../log/fd_log.h"

#define DLIST_(n) FD_EXPAND_THEN_CONCAT3(DLIST_NAME,_,n)

#if DLIST_IMPL_STYLE==0 || DLIST_IMPL_STYLE==1 /* need structures and inlines */

struct DLIST_(private) {

  /* join points here */

  ulong       magic; /* == DLIST_MAGIC */
  DLIST_IDX_T head;  /* index of first list element (or idx_null if empty list) */
  DLIST_IDX_T tail;  /* index of last  list element (or idx_null if empty list) */
};

typedef struct DLIST_(private) DLIST_(private_t);

typedef DLIST_(private_t) DLIST_(t);

typedef ulong DLIST_(iter_t);

FD_PROTOTYPES_BEGIN

/* dlist_private returns the location of the dlist header for a current
   local join.  Assumes join is a current local join.
   dlist_private_const is a const correct version. */

FD_FN_CONST static inline DLIST_(private_t) *
DLIST_(private)( DLIST_(t) * join ) {
  return (DLIST_(private_t) *)join;
}

FD_FN_CONST static inline DLIST_(private_t) const *
DLIST_(private_const)( DLIST_(t) const * join ) {
  return (DLIST_(private_t) const *)join;
}

/* dlist_private_{cidx,idx} compress / decompress 64-bit in-register
   indices to/from their in-memory representations. */

FD_FN_CONST static inline DLIST_IDX_T DLIST_(private_cidx)( ulong       idx  ) { return (DLIST_IDX_T)idx;  }
FD_FN_CONST static inline ulong       DLIST_(private_idx) ( DLIST_IDX_T cidx ) { return (ulong)      cidx; }

/* dlist_private_idx_null returns the element storage index that
   represents NULL. */

FD_FN_CONST static inline ulong DLIST_(private_idx_null)( void ) { return (ulong)(DLIST_IDX_T)~0UL; }

/* dlist_private_idx_is_null returns 1 if idx is the NULL dlist index
   and 0 otherwise. */

FD_FN_CONST static inline int DLIST_(private_idx_is_null)( ulong idx ) { return idx==(ulong)(DLIST_IDX_T)~0UL; }

FD_FN_CONST static ulong DLIST_(ele_max)( void ) { return (ulong)(DLIST_IDX_T)~0UL; }

FD_FN_PURE static inline int
DLIST_(is_empty)( DLIST_(t) const *   join,
                  DLIST_ELE_T const * pool ) {
  (void)pool;
  return DLIST_(private_idx_is_null)( DLIST_(private_idx)( DLIST_(private_const)( join )->head ) );
}

FD_FN_PURE static inline ulong
DLIST_(idx_peek_head)( DLIST_(t) const *   join,
                       DLIST_ELE_T const * pool ) {
  (void)pool;
  return DLIST_(private_idx)( DLIST_(private_const)( join )->head );
}

FD_FN_PURE static inline ulong
DLIST_(idx_peek_tail)( DLIST_(t) const *   join,
                       DLIST_ELE_T const * pool ) {
  (void)pool;
  return DLIST_(private_idx)( DLIST_(private_const)( join )->tail );
}

static inline DLIST_(t) *
DLIST_(idx_push_head)( DLIST_(t) *   join,
                       ulong         ele_idx,
                       DLIST_ELE_T * pool ) {
  DLIST_(private_t) * dlist = DLIST_(private)( join );

  ulong head_idx = DLIST_(private_idx)( dlist->head );

  pool[ ele_idx ].DLIST_PREV = DLIST_(private_cidx)( DLIST_(private_idx_null)() );
  pool[ ele_idx ].DLIST_NEXT = DLIST_(private_cidx)( head_idx );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( head_idx ), &pool[ head_idx ].DLIST_PREV, &dlist->tail ) =
    DLIST_(private_cidx)( ele_idx );

  dlist->head = DLIST_(private_cidx)( ele_idx );
  return join;
}

static inline DLIST_(t) *
DLIST_(idx_push_tail)( DLIST_(t) *   join,
                       ulong         ele_idx,
                       DLIST_ELE_T * pool ) {
  DLIST_(private_t) * dlist = DLIST_(private)( join );

  ulong tail_idx = DLIST_(private_idx)( dlist->tail );

  pool[ ele_idx ].DLIST_PREV = DLIST_(private_cidx)( tail_idx );
  pool[ ele_idx ].DLIST_NEXT = DLIST_(private_cidx)( DLIST_(private_idx_null)() );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( tail_idx ), &pool[ tail_idx ].DLIST_NEXT, &dlist->head ) =
    DLIST_(private_cidx)( ele_idx );

  dlist->tail = DLIST_(private_cidx)( ele_idx );
  return join;
}

static inline ulong
DLIST_(idx_pop_head)( DLIST_(t) *   join,
                      DLIST_ELE_T * pool ) {
  DLIST_(private_t) * dlist = DLIST_(private)( join );

  ulong ele_idx  = DLIST_(private_idx)( dlist->head ); /* Not NULL as per contract */
  ulong next_idx = DLIST_(private_idx)( pool[ ele_idx ].DLIST_NEXT );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( next_idx ), &pool[ next_idx ].DLIST_PREV, &dlist->tail ) =
    DLIST_(private_cidx)( DLIST_(private_idx_null)() );

  dlist->head = DLIST_(private_cidx)( next_idx );
  return ele_idx;
}

static inline ulong
DLIST_(idx_pop_tail)( DLIST_(t) *   join,
                      DLIST_ELE_T * pool ) {
  DLIST_(private_t) * dlist = DLIST_(private)( join );

  ulong ele_idx  = DLIST_(private_idx)( dlist->tail ); /* Not NULL as per contract */
  ulong prev_idx = DLIST_(private_idx)( pool[ ele_idx ].DLIST_PREV );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( prev_idx ), &pool[ prev_idx ].DLIST_NEXT, &dlist->head ) =
    DLIST_(private_cidx)( DLIST_(private_idx_null)() );

  dlist->tail = DLIST_(private_cidx)( prev_idx );
  return ele_idx;
}

static inline DLIST_(t) *
DLIST_(idx_insert_before)( DLIST_(t) *   join,
                           ulong         ele_idx,
                           ulong         next_idx,
                           DLIST_ELE_T * pool ) {
  ulong prev_idx = DLIST_(private_idx)( pool[ next_idx ].DLIST_PREV );

  pool[ ele_idx ].DLIST_PREV = DLIST_(private_cidx)( prev_idx );
  pool[ ele_idx ].DLIST_NEXT = DLIST_(private_cidx)( next_idx );

  pool[ next_idx ].DLIST_PREV = DLIST_(private_cidx)( ele_idx );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( prev_idx ), &pool[ prev_idx ].DLIST_NEXT, &DLIST_(private)( join )->head ) =
    DLIST_(private_cidx)( ele_idx );

  return join;
}

static inline DLIST_(t) *
DLIST_(idx_insert_after)( DLIST_(t) *   join,
                          ulong         ele_idx,
                          ulong         prev_idx,
                          DLIST_ELE_T * pool ) {
  ulong next_idx = DLIST_(private_idx)( pool[ prev_idx ].DLIST_NEXT );

  pool[ ele_idx ].DLIST_PREV = DLIST_(private_cidx)( prev_idx );
  pool[ ele_idx ].DLIST_NEXT = DLIST_(private_cidx)( next_idx );

  pool[ prev_idx ].DLIST_NEXT = DLIST_(private_cidx)( ele_idx );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( next_idx ), &pool[ next_idx ].DLIST_PREV, &DLIST_(private)( join )->tail ) =
    DLIST_(private_cidx)( ele_idx );

  return join;
}

static inline DLIST_(t) *
DLIST_(idx_remove)( DLIST_(t) *   join,
                    ulong         ele_idx,
                    DLIST_ELE_T * pool ) {
  DLIST_(private_t) * dlist = DLIST_(private)( join );

  ulong prev_idx = DLIST_(private_idx)( pool[ ele_idx ].DLIST_PREV );
  ulong next_idx = DLIST_(private_idx)( pool[ ele_idx ].DLIST_NEXT );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( next_idx ), &pool[ next_idx ].DLIST_PREV, &dlist->tail ) =
    DLIST_(private_cidx)( prev_idx );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( prev_idx ), &pool[ prev_idx ].DLIST_NEXT, &dlist->head ) =
    DLIST_(private_cidx)( next_idx );

  return join;
}

static inline DLIST_(t) *
DLIST_(idx_replace)( DLIST_(t) *   join,
                     ulong         ele_idx,
                     ulong         old_idx,
                     DLIST_ELE_T * pool ) {
  DLIST_(private_t) * dlist = DLIST_(private)( join );

  ulong prev_idx = DLIST_(private_idx)( pool[ old_idx ].DLIST_PREV );
  ulong next_idx = DLIST_(private_idx)( pool[ old_idx ].DLIST_NEXT );

  pool[ ele_idx ].DLIST_PREV = DLIST_(private_cidx)( prev_idx );
  pool[ ele_idx ].DLIST_NEXT = DLIST_(private_cidx)( next_idx );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( next_idx ), &pool[ next_idx ].DLIST_PREV, &dlist->tail ) =
    DLIST_(private_cidx)( ele_idx );

  *fd_ptr_if( !DLIST_(private_idx_is_null)( prev_idx ), &pool[ prev_idx ].DLIST_NEXT, &dlist->head ) =
    DLIST_(private_cidx)( ele_idx );

  return join;
}

static inline DLIST_(t) *
DLIST_(remove_all)( DLIST_(t) *   join,
                    DLIST_ELE_T * pool ) {
  (void)pool;
  DLIST_(private_t) * dlist = DLIST_(private)( join );
  dlist->head = DLIST_(private_cidx)( DLIST_(private_idx_null)() );
  dlist->tail = DLIST_(private_cidx)( DLIST_(private_idx_null)() );
  return join;
}

FD_FN_PURE static inline DLIST_(iter_t)
DLIST_(iter_fwd_init)( DLIST_(t) const *   join,
                       DLIST_ELE_T const * pool ) {
  (void)pool;
  return DLIST_(private_idx)( DLIST_(private_const)( join )->head );
}

FD_FN_PURE static inline DLIST_(iter_t)
DLIST_(iter_rev_init)( DLIST_(t) const *   join,
                       DLIST_ELE_T const * pool ) {
  (void)pool;
  return DLIST_(private_idx)( DLIST_(private_const)( join )->tail );
}

FD_FN_CONST static inline int
DLIST_(iter_done)( DLIST_(iter_t)      iter,
                   DLIST_(t) const *   join,
                   DLIST_ELE_T const * pool ) {
  (void)join; (void)pool;
  return DLIST_(private_idx_is_null)( iter );
}

FD_FN_PURE static inline DLIST_(iter_t)
DLIST_(iter_fwd_next)( DLIST_(iter_t)      iter,
                       DLIST_(t) const *   join,
                       DLIST_ELE_T const * pool ) {
  (void)join;
  return DLIST_(private_idx)( pool[ iter ].DLIST_NEXT );
}

FD_FN_PURE static inline DLIST_(iter_t)
DLIST_(iter_rev_next)( DLIST_(iter_t)      iter,
                       DLIST_(t) const *   join,
                       DLIST_ELE_T const * pool ) {
  (void)join;
  return DLIST_(private_idx)( pool[ iter ].DLIST_PREV );
}

FD_FN_CONST static inline ulong
DLIST_(iter_idx)( DLIST_(iter_t)      iter,
                  DLIST_(t) const *   join,
                  DLIST_ELE_T const * pool ) {
  (void)join; (void)pool;
  return iter;
}

FD_FN_PURE static inline DLIST_ELE_T *
DLIST_(ele_peek_head)( DLIST_(t) const * join,
                       DLIST_ELE_T *     pool ) {
  return pool + DLIST_(idx_peek_head)( join, pool );
}

FD_FN_PURE static inline DLIST_ELE_T const *
DLIST_(ele_peek_head_const)( DLIST_(t) const *   join,
                             DLIST_ELE_T const * pool ) {
  return pool + DLIST_(idx_peek_head)( join, pool );
}

FD_FN_PURE static inline DLIST_ELE_T *
DLIST_(ele_peek_tail)( DLIST_(t) const * join,
                       DLIST_ELE_T *     pool ) {
  return pool + DLIST_(idx_peek_tail)( join, pool );
}

FD_FN_PURE static inline DLIST_ELE_T const *
DLIST_(ele_peek_tail_const)( DLIST_(t) const *   join,
                             DLIST_ELE_T const * pool ) {
  return pool + DLIST_(idx_peek_tail)( join, pool );
}

static inline DLIST_(t) *
DLIST_(ele_push_head)( DLIST_(t) *   join,
                       DLIST_ELE_T * ele,
                       DLIST_ELE_T * pool ) {
  return DLIST_(idx_push_head)( join, (ulong)(ele-pool), pool );
}

static inline DLIST_(t) *
DLIST_(ele_push_tail)( DLIST_(t) *   join,
                       DLIST_ELE_T * ele,
                       DLIST_ELE_T * pool ) {
  return DLIST_(idx_push_tail)( join, (ulong)(ele-pool), pool );
}

static inline DLIST_ELE_T *
DLIST_(ele_pop_head)( DLIST_(t) *   join,
                      DLIST_ELE_T * pool ) {
  return pool + DLIST_(idx_pop_head)( join, pool );
}

static inline DLIST_ELE_T*
DLIST_(ele_pop_tail)( DLIST_(t) *   join,
                      DLIST_ELE_T * pool ) {
  return pool + DLIST_(idx_pop_tail)( join, pool );
}

static inline DLIST_(t) *
DLIST_(ele_insert_before)( DLIST_(t) *   join,
                           DLIST_ELE_T * ele,
                           DLIST_ELE_T * next,
                           DLIST_ELE_T * pool ) {
  return DLIST_(idx_insert_before)( join, (ulong)(ele-pool), (ulong)(next-pool), pool );
}

static inline DLIST_(t) *
DLIST_(ele_insert_after)( DLIST_(t) *   join,
                          DLIST_ELE_T * ele,
                          DLIST_ELE_T * prev,
                          DLIST_ELE_T * pool ) {
  return DLIST_(idx_insert_after)( join, (ulong)(ele-pool), (ulong)(prev-pool), pool );
}

static inline DLIST_(t) *
DLIST_(ele_replace)( DLIST_(t) *   join,
                     DLIST_ELE_T * ele,
                     DLIST_ELE_T * old,
                     DLIST_ELE_T * pool ) {
  return DLIST_(idx_replace)( join, (ulong)(ele-pool), (ulong)(old-pool), pool );
}

static inline DLIST_(t) *
DLIST_(ele_remove)( DLIST_(t) *   join,
                    DLIST_ELE_T * ele,
                    DLIST_ELE_T * pool ) {
  return DLIST_(idx_remove)( join, (ulong)(ele-pool), pool );
}

FD_FN_CONST static inline DLIST_ELE_T *
DLIST_(iter_ele)( DLIST_(iter_t)    iter,
                  DLIST_(t) const * join,
                  DLIST_ELE_T *     pool ) {
  (void)join; (void)pool;
  return pool + iter;
}

FD_FN_CONST static inline DLIST_ELE_T const *
DLIST_(iter_ele_const)( DLIST_(iter_t)      iter,
                        DLIST_(t) const *   join,
                        DLIST_ELE_T const * pool ) {
  (void)join; (void)pool;
  return pool + iter;
}

FD_PROTOTYPES_END

#endif

#if DLIST_IMPL_STYLE==1 /* need prototypes */

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong DLIST_(align)    ( void                );
FD_FN_CONST ulong DLIST_(footprint)( void                );
void *            DLIST_(new)      ( void *      shmem   );
DLIST_(t) *       DLIST_(join)     ( void *      shdlist );
void *            DLIST_(leave)    ( DLIST_(t) * join    );
void *            DLIST_(delete)   ( void *      shdlist );

FD_FN_PURE int
DLIST_(verify)( DLIST_(t) const *   join,
                ulong               ele_cnt,
                DLIST_ELE_T const * pool );

FD_PROTOTYPES_END

#else /* need implementations */

#if DLIST_IMPL_STYLE==0 /* local only */
#define DLIST_IMPL_STATIC FD_FN_UNUSED static
#else
#define DLIST_IMPL_STATIC
#endif

FD_PROTOTYPES_BEGIN

FD_FN_CONST DLIST_IMPL_STATIC ulong DLIST_(align)    ( void ) { return alignof(DLIST_(t)); }
FD_FN_CONST DLIST_IMPL_STATIC ulong DLIST_(footprint)( void ) { return sizeof( DLIST_(t)); }

DLIST_IMPL_STATIC void *
DLIST_(new)( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, DLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  // Note: Guaranteed non-zero and not otherwise used
//ulong footprint = DLIST_(footprint)();
//if( FD_UNLIKELY( !footprint ) ) {
//  FD_LOG_WARNING(( "bad footprint" ));
//  return NULL;
//}

  DLIST_(private_t) * dlist = (DLIST_(private_t) *)shmem;

  dlist->head = DLIST_(private_cidx)( DLIST_(private_idx_null)() );
  dlist->tail = DLIST_(private_cidx)( DLIST_(private_idx_null)() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( dlist->magic ) = DLIST_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

DLIST_IMPL_STATIC DLIST_(t) *
DLIST_(join)( void * shdlist ) {
  DLIST_(private_t) * dlist = (DLIST_(private_t) *)shdlist;

  if( FD_UNLIKELY( !dlist ) ) {
    FD_LOG_WARNING(( "NULL shdlist" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)dlist, DLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shdlist" ));
    return NULL;
  }

  if( FD_UNLIKELY( dlist->magic!=DLIST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (DLIST_(t) *)dlist;
}

DLIST_IMPL_STATIC void *
DLIST_(leave)( DLIST_(t) * join ) {

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  return (void *)join;
}

DLIST_IMPL_STATIC void *
DLIST_(delete)( void * shdlist ) {
  DLIST_(private_t) * dlist = (DLIST_(private_t) *)shdlist;

  if( FD_UNLIKELY( !dlist ) ) {
    FD_LOG_WARNING(( "NULL shdlist" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)dlist, DLIST_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shdlist" ));
    return NULL;
  }

  if( FD_UNLIKELY( dlist->magic!=DLIST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( dlist->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shdlist;
}

FD_FN_PURE DLIST_IMPL_STATIC int
DLIST_(verify)( DLIST_(t) const *   join,
                ulong               ele_cnt,
                DLIST_ELE_T const * pool ) {

# define DLIST_TEST(c) do {                                                      \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  /* Validate input args */

  DLIST_TEST( join                       );
  DLIST_TEST( ele_cnt<=DLIST_(ele_max)() );
  DLIST_TEST( (!!pool) | (!ele_cnt)      );

  /* Iterate forward through the dlist, validating as we go */

  DLIST_(private_t) const * dlist = DLIST_(private_const)( join );

  DLIST_TEST( dlist->magic==DLIST_MAGIC );

  ulong rem      = ele_cnt;
  ulong prev_idx = DLIST_(private_idx_null)();
  ulong ele_idx  = DLIST_(private_idx)( dlist->head );
  while( !DLIST_(private_idx_is_null)( ele_idx ) ) {

    /* Visit ele_idx */

    DLIST_TEST( rem ); rem--;                                                  /* Test for cycles */
    DLIST_TEST( ele_idx<ele_cnt );                                             /* Test valid ele_idx */
    DLIST_TEST( DLIST_(private_idx)( pool[ ele_idx ].DLIST_PREV )==prev_idx ); /* Test reverse link integrity */

    /* Advance to next element */

    prev_idx = ele_idx;
    ele_idx  = DLIST_(private_idx)( pool[ ele_idx ].DLIST_NEXT );
  }

  DLIST_TEST( DLIST_(private_idx)( dlist->tail )==prev_idx );

# undef DLIST_TEST

  return 0;
}

FD_PROTOTYPES_END

#undef DLIST_IMPL_STATIC

#endif

#undef DLIST_

#undef DLIST_IMPL_STYLE
#undef DLIST_MAGIC
#undef DLIST_NEXT
#undef DLIST_PREV
#undef DLIST_IDX_T
#undef DLIST_ELE_T
#undef DLIST_NAME
