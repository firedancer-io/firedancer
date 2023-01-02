/* Declares a family of functions implementing a single threaded
   run time fixed-capacity double ended queue (deque) designed for high
   performance contexts.  The deque is implemented with a circular
   buffer and can push and pop from both ends.  Setting DEQUE_MAX to a
   power of two is strongly recommended but not required.  Example
   usage:

     #define DEQUE_NAME my_deque
     #define DEQUE_T    my_ele_t
     #include "util/tmpl/fd_deque.c"

   This creates the following API for use in the local compilation unit:

     ulong      my_deque_align    ( void               ); // required byte alignment of a deque
     ulong      my_deque_footprint( ulong      max     ); // required byte footprint of a deque with the given DEQUE_MAX
     void     * my_deque_new      ( void     * shmem,     // format memory region into a my_deque, my_deque will be empty
                                    ulong      max     ); // (caller not joined on return, mem has required align/footprint, etc)
     my_ele_t * my_deque_join     ( void     * shdeque ); // join a my_deque (unlimited joins, etc) (NOT A CAST OF SHDEQUE)
                                                          // join can be indexed like a normal array with DEQUE_MAX elements
     void     * my_deque_leave    ( my_ele_t * deque   ); // leave a my_deque (matched with join, etc) (NOT A CAST OF DEQUE)
     void     * my_deque_delete   ( void     * shdeque ); // unformat memory (no active joins, etc)

     // Accessors

     ulong my_deque_max( my_ele_t const * deque ); // returns the max elements that could be in the queue (==DEQUE_MAX)
     ulong my_deque_cnt( my_ele_t const * deque ); // returns the number of elements in the queue, in [0,DEQUE_MAX]

     // Simple API

     my_ele_t * my_deque_push_head( my_ele_t * deque, my_ele_t ele ); // push ele at the deque head, returns deque
     my_ele_t * my_deque_push_tail( my_ele_t * deque, my_ele_t ele ); // push ele at the deque tail, returns deque
     my_ele_t   my_deque_pop_head ( my_ele_t * deque               ); // pops ele from the head of the deque, returns ele
     my_ele_t   my_deque_pop_tail ( my_ele_t * deque               ); // pops ele from the tail of the deque, returns ele

     // Advanced API for zero-copy usage

     my_ele_t * my_deque_peek_head  ( my_ele_t * deque ); // peeks at head, returned ptr lifetime is until next op on deque
     my_ele_t * my_deque_peek_tail  ( my_ele_t * deque ); // peeks at tail, returned ptr lifetime is until next op on deque
     my_ele_t * my_deque_insert_head( my_ele_t * deque ); // inserts uninitialized element at head, returns deque
     my_ele_t * my_deque_insert_tail( my_ele_t * deque ); // inserts uninitiaiized element at tail, returns deque
     my_ele_t * my_deque_remove_head( my_ele_t * deque ); // removes head, returns deque
     my_ele_t * my_deque_remove_tail( my_ele_t * deque ); // removes tail, returns deque
     my_ele_t * my_deque_remove_all ( my_ele_t * deque ); // removes all, returns deque, fast O(1)

   By default, none of the functions do any error checking.
   Specifically, the caller promises that cnt<max for any push or insert
   operation and cnt>0 for any pop, peek or remove operation (remove_all
   is fine on an empty deque). */

#include "../bits/fd_bits.h"

#ifndef DEQUE_NAME
#error "Define DEQUE_NAME"
#endif

#ifndef DEQUE_T
#error "Define DEQUE_T"
#endif

/* Implementation *****************************************************/

#define DEQUE_(x) FD_EXPAND_THEN_CONCAT3(DEQUE_NAME,_,x)

struct DEQUE_(private) {
  ulong   max1;  /* Max elements in deque minus 1 */
  ulong   cnt;   /* Num elements in deque, in [0,max] */
  ulong   start; /* Location of current head, in [0,max) */
  ulong   end;   /* Location of current tail, in [0,max) */
  DEQUE_T deque[ 1 ]; /* Actually max in size */
};

typedef struct DEQUE_(private) DEQUE_(private_t);

FD_PROTOTYPES_BEGIN

/* private_from_deque returns a pointer to the deque_private given a
   pointer to the deque. */

FD_FN_CONST static inline DEQUE_(private_t) *
DEQUE_(private_hdr_from_deque)( DEQUE_T * deque ) {
  return (DEQUE_(private_t) *)( (ulong)deque - (ulong)&(((DEQUE_(private_t) *)NULL)->deque) );
}

/* const-correct version of above */

FD_FN_CONST static inline DEQUE_(private_t) const *
DEQUE_(private_const_hdr_from_deque)( DEQUE_T const * deque ) {
  return (DEQUE_(private_t) const *)( (ulong)deque - (ulong)&(((DEQUE_(private_t) *)NULL)->deque) );
}

/* These move i to the previous or next slot to i for given max.
   Input should be in [0,max) and output will be in [0,max). */

FD_FN_CONST static inline ulong DEQUE_(private_prev)( ulong i, ulong max1 ) { return fd_ulong_if( i==0UL,  max1, i-1UL ); }
FD_FN_CONST static inline ulong DEQUE_(private_next)( ulong i, ulong max1 ) { return fd_ulong_if( i>=max1, 0UL,  i+1UL ); }

FD_FN_CONST static inline ulong DEQUE_(align)( void ) { return alignof(DEQUE_(private_t)); }

FD_FN_CONST static inline ulong
DEQUE_(footprint)( ulong max ) {
  return fd_ulong_align_up( fd_ulong_align_up( 32UL, alignof(DEQUE_T) ) + sizeof(DEQUE_T)*max, alignof(DEQUE_(private_t)) );
}

static void *
DEQUE_(new)( void * shmem,
             ulong  max ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shmem;
  hdr->max1  = max-1UL;
  hdr->cnt   = 0UL;
  hdr->start = 0UL;
  hdr->end   = 0UL;
  return hdr;
}

static inline DEQUE_T *
DEQUE_(join)( void * shdeque ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shdeque;
  return hdr->deque;
} 

static inline void * DEQUE_(leave) ( DEQUE_T * deque   ) { return (void *)DEQUE_(private_hdr_from_deque)( deque ); }
static inline void * DEQUE_(delete)( void *    shdeque ) { return shdeque; }

static inline ulong
DEQUE_(max)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->max1 + 1UL;
}

static inline ulong
DEQUE_(cnt)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->cnt;
}

static inline DEQUE_T *
DEQUE_(push_head)( DEQUE_T * deque,
                   DEQUE_T   ele ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  start = DEQUE_(private_prev)( start, max1 );
  hdr->deque[ start ] = ele;
  hdr->cnt   = cnt+1UL;
  hdr->start = start;
  return deque;
}

static inline DEQUE_T *
DEQUE_(push_tail)( DEQUE_T * deque,
                   DEQUE_T   ele ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->deque[ end ] = ele;
  end = DEQUE_(private_next)( end, max1 );
  hdr->cnt = cnt+1UL;
  hdr->end = end;
  return deque;
}

static inline DEQUE_T
DEQUE_(pop_head)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  DEQUE_T ele = hdr->deque[ start ];
  start = DEQUE_(private_next)( start, max1 );
  hdr->cnt   = cnt-1UL;
  hdr->start = start;
  return ele;
}

static inline DEQUE_T
DEQUE_(pop_tail)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  end = DEQUE_(private_prev)( end, max1 );
  DEQUE_T ele = hdr->deque[ end ];
  hdr->cnt = cnt-1UL;
  hdr->end = end;
  return ele;
}

/* FIXME: CONST VERSION OF PEEKS? */

static inline DEQUE_T *
DEQUE_(peek_head)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->deque + hdr->start;
}

static inline DEQUE_T *
DEQUE_(peek_tail)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->deque + DEQUE_(private_prev)( hdr->end, hdr->max1 );
}

static inline DEQUE_T *
DEQUE_(insert_head)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  hdr->cnt    = cnt + 1UL;
  hdr->start  = DEQUE_(private_prev)( start, max1 );
  return deque;
}

static inline DEQUE_T *
DEQUE_(insert_tail)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->cnt   = cnt + 1UL;
  hdr->end   = DEQUE_(private_next)( end, max1 );
  return deque;
}

static inline DEQUE_T *
DEQUE_(remove_head)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  hdr->cnt    = cnt - 1UL;
  hdr->start  = DEQUE_(private_next)( start, max1 );
  return deque;
}

static inline DEQUE_T *
DEQUE_(remove_tail)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->cnt   = cnt - 1UL;
  hdr->end   = DEQUE_(private_prev)( end, max1 );
  return deque;
}

static inline DEQUE_T *
DEQUE_(remove_all)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->cnt   = 0UL;
  hdr->start = 0UL;
  hdr->end   = 0UL;
  return deque;
}

FD_PROTOTYPES_END

#undef DEQUE_MAX
#undef DEQUE_T
#undef DEQUE_NAME

