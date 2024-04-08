/* Declares a family of functions implementing a single-threaded
   compile-time fixed-capacity double-ended queue (deque) designed for
   high performance contexts.  The deque is implemented with a circular
   buffer and can push and pop from both ends.  Setting DEQUE_MAX to a
   power of two is strongly recommended but not required.  Example
   usage:

     #define DEQUE_NAME my_deque
     #define DEQUE_T    my_ele_t
     #define DEQUE_MAX  64UL
     #include "util/tmpl/fd_deque.c"

   This creates the following API for use in the local compilation unit:

     ulong      my_deque_align    ( void               ); // required byte alignment of a deque
     ulong      my_deque_footprint( void               ); // required byte footprint of a deque with the given DEQUE_MAX
     void     * my_deque_new      ( void     * shmem   ); // format memory region into a my_deque, my_deque will be empty
                                                          // (caller not joined on return, mem has required align/footprint, etc)
     my_ele_t * my_deque_join     ( void     * shdeque ); // join a my_deque (unlimited joins, etc) (NOT A CAST OF SHDEQUE)
                                                          // join can be indexed like a normal array with DEQUE_MAX elements
     void     * my_deque_leave    ( my_ele_t * deque   ); // leave a my_deque (matched with join, etc) (NOT A CAST OF DEQUE)
     void     * my_deque_delete   ( void     * shdeque ); // unformat memory (no active joins, etc)

     // Accessors

     ulong my_deque_max  ( my_ele_t const * deque ); // returns the max elements that could be in the deque (==DEQUE_MAX)
     ulong my_deque_cnt  ( my_ele_t const * deque ); // returns the number of elements in the deque, in [0,DEQUE_MAX]
     ulong my_deque_avail( my_ele_t const * deque ); // returns max-cnt
     int   my_deque_empty( my_ele_t const * deque ); // returns 1 if deque is empty and 0 otherwise
     int   my_deque_full ( my_ele_t const * deque ); // returns 1 if deque is full and 0 otherwise

     // Simple API

     my_ele_t * my_deque_push_head( my_ele_t * deque, my_ele_t ele ); // push ele at the deque head, returns deque
     my_ele_t * my_deque_push_tail( my_ele_t * deque, my_ele_t ele ); // push ele at the deque tail, returns deque
     my_ele_t   my_deque_pop_head ( my_ele_t * deque               ); // pops ele from the head of the deque, returns ele
     my_ele_t   my_deque_pop_tail ( my_ele_t * deque               ); // pops ele from the tail of the deque, returns ele

     // Advanced API for zero-copy usage

     my_ele_t * my_deque_peek_head  ( my_ele_t * deque ); // peeks at head, returned ptr lifetime is until next op on deque
     my_ele_t * my_deque_peek_tail  ( my_ele_t * deque ); // peeks at tail, returned ptr lifetime is until next op on deque
     my_ele_t * my_deque_peek_index ( my_ele_t * deque, ulong idx ); // peeks at index, returned ptr lifetime is until next op on deque
     my_ele_t * my_deque_insert_head( my_ele_t * deque ); // inserts uninitialized element at head, returns deque
     my_ele_t * my_deque_insert_tail( my_ele_t * deque ); // inserts uninitialized element at tail, returns deque
     my_ele_t * my_deque_remove_head( my_ele_t * deque ); // removes head, returns deque
     my_ele_t * my_deque_remove_tail( my_ele_t * deque ); // removes tail, returns deque
     my_ele_t * my_deque_remove_all ( my_ele_t * deque ); // removes all, returns deque, fast O(1)

     my_ele_t * my_deque_push_head_nocopy( my_ele_t * deque ); // push the head, returns the new uninitialized element
     my_ele_t * my_deque_push_tail_nocopy( my_ele_t * deque ); // push the tail, returns the new uninitialized element
     my_ele_t * my_deque_pop_head_nocopy ( my_ele_t * deque ); // pops the head, returns the deleted element
     my_ele_t * my_deque_pop_tail_nocopy ( my_ele_t * deque ); // pops the tail, returns the deleted element

     my_ele_t const * my_deque_peek_head_const ( my_ele_t const * deque ); // const version of peek_head
     my_ele_t const * my_deque_peek_tail_const ( my_ele_t const * deque ); // const version of peek_tail
     my_ele_t const * my_deque_peek_index_const( my_ele_t const * deque, ulong idx ); // const version of peek_index

     // my_deque_iter_* allow for iteration over all the elements in
     // a my_deque.  The iteration will be in order from head to tail.
     // Example usage:
     //
     //   for( my_deque_iter_t iter = my_deque_iter_init( deque ); !my_deque_iter_done( deque, iter ); iter = my_deque_iter_next( deque, iter ) ) {
     //     my_deque_t * ele = my_deque_iter_ele( deque, iter );
     //
     //     ... process ele here
     //   }

     my_deque_iter_t  my_deque_iter_init     ( my_deque_t const * deque );
     int              my_deque_iter_done     ( my_deque_t const * deque, my_deque_iter_t iter ); // returns 1 if no more iterations, 0 o.w.
     my_deque_iter_t  my_deque_iter_next     ( my_deque_t const * deque, my_deque_iter_t iter ); // returns next iter value iter
     my_ele_t *       my_deque_iter_ele      ( my_deque_t *       deque, my_deque_iter_t iter ); // assumes not done, return non-NULL ele
     my_ele_t const * my_deque_iter_ele_const( my_deque_t const * deque, my_deque_iter_t iter ); // assumes not done, return non-NULL ele

   For performance, none of the functions do any error checking.
   Specifically, the caller promises that MAX is such that footprint
   will not overflow 2^64 (e.g. MAX << (2^64)/sizeof(my_ele_t)), cnt<max
   for any push or insert operation and cnt>0 for any pop, peek or
   remove operation (remove_all is fine on an empty deque). */

#include "../bits/fd_bits.h"

#include <stddef.h>

#ifndef DEQUE_NAME
#error "Define DEQUE_NAME"
#endif

#ifndef DEQUE_T
#error "Define DEQUE_T"
#endif

#ifndef DEQUE_MAX
#error "Define DEQUE_MAX or use fd_deque_dynamic"
#endif

#if (DEQUE_MAX)<1UL
#error "DEQUE_MAX must be positive"
#endif

/* Implementation *****************************************************/

#define DEQUE_(x) FD_EXPAND_THEN_CONCAT3(DEQUE_NAME,_,x)

struct DEQUE_(private) {

  /* The number of elements in the deque is cnt=end-start and cnt will be
     in [0,max].  If cnt==0, the deque is empty.  If cnt==MAX, the deque
     if full.

     For a non-empty deque, the deque head is at element deque[ start     % MAX ],
     and                    the deque tail is at element deque[ (end-1UL) % MAX ]

     start and end overflow/underflow are fine if max is a power of two
     and start and end are initialized such that overflow / underflow
     will not happen for millennia practically anyway.  More precisely,
     this implementation is guaranteed when max is a power of two and/or
     when fewer than 2^63 operations have been done on the deque (which,
     practically speaking, would take millennia).  If, in some distant
     age, a user does want to support doing more than 2^63 operations
     when max is not a power of two, this can be done by moving start
     and end as close as possible toward 2^63 by the same integer
     multiple of max toward 2^63 sporadically (every couple of hundred
     years or so). */

  ulong   start;
  ulong   end;
  DEQUE_T deque[ (ulong)(DEQUE_MAX) ];
};

typedef struct DEQUE_(private) DEQUE_(private_t);

FD_PROTOTYPES_BEGIN

/* private_from_deque return a pointer to the deque_private given a
   pointer to the deque. */

FD_FN_CONST static inline DEQUE_(private_t) *
DEQUE_(private_hdr_from_deque)( DEQUE_T * deque ) {
  return (DEQUE_(private_t) *)( (ulong)deque - offsetof(DEQUE_(private_t), deque) );
}

/* const-correct version of above */

FD_FN_CONST static inline DEQUE_(private_t) const *
DEQUE_(private_const_hdr_from_deque)( DEQUE_T const * deque ) {
  return (DEQUE_(private_t) const *)( (ulong)deque - offsetof(DEQUE_(private_t), deque) );
}

/* private_slot maps an index to a slot cnt.  The compiler should
   optimize this to a bit-and when MAX is a power of 2 and, hopefully,
   to optimize this to a magic multiply otherwise. */

FD_FN_CONST static inline ulong DEQUE_(private_slot)( ulong i ) { return i % (ulong)(DEQUE_MAX); }

FD_FN_CONST static inline ulong DEQUE_(align)    ( void ) { return alignof(DEQUE_(private_t)); }
FD_FN_CONST static inline ulong DEQUE_(footprint)( void ) { return sizeof (DEQUE_(private_t)); }

static inline void *
DEQUE_(new)( void * shmem ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shmem;
  /* These values are large enough that underflow/overflow will never
     happen in practical usage.  For example, it would take hundreds of
     years if all a core did was a worst case continuous
     push_tail/pop_head pairs (or push_head/pop_tail) at 1 Gpair/sec.
     So we don't need to do any special handling overflow handling in
     practice that might otherwise be required if max is not a
     power-of-two MAX).  Note also that overflow/underflow doesn't
     matter if max is a power of two as per the note above. */
  hdr->start = 1UL << 63;
  hdr->end   = 1UL << 63;
  return hdr;
}

static inline DEQUE_T *
DEQUE_(join)( void * shdeque ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shdeque;
  return hdr->deque;
}

static inline void * DEQUE_(leave) ( DEQUE_T * deque   ) { return (void *)DEQUE_(private_hdr_from_deque)( deque ); }
static inline void * DEQUE_(delete)( void *    shdeque ) { return shdeque; }

FD_FN_CONST static inline ulong DEQUE_(max)( DEQUE_T const * deque ) { (void)deque; return (ulong)(DEQUE_MAX); }

FD_FN_PURE static inline ulong
DEQUE_(cnt)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->end - hdr->start;
}

FD_FN_PURE static inline ulong
DEQUE_(avail)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return ((ulong)(DEQUE_MAX)) - (hdr->end - hdr->start);
}

FD_FN_PURE static inline int
DEQUE_(empty)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return !(hdr->end - hdr->start);
}

FD_FN_PURE static inline int
DEQUE_(full)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return (hdr->end - hdr->start)==((ulong)DEQUE_MAX);
}

static inline DEQUE_T *
DEQUE_(push_head)( DEQUE_T * deque,
                   DEQUE_T   ele ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->start--;
  hdr->deque[ DEQUE_(private_slot)( hdr->start ) ] = ele;
  return deque;
}

static inline DEQUE_T *
DEQUE_(push_tail)( DEQUE_T * deque,
                   DEQUE_T   ele ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->deque[ DEQUE_(private_slot)( hdr->end ) ] = ele;
  hdr->end++;
  return deque;
}

static inline DEQUE_T
DEQUE_(pop_head)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  DEQUE_T ele = hdr->deque[ DEQUE_(private_slot)( hdr->start ) ];
  hdr->start++;
  return ele;
}

static inline DEQUE_T
DEQUE_(pop_tail)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->end--;
  return hdr->deque[ DEQUE_(private_slot)( hdr->end ) ];
}

FD_FN_PURE static inline DEQUE_T *
DEQUE_(peek_head)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  if (hdr->end == hdr->start)
    return NULL;
  return hdr->deque + DEQUE_(private_slot)( hdr->start );
}

FD_FN_PURE static inline DEQUE_T *
DEQUE_(peek_tail)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  if (hdr->end == hdr->start)
    return NULL;
  return hdr->deque + DEQUE_(private_slot)( hdr->end-1UL );
}

FD_FN_PURE static inline DEQUE_T *
DEQUE_(peek_index)( DEQUE_T * deque, ulong idx ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  if (hdr->end == hdr->start)
    return NULL;
  return hdr->deque + DEQUE_(private_slot)( hdr->start + idx );
}

FD_FN_PURE static inline DEQUE_T const *
DEQUE_(peek_head_const)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  if (hdr->end == hdr->start)
    return NULL;
  return hdr->deque + DEQUE_(private_slot)( hdr->start );
}

FD_FN_PURE static inline DEQUE_T const *
DEQUE_(peek_tail_const)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  if (hdr->end == hdr->start)
    return NULL;
  return hdr->deque + DEQUE_(private_slot)( hdr->end-1UL );
}

FD_FN_PURE static inline DEQUE_T const *
DEQUE_(peek_index_const)( DEQUE_T const * deque, ulong idx ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  if (hdr->end <= hdr->start + idx)
    return NULL;
  return hdr->deque + DEQUE_(private_slot)( hdr->start + idx );
}

static inline DEQUE_T * DEQUE_(insert_head)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->start--; return deque; }
static inline DEQUE_T * DEQUE_(insert_tail)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->end++;   return deque; }
static inline DEQUE_T * DEQUE_(remove_head)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->start++; return deque; }
static inline DEQUE_T * DEQUE_(remove_tail)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->end--;   return deque; }

static inline DEQUE_T *
DEQUE_(pop_index)( DEQUE_T * deque, ulong idx ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  if (hdr->end <= hdr->start + idx)
    return NULL;
  ulong original = idx;
  DEQUE_T * iter = hdr->deque + DEQUE_(private_slot)( hdr->start + idx );
  while (hdr->start + idx < hdr->end) {
    *iter = *(iter + 1);
    idx++;
  }
  hdr->end--;
  return &hdr->deque[ DEQUE_(private_slot)( hdr->start + original ) ];
}

static inline DEQUE_T *
DEQUE_(push_head_nocopy)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->start--;
  return &hdr->deque[ DEQUE_(private_slot)( hdr->start ) ];
}

static inline DEQUE_T *
DEQUE_(push_tail_nocopy)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  DEQUE_T * ele = &hdr->deque[ DEQUE_(private_slot)( hdr->end ) ];
  hdr->end++;
  return ele;
}

static inline DEQUE_T *
DEQUE_(pop_head_nocopy)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  DEQUE_T * ele = &hdr->deque[ DEQUE_(private_slot)( hdr->start ) ];
  hdr->start++;
  return ele;
}

static inline DEQUE_T *
DEQUE_(pop_tail_nocopy)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->end--;
  return &hdr->deque[ DEQUE_(private_slot)( hdr->end ) ];
}

static inline DEQUE_T *
DEQUE_(remove_all)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  /* See note in new */
  hdr->start = 1UL << 63;
  hdr->end   = 1UL << 63;
  return deque;
}

typedef ulong DEQUE_(iter_t);

static inline DEQUE_(iter_t)
DEQUE_(iter_init)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->start;
}

static inline DEQUE_(iter_t)
DEQUE_(iter_init_reverse)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->end - 1;
}

static inline int
DEQUE_(iter_done)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return iter == hdr->end;
}

static inline int
DEQUE_(iter_done_reverse)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return iter == hdr->start - 1;
}

static inline DEQUE_(iter_t)
DEQUE_(iter_next)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  (void)deque;
  return iter+1;
}

static inline DEQUE_(iter_t)
DEQUE_(iter_next_reverse)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  (void)deque;
  return iter-1;
}

static inline DEQUE_T *
DEQUE_(iter_ele)( DEQUE_T * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return &hdr->deque[ DEQUE_(private_slot)( iter ) ];
}

static inline DEQUE_T const *
DEQUE_(iter_ele_const)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return &hdr->deque[ DEQUE_(private_slot)( iter ) ];
}

FD_PROTOTYPES_END

#undef DEQUE_

#undef DEQUE_MAX
#undef DEQUE_T
#undef DEQUE_NAME

