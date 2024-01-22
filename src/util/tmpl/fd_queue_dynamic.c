/* Declares a family of functions implementing a single-threaded
   run-time fixed-capacity queue designed for high performance contexts.
   Example usage:

     #define QUEUE_NAME my_queue
     #define QUEUE_T    my_ele_t
     #include "util/tmpl/fd_queue.c"

   This creates the following API for use in the local compilation unit:

     ulong      my_queue_align    ( void               ); // required byte alignment of a queue
     ulong      my_queue_footprint( ulong      max     ); // required byte footprint of a queue with max capacity
     void     * my_queue_new      ( void     * shmem,     // format memory region into a my_queue, my_queue will be empty
                                    ulong      max     ); // (caller not joined on return, mem has required align/footprint, etc)
     my_ele_t * my_queue_join     ( void     * shqueue ); // join a my_queue (unlimited joins, etc) (NOT A CAST OF SHQUEUE)
                                                          // join can be indexed like a normal array with max elements
     void     * my_queue_leave    ( my_ele_t * queue   ); // leave a my_queue (matched with join, etc) (NOT A CAST OF QUEUE)
     void     * my_queue_delete   ( void     * shqueue ); // unformat memory (no active joins, etc)

     // Accessors

     ulong my_queue_max  ( my_ele_t const * queue ); // returns the max elements that could be in the queue
     ulong my_queue_cnt  ( my_ele_t const * queue ); // returns the number of elements in the queue, in [0,max]
     ulong my_queue_avail( my_ele_t const * queue ); // returns max-cnt
     int   my_queue_empty( my_ele_t const * queue ); // returns 1 if queue is empty and 0 otherwise
     int   my_queue_full ( my_ele_t const * queue ); // returns 1 if queue is full and 0 otherwise

     // Simple API

     my_ele_t * my_queue_push( my_ele_t * queue, my_ele_t ele ); // push ele to queue, returns queue
     my_ele_t   my_queue_pop ( my_ele_t * queue               ); // pop ele from queue, returns ele

     // Advanced API for zero-copy usage

     my_ele_t * my_queue_peek_insert( my_ele_t * queue ); // peeks at most recent insert/push,
                                                          // returned ptr lifetime is until next op on queue
     my_ele_t * my_queue_peek_remove( my_ele_t * queue ); // peeks at least recent insert/push,
                                                          // returned ptr lifetime is until next op on queue
     my_ele_t * my_queue_insert     ( my_ele_t * queue ); // push uninitialized element, returns queue
     my_ele_t * my_queue_remove     ( my_ele_t * queue ); // pops queue, returns queue
     my_ele_t * my_queue_remove_all ( my_ele_t * queue ); // removes all, returns queue, fast O(1)

     my_ele_t const * my_queue_peek_insert_const( my_ele_t const * queue ); // const version of peek_insert
     my_ele_t const * my_queue_peek_remove_const( my_ele_t const * queue ); // const version of peek_remove

   For performance, none of the functions do any error checking.
   Specifically, the caller promises that max is such that footprint
   will not overflow 2^64 (e.g. max << (2^64)/sizeof(my_ele_t)), cnt<max
   for any push or insert operation and cnt>0 for any pop, peek or
   remove operation (remove_all is fine on an empty queue). */

#include "../bits/fd_bits.h"

#ifndef QUEUE_NAME
#error "Define QUEUE_NAME"
#endif

#ifndef QUEUE_T
#error "Define QUEUE_T"
#endif

/* Implementation *****************************************************/

#define QUEUE_(x) FD_EXPAND_THEN_CONCAT3(QUEUE_NAME,_,x)

struct QUEUE_(private) {
  ulong   max1;  /* Max elements in queue minus 1 */
  ulong   cnt;   /* Num elements in queue, in [0,max] */
  ulong   start; /* Index of next to pop,  in [0,max) */
  ulong   end;   /* Index of next to push, in [0,max) */
  QUEUE_T queue[ 1 ]; /* Actually max in size */
};

typedef struct QUEUE_(private) QUEUE_(private_t);

FD_PROTOTYPES_BEGIN

/* private_from_queue returns a pointer to the queue_private given a
   pointer to the queue. */

FD_FN_CONST static inline QUEUE_(private_t) *
QUEUE_(private_hdr_from_queue)( QUEUE_T * queue ) {
  return (QUEUE_(private_t) *)( (ulong)queue - (ulong)&(((QUEUE_(private_t) *)NULL)->queue) );
}

/* const-correct version of above */

FD_FN_CONST static inline QUEUE_(private_t) const *
QUEUE_(private_const_hdr_from_queue)( QUEUE_T const * queue ) {
  return (QUEUE_(private_t) const *)( (ulong)queue - (ulong)&(((QUEUE_(private_t) *)NULL)->queue) );
}

/* These move i to the previous or next slot to i for given max.
   Input should be in [0,max) and output will be in [0,max). */

FD_FN_CONST static inline ulong QUEUE_(private_prev)( ulong i, ulong max1 ) { return fd_ulong_if( i==0UL,  max1, i-1UL ); }
FD_FN_CONST static inline ulong QUEUE_(private_next)( ulong i, ulong max1 ) { return fd_ulong_if( i>=max1, 0UL,  i+1UL ); }

FD_FN_CONST static inline ulong QUEUE_(align)( void ) { return alignof(QUEUE_(private_t)); }

FD_FN_CONST static inline ulong
QUEUE_(footprint)( ulong max ) {
  return fd_ulong_align_up( fd_ulong_align_up( 32UL, alignof(QUEUE_T) ) + sizeof(QUEUE_T)*max, alignof(QUEUE_(private_t)) );
}

static inline void *
QUEUE_(new)( void * shmem,
             ulong  max ) {
  QUEUE_(private_t) * hdr = (QUEUE_(private_t) *)shmem;
  hdr->max1  = max-1UL;
  hdr->cnt   = 0UL;
  hdr->start = 0UL;
  hdr->end   = 0UL;
  return hdr;
}

static inline QUEUE_T *
QUEUE_(join)( void * shqueue ) {
  QUEUE_(private_t) * hdr = (QUEUE_(private_t) *)shqueue;
  return hdr->queue;
} 

static inline void * QUEUE_(leave) ( QUEUE_T * queue   ) { return (void *)QUEUE_(private_hdr_from_queue)( queue ); }
static inline void * QUEUE_(delete)( void *    shqueue ) { return shqueue; }

FD_FN_PURE static inline ulong
QUEUE_(max)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->max1 + 1UL;
}

FD_FN_PURE static inline ulong
QUEUE_(cnt)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->cnt;
}

FD_FN_PURE static inline ulong
QUEUE_(avail)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->max1 + 1UL - hdr->cnt;
}

FD_FN_PURE static inline int
QUEUE_(empty)( QUEUE_T const * queue ) {
  return !QUEUE_(private_const_hdr_from_queue)( queue )->cnt;
}

FD_FN_PURE static inline int
QUEUE_(full)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return (hdr->max1 + 1UL)==hdr->cnt;
}

static inline QUEUE_T *
QUEUE_(push)( QUEUE_T * queue,
              QUEUE_T   ele ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->queue[ end ] = ele;
  end = QUEUE_(private_next)( end, max1 );
  hdr->cnt = cnt+1UL;
  hdr->end = end;
  return queue;
}

static inline QUEUE_T
QUEUE_(pop)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  QUEUE_T ele = hdr->queue[ start ];
  start = QUEUE_(private_next)( start, max1 );
  hdr->cnt   = cnt-1UL;
  hdr->start = start;
  return ele;
}

FD_FN_PURE static inline QUEUE_T *
QUEUE_(peek_insert)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  return hdr->queue + QUEUE_(private_prev)( hdr->end, hdr->max1 );
}

FD_FN_PURE static inline QUEUE_T *
QUEUE_(peek_remove)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  return hdr->queue + hdr->start;
}

FD_FN_PURE static inline QUEUE_T const *
QUEUE_(peek_insert_const)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->queue + QUEUE_(private_prev)( hdr->end, hdr->max1 );
}

FD_FN_PURE static inline QUEUE_T const *
QUEUE_(peek_remove_const)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->queue + hdr->start;
}

static inline QUEUE_T *
QUEUE_(insert)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->cnt   = cnt + 1UL;
  hdr->end   = QUEUE_(private_next)( end, max1 );
  return queue;
}

static inline QUEUE_T *
QUEUE_(remove)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  hdr->cnt    = cnt - 1UL;
  hdr->start  = QUEUE_(private_next)( start, max1 );
  return queue;
}

static inline QUEUE_T *
QUEUE_(remove_all)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  hdr->cnt   = 0UL;
  hdr->start = 0UL;
  hdr->end   = 0UL;
  return queue;
}

FD_PROTOTYPES_END

#undef QUEUE_

#undef QUEUE_T
#undef QUEUE_NAME

