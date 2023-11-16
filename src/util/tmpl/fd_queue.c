/* Declares a family of functions implementing a single-threaded
   compile-time fixed-capacity queue designed for high performance
   contexts.  Example usage:

     #define QUEUE_NAME my_queue
     #define QUEUE_T    my_ele_t
     #define QUEUE_MAX  64UL
     #include "util/tmpl/fd_queue.c"

   This creates the following API for use in the local compilation unit:

     ulong      my_queue_align    ( void               ); // required byte alignment of a queue
     ulong      my_queue_footprint( void               ); // required byte footprint of a queue with the given QUEUE_MAX
     void     * my_queue_new      ( void     * shmem   ); // format memory region into a my_queue, my_queue will be empty
                                                          // (caller not joined on return, mem has required align/footprint, etc)
     my_ele_t * my_queue_join     ( void     * shqueue ); // join a my_queue (unlimited joins, etc) (NOT A CAST OF SHQUEUE)
                                                          // join can be indexed like a normal array with QUEUE_MAX elements
     void     * my_queue_leave    ( my_ele_t * queue   ); // leave a my_queue (matched with join, etc) (NOT A CAST OF QUEUE)
     void     * my_queue_delete   ( void     * shqueue ); // unformat memory (no active joins, etc)

     // Accessors

     ulong my_queue_max  ( my_ele_t const * queue ); // returns the max elements that could be in the queue (==QUEUE_MAX)
     ulong my_queue_cnt  ( my_ele_t const * queue ); // returns the number of elements in the queue, in [0,QUEUE_MAX]
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
   Specifically, the caller promises that MAX is such that footprint
   will not overflow 2^64 (e.g. MAX << (2^64)/sizeof(my_ele_t)), cnt<max
   for any push or insert operation and cnt>0 for any pop, peek or
   remove operation (remove_all is fine on an empty queue). */

#include "../bits/fd_bits.h"

#ifndef QUEUE_NAME
#error "Define QUEUE_NAME"
#endif

#ifndef QUEUE_T
#error "Define QUEUE_T"
#endif

#ifndef QUEUE_MAX
#error "Define QUEUE_MAX or use fd_queue_dynamic"
#endif

#if (QUEUE_MAX)<1UL
#error "QUEUE_MAX must be positive"
#endif

/* Implementation *****************************************************/

#define QUEUE_(x) FD_EXPAND_THEN_CONCAT3(QUEUE_NAME,_,x)

struct QUEUE_(private) {

  /* The number of elements in the queue is cnt=end-start and cnt will be
     in [0,max].  If cnt==0, the queue is empty.  If cnt==MAX, the queue
     if full.

     For a non-empty queue, the next to pop  is at element queue[ start     % MAX ],
     and                    the next to push is at element queue[ (end-1UL) % MAX ]

     start and end overflow/underflow are fine if max is a power of two
     and start and end are initialized such that overflow / underflow
     will not happen for millennia practically anyway.  More precisely,
     this implementation is guaranteed when max is a power of two and/or
     when fewer than 2^63 operations have been done on the queue (which,
     practically speaking, would take millennia).  If, in some distant
     age, a user does want to support doing more than 2^63 operations
     when max is not a power of two, this can be done by moving start
     and end as close as possible toward 2^63 by the same integer
     multiple of max toward 2^63 sporadically (every couple of hundred
     years or so). */

  ulong   start;
  ulong   end;
  QUEUE_T queue[ (ulong)(QUEUE_MAX) ];
};

typedef struct QUEUE_(private) QUEUE_(private_t);

FD_PROTOTYPES_BEGIN

/* private_from_queue return a pointer to the queue_private given a
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

/* private_slot maps an index to a slot cnt.  The compiler should
   optimize this to a bit-and when MAX is a power of 2 and, hopefully,
   to optimize this to a magic multiply otherwise. */

FD_FN_CONST static inline ulong QUEUE_(private_slot)( ulong i ) { return i % (ulong)(QUEUE_MAX); }

FD_FN_CONST static inline ulong QUEUE_(align)    ( void ) { return alignof(QUEUE_(private_t)); }
FD_FN_CONST static inline ulong QUEUE_(footprint)( void ) { return sizeof (QUEUE_(private_t)); }

static inline void *
QUEUE_(new)( void * shmem ) {
  QUEUE_(private_t) * hdr = (QUEUE_(private_t) *)shmem;
  /* These values are large enough that underflow/overflow will never
     happen in practical usage.  For example, it would take hundreds of
     years if all a core did was a worst case continuous push/pop pairs
     at 1 Gpair/sec.  So we don't need to do any special handling
     overflow handling in practice that might otherwise be required if
     max is not a power-of-two MAX).  Note also that overflow/underflow
     doesn't matter if max is a power of two as per the note above. */
  hdr->start = 1UL << 63;
  hdr->end   = 1UL << 63;
  return hdr;
}

static inline QUEUE_T *
QUEUE_(join)( void * shqueue ) {
  QUEUE_(private_t) * hdr = (QUEUE_(private_t) *)shqueue;
  return hdr->queue;
} 

static inline void * QUEUE_(leave) ( QUEUE_T * queue   ) { return (void *)QUEUE_(private_hdr_from_queue)( queue ); }
static inline void * QUEUE_(delete)( void *    shqueue ) { return shqueue; }

FD_FN_CONST static inline ulong QUEUE_(max)( QUEUE_T const * queue ) { (void)queue; return (ulong)(QUEUE_MAX); }

FD_FN_PURE static inline ulong
QUEUE_(cnt)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->end - hdr->start;
}

FD_FN_PURE static inline ulong
QUEUE_(avail)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return ((ulong)(QUEUE_MAX)) - (hdr->end - hdr->start);
}

FD_FN_PURE static inline int
QUEUE_(empty)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return !(hdr->end - hdr->start);
}

FD_FN_PURE static inline int
QUEUE_(full)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return (hdr->end - hdr->start)==((ulong)QUEUE_MAX);
}

static inline QUEUE_T *
QUEUE_(push)( QUEUE_T * queue,
              QUEUE_T   ele ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  hdr->queue[ QUEUE_(private_slot)( hdr->end ) ] = ele;
  hdr->end++;
  return queue;
}

static inline QUEUE_T
QUEUE_(pop)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  QUEUE_T ele = hdr->queue[ QUEUE_(private_slot)( hdr->start ) ];
  hdr->start++;
  return ele;
}

FD_FN_PURE static inline QUEUE_T *
QUEUE_(peek_remove)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  return hdr->queue + QUEUE_(private_slot)( hdr->start );
}

FD_FN_PURE static inline QUEUE_T *
QUEUE_(peek_insert)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  return hdr->queue + QUEUE_(private_slot)( hdr->end-1UL );
}

FD_FN_PURE static inline QUEUE_T const *
QUEUE_(peek_insert_const)( QUEUE_T * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->queue + QUEUE_(private_slot)( hdr->end-1UL );
}

FD_FN_PURE static inline QUEUE_T const *
QUEUE_(peek_remove_const)( QUEUE_T const * queue ) {
  QUEUE_(private_t) const * hdr = QUEUE_(private_const_hdr_from_queue)( queue );
  return hdr->queue + QUEUE_(private_slot)( hdr->start );
}

static inline QUEUE_T * QUEUE_(insert)( QUEUE_T * queue ) { QUEUE_(private_hdr_from_queue)( queue )->end++;   return queue; }
static inline QUEUE_T * QUEUE_(remove)( QUEUE_T * queue ) { QUEUE_(private_hdr_from_queue)( queue )->start++; return queue; }

static inline QUEUE_T *
QUEUE_(remove_all)( QUEUE_T * queue ) {
  QUEUE_(private_t) * hdr = QUEUE_(private_hdr_from_queue)( queue );
  /* See note in new */
  hdr->start = 1UL << 63;
  hdr->end   = 1UL << 63;
  return queue;
}

FD_PROTOTYPES_END

#undef QUEUE_

#undef QUEUE_MAX
#undef QUEUE_T
#undef QUEUE_NAME

