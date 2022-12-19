/* Declares a family of functions implementing a single threaded fixed-capacity
   queue designed for high performance contexts.  The queue is implemented with
   a circular buffer and can push and pop from both ends.  Both pushing an
   popping are always O(1), but copy an element.

   Example usage:

#define DEQUE_NAME  my_deque
#define DEQUE_T     long
#include "util/tmpl/fd_deque.c"

This creates the following API for use in the local compilation unit:

     ulong my_deque_align    ( void      ); // required byte alignment of a my_deque_t
     ulong my_deque_footprint( ulong max ); // required byte footprint of a my_deque_t that can hold max elements

     void *       my_deque_new   ( void * shmem, ulong max ); // format memory region into a my_deque, my_deque will be empty
                                                              // (caller not joined on return, mem has required align/footprint, etc)
     long *       my_deque_join  ( void  * shdeque );    // join a my_deque_t (unlimited joins, etc) (NOT A CAST OF SHDEQUE)
     void *       my_deque_leave ( long  *   deque );    // leave a my_deque_t (matched with join, etc) (NOT A CAST OF DEQUE)
     void *       my_deque_delete( void  * shdeque );    // unformat memory (no active joins, etc)


     long *  my_deque_push      ( long * deque, long new_elt ); // pushes new_elt onto the end of the queue
     long *  my_deque_push_front( long * deque, long new_elt ); // pushes new_elt onto the front of the queue
     long    my_deque_pop       ( long * deque ); // returns and pops element from the front of the queue
     long    my_deque_pop_back  ( long * deque ); // returns and pops element from the back of the queue
     ulong   my_deque_cnt       ( long * deque ); // returns the number of elements in the queue
     ulong   my_deque_max       ( long * deque ); // returns the max capacity of the queue

 By default, none of the functions do any error checking.  It's the caller's
 responsibility to prevent underrun and overrun.  Specifically, any call to pop
 has the implicit precondition that cnt > 0, and any call to push has the
 implicit precondition that cnt < max.
   */

#include "../bits/fd_bits.h"

#ifndef DEQUE_NAME
#error "Define DEQUE_NAME"
#endif


#ifndef DEQUE_T
#error "Define DEQUE_T"
#endif

/* #define DEQUE_MAX_POW2 1 to promise that the max will always be a power of
   two.  If so, it uses a branchless higher performing implementation. */
#ifndef DEQUE_MAX_POW2
#define DEQUE_MAX_POW2 0
#endif


/* Implementation *****************************************************/

#define DEQUE_(x) FD_EXPAND_THEN_CONCAT3(DEQUE_NAME,_,x)

#if DEQUE_MAX_POW2
#define _MOD(x) ((x)&(hdr->max-1UL)) /* If y is a power of 2, x%y==x&(y-1) */
#else
#define _MOD(x) (x)
#endif

typedef DEQUE_T DEQUE_(t);

struct DEQUE_(private) {
  /* The exact semantics of start and end depend on if DEQUE_MAX_POW2 is set to 0 or 1.
     In the general case: 
        If start <= end, then the queue constists of elements [start, end).
        Otherwise, it consists of [start, max] followed by [0, end). 
        This means 0 <= start <= max, and 0 <= end <= max.
     In the power of 2 case (in which case mod is cheap):
        start <= end normally (except in the underflow case), but start and end
        may be larger than max.  The queue consists of elements i%max, where i
        is in [start, end).
     Notice (in particular) that deque[max] is potentially an element of the
     queue only in the general case.
     Why this strangeness?  Consider the general case, and start<=end.  Then
     the cnt is (end-start).  If the queue is full, then end-start==max, which
     implies end === start (mod max).  If we're representing start and end in
     the (mod max) domain, then this case is indistinguishable from the queue
     being empty.  To solve this, we just make the queue one element larger,
     represent start and end in the (mod (max+1)) domain.  Since the user
     promises never to insert more than max elements, the queue will never be
     full, and we don't encounter the "alias" case.
     In the power-of-two case, we don't store start and end in the (mod max)
     domain, so we don't encounter this problem.
   */
  ulong    start;
  ulong    end;
  ulong    max;
  DEQUE_(t) deque[ 1 ]; /* Actually max+1 in size in the general case and max
                           in size in the power-of-2 case (see above) */
};

typedef struct DEQUE_(private) DEQUE_(private_t);

FD_PROTOTYPES_BEGIN

/* private_from_deque return a pointer to the deque_private given a pointer
   to the deque. */

FD_FN_CONST static inline DEQUE_(private_t) *
DEQUE_(private_hdr_from_deque)( DEQUE_(t) * deque ) {
  return (DEQUE_(private_t) *)( (ulong)deque - (ulong)&(((DEQUE_(private_t) *)NULL)->deque) );
}

FD_FN_CONST static inline ulong DEQUE_(align)( void ) { return alignof(DEQUE_(private_t)); }

FD_FN_CONST static inline ulong
DEQUE_(footprint)( ulong max ) {
#if DEQUE_MAX_POW2
  return sizeof(DEQUE_(private_t)) + sizeof(DEQUE_(t))*(max-1UL);
#else
  return sizeof(DEQUE_(private_t)) + sizeof(DEQUE_(t))*max;
#endif
}

FD_FN_UNUSED static void * /* Work around -Winline */
DEQUE_(new)( void * shmem,
            ulong  max ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shmem;
  if( FD_UNLIKELY( max==0UL ) ) return NULL;
#if DEQUE_MAX_POW2
  if( FD_UNLIKELY( !fd_ulong_is_pow2( max ) ) ) return NULL;
#endif

  hdr->max   = max;
  hdr->start = 0UL;
  hdr->end   = 0UL;

  return hdr;
}

static inline DEQUE_(t) *
DEQUE_(join)( void * shmem ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shmem;
  return hdr->deque;
} 

static inline void * DEQUE_(leave) ( DEQUE_(t) * deque   ) { return (void *)DEQUE_(private_hdr_from_deque)( deque ); }
static inline void * DEQUE_(delete)( void *    shmem ) { return shmem; }

static inline DEQUE_(t) *
DEQUE_(push)( DEQUE_(t) * deque,
              DEQUE_T     new_elt ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->deque[ _MOD(hdr->end) ] = new_elt;
  hdr->end++;
#if !DEQUE_MAX_POW2
  if( FD_UNLIKELY( hdr->end == hdr->max+1UL ) ) hdr->end = 0UL;
#endif
  return deque;
}

static inline DEQUE_(t) *
DEQUE_(push_front)( DEQUE_(t) * deque,
                    DEQUE_T     new_elt ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
#if !DEQUE_MAX_POW2
  if( FD_UNLIKELY( hdr->start == 0UL ) ) hdr->start = hdr->max+1UL;
#endif
  /* In the pow-2 case, this can underflow, but that's fine. We still get
     correct answers. */
  hdr->start--;
  hdr->deque[ _MOD(hdr->start) ] = new_elt;
  return deque;
}

static inline DEQUE_(t)
DEQUE_(pop)( DEQUE_(t) * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  DEQUE_(t) to_return = hdr->deque[ _MOD(hdr->start) ];
  hdr->start++;
#if !DEQUE_MAX_POW2
  if( FD_UNLIKELY( hdr->start == hdr->max+1UL ) ) hdr->start = 0UL;
#endif
  return to_return;
}

static inline DEQUE_(t)
DEQUE_(pop_back)( DEQUE_(t) * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
#if !DEQUE_MAX_POW2
  if( FD_UNLIKELY( hdr->end == 0UL ) ) hdr->end = hdr->max+1UL;
#endif
  hdr->end--;
  return hdr->deque[ _MOD(hdr->end) ];
}
static inline ulong
DEQUE_(cnt)( DEQUE_(t) * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
#if DEQUE_MAX_POW2
  return hdr->end - hdr->start;
#else
  return fd_ulong_if( hdr->end>=hdr->start, hdr->end, hdr->end+hdr->max+1UL ) - hdr->start;
#endif
}

static inline ulong
DEQUE_(max)( DEQUE_(t) * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->max;
}

FD_PROTOTYPES_END

#undef DEQUE_
#undef _MOD

/* End implementation *************************************************/

#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX_POW2
