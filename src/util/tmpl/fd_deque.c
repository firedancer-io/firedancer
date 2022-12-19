/* Declares a family of functions implementing a single threaded fixed-capacity
   queue designed for high performance contexts.  The queue is implemented with
   a circular buffer and can push and pop from both ends.  Both pushing an
   popping are always O(1), but copy an element.  Setting DEQUE_MAX to a power
   of two automatically will result in tighter assembly code.

   Example usage:

#define DEQUE_NAME  my_deque
#define DEQUE_T     long
#define DEQUE_MAX   64
#include "util/tmpl/fd_deque.c"

This creates the following API for use in the local compilation unit:

     ulong my_deque_align    ( void      ); // required byte alignment of a my_deque_t
     ulong my_deque_footprint( ulong max ); // required byte footprint of a my_deque_t that can hold max elements

     void *       my_deque_new   ( void * shmem    ); // format memory region into a my_deque, my_deque will be empty
                                                      // (caller not joined on return, mem has required align/footprint, etc)
     long *       my_deque_join  ( void  * shdeque ); // join a my_deque (unlimited joins, etc) (NOT A CAST OF SHDEQUE)
     void *       my_deque_leave ( long  *   deque ); // leave a my_deque (matched with join, etc) (NOT A CAST OF DEQUE)
     void *       my_deque_delete( void  * shdeque ); // unformat memory (no active joins, etc)


     long *  my_deque_push      ( long * deque, long new_elt ); // pushes new_elt onto the end of the queue
     long *  my_deque_push_front( long * deque, long new_elt ); // pushes new_elt onto the front of the queue
     long    my_deque_pop       ( long * deque ); // returns and pops element from the front of the queue
     long    my_deque_pop_back  ( long * deque ); // returns and pops element from the back of the queue
     ulong   my_deque_cnt       ( long * deque ); // returns the number of elements in the queue
     ulong   my_deque_max       ( long * deque ); // returns the max capacity of the queue (64 in this case)

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

#ifndef DEQUE_MAX
#error "Define DEQUE_MAX or use fd_deque_dynamic"
#endif

#if ((DEQUE_MAX)<=0)
#error "DEQUE_MAX must be positive"
#endif

#define DEQUE_MAX_POW2 (!((DEQUE_MAX)&((DEQUE_MAX)-1UL)))

#if DEQUE_MAX_POW2
#define _MOD(x) ((x)&((DEQUE_MAX)-1UL)) /* If y is a power of 2, x%y==x&(y-1) */
#else
/* The modulus is a compile-time constant, so hopefully the compiler can use magic multiply. */
#define _MOD(x) (x%(DEQUE_MAX)) 
#endif

/* Implementation *****************************************************/

#define DEQUE_(x) FD_EXPAND_THEN_CONCAT3(DEQUE_NAME,_,x)

typedef DEQUE_T DEQUE_(t);

struct DEQUE_(private) {
  /* The queue consists of elements i%max, where i is in [start, end).
     (In the case that underflow has occurred and start>end as integers,
     interpret the range as [start, end+ULONG_MAX) )
   */
  ulong    start;
  ulong    end;
  DEQUE_(t) deque[ 1 ]; /* Actually max in size */
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
DEQUE_(footprint)( ) {
  return sizeof(DEQUE_(private_t)) + sizeof(DEQUE_(t))*((DEQUE_MAX)-1UL);
}

FD_FN_UNUSED static void * /* Work around -Winline */
DEQUE_(new)( void * shmem ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shmem;

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
  return deque;
}

static inline DEQUE_(t) *
DEQUE_(push_front)( DEQUE_(t) * deque,
                    DEQUE_T     new_elt ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
#if DEQUE_MAX_POW2
  hdr->start--;
#else 
  /* start-- can underflow, which is a problem if 2^64 != 0 (mod DEQUE_MAX) */
  hdr->end   = fd_ulong_if( hdr->start-1UL<hdr->start, hdr->end,       hdr->end  +DEQUE_MAX     );
  hdr->start = fd_ulong_if( hdr->start-1UL<hdr->start, hdr->start-1UL, hdr->start+DEQUE_MAX-1UL );
#endif
  hdr->deque[ _MOD(hdr->start) ] = new_elt;
  return deque;
}

static inline DEQUE_(t)
DEQUE_(pop)( DEQUE_(t) * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  DEQUE_(t) to_return = hdr->deque[ _MOD(hdr->start) ];
  hdr->start++;
  return to_return;
}

static inline DEQUE_(t)
DEQUE_(pop_back)( DEQUE_(t) * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  /* In the non-power-of-2 case, this one can't underflow unless start--
     underflowed, in which case it was corrected, or the queue is underrun */
  hdr->end--;
  return hdr->deque[ _MOD(hdr->end) ];
}
static inline ulong
DEQUE_(cnt)( DEQUE_(t) * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->end - hdr->start;
}

static inline ulong
DEQUE_(max)( void ) {
  return DEQUE_MAX;
}

FD_PROTOTYPES_END
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
#undef DEQUE_MAX_POW2
#undef _MOD
