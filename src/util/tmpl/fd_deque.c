/* Declares a family of functions implementing a single threaded
   compile time fixed-capacity double ended queue (deque) designed for
   high performance contexts.  The deque is implemented with a circular
   buffer and can push and pop from both ends.  Setting DEQUE_MAX to a
   power of two is strongly recommended but not required.  Example
   usage:

     #define DEQUE_NAME my_deque
     #define DEQUE_T    my_ele_t
     #define DEQUE_MAX  64UL
     #include "util/tmpl/fd_deque.c"

   This creates the following API for use in the local compilation unit:

     ulong      my_deque_align      ( void               ); // required byte alignment of a deque
     ulong      my_deque_footprint  ( void               ); // required byte footprint of a deque with the given DEQUE_MAX
     void     * my_deque_new        ( void     * shmem   ); // format memory region into a my_deque, my_deque will be empty
                                                            // (caller not joined on return, mem has required align/footprint, etc)
     my_ele_t * my_deque_join       ( void     * shdeque ); // join a my_deque (unlimited joins, etc) (NOT A CAST OF SHDEQUE)
                                                            // join can be indexed like a normal array with DEQUE_MAX elements
     void     * my_deque_leave      ( my_ele_t * deque   ); // leave a my_deque (matched with join, etc) (NOT A CAST OF DEQUE)
     void     * my_deque_delete     ( void     * shdeque ); // unformat memory (no active joins, etc)

     // Accessors

     ulong      my_deque_max        ( my_ele_t * deque   ); // returns the max elements that could be in the queue (==DEQUE_MAX)
     ulong      my_deque_cnt        ( my_ele_t * deque   ); // returns the number of elements in the queue, in [0,DEQUE_MAX]

     // Simple API

     my_ele_t * my_deque_push_head  ( my_ele_t * deque, my_ele_t ele ); // push ele at the deque head, returns deque
     my_ele_t * my_deque_push_tail  ( my_ele_t * deque, my_ele_t ele ); // push ele at the deque tail, returns deque
     my_ele_t   my_deque_pop_head   ( my_ele_t * deque   ); // pops ele from the head of the deque, returns ele
     my_ele_t   my_deque_pop_tail   ( my_ele_t * deque   ); // pops ele from the tail of the deque, returns ele

     // Advanced API for zero-copy usage

     my_ele_t * my_deque_peek_head  ( my_ele_t * deque   ); // peeks at head, returned ptr lifetime is until next op on deque
     my_ele_t * my_deque_peek_tail  ( my_ele_t * deque   ); // peeks at tail, returned ptr lifetime is until next op on deque
     my_ele_t * my_deque_insert_head( my_ele_t * deque   ); // inserts uninitialized element at head, returns deque
     my_ele_t * my_deque_insert_tail( my_ele_t * deque   ); // inserts uninitiaiized element at tail, returns deque
     my_ele_t * my_deque_remove_head( my_ele_t * deque   ); // removes head, returns deque
     my_ele_t * my_deque_remove_tail( my_ele_t * deque   ); // removes tail, returns deque
     my_ele_t * my_deque_remove_all ( my_ele_t * deque   ); // removes all, returns deque, fast O(1)

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
     and                    the queue tail is at element deque[ (end-1UL) % MAX ]

     start and end are initialized such that overflow / underflow will
     not happen for millenia practically.  More precisely, this
     implementation requires user will not do more than 2^63 operations
     on the deque. */

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
  return (DEQUE_(private_t) *)( (ulong)deque - (ulong)&(((DEQUE_(private_t) *)NULL)->deque) );
}

/* private_slot maps an index to a slot cnt.  The compiler should
   optimize this to a bit-and when MAX is a power of 2 and, hopefully,
   to optimize this to a magic multiply otherwise. */

FD_FN_CONST static inline ulong DEQUE_(private_slot)( ulong i ) { return i % (ulong)(DEQUE_MAX); }

FD_FN_CONST static inline ulong DEQUE_(align)    ( void ) { return alignof(DEQUE_(private_t)); }
FD_FN_CONST static inline ulong DEQUE_(footprint)( void ) { return sizeof (DEQUE_(private_t)); }

FD_FN_UNUSED static void * /* Work around -Winline */
DEQUE_(new)( void * shmem ) {
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shmem;
  /* These values are large enough that underflow / overflow will never
     happen in practical usage (e.g. hundreds of years if all a core did
     was continuously enqueue at 1GHz assuming first that you have a
     planet sized 2^63 deep queue).  So we don't need to do any special
     handling overflow handling in practice that might otherwise be
     required if using a non-power-of-two MAX. */
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

static inline ulong DEQUE_(max)( DEQUE_T * deque ) { (void)deque; return (ulong)(DEQUE_MAX); }

static inline ulong
DEQUE_(cnt)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->end - hdr->start;
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

static inline DEQUE_T *
DEQUE_(peek_head)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->deque + DEQUE_(private_slot)( hdr->start );
}

static inline DEQUE_T *
DEQUE_(peek_tail)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->deque + DEQUE_(private_slot)( hdr->end-1UL );
}

static inline DEQUE_T * DEQUE_(insert_head)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->start--; return deque; }
static inline DEQUE_T * DEQUE_(insert_tail)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->end++;   return deque; }
static inline DEQUE_T * DEQUE_(remove_head)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->start++; return deque; }
static inline DEQUE_T * DEQUE_(remove_tail)( DEQUE_T * deque ) { DEQUE_(private_hdr_from_deque)( deque )->end--;   return deque; }

static inline DEQUE_T *
DEQUE_(remove_all)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  /* See note in new */
  hdr->start = 1UL << 63;
  hdr->end   = 1UL << 63;
  return deque;
}

FD_PROTOTYPES_END

#undef DEQUE_MAX
#undef DEQUE_T
#undef DEQUE_NAME

