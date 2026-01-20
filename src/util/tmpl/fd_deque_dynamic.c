/* Declares a family of functions implementing a single-threaded
   run-time fixed-capacity double-ended queue (deque) designed for high
   performance contexts.  Example usage:

     #define DEQUE_NAME my_deque
     #define DEQUE_T    my_ele_t
     #include "util/tmpl/fd_deque.c"

   This creates the following API for use in the local compilation unit:

     // Constructors

     // IMPORTANT SAFETY TIP!  max==0 is fine for this API.  Calling
     // most APIs on such a deque will be a violation of the API
     // pre-requisites (e.g. push_head and pop_tail are not valid
     // because a max==0 deque is simultaneously full and empty).  The
     // accessors (max==0, cnt==0, avail==0, empty==true, full==true),
     // remove_all (no-op) and iterators (will indicate nothing to
     // iterator over) are still valid to use.

     ulong      my_deque_align    ( void               ); // required byte alignment of a deque
     ulong      my_deque_footprint( ulong      max     ); // required byte footprint of a deque with max capacity
     void     * my_deque_new      ( void     * shmem,     // format memory region into a my_deque, my_deque will be empty
                                    ulong      max     ); // (caller not joined on return, mem has required align/footprint, etc)
     my_ele_t * my_deque_join     ( void     * shdeque ); // join a my_deque (unlimited joins, etc) (NOT A CAST OF SHDEQUE)
                                                          // join can be indexed like a normal array with max elements
     void     * my_deque_leave    ( my_ele_t * deque   ); // leave a my_deque (matched with join, etc) (NOT A CAST OF DEQUE)
     void     * my_deque_delete   ( void     * shdeque ); // unformat memory (no active joins, etc)

     // Accessors

     ulong my_deque_max  ( my_ele_t const * deque ); // returns the max elements that could be in the deque
     ulong my_deque_cnt  ( my_ele_t const * deque ); // returns the number of elements in the deque, in [0,max]
     ulong my_deque_avail( my_ele_t const * deque ); // returns max-cnt
     int   my_deque_empty( my_ele_t const * deque ); // returns 1 if deque is empty and 0 otherwise
     int   my_deque_full ( my_ele_t const * deque ); // returns 1 if deque is full and 0 otherwise

     // Simple API

     // IMPORTANT SAFETY TIP!  The wrap APIs discard the value popped on
     // wrapping.  Thus, these should not be used when a my_ele_t might
     // contain the only reference to a resource (memory, file
     // descriptors, etc) that might need to be released after popping
     // (e.g. use these only if my_ele_t is plain-old-data).

     // IMPORTANT SAFETY TIP!  The pop_idx APIs have an O(cnt) worst
     // case.

     my_ele_t * my_deque_push_head     ( my_ele_t * deque, my_ele_t ele ); // push ele at the deque head, returns deque
     my_ele_t * my_deque_push_tail     ( my_ele_t * deque, my_ele_t ele ); // push ele at the deque tail, returns deque
     my_ele_t   my_deque_pop_head      ( my_ele_t * deque               ); // pops ele from the head of the deque, returns ele
     my_ele_t   my_deque_pop_tail      ( my_ele_t * deque               ); // pops ele from the tail of the deque, returns ele
     my_ele_t * my_deque_push_head_wrap( my_ele_t * deque, my_ele_t ele ); // push ele at the deque head (pops tail first if deque full), returns deque, assumes deque has a positive max
     my_ele_t * my_deque_push_tail_wrap( my_ele_t * deque, my_ele_t ele ); // push ele at the deque tail (pops head first if deque full), returns deque, assumes deque has a positive max
     my_ele_t   my_deque_pop_idx_tail  ( my_ele_t * deque, ulong    idx ); // pops ele at idx, returns ele. idx in [0,cnt). shifts head <= tail

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

     my_ele_t const * my_deque_peek_head_const( my_ele_t const * deque ); // const version of peek_head
     my_ele_t const * my_deque_peek_tail_const( my_ele_t const * deque ); // const version of peek_tail
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

     // my_deque_iter_rev_* allow for iteration similar to the above, but
     // in reverse order from tail to head.
     // Example usage:
     //
     //   for( my_deque_iter_t iter = my_deque_iter_init_rev( deque ); !my_deque_iter_done_rev( deque, iter ); iter = my_deque_iter_prev( deque, iter ) ) {
     //     my_deque_t * ele = my_deque_iter_ele( deque, iter );
     //
     //     ... process ele here
     //   }

     my_deque_iter_t  my_deque_iter_init_rev ( my_deque_t const * deque );
     int              my_deque_iter_done_rev ( my_deque_t const * deque, my_deque_iter_t iter ); // returns 1 if no more iterations, 0 o.w.
     my_deque_iter_t  my_deque_iter_prev     ( my_deque_t const * deque, my_deque_iter_t iter ); // returns prev iter value iter

   For performance, none of the functions do any error checking.
   Specifically, the caller promises that max is such that footprint
   will not overflow 2^64 (e.g. max << (2^64)/sizeof(my_ele_t)), cnt<max
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

#if FD_TMPL_USE_HANDHOLDING
#include "../log/fd_log.h"
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
  return (DEQUE_(private_t) *)( (ulong)deque - offsetof(DEQUE_(private_t), deque) );
}

/* const-correct version of above */

FD_FN_CONST static inline DEQUE_(private_t) const *
DEQUE_(private_const_hdr_from_deque)( DEQUE_T const * deque ) {
  return (DEQUE_(private_t) const *)( (ulong)deque - offsetof(DEQUE_(private_t), deque) );
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

static inline void *
DEQUE_(new)( void * shmem,
             ulong  max ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( !shmem                                                ) ) FD_LOG_CRIT(( "NULL shmem" ));
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, DEQUE_(align)() ) ) ) FD_LOG_CRIT(( "unaligned shmem" ));
# endif
  DEQUE_(private_t) * hdr = (DEQUE_(private_t) *)shmem;
  hdr->max1  = max-1UL; /* Note: will wrap to ULONG_MAX if max==0 (and ULONG_MAX+1 will wrap back to 0) */
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

static inline void *
DEQUE_(delete)( void * shdeque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( !shdeque                                                ) ) FD_LOG_CRIT(( "NULL shdeque" ));
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shdeque, DEQUE_(align)() ) ) ) FD_LOG_CRIT(( "unaligned shmem" ));
# endif
  return shdeque;
}

FD_FN_PURE static inline ulong
DEQUE_(max)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->max1 + 1UL;
}

FD_FN_PURE static inline ulong
DEQUE_(cnt)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->cnt;
}

FD_FN_PURE static inline ulong
DEQUE_(avail)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->max1 + 1UL - hdr->cnt;
}

FD_FN_PURE static inline int
DEQUE_(empty)( DEQUE_T const * deque ) {
  return !DEQUE_(private_const_hdr_from_deque)( deque )->cnt;
}

FD_FN_PURE static inline int
DEQUE_(full)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return (hdr->max1 + 1UL)==hdr->cnt;
}

static inline DEQUE_T *
DEQUE_(push_head)( DEQUE_T * deque,
                   DEQUE_T   ele ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(full)( deque ) ) ) FD_LOG_CRIT(( "cannot push to full deque" ));
# endif
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
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(full)( deque ) ) ) FD_LOG_CRIT(( "cannot push to full deque" ));
# endif
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
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot pop from empty deque" ));
# endif
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
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot pop from empty deque" ));
# endif
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

static inline DEQUE_T *
DEQUE_(push_head_wrap)( DEQUE_T * deque,
                        DEQUE_T   ele ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  ulong end   = hdr->end;

# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( max1==ULONG_MAX ) ) FD_LOG_CRIT(( "cannot push_head_wrap when max is zero" ));
# endif

  /* If the deque is full, pop and discard the tail. */

  int is_full = (cnt>max1);
  end  = fd_ulong_if( !is_full, end, DEQUE_(private_prev)( end, max1 ) );
  cnt -= (ulong)is_full;

  /* Push the head */

  start = DEQUE_(private_prev)( start, max1 );
  hdr->deque[ start ] = ele;

  hdr->cnt   = cnt + 1UL;
  hdr->start = start;
  hdr->end   = end;
  return deque;
}

static inline DEQUE_T *
DEQUE_(push_tail_wrap)( DEQUE_T * deque,
                        DEQUE_T   ele ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  ulong end   = hdr->end;

# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( max1==ULONG_MAX ) ) FD_LOG_CRIT(( "cannot push_tail_wrap when max is zero" ));
# endif

  /* If the deque is full, pop and discard the head. */

  int is_full = (cnt>max1);
  start  = fd_ulong_if( !is_full, start, DEQUE_(private_next)( start, max1 ) );
  cnt   -= (ulong)is_full;

  /* Push the head */

  hdr->deque[ end ] = ele;
  end = DEQUE_(private_next)( end, max1 );

  hdr->cnt   = cnt + 1UL;
  hdr->start = start;
  hdr->end   = end;
  return deque;
}

static inline DEQUE_T
DEQUE_(pop_idx_tail)( DEQUE_T * deque, ulong idx ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque )    ) ) FD_LOG_CRIT(( "cannot pop from empty deque" ));
  if( FD_UNLIKELY( idx>=DEQUE_(cnt)( deque ) ) ) FD_LOG_CRIT(( "index out of bounds" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );

  ulong max1 = hdr->max1;

  ulong slot = hdr->start + idx;
        slot = fd_ulong_if( slot <= max1, slot, slot - max1 - 1UL );
  ulong cnt  = --hdr->cnt;
  ulong rem  = cnt - idx;

  hdr->end   = DEQUE_(private_prev)( hdr->end, max1 );

  DEQUE_T * cur = &deque[ slot ];
  DEQUE_T   ele = *cur;
  while( rem-- ) {
    slot = DEQUE_(private_next)( slot, max1 );
    DEQUE_T * next = &deque[ slot ];
    *cur = *next;
     cur =  next;
  }
  return ele;
}

FD_FN_PURE static inline DEQUE_T *
DEQUE_(peek_head)( DEQUE_T * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot peek on empty deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->deque + hdr->start;
}

FD_FN_PURE static inline DEQUE_T *
DEQUE_(peek_tail)( DEQUE_T * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot peek on empty deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  return hdr->deque + DEQUE_(private_prev)( hdr->end, hdr->max1 );
}

FD_FN_PURE static inline DEQUE_T *
DEQUE_(peek_index)( DEQUE_T * deque, ulong idx ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot peek on empty deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong slot = hdr->start + idx;
        slot = fd_ulong_if( slot <= hdr->max1, slot, slot - hdr->max1 - 1UL );
  return hdr->deque + slot;
}

FD_FN_PURE static inline DEQUE_T const *
DEQUE_(peek_head_const)( DEQUE_T const * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot peek on empty deque" ));
# endif
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->deque + hdr->start;
}

FD_FN_PURE static inline DEQUE_T const *
DEQUE_(peek_tail_const)( DEQUE_T const * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot peek on empty deque" ));
# endif
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  return hdr->deque + DEQUE_(private_prev)( hdr->end, hdr->max1 );
}

FD_FN_PURE static inline DEQUE_T const *
DEQUE_(peek_index_const)( DEQUE_T const * deque, ulong idx ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot peek on empty deque" ));
# endif
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  ulong slot = hdr->start + idx;
        slot = fd_ulong_if( slot <= hdr->max1, slot, slot - hdr->max1 - 1UL );
  return hdr->deque + slot;
}

static inline DEQUE_T *
DEQUE_(insert_head)( DEQUE_T * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(full)( deque ) ) ) FD_LOG_CRIT(( "cannot insert into full deque" ));
# endif
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
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(full)( deque ) ) ) FD_LOG_CRIT(( "cannot insert into full deque" ));
# endif
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
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot remove from empty deque" ));
# endif
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
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot remove from empty deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->cnt   = cnt - 1UL;
  hdr->end   = DEQUE_(private_prev)( end, max1 );
  return deque;
}

static inline DEQUE_T *
DEQUE_(push_head_nocopy)( DEQUE_T * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(full)( deque ) ) ) FD_LOG_CRIT(( "cannot push to full deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  hdr->cnt    = cnt + 1UL;
  hdr->start  = DEQUE_(private_prev)( start, max1 );
  return hdr->deque + hdr->start;
}

static inline DEQUE_T *
DEQUE_(push_tail_nocopy)( DEQUE_T * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(full)( deque ) ) ) FD_LOG_CRIT(( "cannot push to full deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->cnt   = cnt + 1UL;
  DEQUE_T * res = hdr->deque + hdr->end;
  hdr->end   = DEQUE_(private_next)( end, max1 );
  return res;
}

static inline DEQUE_T *
DEQUE_(pop_head_nocopy)( DEQUE_T * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot pop from empty deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1  = hdr->max1;
  ulong cnt   = hdr->cnt;
  ulong start = hdr->start;
  hdr->cnt    = cnt - 1UL;
  DEQUE_T * res = hdr->deque + hdr->start;
  hdr->start  = DEQUE_(private_next)( start, max1 );
  return res;
}

static inline DEQUE_T *
DEQUE_(pop_tail_nocopy)( DEQUE_T * deque ) {
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( DEQUE_(empty)( deque ) ) ) FD_LOG_CRIT(( "cannot pop from empty deque" ));
# endif
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  ulong max1 = hdr->max1;
  ulong cnt  = hdr->cnt;
  ulong end  = hdr->end;
  hdr->cnt   = cnt - 1UL;
  hdr->end   = DEQUE_(private_prev)( end, max1 );
  return hdr->deque + hdr->end;
}

static inline DEQUE_T *
DEQUE_(remove_all)( DEQUE_T * deque ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
  hdr->cnt   = 0UL;
  hdr->start = 0UL;
  hdr->end   = 0UL;
  return deque;
}

typedef struct { ulong rem; ulong idx; } DEQUE_(iter_t);

static inline DEQUE_(iter_t)
DEQUE_(iter_init)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  DEQUE_(iter_t) iter;
  iter.rem = hdr->cnt;
  iter.idx = hdr->start;
  return iter;
}

static inline DEQUE_(iter_t)
DEQUE_(iter_init_rev)( DEQUE_T const * deque ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  DEQUE_(iter_t) iter;
  iter.rem = hdr->cnt;
  iter.idx = hdr->end;
  iter.idx = DEQUE_(private_prev)( iter.idx, hdr->max1 );
  return iter;
}

static inline int
DEQUE_(iter_done)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  (void)deque;
  return !iter.rem;
}

static inline int
DEQUE_(iter_done_rev)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  (void)deque;
  return !iter.rem;
}

__attribute__((warn_unused_result)) static inline DEQUE_(iter_t)
DEQUE_(iter_next)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  iter.rem--;
  iter.idx = DEQUE_(private_next)( iter.idx, hdr->max1 );
  return iter;
}

__attribute__((warn_unused_result)) static inline DEQUE_(iter_t)
DEQUE_(iter_prev)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
  iter.rem--;
  iter.idx = DEQUE_(private_prev)( iter.idx, hdr->max1 );
  return iter;
}

static inline DEQUE_T *
DEQUE_(iter_ele)( DEQUE_T * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) * hdr = DEQUE_(private_hdr_from_deque)( deque );
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( (iter.rem==0) | (iter.rem>hdr->cnt) ) ) FD_LOG_CRIT(( "iter out of bounds" ));
# endif
  return hdr->deque + iter.idx;
}

static inline DEQUE_T const *
DEQUE_(iter_ele_const)( DEQUE_T const * deque, DEQUE_(iter_t) iter ) {
  DEQUE_(private_t) const * hdr = DEQUE_(private_const_hdr_from_deque)( deque );
# if FD_TMPL_USE_HANDHOLDING
  if( FD_UNLIKELY( (iter.rem==0) | (iter.rem>hdr->cnt) ) ) FD_LOG_CRIT(( "iter out of bounds" ));
# endif
  return hdr->deque + iter.idx;
}

FD_PROTOTYPES_END

#undef DEQUE_

#undef DEQUE_T
#undef DEQUE_NAME
