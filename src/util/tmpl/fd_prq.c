/* Declare ultra high performance priority queues of bounded run-time
   size.  Typical usage:

     struct event {
       ... app stuff
       long timeout; // Technically "PRQ_TIMEOUT_T PRQ_TIMEOUT;"
       ... app stuff
     };

     typedef struct event event_t;

     #define PRQ_NAME eventq
     #define PRQ_T    event_t
     #include "util/tmpl/fd_prq.c"

  will declare the following static inline APIs as a header only style
  library in the compilation unit: 

    // align/footprint - Return the alignment/footprint required for a
    // memory region to be used as eventq that can hold up to max
    // events.
    //
    // new - Format a memory region pointed to by shmem into a eventq.
    // Assumes shmem points to a region with the required alignment and
    // footprint not in use by anything else.  Caller is not joined on
    // return.  Returns shmem.
    //
    // join - Join an eventq.  Assumes sheventq points at a region
    // formatted as an eventq.  Returns a pointer to the eventq's heap.
    // The events on the heap are indexed [0,cnt).  heap[0] is the
    // current min event on the heap (that is, heap[0] is not strictly
    // after any other event on the heap).  The remaining events on the
    // heap can be in any order.  Operations on the heap can reorganize
    // the indexing in arbitrary ways (heap[0] will always be the min
    // event when there is 1 or more events on the heap though).  THIS
    // IS NOT JUST A SIMPLE CAST OF SHEVENTQ.
    //
    // leave - Leave an eventq.  Asumes heap points to the eventq's
    // heap.  Returns a pointer to the shared memory region the join.
    // THIS IS NOT JUST A SIMPLE CAST OF HEAP
    //
    // delete - Unformat a memory region used as an eventq.  Assumes
    // sheventq points to a formatted region with no current joins.
    // Returns a pointer to the unformated memory region.

    ulong     eventq_align    ( void                        );
    ulong     eventq_footprint( ulong      max              );
    void *    eventq_new      ( void *     shmem, ulong max );
    event_t * eventq_join     ( void *     sheventq         ); // not just a cast of sheventq
    void *    eventq_leave    ( event_t *  heap             ); // not just a cast of eventq
    void *    eventq_delete   ( void *     sheventq         );

    // cnt returns the current number events in the heap
    // max returns the maximum number events in the heap

    ulong     eventq_cnt      ( event_t const * heap ); // In [0,max]
    ulong     eventq_max      ( event_t const * heap );

    // insert inserts the event_t pointed to by event into the event
    // queue.  Caller promises there is room in the eventq for event.
    // The eventq has no interest in event on return (its contents are
    // copied into the event queue).  Fast O(lg cnt).  Returns heap.
    //
    // remove_min is optimized version of remove( heap, 0UL ).  Caller
    // promises there at least one event on the heap.  Fast O(lg cnt).
    // Returns heap.
    //
    // remove removes the event_t currently at heap[idx] from the heap.
    // idx should be in [0,cnt) where cnt is the number of events on the
    // heap at call start (as such, the caller also promises there are
    // at least idx+1 events on the help).  Fast O(lg cnt).  Returns
    // heap.
    //
    // remove_all removes all events from heap.  Fast O(1).  Returns
    // heap.

    event_t * eventq_insert    ( event_t * heap, event_t const * event );
    event_t * eventq_remove_min( event_t * heap );
    event_t * eventq_remove    ( event_t * heap, ulong idx );
    event_t * eventq_remove_all( event_t * heap );

    // Note none of this APIs do any input argument checking as they are
    // meant to be used in ultra high performance contexts.  Thus they
    // require the user to be careful.  There is enough functionality
    // here though to trivially wrap this in variants that test user
    // arguments for sanity.

    // Really large event_t are not recommended due to excess implied
    // data motion under the hood.  Cases with
    // sizeof(event_t)==alignof(event_t)==32 are particular good
    // performance practically.

    You can do this as often as you like in a compilation unit to get
    different types of priority queues.  Since it is all static inline,
    it is fine to do this in a header too.  Additional options to fine
    tune this are detailed below. */

#include "../bits/fd_bits.h"
#include <stddef.h>

#ifndef offsetof
#  define offsetof(TYPE,MEMB) ((ulong)((TYPE*)0)->MEMB)
#endif

#ifndef PRQ_NAME
#error "Define PRQ_NAME"
#endif

/* A PRQ_T should be something something reasonable to shallow copy with
   the fields described above.  PRQ_T that are 32-bytes in size with
   32-byte alignment have particularly good cache Feng Shui. */

#ifndef PRQ_T
#error "Define PRQ_T"
#endif

/* Setting PRQ_EXPLITICT_TIMEOUT to 0 allows the user to use a comparison
   function to compare elements in the PRQ without having a single explicit
   timeout field. */
#ifndef PRQ_EXPLICIT_TIMEOUT
#define PRQ_EXPLICIT_TIMEOUT 1
#endif

#if PRQ_EXPLICIT_TIMEOUT
/* PRQ_TIMEOUT allows the user to specify the name of the timeout
   field used for the PRQ.  Defaults to timeout. */

#ifndef PRQ_TIMEOUT
#define PRQ_TIMEOUT timeout
#endif

/* PRQ_TIMEOUT_T allows the user to specify the type of the timeout
   field.  Defaults to long. */

#ifndef PRQ_TIMEOUT_T
#define PRQ_TIMEOUT_T long
#endif

/* PRQ_TIMEOUT_AFTER returns 1 if the timeout x is strictly after the
   timeout y.  Can be changed to create max-queues instead of min queues
   for example (or use orderable but non-integral types for timeouts). */

#ifndef PRQ_TIMEOUT_AFTER
#define PRQ_TIMEOUT_AFTER(x,y) ((x)>(y))
#endif

#else /* PRQ_EXPLICIT_TIMEOUT */

#ifndef PRQ_AFTER
#define PRQ_AFTER(x,y) ((x)>(y))
#endif

#endif

/* The PRQ_TMP_* are meant to allow users of PRQ to do extreme low level
   optimizations for a particular implementation (e.g. loading an PRQ_T
   directly into vector registers and operating on the PRQ_T in the
   registers directly).  It is okay for these macros to do multiple
   evaluations of their arguments and be more than one single linguistic
   expression. */

/* PRQ_TMP_LD declare some ideally register temporaries (t_0,t_1,...)
   and loads the PRQ_T at p into them. */

#ifndef PRQ_TMP_LD
#define PRQ_TMP_LD(t,p) PRQ_T t = (p)[0]
#endif

/* PRQ_TMP_ST stores an PRQ_T in temporaries t (see PRQ_TMP_LD) to the
   PRQ_T pointed to by p. */

#ifndef PRQ_TMP_ST
#define PRQ_TMP_ST(p,t) (p)[0] = (t)
#endif

/* PRQ_TMP_TIMEOUT returns the timeout associated with the PRQ_T in
   temporaries t. */

#ifndef PRQ_TMP_TIMEOUT
#  if PRQ_EXPLICIT_TIMEOUT
#    define PRQ_TMP_TIMEOUT(t) ((t).PRQ_TIMEOUT)
#  endif
#endif

/* PRQ_TMP_AFTER returns 1UL if timeout associated with the PRQ_T in
   temporaries x is strictly after the PRQ_T in temporaries in y and 0UL
   otherwise. */

#ifndef PRQ_TMP_AFTER
#  if PRQ_EXPLICIT_TIMEOUT
#    define PRQ_TMP_AFTER(x,y) ((ulong)PRQ_TIMEOUT_AFTER( PRQ_TMP_TIMEOUT(x), PRQ_TMP_TIMEOUT(y) ))
#  else
#    define PRQ_TMP_AFTER(x,y) ((ulong)PRQ_AFTER( x, y ))
#  endif
#endif

/* PRQ_TMP_CMOV does "if(c) x = y" where x and y are PRQ_T located in
   temporaries. */

#ifndef PRQ_TMP_CMOV
#define PRQ_TMP_CMOV(c,x,y) if( (c) ) (x) = (y)
#endif

/* Implementation *****************************************************/

#define PRQ_(n) FD_EXPAND_THEN_CONCAT3(PRQ_NAME,_,n)

struct PRQ_(private) {
  ulong max;
  ulong cnt;
  PRQ_T heap[1]; /* note that is half cache line aligned if PRQ_T is 32 byte and aligned 32 byte */
  /* max+1 PRQ_T follow here */
};

typedef struct PRQ_(private) PRQ_(private_t);

FD_PROTOTYPES_BEGIN

/* Private APIs *******************************************************/

/* private_from_heap return a pointer to the prq_private given a pointer
   to the prq's heap.  private_from_heap_const also provided for
   const-correctness purposes. */

FD_FN_CONST static inline PRQ_(private_t) *
PRQ_(private_from_heap)( PRQ_T * heap ) {
  ulong ofs = offsetof( PRQ_(private_t), heap );
  return (PRQ_(private_t) *)( (ulong)heap - (ulong)(ofs) );
}

FD_FN_CONST static inline PRQ_(private_t) const *
PRQ_(private_from_heap_const)( PRQ_T const * heap ) {
  ulong ofs = offsetof( PRQ_(private_t), heap );
  return (PRQ_(private_t) const *)( (ulong)heap - (ulong)(ofs) );
}

/* fill_hole_up fills the hole in heap with event and then bubbles it
   up toward the root until the heap property is satisfied.  This
   requires event's timeout to be less than or equal to the timeouts of
   the children in the sub-heap rooted at hole.  This is trivially true
   if hole is a leaf (i.e. no children) and also true if the new_event's
   timeout is less than or equal to the hole's parent timeout (i.e. the
   parent has a timeout less than or equal to its children so the
   new_event does too). */

FD_FN_UNUSED static void /* Work around -Winline */
PRQ_(private_fill_hole_up)( PRQ_T *       heap,     /* Heap, indexed 0:hole+1 */
                            ulong         hole,     /* Location of the hole to fill */
                            PRQ_T const * event ) { /* Event to fill the hole with */

  PRQ_TMP_LD( tmp_event, event );                                 /* Load the event to fill the hole with */
#if PRQ_EXPLICIT_TIMEOUT
  PRQ_TIMEOUT_T event_timeout = PRQ_TMP_TIMEOUT( tmp_event );
#endif
  while( hole ) {                                                 /* If the hole to fill has a parent */
    ulong parent = (hole-1UL) >> 1;                               /*   Load the parent */
    PRQ_TMP_LD( tmp_parent, heap + parent );
#if PRQ_EXPLICIT_TIMEOUT
    PRQ_TIMEOUT_T parent_timeout = PRQ_TMP_TIMEOUT( tmp_parent );
    if( FD_LIKELY( !PRQ_TIMEOUT_AFTER( parent_timeout, event_timeout ) ) )
#else
    if( FD_LIKELY( !PRQ_TMP_AFTER( tmp_parent, tmp_event ) ) )
#endif
      break;                                                      /*   If the parent at least as old as the event, ... */
    PRQ_TMP_ST( heap + hole, tmp_parent );                        /*   Otherwise, fill the hole with the hole's parent */
    hole = parent;                                                /*   and recurse on the created hole at parent */
  }

  PRQ_TMP_ST( heap + hole, tmp_event );                           /* ... fill the hole with the event to schedule */
}

/* fill_hole_dn fills the hole in heap with the last event on the heap
   and bubbles it down toward the leaves until the heap property is
   restored.  This requires that the hole to fill is the root of the
   heap (i.e. a remove-min) or the hole's parent timeout is less than or
   equal to the timeout of the heap's last event (i.e. as might happen
   in a cancel). */

FD_FN_UNUSED static void /* Work around -Winline */
PRQ_(private_fill_hole_dn)( PRQ_T * heap,   /* Heap, half cache line aligned for best perf (assuming 32-byte PRQ_T),
                                               heap[max] and heap[max+1] are dummy slots */
                            ulong   hole,   /* Location of the hole to fill, in [0,cnt] */
                            ulong   cnt ) { /* Location of the last heap event == heap event count not including the hole,
                                               cnt is in [0,max) (if there is is a hole, cnt can't be max) */

  /* Note that this branch isn't strictly necessary.  If hole==cnt,
     heap[hole] will be detected as childless and will be filled by
     itself in a nop. */

  if( FD_UNLIKELY( hole>=cnt ) ) return; /* No hole to fill (empty heap or hole at the end such that heap is still contiguous) */

  /* At this point, there is a hole to fill (hole<cnt, hole in [0,cnt)
     and cnt in [1,max).  Fill the hole by removing the last event and
     reinserting it.  This will keep events contiguously packed while
     satisfying the heap property. */

  PRQ_TMP_LD( tmp_reinsert, heap+cnt );

  ulong speculate_max = cnt | 1UL; /* First odd number >= cnt, in [cnt,cnt+1] */

  for(;;) {

    /* Determine where the first child of the hole is located.  We clamp
       this to the first odd number >= cnt such speculative loads done
       on a hole that has no children don't go far past the end of the
       heap and only hit one cache line.  As such, child is an odd
       number in [1,cnt+1] and, as cnt<=max-1, child must be in [1,max].
       This in turn implies child1 is even and in [2,max+1]. */

    ulong child  = fd_ulong_min( 2UL*hole+1UL, speculate_max );
    ulong child1 = child+1UL;

    /* Speculatively load the two children of this hole.  These loads
       will always hit the same cache line (the heap is half cache line
       aligned and child is odd) and these loads are safe even if this
       hole has fewer children due to the above clamp and dummy slots. */

    PRQ_TMP_LD( tmp_child,  heap+child  );
    PRQ_TMP_LD( tmp_child1, heap+child1 );

    /* If there is a second child and the second child is before the
       first child, the hole should be filled with either the second
       child or the event to reinsert.  Otherwise, the hole should be
       filled with the first child (if any) or the event to reinsert.

       Sigh - compiler won't do a SSE register cmov branchlessly and
       also often undoes the corresponding child index update cmov.
       This leaves one or more algorithmically unpredictable branches in
       a critical place ... so we DIY. */

    ulong use_child1 = ((ulong)(child1<cnt)) & PRQ_TMP_AFTER( tmp_child, tmp_child1 );
    PRQ_TMP_CMOV( use_child1, tmp_child, tmp_child1 );
    child += use_child1;

    /* If there was a child selected above and the event to reinsert is
       strictly after the child, fill the hole with the child (making a
       new hole).  Otherwise, fill the hole with the event to reinsert
       and we are done.
       
       Sigh - see above DIY sigh. */

    ulong use_reinsert = ((ulong)(child>=cnt)) | PRQ_TMP_AFTER( tmp_child, tmp_reinsert );
    PRQ_TMP_CMOV( use_reinsert, tmp_child, tmp_reinsert );
    PRQ_TMP_ST( heap+hole, tmp_child );
    if( use_reinsert ) break; /* Unclear branch prob */
    hole = child;
  }
}

/* fill_hole has the exact same semantics as fill_hold_dn but only
   requires the ancestors and descendents of the hole obey the heap
   property (it will bubble the heap in the appropriate direction). */

static inline void
PRQ_(private_fill_hole)( PRQ_T * heap,
                         ulong   hole,
                         ulong   cnt ) {

  /* If the heap is still compact given the location of the hole,
     nothing to do.  Otherwise, we are going to fill the hole with the
     last event on the heap.  Note that this is not strictly necessary. */

  if( FD_UNLIKELY( hole>=cnt ) ) return;

  /* If the hole has a parent that is after the last event on the heap,
     we need bubble the hole up to find where to reinsert the last
     event.  Otherwise, we need to bubble down.  Branch prob here is not
     obvious and probably application dependent. */
#if PRQ_EXPLICIT_TIMEOUT
  if( hole && PRQ_TIMEOUT_AFTER( heap[ (hole-1UL)>>1 ].PRQ_TIMEOUT, heap[ cnt ].PRQ_TIMEOUT ) )
#else
  if( hole && PRQ_AFTER        ( heap[ (hole-1UL)>>1 ]            , heap[ cnt ]             ) )
#endif
    PRQ_(private_fill_hole_up)( heap, hole, &heap[cnt] );
  else
    PRQ_(private_fill_hole_dn)( heap, hole, cnt );
}

/* Public APIS ********************************************************/

static inline ulong PRQ_(align)( void ) { return alignof(PRQ_(private_t)); }

static inline ulong
PRQ_(footprint)( ulong max ) {
  /* 2UL is for the dummy slots */
  return fd_ulong_align_up( fd_ulong_align_up( 16UL, alignof(PRQ_T) ) + sizeof(PRQ_T)*(max+2UL), alignof(PRQ_(private_t)) );
}

static inline void *
PRQ_(new)( void * mem,
           ulong  max ) {
  /* FIXME: VALIDATE MEM AND MAX? */
  PRQ_(private_t) * prq = (PRQ_(private_t) *)mem;
  prq->cnt = 0UL;
  prq->max = max;
  return (void *)prq;
}

static inline PRQ_T * PRQ_(join  )( void *  prq  ) { return ((PRQ_(private_t) *)prq)->heap;          }
static inline void *  PRQ_(leave )( PRQ_T * heap ) { return (void *)PRQ_(private_from_heap)( heap ); }
static inline void *  PRQ_(delete)( void *  prq  ) { return prq;                                     }

static inline ulong PRQ_(cnt)( PRQ_T const * heap ) { return PRQ_(private_from_heap_const)( heap )->cnt;  }
static inline ulong PRQ_(max)( PRQ_T const * heap ) { return PRQ_(private_from_heap_const)( heap )->max;  }

static inline PRQ_T *
PRQ_(insert)( PRQ_T *       heap,
              PRQ_T const * event ) {
  PRQ_(private_t) * prq = PRQ_(private_from_heap)( heap );
  /* FIXME: HANDHOLDING OPTIONS TO TEST FOR OVERFLOW */
  ulong hole = prq->cnt++;
  PRQ_(private_fill_hole_up)( heap, hole, event );
  return heap;
}

static inline PRQ_T *
PRQ_(remove_min)( PRQ_T * heap ) {
  PRQ_(private_t) * prq = PRQ_(private_from_heap)( heap );
  /* FIXME: HANDHOLDING OPTIONS TO TEST FOR UNDERFLOW */
  ulong cnt = --prq->cnt;
  PRQ_(private_fill_hole_dn)( heap, 0UL, cnt );
  return heap;
}

static inline PRQ_T *
PRQ_(remove)( PRQ_T * heap,
              ulong   idx ) {
  PRQ_(private_t) * prq = PRQ_(private_from_heap)( heap );
  /* FIXME: HANDHOLDING OPTIONS TO TEST FOR UNDERFLOW */
  ulong cnt = --prq->cnt;
  PRQ_(private_fill_hole)( heap, idx, cnt );
  return heap;
}

static inline PRQ_T *
PRQ_(remove_all)( PRQ_T * heap ) {
  PRQ_(private_t) * prq = PRQ_(private_from_heap)( heap );
  prq->cnt = 0UL;
  return heap;
}

FD_PROTOTYPES_END

#undef PRQ_

/* End implementation *************************************************/

#undef PRQ_TMP_CMOV
#undef PRQ_TMP_AFTER
#undef PRQ_TMP_TIMEOUT
#undef PRQ_TMP_ST
#undef PRQ_TMP_LD

#undef PRQ_AFTER
#undef PRQ_TIMEOUT_AFTER
#undef PRQ_TIMEOUT_T
#undef PRQ_TIMEOUT
#undef PRQ_EXPLICIT_TIMEOUT
#undef PRQ_T
#undef PRQ_NAME

