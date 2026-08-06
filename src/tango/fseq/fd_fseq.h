#ifndef HEADER_fd_src_tango_fseq_fd_fseq_h
#define HEADER_fd_src_tango_fseq_fd_fseq_h

/* fseq provides APIs for wrapping up a sequence number as a persistent
   shared memory object (primarily for use in rx->tx flow control
   communications but potentially could be used for other cases of
   making sequence numbers visible to other processes at run-time). */

#include "../fd_tango_base.h"

/* FD_FSEQ_{ALIGN,FOOTPRINT} specify the alignment and footprint needed
   for a fseq.  ALIGN is a positive integer power of 2.  FOOTPRINT is a
   multiple of ALIGN.  ALIGN is recommended to be at least double cache
   line to mitigate various kinds of false sharing.  These are provided
   to facilitate compile time declarations. */

#define FD_FSEQ_ALIGN     (128UL)
#define FD_FSEQ_FOOTPRINT (128UL)

/* FD_FSEQ_APP_{ALIGN,FOOTPRINT} specify the alignment and footprint of
   a fseq's application region.  ALIGN is a positive integer power of 2.
   FOOTPRINT is a multiple of ALIGN. */

#define FD_FSEQ_APP_ALIGN     (32UL)
#define FD_FSEQ_APP_FOOTPRINT (96UL)

/* FD_FSEQ_SLEEP_BIT is a bit in fseq[1] indicating that the consumer is
   currently asleep.  When this bit is set, the consumer will only make
   progress (advance fseq[0]) when woken by a producer.  fseq is
   agnostic to the sleep/wake mechanism. (typically futex on Linux). */

#define FD_FSEQ_SLEEP_BIT (1UL<<0)

FD_PROTOTYPES_BEGIN

/* fd_fseq_{align,footprint} return the required alignment and footprint
   of a memory region suitable for use as a fseq.  fd_fseq_align returns
   FD_FSEQ_ALIGN.  fd_fseq_footprint returns FD_FSEQ_FOOTPRINT. */

FD_FN_CONST ulong
fd_fseq_align( void );

FD_FN_CONST ulong
fd_fseq_footprint( void );

/* fd_fseq_new formats an unused memory region for use as a fseq.  Assumes
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  The fseq will be
   initialized to seq0 and the application region will be cleared to 0.
   Returns shmem (and the memory region it points to will be formatted
   as a fseq, caller is not joined) and NULL on failure (logs details).
   Reasons for failure include an obviously bad memory region. */

void *
fd_fseq_new( void * shmem,
             ulong  seq0 );

/* fd_fseq_join joins the caller to the fseq.  shfseq points to the first
   byte of the memory region backing the fseq in the caller's address
   space.  Returns a pointer in the local address space to the fseq on
   success (IMPORTANT! THIS SHOULD NOT BE ASSUMED TO BE JUST A CAST OF
   SHFSEQ) or NULL on failure (logs details).  Reasons for failure
   include the shfseq is obviously not a local pointer to a memory
   region holding a fseq.  Every successful join should have a matching
   leave.  The lifetime of the join is until the matching leave or
   caller's thread group is terminated. */

ulong *
fd_fseq_join( void * shfseq );

/* fd_fseq_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success (IMPORTANT! THIS SHOULD
   NOT BE ASSUMED TO BE JUST A CAST OF FSEQ) and NULL on failure (logs
   details).  Reasons for failure include fseq is NULL. */

void *
fd_fseq_leave( ulong const * fseq );

/* fd_fseq_delete unformats a memory region used as a fseq.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g. shfseq
   obviously does not point to a fseq ... logs details).  The ownership
   of the memory region is transferred to the caller on success. */

void *
fd_fseq_delete( void * shfseq );

/* fd_fseq_app_laddr returns local address of the fseq's application
   region.  This will have FD_FSEQ_APP_ALIGN alignment and room for at
   least FD_FSEQ_APP_FOOTPRINT bytes.  Assumes fseq is a current local
   join.  fd_fseq_app_laddr_const is for const correctness.  The return
   values are valid for the lifetime of the local join. */

FD_FN_CONST static inline void *       fd_fseq_app_laddr      ( ulong *       fseq ) { return (void       *)(fseq+2); }
FD_FN_CONST static inline void const * fd_fseq_app_laddr_const( ulong const * fseq ) { return (void const *)(fseq+2); }

/* fd_fseq_seq0 returns the sequencer number used when the fseq was
   created.  Assumes fseq is a current local join. */

FD_FN_PURE static inline ulong fd_fseq_seq0( ulong const * fseq ) { return fseq[-1]; }

/* fd_fseq_query reads the current sequence number stored the fseq.  The
   value is observed at some point between when the call started and the
   call returned.  This acts as an implicit compiler fence.  Assumes
   fseq is a current local join. */

static inline ulong
fd_fseq_query( ulong const * fseq ) {
# if FD_HAS_X86
  FD_COMPILER_MFENCE();
  ulong seq = FD_VOLATILE_CONST( fseq[0] );
  FD_COMPILER_MFENCE();
  return seq;
# else
  return __atomic_load_n( fseq, __ATOMIC_ACQUIRE );
# endif
}

/* fd_fseq_update updates the sequence number stored in the fseq to seq.
   The value is updated at some point between when the call started and
   the call returned.  This acts as an implicit compiler fence.  Assumes
   fseq is a current local join. */

static inline void
fd_fseq_update( ulong * fseq,
                ulong   seq ) {
# if FD_HAS_X86
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq[0] ) = seq;
  FD_COMPILER_MFENCE();
# else
  __atomic_store_n( fseq, seq, __ATOMIC_RELEASE );
# endif
}

/* fd_fseq_sleep_set hints that the calling thread's sleep state.
   sleep==0 implies that the calling thread is active and updating
   fseq[0].  sleep==1 implies that the calling thread might not advance
   fseq[0] until woken by another thread.  sleep should be a compile-
   time constant.

   Forms a StoreLoad barrier.  Subsequent memory accesses in program
   order execute only once the sleep state update is visible to all
   other threads. */

static inline void
fd_fseq_sleep_set( ulong * fseq,
                   int     sleep ) {
  /* On first sight, this atomic RMW looks like it could be relaxed into
     a SeqCst store since the calling thread is the only writer to
     fseq[1].  Implementing the StoreLoad barrier with just a SeqCst
     store would require a stronger load operation on the query side
     though, and ends up not being worth it. */
  if( sleep ) { /* compile time folded */
    __atomic_fetch_or( fseq+1, FD_FSEQ_SLEEP_BIT, __ATOMIC_SEQ_CST );
  } else {
    __atomic_fetch_and( fseq+1, ~FD_FSEQ_SLEEP_BIT, __ATOMIC_SEQ_CST );
  }
}

/* fd_fseq_sleep_{start,end} are provided for convenience. */

static inline void fd_fseq_sleep_start( ulong * fseq ) { fd_fseq_sleep_set( fseq, 1 ); }
static inline void fd_fseq_sleep_end  ( ulong * fseq ) { fd_fseq_sleep_set( fseq, 0 ); }

/* fd_fseq_sleep_query returns 1 if the thread advancing fseq[0] hints
   that it is asleep, 0 otherwise.  If the calling thread desires that
   fseq[0] advances and the return value is 1, a wake should be issued.
   fd_fseq_new sets the sleep bit to 0, so the default return value of
   this function is 0. */

static inline int
fd_fseq_sleep_query( ulong const * fseq ) {
  return !!( __atomic_load_n( fseq+1, __ATOMIC_ACQUIRE ) & FD_FSEQ_SLEEP_BIT );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_fseq_fd_fseq_h */
