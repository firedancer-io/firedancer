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

/* FD_FSEQ_DIAG_* specify standard locations in the fseq's application
   region that can be used across a wide variety communicating producers
   and consumers for accumulating flow control diagnostics in a standard
   remote monitoring friendly way.  Treating the application region as
   an array of ulongs:

     PUB_CNT   is the number of received fragments processed/forwarded by the consumer
     PUB_SZ    is the number of received fragment payload bytes processed/forward by the consumer
     FILT_CNT  is the number of received fragments skipped/ignored/filtered by the consumer
     FILT_SZ   is the number of received fragment payload bytes skipped/ignored/filtered by the consumer
     OVRNP_CNT is the number of input overruns detected while polling for metadata by the consumer
     OVRNR_CNT is the number of input overruns detected while reading metadata by the consumer
     SLOW_CNT  is the number of times the consumer was detected as rate limiting consumer by the producer

   It is worth noting that, given properly configured flow control:

     OVRNP_CNT==OVRNR_CNT==0
     PUB_CNT+FILT_CNT==RX_CNT==TX_CNT
     PUB_SZ +FILT_SZ ==RX_SZ ==TX_SZ

   so there isn't much utility adding additional counters for RX_CNT,
   RX_SZ, TX_CNT and/or TX_SZ as these can be strictly derived from the
   counters that are already there under normal operating conditions and
   abnormal operating conditions can be detected.

   Note that application that use these counters, counters 7:11 remain
   available for application specific usage.  To avoid cache line ping
   pong, it recommend that any use of these be for rare events and/or
   for events counted by the producer. */

#define FD_FSEQ_DIAG_PUB_CNT   (0UL) /* On the 1st fseq cache line, updated by the consumer frequently */
#define FD_FSEQ_DIAG_PUB_SZ    (1UL) /* " */
#define FD_FSEQ_DIAG_FILT_CNT  (2UL) /* " */
#define FD_FSEQ_DIAG_FILT_SZ   (3UL) /* " */
#define FD_FSEQ_DIAG_OVRNP_CNT (4UL) /* On the 2nd fseq cache line, updated by the consumer, ideally never */
#define FD_FSEQ_DIAG_OVRNR_CNT (5UL) /* " */
#define FD_FSEQ_DIAG_SLOW_CNT  (6UL) /* ", updated by the producer, rarely */

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

/* fd_fctl_app_laddr returns local address of the fctl's application
   region.  This will have FD_FCTL_APP_ALIGN alignment and room for at
   least FD_FCTL_APP_FOOTPRINT bytes.  Assumes fseq is a current local
   join.  fd_cnc_app_laddr_const is for const correctness.  The return
   values are valid for the lifetime of the local join. */

FD_FN_CONST static inline void *       fd_fseq_app_laddr      ( ulong *       fseq ) { return (void       *)&fseq[2]; }
FD_FN_CONST static inline void const * fd_fseq_app_laddr_const( ulong const * fseq ) { return (void const *)&fseq[2]; }

/* fd_fseq_seq0 returns the sequencer number used when the fseq was
   created.  Assumes fseq is a current local join. */

FD_FN_PURE static inline ulong fd_fseq_seq0( ulong const * fseq ) { return fseq[-1]; }

/* fd_fseq_query reads the current sequence number stored the fseq.  The
   value is observed at some point between when the call started and the
   call returned.  This acts as an implicit compiler fence.  Assumes
   fseq is a current local join. */

static inline ulong
fd_fseq_query( ulong const * fseq ) {
  FD_COMPILER_MFENCE();
  ulong seq = FD_VOLATILE_CONST( fseq[0] );
  FD_COMPILER_MFENCE();
  return seq;
}

/* fd_fseq_update updates the sequence number stored in the fseq to seq.
   The value is updated at some point between when the call started and
   the call returned.  This acts as an implicit compiler fence.  Assumes
   fseq is a current local join. */

static inline void
fd_fseq_update( ulong * fseq,
                ulong   seq ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq[0] ) = seq;
  FD_COMPILER_MFENCE();
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_fseq_fd_fseq_h */
