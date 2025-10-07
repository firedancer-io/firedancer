#ifndef HEADER_fd_src_vinyl_cq_fd_vinyl_cq_h
#define HEADER_fd_src_vinyl_cq_fd_vinyl_cq_h

/* A fd_vinyl_comp_t provides details about vinyl request completions. */

#include "../fd_vinyl_base.h"

/* FD_VINYL_COMP_{ALIGN,FOOTPRINT} give the byte alignment and footprint
   of a fd_vinyl_comp_t.  ALIGN is a reasonable power-of-2.  FOOTPRINT
   is a multiple of ALIGN. */

#define FD_VINYL_COMP_ALIGN     (32UL)
#define FD_VINYL_COMP_FOOTPRINT (32UL)

/* FD_VINYL_COMP_QUOTA_MAX gives the maximum client acquire quota that
   can be returned by a completion. */

#define FD_VINYL_COMP_QUOTA_MAX (65535UL)

/* FIXME: consider eching back the val_gaddr and err_gaddr array back
   too?  Maybe helpful in the case of read pipelining (e.g. request made
   on one thread, completion received on a different thread).  But the
   req_id can probably encode this for a case like this without needing
   to bloat the completion footprint. */

struct __attribute__((aligned(FD_VINYL_COMP_ALIGN))) fd_vinyl_comp {
  ulong  seq;       /* Completion sequence number */
  ulong  req_id;    /* Echoed from corresponding request */
  ulong  link_id;   /* Echoed from corresponding request */
  short  err;       /* FD_VINYL_SUCCESS (0) if the request was processed (see request err array for individual failure details)
                       FD_VINYL_ERR_* (negative) otherwise (no items in the request were processed) */
  ushort batch_cnt; /* Num items requested */
  ushort fail_cnt;  /* If a successful completion, num items that failed processing, in [0,batch_cnt].
                       If a failed completion, 0 (no items were processed). */
  ushort quota_rem; /* Client quota remaining when request completed processing.
                       0<=quota_rem<=client quota_max<=FD_VINYL_COMP_QUOTA_MAX */
};

typedef struct fd_vinyl_comp fd_vinyl_comp_t;

/* A fd_vinyl_cq_t is an interprocess sharable persistent SPMC
   queue used to communicate fd_vinyl_comp_t completions from a vinyl
   tile to clients.  It is implemented as a hybrid direct mapped cache /
   queue with similar lockfree properties to a tango mcache.
   Specifically, when publishing a completion into a cq, a producer:

   - Assigns the completion the cq's next sequence number and determines
     the corresponding cache line.

   - Sets the cache line seq to seq-1.  Because the cq's cache has at
     least 4 lines (2 is enough for this particular case), this is a seq
     that will never be held in that line.  This atomically indicates to
     a concurrent consumer that seq-comp_cnt is no longer available in
     cache and that seq is in the process of being published into the
     line.

   - Set the rest of the completion fields.

   - Sets the cache line seq to seq.  This atomically indicates that
     completion seq is ready.

   - Advances the cq's seq cursor.  From a consumer's point of view,
     this cursor has the property that that [0,seq) have been published
     and (seq,ULONG_MAX] have not been published.  This cursor should
     only be used by consumers to synchronize their local cursors at
     initialization.

   When reading completions from a cq, a consumer:

   - Determine the cache line for consumer's seq.

   - Reads the cache line seq.

   - Reads the rest of the completion fields.

   - Reads the cache line seq again.

   If the first and second reads do not match, the vinyl tile is in the
   process of updating that cache line (most likely the consumer is
   caught up and producer is about to produce seq ... the consumer
   should try again soon).

   Otherwise, if the read sequence numbers match the consumer's seq, the
   consumer received completion seq and should advance their local seq.

   If they are behind the consumer's seq, the producer has not written
   seq yet and the consumer should try again later.

   If they are ahead of the consumer's seq, the producer has overrun the
   consumer (the amount ahead gives a ballpark how far the consumer fell
   behind) and the consumer should recover / reinit.  As such, flow
   control is managed by the application (e.g. if the application
   ensures that there are at most comp_cnt completion generating vinyl
   requests pending at any given time on this cq, no overruns are
   possible).

   Note that because fd_vinyl_comp_t are AVX-2 friendly, it is possible
   to SIMD accelerate producers and consumers (also similar to
   fd_tango). */

/* FIXME: consider making comp_cnt a compile time constant? */

#define FD_VINYL_CQ_MAGIC (0xfd3a7352dc03a6c0UL) /* fd warm snd cq magc version 0 */

struct __attribute__((aligned(128))) fd_vinyl_cq_private {

  ulong magic;    /* ==FD_VINYL_CQ_MAGIC */
  ulong comp_cnt; /* Number of completions that can be in flight on this cq at any given time, power of 2 of least 4 */
  uchar _[ 112 ]; /* Put seq on a separate cache line pair */
  ulong seq;      /* Completion sequence number to publish next */
  /* padding to 128 alignment */
  /* fd_vinyl_comp_t comp[ comp_cnt ] here, seq number at idx = seq & (comp_cnt-1UL) when available */
  /* padding to 128 alignment */

};

typedef struct fd_vinyl_cq_private fd_vinyl_cq_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_cq_{align,footprint,new,join,leave_delete} have the usual
   interprocess shared persistent memory object semantics.  comp_cnt is
   a power-of-2 of at least 4 that gives the number completions that can
   be in flight on this cq. */

FD_FN_CONST ulong fd_vinyl_cq_align    ( void );
FD_FN_CONST ulong fd_vinyl_cq_footprint( ulong comp_cnt );
void *            fd_vinyl_cq_new      ( void * shmem, ulong comp_cnt );
fd_vinyl_cq_t *   fd_vinyl_cq_join     ( void * shcq );
void *            fd_vinyl_cq_leave    ( fd_vinyl_cq_t * cq );
void *            fd_vinyl_cq_delete   ( void * shcq );

/* fd_vinyl_cq_comp returns the location in the caller's address space
   of the cq's completion array.  fd_vinyl_cq_comp_const is a const
   correct version.  fd_vinyl_cq_comp_cnt is the size of this array.
   The lifetime of the returned array is the lifetime of the local join.
   These assume cq is a current local join.

   fd_vinyl_cq_comp_idx gives the array index that will cache completion
   seq in a cq completion array with comp_cnt elements. */

FD_FN_CONST static inline fd_vinyl_comp_t *
fd_vinyl_cq_comp( fd_vinyl_cq_t * cq ) {
  return (fd_vinyl_comp_t *)(cq+1);
}

FD_FN_CONST static inline fd_vinyl_comp_t const *
fd_vinyl_cq_comp_const( fd_vinyl_cq_t const * cq ) {
  return (fd_vinyl_comp_t const *)(cq+1);
}

FD_FN_PURE static inline ulong fd_vinyl_cq_comp_cnt( fd_vinyl_cq_t const * cq ) { return cq->comp_cnt; }

FD_FN_CONST static inline ulong fd_vinyl_cq_comp_idx( ulong seq, ulong comp_cnt ) { return seq & (comp_cnt-1UL); }

/* fd_vinyl_cq_seq returns the position of the producer's sequence
   number cursor.  Specifically, at some point during the call,
   completions [0,seq) were published, completions (seq,ULONG_MAX] were
   not been published, and completion seq was either published, being
   published or not published.  This is used for initial synchronization
   between producer and consumers.  This is a compiler fence. */

static inline ulong
fd_vinyl_cq_seq( fd_vinyl_cq_t const * cq ) {
  FD_COMPILER_MFENCE();
  ulong seq = cq->seq;
  FD_COMPILER_MFENCE();
  return seq;
}

/* fd_vinyl_cq_send sends a completion.  If comp is non-NULL, the
   completion will be written out-of-band to the location comp (assumes
   comp->seq is not 1 on entry and will set to 1 once the send it done).
   Otherwise, if cq is non-NULL, the completion will be enquened into
   the given cq (assumes cq is a current local join).  If both cq and
   comp are NULL, this is a no-op.  This is a compiler fence. */

/* FIXME: consider SIMD accelerating */

static inline void
fd_vinyl_cq_send( fd_vinyl_cq_t *   cq,
                  fd_vinyl_comp_t * comp,
                  ulong             req_id,
                  ulong             link_id,
                  int               err,          /* In [-2^15,2^15) */
                  ulong             batch_cnt,    /* In [0,2^16)  */
                  ulong             fail_cnt,     /* In [0,2^16) */
                  ulong             quota_rem ) { /* In [0,2^16) */

  ulong stack_seq[1];

  ulong   seq;
  ulong * _seq;

  if( FD_UNLIKELY( comp ) ) { /* Send directly */

    seq  = 1UL;       /* For direct sends, comp->seq should have already been set to something != 1 */
    _seq = stack_seq;

  } else if( FD_LIKELY( cq ) ) { /* Send via cq */

    seq  = cq->seq;
    _seq = &cq->seq;
    comp = fd_vinyl_cq_comp( cq ) + fd_vinyl_cq_comp_idx( seq, cq->comp_cnt );

    FD_COMPILER_MFENCE();
    comp->seq = seq - 1UL; /* Mark completion seq being written */

  } else { /* No place to send completion */

    FD_COMPILER_MFENCE(); /* Consistent semantics in all cases */
    return;

  }

  FD_COMPILER_MFENCE();
  comp->req_id    = req_id;
  comp->link_id   = link_id;
  comp->err       = (short)err;
  comp->batch_cnt = (ushort)batch_cnt;
  comp->fail_cnt  = (ushort)fail_cnt;
  comp->quota_rem = (ushort)quota_rem;
  FD_COMPILER_MFENCE();
  comp->seq = seq; /* Mark completion seq as written */
  FD_COMPILER_MFENCE();
  *_seq = seq + 1UL; /* Record that completions [0,seq) are published */
  FD_COMPILER_MFENCE();

}

/* fd_vinyl_cq_recv receives completion seq from the given cq.  Returns
   0 on success, positive if completion seq has not been published yet
   and negative if the consumer has been overrun by the producer.  On
   return, *dst contains the desired completion on success and is
   clobbered otherwise.  Assumes cq is a current local join and dst is
   valid.  This is a compiler fence. */

/* FIXME: consider SIMD accelerating */

static inline long
fd_vinyl_cq_recv( fd_vinyl_cq_t const * cq,
                  ulong                 seq,
                  fd_vinyl_comp_t *     dst ) {
  fd_vinyl_comp_t const * src = fd_vinyl_cq_comp_const( cq ) + fd_vinyl_cq_comp_idx( seq, cq->comp_cnt );

  FD_COMPILER_MFENCE();
  ulong seq0 = src->seq;
  FD_COMPILER_MFENCE();
  *dst = *src;
  FD_COMPILER_MFENCE();
  ulong seq1 = src->seq;
  FD_COMPILER_MFENCE();

  long diff0 = (long)(seq-seq0);
  long diff1 = (long)(seq-seq1);
  return fd_long_if( !diff0, diff1, diff0 );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_cq_fd_vinyl_cq_h */
