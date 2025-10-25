#ifndef HEADER_fd_src_vinyl_rq_fd_vinyl_rq_h
#define HEADER_fd_src_vinyl_rq_fd_vinyl_rq_h

/* A fd_vinyl_req_t describes a batch request to a vinyl tile.  Batch
   requests from a client are processed in order from that client.  The
   individual items in a batch request can be processed in _any_ order
   (including concurrently).  Thus ...

   IMPORTANT SAFETY TIP!  The client promises that all items in a
   request are logically independent such that they can be safely
   processed in an arbitrary order / in parallel.

   The simplest way to ensure this is to keep all keys in a request
   unique.  That being said, repeated keys in a request will generally
   "do the right thing" in the sense that the result can be interpreted
   as though each item in the request executed in some order (with some
   technical caveats for the advanced optimization of processing batch
   items before receiving a completion).  Batch requests from different
   clients can be arbitrarily interleaved at batch request granularity.

   As such, a batch request executes _atomically_ relative to other
   requests.

   Note though that concurrent meta readers see individual batch items
   complete as they happen.  Specifically, except for "move", individual
   items in a batch complete atomically in whatever order they were
   processed.  (During the move of an individual item for the current
   implementation, there is a brief momment where a concurrent meta
   reader could observe both key_src and key_dst as not present.)
   Similarly clients doing speculative processing will see individual
   batch items complete atomically (including move) in whatever order
   they are being processed (which is the point of speculative
   processing). */

#include "../fd_vinyl_base.h"

/* FD_VINYL_REQ_{ALIGN,FOOTPRINT} give the byte alignment and footprint
   of a fd_vinyl_req_t.  ALIGN is a reasonable power-of-2.  FOOTPRINT is
   a multiple of ALIGN. */

#define FD_VINYL_REQ_ALIGN     (64UL)
#define FD_VINYL_REQ_FOOTPRINT (64UL)

/* FD_VINYL_REQ_TYPE_* give supported request types.  Note that
   requests like JOIN are handled out of band because the client doesn't
   have a rq to send the request until it is joined.  (LEAVE could be
   handled in band though but is handle via the same mechanism as JOIN
   for symmetry.  SYNC and PART requests are also handled out of band as
   they don't pertain to individual clients.) */

#define FD_VINYL_REQ_TYPE_ACQUIRE (0) /* Acquire the requested pairs */
#define FD_VINYL_REQ_TYPE_RELEASE (1) /* Release the requested pairs */
#define FD_VINYL_REQ_TYPE_ERASE   (2) /* Erase   the requested pairs */
#define FD_VINYL_REQ_TYPE_MOVE    (3) /* Move    the requested pairs (replace if dst exists, rename if not) */
#define FD_VINYL_REQ_TYPE_FETCH   (4) /* Fetch   the requested pairs into cache (does not generate a completion) */
#define FD_VINYL_REQ_TYPE_FLUSH   (5) /* Flush   the requested pairs from cache (does not generate a completion) */
#define FD_VINYL_REQ_TYPE_TRY     (6) /* Start to speculatively read (non-blocking) the requested pairs */
#define FD_VINYL_REQ_TYPE_TEST    (7) /* Test for speculation success */

/* FD_VINL_REQ_FLAG_* give flags that specify options for the above
   request types. */

#define FD_VINYL_REQ_FLAG_MODIFY (1UL<<0) /* (Acquire) The client intends to modify the given pairs (info and/or val)
                                             (Release) The client modified          the given pairs (info and/or val) */
#define FD_VINYL_REQ_FLAG_IGNORE (1UL<<1) /* (Acquire) Ignore the existing pair val               (ignored if not MODIFY),
                                             (Release) Cached pair val and/or info were clobbered (ignored if MODIFY or an acquire-for-read FIXME: have acquire-for-read with ignore set flush?) */
#define FD_VINYL_REQ_FLAG_CREATE (1UL<<2) /* (Acquire) Create any pairs that do not already exist (ignored if not MODIFY) */
#define FD_VINYL_REQ_FLAG_EXCL   (1UL<<3) /* (Acquire) Do not modify any pairs that already exist (ignored if not MODIFY) */
#define FD_VINYL_REQ_FLAG_ERASE  (1UL<<4) /* (Release) Erase given pairs                          (ignored if not MODIFY) */
#define FD_VINYL_REQ_FLAG_BY_KEY (1UL<<5) /* (Release) Use keys instead of cache val gaddrs to specify pairs to release */
#define FD_VINYL_REQ_FLAG_MRU    (0UL<<6) /* Make given pairs MRU (note: arb order from MRU->LRU for individual items in batch) */
#define FD_VINYL_REQ_FLAG_LRU    (1UL<<6) /* Make given pairs LRU (note: arb order from LRU->MRU for individual items in batch) */
#define FD_VINYL_REQ_FLAG_UNC    (2UL<<6) /* Do not change eviction priorities for the given pairs */

/* A fd_vinyl_req_t gives the layout of a request */

struct __attribute__((aligned(FD_VINYL_REQ_ALIGN))) fd_vinyl_req {

  ulong  seq;       /* Message sequence number */
  ulong  req_id;    /* Request id (identifies the request for the completion recipients) */
  ulong  link_id;   /* Link id (identifies client -> vinyl tile for request and completion recipients) */
  schar  type;      /* == FD_VINYL_REQ_TYPE_* */
  uchar  flags;     /* Bit-or of FD_VINYL_REQ_FLAG flags */
  ushort batch_cnt; /* Num key-val pairs in request */
  uint   val_max;   /* (acquire with modify) Max byte size pair val, in [0,FD_VINYL_VAL_MAX] */

  /* key_gaddr is typically the shared client request global address of
     a:

       fd_vinyl_key_t key[ batch_cnt ]

     array that contains the set of keys for this batch request.  The
     vinyl tile will typically have a read interest in this region until
     the request is completed.  In particular:

       ACQUIRE - keys to acquire
       RELEASE - (BY_KEY) keys to release, (~BY_KEY) ignored (release ~BY_KEY faster)
       ERASE   - keys to erase
       FETCH   - keys to fetch
       FLUSH   - keys to flush
       MOVE    - src keys to move
       TRY     - keys to speculatively read
       TEST    - ignored

     If there are redundant keys in a batch request, from the caller's
     perspective, the items will appear to executed in some serial
     order.  E.g. in an acquire for modify, the first batch item
     processed for a key will result in either success or a failure and
     the remaining batch items for key will result in either AGAIN
     (because the first item acquired) or failure (because it couldn't
     acquire key for the same reason as first item).

     IMPORTANT SAFETY TIP!  When doing the advanced optimization of
     processing batch items before receiving a completion in a batch
     acquire-for-read or a try, the remaining batch items for key can
     report success before the first batch item for key has finished
     reading, validating and decoding the pair.  See case_acquire for
     more details.

     Note that, for FETCH, evict prio flags are ignored.  The keys will
     always be fetched at MRU priority. */

  ulong key_gaddr;

  /* val_gaddr_gaddr is typically the shared client request global
     address of a:

       ulong val_gaddr[ batch_cnt ]

     array where shared data cache global addresses for pair vals should
     be stored on completion.  The current pair info is also available
     to the client at this location for read / modification.  The vinyl
     tile will have a write interest in this region until the request is
     complete.  On receipt of a successful completion, batch items that
     were successfully processed will have valid entries and batch items
     that failed will have unchanged entries.  On receipt of a failed
     completion, this array will be unchanged.  In particular:

       ACQUIRE - pair val (and pair info) data cache global address
       RELEASE - (BY_KEY) ignored, (~BY_KEY) data cache global addresses
                 of pairs to release (i.e. echo back the array returned
                 by acquire), (release ~BY_KEY faster)
       ERASE   - ignored
       MOVE    - this field is repurposed to point to the batch_cnt dst
                 keys for the move (vinyl tile will have a read interest
                 in this region until the request is complete)
                 (FIXME: consider having key_gaddr be 2*batch_cnt for
                 move, store all the keys there, and ignore this
                 entirely ...  would make sense if it is easier for
                 store move src/dst keys interleaved)
       FETCH   - ignored
       FLUSH   - ignored
       TRY     - pair val (and pair info) data cache global addresses
                 must be a 2*batch_cnt array for try (the second half is
                 for internal use).  Note that the info region
                 (including the val_sz for the try) might be corrupt.
                 The pointer returned though is guaranteed to be
                 readable out to FD_VINYL_VAL_MAX regardless val_sz.
       TEST    - echo back the same array (with an untouched second
                 half) from the corresponding try */

  ulong val_gaddr_gaddr;

  /* err_gaddr is typically the shared client request global address of
     a:

       schar err[ batch_cnt ]

     array where the results of individual batch item executions will be
     stored by the vinyl tile.  The vinyl tile will have a write
     interest in this region until the request is completed.  On receipt
     of a successful completion, the individual entries will be valid.
     Entries will be FD_VINYL_SUCCESS (zero) or a FD_VINYL_ERR code
     (negative).  On receipt of a failed completion, this array is
     unchanged.  In particular:

       ACQUIRE (for read)

         SUCCESS - acquired the corresponding pair key.  The pair val
                   and pair info can be found via the corresponding
                   val_gaddr in the shared data cache.  This location
                   will be stable until the pair is released.  info will
                   have the current pair metadata (including the val
                   byte size), val will have the current pair val.

         AGAIN   - there was a conflicting acquire on pair key, try
                   again after the conflicting acquire has been
                   released.  That is, pair key is currently
                   acquired-for-modify (this includes pair key in the
                   process of being created).

         KEY     - pair key did not exist at bstream seq_present and
                   is not in the process of being created.

       ACQUIRE (for modify)

         SUCCESS - acquired the corresponding pair key.  The pair val
                   and pair info can be found via the corresponding
                   val_gaddr in the shared data cache.  This location
                   will be stable until the pair is released.

                   If pair key exists and ignore was _not_ set, info
                   will contain the current pair metadata (including the
                   val byte size), val contain the current pair val and
                   the val region will be sized to the greater of the
                   current val byte size and the requested max val byte
                   size.

                   If pair key exists and ignore _was_ set, info will
                   contain the _current_ pair metadata (_but_ with a val
                   byte size of 0), val will be empty and the region
                   will be sized to the requested max val byte size.

                   If pair key did not exist, the pair info will be all
                   zeros, val will be empty and the val region will be
                   sized to the requested max val byte size.

         INVAL   - pair key existed and exclusive was set

         KEY     - pair key did not exist and create was not set

         AGAIN   - there was a conflicting acquire on pair, try again
                   after conflicting acquire(s) have been released.
                   That is, pair key is currently acquired-for-read one
                   or more times or acquired-for-modify.

       RELEASE

         SUCCESS - released the corresponding pair key.  The key-val
                   store was updated appropriately.  In particular:

                   When releasing an acquire-for-modify _with_ modify
                   set, the modification "happened" (i.e. is now part of
                   the bstream's past).  This includes creating or
                   erasing a pair.  The cached pair info gave the
                   modified pair info (including the updated pair val
                   byte size).

                   When releasing an acquire-for-modify _without_ modify
                   set, the modification was cancelled.  If the ignore
                   flag _was_set, the vinyl tile assumed the cached info
                   and/or val were clobbered by the client during the
                   acquire.  If the ignore flag was _not_ set, the vinyl
                   tile assumed the client did not alter any pair value
                   or pair info _at_ _any_ _time_ _during_ _the_
                   _acquire_ (such that the cached values and any
                   speculations on those cached values during the
                   acquire were valid).  Note that when releasing an
                   acquire-for-modify-with-ignore, the implicily
                   clobbered the cached pair info val byte size and
                   cached pair val for pairs that had a non-zero val
                   size immediately before the acquire.  Since the
                   client probably didn't know if the val size was zero
                   beforehand, it is strongly recommended that
                   acquire-for-modify-with-ignore only be canceled via a
                   release-with-ignore.

                   TL;DR If client never wrote to the cached pair info
                   or cached pair val on an
                   acquire-for-modify-without-ignore, the modification
                   can be cancelled fast with a release-without-modify.
                   In all other cases, a modification should be
                   cancelled via a release-without-modify-with-ignore.

                   Note that release-with-modify of an acquire-for-read
                   is considered a catastrophe (the client modified data
                   it promised not to change and may have corrupted
                   state of themselves, other clients and the store
                   itself).  Overrunning pair cache storage (the client
                   set the pair info val_sz to something larger than the
                   acquire-with-modify val_max) is also treated as a
                   catastrophe for similar reasons.

         INVAL   - the corresponding key (BY_KEY) / val (~BY_KEY) did
                   not appear to be to an acquired pair

       ERASE

         SUCCESS - the corresponding key was erased

         KEY     - the corresponding key did not exist

         AGAIN   - corresponding key is currently acquired for something
                   (including read, modify or create), try again after
                   conflicting acquires have been released

       MOVE

         SUCCESS - the corresponding src_key was renamed to the
                   corresponding dst_key.  If dst_key existed before the
                   move, it was atomically erased before renaming pair
                   src_key.  The new pair dst_key has the pair info and
                   pair val of the old pair src_key.

                   Note that a move from src_key to src_key is treated
                   as a no-op that immediately succeeds (with no
                   checking, for example, whether or not src_key even
                   exists).

         KEY     - the corresponding src_key did not exist

         AGAIN   - there was at least one conflicting acquire on src_key
                   and/or dst_key.  Try again after the conflicting
                   acquires have been released.

       FETCH - ignored

       FLUSH - ignored

       TRY

         SUCCESS - the client is clear to try a speculative
                   (non-blocking) read of the corresponding key.  The
                   key was located in the data cache region at the given
                   val_gaddr at the start of the try.

         KEY     - the corresponding key did not exist to try

         AGAIN   - the corresponding key was acquired-for-modify
                   (includes create), try again after conflicting
                   acquires have been released

       TEST

         SUCCESS - the speculative read was successful

         INVAL   - the corresponding try never started (i.e. try failed
                   with KEY or AGAIN)

         CORRUPT - the corresponding try failed (i.e. the pair was
                   potentially changed during the speculation)

     If these are set to a positive number before sending the request,
     the caller can detect individual items as they finish processing
     (and then access the pair val and pair info via the corresponding
     val_gaddr on success) before receiving the completion (with some
     caveats for requests with redundant keys described in
     case_acquire). */

  ulong err_gaddr;

  /* comp_gaddr gives the shared client request gaddr of a:

       fd_vinyl_comp_t comp[ 1 ]

     or zero.

     If non-zero, the completion information will be written into comp
     (with comp->seq set to 1 last).  If not, the completion will be
     sent to the completion queue registered to the client for this
     vinyl tile (and if no completion queue was registered, no
     completion will be sent ... which is not a recommended mode of
     operations).

     If a completion was successful, err will be FD_VINYL_SUCCESS (0),
     batch_cnt will match the request batch_cnt, fail_cnt will give the
     number of individual items in the batch that failed (in
     [0,batch_cnt]), and quota_rem will give the remaining client
     acquire quota (each successful acquire/release
     decrements/increments the client's remaining quota by 1 all other
     operations do not impact the client's quota).

     If a completion has an error, err will be a FD_VINYL_ERR code
     (negative).  No processing of any items in the batch was done,
     batch_cnt will match the request batch_cnt, fail_cnt will be zero
     and quota_rem will give the remaining client acquire quota
     (unchanged).  Reasons for a completion error are:

       INVAL - one or more input arrays were unmappable (i.e. not a
               valid global address in the shared client request memory
               region) or this was a modify request with a requested val
               byte size larger than FD_VINYL_VAL_MAX.

       FULL  - client acquire quota remaining is too low to process this
               request fully (ACQUIRE only)

     FETCH and FLUSH requests do not produce completions. */

  ulong  comp_gaddr;
};

typedef struct fd_vinyl_req fd_vinyl_req_t;

/* A fd_vinyl_rq_t is an interprocess shared persistent SPMC queue
   used to communicate fd_vinyl_req_t requests from a client to vinyl
   tiles.  It is virtually identically to fd_vinyl_cq_t but holds
   fd_vinyl_req_t instead of fd_vinyl_comp_t.  See fd_vinyl_cq_t for
   concurrency and flow control details. */

#define FD_VINYL_RQ_MAGIC (0xfd3a7352d703a6c0UL) /* fd warm snd rq magc version 0 */

struct __attribute__((aligned(128))) fd_vinyl_rq_private {

  ulong magic;    /* ==FD_VINYL_RQ_MAGIC */
  ulong req_cnt;  /* Number of requests that can be in flight on this cq at any given time, power of 2 of least 4 */
  uchar _[ 112 ]; /* Padding to put seq on a separate cache line pair */
  ulong seq;      /* Request sequence number to publish next */

  /* padding to 128 alignment */

  /* fd_vinyl_req_t req[ req_cnt ] here, seq number at idx = seq & (req_cnt-1UL) when available */

  /* padding to 128 alignment */

};

typedef struct fd_vinyl_rq_private fd_vinyl_rq_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_req_{flag_*,evict_prio} extract the {given flag,eviction
   priority} from a fd_vinyl_req_t flags field. */

FD_FN_CONST static inline int fd_vinyl_req_flag_modify( ulong flags ) { return !!(flags & FD_VINYL_REQ_FLAG_MODIFY); }
FD_FN_CONST static inline int fd_vinyl_req_flag_ignore( ulong flags ) { return !!(flags & FD_VINYL_REQ_FLAG_IGNORE); }
FD_FN_CONST static inline int fd_vinyl_req_flag_create( ulong flags ) { return !!(flags & FD_VINYL_REQ_FLAG_CREATE); }
FD_FN_CONST static inline int fd_vinyl_req_flag_excl  ( ulong flags ) { return !!(flags & FD_VINYL_REQ_FLAG_EXCL  ); }
FD_FN_CONST static inline int fd_vinyl_req_flag_erase ( ulong flags ) { return !!(flags & FD_VINYL_REQ_FLAG_ERASE);  }
FD_FN_CONST static inline int fd_vinyl_req_flag_by_key( ulong flags ) { return !!(flags & FD_VINYL_REQ_FLAG_BY_KEY); }
FD_FN_CONST static inline int fd_vinyl_req_evict_prio ( ulong flags ) { return (int)((flags >> 6) & 3UL);            }

/* fd_vinyl_rq_{align,footprint,new,join,leave_delete} have the usual
   interprocess shared persistent object semantics.  req_cnt is a
   power-of-2 of at least 4 that gives the number requests that can be
   in flight on this rq. */

FD_FN_CONST ulong fd_vinyl_rq_align    ( void );
FD_FN_CONST ulong fd_vinyl_rq_footprint( ulong req_cnt );
void *            fd_vinyl_rq_new      ( void * shmem, ulong req_cnt );
fd_vinyl_rq_t *   fd_vinyl_rq_join     ( void * shrq );
void *            fd_vinyl_rq_leave    ( fd_vinyl_rq_t * rq );
void *            fd_vinyl_rq_delete   ( void * shrq );

/* fd_vinyl_rq_req returns the location in the caller's address space of
   the rq's request array.  fd_vinyl_rq_req_const is a const correct
   version.  fd_vinyl_rq_req_cnt is the size of this array.  The
   lifetime of the returned array is the lifetime of the local join.
   These assume rq is a current local join.

   fd_vinyl_rq_req_idx gives the array index that will cache request seq
   in a rq request array with req_cnt elements. */

FD_FN_CONST static inline fd_vinyl_req_t *
fd_vinyl_rq_req( fd_vinyl_rq_t * rq ) {
  return (fd_vinyl_req_t *)(rq+1);
}

FD_FN_CONST static inline fd_vinyl_req_t const *
fd_vinyl_rq_req_const( fd_vinyl_rq_t const * rq ) {
  return (fd_vinyl_req_t const *)(rq+1);
}

FD_FN_PURE static inline ulong fd_vinyl_rq_req_cnt( fd_vinyl_rq_t const * rq ) { return rq->req_cnt; }

FD_FN_CONST static inline ulong fd_vinyl_rq_req_idx( ulong seq, ulong req_cnt ) { return seq & (req_cnt-1UL); }

/* fd_vinyl_rq_seq returns the position of the request producer's
   sequence number cursor.  Specifically, at some point during the call,
   requests [0,seq) were published, requests (seq,ULONG_MAX] were not
   published, and request seq was either published, being published or
   not published.  This is used for initial synchronization between
   producer and consumers.  This is a compiler fence. */

static inline ulong
fd_vinyl_rq_seq( fd_vinyl_rq_t const * rq ) {
  FD_COMPILER_MFENCE();
  ulong seq = rq->seq;
  FD_COMPILER_MFENCE();
  return seq;
}

/* fd_vinyl_rq_send enqueues the given request into the given rq.
   Assumes rq is a current local join.  This is a compiler fence. */

/* FIXME: consider SIMD accelerating */

static inline void
fd_vinyl_rq_send( fd_vinyl_rq_t * rq,
                  ulong           req_id,
                  ulong           link_id,
                  int             type,            /* In [-2^7,2^7) */
                  ulong           flags,           /* In [0,2^8)  */
                  ulong           batch_cnt,       /* In [0,2^16) */
                  ulong           val_max,
                  ulong           key_gaddr,
                  ulong           val_gaddr_gaddr,
                  ulong           err_gaddr,
                  ulong           comp_gaddr ) {
  ulong            seq = rq->seq;
  fd_vinyl_req_t * req = fd_vinyl_rq_req( rq ) + fd_vinyl_rq_req_idx( seq, rq->req_cnt );
  FD_COMPILER_MFENCE();
  req->seq             = seq - 1UL; /* Mark request seq being written */
  FD_COMPILER_MFENCE();
  req->req_id          = req_id;
  req->link_id         = link_id;
  req->type            = (schar)type;
  req->flags           = (uchar)flags;
  req->batch_cnt       = (ushort)batch_cnt;
  req->val_max         = (uint)val_max;
  req->key_gaddr       = key_gaddr;
  req->val_gaddr_gaddr = val_gaddr_gaddr;
  req->err_gaddr       = err_gaddr;
  req->comp_gaddr      = comp_gaddr;
  FD_COMPILER_MFENCE();
  req->seq             = seq; /* Mark request seq as written */
  FD_COMPILER_MFENCE();
  rq->seq              = seq + 1UL; /* Record that requests [0,seq) are published */
  FD_COMPILER_MFENCE();
}

/* fd_vinyl_rq_recv receives request seq from the given rq.  Returns 0
   on success, positive if request seq has not been published yet and
   negative if the consumer has been overrun by the producer.  On
   return, *dst will contain the desired request on success and was
   clobbered otherwise.  Assumes rq is a current local join and dst is
   valid.  This is a compiler fence. */

/* FIXME: consider SIMD accelerating */

static inline long
fd_vinyl_rq_recv( fd_vinyl_rq_t const * rq,
                  ulong                 seq,
                  fd_vinyl_req_t *      dst ) {
  fd_vinyl_req_t const * src = fd_vinyl_rq_req_const( rq ) + fd_vinyl_rq_req_idx( seq, rq->req_cnt );

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

#endif /* HEADER_fd_src_vinyl_rq_fd_vinyl_rq_h */
