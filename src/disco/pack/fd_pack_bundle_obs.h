#ifndef HEADER_fd_src_disco_pack_fd_pack_bundle_obs_h
#define HEADER_fd_src_disco_pack_fd_pack_bundle_obs_h

/* fd_pack_bundle_obs ("bobs") follows each bundle through the pack
   tile so that every bundle that did not land can be attributed to
   exactly one cause, together with the tip it would have paid.  It is
   pure bookkeeping: it never influences scheduling.

   It has three parts:

   - Blocked-time accounting.  While we are leader and bundles are
     pending, the pack tile calls fd_pack_bobs_charge on every
     scheduling pass with the reason the head bundle could not be
     scheduled (or FD_PACK_BOBS_REASON_NONE).  The time since the
     previous call is charged to the previous reason, in monotonic
     per-reason counters.  Each observation snapshots the counters when
     the bundle arrives, so the difference when it finishes is the
     reason mix during its wait.  This attributes head-of-line blocking
     to every bundle queued behind the head too.

   - An observation pool.  One element per bundle, indexed while the
     bundle is pending by pack's index of its first transaction (see
     fd_pack_txn_idx), and after it is scheduled by an observation id
     that the execle echoes back with the outcome.

   - Pure classification helpers for the arrival phase and the final
     cause. */

#include "fd_pack.h"

/* Leader rotations are this many consecutive slots, aligned to
   multiples of it (see FD_EPOCH_SLOTS_PER_ROTATION). */

#define FD_PACK_BOBS_SLOTS_PER_ROTATION (4UL)

/* Blocked reasons.  The order matches the BundleBlockedReason metrics
   enum. */

#define FD_PACK_BOBS_REASON_NONE             (-1)
#define FD_PACK_BOBS_REASON_LANE_VOTE        0 /* bundle lane busy with a vote microblock */
#define FD_PACK_BOBS_REASON_LANE_TXN         1 /* bundle lane busy with a normal transaction */
#define FD_PACK_BOBS_REASON_LANE_BUNDLE      2 /* bundle lane busy with another bundle */
#define FD_PACK_BOBS_REASON_VOTE_PREEMPT     3 /* lane idle but votes took the microblock */
#define FD_PACK_BOBS_REASON_IB_NOT_READY     4 /* waiting on the initializer bundle */
#define FD_PACK_BOBS_REASON_CONFLICT_TPU     5 /* head conflicts with in-flight normal transactions */
#define FD_PACK_BOBS_REASON_CONFLICT_BUNDLE  6 /* head conflicts with an in-flight bundle */
#define FD_PACK_BOBS_REASON_CONFLICT_VOTE    7 /* head conflicts with in-flight votes */
#define FD_PACK_BOBS_REASON_DOES_NOT_FIT     8 /* block limits */
#define FD_PACK_BOBS_REASON_CNT              9

/* Final causes.  The order matches the BundleOutcome metrics enum. */

#define FD_PACK_BOBS_CAUSE_LANDED            0
#define FD_PACK_BOBS_CAUSE_REJECTED          1
#define FD_PACK_BOBS_CAUSE_PARTIAL           2
#define FD_PACK_BOBS_CAUSE_EXEC_STATE_TPU    3
#define FD_PACK_BOBS_CAUSE_EXEC_STATE_BUNDLE 4
#define FD_PACK_BOBS_CAUSE_EXEC_STATE_OTHER  5
#define FD_PACK_BOBS_CAUSE_EXEC_DUPLICATE    6
#define FD_PACK_BOBS_CAUSE_EXEC_OTHER        7
#define FD_PACK_BOBS_CAUSE_EXEC_UNKNOWN      8
#define FD_PACK_BOBS_CAUSE_DUP_DELETED       9
#define FD_PACK_BOBS_CAUSE_BLOCKED_BASE     10 /* + FD_PACK_BOBS_REASON_* */
#define FD_PACK_BOBS_CAUSE_LATE             19
#define FD_PACK_BOBS_CAUSE_EXPIRED          20
#define FD_PACK_BOBS_CAUSE_EVICTED          21
#define FD_PACK_BOBS_CAUSE_CNT              22

FD_STATIC_ASSERT( FD_PACK_BOBS_CAUSE_BLOCKED_BASE+FD_PACK_BOBS_REASON_CNT==FD_PACK_BOBS_CAUSE_LATE, bobs_cause );

/* Arrival phases.  The order matches the phase part of the
   BundleArrivalResult metrics enum. */

#define FD_PACK_BOBS_PHASE_BEFORE_WINDOW 0 /* not leader, our next slot has not started */
#define FD_PACK_BOBS_PHASE_EARLY         1 /* first third of a leader slot (or between two of our slots) */
#define FD_PACK_BOBS_PHASE_MID           2
#define FD_PACK_BOBS_PHASE_LATE          3
#define FD_PACK_BOBS_PHASE_AFTER_WINDOW  4 /* not leader, just after the last slot of our rotation */
#define FD_PACK_BOBS_PHASE_CNT           5

/* Execution error kinds, as mapped by the pack tile from the execle's
   transaction error. */

#define FD_PACK_BOBS_EXEC_ERR_INSTRUCTION 1 /* instruction error: typically state changed since simulation */
#define FD_PACK_BOBS_EXEC_ERR_DUPLICATE   2 /* already processed, or nonce already advanced */
#define FD_PACK_BOBS_EXEC_ERR_OTHER       3
#define FD_PACK_BOBS_EXEC_ERR_UNKNOWN     4 /* no outcome was reported */

/* Observation states */

#define FD_PACK_BOBS_STATE_FREE      0
#define FD_PACK_BOBS_STATE_PENDING   1 /* in pack */
#define FD_PACK_BOBS_STATE_SCHEDULED 2 /* sent to an execle, awaiting its outcome */

struct fd_pack_bobs_ele {
  ulong gen;                /* incremented on every acquire, part of the obs id */
  int   state;              /* FD_PACK_BOBS_STATE_* */
  ulong pack_idx;           /* while PENDING: pack index of the first transaction */
  ulong prev_sched;         /* while SCHEDULED: doubly linked list, oldest first */
  ulong next_sched;

  ulong sig8[ FD_PACK_MAX_TXN_PER_BUNDLE ]; /* first 8 signature bytes of each transaction */
  ulong txn_cnt;

  long  arrival_ns;         /* when the validator received the bundle */
  long  slot_start_ns;      /* pack start of the slot current at, or first after, arrival; 0 if none yet */
  int   phase;              /* FD_PACK_BOBS_PHASE_* */
  ulong static_tip;         /* lamports */

  /* The blocked counters when the bundle arrived; once scheduled
     (wait_frozen), the blocked time during its wait instead. */
  ulong blocked_snap[ FD_PACK_BOBS_REASON_CNT ];
  int   wait_frozen;

  long  sched_ns;           /* 0 if never scheduled */
  ulong interference;       /* info from the bundle leave callback */
};
typedef struct fd_pack_bobs_ele fd_pack_bobs_ele_t;

struct fd_pack_bobs;
typedef struct fd_pack_bobs fd_pack_bobs_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong fd_pack_bobs_align    ( void );
FD_FN_CONST ulong fd_pack_bobs_footprint( ulong ele_max, ulong pack_idx_max );

void *           fd_pack_bobs_new ( void * mem, ulong ele_max, ulong pack_idx_max );
fd_pack_bobs_t * fd_pack_bobs_join( void * mem );

/* fd_pack_bobs_charge charges the time since the previous call to the
   previous call's reason (nothing if it was
   FD_PACK_BOBS_REASON_NONE), then remembers reason.  now is in any
   monotonic time unit (the pack tile uses ticks); a now earlier than
   a previous call's charges nothing. */

void fd_pack_bobs_charge( fd_pack_bobs_t * bobs, long now, int reason );

/* fd_pack_bobs_flush charges the time up to now to the current reason
   without changing it. */

void fd_pack_bobs_flush( fd_pack_bobs_t * bobs, long now );

/* fd_pack_bobs_blocked returns the cumulative blocked time per reason,
   indexed by FD_PACK_BOBS_REASON_*. */

ulong const * fd_pack_bobs_blocked( fd_pack_bobs_t const * bobs );

/* fd_pack_bobs_acquire returns a zeroed element with the blocked
   counters snapshotted, or NULL if the pool is full. */

fd_pack_bobs_ele_t * fd_pack_bobs_acquire( fd_pack_bobs_t * bobs );

/* fd_pack_bobs_register indexes a PENDING ele by pack_idx, which must
   be < pack_idx_max and not already registered. */

void fd_pack_bobs_register( fd_pack_bobs_t * bobs, fd_pack_bobs_ele_t * ele, ulong pack_idx );

/* fd_pack_bobs_query returns the PENDING element registered at
   pack_idx, or NULL. */

fd_pack_bobs_ele_t * fd_pack_bobs_query( fd_pack_bobs_t * bobs, ulong pack_idx );

/* fd_pack_bobs_id returns the observation id of ele, which is stable
   from acquire to release and never 0. */

ulong fd_pack_bobs_id( fd_pack_bobs_t const * bobs, fd_pack_bobs_ele_t const * ele );

/* fd_pack_bobs_scheduled unregisters a PENDING ele and moves it to the
   SCHEDULED list (newest at the tail), and freezes its blocked time
   (see fd_pack_bobs_delta).  Returns its obs id. */

ulong fd_pack_bobs_scheduled( fd_pack_bobs_t * bobs, fd_pack_bobs_ele_t * ele );

/* fd_pack_bobs_query_id returns the live (PENDING or SCHEDULED) element
   with obs id id, or NULL (stale, unknown or 0). */

fd_pack_bobs_ele_t * fd_pack_bobs_query_id( fd_pack_bobs_t * bobs, ulong id );

/* fd_pack_bobs_oldest_scheduled returns the SCHEDULED element that was
   scheduled earliest, or NULL. */

fd_pack_bobs_ele_t * fd_pack_bobs_oldest_scheduled( fd_pack_bobs_t * bobs );

/* fd_pack_bobs_release unregisters (if PENDING) or unlinks (if
   SCHEDULED) ele and returns it to the pool. */

void fd_pack_bobs_release( fd_pack_bobs_t * bobs, fd_pack_bobs_ele_t * ele );

ulong fd_pack_bobs_used( fd_pack_bobs_t const * bobs );

/* fd_pack_bobs_delta computes, for ele, the blocked time per reason
   during its wait into out (indexed by FD_PACK_BOBS_REASON_*): from
   when it arrived until it was scheduled, or until now if it has not
   been.  Call fd_pack_bobs_flush first to include time up to now. */

void fd_pack_bobs_delta( fd_pack_bobs_t const * bobs, fd_pack_bobs_ele_t const * ele, ulong out[ static FD_PACK_BOBS_REASON_CNT ] );

/* fd_pack_bobs_phase classifies an arrival at time arrival.  If
   is_leader, slot_start and slot_end bound the current leader slot's
   pack window.  Otherwise, last_end is when our last leader slot's
   pack window ended (0 if never), last_slot that slot (ULONG_MAX if
   never), and slot_dur a slot duration.  All times are in the same
   units. */

int
fd_pack_bobs_phase( long  arrival,
                    int   is_leader,
                    long  slot_start,
                    long  slot_end,
                    long  last_end,
                    ulong last_slot,
                    long  slot_dur );

/* fd_pack_bobs_cause_exec returns the cause for a scheduled bundle.
   landed is non-zero if it landed; otherwise err_kind is one of
   FD_PACK_BOBS_EXEC_ERR_*.  interference is the leave callback info. */

int
fd_pack_bobs_cause_exec( int   landed,
                         int   err_kind,
                         ulong interference );

/* fd_pack_bobs_cause_unscheduled returns the cause for a bundle that
   left pack without being scheduled.  leave_reason is one of
   FD_PACK_BUNDLE_LEAVE_* (not SCHEDULED), delta the blocked time
   during its wait, phase its arrival phase. */

int
fd_pack_bobs_cause_unscheduled( int         leave_reason,
                                ulong const delta[ static FD_PACK_BOBS_REASON_CNT ],
                                int         phase );

/* fd_pack_bobs_cause_is_missed returns 1 if the cause counts as missed
   revenue: not landed, and not lost to a competing bundle or to a copy
   that landed elsewhere. */

FD_FN_CONST static inline int
fd_pack_bobs_cause_is_missed( int cause ) {
  return (cause!=FD_PACK_BOBS_CAUSE_LANDED) &
         (cause!=FD_PACK_BOBS_CAUSE_EXEC_STATE_BUNDLE) &
         (cause!=FD_PACK_BOBS_CAUSE_DUP_DELETED);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_pack_fd_pack_bundle_obs_h */
