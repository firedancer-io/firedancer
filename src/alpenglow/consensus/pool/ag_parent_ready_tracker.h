#ifndef HEADER_fd_src_alpenglow_consensus_pool_ag_parent_ready_tracker_h
#define HEADER_fd_src_alpenglow_consensus_pool_ag_parent_ready_tracker_h

#include "../../ag_alpenglow_base.h"
#include "ag_finality_tracker.h" /* ag_finalization_event_t */
#include "parent_ready_tracker/ag_parent_ready_state.h"

struct ag_parent_ready {
  ulong         slot;
  ag_block_id_t parent;
};
typedef struct ag_parent_ready ag_parent_ready_t;

/* How many parents one slot can newly ready, so the tracker's answer
   buffer is AG_PARENT_READY_PER_SLOT*slot_max and cannot overflow -- the
   same shape as the pool's event channel, and for the same reason a flat
   cap was wrong there: a long skip run readies parents at every window
   start it crosses, so the count scales with the tracked window, not with
   a constant.

   A window start takes one entry per parent it is handed, and what it can
   be handed is what the window below it holds: AG_SLOTS_PER_WINDOW slots,
   each with at most AG_PARENT_READY_STATE_CAP notar-fallback blocks and
   AG_PARENT_READY_STATE_CAP ready ids.  Spread back over the slots that
   produced them that is 2*AG_PARENT_READY_STATE_CAP apiece.

   TODO: a ceiling, not a tight bound -- the same caveat AG_POOL_EVENTS_PER_SLOT
   carries. */

#define AG_PARENT_READY_PER_SLOT (2UL*AG_PARENT_READY_STATE_CAP)

struct ag_parent_ready_tracker;
typedef struct ag_parent_ready_tracker ag_parent_ready_tracker_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_parent_ready_tracker_align( void );

FD_FN_CONST ulong
ag_parent_ready_tracker_footprint( ulong slot_max );

void *
ag_parent_ready_tracker_new( void * shmem,
                             ulong  slot_max,
                             ulong  seed );

ag_parent_ready_tracker_t *
ag_parent_ready_tracker_join( void * shtracker );

void *
ag_parent_ready_tracker_leave( ag_parent_ready_tracker_t const * tracker );

void *
ag_parent_ready_tracker_delete( void * shtracker );

/* ag_parent_ready_tracker_root is the slot the tracker's window starts at:
   everything below it has been shed.  prune sets it, and an owner sweeping
   its own per-slot state alongside reads it to find where the last sweep
   stopped. */

FD_FN_PURE ulong
ag_parent_ready_tracker_root( ag_parent_ready_tracker_t const * self );

/* The two mark_* calls answer with the parents they made newly ready.  The
   array is the tracker's own, not the caller's: its length is a function of
   slot_max, so a caller cannot size one on the stack.  It is borrowed --
   valid until the next call that writes it, which is long enough to walk it
   and nothing more, so a caller that needs it to outlive that copies. */

ag_parent_ready_t const *
ag_parent_ready_tracker_mark_notar_fallback( ag_parent_ready_tracker_t * self,
                                             ag_block_id_t const *       id,
                                             ulong *                     cnt );

ag_parent_ready_t const *
ag_parent_ready_tracker_mark_skipped( ag_parent_ready_tracker_t * self,
                                      ulong                       marked_slot,
                                      ulong *                     cnt );

/* ag_parent_ready_tracker_handle_finalization applies one finality
   tracker verdict -- whatever ag_finality_tracker_mark_* just returned --
   and reports the parent that became newly ready.  At most one parent can
   become ready per call, so the return value is the whole answer: a
   ag_parent_ready_t whose slot is ULONG_MAX means none did, the same
   Option::None the slot states spell that way. */

ag_parent_ready_t
ag_parent_ready_tracker_handle_finalization( ag_parent_ready_tracker_t *     self,
                                             ag_finalization_event_t const * event );

ag_block_id_t const *
ag_parent_ready_tracker_parents_ready( ag_parent_ready_tracker_t * self,
                                       ulong                       slot,
                                       ulong *                     cnt );

int
ag_parent_ready_tracker_wait_for_parent_ready( ag_parent_ready_tracker_t * self,
                                               ulong                       slot,
                                               ag_block_id_t *             out_id );

void
ag_parent_ready_tracker_prune( ag_parent_ready_tracker_t * self,
                               ulong                       new_root );

FD_PROTOTYPES_END

#endif
