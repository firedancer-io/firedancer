#ifndef HEADER_fd_src_alpenglow_consensus_pool_fd_parent_ready_tracker_h
#define HEADER_fd_src_alpenglow_consensus_pool_fd_parent_ready_tracker_h

/* fd_parent_ready_tracker mirrors
   alpenglow/src/consensus/pool/parent_ready_tracker.rs.

   It tracks the parent-ready condition across slots.

   The parent-ready condition pertains to a slot `s` and a block hash
   hash(b), where `s` is the first slot of a leader window and s > slot(b).
   Specifically, it is defined as the following:
     - Block b is notarized or notarized-fallback, AND
     - slots slot(b)+1 (inclusive) to s (non-inclusive) are skip-certified.

   Additional restrictions on notarization votes ensure that the parent-
   ready condition holds for a block b only if it also holds for all
   ancestors of b.  Together this ensures that the block b is a valid
   parent for block production.

   This is a relocatable wksp object owning a fd_pool of per-slot
   fd_parent_ready_state_t elements indexed by a fd_map_chain keyed by
   slot, following the canonical fd_ghost layout: an
   __attribute__((aligned(128UL))) top struct holding only ulong gaddrs,
   with align/footprint/new/join/leave/delete and the
   FD_SCRATCH_ALLOC_INIT/APPEND/FINI layout.

   Methods mirror the Rust ParentReadyTracker:
     - mark_notar_fallback(id)       -> newly connected parents
     - mark_skipped(slot)            -> newly connected parents
     - handle_finalization(...)      -> at most one (highest-slot) parent
     - parents_ready(slot)           -> list of valid parents (no creation)
     - wait_for_parent_ready(slot)   -> 1 + out parent, else 0 (synchronous)
     - prune(new_root)               -> drop slots < new_root
     - slot_state(slot)              -> lazily creating per-slot state

   The Rust mark_notar_fallback / mark_skipped / handle_finalization
   return SmallVec<[(Slot,BlockId);1]>.  In C the caller provides an out
   buffer of fd_parent_ready_t and a count pointer.  Each entry pairs a
   newly-ready parent block id with the window-start slot it is a valid
   parent for. */

#include "../../fd_alpenglow_base.h"
#include "parent_ready_tracker/fd_parent_ready_state.h"

/* fd_parent_ready_t mirrors the Rust (Slot, BlockId) tuple returned by
   the mark / handle_finalization methods: a newly-ready parent block id
   paired with the (window-start) slot it has become a valid parent for. */

struct fd_parent_ready {
  ulong         slot;   /* window-start slot the parent has become ready for */
  fd_block_id_t parent; /* the parent block id */
};
typedef struct fd_parent_ready fd_parent_ready_t;

/* FD_PARENT_READY_OUT_MAX bounds the size of the caller-provided out
   buffer for the mark / handle_finalization methods.  A single
   mark_notar_fallback or mark_skipped call can connect a parent to at
   most one window per traversed slot, bounded by slot_max; in practice
   the list is tiny (the Rust SmallVec inline size is 1).  Callers should
   size their out buffer at least this large for safety. */

#define FD_PARENT_READY_OUT_MAX (64UL)

struct fd_parent_ready_tracker;
typedef struct fd_parent_ready_tracker fd_parent_ready_tracker_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_parent_ready_tracker_{align,footprint} return the required
   alignment and footprint of a memory region suitable for use as a
   tracker holding per-slot state for up to slot_max distinct slots. */

FD_FN_CONST ulong
fd_parent_ready_tracker_align( void );

FD_FN_CONST ulong
fd_parent_ready_tracker_footprint( ulong slot_max );

/* fd_parent_ready_tracker_new formats an unused memory region for use as
   a tracker.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment.  The tracker
   starts empty (no slot state, root = genesis slot 0).  Use
   fd_parent_ready_tracker_default to additionally seed the genesis
   state, mirroring the Rust Default impl. */

void *
fd_parent_ready_tracker_new( void * shmem,
                             ulong  slot_max,
                             ulong  seed );

/* fd_parent_ready_tracker_join joins the caller to the tracker.  Returns
   a pointer in the local address space on success. */

fd_parent_ready_tracker_t *
fd_parent_ready_tracker_join( void * shtracker );

/* fd_parent_ready_tracker_leave leaves a current local join.  Returns
   the underlying shared memory region on success, NULL on failure. */

void *
fd_parent_ready_tracker_leave( fd_parent_ready_tracker_t const * tracker );

/* fd_parent_ready_tracker_delete unformats a memory region used as a
   tracker.  Returns the underlying shared memory region. */

void *
fd_parent_ready_tracker_delete( void * shtracker );

/* fd_parent_ready_tracker_default seeds an already new+join'd tracker
   with the genesis state, mirroring the Rust Default impl: the genesis
   block is initially the only notarized-fallback, and root = genesis
   slot 0.  Returns tracker.  Idempotent only on a freshly new'd tracker. */

fd_parent_ready_tracker_t *
fd_parent_ready_tracker_default( fd_parent_ready_tracker_t * tracker );

/* Accessors */

/* fd_parent_ready_tracker_root returns the lowest slot still tracked;
   everything below it has been pruned. */

FD_FN_PURE ulong
fd_parent_ready_tracker_root( fd_parent_ready_tracker_t const * tracker );

/* Operations */

/* fd_parent_ready_tracker_mark_notar_fallback marks the block keyed by
   id as notarized-fallback.  Writes any newly connected parents to the
   out buffer (each having id as the parent) and writes the count to
   *out_cnt.  Mirrors ParentReadyTracker::mark_notar_fallback.

   out must point to a buffer of at least FD_PARENT_READY_OUT_MAX
   fd_parent_ready_t entries. */

void
fd_parent_ready_tracker_mark_notar_fallback( fd_parent_ready_tracker_t * tracker,
                                             fd_block_id_t const *       id,
                                             fd_parent_ready_t *         out,
                                             ulong *                     out_cnt );

/* fd_parent_ready_tracker_mark_skipped marks marked_slot as skipped.
   Writes any newly connected parents to the out buffer and the count to
   *out_cnt.  Mirrors ParentReadyTracker::mark_skipped.

   out must point to a buffer of at least FD_PARENT_READY_OUT_MAX
   fd_parent_ready_t entries. */

void
fd_parent_ready_tracker_mark_skipped( fd_parent_ready_tracker_t * tracker,
                                      ulong                       marked_slot,
                                      fd_parent_ready_t *         out,
                                      ulong *                     out_cnt );

/* fd_parent_ready_tracker_handle_finalization handles a finalization
   event, decomposed into:
     - has_finalized / finalized      : the explicitly finalized block (if any)
     - implicitly_finalized / if_cnt  : blocks implicitly finalized (marked notar-fallback)
     - implicitly_skipped   / is_cnt  : slots implicitly skipped (marked skipped)

   Marks blocks as notarized-fallback and slots as skipped as
   appropriate.  Writes at most one newly ready parent (for the highest
   slot) to out and the count (0 or 1) to *out_cnt.  Mirrors
   ParentReadyTracker::handle_finalization.

   out must point to a buffer of at least one fd_parent_ready_t entry. */

void
fd_parent_ready_tracker_handle_finalization( fd_parent_ready_tracker_t * tracker,
                                             int                         has_finalized,
                                             fd_block_id_t const *       finalized,
                                             fd_block_id_t const *       implicitly_finalized,
                                             ulong                       if_cnt,
                                             ulong const *               implicitly_skipped,
                                             ulong                       is_cnt,
                                             fd_parent_ready_t *         out,
                                             ulong *                     out_cnt );

/* fd_parent_ready_tracker_parents_ready returns the list of all valid
   parents for slot, as of now, writing the count to *cnt.  Returns NULL
   (and *cnt = 0) if there is no state for slot.  Does not create state.
   Mirrors ParentReadyTracker::parents_ready. */

fd_block_id_t const *
fd_parent_ready_tracker_parents_ready( fd_parent_ready_tracker_t * tracker,
                                       ulong                       slot,
                                       ulong *                     cnt );

/* fd_parent_ready_tracker_wait_for_parent_ready returns 1 and writes the
   minimal-slot ready parent to *out_id iff a parent is already ready for
   slot, else returns 0.  Lazily creates state for slot if necessary.
   Synchronous form of ParentReadyTracker::wait_for_parent_ready. */

int
fd_parent_ready_tracker_wait_for_parent_ready( fd_parent_ready_tracker_t * tracker,
                                               ulong                       slot,
                                               fd_block_id_t *             out_id );

/* fd_parent_ready_tracker_prune removes all tracked state for slots
   strictly below new_root.  After this only slots >= new_root are
   retained, and calls for slots < new_root are ignored.  Mirrors
   ParentReadyTracker::prune. */

void
fd_parent_ready_tracker_prune( fd_parent_ready_tracker_t * tracker,
                               ulong                       new_root );

/* fd_parent_ready_tracker_slot_state returns the fd_parent_ready_state_t
   for slot, lazily creating (Default-initialized) state if necessary.
   Mirrors ParentReadyTracker::slot_state.  Returns NULL only if the pool
   is exhausted (slot_max exceeded). */

fd_parent_ready_state_t *
fd_parent_ready_tracker_slot_state( fd_parent_ready_tracker_t * tracker,
                                    ulong                       slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_pool_fd_parent_ready_tracker_h */
