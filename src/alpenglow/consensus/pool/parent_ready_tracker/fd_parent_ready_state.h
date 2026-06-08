#ifndef HEADER_fd_src_alpenglow_consensus_pool_parent_ready_tracker_fd_parent_ready_state_h
#define HEADER_fd_src_alpenglow_consensus_pool_parent_ready_tracker_fd_parent_ready_state_h

/* fd_parent_ready_state mirrors
   alpenglow/src/consensus/pool/parent_ready_tracker/parent_ready_state.rs.

   It holds the per-slot state used by the parent-ready tracker
   (fd_parent_ready_tracker.{h,c}) to track the parent-ready condition.

   The Rust reference uses a tokio oneshot channel to notify a waiter when
   a parent becomes ready.  In the C port the async oneshot waiter is
   dropped entirely: fd_parent_ready_state_wait_for_parent_ready returns
   synchronously, returning 1 (with the minimal-slot ready parent written
   to an out fd_block_id_t) iff a parent is already ready, else 0.

   fd_parent_ready_state_t is intended to be embedded as a fd_pool element
   keyed by slot inside fd_parent_ready_tracker, so it carries the
   pool/map link fields (next/map_next) directly.  See
   fd_parent_ready_tracker.c for the pool/map_chain instantiation. */

#include "../../../fd_alpenglow_base.h"

/* FD_PARENT_READY_STATE_CAP bounds the number of notarized-fallback
   block hashes and the number of ready parent block ids tracked per
   slot.  The Rust reference uses SmallVec<[_;1]> for both, optimizing
   for the common case of a single entry but allowing growth.  Multiple
   notar-fallbacks per slot can arise from equivocation, and multiple
   ready parents per start-of-window slot can arise from skip-connected
   forks; we cap both at a small fixed bound to stay allocation-free.  */

#define FD_PARENT_READY_STATE_CAP (8UL)

/* fd_parent_ready_state_t holds the relevant state for a single slot.

   Mirrors the Rust ParentReadyState struct:
     - skip               : whether this slot is skip-certified
     - notar_fallbacks    : blocks that are notarized-fallback for this slot
     - is_ready/ready_ids : current status of the parent-ready condition

   slot is the map key.  next is reserved for fd_pool/fd_map_chain.  */

struct fd_parent_ready_state {
  ulong         slot;                                          /* map key: the slot this state tracks */
  ulong         next;                                          /* reserved for fd_pool and fd_map_chain */

  int           skip;                                          /* 1 iff this slot is skip-certified */

  uchar         notar_fallbacks_cnt;                           /* number of notarized-fallback hashes, in [0,CAP] */
  fd_hash_t     notar_fallbacks[FD_PARENT_READY_STATE_CAP];    /* notarized-fallback block hashes for this slot */

  uchar         is_ready;                                      /* 1 iff at least one parent is ready for this slot */
  uchar         ready_cnt;                                     /* number of ready parent ids, in [0,CAP] */
  fd_block_id_t ready_ids[FD_PARENT_READY_STATE_CAP];          /* valid parents for this slot */
};
typedef struct fd_parent_ready_state fd_parent_ready_state_t;

FD_PROTOTYPES_BEGIN

/* fd_parent_ready_state_init initializes state to the Default value
   (mirrors #[derive(Default)] ParentReadyState): not skipped, no
   notar-fallbacks, not ready. */

void
fd_parent_ready_state_init( fd_parent_ready_state_t * state,
                            ulong                     slot );

/* fd_parent_ready_state_genesis initializes state for the genesis block
   (mirrors ParentReadyState::genesis): like init but with the genesis
   block hash (all-zero) as the single notarized-fallback. */

void
fd_parent_ready_state_genesis( fd_parent_ready_state_t * state,
                               ulong                     slot );

/* fd_parent_ready_state_mark_skip marks this slot as skip-certified.
   Returns 1 iff this slot was not already skip-certified (mirrors
   ParentReadyState::mark_skip). */

int
fd_parent_ready_state_mark_skip( fd_parent_ready_state_t * state );

/* fd_parent_ready_state_is_skip_certified returns 1 iff this slot is
   skip-certified (mirrors ParentReadyState::is_skip_certified). */

FD_FN_PURE static inline int
fd_parent_ready_state_is_skip_certified( fd_parent_ready_state_t const * state ) {
  return state->skip;
}

/* fd_parent_ready_state_mark_notar_fallback marks the block keyed by
   hash as notarized-fallback for this slot.  Returns 1 iff this block
   was not already marked (mirrors ParentReadyState::mark_notar_fallback).
   FD_LOG_ERR on overflow (more than CAP distinct notar-fallbacks). */

int
fd_parent_ready_state_mark_notar_fallback( fd_parent_ready_state_t * state,
                                           fd_hash_t const *         hash );

/* fd_parent_ready_state_notar_fallback_blocks returns a pointer to the
   array of notarized-fallback block hashes for this slot and writes the
   count to *cnt.  Mirrors ParentReadyState::notar_fallback_blocks
   (iteration). */

FD_FN_PURE static inline fd_hash_t const *
fd_parent_ready_state_notar_fallback_blocks( fd_parent_ready_state_t const * state,
                                             ulong *                         cnt ) {
  *cnt = (ulong)state->notar_fallbacks_cnt;
  return state->notar_fallbacks;
}

/* fd_parent_ready_state_add_to_ready adds id to this slot's ready
   parents list (mirrors ParentReadyState::add_to_ready).  FD_LOG_ERR if
   id is already marked ready for this slot (matches the Rust assert) or
   on overflow. */

void
fd_parent_ready_state_add_to_ready( fd_parent_ready_state_t * state,
                                    fd_block_id_t const *     id );

/* fd_parent_ready_state_ready_block_ids returns a pointer to the array
   of currently valid parents for this slot and writes the count to
   *cnt (mirrors ParentReadyState::ready_block_ids). */

FD_FN_PURE static inline fd_block_id_t const *
fd_parent_ready_state_ready_block_ids( fd_parent_ready_state_t const * state,
                                       ulong *                         cnt ) {
  *cnt = (ulong)state->ready_cnt;
  return state->ready_ids;
}

/* fd_parent_ready_state_wait_for_parent_ready requests a valid parent
   for this slot.  Returns 1 and writes the minimal-slot ready parent to
   *out_id iff at least one parent is already ready, else returns 0
   (and leaves *out_id untouched).

   This is the synchronous form of ParentReadyState::wait_for_parent_ready:
   the Rust Either::Left(BlockId) becomes return 1 + *out_id, and the
   Either::Right(oneshot::Receiver) "not ready yet" case becomes return 0. */

int
fd_parent_ready_state_wait_for_parent_ready( fd_parent_ready_state_t const * state,
                                             fd_block_id_t *                 out_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_pool_parent_ready_tracker_fd_parent_ready_state_h */
