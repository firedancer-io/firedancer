#ifndef HEADER_fd_src_alpenglow_consensus_pool_fd_finality_tracker_h
#define HEADER_fd_src_alpenglow_consensus_pool_fd_finality_tracker_h

/* fd_finality_tracker is the Firedancer C port of
   alpenglow/src/consensus/pool/finality_tracker.rs.

   It tracks the finality of blocks.  This is used internally as part of
   the consensus Pool (alpenglow/src/consensus/pool.rs).

   It keeps track of:
     - Direct finalization of blocks,
     - resulting indirect (implicit) finalizations of ancestor blocks, and
     - resulting implicit skipping of earlier slots

   It does this based on:
     - Notarization of blocks,
     - finalization of slots,
     - fast finalization of blocks, and
     - availability of blocks and knowledge of their parents.

   In the Rust reference the tracker holds:
     - status:                 BTreeMap<Slot, FinalizationStatus>
     - parents:                BTreeMap<BlockId, BlockId>
     - highest_finalized_slot: Slot
     - first_unpruned_slot:    Slot

   We mirror this 1:1.  Per the project conventions, the two BTreeMaps are
   built directly on the lowest-level util generics:

     - status:  fd_pool + fd_map_chain (keyed by slot ulong) + fd_treap
       (ordered by slot, supporting the in-order range prune that mirrors
       Rust's BTreeMap::split_off).

     - parents: fd_pool + fd_map_chain (keyed by fd_block_id_t) + fd_treap
       (ordered by slot, supporting the range prune that mirrors Rust's
       BTreeMap::retain(|(slot,_),_| slot >= root)).

   The tracker is a relocatable wksp object, following the canonical
   fd_ghost pattern: an aligned(128) top struct holding only gaddrs, with
   align / footprint / new / join / leave / delete and the
   FD_SCRATCH_ALLOC layout. */

#include "../../fd_alpenglow_base.h" /* fd_block_id_t, Slot, fd_block_id_eq, GENESIS hash (all-zero) */

/* FinalizationStatus: the possible states a slot can be in regarding
   finality (alpenglow/src/consensus/pool/finality_tracker.rs
   FinalizationStatus).

   In Rust this is an enum with payloads.  In C we keep the discriminant
   in a small int and store the (optional) BlockHash alongside in the
   status element.  The hash field is only meaningful for the variants
   that carry one (Notarized / Finalized / ImplicitlyFinalized). */

#define FD_FIN_STATUS_NOTARIZED            (0) /* block with given hash is notarized, slot not yet (known to be) finalized */
#define FD_FIN_STATUS_FINAL_PENDING_NOTAR  (1) /* slot is known finalized, but we are missing the notarization certificate */
#define FD_FIN_STATUS_FINALIZED            (2) /* slot is finalized, and notarized block is known to have the given hash */
#define FD_FIN_STATUS_IMPLICITLY_FINALIZED (3) /* block with given hash was implicitly finalized through later finalization */
#define FD_FIN_STATUS_IMPLICITLY_SKIPPED   (4) /* slot was implicitly skipped through later finalization */

/* FD_FINALITY_EVENT_CAP bounds the number of implicitly finalized blocks
   and implicitly skipped slots a single FinalizationEvent can carry.  In
   the Rust reference these are unbounded Vecs, but a single finalization
   can only implicitly finalize / skip the slots between the newly
   finalized block and the previous watermark.  In practice this gap is
   tiny (a handful of leader windows).  64 leaves generous headroom; if it
   is ever exceeded that indicates either a pathological unresolved-parent
   backlog or a logic error, so we FD_LOG_ERR (fatal) rather than silently
   truncate. */

#define FD_FINALITY_EVENT_CAP (64UL)

/* fd_finalization_event_t mirrors
   alpenglow/src/consensus/pool/finality_tracker.rs FinalizationEvent.

     - has_finalized / finalized:     the directly finalized block, if any
       (Rust: Option<BlockId>).
     - if_cnt / implicitly_finalized:  any implicitly finalized blocks
       (Rust: Vec<BlockId>).
     - is_cnt / implicitly_skipped:    any implicitly skipped slots
       (Rust: Vec<Slot>).

   The default ("empty") event has has_finalized==0 and both counts 0. */

struct fd_finalization_event {
  int           has_finalized;                          /* 1 iff a block was directly finalized this call */
  fd_block_id_t finalized;                              /* the directly finalized block (valid iff has_finalized) */
  ulong         if_cnt;                                 /* number of entries in implicitly_finalized */
  fd_block_id_t implicitly_finalized[ FD_FINALITY_EVENT_CAP ];
  ulong         is_cnt;                                 /* number of entries in implicitly_skipped */
  ulong         implicitly_skipped[ FD_FINALITY_EVENT_CAP ];
};
typedef struct fd_finalization_event fd_finalization_event_t;

/* fd_finality_tracker_t is the opaque top-level handle. */

struct fd_finality_tracker;
typedef struct fd_finality_tracker fd_finality_tracker_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_finality_tracker_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a finality tracker
   holding up to slot_max distinct (live, unpruned) status slots and
   blockid_max distinct (live, unpruned) parent edges. */

FD_FN_CONST ulong
fd_finality_tracker_align( void );

FD_FN_CONST ulong
fd_finality_tracker_footprint( ulong slot_max,
                               ulong blockid_max );

/* fd_finality_tracker_new formats an unused memory region for use as a
   finality tracker.  shmem is a non-NULL pointer to this region in the
   local address space with the required footprint and alignment.  seed is
   used to seed the internal hash maps.

   On return the tracker is in the Rust Default state: the genesis slot
   (0) is present in status as Notarized(GENESIS_BLOCK_HASH) (the all-zero
   hash), parents is empty, and both highest_finalized_slot and
   first_unpruned_slot are the genesis slot (0).

   Returns shmem on success and NULL on failure (logs details). */

void *
fd_finality_tracker_new( void * shmem,
                         ulong  slot_max,
                         ulong  blockid_max,
                         ulong  seed );

/* fd_finality_tracker_join joins the caller to the finality tracker.
   Returns a pointer in the local address space to the tracker on
   success and NULL on failure (logs details). */

fd_finality_tracker_t *
fd_finality_tracker_join( void * shtracker );

/* fd_finality_tracker_leave leaves a current local join.  Returns a
   pointer to the underlying shared memory region on success and NULL on
   failure (logs details). */

void *
fd_finality_tracker_leave( fd_finality_tracker_t const * tracker );

/* fd_finality_tracker_delete unformats a memory region used as a finality
   tracker.  Assumes nobody is joined.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details). */

void *
fd_finality_tracker_delete( void * shtracker );

/* Operations.  These mirror the FinalityTracker methods 1:1.  Each
   returns a FinalizationEvent by value (the caller owns out, which must
   be non-NULL); on return out describes any newly finalized / implicitly
   finalized / implicitly skipped slots resulting from the call. */

/* fd_finality_tracker_add_parent adds the given parent for the given
   block, handling any resulting implicit finalizations.  Mirrors
   FinalityTracker::add_parent.  Requires block->slot > parent->slot. */

void
fd_finality_tracker_add_parent( fd_finality_tracker_t *   tracker,
                                fd_block_id_t const *     block,
                                fd_block_id_t const *     parent,
                                fd_finalization_event_t * out );

/* fd_finality_tracker_mark_fast_finalized marks the given block as fast
   finalized.  Mirrors FinalityTracker::mark_fast_finalized. */

void
fd_finality_tracker_mark_fast_finalized( fd_finality_tracker_t *   tracker,
                                         fd_block_id_t const *     block,
                                         fd_finalization_event_t * out );

/* fd_finality_tracker_mark_notarized marks the given block as notarized,
   handling any resulting direct / implicit finalizations.  Mirrors
   FinalityTracker::mark_notarized. */

void
fd_finality_tracker_mark_notarized( fd_finality_tracker_t *   tracker,
                                    fd_block_id_t const *     block,
                                    fd_finalization_event_t * out );

/* fd_finality_tracker_mark_finalized marks the given slot as finalized,
   handling any resulting direct / implicit finalizations.  Mirrors
   FinalityTracker::mark_finalized. */

void
fd_finality_tracker_mark_finalized( fd_finality_tracker_t *   tracker,
                                    ulong                     slot,
                                    fd_finalization_event_t * out );

/* Accessors */

/* fd_finality_tracker_highest_finalized_slot returns the highest
   finalized slot so far (a slot that has a fast finalization, or a
   finalization + notarization).  Note that some slots before this may
   still be undecided.  Mirrors FinalityTracker::highest_finalized_slot. */

FD_FN_PURE ulong
fd_finality_tracker_highest_finalized_slot( fd_finality_tracker_t const * tracker );

/* fd_finality_tracker_first_unpruned_slot returns the first slot whose
   state has not yet been pruned.  All slots below this are decided and no
   longer tracked.  Mirrors FinalityTracker::first_unpruned_slot. */

FD_FN_PURE ulong
fd_finality_tracker_first_unpruned_slot( fd_finality_tracker_t const * tracker );

/* fd_finality_tracker_status queries the FinalizationStatus of slot.
   Returns one of FD_FIN_STATUS_* on success and -1 if slot has no status
   entry.  If the returned status carries a block hash (NOTARIZED,
   FINALIZED, IMPLICITLY_FINALIZED) and out_hash is non-NULL, *out_hash is
   set to that hash.  This is a test / introspection helper with no direct
   analogue in the Rust reference (which exposes the BTreeMap directly to
   its in-module tests). */

int
fd_finality_tracker_status( fd_finality_tracker_t const * tracker,
                            ulong                         slot,
                            fd_hash_t *                   out_hash );

/* fd_finality_tracker_has_parent returns 1 iff a parent edge has been
   recorded for block.  Test / introspection helper. */

FD_FN_PURE int
fd_finality_tracker_has_parent( fd_finality_tracker_t const * tracker,
                                fd_block_id_t const *         block );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_pool_fd_finality_tracker_h */
