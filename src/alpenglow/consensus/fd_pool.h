#ifndef HEADER_fd_src_alpenglow_consensus_fd_pool_h
#define HEADER_fd_src_alpenglow_consensus_fd_pool_h

/* fd_pool mirrors alpenglow/src/consensus/pool.rs: the central consensus
   data structure (the Rust PoolImpl).  Any received votes or certificates
   are placed into the pool.  The pool then tracks status for each slot and
   notifies Votor / Repair.

   The pool owns:

     - slot_states:           BTreeMap<Slot, SlotState>
                              -> fd_pool + fd_map_chain (keyed by slot), one
                                 wksp-backed fd_slot_state region per live slot.
     - parent_ready_tracker:  fd_parent_ready_tracker
     - finality_tracker:      fd_finality_tracker
     - s2n_waiting_parent_cert: BTreeMap<BlockId, BlockId>
                              -> fd_pool + fd_map_chain (keyed by fd_block_id_t).

   EVENTS.  In Rust the pool emits PoolEvent over an mpsc channel to Votor
   and BlockId repair requests over a second channel.  Here, both the
   votor-bound events and the repair requests are *appended* to two
   caller-provided output sinks, mirroring the slot_state output model:

     - an fd_pool_evt_t out-array (ParentReady / SafeToNotar / SafeToSkip /
       CertCreated / Standstill), and
     - an fd_block_id_t repair out-array.

   The caller initializes the *_cnt fields to 0 and the *_max fields to the
   capacity of the backing arrays before each pool call; the pool appends
   and updates the counts.

   This is a relocatable wksp object, formatted by the canonical fd_ghost.c
   pattern: an aligned(128) top struct holding only gaddrs, with
   align / footprint(slot_max,validator_max,blockid_max) / new(...,seed) /
   join / leave / delete and the FD_SCRATCH_ALLOC layout.

   Per project convention this is built directly on the lowest-level util
   generics (fd_pool, fd_map_chain) rather than the choreo primitives, and
   wraps the three Tier1 pool submodules (finality_tracker,
   parent_ready_tracker, slot_state). */

#include "../fd_alpenglow_base.h"  /* Slot/Stake/ValidatorIndex, fd_block_id_t */
#include "fd_vote.h"               /* fd_ag_vote_t + concrete vote types          */
#include "fd_cert.h"               /* fd_cert_t + concrete cert types          */
#include "fd_epoch_info.h"         /* fd_epoch_info_t / fd_validator_info_t    */
#include "pool/fd_slot_state.h"    /* fd_slashable_offence_t (Slashable detail) */

/* AddVoteError (pool.rs).  add_vote returns FD_POOL_SUCCESS (0) or one of
   these (negative).  The Slashable variant additionally fills *out_offence
   in fd_pool_add_vote (see below). */

#define FD_POOL_SUCCESS                  ( 0)
#define FD_POOL_ERR_SLOT_OUT_OF_BOUNDS   (-1) /* AddVoteError::SlotOutOfBounds / AddCertError::SlotOutOfBounds */
#define FD_POOL_ERR_UNKNOWN_SIGNER       (-2) /* AddVoteError::UnknownSigner   */
#define FD_POOL_ERR_INVALID_SIGNATURE    (-3) /* AddVoteError::InvalidSignature / AddCertError::InvalidSignature */
#define FD_POOL_ERR_DUPLICATE            (-4) /* AddVoteError::Duplicate / AddCertError::Duplicate */
#define FD_POOL_ERR_SLASHABLE            (-5) /* AddVoteError::Slashable        */
#define FD_POOL_ERR_THRESHOLD_NOT_MET    (-6) /* AddCertError::ThresholdNotMet  */
#define FD_POOL_ERR_FULL                 (-7) /* pool/map exhausted (no Rust analogue; bounded C resource) */

/* fd_pool_evt_kind: the PoolEvent variants (pool.rs PoolEvent).  In Rust the
   Standstill variant carries Vec<Cert> + Vec<Vote>; here those are conveyed
   separately via the dedicated standstill output buffers of
   fd_pool_recover_from_standstill (so the event itself only carries the
   slot). */

#define FD_POOL_EVT_PARENT_READY  (0) /* ParentReady { slot, parent } */
#define FD_POOL_EVT_SAFE_TO_NOTAR (1) /* SafeToNotar(BlockId)         */
#define FD_POOL_EVT_SAFE_TO_SKIP  (2) /* SafeToSkip(Slot)             */
#define FD_POOL_EVT_CERT_CREATED  (3) /* CertCreated(Cert)            */
#define FD_POOL_EVT_STANDSTILL    (4) /* Standstill(Slot, ..)         */

/* fd_pool_evt_t is one emitted PoolEvent.  Which union member is meaningful
   depends on kind:

     PARENT_READY  : slot (window-start) + parent block id
     SAFE_TO_NOTAR : block.slot + block.hash    (BlockId)
     SAFE_TO_SKIP  : slot                       (only slot meaningful)
     CERT_CREATED  : cert
     STANDSTILL    : slot (== finalized_slot.next()); certs/votes are in the
                     recover_from_standstill standstill output buffers. */

struct fd_pool_evt {
  int kind;                /* FD_POOL_EVT_*       */
  union {
    struct { ulong slot; fd_block_id_t parent; } parent_ready; /* PARENT_READY */
    fd_block_id_t block;   /* SAFE_TO_NOTAR       */
    ulong         slot;    /* SAFE_TO_SKIP / STANDSTILL */
    fd_cert_t     cert;    /* CERT_CREATED        */
  } inner;
};
typedef struct fd_pool_evt fd_pool_evt_t;

/* fd_pool_out_t is the caller-provided output sink for the votor-bound
   events and the repair requests.  Mirrors the (pool_tx, repair_tx)
   channels of the Rust PoolImpl.  Size generously: a single add_vote /
   add_cert can emit several CertCreated events, plus safe-to-notar /
   safe-to-skip / parent-ready. */

struct fd_pool_out {
  fd_pool_evt_t * events;  ulong events_cnt;  ulong events_max;  /* -> votor */
  fd_block_id_t * repairs; ulong repairs_cnt; ulong repairs_max; /* -> repair */
};
typedef struct fd_pool_out fd_pool_out_t;

/* fd_pool_t is opaque; its internal layout is private to fd_pool.c. */

typedef struct fd_pool fd_pool_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_pool_{align,footprint} return the alignment and footprint of a memory
   region suitable for use as a pool tracking up to slot_max live (unpruned)
   slots, validator_max validators, and blockid_max distinct safe-to-notar
   waiting edges.  validator_max bounds the epoch validator set the pool may
   hold and the per-slot vote arrays. */

FD_FN_CONST ulong
fd_pool_align( void );

FD_FN_CONST ulong
fd_pool_footprint( ulong slot_max,
                   ulong validator_max,
                   ulong blockid_max );

/* fd_pool_new formats mem (>= footprint, aligned, in a wksp) as an
   empty pool : empty slot_states, an empty s2n map, a Default finality
   tracker (genesis slot notarized) and a Default parent-ready tracker
   (genesis notar-fallback).

   Returns mem on success, NULL on failure (logs details). */

void *
fd_pool_new( void *            mem,
             ulong             slot_max,
             ulong             validator_max,
             ulong             blockid_max,
             ulong             seed,
             ulong             root_slot,        /* baseline finalized slot (snapshot slot, or 0) */
             fd_hash_t const * root_block_hash );/* its block id (NULL => all-zero genesis hash)    */

/* fd_pool_join / leave / delete mirror the canonical triplet (fd_ghost.h). */

fd_pool_t * fd_pool_join  ( void *            mem );
void *      fd_pool_leave ( fd_pool_t const * pool );
void *      fd_pool_delete( void *            mem );

/* Operations */

/* fd_pool_add_cert adds a new certificate to the pool, checking validity
   (slot bounds, stake threshold, signature, non-duplicate) before storing.
   Mirrors PoolImpl::add_cert.  Any resulting events / repair requests are
   appended to *out.  Returns FD_POOL_SUCCESS or an FD_POOL_ERR_* code. */

int
fd_pool_add_cert( fd_pool_t *                       pool,
                  fd_cert_t const *                 cert,
                  fd_validator_epoch_info_t const * epoch_info,
                  fd_pool_out_t *                   out );

/* fd_pool_add_vote adds a new vote to the pool, checking validity (slot
   bounds, known signer, signature, slashable offence, non-duplicate) before
   counting.  Mirrors PoolImpl::add_vote.  Any resulting certs / events /
   repair requests are appended to *out.

   Returns FD_POOL_SUCCESS or an FD_POOL_ERR_* code.  On
   FD_POOL_ERR_SLASHABLE, if out_offence is non-NULL the detected offence is
   written to *out_offence (it carries the offence kind, validator, slot). */

int
fd_pool_add_vote( fd_pool_t *                       pool,
                  fd_ag_vote_t const *              vote,
                  fd_validator_epoch_info_t const * epoch_info,
                  fd_pool_out_t *                   out,
                  fd_slashable_offence_t *          out_offence );

/* fd_pool_add_block registers a new block with its parent in the pool.
   Should be called once for every valid block (e.g. by the blockstore).
   Ensures parent information is available for safe-to-notar checks.  Any
   resulting events / repair requests are appended to *out.  Mirrors
   PoolImpl::add_block.  Requires block_id->slot > parent_id->slot. */

void
fd_pool_add_block( fd_pool_t *                       pool,
                   fd_block_id_t const *             block_id,
                   fd_block_id_t const *             parent_id,
                   fd_validator_epoch_info_t const * epoch_info,
                   fd_pool_out_t *                   out );

/* fd_pool_recover_from_standstill triggers recovery from a standstill.  It
   determines which certificates and votes need re-broadcasting and emits a
   single FD_POOL_EVT_STANDSTILL event into out->events (whose slot is
   finalized_slot.next()).  The certs to re-broadcast are appended to
   certs[0,*certs_cnt<=certs_max) and the own votes to votes[0,*votes_cnt<=
   votes_max).  Mirrors PoolImpl::recover_from_standstill.

   FD_TEST-asserts a final cert exists for the finalized slot (matching the
   Rust assert!(!certs.is_empty(), "no final cert")). */

void
fd_pool_recover_from_standstill( fd_pool_t *     pool,
                                 fd_pool_out_t * out,
                                 fd_cert_t *     certs, ulong * certs_cnt, ulong certs_max,
                                 fd_ag_vote_t *  votes, ulong * votes_cnt, ulong votes_max );

/* Accessors (PoolImpl pub methods) */

/* fd_pool_finalized_slot returns the currently highest finalized (fast or
   slow) slot.  Mirrors PoolImpl::finalized_slot. */

FD_FN_PURE ulong
fd_pool_finalized_slot( fd_pool_t const * pool );

/* fd_pool_first_unpruned_slot returns the first slot whose state has not
   been pruned.  Mirrors PoolImpl::first_unpruned_slot. */

FD_FN_PURE ulong
fd_pool_first_unpruned_slot( fd_pool_t const * pool );

/* fd_pool_parents_ready returns all valid ready parents for slot, writing
   the count to *cnt (NULL / *cnt=0 if no state for slot).  Mirrors
   PoolImpl::parents_ready. */

fd_block_id_t const *
fd_pool_parents_ready( fd_pool_t * pool, ulong slot, ulong * cnt );

/* fd_pool_is_parent_ready returns 1 iff parent is a ready parent for slot.
   Mirrors PoolImpl::is_parent_ready. */

int
fd_pool_is_parent_ready( fd_pool_t * pool, ulong slot, fd_block_id_t const * parent );

/* fd_pool_has_notar_or_fallback_cert returns 1 iff the pool contains a
   notar(-fallback) certificate for slot.  Mirrors
   PoolImpl::has_notar_or_fallback_cert. */

FD_FN_PURE int
fd_pool_has_notar_or_fallback_cert( fd_pool_t const * pool, ulong slot );

/* fd_pool_get_notarized_block writes the hash of the notarized block for
   slot into *out_hash and returns 1 iff a notar cert exists for slot, else
   returns 0.  Mirrors PoolImpl::get_notarized_block. */

int
fd_pool_get_notarized_block( fd_pool_t const * pool, ulong slot, fd_hash_t * out_hash );

/* fd_pool_has_final_cert / has_notar_cert / has_skip_cert return whether the
   pool holds the corresponding cert for slot.  Mirror the PoolImpl methods
   of the same names. */

FD_FN_PURE int fd_pool_has_final_cert( fd_pool_t const * pool, ulong slot );
FD_FN_PURE int fd_pool_has_notar_cert( fd_pool_t const * pool, ulong slot );
FD_FN_PURE int fd_pool_has_skip_cert ( fd_pool_t const * pool, ulong slot );

/* fd_pool_contains_slot returns 1 iff the pool currently holds slot_state
   for slot (i.e. slot >= first_unpruned_slot and has been touched).  Test /
   introspection helper mirroring the Rust tests' slot_states.contains_key. */

FD_FN_PURE int fd_pool_contains_slot( fd_pool_t const * pool, ulong slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_fd_pool_h */
