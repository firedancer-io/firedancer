#ifndef HEADER_fd_src_alpenglow_consensus_pool_fd_slot_state_h
#define HEADER_fd_src_alpenglow_consensus_pool_fd_slot_state_h

/* fd_slot_state mirrors alpenglow/src/consensus/pool/slot_state.rs: the
   data structure holding all of the pool's per-slot state — the votes,
   the running stake totals, the certificates, and the safe-to-notar /
   safe-to-skip bookkeeping for a single slot.

   The Rust reference defines:

     SlotState         - the per-slot container (votes + voted_stakes +
                         certificates + parents + pending/sent safe-to-notar
                         + sent_safe_to_skip + slot + epoch_info).
     SlotVotes         - per-validator votes for all five vote kinds.
     SlotVotedStake    - per-hash and scalar running stake totals.
     SlotCertificates  - the (at most) one-of-each cert kinds for the slot.

   plus the ParentStatus and SafeToNotarStatus status enums, and a set of
   methods (add_cert, add_vote, count_*_stake, check_safe_to_notar,
   check_slashable_offence, should_ignore_vote, notify_parent_known /
   notify_parent_certified).

   OWNERSHIP MODEL.  An fd_slot_state_t is a relocatable wksp object that
   owns all of its backing pools and maps, formatted by the canonical
   fd_ghost.c pattern: an __attribute__((aligned(128UL))) top struct that
   holds only gaddrs, with align / footprint(validator_max) / new(...,seed)
   / join / leave / delete.  The per-validator inline vote arrays are sized
   to validator_max and laid out contiguously after the top struct.  A
   downstream fd_pool of slot_states (mirroring PoolImpl.slot_states) is
   expected to allocate one backing region per live slot; this module is
   testable in isolation against a single wksp-backed slot_state.

   OUTPUTS.  In Rust, SlotState methods return a
   (SmallVec<Cert>, SmallVec<PoolEvent>, SmallVec<BlockId>) tuple.  Here the
   caller supplies an fd_slot_state_outputs_t with bounded arrays into which
   newly created certs, votor events (SafeToNotar / SafeToSkip) and
   blocks-to-repair are appended.

   Per project convention this is built directly on the lowest-level util
   generics (fd_pool, fd_map_chain) rather than the choreo primitives. */

#include "../../fd_alpenglow_base.h" /* Slot/Stake/ValidatorIndex, fd_block_id_t */
#include "../fd_vote.h"              /* fd_ag_vote_t + concrete vote types         */
#include "../fd_cert.h"             /* fd_cert_t + concrete cert types          */
#include "../fd_epoch_info.h"       /* fd_epoch_info_t / fd_validator_info_t    */

/* ParentStatus (slot_state.rs).  A block's parent is either Known (present
   in blockstore) or Certified (notarized-fallback).  FD_SLOT_STATE_PARENT_NONE
   is the internal "no entry" sentinel (the BTreeMap entry being vacant). */

#define FD_SLOT_STATE_PARENT_NONE      (0)
#define FD_SLOT_STATE_PARENT_KNOWN     (1)
#define FD_SLOT_STATE_PARENT_CERTIFIED (2)

/* SafeToNotarStatus (slot_state.rs): the possible results of the
   safe-to-notar check. */

#define FD_SLOT_STATE_S2N_SAFE_TO_NOTAR (0)
#define FD_SLOT_STATE_S2N_MISSING_BLOCK (1)
#define FD_SLOT_STATE_S2N_AWAITING      (2)

/* SlashableOffence (alpenglow/src/consensus/pool.rs).  Mirrors the four
   slashable offences the pool may detect.  FD_SLASHABLE_NONE is the
   "no offence" sentinel (Rust Option::None). */

#define FD_SLASHABLE_NONE                       (0)
#define FD_SLASHABLE_NOTAR_DIFFERENT_HASH       (1)
#define FD_SLASHABLE_SKIP_AND_NOTARIZE          (2)
#define FD_SLASHABLE_SKIP_AND_FINALIZE          (3)
#define FD_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE (4)

/* fd_slashable_offence_t mirrors the SlashableOffence enum payload: the
   offence kind plus the (validator, slot) it was detected for.  kind is
   FD_SLASHABLE_NONE when no offence was found. */

struct fd_slashable_offence {
  int   kind;      /* FD_SLASHABLE_* */
  ulong validator; /* ValidatorIndex */
  ulong slot;      /* Slot           */
};
typedef struct fd_slashable_offence fd_slashable_offence_t;

/* fd_pool_event_t is the subset of PoolEvent (alpenglow/src/consensus/pool.rs)
   that the slot_state itself emits: SafeToNotar(BlockId) and
   SafeToSkip(Slot).  (ParentReady / CertCreated / Standstill are emitted by
   the parent pool, not the slot_state.)  CertCreated is conveyed separately
   via the certs array of fd_slot_state_outputs_t. */

#define FD_POOL_EVENT_SAFE_TO_NOTAR (0)
#define FD_POOL_EVENT_SAFE_TO_SKIP  (1)

struct fd_pool_event {
  int           kind; /* FD_POOL_EVENT_* */
  fd_block_id_t block; /* SafeToNotar: the block; SafeToSkip: only block.slot is meaningful */
};
typedef struct fd_pool_event fd_pool_event_t;

/* fd_slot_state_outputs_t is the caller-provided output sink, mirroring the
   Rust SlotStateOutputs tuple (SmallVec<Cert>, SmallVec<PoolEvent>,
   SmallVec<BlockId>).  The caller initializes the *_cnt fields to 0 and the
   *_max fields to the capacity of the backing arrays before each call; the
   slot_state appends and updates the counts.  A single add_vote can in the
   worst case create up to 3 certs (notar-fallback + notar + fast-final) and
   emit several events, so size the arrays generously (>= 4 each is safe). */

struct fd_slot_state_outputs {
  fd_cert_t *       certs;       ulong certs_cnt;       ulong certs_max;
  fd_pool_event_t * events;      ulong events_cnt;      ulong events_max;
  fd_block_id_t *   repairs;     ulong repairs_cnt;     ulong repairs_max;
};
typedef struct fd_slot_state_outputs fd_slot_state_outputs_t;

/* fd_notify_parent_result_t mirrors the Option<Either<PoolEvent, BlockId>>
   returned by SlotState::notify_parent_certified.  kind selects which (if
   any) of the union members is meaningful. */

#define FD_NOTIFY_PARENT_NONE  (0) /* Rust None              */
#define FD_NOTIFY_PARENT_EVENT (1) /* Rust Some(Left(event)) */
#define FD_NOTIFY_PARENT_REPAIR (2) /* Rust Some(Right(blk)) */

struct fd_notify_parent_result {
  int kind; /* FD_NOTIFY_PARENT_* */
  union {
    fd_pool_event_t event;
    fd_block_id_t   repair;
  } inner;
};
typedef struct fd_notify_parent_result fd_notify_parent_result_t;

/* fd_slot_state_t is opaque; it is a relocatable wksp object whose internal
   layout is private to fd_slot_state.c. */

typedef struct fd_slot_state fd_slot_state_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_slot_state_{align,footprint} return the alignment and footprint of a
   memory region suitable for use as a slot_state over up to validator_max
   validators.  validator_max bounds the per-validator inline vote arrays and
   the per-hash / per-(validator,hash) maps. */

FD_FN_CONST ulong fd_slot_state_align( void );

FD_FN_CONST ulong fd_slot_state_footprint( ulong validator_max );

/* fd_slot_state_new formats mem (>= footprint, aligned) as an empty
   slot_state for slot, owned by validator own_id, over validator_max
   validators.  seed seeds the internal maps.  Returns mem on success, NULL
   on failure (logs details).  Mirrors SlotState::new (initially empty). */

void * fd_slot_state_new( void * mem, ulong slot, ulong own_id, ulong validator_max, ulong seed );

/* fd_slot_state_join / leave / delete mirror the canonical join/leave/delete
   triplet (see fd_ghost.h). */

fd_slot_state_t * fd_slot_state_join  ( void *                  mem );
void *            fd_slot_state_leave ( fd_slot_state_t const * ss );
void *            fd_slot_state_delete( void *                  mem );

/* Operations */

/* fd_slot_state_add_cert adds a certificate to this slot, mirroring
   SlotState::add_cert.  For a NotarFallback cert the cert is only stored if
   no notar-fallback cert for the same block hash already exists.  The cert is
   copied into the slot_state. */

void fd_slot_state_add_cert( fd_slot_state_t * ss, fd_cert_t const * cert );

/* fd_slot_state_add_vote adds a vote to this slot, mirroring
   SlotState::add_vote.  It updates the running stake totals, creates any new
   certificates and checks the safe-to-notar / safe-to-skip conditions,
   appending newly created certs / events / blocks-to-repair to *out.
   voter_stake is the stake of the vote's signer (looked up by the caller from
   the epoch info).

   The vote is copied into the slot_state.  The caller is responsible for
   first calling fd_slot_state_should_ignore_vote (to skip duplicates) and
   fd_slot_state_check_slashable_offence (to detect slashing). */

void fd_slot_state_add_vote( fd_slot_state_t *         ss,
                             fd_ag_vote_t const *      vote,
                             ulong                     voter_stake,
                             fd_epoch_info_t const *   epoch_info,
                             fd_slot_state_outputs_t * out );

/* fd_slot_state_notify_parent_known marks the parent of the block keyed by
   hash as Known (present in blockstore), mirroring
   SlotState::notify_parent_known.  If an entry already exists it is left
   unchanged (BTreeMap::entry().or_insert). */

void fd_slot_state_notify_parent_known( fd_slot_state_t * ss, fd_hash_t const * hash );

/* fd_slot_state_notify_parent_certified marks the parent of the block keyed
   by hash as Certified and potentially emits a safe-to-notar event, mirroring
   SlotState::notify_parent_certified.  Returns the result (see
   fd_notify_parent_result_t).  FD_TEST-asserts that notify_parent_known has
   been called for hash (Rust panics "parent not known"). */

fd_notify_parent_result_t
fd_slot_state_notify_parent_certified( fd_slot_state_t *       ss,
                                       fd_hash_t const *       hash,
                                       fd_epoch_info_t const * epoch_info );

/* fd_slot_state_check_slashable_offence returns the slashable offence the
   given vote would constitute given the slot's current votes, mirroring
   SlotState::check_slashable_offence.  The returned struct has kind
   FD_SLASHABLE_NONE if there is no offence.  Must be called before dismissing
   duplicates via should_ignore_vote. */

FD_FN_PURE fd_slashable_offence_t
fd_slot_state_check_slashable_offence( fd_slot_state_t const * ss, fd_ag_vote_t const * vote );

/* fd_slot_state_should_ignore_vote returns 1 iff the given vote should be
   ignored as a (benign) duplicate, mirroring SlotState::should_ignore_vote.
   Votes for which this returns 1 must never be counted (double counting). */

FD_FN_PURE int
fd_slot_state_should_ignore_vote( fd_slot_state_t const * ss, fd_ag_vote_t const * vote );

/* fd_slot_state_is_notar_fallback returns 1 iff a notar-fallback cert exists
   for block_hash in this slot (SlotState::is_notar_fallback). */

FD_FN_PURE int
fd_slot_state_is_notar_fallback( fd_slot_state_t const * ss, fd_hash_t const * block_hash );

/* Accessors exposing internal running totals / vote presence for tests and
   the downstream pool, mirroring the pub(super) fields the Rust tests read. */

FD_FN_PURE ulong fd_slot_state_slot( fd_slot_state_t const * ss );

/* fd_slot_state_notar_stake returns the running notar stake for block_hash
   (voted_stakes.notar.get(hash).unwrap_or(0)). */

FD_FN_PURE ulong fd_slot_state_notar_stake         ( fd_slot_state_t const * ss, fd_hash_t const * block_hash );
FD_FN_PURE ulong fd_slot_state_notar_fallback_stake( fd_slot_state_t const * ss, fd_hash_t const * block_hash );
FD_FN_PURE ulong fd_slot_state_skip_stake          ( fd_slot_state_t const * ss );
FD_FN_PURE ulong fd_slot_state_skip_fallback_stake ( fd_slot_state_t const * ss );
FD_FN_PURE ulong fd_slot_state_finalize_stake      ( fd_slot_state_t const * ss );
FD_FN_PURE ulong fd_slot_state_notar_or_skip_stake ( fd_slot_state_t const * ss );
FD_FN_PURE ulong fd_slot_state_top_notar_stake     ( fd_slot_state_t const * ss );

/* fd_slot_state_has_notar_vote returns 1 iff validator v cast a notar vote
   (votes.notar[v].is_some()). */

FD_FN_PURE int fd_slot_state_has_notar_vote( fd_slot_state_t const * ss, ulong v );

/* fd_slot_state_has_notar_cert / has_finalize_cert / has_skip_cert /
   has_fast_finalize_cert return whether the corresponding single-cert slot is
   populated (certificates.<kind>.is_some()). */

FD_FN_PURE int fd_slot_state_has_notar_cert        ( fd_slot_state_t const * ss );
FD_FN_PURE int fd_slot_state_has_skip_cert         ( fd_slot_state_t const * ss );
FD_FN_PURE int fd_slot_state_has_fast_finalize_cert( fd_slot_state_t const * ss );
FD_FN_PURE int fd_slot_state_has_finalize_cert     ( fd_slot_state_t const * ss );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_pool_fd_slot_state_h */
