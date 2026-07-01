#ifndef HEADER_fd_src_alpenglow_consensus_fd_votor_h
#define HEADER_fd_src_alpenglow_consensus_fd_votor_h

/* fd_votor mirrors alpenglow/src/consensus/votor.rs: the per-slot voting
   decision process of the Alpenglow consensus protocol.

   Besides Pool, Votor is the other main internal component of Alpenglow.  It
   makes the main voting decisions: when to cast notar, skip, notar-fallback,
   skip-fallback and final votes.  In the Rust reference Votor is an async task
   that consumes three event streams (PoolEvent, BlockstoreEvent and its own
   timeout events) on tokio channels, keeps per-slot state, and broadcasts
   votes/certs over an All2All instance.

   The C port collapses the async machinery:
     - the voting_loop / tokio::select! is gone.  The tile calls one of the
       four handlers (fd_votor_handle_{pool,blockstore,timeout}_event,
       fd_votor_handle_cert_created via the pool handler) directly.
     - all2all.broadcast(..) and the timeout_sender.send(..) become APPENDS to
       caller-provided out-buffers (fd_votor_out_t): outgoing votes/certs to
       broadcast and timeouts to schedule.  The tile owns the wall-clock and
       turns scheduled fd_votor_timeout_t's into deadline checks that feed back
       into fd_votor_handle_timeout_event.
     - tokio::spawn'd timer tasks (set_timeouts) become a flat list of
       fd_votor_timeout_t entries emitted into the out-buffer; the tile
       attaches the actual deadlines (DELTA_TIMEOUT + DELTA_FIRST_SLICE for the
       crashed-leader timeout, then DELTA_BLOCK steps for the per-slot
       timeouts).

   The per-slot SlotState machine and all the Votor methods (set_timeouts,
   try_notar, try_final, try_skip_window, check_pending_blocks, prune, the
   genesis prepopulation, the bad_window slashing invariant) are reproduced
   faithfully.

   Per the project conventions the slot map is built directly on the
   lowest-level util generics (fd_pool + fd_map_chain keyed by slot).  fd_votor
   is a relocatable wksp object following the canonical fd_ghost layout. */

#include "../fd_alpenglow_base.h"
#include "fd_vote.h"
#include "fd_cert.h"
#include "fd_epoch_info.h"

/* FD_VOTOR_PARENTS_READY_MAX bounds the inline parents_ready set on each
   SlotState.  In the Rust reference parents_ready is an unbounded BTreeSet of
   (parent_slot, parent_hash) pairs, but in practice only a small number of
   distinct valid parents are ever ParentReady'd for a single slot (one per
   competing fork the leader could have built on).  We bound it inline. */

#define FD_VOTOR_PARENTS_READY_MAX (8UL)

/* fd_consensus_message_t mirrors the Rust ConsensusMessage (the All2All
   payload): the tagged union of a single Vote or a single Cert that Votor
   broadcasts.  The C handlers append these into the out-buffer instead of
   calling all2all.broadcast. */

#define FD_CONSENSUS_MESSAGE_VOTE (0U)
#define FD_CONSENSUS_MESSAGE_CERT (1U)

struct fd_consensus_message {
  uint discriminant; /* FD_CONSENSUS_MESSAGE_VOTE / FD_CONSENSUS_MESSAGE_CERT */
  union {
    fd_ag_vote_t vote;
    fd_cert_t cert;
  } inner;
};
typedef struct fd_consensus_message fd_consensus_message_t;

/* fd_votor_timeout_t mirrors the Rust VotorTimeout enum: the internal timeout
   events Votor schedules for itself.  In the C port set_timeouts and
   handle_cert_created append these into the out-buffer; the tile attaches the
   wall-clock deadline and feeds them back into fd_votor_handle_timeout_event
   when they fire.

     FD_VOTOR_TIMEOUT_TIMEOUT         - regular per-slot timeout (Timeout)
     FD_VOTOR_TIMEOUT_CRASHED_LEADER  - early crashed-leader timeout
                                        (TimeoutCrashedLeader) */

#define FD_VOTOR_TIMEOUT_TIMEOUT        (0U)
#define FD_VOTOR_TIMEOUT_CRASHED_LEADER (1U)

struct fd_votor_timeout {
  uint  kind; /* FD_VOTOR_TIMEOUT_TIMEOUT / FD_VOTOR_TIMEOUT_CRASHED_LEADER */
  ulong slot;
};
typedef struct fd_votor_timeout fd_votor_timeout_t;

/* fd_votor_out_t is the caller-provided out-buffer the handlers append to.
   msgs[0,msg_cnt) collects the votes/certs to broadcast (in emission order)
   and timeouts[0,timeout_cnt) collects the timeouts to schedule.  The caller
   sets the *_max capacities and resets *_cnt to 0 before invoking a handler;
   on return *_cnt reflects everything appended by that handler.

   The handlers FD_TEST that they never overflow the provided capacities, so
   the caller must size the buffers generously (a single handler invocation can
   emit at most O(SLOTS_PER_WINDOW) votes plus, via set_timeouts, one
   crashed-leader timeout and SLOTS_PER_WINDOW per-slot timeouts, plus the
   Standstill bundle which the caller bounds). */

struct fd_votor_out {
  fd_consensus_message_t * msgs;
  ulong                    msg_cnt;
  ulong                    msg_max;
  fd_votor_timeout_t *     timeouts;
  ulong                    timeout_cnt;
  ulong                    timeout_max;
};
typedef struct fd_votor_out fd_votor_out_t;

/* fd_votor_pool_event_t mirrors the Rust PoolEvent enum (the events Votor
   consumes from Pool).  Named after the Rust variants:

     ParentReady { slot, parent }    - a new valid parent for slot is ready
     SafeToNotar((slot, hash))       - safe to notar-fallback for (slot, hash)
     SafeToSkip(slot)                - safe to skip-fallback for slot
     CertCreated(cert)               - a new certificate was created
     Standstill(slot, certs, votes)  - recovery bundle (re-broadcast)

   For Standstill the recovery bundle is supplied as a slice of
   fd_consensus_message_t (certs first, then votes, in the order they should be
   re-broadcast); the C handler simply copies them into the out-buffer. */

#define FD_VOTOR_POOL_EVENT_PARENT_READY (0U)
#define FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR (1U)
#define FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP  (2U)
#define FD_VOTOR_POOL_EVENT_CERT_CREATED  (3U)
#define FD_VOTOR_POOL_EVENT_STANDSTILL    (4U)

struct fd_votor_pool_event {
  uint discriminant; /* FD_VOTOR_POOL_EVENT_* */
  union {
    struct { ulong slot; fd_block_id_t parent; }     parent_ready;  /* ParentReady */
    fd_block_id_t                                    safe_to_notar; /* SafeToNotar */
    ulong                                            safe_to_skip;  /* SafeToSkip  */
    fd_cert_t                                        cert_created;  /* CertCreated */
    struct {
      ulong                          slot;
      fd_consensus_message_t const * bundle; /* certs then votes */
      ulong                          bundle_cnt;
    } standstill;                                                   /* Standstill  */
  } inner;
};
typedef struct fd_votor_pool_event fd_votor_pool_event_t;

/* fd_votor_blockstore_event_t mirrors the Rust BlockstoreEvent enum (the
   events Votor consumes from Blockstore).  Named after the Rust variants:

     FirstShred(slot)               - first shred for slot received
     InvalidBlock(slot)             - leader produced an invalid block
     Block { slot, block_id,
             parent_block_id }      - a complete valid block (BlockInfo) is
                                      available.  The Rust BlockInfo carries
                                      {hash, parent:(parent_slot,parent_hash)};
                                      here block_id = (slot,hash) and
                                      parent_block_id = (parent_slot,parent_hash). */

#define FD_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED   (0U)
#define FD_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK (1U)
#define FD_VOTOR_BLOCKSTORE_EVENT_BLOCK         (2U)

struct fd_votor_blockstore_event {
  uint discriminant; /* FD_VOTOR_BLOCKSTORE_EVENT_* */
  union {
    ulong first_shred;   /* FirstShred   */
    ulong invalid_block; /* InvalidBlock */
    struct {
      ulong         slot;
      fd_block_id_t block_id;
      fd_block_id_t parent_block_id;
    } block;             /* Block        */
  } inner;
};
typedef struct fd_votor_blockstore_event fd_votor_blockstore_event_t;

/* fd_votor_slot_state_t is the per-slot voting state (Rust SlotState),
   one entry per slot in the slots pool/map.  It is an aligned(128) pool
   element keyed by slot (mirroring the canonical fd_ghost_blk_t layout):
   slot is the map key, next is reserved for fd_pool / fd_map_chain. */

struct __attribute__((aligned(128UL))) fd_votor_slot_state {
  ulong slot; /* map key (the slot this state tracks)                     */
  ulong next; /* reserved for internal use by fd_pool and fd_map_chain    */

  int   voted;                /* voted notar or skip for this slot              */
  int   has_voted_notar;      /* whether voted_notar holds a hash               */
  fd_hash_t voted_notar;      /* the hash we voted notar for (if has_voted_notar)*/
  int   bad_window;           /* the 'bad window' flag (load-bearing slashing
                                 invariant: permanently disables Final)        */
  int   has_block_notarized;  /* whether block_notarized holds a hash           */
  fd_hash_t block_notarized;  /* hash of the block with a notar cert (not
                                 notar-fallback)                               */

  /* parents_ready: valid parents for this slot as (parent_slot,parent_hash)
     pairs (Rust BTreeSet<BlockId>).  Bounded inline. */
  ulong         parents_ready_cnt;
  fd_block_id_t parents_ready[ FD_VOTOR_PARENTS_READY_MAX ];

  int   received_shred;       /* received >=1 shred for this slot                */

  /* pending_block: a block waiting for previous slots to be notarized
     (Rust Option<BlockInfo>).  block_id = (slot,hash), parent_block_id =
     (parent_slot,parent_hash). */
  int           has_pending_block;
  fd_block_id_t pending_block_id;
  fd_block_id_t pending_parent_block_id;

  int   retired;              /* Votor is done with this slot ('ItsOver')        */
};
typedef struct fd_votor_slot_state fd_votor_slot_state_t;

/* fd_votor_t is the relocatable, wksp-resident top-level Votor object.
   Following the canonical fd_ghost layout it holds only ulong gaddrs (for the
   slots pool and map) plus inline scalar state.  The voting_key is embedded
   inline (it is small and fixed-size). */

struct fd_votor;
typedef struct fd_votor fd_votor_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_votor_{align,footprint} return the required alignment and footprint of a
   memory region suitable for use as a votor tracking up to slot_max live
   slots' state at once. */

FD_FN_CONST ulong
fd_votor_align( void );

FD_FN_CONST ulong
fd_votor_footprint( ulong slot_max );

/* fd_votor_new formats an unused memory region for use as a votor.  shmem is a
   non-NULL pointer to this region in the local address space with the required
   footprint and alignment. voting_key our BLS secret key used to sign votes, and seed the map hash
   seed.  Pre-populates the dummy genesis block's SlotState and emits the
   genesis window's timeouts into out (mirroring Votor::new, which calls
   set_timeouts(0)).  Returns shmem on success and NULL on failure (logs). */

void *
fd_votor_new( void *                 shmem,
              ulong                  slot_max,
              fd_aggsig_sk_t const * voting_key,
              ulong                  seed,
              fd_votor_out_t *       out );

/* fd_votor_join joins the caller to the votor.  Returns a local-address-space
   handle on success and NULL on failure (logs). */

fd_votor_t *
fd_votor_join( void * shvotor );

/* fd_votor_leave leaves a current local join.  Returns the underlying shared
   memory region on success and NULL on failure (logs). */

void *
fd_votor_leave( fd_votor_t const * votor );

/* fd_votor_delete unformats a memory region used as a votor.  Returns the
   underlying shared memory region on success and NULL on failure (logs). */

void *
fd_votor_delete( void * shvotor );

/* Accessors */

/* fd_votor_highest_final_cert_slot returns the highest slot for which we have
   seen a (slow) final or fast-final cert (Votor::highest_final_cert_slot). */

FD_FN_PURE ulong
fd_votor_highest_final_cert_slot( fd_votor_t const * votor );

/* fd_votor_slot_state queries the per-slot state for slot, or NULL if none is
   currently retained (mirrors Votor::slots.get).  The returned pointer is
   valid until the next mutating handler call. */

fd_votor_slot_state_t const *
fd_votor_slot_state( fd_votor_t const * votor, ulong slot );

/* Event handlers.  Each appends its outgoing votes/certs and scheduled
   timeouts to out (the caller resets out->*_cnt to 0 first).  validators /
   validator_cnt are the current epoch's validator set, used only to fill in
   the per-signer stake bitmask length when re-aggregating; they may be the
   fd_epoch_info_validators(...) array. */

/* fd_votor_handle_pool_event mirrors Votor::handle_pool_event (which dispatches
   to handle_cert_created for CertCreated). */

void
fd_votor_handle_pool_event( fd_votor_t *                  votor,
                            fd_votor_pool_event_t const * event,
                            fd_votor_out_t *              out );

/* fd_votor_handle_blockstore_event mirrors Votor::handle_blockstore_event. */

void
fd_votor_handle_blockstore_event( fd_votor_t *                        votor,
                                  fd_votor_blockstore_event_t const * event,
                                  fd_votor_out_t *                    out );

/* fd_votor_handle_timeout_event mirrors Votor::handle_timeout_event. */

void
fd_votor_handle_timeout_event( fd_votor_t *               votor,
                               fd_votor_timeout_t const * event,
                               fd_votor_out_t *           out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_fd_votor_h */
