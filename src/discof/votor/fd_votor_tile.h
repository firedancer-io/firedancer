#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

/* The Votor tile drives the Alpenglow consensus core (fd_votor + fd_pool)
   the same way the Tower tile drives TowerBFT (fd_tower + fd_ghost).  It is
   structurally a clone of fd_tower_tile.c: it consumes the same replay /
   gossip / epoch / ipecho frags, but instead of running the slot-based
   TowerBFT fork-choice rule it feeds Alpenglow blocks/votes/certs into the
   consensus core and re-broadcasts the votes and certs the core emits.

   Unlike TowerBFT, Alpenglow votes are not on-chain vote-account
   transactions: they are standalone BLS consensus messages (Vote / Cert)
   gossiped directly between validators (the "All2All" broadcast in the Rust
   reference).  So the Votor tile reads NO accountsDB / banks vote-account
   state, keeps NO tower checkpoint files, and maintains NO authorized-voter
   table.  Each validator signs with a single fixed BLS voting key.

   In general, like Tower, Votor uses "block_id" (slot, merkle-root hash) as
   the canonical identifier for a block.  In the Alpenglow core this is the
   fd_block_id_t (a (Slot, BlockHash) pair). */

#include "../../alpenglow/consensus/fd_vote.h"
#include "../../alpenglow/consensus/fd_cert.h"
#include "../../alpenglow/fd_alpenglow_base.h"
#include "../../disco/topo/fd_topo.h"

/* The out link votor_out carries one fd_votor_msg_t per frag, tagged with
   one of the FD_VOTOR_SIG_* sigs below.

   - FD_VOTOR_SIG_VOTE      : broadcast a single Alpenglow vote (consumed by
                              the gossip / send tile and All2All-broadcast).
   - FD_VOTOR_SIG_CERT      : broadcast a single Alpenglow certificate.
   - FD_VOTOR_SIG_SLOT_DONE : 1-to-1 with the completion of a replayed slot.
                              Echoes the replay_slot/replay_bank_idx back to
                              replay (so it can drop the bank refcount) and
                              tells replay/poh which fork to reset onto.
   - FD_VOTOR_SIG_FINALIZED : consensus finalized a slot (a final / fast-final
                              cert).  Cert-driven; fired as soon as finalization
                              advances, independent of whether we have replayed
                              the slot.  A notification, not a root command.
   - FD_VOTOR_SIG_ROOTED    : the bank root advanced -- the highest slot that is
                              BOTH finalized AND replayed (its bank is frozen).
                              This is the "root your bank here" command for
                              replay; it lags FINALIZED during catchup. */

#define FD_VOTOR_SIG_VOTE      (0UL)
#define FD_VOTOR_SIG_CERT      (1UL)
#define FD_VOTOR_SIG_SLOT_DONE (2UL)
#define FD_VOTOR_SIG_FINALIZED (3UL)
#define FD_VOTOR_SIG_ROOTED    (4UL)

/* fd_votor_slot_done_t is published once per completed replay slot.  It
   mirrors the relevant subset of fd_tower_slot_done_t: the replay slot and
   bank_idx to echo back, and the fork (slot + block_id) to reset the leader
   pipeline onto. */

struct fd_votor_slot_done {
  ulong     replay_slot;
  ulong     replay_bank_idx;
  ulong     reset_slot;
  fd_hash_t reset_block_id;
};
typedef struct fd_votor_slot_done fd_votor_slot_done_t;

/* fd_votor_finalized_t and fd_votor_rooted_t carry a (slot, block_id)
   -- used for both FD_VOTOR_SIG_FINALIZED (consensus finalized the
   slot) and FD_VOTOR_SIG_ROOTED (the bank root advanced to the slot).
   Same shape; the sig distinguishes the meaning. */

struct fd_votor_finalized {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_finalized fd_votor_finalized_t;
struct fd_votor_rooted {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_votor_rooted fd_votor_rooted_t;

union fd_votor_msg {
  fd_ag_vote_t         vote;      /* FD_VOTOR_SIG_VOTE      */
  fd_cert_t            cert;      /* FD_VOTOR_SIG_CERT      */
  fd_votor_slot_done_t slot_done; /* FD_VOTOR_SIG_SLOT_DONE */
  fd_votor_finalized_t finalized; /* FD_VOTOR_SIG_FINALIZED */
  fd_votor_rooted_t    rooted;    /* FD_VOTOR_SIG_ROOTED    */
};
typedef union fd_votor_msg fd_votor_msg_t;

/* fd_votor_consensus_msg_t is the staged wire layout for an Alpenglow
   ConsensusMessage carried over the GOSSIP in link.  FD gossip does not yet
   transport Alpenglow messages, so this is a fixed-layout placeholder for the
   ingest path: a tagged union of one Vote or one Cert.  The discriminant
   matches fd_consensus_message_t (FD_CONSENSUS_MESSAGE_{VOTE,CERT}).

   TODO: once FD gossip carries Alpenglow messages natively, this should be
   replaced by the real on-wire (de)serialization (fd_aggsig_deserialize for
   the embedded signatures etc.). */

#define FD_VOTOR_CONSENSUS_MSG_VOTE (0U)
#define FD_VOTOR_CONSENSUS_MSG_CERT (1U)

struct fd_votor_consensus_msg {
  uint discriminant; /* FD_VOTOR_CONSENSUS_MSG_{VOTE,CERT} */
  union {
    fd_ag_vote_t vote;
    fd_cert_t cert;
  } inner;
};
typedef struct fd_votor_consensus_msg fd_votor_consensus_msg_t;

/* define a minheap for the timeouts */
struct fd_timeout {
  ulong slot;
  long  ts;
  uint  kind;
  uint  left;
  uint  right;
};
typedef struct fd_timeout fd_timeout_t;

#define HEAP_NAME fd_timeout_heap
#define HEAP_T    fd_timeout_t
#define HEAP_LT(e0,e1) ( ((e0)->ts <= (e1)->ts) )
#define HEAP_IDX_T uint
#include "../../util/tmpl/fd_heap.c"

#define POOL_NAME  fd_timeout_pool
#define POOL_T     fd_timeout_t
#define POOL_IDX_T uint
#define POOL_NEXT  left
#include "../../util/tmpl/fd_pool.c"

extern fd_topo_run_tile_t fd_tile_votor;

#endif /* HEADER_fd_src_discof_votor_fd_votor_tile_h */
