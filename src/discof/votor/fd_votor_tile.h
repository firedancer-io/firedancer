#ifndef HEADER_fd_src_discof_votor_fd_votor_tile_h
#define HEADER_fd_src_discof_votor_fd_votor_tile_h

/* The Votor tile drives the Alpenglow consensus core (ag_votor + ag_pool)
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
   ag_block_id_t (a (Slot, BlockHash) pair). */

#include "../../alpenglow/consensus/ag_vote.h"
#include "../../alpenglow/consensus/ag_cert.h"
#include "../../alpenglow/ag_alpenglow_base.h"
#include "../../disco/topo/fd_topo.h"

/* Three kinds of message flow through the votor tile, and each one flows
   in BOTH directions -- the same FD_VOTOR_SIG_* value tags the inbound
   frag and the outbound one, so handle_slot / handle_cert / handle_vote
   are the tile's whole consensus ingress surface:

   - FD_VOTOR_SIG_VOTE : in  a peer's vote, over QUIC.
                         out a vote the votor cast, to All2All-broadcast.
   - FD_VOTOR_SIG_CERT : in  a peer's cert over QUIC, or one replay lifted
                             out of a block footer.
                         out a cert the pool built, to All2All-broadcast.
   - FD_VOTOR_SIG_SLOT : in  replay completed (or killed) a slot.
                         out 1-to-1 with the completion of a replayed slot:
                             echoes the replay_slot/replay_bank_idx back to
                             replay (so it can drop the bank refcount) and
                             tells replay/poh which fork to reset onto.

   The remaining sigs are outbound only:

   - FD_VOTOR_SIG_NOTARFB   : a block version that gathered (fallback) notar
                              votes or certs and that we may not have locally;
                              repair fetches it.
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
#define FD_VOTOR_SIG_SLOT      (2UL)
#define FD_VOTOR_SIG_NOTARFB   (3UL)
#define FD_VOTOR_SIG_FINALIZED (4UL)
#define FD_VOTOR_SIG_ROOTED    (5UL)

/* FD_VOTOR_SIG_RX is OR'd into the sig of a VOTE or CERT frag that the
   tile RECEIVED, and is clear on one it originated.  The kind says WHAT
   the message is and is the same in both directions; this says which way
   this particular frag went.

   It matters for certs especially: a cert the pool built by aggregating
   votes it collected is a different event from the same cert arriving
   ready-made from a peer, and the payload alone cannot tell them apart
   (unlike a vote, where the signer rank identifies us).

   Only VOTE and CERT ever carry it, so a consumer matching SLOT /
   NOTARFB / FINALIZED / ROOTED compares against the bare value as
   before; one that cares about votes or certs masks it off with
   FD_VOTOR_SIG_KIND. */

#define FD_VOTOR_SIG_RX        (0x100UL)
#define FD_VOTOR_SIG_KIND(sig) ( (sig) & 0xFFUL )

/* fd_votor_slot_done_t is published once per completed replay slot.  It
   mirrors the relevant subset of fd_tower_slot_done_t: the replay slot and
   bank_idx to echo back, and the fork (slot + block_id) to reset the leader
   pipeline onto. */

struct ag_votor_slot_done {
  ulong     replay_slot;
  ulong     replay_bank_idx;
  ulong     reset_slot;
  fd_hash_t reset_block_id;
};
typedef struct ag_votor_slot_done ag_votor_slot_done_t;

struct ag_votor_notar_slot {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct ag_votor_notar_slot ag_votor_notar_fallback_t;
typedef struct ag_votor_notar_slot ag_votor_finalized_t;
typedef struct ag_votor_notar_slot ag_votor_rooted_t;

/* ag_votor_finalized_t and ag_votor_rooted_t carry a (slot, block_id)
   -- used for both FD_VOTOR_SIG_FINALIZED (consensus finalized the
   slot) and FD_VOTOR_SIG_ROOTED (the bank root advanced to the slot).
   Same shape; the sig distinguishes the meaning. */
union ag_votor_msg {
  ag_vote_t                 vote;      /* FD_VOTOR_SIG_VOTE      */
  ag_cert_t                 cert;      /* FD_VOTOR_SIG_CERT      */
  ag_votor_slot_done_t      slot_done; /* FD_VOTOR_SIG_SLOT      */
  ag_votor_notar_fallback_t notar_fallback; /* FD_VOTOR_SIG_NOTARFB */
  ag_votor_finalized_t      finalized; /* FD_VOTOR_SIG_FINALIZED */
  ag_votor_rooted_t         rooted;    /* FD_VOTOR_SIG_ROOTED    */
};
typedef union ag_votor_msg ag_votor_msg_t;

/* fd_votor_consensus_msg_t is the staged wire layout for an Alpenglow
   ConsensusMessage carried over the GOSSIP in link.  FD gossip does not yet
   transport Alpenglow messages, so this is a fixed-layout placeholder for the
   ingest path: a tagged union of one Vote or one Cert.  The kind
   matches ag_consensus_message_t (AG_CONSENSUS_MESSAGE_{VOTE,CERT}).

   TODO: once FD gossip carries Alpenglow messages natively, this should be
   replaced by the real on-wire (de)serialization (ag_aggsig_deserialize for
   the embedded signatures etc.). */

#define FD_VOTOR_CONSENSUS_MSG_VOTE (0U)
#define FD_VOTOR_CONSENSUS_MSG_CERT (1U)

struct fd_votor_consensus_msg {
  uint kind; /* FD_VOTOR_CONSENSUS_MSG_{VOTE,CERT} */
  union {
    ag_vote_t vote;
    ag_cert_t cert;
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
