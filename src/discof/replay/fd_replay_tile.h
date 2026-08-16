#ifndef HEADER_fd_src_discof_replay_fd_replay_tile_h
#define HEADER_fd_src_discof_replay_fd_replay_tile_h

/* Banks and Reasm
   =================

   OVERVIEW

   Reasm maintains a tree of FEC sets organized as a main tree (rooted
   at the published root) plus orphan trees.  Each FEC set in the
   connected tree may be associated with a bank via bank_idx, or be
   still unreplayed.  In general, reasm tries to approximate the state
   of banks as closely as possible.  It's inexact, because reasm is
   stored at the FEC unit, while banks are stored at the slot unit.

   When reasm delivers a FEC set (via fd_reasm_pop), the replay tile
   processes it by assigning it a bank.  If it's the first FEC in a
   slot (fec_set_idx==0), a new bank is provisioned from the parent's
   bank.  Subsequent FECs in the same slot inherit the bank_idx from
   the preceding FEC.  This means all FEC sets within a single slot
   share the same bank_idx, with the exception of equivocating FECs.

   PUBLISHING (ROOT ADVANCEMENT)

   When tower sends a new consensus root, replay advances the
   published root along the rooted fork as far as possible.  A block
   on the rooted fork is safe to prune when it and all minority fork
   subtrees branching from it have refcnt 0.  Publishing calls
   fd_reasm_publish to prune the reasm tree (and the store) of any
   FEC sets that do not descend from the new root.

   REASM EVICTION (POOL-PRESSURE EVICTION)

   When the reasm pool is nearly full (1 free element remaining) and a
   new FEC needs to be inserted, reasm runs its eviction policy to free
   space.  The eviction in general prioritizes orphans first, and then
   frontier slots that are incomplete.

   If eviction succeeds, the evicted chain is returned as a linked
   list of pool elements (removed from maps but still acquired in
   the pool).  The replay tile is responsible for:
     1. Publishing each evicted FEC to repair (REPLAY_SIG_REASM_EVICTED)
        so repair can re-request the data.
     2. Releasing each evicted element back to the reasm pool before
        the next insert.

   It's important to note that replay bank eviction is NOT coupled with
   reasm FEC eviction.  Reasm FEC eviction is triggered by the reasm pool
   being full, and is independent of the replay bank eviction.  Reasm
   FEC eviction is triggered by the reasm pool being full while banks
   eviction is triggered by the banks being full and the scheduler
   being drained.

   By evicting and publishing evicted FECs to repair, replay is
   attempting a "go-around" strategy to ensure progress is made even
   when memory pressure is high.  An evicted FEC - if valid - will be
   requested by repair and eventually re-delivered to replay, where
   hopefully by then there will be pool capacity to insert and replay
   the FEC.

   SNAPSHOT PRODUCTION

   Snapshot production is either periodically scheduled (driven by
   replay tile) or externally requested (through admin tile).  The
   replay tile stops compaction (via snapshot_sync) and rooting until
   the snapshot is created. */

#include "../poh/fd_poh_tile.h"
#include "../../alpenglow/consensus/ag_cert.h"
#include "../../disco/tiles.h"

#define REPLAY_SIG_SLOT_COMPLETED (0)
#define REPLAY_SIG_SLOT_DEAD      (1)
#define REPLAY_SIG_ROOT_ADVANCED  (2)
#define REPLAY_SIG_RESET          (3)
#define REPLAY_SIG_BECAME_LEADER  (4)
#define REPLAY_SIG_OC_ADVANCED    (5)
#define REPLAY_SIG_TXN_EXECUTED   (6)
#define REPLAY_SIG_REASM_EVICTED  (7)
#define REPLAY_SIG_WFS_DONE       (8)
#define REPLAY_SIG_DROP_BANK_REF  (9)
#define REPLAY_SIG_SNAP_START    (10)
#define REPLAY_SIG_FINAL_CERT    (11)
#define REPLAY_SIG_AG_COMPLETE_BLOCK (12) /* alpenglow: close the block in progress */
#define REPLAY_SIG_AG_FOOTER         (13) /* alpenglow: the serialized BlockFooter */
#define REPLAY_SIG_CONSENSUS_UPDATE  (14) /* alpenglow: consensus state for the gui */

/* replay_out mcache seq[i] slots */
#define REPLAY_SYNC_SEQ  (0UL) /* mcache->seq[0]: recently published seq no */
#define REPLAY_SYNC_SNAP (1UL) /* mcache->seq[1]: last published snap msg (acq-rel) */

/* fd_replay_slot_completed promises that it will deliver at most 2
   frags for a given slot (at most 2 equivocating blocks).  The first
   block is the first one we replay to completion.  The second version
   (if there is) is always the confirmed equivocating block.  This
   guarantee is provided by fd_reasm. */

struct fd_replay_slot_completed {
  ulong slot;
  ulong root_slot;
  ulong storage_slot;
  ulong epoch;
  ulong slot_in_epoch;
  ulong slots_per_epoch;
  ulong block_height;
  ulong parent_slot;

  fd_hash_t block_id;        /* block id (last FEC set's merkle root) of the slot received from replay */
  fd_hash_t parent_block_id; /* parent block id of the slot received from replay */
  fd_hash_t bank_hash;       /* bank hash of the slot received from replay */
  fd_hash_t block_hash;      /* last microblock header hash of slot received from replay */
  ulong     transaction_count;   /* since genesis */

  struct {
    double initial;
    double terminal;
    double taper;
    double foundation;
    double foundation_term;
  } inflation;

  struct {
    ulong lamports_per_uint8_year;
    double exemption_threshold;
    uchar burn_percent;
  } rent;

  /* Reference to the bank for this completed slot. */
  ulong bank_idx;
  ulong bank_seq;
  ulong parent_bank_idx;   /* parent bank's pool index (ULONG_MAX if none) */
  ulong parent_bank_seq;   /* parent bank's app-wide seq    (ULONG_MAX if none) */
  fd_accdb_fork_id_t accdb_fork_id;

  long first_fec_set_received_nanos;      /* timestamp when replay received the first fec of the slot from turbine or repair */
  long preparation_begin_nanos;           /* timestamp when replay began preparing the state to begin execution of the slot */
  long first_transaction_scheduled_nanos; /* timestamp when replay first sent a transaction to be executed */
  long last_transaction_finished_nanos;   /* timestamp when replay received the last execution completion */
  long completion_time_nanos;             /* timestamp when replay completed finalizing the slot and notified tower */

  int is_leader; /* whether we were leader for this slot */
  ulong identity_balance;

  /* since slot start, default ULONG_MAX */
  ulong vote_success;
  ulong vote_failed;
  ulong nonvote_success;
  ulong nonvote_failed;

  ulong transaction_fee;
  ulong priority_fee;
  ulong tips;
  ulong shred_cnt;

  struct {
    ulong block_cost;
    ulong vote_cost;
    ulong allocated_accounts_data_size;
    ulong block_cost_limit;
    ulong vote_cost_limit;
    ulong account_cost_limit;
  } cost_tracker;
};

typedef struct fd_replay_slot_completed fd_replay_slot_completed_t;

struct fd_replay_slot_dead {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_replay_slot_dead fd_replay_slot_dead_t;

struct fd_replay_oc_advanced {
  ulong slot;
  ulong bank_idx;
  ulong bank_seq;  /* fork discriminator of the optimistically-confirmed bank */
};
typedef struct fd_replay_oc_advanced fd_replay_oc_advanced_t;

struct fd_replay_root_advanced {
  ulong     bank_idx;
  ulong     bank_seq;  /* fork discriminator of the rooted bank */
  ulong     slot;
  fd_hash_t bank_hash;
};
typedef struct fd_replay_root_advanced fd_replay_root_advanced_t;

struct fd_replay_txn_executed {
  fd_txn_p_t txn[ 1 ];
  int is_committable;
  int is_fees_only;
  int txn_err;
  long  tick_parsed;
  long  tick_sigverify_disp;
  long  tick_sigverify_done;
  long  tick_exec_disp;
  long  tick_exec_done;
};
typedef struct fd_replay_txn_executed fd_replay_txn_executed_t;

struct fd_replay_fec_evicted {
  fd_hash_t mr;
  ulong     slot;
  uint      fec_set_idx;
  ulong     bank_idx;
};
typedef struct fd_replay_fec_evicted fd_replay_fec_evicted_t;

/* Only rpc needs to consume this message since tower holds refcnts
   transiently and will drop them without a further trigger from the
   replay tile and the resolv tile holds onto a bank reference based on
   the root, which will never be forced to drop its bank reference. */
struct fd_replay_drop_bank_ref {
  ulong bank_idx;
};
typedef struct fd_replay_drop_bank_ref fd_replay_drop_bank_ref_t;

/* The replay tile broadcasts fd_replay_snap_start_t
   (REPLAY_SIG_SNAP_START) just before starting snapshot creation. */

struct fd_replay_snap_start {
  ulong bank_idx;
  ulong base_slot;
  ulong slot; /* ==base_slot implies full snapshot, else incremental */
};
typedef struct fd_replay_snap_start fd_replay_snap_start_t;

/* fd_replay_final_cert carries the finalization cert parsed out of an
   Alpenglow block footer, already verified by replay.  cert_cnt is 1
   (FastFinal) or 2 (Final + Notar, slow finalization). */
struct fd_replay_final_cert {
  ulong     slot;     /* the block whose footer carried the cert */
  ulong     cert_cnt;
  ag_cert_t certs[ 2 ];
};
typedef struct fd_replay_final_cert fd_replay_final_cert_t;

/* ALPENGLOW.  Sent to poh when the deadline for the block in progress
   has passed, or pack has run dry, asking it to close the block.  poh
   does not close it immediately: it first waits for every microblock
   pack accounted for to land, because registering the tick freezes the
   bank and a microblock still in flight would then commit against a
   frozen bank. */
struct fd_replay_ag_complete_block {
  ulong slot;
};
typedef struct fd_replay_ag_complete_block fd_replay_ag_complete_block_t;

/* ALPENGLOW.  The serialized BlockFooter, built by replay once the tick
   poh sent with FD_POH_SIG_AG_TICK has been registered and the bank has
   frozen.  poh publishes it, then the tick, and the block is over. */
struct fd_replay_ag_footer {
  ulong slot;
  ulong footer_sz;
  uchar footer[ FD_POH_AG_MARKER_MAX ];
};
typedef struct fd_replay_ag_footer fd_replay_ag_footer_t;

/* ALPENGLOW.  The consensus summary the gui needs, and the alpenglow
   counterpart of the fd_tower_slot_done_t the tower tile sends the gui
   directly over tower_out.  There is no votor_gui link: it comes from
   replay because the gui keys every record on (slot, bank_seq) and
   replay owns the block_id -> bank mapping that votor's messages, which
   name blocks only by block_id, do not have.  The same indirection
   already carries the optimistically-confirmed level under TowerBFT
   (fd_tower_slot_confirmed_t -> REPLAY_SIG_OC_ADVANCED).

   Riding on replay_out also fixes the ordering for free: the gui learns
   a slot exists from REPLAY_SIG_SLOT_COMPLETED on this same link, which
   is necessarily published before votor can respond to it, so no
   deferral is needed the way it is for tower_out.

   Each of the three slots is ULONG_MAX when this update does not carry
   it.  vote_slot and is_voting are whatever votor last reported, which
   is nothing at all until the first slot completes -- an update driven
   by a certificate can precede that, and reports not voting until the
   first slot_done corrects it. */

struct fd_replay_consensus_update {
  ulong replay_slot;        /* the slot votor just processed a completion for */
  ulong replay_bank_seq;
  ulong reset_slot;         /* the fork the leader pipeline was reset onto    */
  ulong reset_bank_seq;
  ulong finalized_slot;     /* newly finalized by certificate                 */
  ulong finalized_bank_seq;
  ulong vote_slot;          /* highest slot we cast a vote in, ULONG_MAX if none */
  int   is_voting;
};
typedef struct fd_replay_consensus_update fd_replay_consensus_update_t;

union fd_replay_message {
  fd_replay_slot_completed_t    slot_completed;
  fd_replay_root_advanced_t     root_advanced;
  fd_replay_oc_advanced_t       oc_advanced;
  fd_poh_reset_t                reset;
  fd_became_leader_t            became_leader;
  fd_replay_txn_executed_t      txn_executed;
  fd_replay_fec_evicted_t       reasm_evicted;
  fd_replay_drop_bank_ref_t     drop_bank_ref;
  fd_replay_final_cert_t        final_cert;
  fd_replay_ag_complete_block_t ag_complete_block;
  fd_replay_ag_footer_t         ag_footer;
  fd_replay_consensus_update_t  consensus_update;
};

typedef union fd_replay_message fd_replay_message_t;

#endif /* HEADER_fd_src_discof_replay_fd_replay_tile_h */
