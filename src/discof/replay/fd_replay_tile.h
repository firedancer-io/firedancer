#ifndef HEADER_fd_src_discof_replay_fd_replay_tile_h
#define HEADER_fd_src_discof_replay_fd_replay_tile_h

/* Banks and Reasm
   =================

   OVERVIEW

   Reasm and banks are tightly coupled.  Reasm maintains a tree of FEC
   sets organized as a main tree (rooted at the published root) plus
   orphan trees.  Each FEC set in the connected tree may be associated
   with a bank via bank_idx, or be still unreplayed.  In general, reasm
   tries to approximate the state of banks as closely as possible.  It's
   inexact, because reasm is stores at the FEC unit, while banks are
   stored at the slot unit.

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
   frontier slots that are incomplete.  Evicted orphans has no effect on
   the banks; if they were orphans, then banks had no knowledge of them.

   If eviction succeeds, the evicted chain is returned as a linked
   list of pool elements (removed from maps but still acquired in
   the pool).  The replay tile is responsible for:
     1. If the evicted chain had a valid bank_idx, marking that bank
        dead and abandoning it in the scheduler.
     2. Publishing each evicted FEC to repair (REPLAY_SIG_REASM_EVICTED)
        so repair can re-request the data.
     3. Releasing each evicted element back to the reasm pool before
        the next insert.

   BANKS-DRIVEN EVICTION

   Separately from reasm pool pressure, when banks are full (no free
   bank slots) and the scheduler is drained, replay itself evicts
   frontier banks to make room.  This works by:
     1. Iterating over frontier (leaf) banks.
     2. Marking each as dead and abandoning it in the scheduler.
     3. Calling fd_reasm_remove on the corresponding FEC chain in
        reasm, which walks up the tree to the bank boundary (slot
        boundary or equivocation point) and removes the chain.
     4. Same process happens as above where evicted FECs are published
        to repair.

   By evicting and publishing evicted FECs to repair, replay is
   attempting a "go-around" strategy to ensure progress is made even
   when memory pressure is high.  An evicted FEC - if valid - will be
   requested by repair and eventually re-delivered to replay, where
   hopefully by then there will be pool capacity to insert and replay
   the FEC. */

#include "../poh/fd_poh_tile.h"
#include "../../disco/tiles.h"
#include "../reasm/fd_reasm.h"
#include "../../flamenco/types/fd_types_custom.h"

#define REPLAY_SIG_SLOT_COMPLETED (0)
#define REPLAY_SIG_SLOT_DEAD      (1)
#define REPLAY_SIG_ROOT_ADVANCED  (2)
#define REPLAY_SIG_RESET          (3)
#define REPLAY_SIG_BECAME_LEADER  (4)
#define REPLAY_SIG_OC_ADVANCED    (5)
#define REPLAY_SIG_TXN_EXECUTED   (6)
#define REPLAY_SIG_REASM_EVICTED  (7)

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

  /* Reference to the bank for this completed slot.  TODO: We can
     eliminate non-timestamp fields and have consumers just use
     bank_idx. */
  ulong bank_idx;

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
};
typedef struct fd_replay_oc_advanced fd_replay_oc_advanced_t;

struct fd_replay_root_advanced {
  ulong bank_idx;
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


union fd_replay_message {
  fd_replay_slot_completed_t  slot_completed;
  fd_replay_root_advanced_t   root_advanced;
  fd_replay_oc_advanced_t     oc_advanced;
  fd_poh_reset_t              reset;
  fd_became_leader_t          became_leader;
  fd_replay_txn_executed_t    txn_executed;
  fd_replay_fec_evicted_t          reasm_evicted;
};

typedef union fd_replay_message fd_replay_message_t;

#endif /* HEADER_fd_src_discof_replay_fd_replay_tile_h */
