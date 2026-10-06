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
   the snapshot is created.

   ALPENGLOW

   Under alpenglow, the replay tile doesn't use the reasm, but rather
   relies on rotor to deliver FECs. Similar to reasm, rotor delivers
   FECs in replayable order, with no restrictions on interleaving
   between forks. Every delivered FEC is already in store. Alpenglow
   also introduces the double merkle root, which uniquely identifies
   each FEC set as part of one slot version. For equivocating slots, the
   block_id is known before delivery, and so replay can identify how to
   allocate banks in the equivocation case.

   Replay can rely on the fact that any new version of the slot
   (equivocations or not) is delivered from FEC 0 — blocks are never
   delivered starting mid-block. There is also at most one live delivery
   stream per logical block.  When the turbine version is being streamed
   in, the block_id is still unknown, but if a votor-driven version of
   the block arrives before the turbine copy is complete, the turbine
   copy is abandoned, and will never finish delivering to replay.

   Alpenglow simplifies eviction logic by removing the notion of reasm
   evictions.  Rotor is sized to protocol limits and will not have
   evictions; and thus can be relied on to always have all data since
   the root. Banks can still evict.  On an eviction, some context in the
   replayable chain of FECs is lost, and newer incoming FECs may be
   unlinked.  When this happens, replay sends a signal to rotor to send
   the next FEC with the full replayable path from root. Replay will
   need to drain the rotor dcache until it receives a FEC that is
   connected, and then resume normal replay.  It may need to drop FECs
   that have already been replayed, or send multiple signals to rotor to
   re-deliver. */

#include "../poh/fd_poh_tile.h"
#include "../../disco/tiles.h"
#include "../../choreo/votor/ag_cert.h"
#include "../../flamenco/alpenglow/fd_block_marker.h"

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
#define REPLAY_SIG_SNAP_START     (10)
#define REPLAY_SIG_FINAL_CERT     (11)
#define REPLAY_SIG_LEADER_FOOTER  (12)
#define REPLAY_SIG_MISSING_FEC    (13)

/* Boot stream messages
   ====================

   With [snapshots.instant_boot.serve] on, replay mirrors the blocks it
   replays to the stream tile over replay_strmk, which turns them into
   boot streams that a peer can start executing from before its
   snapshot has finished loading.  The sig of each frag selects the
   message below.  The link is unreliable and replay never waits on it,
   so a stream tile that falls behind sees a sequence gap and starts
   over.

   Every message that hands out a reference on a bank carries a
   hold_token, and the stream tile returns the reference by sending
   that token back verbatim as the sig on strmk_replay.  A token names
   one reference and no other, even when two references are on the same
   bank, which is the normal case: the bank a stream chains off is also
   the parent of the first block after it.  Returning a token twice,
   or returning one replay has already taken back, does nothing.  The
   tile does not have to interpret the token, only hand it back.

   Replay sends FD_STRMK_SIG_RESET when it has taken every outstanding
   reference back, which it does when the stream tile owes one for too
   long, when it owes more than replay can record, when the accounts of
   a block did not fit in its sink, and when the shredded bytes of a
   block replay produced itself are no longer in the store: a stream is
   a chain of blocks and cannot skip one.  A reset cancels every
   reference the stream tile was given before it; returning one of
   those tokens afterwards is harmless, replay no longer recognises
   it.

   A reference has two deadlines.  The stream tile reads a block's
   accounts once it has the block's end, so from that moment it has 4
   seconds to return the reference.  Until then only a 60 second
   backstop applies, measured from the block start, because replay
   itself may take that long to finish a block it is catching up on.

   The 4 second clock is paused for as long as the tile owes the
   reference a stream start gave it, because opening a stream writes a
   manifest, a status cache and a bundle, and the tile cannot read a
   block until that is done.  The clocks restart when that reference
   comes back, so the time spent opening a stream is not charged to
   the blocks that queued up behind it.  The 60 second backstop
   applies throughout. */

#define FD_STRMK_SIG_BLOCK_START  (1UL)
#define FD_STRMK_SIG_TXN_KEYS     (2UL)
#define FD_STRMK_SIG_BLOCK_END    (3UL)
#define FD_STRMK_SIG_BLOCK_DEAD   (4UL)
#define FD_STRMK_SIG_STREAM_START (5UL)
#define FD_STRMK_SIG_RESET        (6UL)
#define FD_STRMK_SIG_TXN_TABLES   (7UL)

/* MTU of replay_strmk, see fd_topo_initialize. */

#define FD_STRMK_MTU (4096UL)

/* Replay publishes a block start as soon as the block has a bank, and
   holds a reference on the parent bank for the stream tile.  It always
   precedes the block's keys, so the stream tile can file them under a
   block it has already heard of.  Blocks this validator produced
   itself are streamed too, even though they never reach the scheduler:
   replay walks their shredded bytes for keys.

   bank_idx is recycled across blocks, so state has to be keyed on the
   pair with bank_seq, which is unique for the life of the validator.
   The fork the block's accounts are read at is not known yet and
   arrives with the block end. */

struct fd_strmk_block_start {
  ulong slot;
  ulong bank_idx;
  ulong bank_seq;
  ulong parent_bank_idx;
  ulong hold_token;      /* return on strmk_replay once the block is written */
};
typedef struct fd_strmk_block_start fd_strmk_block_start_t;

/* Account keys of a block's transactions, in parse order: the static
   keys of a transaction, then the keys its lookup tables expanded to,
   then the addresses of those tables.  The table accounts are in here
   because a peer booting off the stream replays the block itself and
   has to expand the tables again, which means reading them.

   A transaction whose tables replay could not expand contributes only
   its static keys here; the addresses of those tables arrive in
   FD_STRMK_SIG_TXN_TABLES instead, which carries this same struct and
   follows the block's keys for that FEC set.  Its keys are lookup
   tables the stream tile has to read and expand at the fork the block
   end names, and whose addresses it has to carry in the stream along
   with whatever they expand to.

   A message carries the keys of as many transactions as fit, so the
   stream tile accumulates keys per block and does not learn
   transaction boundaries. */

#define FD_STRMK_TXN_KEY_MAX (127UL)

struct fd_strmk_txn_keys {
  ulong       slot;
  ulong       bank_idx;
  ushort      key_cnt;
  fd_pubkey_t keys[ FD_STRMK_TXN_KEY_MAX ];
};
typedef struct fd_strmk_txn_keys fd_strmk_txn_keys_t;

/* Replay publishes a block end once a block completes, and the same
   message with sig FD_STRMK_SIG_BLOCK_DEAD, a zero collector and an
   unset fork (val USHORT_MAX, what the accounts database uses for no
   fork) for a block that died, so the stream tile can drop its partial
   state.

   parent_accdb_fork_id is the fork the block's accounts are read at,
   and it is only valid here: the fork is created when the block starts
   executing, which is after its block start went out, and the fork the
   parent bank held before that may since have been purged.  So the
   stream tile reads a block's accounts at the fork its block end
   names, never earlier, and never at all for a block that died.  The
   hold the block start took keeps the fork alive until the tile
   returns it.

   parent_bank_seq is the parent bank's bank_seq, so the stream tile
   can tell the bank it is about to read from a different bank that has
   since taken the same index.  The hold pins the parent, so the value
   is the same whether it is read when the child is created or at
   completion.  It is ULONG_MAX when the parent is gone, which only
   happens for a block that died.

   txn_cnt is the number of transactions the block committed, which is
   not the number the stream carries keys for: keys are collected as
   transactions are parsed, before any of them is executed.  collector
   is the account fee settlement credits with the block's fee reward,
   which no transaction in the block names. */

struct fd_strmk_block_end {
  ulong              slot;
  ulong              bank_idx;
  ulong              bank_seq;
  ulong              parent_bank_seq;
  ulong              txn_cnt;
  fd_accdb_fork_id_t parent_accdb_fork_id;
  fd_pubkey_t        collector;
};
typedef struct fd_strmk_block_end fd_strmk_block_end_t;

/* Replay publishes a stream start right after it asks the snapshot
   maker for the incremental snapshot a new stream chains off, holding
   a reference on that snapshot's bank for the stream tile.  A full
   snapshot starts no stream.  This hold has a much longer deadline
   than a block's, because the stream tile writes a manifest and a
   status cache before it is done with the bank. */

struct fd_strmk_stream_start {
  ulong slot;
  ulong bank_idx;
  ulong hold_token;      /* return on strmk_replay once the stream is written */
};
typedef struct fd_strmk_stream_start fd_strmk_stream_start_t;

FD_STATIC_ASSERT( sizeof(fd_strmk_block_start_t )<=FD_STRMK_MTU, strmk_mtu );
FD_STATIC_ASSERT( sizeof(fd_strmk_txn_keys_t    )<=FD_STRMK_MTU, strmk_mtu );
FD_STATIC_ASSERT( sizeof(fd_strmk_block_end_t   )<=FD_STRMK_MTU, strmk_mtu );
FD_STATIC_ASSERT( sizeof(fd_strmk_stream_start_t)<=FD_STRMK_MTU, strmk_mtu );

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

  int    voted;           /* our vote was in the reward cert this block carried */
  ushort voted_rank;      /* our rank in the reward slot's epoch, USHORT_MAX if we are not a voter */
  ushort vote_count;      /* distinct reward cert signers for slot-FD_NUM_SLOTS_FOR_REWARD, USHORT_MAX if unknown */
  ulong  vote_balance;    /* ULONG_MAX if not sampled */
  ushort vote_commission; /* USHORT_MAX if not sampled */

  struct {
    ulong block_cost;
    ulong allocated_accounts_data_size;
    ulong block_cost_limit;
    ulong account_cost_limit;
    ulong pool_idx;
  } cost_tracker;

  fd_block_footer_t footer;
};

typedef struct fd_replay_slot_completed fd_replay_slot_completed_t;

struct fd_replay_slot_dead {
  ulong             slot;
  fd_hash_t         block_id;

  /* Agave can finalize off the certs in a dead block's footer.

     TODO dead blocks short-circuit from parsing out the footer unless
     it's a BHM.  Always read the footer? */

  fd_block_footer_t footer;
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
  fd_hash_t block_id;
};
typedef struct fd_replay_root_advanced fd_replay_root_advanced_t;

struct fd_replay_txn_executed {
  fd_txn_p_t txn[ 1 ];
  int is_committable;
  int is_fees_only;
  int is_noop;
  int txn_err;
  int is_simple_vote;

  /* LONG_MAX if stage was not reached */
  long  tick_parsed;
  long  tick_sigverify_disp;
  long  tick_sigverify_done;
  long  tick_exec_disp;
  long  tick_exec_done;
  long  tick_load_start;
  long  tick_check_start;
  long  tick_exec_start;
  long  tick_commit_start;
  long  tick_commit_end;

  ulong slot;
  ulong bank_seq;
  ulong index_in_slot;
  ulong exec_tile_idx;
  ulong sigverify_exec_tile_idx;
  uint  compute_units_consumed; /* possibly zero if is_committable is zero */
  ulong max_compute_units;
  ulong transaction_fee;
  ulong priority_fee;
  ulong tips;
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
  ulong       bank_idx;
  ulong       base_slot;
  ulong       slot;   /* ==base_slot implies full snapshot, else incremental */
  fd_pubkey_t leader; /* leader of slot, written to the manifest for Agave */
};
typedef struct fd_replay_snap_start fd_replay_snap_start_t;

/* fd_replay_final_cert carries the finalization cert parsed out of an
   Alpenglow block footer. */
struct fd_replay_final_cert {
  ulong     slot;     /* the block whose footer carried the cert */
  uint      cert_cnt;
  ag_cert_t certs[ 2 ];
};
typedef struct fd_replay_final_cert fd_replay_final_cert_t;

struct fd_replay_leader_footer {
  ulong             slot;
  fd_block_footer_t footer;
};
typedef struct fd_replay_leader_footer fd_replay_leader_footer_t;

union fd_replay_message {
  fd_replay_slot_completed_t  slot_completed;
  fd_replay_slot_dead_t       slot_dead;
  fd_replay_root_advanced_t   root_advanced;
  fd_replay_oc_advanced_t     oc_advanced;
  fd_poh_reset_t              reset;
  fd_became_leader_t          became_leader;
  fd_replay_txn_executed_t    txn_executed;
  fd_replay_fec_evicted_t     reasm_evicted;
  fd_replay_drop_bank_ref_t   drop_bank_ref;
  fd_replay_leader_footer_t   leader_footer;
};

typedef union fd_replay_message fd_replay_message_t;

#endif /* HEADER_fd_src_discof_replay_fd_replay_tile_h */
