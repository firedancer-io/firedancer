#ifndef HEADER_fd_src_disco_tiles_h
#define HEADER_fd_src_disco_tiles_h

#include "stem/fd_stem.h"
#include "shred/fd_shredder.h"
#include "../ballet/shred/fd_shred.h"
#include "../flamenco/leaders/fd_leaders_base.h"
#include "pack/fd_pack.h"
#include "topo/fd_topo.h"
#include "bundle/fd_bundle_crank.h"
#include "../disco/metrics/generated/fd_metrics_pack.h"

#include <linux/filter.h>

struct fd_became_leader {
   ulong slot;

  /* Start and end time of the slot in nanoseconds (from
     fd_log_wallclock()). */
  long   slot_start_ns;
  long   slot_end_ns;

  /* An opaque pointer to a Rust Arc<Bank> object, which should only
     be used with fd_ext_* functions to execute transactions or drop
     the bank.  The ownership is complicated, but basically any bank
     tile that receives this frag has a strong refcnt to the bank and
     should release it when done, other tiles should ignore and never
     use the bank. */
  void const * bank;

  /* In Firedancer, we just pass around the bank_idx which has already
     been refcounted by the replay tile, rather than a bank pointer. */
  ulong bank_idx;

  /* The maximum number of microblocks that pack is allowed to put
     into the block. This allows PoH to accurately track and make sure
     microblocks do not need to be dropped. */
  ulong max_microblocks_in_slot;

  /* The number of ticks (effectively empty microblocks) that the PoH
     tile will put in the block.  This is used to adjust some pack
     limits. */
  ulong ticks_per_slot;

  ulong tick_duration_ns;

  /* The number of ticks that the PoH tile has skipped, but needs to
     publish to show peers they were skipped correctly.  This is used
     to adjust some pack limits. */
  ulong total_skipped_ticks;

  /* The number of hashes per tick.  This is used to update the
     parameter for the proof of history component in case it has
     changed. */
  ulong hashcnt_per_tick;

  /* The epoch of the slot for which we are becoming leader. */
  ulong epoch;

  /* Consensus-critical cost limits for the slot we are becoming leader.
     These are typically unchanging, but may change after a feature
     activation. */
  struct {
    ulong slot_max_cost;
    ulong slot_max_vote_cost;
    ulong slot_max_write_cost_per_acct;
    ulong slot_max_allocated_data_per_block;
    ulong slot_max_data_shreds;
  } limits;

  /* Information from the accounts database as of the start of the slot
     determined by the bank above that is necessary to crank the bundle
     tip programs properly.  If bundles are not enabled (determined
     externally, but the relevant tiles should know), these fields are
     set to 0. */
  struct {
    fd_bundle_crank_tip_payment_config_t config[1];
    uchar                                tip_receiver_owner[32];
    uchar                                last_blockhash[32];
  } bundle[1];
};
typedef struct fd_became_leader fd_became_leader_t;

struct fd_rooted_bank {
  void * bank;
  ulong  slot;
};

typedef struct fd_rooted_bank fd_rooted_bank_t;

struct fd_completed_bank {
   ulong slot;
   uchar hash[32];
};

typedef struct fd_completed_bank fd_completed_bank_t;

/* fd_txn_ns_dt contains nanosecond offsets for an executed solana
   transaction relative to the publish event by pack for its
   corresponding microblock.

   In Firedancer, these states align with the struct declaration order,
   but in Frankendancer the "check" phase happens before "load". */
struct __attribute__((packed)) fd_txn_ns_dt {
  float load_start;
  float check_start;
  float exec_start;
  float commit_start;
  float commit_end;
};

typedef struct fd_txn_ns_dt fd_txn_ns_dt_t;

struct fd_microblock_trailer {
  /* The hash of the transactions in the microblock, ready to be
     mixed into PoH. */
  uchar hash[ 32UL ];

   /* A sequentially increasing index of the first transaction in the
     microblock, across all slots ever processed by pack.  This is used
     by monitoring tools that maintain an ordered history of
     transactions. */
  ulong pack_txn_idx;

  /* The tips included in the transaction, in lamports. 0 for non-bundle
     transactions */
  ulong tips;

  fd_txn_ns_dt_t txn_ns_dt;
};
typedef struct fd_microblock_trailer fd_microblock_trailer_t;

/* Sentinel sig values for messages on the pack_poh.  Normal
   done_packing messages use fd_disco_execle_sig( slot, pack_idx ). */
#define FD_PACK_MSG_DONE_DRAINING   (ULONG_MAX)
#define FD_PACK_MSG_REDUCE_MB_BOUND (ULONG_MAX-1UL)

#define FD_PACK_END_SLOT_REASON_TIME          (1)
#define FD_PACK_END_SLOT_REASON_MICROBLOCK    (2)
#define FD_PACK_END_SLOT_REASON_LEADER_SWITCH (3)

struct fd_done_packing {
  ulong microblocks_in_slot;

  fd_pack_limits_usage_t limits_usage[ 1 ];
  fd_pack_limits_t limits[ 1 ];

  ulong block_results    [ FD_METRICS_COUNTER_PACK_TXN_SCHEDULED_CNT ];
  ulong end_block_results[ FD_METRICS_COUNTER_PACK_TXN_SCHEDULED_CNT ];

  fd_pack_smallest_t pending_smallest[ 1 ];
  fd_pack_smallest_t pending_votes_smallest[ 1 ];

  int end_slot_reason;
};
typedef struct fd_done_packing fd_done_packing_t;

struct fd_microblock_execle_trailer {
  /* An opaque pointer to the bank to use when executing and committing
     transactions.  The lifetime of the bank is owned by the PoH tile,
     which guarantees it is valid while pack or bank tiles might be
     using it. */
  void const * bank;

  /* In full Firedancer we just pass an index of the bank in a pool of
     banks.  The lifetime is fully managed by the replay tile, which has
     given us a refcount while we are leader for this bank.  bank value
     above will be NULL. */
  ulong bank_idx;

  /* The sequentially increasing index of the microblock, across all
     execles.  This is used by PoH to ensure microblocks get committed
     in the same order they are executed. */
  ulong microblock_idx;
  uint  pack_idx;

  /* A sequentially increasing index of the first transaction in the
     microblock, across all slots ever processed by pack.  This is used
     by monitoring tools that maintain an ordered history of
     transactions. */
  ulong pack_txn_idx;

  /* If the microblock is a bundle, with a set of potentially
     conflicting transactions that should be executed in order, and
     all either commit or fail atomically. */
  int is_bundle;
};
typedef struct fd_microblock_execle_trailer fd_microblock_execle_trailer_t;

/* Exact worst-case frag sizes for the pack_execle and execle_poh
   links.  execle strips the ALT accounts from each fd_txn_e_t before
   forwarding to poh, so the poh side is smaller. */
#define FD_PACK_EXECLE_MTU (MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_e_t)+sizeof(fd_microblock_execle_trailer_t))
#define FD_EXECLE_POH_MTU  (MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t)+sizeof(fd_microblock_trailer_t))

#endif /* HEADER_fd_src_disco_tiles_h */
