#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../disco/fd_txn_p.h"
#include "../../flamenco/types/fd_types_custom.h"

/* Exec tile task types. */
#define FD_EXECRP_TT_TXN_EXEC                       (1UL) /* Transaction execution. */
#define FD_EXECRP_TT_TXN_SIGVERIFY                  (2UL) /* Transaction sigverify. */
#define FD_EXECRP_TT_POH_HASH                       (3UL) /* PoH hashing. */
#define FD_EXECRP_TT_EPOCH_REWARD_POINTS            (4UL) /* Epoch boundary reward points. */
#define FD_EXECRP_TT_EPOCH_CALC_STAKE_VOTE_REWARDS  (5UL) /* Epoch boundary stake / vote rewards. */
#define FD_EXECRP_TT_EPOCH_SETUP_REWARD_PARTITIONS  (6UL) /* Epoch boundary setup stake reward partitions. */
#define FD_EXECRP_TT_EPOCH_REFRESH_DELEGATIONS      (7UL) /* Epoch boundary refresh delegations (stake_accum map build). */

/* Sent from the replay tile to the exec tiles.  These describe one of
   several types of tasks for an exec tile.  An idx to the bank in the
   bank pool must be sent over because the key of the bank will change
   as FEC sets are processed. */

struct fd_execrp_txn_exec_msg {
  ulong      bank_idx;
  ulong      txn_idx;
  fd_txn_p_t txn[ 1 ];

  /* Used currently by solcap to maintain ordering of messages
     this will change to using txn sigs eventually */
  ulong      capture_txn_idx;
};
typedef struct fd_execrp_txn_exec_msg fd_execrp_txn_exec_msg_t;

struct fd_execrp_txn_sigverify_msg {
  ulong      bank_idx;
  ulong      txn_idx;
  fd_txn_p_t txn[ 1 ];
};
typedef struct fd_execrp_txn_sigverify_msg fd_execrp_txn_sigverify_msg_t;

struct fd_execrp_poh_hash_msg {
  ulong     bank_idx;
  ulong     mblk_idx;
  ulong     hashcnt;
  fd_hash_t hash[ 1 ];
};
typedef struct fd_execrp_poh_hash_msg fd_execrp_poh_hash_msg_t;

struct fd_execrp_epoch_reward_points_msg {
  ulong bank_idx;
  ulong partition_idx;
  ulong total_partitions;
};
typedef struct fd_execrp_epoch_reward_points_msg fd_execrp_epoch_reward_points_msg_t;

/* fd_execrp_epoch_calc_stake_vote_rewards_msg requests that the exec
   tile run calculate_stake_vote_rewards_partitioned on its assigned
   slice of the stake_delegations map.  The replay tile must have
   already:
     - populated runtime_stack->stakes.stake_points_result[] via the
       preceding EPOCH_REWARD_POINTS phase;
     - reset runtime_stack->stakes.vote_ele[].vote_rewards = 0 and
       runtime_stack->stakes.stake_rewards_cnt = 0;
     - computed total_rewards (capitalization * validator_rate *
       epoch_duration, gated by total_points>0).

   The reply carries no payload -- the exec tile's contribution is
   accumulated into the shared runtime_stack via atomic adds. */

struct fd_execrp_epoch_calc_stake_vote_rewards_msg {
  ulong   bank_idx;
  ulong   partition_idx;
  ulong   total_partitions;
  ulong   rewarded_epoch;
  ulong   total_rewards;
  uint128 total_points;
};
typedef struct fd_execrp_epoch_calc_stake_vote_rewards_msg fd_execrp_epoch_calc_stake_vote_rewards_msg_t;

/* fd_execrp_epoch_setup_reward_partitions_msg requests that the exec
   tile run setup_stake_partitions_partitioned on its assigned slice
   of the stake_delegations map.  The replay tile must have already:
     - populated runtime_stack->stakes.stake_rewards_result[] via the
       preceding EPOCH_CALC_STAKE_VOTE_REWARDS phase;
     - called fd_begin_partitioned_rewards_init_partitions, which
       calls fd_stake_rewards_init with the final num_partitions
       derived from stake_rewards_cnt and publishes the fork index on
       bank->stake_rewards_fork_id.

   The reply carries no payload.  fd_stake_rewards_insert is
   concurrency safe; workers coordinate through atomic counters and
   CAS-spin list-head pushes in the bank's stake_rewards structure. */

struct fd_execrp_epoch_setup_reward_partitions_msg {
  ulong   bank_idx;
  ulong   partition_idx;
  ulong   total_partitions;
  ulong   rewarded_epoch;
  ulong   total_rewards;
  uint128 total_points;
};
typedef struct fd_execrp_epoch_setup_reward_partitions_msg fd_execrp_epoch_setup_reward_partitions_msg_t;

/* fd_execrp_epoch_refresh_delegations_msg requests that the exec
   tile run fd_refresh_delegations_partitioned on its assigned slice
   of stake_delegations.  is_resume=0 on the initial dispatch and
   the worker resets its local stash; is_resume=1 after replay has
   drained the slot following a flush reply, in which case the
   worker picks up iteration from saved iterator state. */

struct fd_execrp_epoch_refresh_delegations_msg {
  ulong bank_idx;
  ulong partition_idx;
  ulong total_partitions;
  int   is_resume;
};
typedef struct fd_execrp_epoch_refresh_delegations_msg fd_execrp_epoch_refresh_delegations_msg_t;

union fd_execrp_task_msg {
  fd_execrp_txn_exec_msg_t                      txn_exec;
  fd_execrp_txn_sigverify_msg_t                 txn_sigverify;
  fd_execrp_poh_hash_msg_t                      poh_hash;
  fd_execrp_epoch_reward_points_msg_t           epoch_reward_points;
  fd_execrp_epoch_calc_stake_vote_rewards_msg_t epoch_calc_stake_vote_rewards;
  fd_execrp_epoch_setup_reward_partitions_msg_t epoch_setup_reward_partitions;
  fd_execrp_epoch_refresh_delegations_msg_t     epoch_refresh_delegations;
};

typedef union fd_execrp_task_msg fd_execrp_task_msg_t;

/* Sent from exec tiles to the replay tile, notifying the replay tile
   that a task has been completed.  That is, if the task has any
   observable side effects, such as updates to accounts, then those side
   effects are fully visible on any other exec tile. */

struct fd_execrp_txn_exec_done_msg {
  ulong txn_idx;

  /* These flags form a nested series of if statements.
     if( is_committable ) {
       if( is_fees_only ) {
         instructions will not be executed
         txn_err will be non-zero and will be one of the account loader errors
       } else {
         instructions will execute
         if( txn_err is non-zero ) {
           there's likely an instruction error
         } else {
           transaction executed successfully
           https://github.com/anza-xyz/agave/blob/v3.1.8/svm/src/transaction_execution_result.rs#L26
         }
       }
     } else {
       either failed before account loading, or failed cost tracker
     }
  */
  int is_committable;
  int is_fees_only;
  int txn_err;

  /* used by monitoring tools */
  ulong  slot;
  ushort start_shred_idx;
  ushort end_shred_idx;

  /* vote.slot==ULONG_MAX if this was not a vote transaction */
  struct {
    ulong slot;
    fd_pubkey_t identity[ 1 ];
    fd_pubkey_t vote_acct[ 1 ];
  } vote;
};
typedef struct fd_execrp_txn_exec_done_msg fd_execrp_txn_exec_done_msg_t;

struct fd_execrp_txn_sigverify_done_msg {
  ulong txn_idx;
  int   err;
};
typedef struct fd_execrp_txn_sigverify_done_msg fd_execrp_txn_sigverify_done_msg_t;

struct fd_execrp_poh_hash_done_msg {
  ulong     mblk_idx;
  ulong     hashcnt;
  fd_hash_t hash[ 1 ];
};
typedef struct fd_execrp_poh_hash_done_msg fd_execrp_poh_hash_done_msg_t;

struct fd_execrp_epoch_reward_points_done_msg {
  uint128 points;
};
typedef struct fd_execrp_epoch_reward_points_done_msg fd_execrp_epoch_reward_points_done_msg_t;

/* No payload needed: exec tile's contribution is already in shmem. */
struct fd_execrp_epoch_calc_stake_vote_rewards_done_msg {
  ulong partition_idx;
};
typedef struct fd_execrp_epoch_calc_stake_vote_rewards_done_msg fd_execrp_epoch_calc_stake_vote_rewards_done_msg_t;

/* No payload needed: insertion effects are already visible in
   bank->stake_rewards. */
struct fd_execrp_epoch_setup_reward_partitions_done_msg {
  ulong partition_idx;
};
typedef struct fd_execrp_epoch_setup_reward_partitions_done_msg fd_execrp_epoch_setup_reward_partitions_done_msg_t;

/* fd_execrp_epoch_refresh_delegations_done_msg reports the result of
   one refresh-delegations chunk.  is_flush=0 means the worker
   completed its partition; total_{effective,activating,deactivating}
   carry the scalar stake totals accumulated since the last dispatch.
   is_flush=1 means the local stash filled up and iterator state is
   saved in shmem; replay must drain the slot and send a resume
   frag.  The scalar totals still carry the partial amounts
   accumulated before the flush -- replay folds them into the global
   running totals and the worker restarts its local totals at 0 on
   resume. */

struct fd_execrp_epoch_refresh_delegations_done_msg {
  ulong partition_idx;
  int   is_flush;
  ulong total_effective;
  ulong total_activating;
  ulong total_deactivating;
};
typedef struct fd_execrp_epoch_refresh_delegations_done_msg fd_execrp_epoch_refresh_delegations_done_msg_t;

struct fd_execrp_task_done_msg {
  ulong bank_idx;
  union {
    fd_execrp_txn_exec_done_msg_t                      txn_exec[ 1 ];
    fd_execrp_txn_sigverify_done_msg_t                 txn_sigverify[ 1 ];
    fd_execrp_poh_hash_done_msg_t                      poh_hash[ 1 ];
    fd_execrp_epoch_reward_points_done_msg_t           epoch_reward_points[ 1 ];
    fd_execrp_epoch_calc_stake_vote_rewards_done_msg_t epoch_calc_stake_vote_rewards[ 1 ];
    fd_execrp_epoch_setup_reward_partitions_done_msg_t epoch_setup_reward_partitions[ 1 ];
    fd_execrp_epoch_refresh_delegations_done_msg_t     epoch_refresh_delegations[ 1 ];
  };
};
typedef struct fd_execrp_task_done_msg fd_execrp_task_done_msg_t;

#endif /* HEADER_fd_src_discof_replay_fd_execrp_h */
