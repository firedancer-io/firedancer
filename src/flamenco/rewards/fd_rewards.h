#ifndef HEADER_fd_src_flamenco_rewards_fd_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_rewards_h

/* fd_rewards.h provides APIs for distributing Solana staking rewards. */

#include "../stakes/fd_stake_delegations.h"

struct fd_prev_epoch_inflation_rewards {
  ulong  validator_rewards;
  double prev_epoch_duration_in_years;
  double validator_rate;
  double foundation_rate;
};
typedef struct fd_prev_epoch_inflation_rewards fd_prev_epoch_inflation_rewards_t;

struct fd_partitioned_rewards_calculation {
  uint128 validator_points;
  ulong   old_vote_balance_and_staked;
  ulong   validator_rewards;
  double  validator_rate;
  double  foundation_rate;
  double  prev_epoch_duration_in_years;
  ulong   capitalization;
};
typedef struct fd_partitioned_rewards_calculation fd_partitioned_rewards_calculation_t;

FD_PROTOTYPES_BEGIN

/* The four-phase parallel epoch-boundary rewards pipeline.  Each
   _partitioned function is a map operator: callers (typically
   execrp tiles) invoke it with a unique (partition_idx,
   total_partitions) and the results fold together into shared state.
   Single-threaded callers (see fd_runtime_epoch_boundary) call each
   with (0, 1).  See fd_runtime.h for the full map-reduce protocol. */

/* Phase 1: reward_points.  Returns the partition's partial sum of
   points.  Caller sums returns across partitions to obtain
   total_points, then runs fd_rewards_compute_total_rewards. */

uint128
calculate_reward_points_partitioned( fd_bank_t *                    bank,
                                     fd_stake_delegations_t const * stake_delegations,
                                     fd_stake_history_t const *     stake_history,
                                     fd_runtime_stack_t *           runtime_stack,
                                     ulong                          partition_idx,
                                     ulong                          total_partitions );

ulong
fd_rewards_compute_total_rewards( fd_bank_t const * bank,
                                  ulong             prev_epoch,
                                  uint128           total_points );

/* Phase 2: stake_vote_rewards.  Writes per-delegation scratch to
   runtime_stack->stakes.stake_rewards_result[] (disjoint per
   worker, no contention); atomically accumulates into
   runtime_stack->stakes.vote_ele[].vote_rewards and
   runtime_stack->shmem->stake_rewards_cnt.  Caller must first reset
   those shared accumulators to 0 (see
   fd_runtime_epoch_boundary_reset_vote_rewards), and must have run
   calculate_reward_points_partitioned earlier so
   stake_points_result[] is populated. */

void
calculate_stake_vote_rewards_partitioned( fd_bank_t *                    bank,
                                          fd_stake_delegations_t const * stake_delegations,
                                          fd_stake_history_t const *     stake_history,
                                          ulong                          rewarded_epoch,
                                          ulong                          total_rewards,
                                          uint128                        total_points,
                                          fd_runtime_stack_t *           runtime_stack,
                                          ulong                          partition_idx,
                                          ulong                          total_partitions );

/* Phase 3: setup_stake_partitions.  Between phase 2 and phase 3 the
   caller must invoke fd_begin_partitioned_rewards_init_partitions
   (single-threaded) to initialize the bank's stake_rewards fork.
   Each worker then appends to its local per-partition chains and
   splices them onto the shared partition_idxs_head[] at the end --
   no explicit reduce step needed. */

void
fd_begin_partitioned_rewards_init_partitions( fd_bank_t *          bank,
                                              fd_runtime_stack_t * runtime_stack,
                                              fd_capture_ctx_t *   capture_ctx,
                                              fd_hash_t const *    parent_blockhash,
                                              uint128              total_points,
                                              ulong                total_rewards );

void
setup_stake_partitions_partitioned( fd_bank_t *                    bank,
                                    fd_stake_delegations_t const * stake_delegations,
                                    fd_stake_history_t const *     stake_history,
                                    fd_runtime_stack_t *           runtime_stack,
                                    ulong                          rewarded_epoch,
                                    ulong                          total_rewards,
                                    uint128                        total_points,
                                    ulong                          partition_idx,
                                    ulong                          total_partitions );

/* Post-phase-3: distributes vote-account rewards (reading the
   vote_ele[].vote_rewards accumulators), verifies invariants,
   publishes summary state, and initializes the epoch_rewards
   sysvar. */

void
fd_begin_partitioned_rewards_finalize( fd_bank_t *                    bank,
                                       fd_accdb_user_t *              accdb,
                                       fd_funk_txn_xid_t const *      xid,
                                       fd_runtime_stack_t *           runtime_stack,
                                       fd_capture_ctx_t *             capture_ctx,
                                       fd_hash_t const *              parent_blockhash,
                                       uint128                        total_points,
                                       ulong                          total_rewards );

/* fd_rewards_recalculate_partitioned_rewards restores epoch bank
   stake and account reward calculations from the epoch_rewards
   sysvar snapshot.  Does not update accounts.  Called when restoring
   replay state from a snapshot. */

void
fd_rewards_recalculate_partitioned_rewards( fd_banks_t *              banks,
                                            fd_bank_t *               bank,
                                            fd_accdb_user_t *         accdb,
                                            fd_funk_txn_xid_t const * xid,
                                            fd_runtime_stack_t *      runtime_stack,
                                            fd_capture_ctx_t *        capture_ctx );

/* fd_distribute_partitioned_epoch_rewards pays out rewards to stake
   accounts.  Called at the beginning of a few slots per epoch.

   Call stack is as follows:
   - distribute_epoch_rewards_in_partition
     - for each stake account: distribute_epoch_reward_to_stake_acc */

void
fd_distribute_partitioned_epoch_rewards( fd_bank_t *               bank,
                                         fd_accdb_user_t *         accdb,
                                         fd_funk_txn_xid_t const * xid,
                                         fd_capture_ctx_t *        capture_ctx );

/* fd_rewards_get_reward_distribution_num_blocks returns the number of
   blocks required to distribute rewards for a given epoch schedule and
   stake account count. Useful for testing partition sizing logic. */

uint
fd_rewards_get_reward_distribution_num_blocks( fd_epoch_schedule_t const * epoch_schedule,
                                               ulong                       slot,
                                               ulong                       total_stake_accounts );

struct fd_commission_split {
  ulong voter_portion;
  ulong staker_portion;
  uint  is_split;
};

typedef struct fd_commission_split fd_commission_split_t;

void
fd_vote_commission_split( uchar                   commission,
                          ulong                   on,
                          fd_commission_split_t * result );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_rewards_h */
