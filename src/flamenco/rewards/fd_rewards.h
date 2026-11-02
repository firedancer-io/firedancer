#ifndef HEADER_fd_src_flamenco_rewards_fd_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_rewards_h

/* fd_rewards.h provides APIs for distributing Solana staking rewards. */

#include "../stakes/fd_stake_delegations.h"
#include "../runtime/sysvar/fd_sysvar_base.h"

struct fd_partitioned_rewards_calculation {
  ulong old_vote_balance_and_staked;
  ulong validator_rewards;
  ulong capitalization;
};
typedef struct fd_partitioned_rewards_calculation fd_partitioned_rewards_calculation_t;

FD_PROTOTYPES_BEGIN

/* fd_apply_double_disinflation_rate applies the
   double_disinflation_rate feature gate to the given bank. It updates
   the given bank's inflation->taper and inflation->initial values.

   https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/runtime/src/bank.rs#L6117-L6130 */

void
fd_apply_double_disinflation_rate( fd_bank_t * bank );

/* fd_apply_integer_inflation_initial_rate applies the
   remove_runtime_float_ops feature gate to the given bank.  It sets the
   given bank's inflation->initial to 8%.  This is not actually used
   after remove_runtime_float_ops is activated, but we set it so that
   our manifest is consistent with Agave's.

   https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L6257-L6261 */

void
fd_apply_integer_inflation_initial_rate( fd_bank_t * bank );

/* fd_begin_partitioned_rewards updates epoch bank stake and vote
   account reward calculations.  Updates vote accounts with payouts and
   increases capitalization.  Called in the epoch boundary (start of
   first block of an epoch).

   Call stack is as follows:
   - begin_partitioned_rewards
     - calculate_rewards_and_distribute_vote_rewards
       - calculate_rewards_for_partitioning
         - calculate_reward_points_partitioned (caches stake points)
           - calculate_alpenglow_points
         - calculate_stake_vote_rewards (calculates reward list)
           - for each delegation: redeem_rewards
       - ... update all vote accounts ...
     - ... update epoch rewards bank field ... */

void
fd_begin_partitioned_rewards( fd_bank_t *                    bank,
                              fd_accdb_t *                   accdb,
                              fd_runtime_stack_t *           runtime_stack,
                              fd_capture_ctx_t *             capture_ctx,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_hash_t const *              parent_blockhash,
                              ulong                          parent_epoch,
                              ulong                          parent_capitalization );

/* fd_rewards_recalculate_partitioned_rewards restores epoch bank stake
   and account reward calculations.  Does not update accounts.  Called
   when restoring replay state from a snapshot.

   Call stack is as follows:
   - calculate_stake_vote_rewards (calculates reward list)
     - for each delegation: calculate_alpenglow_points, redeem_rewards */

void
fd_rewards_recalculate_partitioned_rewards( fd_bank_t *          bank,
                                            fd_accdb_t *         accdb,
                                            fd_runtime_stack_t * runtime_stack,
                                            fd_capture_ctx_t *   capture_ctx );

/* fd_distribute_partitioned_epoch_rewards pays out rewards to stake
   accounts.  Called at the beginning of a few slots per epoch or when
   partitioned rewards need to be recalculated (rewards windowing).

   Call stack is as follows:
   - distribute_epoch_rewards_in_partition
     - for each stake account: distribute_epoch_reward_to_stake_acc */

void
fd_distribute_partitioned_epoch_rewards( fd_bank_t *          bank,
                                         fd_accdb_t *         accdb,
                                         fd_runtime_stack_t * runtime_stack,
                                         fd_capture_ctx_t *   capture_ctx );

/* fd_rewards_get_reward_distribution_num_blocks returns the number of
   blocks required to distribute rewards for a given epoch schedule and
   stake account count. Useful for testing partition sizing logic. */

uint
fd_rewards_get_reward_distribution_num_blocks( fd_epoch_schedule_t const * epoch_schedule,
                                               ulong                       slot,
                                               ulong                       total_stake_accounts,
                                               ulong                       stake_account_stores_per_block );

struct fd_commission_split {
  ulong voter_portion;
  ulong staker_portion;
  uint  is_split;
};

typedef struct fd_commission_split fd_commission_split_t;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_rewards_h */
