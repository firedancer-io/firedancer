#ifndef HEADER_fd_src_flamenco_runtime_fd_rewards_h
#define HEADER_fd_src_flamenco_runtime_fd_rewards_h

/* fd_rewards.h provides APIs for distributing Solana staking rewards. */

#include "../types/fd_types.h"
#include "../stakes/fd_stake_delegations.h"

FD_PROTOTYPES_BEGIN

/* fd_begin_partitioned_rewards updates epoch bank stake and vote
   account reward calculations.  Updates vote accounts with payouts and
   increases capitalization.  Called in the epoch boundary (start of
   first block of an epoch).

   Call stack is as follows:
   - begin_partitioned_rewards
     - calculate_rewards_and_distribute_vote_rewards
       - calculate_rewards_for_partitioning
         - calculate_reward_points_partitioned (calculates total points)
           - calculate_points_all
         - calculate_stake_vote_rewards (calculates reward list)
           - calculate_stake_vote_rewards_account
             - for each delegation: redeem_rewards
               - calculate_stake_rewards
                 - calculate_stake_points_and_credits
       - ... update all vote accounts ...
     - ... update epoch rewards bank field ... */

void
fd_begin_partitioned_rewards( fd_exec_slot_ctx_t *           slot_ctx,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_hash_t const *              parent_blockhash,
                              ulong                          parent_epoch,
                              fd_spad_t *                    runtime_spad );

/* fd_rewards_recalculate_partitioned_rewards restores epoch bank stake
   and account reward calculations.  Does not update accounts.  Called
   when restoring replay state from a snapshot.

   Call stack is as follows:
   - calculate_stake_vote_rewards (calculates reward list)
     - calculate_stake_vote_rewards_account
       - for each delegation: redeem_rewards
         - calculate_stake_rewards
           - calculate_stake_points_and_credits */

void
fd_rewards_recalculate_partitioned_rewards( fd_exec_slot_ctx_t * slot_ctx,
                                            fd_spad_t *          runtime_spad );

/* fd_distribute_partitioned_epoch_rewards pays out rewards to stake
   accounts.  Called at the beginning of a few slots per epoch.

   Call stack is as follows:
   - distribute_epoch_rewards_in_partition
     - for each stake account: distribute_epoch_reward_to_stake_acc */

void
fd_distribute_partitioned_epoch_rewards( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_rewards_h */
