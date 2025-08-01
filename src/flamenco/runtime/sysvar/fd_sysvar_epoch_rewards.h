#ifndef HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h
#define HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h

#include "fd_sysvar_base.h"
#include "../../types/fd_types.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_epoch_rewards_read reads the current value of the rent
   sysvar from funk. If the account doesn't exist in funk or if the account
   has zero lamports, this function returns NULL. */

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read( fd_funk_t *                 funk,
                              fd_funk_txn_t *             funk_txn,
                              fd_sysvar_epoch_rewards_t * out );

/* Update EpochRewards sysvar with distributed rewards

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_rewards.rs#L44 */
void
fd_sysvar_epoch_rewards_distribute( fd_exec_slot_ctx_t * slot_ctx,
                                    ulong                distributed );

/* Set the EpochRewards sysvar to inactive

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L82 */
void
fd_sysvar_epoch_rewards_set_inactive( fd_exec_slot_ctx_t * slot_ctx );

/* Initialize the EpochRewards sysvar account

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L25 */
void
fd_sysvar_epoch_rewards_init( fd_exec_slot_ctx_t * slot_ctx,
                              ulong                distributed_rewards,
                              ulong                distribution_starting_block_height,
                              ulong                num_partitions,
                              ulong                total_rewards,
                              uint128              total_points,
                              fd_hash_t const *    last_blockhash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h */
