#ifndef HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h
#define HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"

FD_PROTOTYPES_BEGIN

/* Read the current value of the EpochRewards sysvar from Funk. */
fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read(
    fd_sysvar_epoch_rewards_t * result,
    fd_exec_slot_ctx_t * slot_ctx
);

/* Update EpochRewards sysvar with distributed rewards

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_rewards.rs#L44 */
void
fd_sysvar_epoch_rewards_distribute(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong distributed
);

/* Set the EpochRewards sysvar to inactive

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L82 */
void
fd_sysvar_epoch_rewards_set_inactive(
  fd_exec_slot_ctx_t * slot_ctx
);

/* Initialize the EpochRewards sysvar account

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L25 */
void
fd_sysvar_epoch_rewards_init(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong total_rewards,
    ulong distributed_rewards,
    ulong distribution_starting_block_height,
    ulong num_partitions,
    fd_point_value_t point_value,
    const fd_hash_t * last_blockhash
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h */
