#ifndef HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h
#define HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

void
fd_sysvar_epoch_rewards_read(
    fd_global_ctx_t * global,
    fd_sysvar_epoch_rewards_t * result,
    fd_acc_lamports_t * acc_lamports 
);

/* Update EpochRewards sysvar with distributed rewards */
void
fd_sysvar_epoch_rewards_update(
    fd_global_ctx_t * global,
    ulong distributed
);

/* Initialize the epoch rewards sysvar account. */
void fd_sysvar_epoch_rewards_init(
    fd_global_ctx_t* global,
    ulong total_rewards,
    ulong distributed_rewards,
    ulong distribution_complete_block_height
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_epoch_rewards_h */
