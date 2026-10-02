#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_epoch_rewards_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_epoch_rewards_h

#include "../fd_bank.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_epoch_rewards_read reads the current value of the epoch
   rewards sysvar.  Returns NULL on failure. */

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read( fd_accdb_t *                accdb,
                              fd_accdb_fork_id_t          fork_id,
                              fd_sysvar_epoch_rewards_t * out );

/* Update EpochRewards sysvar with distributed rewards

   https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L75 */
void
fd_sysvar_epoch_rewards_distribute( fd_bank_t *        bank,
                                    fd_accdb_t *       accdb,
                                    fd_capture_ctx_t * capture_ctx,
                                    ulong              distributed,
                                    ulong              debit_block_reward_lamports );

/* Set the EpochRewards sysvar to inactive

    https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L113 */
void
fd_sysvar_epoch_rewards_set_inactive( fd_bank_t *        bank,
                                      fd_accdb_t *       accdb,
                                      fd_capture_ctx_t * capture_ctx );

/* Initialize the EpochRewards sysvar account

    https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L27 */
void
fd_sysvar_epoch_rewards_init( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx,
                              ulong              distributed_rewards,
                              ulong              distribution_starting_block_height,
                              ulong              num_partitions,
                              ulong              total_rewards,
                              uint128            total_points,
                              fd_hash_t const *  last_blockhash,
                              ulong              block_rewards );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_epoch_rewards_h */
