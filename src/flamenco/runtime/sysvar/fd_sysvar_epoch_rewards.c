#include "fd_sysvar_epoch_rewards.h"
#include "fd_sysvar_cache.h"

/* Since there are multiple sysvar epoch rewards updates within a single slot,
   we need to ensure that the cache stays updated after each change (versus with other
   sysvars which only get updated once per slot and then synced up after) */
void
fd_sysvar_epoch_rewards_distribute( fd_exec_slot_ctx_t * slot_ctx,
                                    ulong                distributed ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read( slot_ctx->sysvar_cache, epoch_rewards ) ) ) {
    FD_LOG_ERR(( "fd_sysvar_epoch_rewards_read failed" ));
  }

  if( FD_UNLIKELY( !epoch_rewards->active ) ) {
    FD_LOG_ERR(( "sysvar epoch rewards is not active" ));
  }

  if( FD_UNLIKELY( fd_ulong_sat_add( epoch_rewards->distributed_rewards, distributed ) > epoch_rewards->total_rewards ) ) {
    FD_LOG_ERR(( "distributed rewards overflow" ));
  }

  epoch_rewards->distributed_rewards += distributed;

  fd_sysvar_epoch_rewards_write( slot_ctx, epoch_rewards );
}

void
fd_sysvar_epoch_rewards_set_inactive( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read( slot_ctx->sysvar_cache, epoch_rewards ) ) ) {
    FD_LOG_ERR(( "fd_sysvar_epoch_rewards_read failed" ));
  }

  if( FD_UNLIKELY( epoch_rewards->total_rewards < epoch_rewards->distributed_rewards ) ) {
    FD_LOG_ERR(( "distributed rewards overflow" ));
  }

  epoch_rewards->active = 0;

  fd_sysvar_epoch_rewards_write( slot_ctx, epoch_rewards );
}

/* Create EpochRewards sysvar with calculated rewards

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L25 */
void
fd_sysvar_epoch_rewards_init( fd_exec_slot_ctx_t * slot_ctx,
                              ulong                distributed_rewards,
                              ulong                distribution_starting_block_height,
                              ulong                num_partitions,
                              fd_point_value_t     point_value,
                              fd_hash_t const *    last_blockhash ) {
  fd_sysvar_epoch_rewards_t epoch_rewards = {
    .distribution_starting_block_height = distribution_starting_block_height,
    .num_partitions                     = num_partitions,
    .total_points                       = point_value.points,
    .total_rewards                      = point_value.rewards,
    .distributed_rewards                = distributed_rewards,
    .active                             = 1
  };

  if( FD_UNLIKELY( epoch_rewards.total_rewards<distributed_rewards ) ) {
    FD_LOG_ERR(( "total rewards overflow" ));
  }

  fd_memcpy( &epoch_rewards.parent_blockhash, last_blockhash, FD_HASH_FOOTPRINT );

  fd_sysvar_epoch_rewards_write( slot_ctx, &epoch_rewards );
}
