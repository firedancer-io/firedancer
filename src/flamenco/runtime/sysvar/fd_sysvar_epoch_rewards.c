#include "fd_sysvar_epoch_rewards.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

static int
validate( fd_sysvar_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->active!=0 && epoch_rewards->active!=1;

}

static void
write_epoch_rewards( fd_bank_t *                 bank,
                     fd_accdb_t *                accdb,
                     fd_capture_ctx_t *          capture_ctx,
                     fd_sysvar_epoch_rewards_t * epoch_rewards ) {
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_epoch_rewards_id, epoch_rewards, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );
}

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read( fd_accdb_t *                accdb,
                              fd_accdb_fork_id_t          fork_id,
                              fd_sysvar_epoch_rewards_t * out ) {
  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork_id, fd_sysvar_epoch_rewards_id.uc );
  if( FD_UNLIKELY( !entry.lamports ) ) return NULL;
  if( FD_UNLIKELY( entry.data_len!=FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ ) ) return NULL;

  fd_memcpy( out, entry.data, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );

  fd_accdb_unread_one( accdb, &entry );
  if( FD_UNLIKELY( validate( out ) ) ) return NULL;
  return out;
}

/* Since there are multiple sysvar epoch rewards updates within a single slot,
   we need to ensure that the cache stays updated after each change (versus with other
   sysvars which only get updated once per slot and then synced up after) */
void
fd_sysvar_epoch_rewards_distribute( fd_bank_t *        bank,
                                    fd_accdb_t *       accdb,
                                    fd_capture_ctx_t * capture_ctx,
                                    ulong              distributed ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( accdb, bank->accdb_fork_id, epoch_rewards ) );
  FD_TEST( epoch_rewards->active );

  ulong new_distributed = fd_ulong_sat_add( epoch_rewards->distributed_rewards, distributed );
  FD_TEST( new_distributed<=epoch_rewards->total_rewards );
  epoch_rewards->distributed_rewards += distributed;

  write_epoch_rewards( bank, accdb, capture_ctx, epoch_rewards );
}

void
fd_sysvar_epoch_rewards_set_inactive( fd_bank_t *        bank,
                                      fd_accdb_t *       accdb,
                                      fd_capture_ctx_t * capture_ctx ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( accdb, bank->accdb_fork_id, epoch_rewards ) );
  FD_TEST( epoch_rewards->total_rewards>=epoch_rewards->distributed_rewards );

  epoch_rewards->active = 0;
  write_epoch_rewards( bank, accdb, capture_ctx, epoch_rewards );
}

/* Create EpochRewards sysvar with calculated rewards

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L25 */
void
fd_sysvar_epoch_rewards_init( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx,
                              ulong              distributed_rewards,
                              ulong              distribution_starting_block_height,
                              ulong              num_partitions,
                              ulong              total_rewards,
                              uint128            total_points,
                              fd_hash_t const *  last_blockhash ) {
  fd_sysvar_epoch_rewards_t epoch_rewards = {
    .distribution_starting_block_height = distribution_starting_block_height,
    .num_partitions                     = num_partitions,
    .total_points                       = { .ud=total_points },
    .total_rewards                      = total_rewards,
    .distributed_rewards                = distributed_rewards,
    .active                             = 1,
    .parent_blockhash                   = *last_blockhash
  };

  FD_TEST( epoch_rewards.total_rewards>=epoch_rewards.distributed_rewards );
  write_epoch_rewards( bank, accdb, capture_ctx, &epoch_rewards );
}
