#include "fd_sysvar_epoch_rewards.h"
#include "../../events/fd_event_runtime.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"
#include "fd_sysvar_rent.h"

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

/* write_epoch_rewards with the balance set to the rent exempt minimum,
   burning any surplus.
   Agave: create_account with RENT_UNADJUSTED_INITIAL_BALANCE followed by
   adjust_sysvar_balance_for_rent. */
static void
write_epoch_rewards_reset_balance( fd_bank_t *                 bank,
                                   fd_accdb_t *                accdb,
                                   fd_capture_ctx_t *          capture_ctx,
                                   fd_sysvar_epoch_rewards_t * epoch_rewards ) {
  fd_accdb_svm_update_t update[1];
  fd_acc_t              acc = fd_accdb_svm_open_rw( bank, accdb, update, &fd_sysvar_epoch_rewards_id, 1 );
  fd_memcpy( acc.owner, &fd_sysvar_owner_id, 32UL );
  acc.executable = 0;
  fd_memcpy( acc.data, epoch_rewards, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );
  acc.data_len = FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ;
  acc.lamports = fd_ulong_max( fd_rent_exempt_minimum_balance( &bank->f.rent, acc.data_len ), FD_SYSVAR_RENT_UNADJUSTED_INITIAL_BALANCE );
  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &acc, update );
}

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read( fd_accdb_t *                accdb,
                              fd_accdb_fork_id_t          fork_id,
                              fd_sysvar_epoch_rewards_t * out ) {
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, fd_sysvar_epoch_rewards_id.uc );
  if( FD_UNLIKELY( !acc.lamports ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return NULL;
  }
  if( FD_UNLIKELY( acc.data_len!=FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return NULL;
  }

  fd_memcpy( out, acc.data, FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );

  fd_accdb_unread_one( accdb, &acc );
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
                                    ulong              distributed,
                                    ulong              debit_block_reward_lamports ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( accdb, bank->accdb_fork_id, epoch_rewards ) );
  FD_TEST( epoch_rewards->active );

  ulong new_distributed = fd_ulong_sat_add( epoch_rewards->distributed_rewards, distributed );
  FD_TEST( new_distributed<=epoch_rewards->total_rewards );
  epoch_rewards->distributed_rewards += distributed;

  write_epoch_rewards( bank, accdb, capture_ctx, epoch_rewards );

  if( FD_UNLIKELY( !debit_block_reward_lamports ) ) return;

  fd_accdb_svm_update_t update[1];
  fd_acc_t              acc = fd_accdb_svm_open_rw( bank, accdb, update, &fd_sysvar_epoch_rewards_id, 0 );
  /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L101 */
  FD_TEST( acc.lamports>=debit_block_reward_lamports );
  acc.lamports -= debit_block_reward_lamports;
  /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L102-L105 */
  FD_TEST( acc.lamports>=fd_rent_exempt_minimum_balance( &bank->f.rent, acc.data_len ) );
  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &acc, update );
}

void
fd_sysvar_epoch_rewards_set_inactive( fd_bank_t *        bank,
                                      fd_accdb_t *       accdb,
                                      fd_capture_ctx_t * capture_ctx ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( accdb, bank->accdb_fork_id, epoch_rewards ) );
  FD_TEST( epoch_rewards->total_rewards>=epoch_rewards->distributed_rewards );

  epoch_rewards->active = 0;

  if( FD_FEATURE_ACTIVE_BANK( bank, block_revenue_sharing ) ) {
    /* Don't inherit the balance to ensure that any remaining lamports
       get burned: the balance is reset to the rent-exempt minimum and
       capitalization is updated.
       https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L120-L135 */
    write_epoch_rewards_reset_balance( bank, accdb, capture_ctx, epoch_rewards );
  } else {
    write_epoch_rewards( bank, accdb, capture_ctx, epoch_rewards );
  }
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
                              fd_hash_t const *  last_blockhash,
                              ulong              block_rewards ) {
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
  if( FD_UNLIKELY( fd_bank_report_runtime_diffs( bank ) ) ) fd_event_runtime_epoch_rewards( &epoch_rewards );
  write_epoch_rewards( bank, accdb, capture_ctx, &epoch_rewards );

  /* https://github.com/anza-xyz/agave/blob/v4.4.0-alpha.5/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L58-L69 */
  if( block_rewards ) {
    fd_accdb_svm_credit( bank, accdb, capture_ctx, &fd_sysvar_epoch_rewards_id, block_rewards, 0 );
  }
}
