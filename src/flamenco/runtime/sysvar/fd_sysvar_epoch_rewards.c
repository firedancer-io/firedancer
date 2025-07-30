#include "fd_sysvar_epoch_rewards.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_txn_account.h"
#include "../fd_system_ids.h"

static void
write_epoch_rewards( fd_exec_slot_ctx_t * slot_ctx, fd_sysvar_epoch_rewards_t * epoch_rewards ) {
  ulong sz = fd_sysvar_epoch_rewards_size( epoch_rewards );
  uchar enc[sz];
  fd_memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc + sz
  };
  if( FD_UNLIKELY( fd_sysvar_epoch_rewards_encode( epoch_rewards, &ctx ) ) ) {
    FD_LOG_ERR(( "fd_sysvar_epoch_rewards_encode failed" ));
  }

  fd_sysvar_set( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn, &fd_sysvar_owner_id, &fd_sysvar_epoch_rewards_id, enc, sz, fd_bank_slot_get( slot_ctx->bank ) );
}

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read( fd_funk_t *                 funk,
                              fd_funk_txn_t *             funk_txn,
                              fd_sysvar_epoch_rewards_t * out ) {
  FD_TXN_ACCOUNT_DECL( acc );
  int err = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_epoch_rewards_id, funk, funk_txn );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( acc->vt->get_lamports( acc ) == 0UL ) ) {
    return NULL;
  }

  return fd_bincode_decode_static(
      sysvar_epoch_rewards, out,
      acc->vt->get_data( acc ),
      acc->vt->get_data_len( acc ),
      &err );
}

/* Since there are multiple sysvar epoch rewards updates within a single slot,
   we need to ensure that the cache stays updated after each change (versus with other
   sysvars which only get updated once per slot and then synced up after) */
void
fd_sysvar_epoch_rewards_distribute( fd_exec_slot_ctx_t * slot_ctx,
                                    ulong                distributed ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read( slot_ctx->funk, slot_ctx->funk_txn, epoch_rewards ) ) ) {
    FD_LOG_ERR(( "failed to read sysvar epoch rewards" ));
  }

  if( FD_UNLIKELY( !epoch_rewards->active ) ) {
    FD_LOG_ERR(( "sysvar epoch rewards is not active" ));
  }

  if( FD_UNLIKELY( fd_ulong_sat_add( epoch_rewards->distributed_rewards, distributed ) > epoch_rewards->total_rewards ) ) {
    FD_LOG_ERR(( "distributed rewards overflow" ));
  }

  epoch_rewards->distributed_rewards += distributed;

  write_epoch_rewards( slot_ctx, epoch_rewards );
}

void
fd_sysvar_epoch_rewards_set_inactive( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read( slot_ctx->funk, slot_ctx->funk_txn, epoch_rewards ) ) ) {
    FD_LOG_ERR(( "failed to read sysvar epoch rewards" ));
  }

  if( FD_UNLIKELY( epoch_rewards->total_rewards < epoch_rewards->distributed_rewards ) ) {
    FD_LOG_ERR(( "distributed rewards overflow" ));
  }

  epoch_rewards->active = 0;

  write_epoch_rewards( slot_ctx, epoch_rewards );
}

/* Create EpochRewards sysvar with calculated rewards

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L25 */
void
fd_sysvar_epoch_rewards_init( fd_exec_slot_ctx_t * slot_ctx,
                              ulong                distributed_rewards,
                              ulong                distribution_starting_block_height,
                              ulong                num_partitions,
                              ulong                total_rewards,
                              uint128              total_points,
                              fd_hash_t const *    last_blockhash ) {
  fd_sysvar_epoch_rewards_t epoch_rewards = {
    .distribution_starting_block_height = distribution_starting_block_height,
    .num_partitions                     = num_partitions,
    .total_points                       = total_points,
    .total_rewards                      = total_rewards,
    .distributed_rewards                = distributed_rewards,
    .active                             = 1,
    .parent_blockhash                   = *last_blockhash
  };

  if( FD_UNLIKELY( epoch_rewards.total_rewards<distributed_rewards ) ) {
    FD_LOG_ERR(( "total rewards overflow" ));
  }

  write_epoch_rewards( slot_ctx, &epoch_rewards );
}
