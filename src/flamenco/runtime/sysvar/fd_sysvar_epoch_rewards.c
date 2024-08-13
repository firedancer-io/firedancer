#include "fd_sysvar_epoch_rewards.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_borrowed_account.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_epoch_ctx.h"

static void
write_epoch_rewards( fd_exec_slot_ctx_t * slot_ctx, fd_sysvar_epoch_rewards_t * epoch_rewards ) {
  ulong sz = fd_sysvar_epoch_rewards_size( epoch_rewards );
  uchar enc[sz];
  fd_memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_sysvar_epoch_rewards_encode( epoch_rewards, &ctx ) ) {
    FD_LOG_ERR(("fd_sysvar_epoch_rewards_encode failed"));
  }

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_epoch_rewards_id, enc, sz, slot_ctx->slot_bank.slot, 0UL );
}

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read(
    fd_sysvar_epoch_rewards_t * result,
    fd_exec_slot_ctx_t  * slot_ctx
) {
  FD_BORROWED_ACCOUNT_DECL(acc);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_epoch_rewards_id, acc );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    return NULL;
  }

  fd_bincode_decode_ctx_t decode =
    { .data    = acc->const_data,
      .dataend = acc->const_data + acc->const_meta->dlen,
      .valloc  = {0}  /* valloc not required */ };

  if( FD_UNLIKELY( fd_sysvar_epoch_rewards_decode( result, &decode )!=FD_BINCODE_SUCCESS ) )
    return NULL;

  return result;
}

void
fd_sysvar_epoch_rewards_distribute(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong distributed
) {
    FD_TEST( FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) );

    fd_sysvar_epoch_rewards_t epoch_rewards[1];
    if ( FD_UNLIKELY( fd_sysvar_epoch_rewards_read( epoch_rewards, slot_ctx ) == NULL ) ) {
      FD_LOG_ERR(( "failed to read sysvar epoch rewards" ));
    }
    FD_TEST( epoch_rewards->active );

    FD_TEST( fd_ulong_sat_add( epoch_rewards->distributed_rewards, distributed ) <= epoch_rewards->total_rewards );

    epoch_rewards->distributed_rewards += distributed;

    write_epoch_rewards( slot_ctx, epoch_rewards );
}

void
fd_sysvar_epoch_rewards_set_inactive(
  fd_exec_slot_ctx_t * slot_ctx
) {
    fd_sysvar_epoch_rewards_t epoch_rewards[1];
    if ( FD_UNLIKELY( fd_sysvar_epoch_rewards_read( epoch_rewards, slot_ctx ) == NULL ) ) {
      FD_LOG_ERR(( "failed to read sysvar epoch rewards" ));
    }
    FD_TEST( epoch_rewards->distributed_rewards == epoch_rewards->total_rewards );

    epoch_rewards->active = 0;

    write_epoch_rewards( slot_ctx, epoch_rewards );
}

/* Create EpochRewards syavar with calculated rewards

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs#L25 */
void
fd_sysvar_epoch_rewards_init(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong total_rewards,
    ulong distributed_rewards,
    ulong distribution_starting_block_height,
    ulong num_partitions,
    uint128 total_points,
    const fd_hash_t * last_blockhash
) {
    FD_TEST( FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) );
    FD_TEST( total_rewards >= distributed_rewards );

    fd_sysvar_epoch_rewards_t epoch_rewards = {
      .distribution_starting_block_height = distribution_starting_block_height,
      .num_partitions = num_partitions,
      .total_points = total_points,
      .total_rewards = total_rewards,
      .distributed_rewards = distributed_rewards,
      .active = 1
    };

    fd_memcpy( &epoch_rewards.parent_blockhash, last_blockhash, FD_HASH_FOOTPRINT );

    write_epoch_rewards( slot_ctx, &epoch_rewards );
}
