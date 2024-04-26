#include "fd_sysvar_epoch_rewards.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

// THIS IS ALL WRONG... the partitioned epoch rewards code paths have not been finalized with agave
// so these changes are here to support getting the fuzz tests to pass and not actual ledger correctness.
//
// Also, since this feature has not been activated in mainnet or testnet, the account itself does not
// exist which is why they felt free to change the layout outside of a feature flag.
//
// Once the Agave code has stabilized, we will make a proper implementation pass

void
fd_sysvar_epoch_rewards_burn_and_purge(
    fd_exec_slot_ctx_t  * slot_ctx
) {
    FD_BORROWED_ACCOUNT_DECL(rewards);

    int rc = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_epoch_rewards_id, 0, 0, rewards);
    if ( FD_UNLIKELY( rc ) ) return; // not good...

    fd_memcpy(rewards->meta->info.owner, fd_solana_system_program_id.key, sizeof(fd_pubkey_t));
    rewards->meta->dlen = 0;
    rewards->meta->info.lamports = 0;
}

static void
write_epoch_rewards( fd_exec_slot_ctx_t * slot_ctx, fd_sysvar_epoch_rewards_t * epoch_rewards, fd_acc_lamports_t acc_lamports) {
  ulong          sz = fd_sysvar_epoch_rewards_size( epoch_rewards );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_sysvar_epoch_rewards_encode( epoch_rewards, &ctx ) ) {
    FD_LOG_ERR(("fd_sysvar_epoch_rewards_encode failed"));
  }

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_epoch_rewards_id, enc, sz, slot_ctx->slot_bank.slot, acc_lamports );
}


fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read(
    fd_sysvar_epoch_rewards_t * result,
    fd_exec_slot_ctx_t  * slot_ctx,
    fd_acc_lamports_t * acc_lamports
) {
  FD_BORROWED_ACCOUNT_DECL(acc);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_epoch_rewards_id, acc );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t decode =
    { .data    = acc->const_data,
      .dataend = acc->const_data + acc->const_meta->dlen,
      .valloc  = {0}  /* valloc not required */ };

  if( FD_UNLIKELY( fd_sysvar_epoch_rewards_decode( result, &decode )!=FD_BINCODE_SUCCESS ) )
    return NULL;

  if( acc_lamports )
    *acc_lamports = acc->const_meta->info.lamports;

  return result;
}

/* Update EpochRewards sysvar with distributed rewards */
void
fd_sysvar_epoch_rewards_update(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong distributed
) {
    fd_sysvar_epoch_rewards_t result;
    fd_acc_lamports_t acc_lamports = 0UL;
    fd_sysvar_epoch_rewards_read( &result, slot_ctx, &acc_lamports );
    FD_TEST( acc_lamports != 0 );

    FD_TEST( result.epoch_rewards.distributed_rewards + distributed <= result.epoch_rewards.total_rewards );
    result.epoch_rewards.distributed_rewards += distributed;

    acc_lamports -= distributed;

    write_epoch_rewards( slot_ctx, &result, acc_lamports);
}

/* Create EpochRewards syavar with calculated rewards */
void
fd_sysvar_epoch_rewards_init(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong total_rewards,
    ulong distributed_rewards,
    ulong distribution_complete_block_height
) {
    FD_TEST( total_rewards >= distributed_rewards );

    fd_sysvar_epoch_rewards_t epoch_rewards = {
        .epoch_rewards= {
//          .distribution_starting_block_height = distribution_starting_block_height,
          .distribution_starting_block_height = distribution_complete_block_height,
//          .num_partitions = num_partitions,
          .num_partitions = 0,
//          .parent_blockhash = parent_blockhash,
//          .total_points = total_points,
          .total_points = 0,
          .total_rewards = total_rewards,
          .distributed_rewards = distributed_rewards,
          .active = true
        }
    };
    // set the account lamports to the undistributed rewards
    fd_acc_lamports_t undistributed_rewards = total_rewards - distributed_rewards;
    write_epoch_rewards( slot_ctx, &epoch_rewards, undistributed_rewards);
}
