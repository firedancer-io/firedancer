#include "fd_sysvar_epoch_rewards.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"

void
fd_sysvar_epoch_rewards_burn_and_purge(
    fd_global_ctx_t * global
) {
    FD_BORROWED_ACCOUNT_DECL(rewards);

    int rc = fd_acc_mgr_modify( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_epoch_rewards, 0, 0, rewards);
    if ( FD_UNLIKELY( rc ) ) return; // not good...

    fd_memcpy(rewards->meta->info.owner, (fd_pubkey_t *) global->solana_system_program, sizeof(fd_pubkey_t));
    rewards->meta->dlen = 0;
    rewards->meta->info.lamports = 0;
}

static void
write_epoch_rewards( fd_global_ctx_t * global, fd_sysvar_epoch_rewards_t * epoch_rewards, fd_acc_lamports_t * acc_lamports) {
  ulong          sz = fd_sysvar_epoch_rewards_size( epoch_rewards );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_sysvar_epoch_rewards_encode( epoch_rewards, &ctx ) ) {
    FD_LOG_ERR(("fd_sysvar_epoch_rewards_encode failed"));
  }

  fd_sysvar_set( global, global->sysvar_owner, (fd_pubkey_t *) global->sysvar_epoch_rewards, enc, sz, global->bank.slot, acc_lamports );
}


void
fd_sysvar_epoch_rewards_read(
    fd_global_ctx_t * global,
    fd_sysvar_epoch_rewards_t * result,
    fd_acc_lamports_t * acc_lamports
) {
    FD_BORROWED_ACCOUNT_DECL(rewards_rec);

    int err = fd_acc_mgr_view( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->sysvar_epoch_rewards, rewards_rec );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to read fees sysvar: %d", err ));
      return;
    }

    fd_bincode_decode_ctx_t decode = {
      .data    = rewards_rec->const_data,
      .dataend = rewards_rec->const_data + rewards_rec->const_meta->dlen,
      .valloc  = global->valloc
    };

    if( FD_UNLIKELY( fd_sysvar_epoch_rewards_decode( result, &decode ) ) )
        FD_LOG_ERR(("fd_sysvar_epoch_rewards_decode failed"));

    if (NULL != acc_lamports)
      *acc_lamports = rewards_rec->const_meta->info.lamports;
}

/* Update EpochRewards sysvar with distributed rewards */
void
fd_sysvar_epoch_rewards_update(
    fd_global_ctx_t * global,
    ulong distributed
) {
    fd_sysvar_epoch_rewards_t result;
    fd_acc_lamports_t acc_lamports = 0UL;
    fd_sysvar_epoch_rewards_read( global, &result, &acc_lamports );
    FD_TEST( acc_lamports != 0 );

    FD_TEST( result.epoch_rewards.distributed_rewards + distributed <= result.epoch_rewards.total_rewards );
    result.epoch_rewards.distributed_rewards += distributed;

    acc_lamports -= distributed;

    write_epoch_rewards( global, &result, &acc_lamports);
}

/* Create EpochRewards syavar with calculated rewards */
void
fd_sysvar_epoch_rewards_init(
    fd_global_ctx_t* global,
    ulong total_rewards,
    ulong distributed_rewards,
    ulong distribution_complete_block_height
) {
    FD_TEST( total_rewards >= distributed_rewards );

    fd_sysvar_epoch_rewards_t epoch_rewards = {
        .epoch_rewards={
            .distributed_rewards = distributed_rewards,
            .total_rewards = total_rewards,
            .distribution_complete_block_height = distribution_complete_block_height
        }
    };
    // set the account lamports to the undistributed rewards
    fd_acc_lamports_t undistributed_rewards = total_rewards - distributed_rewards;
    write_epoch_rewards( global, &epoch_rewards, &undistributed_rewards);
}
