#include "fd_sysvar_stake_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_txn_account.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"

/* Ensure that the size declared by our header matches the minimum size
   of the corresponding fd_types entry. */

static void
write_stake_history( fd_exec_slot_ctx_t * slot_ctx,
                     fd_stake_history_t * stake_history ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/stake_history.rs#L12 */
  uchar enc[16392] = {0};

  fd_bincode_encode_ctx_t encode =
    { .data    = enc,
      .dataend = enc + sizeof(enc) };
  if( FD_UNLIKELY( fd_stake_history_encode( stake_history, &encode )!=FD_BINCODE_SUCCESS ) )
    FD_LOG_ERR(("fd_stake_history_encode failed"));

  fd_sysvar_account_update( slot_ctx, &fd_sysvar_stake_history_id, enc, sizeof(enc) );
}

fd_stake_history_t *
fd_sysvar_stake_history_read( fd_funk_t *     funk,
                              fd_funk_txn_t * funk_txn,
                              fd_spad_t *     spad ) {
  FD_TXN_ACCOUNT_DECL( stake_rec );
  int err = fd_txn_account_init_from_funk_readonly( stake_rec, &fd_sysvar_stake_history_id, funk, funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( stake_rec->vt->get_lamports( stake_rec )==0 ) ) {
    return NULL;
  }

  return fd_bincode_decode_spad(
      stake_history, spad,
      stake_rec->vt->get_data( stake_rec ),
      stake_rec->vt->get_data_len( stake_rec ),
      &err );
}

void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_stake_history_t stake_history;
  fd_stake_history_new( &stake_history );
  write_stake_history( slot_ctx, &stake_history );
}

void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *                        slot_ctx,
                                fd_epoch_stake_history_entry_pair_t const * pair,
                                fd_spad_t *                                 runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  // Need to make this maybe zero copies of map...
  fd_stake_history_t * stake_history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );

  if( stake_history->fd_stake_history_offset == 0 ) {
    stake_history->fd_stake_history_offset = stake_history->fd_stake_history_size - 1;
  } else {
    stake_history->fd_stake_history_offset--;
  }

  if( stake_history->fd_stake_history_len < stake_history->fd_stake_history_size ) {
    stake_history->fd_stake_history_len++;
  }

  // This should be done with a bit mask
  ulong idx = stake_history->fd_stake_history_offset;

  stake_history->fd_stake_history[ idx ].epoch              = pair->epoch;
  stake_history->fd_stake_history[ idx ].entry.activating   = pair->entry.activating;
  stake_history->fd_stake_history[ idx ].entry.effective    = pair->entry.effective;
  stake_history->fd_stake_history[ idx ].entry.deactivating = pair->entry.deactivating;

  write_stake_history( slot_ctx, stake_history );

  } FD_SPAD_FRAME_END;
}
