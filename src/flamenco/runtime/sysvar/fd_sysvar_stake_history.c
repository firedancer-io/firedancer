#include "fd_sysvar_stake_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
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

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_stake_history_id, enc, sizeof(enc), slot_ctx->slot_bank.slot );
}

fd_stake_history_t *
fd_sysvar_stake_history_read( fd_stake_history_t * result,
                              fd_exec_slot_ctx_t * slot_ctx,
                              fd_valloc_t *        valloc ) {
  FD_BORROWED_ACCOUNT_DECL(stake_rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_stake_history_id, stake_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t ctx = {
    .data = stake_rec->const_data,
    .dataend = (char *) stake_rec->const_data + stake_rec->const_meta->dlen,
    .valloc  = *valloc
  };

  if( FD_UNLIKELY( fd_stake_history_decode( result, &ctx )!=FD_BINCODE_SUCCESS ) )
    return NULL;
  return result;
}

void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_stake_history_t stake_history;
  fd_stake_history_new( &stake_history );
  write_stake_history( slot_ctx, &stake_history );
}

void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *       slot_ctx,
                                fd_stake_history_entry_t * entry ) {
  // Need to make this maybe zero copies of map...
  fd_stake_history_t stake_history;
  fd_sysvar_stake_history_read( &stake_history, slot_ctx, &slot_ctx->valloc );

  if( stake_history.fd_stake_history_offset == 0 )
    stake_history.fd_stake_history_offset = stake_history.fd_stake_history_size - 1;
  else
    stake_history.fd_stake_history_offset--;

  if( stake_history.fd_stake_history_len < stake_history.fd_stake_history_size)
    stake_history.fd_stake_history_len++;

  // This should be done with a bit mask
  ulong idx = stake_history.fd_stake_history_offset;

  stake_history.fd_stake_history[ idx ].epoch = entry->epoch;
  stake_history.fd_stake_history[ idx ].activating = entry->activating;
  stake_history.fd_stake_history[ idx ].effective = entry->effective;
  stake_history.fd_stake_history[ idx ].deactivating = entry->deactivating;

  write_stake_history( slot_ctx, &stake_history);
  fd_bincode_destroy_ctx_t destroy = { .valloc = slot_ctx->valloc };
  fd_stake_history_destroy( &stake_history, &destroy );
}
