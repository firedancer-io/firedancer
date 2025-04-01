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

static fd_stake_history_t *
fd_sysvar_stake_history_read( fd_exec_slot_ctx_t * slot_ctx,
                              fd_spad_t *          runtime_spad ) {
  FD_TXN_ACCOUNT_DECL( stake_rec );
  int err = fd_txn_account_init_from_funk_readonly( stake_rec, &fd_sysvar_stake_history_id, slot_ctx->funk, slot_ctx->funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t ctx = {
    .data    = stake_rec->vt->get_data( stake_rec),
    .dataend = stake_rec->vt->get_data( stake_rec) + stake_rec->vt->get_data_len( stake_rec),
  };

  ulong total_sz = 0UL;
  err = fd_stake_history_decode_footprint( &ctx, &total_sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    return NULL;
  }

  uchar * mem = fd_spad_alloc( runtime_spad, fd_stake_history_align(), total_sz );
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "Failed to allocate memory for stake history" ));
  }

  return fd_stake_history_decode( mem, &ctx );
}

void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_stake_history_t stake_history;
  fd_stake_history_new( &stake_history );
  write_stake_history( slot_ctx, &stake_history );
}

void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *       slot_ctx,
                                fd_stake_history_entry_t * entry,
                                fd_spad_t *                runtime_spad ) {
  // Need to make this maybe zero copies of map...
  fd_stake_history_t * stake_history = fd_sysvar_stake_history_read( slot_ctx, runtime_spad );

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

  stake_history->fd_stake_history[ idx ].epoch = entry->epoch;
  stake_history->fd_stake_history[ idx ].activating = entry->activating;
  stake_history->fd_stake_history[ idx ].effective = entry->effective;
  stake_history->fd_stake_history[ idx ].deactivating = entry->deactivating;

  write_stake_history( slot_ctx, stake_history );
}
