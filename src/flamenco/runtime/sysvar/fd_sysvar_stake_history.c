#include "fd_sysvar_stake_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../accdb/fd_accdb_sync.h"

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
fd_sysvar_stake_history_read( fd_accdb_client_t *  accdb,
                              fd_stake_history_t * out ) {
  fd_accdb_ref_t borrow[1];
  int db_err = fd_accdb_borrow( accdb, borrow, fd_sysvar_stake_history_id.uc );
  if( FD_UNLIKELY( db_err==FD_ACCDB_ERR_KEY ) ) return NULL;
  if( FD_UNLIKELY( db_err!=FD_ACCDB_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_accdb_borrow(sysvar_stake_history) failed (%i-%s)", db_err, fd_accdb_strerror( db_err ) ));
  }

  fd_stake_history_t * result = fd_bincode_decode_static(
      stake_history, out,
      fd_accdb_ref_data   ( borrow ),
      fd_accdb_ref_data_sz( borrow ),
      NULL );

  fd_accdb_release( accdb, borrow );
  return result;
}

void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_stake_history_t stake_history;
  fd_stake_history_new( &stake_history );
  write_stake_history( slot_ctx, &stake_history );
}

void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *                        slot_ctx,
                                fd_epoch_stake_history_entry_pair_t const * pair ) {
  fd_stake_history_t stake_history_[1];
  fd_stake_history_t * stake_history = fd_sysvar_stake_history_read( slot_ctx->accdb, stake_history_ );
  if( FD_UNLIKELY( !stake_history ) ) {
    FD_LOG_ERR(( "Cannot update stake history: fd_sysvar_stake_history_read failed (corrupt sysvar?)" ));
  }

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
}
