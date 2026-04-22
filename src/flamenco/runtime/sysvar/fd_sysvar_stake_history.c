#include "fd_sysvar_stake_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

static void
write_stake_history( fd_bank_t *                bank,
                     fd_accdb_t *               accdb,
                     fd_capture_ctx_t *         capture_ctx,
                     fd_stake_history_t const * stake_history ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/stake_history.rs#L12 */
  uchar __attribute__((aligned(FD_STAKE_HISTORY_ALIGN))) enc[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ] = {0};
  fd_bincode_encode_ctx_t encode = {
    .data    = enc,
    .dataend = enc+sizeof(enc)
  };

  FD_TEST( fd_stake_history_encode( stake_history, &encode )==FD_BINCODE_SUCCESS );
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_stake_history_id, enc, sizeof(enc) );
}

fd_stake_history_t *
fd_sysvar_stake_history_read( fd_accdb_t *         accdb,
                              fd_accdb_fork_id_t   fork_id,
                              fd_stake_history_t * stake_history ) {
  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork_id, fd_sysvar_stake_history_id.uc );
  if( FD_UNLIKELY( !entry.lamports ) ) return NULL;

  stake_history = fd_bincode_decode_static( stake_history, stake_history, entry.data, entry.data_len );
  fd_accdb_unread_one( accdb, &entry );
  return stake_history;
}

void
fd_sysvar_stake_history_init( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx ) {
  fd_stake_history_t stake_history;
  fd_stake_history_new( &stake_history );
  write_stake_history( bank, accdb, capture_ctx, &stake_history );
}

void
fd_sysvar_stake_history_update( fd_bank_t *                                 bank,
                                fd_accdb_t *                                accdb,
                                fd_capture_ctx_t *                          capture_ctx,
                                fd_epoch_stake_history_entry_pair_t const * pair ) {
  fd_stake_history_t stake_history[1];
  FD_TEST( fd_sysvar_stake_history_read( accdb, bank->accdb_fork_id, stake_history ) );

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

  write_stake_history( bank, accdb, capture_ctx, stake_history );
}
