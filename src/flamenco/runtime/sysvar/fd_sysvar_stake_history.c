#include "fd_sysvar_stake_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_stake_history_t stake_history;
  fd_stake_history_new( &stake_history );
  write_stake_history( slot_ctx, &stake_history );
}

void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *                  slot_ctx,
                                fd_epoch_stake_history_entry_pair_t * pair,
                                fd_spad_t *                           runtime_spad ) {
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
}
