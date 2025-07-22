#include "fd_sysvar_stake_history.h"
#include "../fd_system_ids.h"
#include "fd_sysvar_epoch_schedule.h"

void
fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong sz_max;
  uchar * data = fd_sysvar_cache_data_modify_prepare( slot_ctx, &fd_sysvar_stake_history_id, NULL, &sz_max );
  FD_TEST( sz_max>=FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  fd_memset( data, 0, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  fd_sysvar_cache_data_modify_commit( slot_ctx, &fd_sysvar_stake_history_id, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );

}

/* https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2365 */

void
fd_sysvar_stake_history_update( fd_exec_slot_ctx_t *                        slot_ctx,
                                fd_epoch_stake_history_entry_pair_t const * entry ) {

  fd_sysvar_cache_t * sysvar_cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  fd_epoch_schedule_t const epoch_schedule = fd_sysvar_epoch_schedule_read_nofail( sysvar_cache );

  ulong const prev_slot  = fd_bank_parent_slot_get( slot_ctx->bank );
  ulong const cur_slot   = fd_bank_slot_get( slot_ctx->bank );
  ulong const prev_epoch = fd_slot_to_epoch( &epoch_schedule, prev_slot, NULL );
  ulong const cur_epoch  = fd_slot_to_epoch( &epoch_schedule, cur_slot,  NULL );

  if( FD_LIKELY( prev_epoch==cur_epoch ) ) return;

  if( FD_UNLIKELY( !fd_sysvar_stake_history_is_valid( sysvar_cache ) ) ) {
    fd_sysvar_stake_history_init( slot_ctx );
  }

  fd_stake_history_t * stake_history = fd_sysvar_stake_history_join( slot_ctx );
  if( FD_UNLIKELY( !stake_history ) ) FD_LOG_ERR(( "Stake history sysvar is invalid, cannot update" ));

  if( stake_history->fd_stake_history_offset == 0 ) {
    stake_history->fd_stake_history_offset = stake_history->fd_stake_history_size - 1;
  } else {
    stake_history->fd_stake_history_offset--;
  }

  if( stake_history->fd_stake_history_len < stake_history->fd_stake_history_size ) {
    stake_history->fd_stake_history_len++;
  }

  // This should be done with a bit mask
  // (FIXME what did Josh mean with this comment)
  ulong idx = stake_history->fd_stake_history_offset;

  stake_history->fd_stake_history[ idx ] = *entry;

  fd_sysvar_stake_history_leave( slot_ctx, stake_history );
}
