#include "fd_sysvar_last_restart_slot.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

static void
fd_sysvar_last_restart_slot_write( fd_bank_t *        bank,
                                   fd_accdb_t *       accdb,
                                   fd_capture_ctx_t * capture_ctx,
                                   ulong              slot ) {
  uchar enc[ 8 ];
  FD_STORE( ulong, enc, slot );
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_last_restart_slot_id, enc, sizeof(enc) );
}

void
fd_sysvar_last_restart_slot_init( fd_bank_t *        bank,
                                  fd_accdb_t *       accdb,
                                  fd_capture_ctx_t * capture_ctx ) {
  if( !FD_FEATURE_ACTIVE_BANK( bank, last_restart_slot_sysvar ) ) return;

  fd_sysvar_last_restart_slot_write( bank, accdb, capture_ctx, 0UL );
}

static ulong
fd_sysvar_last_restart_slot_read( fd_accdb_t *       accdb,
                                  fd_accdb_fork_id_t fork_id,
                                  ulong              sentinel ) {
  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork_id, fd_sysvar_last_restart_slot_id.uc );
  if( FD_UNLIKELY( !entry.lamports ) ) return sentinel;

  ulong result = FD_LOAD( ulong, entry.data );
  fd_accdb_unread_one( accdb, &entry );
  return result;
}

/* fd_sysvar_last_restart_slot_update is equivalent to
   Agave's solana_runtime::bank::Bank::update_last_restart_slot */

void
fd_sysvar_last_restart_slot_update( fd_bank_t *        bank,
                                    fd_accdb_t *       accdb,
                                    fd_capture_ctx_t * capture_ctx,
                                    ulong              last_restart_slot_want ) {

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2093-L2095 */
  if( !FD_FEATURE_ACTIVE_BANK( bank, last_restart_slot_sysvar ) ) return;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2098-L2106 */
  ulong last_restart_slot_have = fd_sysvar_last_restart_slot_read( accdb, bank->accdb_fork_id, ULONG_MAX );

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2122-L2130 */
  if( last_restart_slot_have!=last_restart_slot_want ) {
    fd_sysvar_last_restart_slot_write( bank, accdb, capture_ctx, last_restart_slot_want );
  }
}
