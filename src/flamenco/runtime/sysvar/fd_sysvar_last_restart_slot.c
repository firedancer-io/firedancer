#include "fd_sysvar_last_restart_slot.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../../accdb/fd_accdb_sync.h"

void
fd_sysvar_last_restart_slot_write(
    fd_bank_t *               bank,
    fd_accdb_user_t *         accdb,
    fd_funk_txn_xid_t const * xid,
    fd_capture_ctx_t *        capture_ctx,
    ulong                     slot
) {
  uchar enc[ 8 ];
  FD_STORE( ulong, enc, slot );
  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_last_restart_slot_id, enc, sizeof(enc) );
}

void
fd_sysvar_last_restart_slot_init( fd_bank_t *               bank,
                                  fd_accdb_user_t *         accdb,
                                  fd_funk_txn_xid_t const * xid,
                                  fd_capture_ctx_t *        capture_ctx ) {

  if( !FD_FEATURE_ACTIVE_BANK( bank, last_restart_slot_sysvar ) ) return;

  fd_sysvar_last_restart_slot_write( bank, accdb, xid, capture_ctx, 0UL );
}

ulong
fd_sysvar_last_restart_slot_read( fd_accdb_user_t *         accdb,
                                  fd_funk_txn_xid_t const * xid,
                                  ulong                     sentinel ) {

  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, &fd_sysvar_last_restart_slot_id ) ) ) {
    return sentinel;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_accdb_ref_lamports( ro )==0UL ) ) {
    fd_accdb_close_ro( accdb, ro );
    return sentinel;
  }

  ulong result = FD_LOAD( ulong, fd_accdb_ref_data_const( ro ) );
  fd_accdb_close_ro( accdb, ro );
  return result;
}

/* fd_sysvar_last_restart_slot_update is equivalent to
   Agave's solana_runtime::bank::Bank::update_last_restart_slot */

void
fd_sysvar_last_restart_slot_update( fd_bank_t *               bank,
                                    fd_accdb_user_t *         accdb,
                                    fd_funk_txn_xid_t const * xid,
                                    fd_capture_ctx_t *        capture_ctx,
                                    ulong                     last_restart_slot_want ) {

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2093-L2095 */
  if( !FD_FEATURE_ACTIVE_BANK( bank, last_restart_slot_sysvar ) ) return;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2098-L2106 */
  ulong last_restart_slot_have = fd_sysvar_last_restart_slot_read( accdb, xid, ULONG_MAX );

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2122-L2130 */
  if( last_restart_slot_have!=last_restart_slot_want ) {
    fd_sysvar_last_restart_slot_write( bank, accdb, xid, capture_ctx, last_restart_slot_want );
  }
}
