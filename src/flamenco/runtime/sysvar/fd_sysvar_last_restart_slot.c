#include "fd_sysvar_last_restart_slot.h"
#include "fd_sysvar.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../../accdb/fd_accdb_sync.h"
#include "fd_sysvar_base.h"

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

  if( FD_UNLIKELY( fd_accdb_ref_data_sz( ro )!=FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ ) ) {
    fd_accdb_close_ro( accdb, ro );
    return sentinel;
  }

  ulong result = FD_LOAD( ulong, fd_accdb_ref_data_const( ro ) );
  fd_accdb_close_ro( accdb, ro );
  return result;
}

/* fd_sysvar_last_restart_slot_update is equivalent to
   Agave's solana_runtime::bank::Bank::update_last_restart_slot */

ulong
fd_sysvar_last_restart_slot_derive( fd_bank_t const * bank ) {
  ulong slot = bank->f.slot;
  ulong last_restart_slot = 0UL;

  for( ulong i=0UL; i<bank->f.hard_fork_cnt; i++ ) {
    ulong hard_fork_slot = bank->f.hard_forks[ i ].slot;
    if( hard_fork_slot<=slot && hard_fork_slot>last_restart_slot ) {
      last_restart_slot = hard_fork_slot;
    }
  }

  return last_restart_slot;
}

void
fd_sysvar_last_restart_slot_update( fd_bank_t *               bank,
                                    fd_accdb_user_t *         accdb,
                                    fd_funk_txn_xid_t const * xid,
                                    fd_capture_ctx_t *        capture_ctx ) {

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2093-L2095 */
  if( !FD_FEATURE_ACTIVE_BANK( bank, last_restart_slot_sysvar ) ) return;

  ulong last_restart_slot_want = fd_sysvar_last_restart_slot_derive( bank );
  bank->f.last_restart_slot = last_restart_slot_want;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2098-L2106 */
  ulong last_restart_slot_have = fd_sysvar_last_restart_slot_read( accdb, xid, ULONG_MAX );

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2122-L2130 */
  if( last_restart_slot_have!=last_restart_slot_want ) {
    fd_sysvar_last_restart_slot_write( bank, accdb, xid, capture_ctx, last_restart_slot_want );
  }
}
