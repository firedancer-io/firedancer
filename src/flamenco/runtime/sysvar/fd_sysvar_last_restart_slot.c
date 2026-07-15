#include "fd_sysvar_last_restart_slot.h"
#include "fd_sysvar.h"
#include "../fd_bank.h"
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
  fd_sysvar_last_restart_slot_write( bank, accdb, capture_ctx, 0UL );
}

ulong
fd_sysvar_last_restart_slot_read( fd_accdb_t *       accdb,
                                  fd_accdb_fork_id_t fork_id,
                                  ulong              sentinel ) {
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, fd_sysvar_last_restart_slot_id.uc );
  if( FD_UNLIKELY( !acc.lamports || acc.data_len!=FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return sentinel;
  }

  ulong result = FD_LOAD( ulong, acc.data );
  fd_accdb_unread_one( accdb, &acc );
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
fd_sysvar_last_restart_slot_update( fd_bank_t *        bank,
                                    fd_accdb_t *       accdb,
                                    fd_capture_ctx_t * capture_ctx ) {

  ulong last_restart_slot_want = fd_sysvar_last_restart_slot_derive( bank );

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2098-L2106 */
  ulong last_restart_slot_have = fd_sysvar_last_restart_slot_read( accdb, bank->accdb_fork_id, ULONG_MAX );

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2122-L2130 */
  if( last_restart_slot_have!=last_restart_slot_want ) {
    fd_sysvar_last_restart_slot_write( bank, accdb, capture_ctx, last_restart_slot_want );
  }
}
