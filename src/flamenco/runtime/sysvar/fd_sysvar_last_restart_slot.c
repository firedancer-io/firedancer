#include "fd_sysvar_last_restart_slot.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_acc_mgr.h"

void
fd_sysvar_last_restart_slot_write(
    fd_bank_t *                               bank,
    fd_accdb_user_t *                         accdb,
    fd_funk_txn_xid_t const *                 xid,
    fd_capture_ctx_t *                        capture_ctx,
    fd_sol_sysvar_last_restart_slot_t const * sysvar
) {
  uchar enc[ 8 ];
  FD_STORE( ulong, enc, sysvar->slot );
  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_last_restart_slot_id, enc, sizeof(enc) );
}

void
fd_sysvar_last_restart_slot_init( fd_bank_t *               bank,
                                  fd_accdb_user_t *         accdb,
                                  fd_funk_txn_xid_t const * xid,
                                  fd_capture_ctx_t *        capture_ctx ) {

  if( !FD_FEATURE_ACTIVE_BANK( bank, last_restart_slot_sysvar ) ) {
    return;
  }

  fd_sol_sysvar_last_restart_slot_t sysvar = {0};
  fd_sysvar_last_restart_slot_write( bank, accdb, xid, capture_ctx, &sysvar );
}

/* https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2217 */

ulong
fd_sysvar_last_restart_slot_derive(
    fd_hard_forks_global_t const * hard_forks,
    ulong                          current_slot
) {

  if( FD_UNLIKELY( hard_forks->hard_forks_len == 0 ) ) {
    /* SIMD-0047: The first restart slot should be `0` */
    return 0UL;
  }

  fd_slot_pair_t const * head = fd_hard_forks_hard_forks_join( (fd_hard_forks_global_t *)hard_forks );
  fd_slot_pair_t const * tail = head + hard_forks->hard_forks_len - 1UL;

  for( fd_slot_pair_t const *pair = tail; pair >= head; pair-- ) {
    if( pair->slot <= current_slot ) {
      return pair->slot;
    }
  }

  return 0UL;
}

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_last_restart_slot_read(
    fd_funk_t *                         funk,
    fd_funk_txn_xid_t const *           xid,
    fd_sol_sysvar_last_restart_slot_t * out
) {

  fd_txn_account_t acc[1];
  int err = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_last_restart_slot_id, funk, xid );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return NULL;

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_txn_account_get_lamports( acc )==0UL ) ) return NULL;

  return fd_bincode_decode_static(
      sol_sysvar_last_restart_slot, out,
      fd_txn_account_get_data( acc ),
      fd_txn_account_get_data_len( acc ),
      &err );
}

/* fd_sysvar_last_restart_slot_update is equivalent to
   Agave's solana_runtime::bank::Bank::update_last_restart_slot */

void
fd_sysvar_last_restart_slot_update(
    fd_bank_t *               bank,
    fd_accdb_user_t *         accdb,
    fd_funk_txn_xid_t const * xid,
    fd_capture_ctx_t *        capture_ctx,
    ulong                     last_restart_slot_want
) {

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2093-L2095 */
  if( !FD_FEATURE_ACTIVE_BANK( bank, last_restart_slot_sysvar ) ) return;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2098-L2106 */
  ulong last_restart_slot_have = ULONG_MAX;
  fd_sol_sysvar_last_restart_slot_t sysvar;
  if( FD_LIKELY( fd_sysvar_last_restart_slot_read( accdb->funk, xid, &sysvar ) ) ) {
    last_restart_slot_have = sysvar.slot;
  }

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2122-L2130 */
  if( last_restart_slot_have != last_restart_slot_want ) {
    sysvar.slot = last_restart_slot_want;
    fd_sysvar_last_restart_slot_write( bank, accdb, xid, capture_ctx, &sysvar );
  }
}
