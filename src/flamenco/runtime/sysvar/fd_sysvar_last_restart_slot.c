#include "fd_sysvar_last_restart_slot.h"
#include "../../types/fd_types.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_runtime.h"
#include "../fd_bank_mgr.h"
void
fd_sysvar_last_restart_slot_init( fd_exec_slot_ctx_t * slot_ctx ) {

  if( !FD_FEATURE_ACTIVE( slot_ctx->slot, slot_ctx->epoch_ctx->features, last_restart_slot_sysvar ) ) {
    FD_LOG_INFO(( "sysvar LastRestartSlot not supported by this ledger version!" ));
    return;
  }

  fd_bank_mgr_t bank_mgr_obj;
  fd_bank_mgr_t * bank_mgr = fd_bank_mgr_join( &bank_mgr_obj, slot_ctx->funk, slot_ctx->funk_txn );

  fd_sol_sysvar_last_restart_slot_t const * sysvar = fd_bank_mgr_last_restart_slot_query( bank_mgr );

  fd_sol_sysvar_last_restart_slot_t sysvar_default = {0};
  sysvar = !!sysvar ? sysvar : &sysvar_default;

  ulong sz = fd_sol_sysvar_last_restart_slot_size( sysvar );
  uchar enc[ sz ];
  fd_memset( enc, 0, sz );

  fd_bincode_encode_ctx_t encode = {
    .data    = enc,
    .dataend = enc + sz,
  };
  int err = fd_sol_sysvar_last_restart_slot_encode( sysvar, &encode );
  FD_TEST( err==FD_BINCODE_SUCCESS );

  fd_sysvar_set( slot_ctx,
                 &fd_sysvar_owner_id,
                 &fd_sysvar_last_restart_slot_id,
                 enc, sz,
                 slot_ctx->slot );
}

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_last_restart_slot_read( fd_funk_t *     funk,
                                  fd_funk_txn_t * funk_txn,
                                  fd_spad_t *     spad ) {

  FD_TXN_ACCOUNT_DECL( acc );
  int err = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_last_restart_slot_id, funk, funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return NULL;

  return fd_bincode_decode_spad(
      sol_sysvar_last_restart_slot, spad,
      acc->vt->get_data( acc ),
      acc->vt->get_data_len( acc ),
      &err );
}

/* fd_sysvar_last_restart_slot_update is equivalent to
   Agave's solana_runtime::bank::Bank::update_last_restart_slot */

void
fd_sysvar_last_restart_slot_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2093-L2095 */
  if( !FD_FEATURE_ACTIVE( slot_ctx->slot, slot_ctx->epoch_ctx->features, last_restart_slot_sysvar ) ) return;

  int   has_current_last_restart_slot = 0;
  ulong current_last_restart_slot     = 0UL;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2098-L2106 */
  fd_sol_sysvar_last_restart_slot_t * old_account = fd_sysvar_last_restart_slot_read( slot_ctx->funk,
                                                                                      slot_ctx->funk_txn,
                                                                                      runtime_spad );
  ulong old_account_slot        = old_account ? old_account->slot : 0UL;
  has_current_last_restart_slot = 1;
  current_last_restart_slot     = old_account_slot;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2108-L2120 */
  /* FIXME: Query hard forks list */
  fd_bank_mgr_t bank_mgr_obj;
  fd_bank_mgr_t * bank_mgr = fd_bank_mgr_join( &bank_mgr_obj, slot_ctx->funk, slot_ctx->funk_txn );
  ulong last_restart_slot = fd_bank_mgr_last_restart_slot_query( bank_mgr )->slot;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2122-L2130 */
  if( !has_current_last_restart_slot || current_last_restart_slot != last_restart_slot ) {
    fd_sysvar_set(
        slot_ctx, &fd_sysvar_owner_id,
        &fd_sysvar_last_restart_slot_id,
        &last_restart_slot, sizeof(ulong),
        slot_ctx->slot );
  }
}
