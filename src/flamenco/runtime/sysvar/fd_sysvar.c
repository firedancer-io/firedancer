#include "fd_sysvar.h"
#include "fd_sysvar_rent.h"
#include "../fd_system_ids.h"
#include "../fd_runtime_account.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1813 */
void
fd_sysvar_account_update( fd_exec_slot_ctx_t * slot_ctx,
                          fd_pubkey_t const *  address,
                          void const *         data,
                          ulong                sz ) {
  fd_rent_t const * rent    = fd_bank_rent_query( slot_ctx->bank );
  ulong     const   min_bal = fd_rent_exempt_minimum_balance( rent, sz );

  FD_RUNTIME_ACCOUNT_UPDATE_BEGIN( slot_ctx, address, rec, sz ) {
    fd_accdb_ref_owner_set( rec, &fd_sysvar_owner_id );
    ulong const lamports_before = fd_accdb_ref_lamports( rec->ro );
    ulong const lamports_after  = fd_ulong_max( lamports_before, min_bal );
    fd_accdb_ref_lamports_set( rec, lamports_after );
    fd_accdb_ref_data_set( rec, data, sz );

    FD_LOG_DEBUG(( "Updated sysvar: address=%s data_sz=%lu slot=%lu lamports=%lu",
                   FD_BASE58_ENC_32_ALLOCA( address ), sz, fd_bank_slot_get( slot_ctx->bank ), lamports_after ));
  }
  FD_RUNTIME_ACCOUNT_UPDATE_END;
}

int
fd_sysvar_instr_acct_check( fd_exec_instr_ctx_t const * ctx,
                            ulong                       idx,
                            fd_pubkey_t const *         addr_want ) {

  if( FD_UNLIKELY( idx >= ctx->instr->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  ushort idx_in_txn = ctx->instr->accounts[idx].index_in_transaction;
  fd_pubkey_t const * addr_have = &ctx->txn_ctx->account_keys[ idx_in_txn ];
  if( FD_UNLIKELY( 0!=memcmp( addr_have, addr_want, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
