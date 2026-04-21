#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_runtime.h"
#include "../fd_accdb_svm.h"
#include "fd_sysvar_rent.h"

/* https://github.com/anza-xyz/agave/blob/v3.1/runtime/src/bank.rs#L2025 */

void
fd_sysvar_account_update( fd_bank_t *         bank,
                          fd_accdb_t *        accdb,
                          fd_capture_ctx_t *  capture_ctx,
                          fd_pubkey_t const * address,
                          void const *        data,
                          ulong               sz ) {
  fd_accdb_svm_write( bank, accdb, capture_ctx, address, &fd_sysvar_owner_id, data, sz, fd_rent_exempt_minimum_balance( &bank->f.rent, sz ), 0 );

  if( FD_UNLIKELY( fd_log_level_logfile()<=0 || fd_log_level_stderr()<=0 ) ) {
    char name[ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( address->uc, NULL, name );
    FD_LOG_DEBUG(( "Updated sysvar: address=%s data_sz=%lu", name, sz ));
  }
}

int
fd_sysvar_instr_acct_check( fd_exec_instr_ctx_t const * ctx,
                            ulong                       idx,
                            fd_pubkey_t const *         addr_want ) {
  if( FD_UNLIKELY( idx>=ctx->instr->acct_cnt ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  ushort idx_in_txn = ctx->instr->accounts[ idx ].index_in_transaction;
  uchar const * addr_have = ctx->txn_out->accounts.keys[ idx_in_txn ].uc;
  if( FD_UNLIKELY( memcmp( addr_have, addr_want, 32UL ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  return FD_EXECUTOR_INSTR_SUCCESS;
}
