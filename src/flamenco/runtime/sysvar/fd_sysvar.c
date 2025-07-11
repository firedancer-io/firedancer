#include "fd_sysvar.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_txn_ctx.h"

FD_FN_PURE int
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
