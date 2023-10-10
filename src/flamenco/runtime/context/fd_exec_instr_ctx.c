#include "fd_exec_instr_ctx.h"

#include "../fd_acc_mgr.h"

inline int
fd_instr_borrowed_account_view_idx( fd_exec_instr_ctx_t * ctx,
                                    uchar idx,
                                    fd_borrowed_account_t * *  account ) {
  if( idx >= ctx->instr->acct_cnt ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  // TODO: check if readable???
  fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[idx];
  *account = instr_account;
  return FD_ACC_MGR_SUCCESS;
}

int
fd_instr_borrowed_account_view( fd_exec_instr_ctx_t * ctx,
                                fd_pubkey_t const *      pubkey,
                                fd_borrowed_account_t * * account ) {
  for( ulong i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if readable???
      fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[i];
      *account = instr_account;

      if (FD_UNLIKELY(!FD_RAW_ACCOUNT_EXISTS(instr_account->const_meta)))
        return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;

      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

int
fd_instr_borrowed_account_modify_idx( fd_exec_instr_ctx_t * ctx,
                                uchar idx,
                                int do_create,
                                ulong min_data_sz,
                                fd_borrowed_account_t * *  account ) {
  if( idx >= ctx->instr->acct_cnt ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[idx];
  int err = fd_acc_mgr_modify( ctx->acc_mgr, ctx->funk_txn, &ctx->instr->acct_pubkeys[idx], do_create, min_data_sz, instr_account );
  if( err != FD_ACC_MGR_SUCCESS ) {
    return err;
  }
  // TODO: check if writable???
  *account = instr_account;
  return FD_ACC_MGR_SUCCESS;
}

int
fd_instr_borrowed_account_modify( fd_exec_instr_ctx_t * ctx,
                                  fd_pubkey_t const * pubkey,
                                  int do_create,
                                  ulong min_data_sz,
                                  fd_borrowed_account_t * * account ) {
  for( ulong i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if writable???
      fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[i];
      int err = fd_acc_mgr_modify( ctx->acc_mgr, ctx->funk_txn, &ctx->instr->acct_pubkeys[i], do_create, min_data_sz, instr_account );
      if( err != FD_ACC_MGR_SUCCESS ) {
        return err;
      }
      *account = instr_account;
      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}
