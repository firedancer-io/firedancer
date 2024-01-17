#include "fd_exec_instr_ctx.h"
#include "fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"

int
fd_instr_borrowed_account_view_idx( fd_exec_instr_ctx_t * ctx,
                                    uchar idx,
                                    fd_borrowed_account_t * *  account ) {
  if( idx >= ctx->instr->acct_cnt )
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;

  fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[idx];
  *account = instr_account;
  return FD_ACC_MGR_SUCCESS;
}

int
fd_instr_borrowed_account_modify_idx( fd_exec_instr_ctx_t *    ctx,
                                      uchar                    idx,
                                      ulong                    min_data_sz,
                                      fd_borrowed_account_t ** account ) {
  if( FD_UNLIKELY( idx >= ctx->instr->acct_cnt ) )
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, idx ) ) ) {
    /* FIXME: we should just handle the try_borrow_account semantics correctly */
    FD_LOG_DEBUG(( "unwritable account passed to fd_instr_borrowed_account_modify_idx (idx=%u)", idx ));
  }

  fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[idx];
  if( min_data_sz > instr_account->const_meta->dlen ) {
    /* TODO expensive copy */
    void * new_instr_account_data = fd_valloc_malloc( ctx->txn_ctx->valloc, 8UL, min_data_sz );
    void * old_instr_account_data = fd_borrowed_account_resize( instr_account, new_instr_account_data, min_data_sz );
    if( old_instr_account_data != NULL ) {
      fd_valloc_free( ctx->txn_ctx->valloc, old_instr_account_data );
    }
  }

  /* TODO: consider checking if account is writable */
  *account = instr_account;
  return FD_ACC_MGR_SUCCESS;
}
