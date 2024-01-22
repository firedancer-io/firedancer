#include "fd_exec_instr_ctx.h"
#include "fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"

void *
fd_exec_instr_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_INSTR_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset(mem, 0, FD_EXEC_INSTR_CTX_FOOTPRINT);

  fd_exec_instr_ctx_t * self = (fd_exec_instr_ctx_t *) mem;

  FD_COMPILER_MFENCE();
  self->magic = FD_EXEC_INSTR_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_exec_instr_ctx_t *
fd_exec_instr_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_instr_ctx_t * ctx = (fd_exec_instr_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_INSTR_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_exec_instr_ctx_leave( fd_exec_instr_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_INSTR_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_exec_instr_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_INSTR_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_instr_ctx_t * hdr = (fd_exec_instr_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_EXEC_INSTR_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

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
fd_instr_borrowed_account_view( fd_exec_instr_ctx_t * ctx,
                                fd_pubkey_t const *      pubkey,
                                fd_borrowed_account_t * * account ) {
  for( ulong i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if readable???
      fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[i];
      *account = instr_account;

      if (FD_UNLIKELY(!fd_acc_exists(instr_account->const_meta))) {
        return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
      }

      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
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

int
fd_instr_borrowed_account_modify( fd_exec_instr_ctx_t * ctx,
                                  fd_pubkey_t const * pubkey,
                                  ulong min_data_sz,
                                  fd_borrowed_account_t * * account ) {
  for( ulong i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if writable???
      if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, (uchar)i ) ) ) {
        // FIXME: we should just handle the try_borrow_account semantics correctly
        FD_LOG_DEBUG(( "unwritable account passed to fd_instr_borrowed_account_modify_idx (idx=%lu, account=%32J)", i, pubkey ));
      }
      fd_borrowed_account_t * instr_account = ctx->instr->borrowed_accounts[i];
      if( min_data_sz > instr_account->const_meta->dlen ) {
        void * new_instr_account_data = fd_valloc_malloc( ctx->txn_ctx->valloc, 8UL, sizeof(fd_account_meta_t) + min_data_sz );
        void * old_instr_account_data = fd_borrowed_account_resize( instr_account, new_instr_account_data, min_data_sz );
        if( old_instr_account_data != NULL ) {
          fd_valloc_free( ctx->txn_ctx->valloc, old_instr_account_data );
        }
      }
      *account = instr_account;
      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}
