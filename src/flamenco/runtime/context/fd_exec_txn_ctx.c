#include "fd_exec_txn_ctx.h"
#include "fd_exec_slot_ctx.h"
#include "../program/fd_compute_budget_program.h"
#include "../../vm/fd_vm_context.h"

void *
fd_exec_txn_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_TXN_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  // fd_memset(mem, 0, FD_EXEC_TXN_CTX_FOOTPRINT);

  fd_exec_txn_ctx_t * self = (fd_exec_txn_ctx_t *) mem;

  FD_COMPILER_MFENCE();
  self->magic = FD_EXEC_TXN_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_exec_txn_ctx_t *
fd_exec_txn_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * ctx = (fd_exec_txn_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_exec_txn_ctx_leave( fd_exec_txn_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_exec_txn_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_TXN_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * hdr = (fd_exec_txn_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

int
fd_txn_borrowed_account_view( fd_exec_txn_ctx_t * ctx,
                              fd_pubkey_t const *      pubkey,
                              fd_borrowed_account_t * * account ) {
  for( ulong i = 0; i < ctx->accounts_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->accounts[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if readable???
      fd_borrowed_account_t * txn_account = &ctx->borrowed_accounts[i];
      *account = txn_account;

      if( FD_UNLIKELY( !fd_acc_exists( txn_account->const_meta ) ) )
        return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;

      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

int
fd_txn_borrowed_account_executable_view( fd_exec_txn_ctx_t * ctx,
                                         fd_pubkey_t const *      pubkey,
                                         fd_borrowed_account_t * * account ) {
  for( ulong i = 0; i < ctx->executable_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->executable_accounts[i].pubkey->uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if readable???
      fd_borrowed_account_t * txn_account = &ctx->executable_accounts[i];
      *account = txn_account;

      if( FD_UNLIKELY( !fd_acc_exists( txn_account->const_meta ) ) )
        return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;

      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

int
fd_txn_borrowed_account_modify_idx( fd_exec_txn_ctx_t * ctx,
                                    uchar idx,
                                    ulong min_data_sz,
                                    fd_borrowed_account_t * *  account ) {
  if( idx >= ctx->accounts_cnt ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  fd_borrowed_account_t * txn_account = &ctx->borrowed_accounts[idx];
  if( min_data_sz > txn_account->meta->dlen ) {
    void * new_txn_account_data = fd_valloc_malloc( ctx->valloc, 8UL, min_data_sz );
    void * old_txn_account_data = fd_borrowed_account_resize( txn_account, new_txn_account_data, min_data_sz );
    if( old_txn_account_data != NULL ) {
      fd_valloc_free( ctx->valloc, old_txn_account_data );
    }
  }

  // TODO: check if writable???
  *account = txn_account;
  return FD_ACC_MGR_SUCCESS;
}

int
fd_txn_borrowed_account_modify( fd_exec_txn_ctx_t * ctx,
                                fd_pubkey_t const * pubkey,
                                ulong min_data_sz,
                                fd_borrowed_account_t * * account ) {
  for( ulong i = 0; i < ctx->accounts_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->accounts[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if writable???
      fd_borrowed_account_t * txn_account = &ctx->borrowed_accounts[i];
      if( min_data_sz > txn_account->const_meta->dlen ) {
        void * new_txn_account_data = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(fd_account_meta_t) + min_data_sz );
        void * old_txn_account_data = fd_borrowed_account_resize( txn_account, new_txn_account_data, min_data_sz );
        if( old_txn_account_data != NULL ) {
          fd_valloc_free( ctx->valloc, old_txn_account_data );
        }
      }
      *account = txn_account;
      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

void
fd_exec_txn_ctx_setup( fd_exec_txn_ctx_t *   txn_ctx,
                       fd_txn_t const *      txn_descriptor,
                       fd_rawtxn_b_t const * txn_raw ) {
  txn_ctx->compute_unit_limit = 200000;
  txn_ctx->compute_unit_price = 0;
  txn_ctx->compute_meter      = 200000;
  txn_ctx->prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED;
  txn_ctx->custom_err         = UINT_MAX;

  txn_ctx->instr_stack_sz     = 0;
  txn_ctx->accounts_cnt       = 0;
  txn_ctx->executable_cnt     = 0;
  txn_ctx->paid_fees          = 0;
  txn_ctx->heap_size          = FD_VM_DEFAULT_HEAP_SZ;
  txn_ctx->loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;

  txn_ctx->txn_descriptor = txn_descriptor;
  txn_ctx->_txn_raw = txn_raw;

  txn_ctx->num_instructions = 0;
  memset( txn_ctx->return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_ctx->return_data.len = 0;
}

void
fd_exec_txn_ctx_teardown( fd_exec_txn_ctx_t * txn_ctx ) {
  (void)txn_ctx;
}

void
fd_exec_txn_ctx_from_exec_slot_ctx( fd_exec_slot_ctx_t * slot_ctx,
                                    fd_exec_txn_ctx_t * txn_ctx ) {
  txn_ctx->slot_ctx = slot_ctx;
  txn_ctx->epoch_ctx = slot_ctx->epoch_ctx;
  txn_ctx->valloc = slot_ctx->valloc;
  txn_ctx->funk_txn = NULL;
  txn_ctx->acc_mgr = slot_ctx->acc_mgr;
}
