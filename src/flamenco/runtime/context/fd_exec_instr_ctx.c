#include "fd_exec_instr_ctx.h"
#include "../fd_borrowed_account.h"

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
fd_exec_instr_ctx_try_borrow_account( fd_exec_instr_ctx_t const * ctx,
                                      ushort                      instr_acc_idx,
                                      ushort                      idx_in_txn,
                                      fd_borrowed_account_t *     account ) {  
  /* Get the account from the transaction context using idx_in_txn.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L600-L602 */
  fd_txn_account_t * txn_account = NULL;
  int err = fd_exec_txn_ctx_get_account_at_index( ctx->txn_ctx, idx_in_txn, &txn_account );
  if( FD_UNLIKELY( err ) ) {
    /* Return a MissingAccount error if the account is not found.
       https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L603 */
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  /* Return an AccountBorrowFailed error if the write is not acquirable.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L605 */
  int acquire_result = fd_txn_account_acquire_write( txn_account );
  if( FD_UNLIKELY( !acquire_result ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* Create a BorrowedAccount upon success.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L606 */
  fd_borrowed_account_init( account, txn_account, ctx, (int)instr_acc_idx );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_exec_instr_ctx_try_borrow_instr_account( fd_exec_instr_ctx_t const * ctx,
                                            ushort                      idx,
                                            fd_borrowed_account_t *     account ) {
  /* Find the index of the account in the transaction context.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L649-L650 */
  ushort idx_in_txn;
  int err = fd_exec_instr_ctx_get_index_of_instr_account_in_transaction( ctx, idx, &idx_in_txn );
  if( FD_UNLIKELY( err ) ) return err;

  return fd_exec_instr_ctx_try_borrow_account( ctx, idx, idx_in_txn, account );
}

int
fd_exec_instr_ctx_try_borrow_instr_account_with_key( fd_exec_instr_ctx_t *   ctx,
                                                     fd_pubkey_t const *     pubkey,
                                                     fd_borrowed_account_t * account ) {
  for( ushort i = 0; i < ctx->instr->acct_cnt; i++ ) {
    ushort idx_in_txn = ctx->instr->accts[ i ].index_in_transaction;
    if( memcmp( pubkey->uc, ctx->txn_ctx->account_keys[ idx_in_txn ].uc, sizeof(fd_pubkey_t) )==0 ) {
      return fd_exec_instr_ctx_try_borrow_instr_account( ctx, i, account );
    }
  }
  return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
}

int
fd_exec_instr_ctx_find_idx_of_instr_account( fd_exec_instr_ctx_t const * ctx,
                                             fd_pubkey_t const *         pubkey ) {
  for( int i = 0; i < ctx->instr->acct_cnt; i++ ) {
    ushort idx_in_txn = ctx->instr->accts[ i ].index_in_transaction;
    if( memcmp( pubkey->uc, ctx->txn_ctx->account_keys[ idx_in_txn ].uc, sizeof(fd_pubkey_t) )==0 ) {
      return i;
    }
  }
  return -1;
}

int
fd_exec_instr_ctx_try_borrow_last_program_account( fd_exec_instr_ctx_t const * ctx,
                                                   fd_borrowed_account_t * account ) {
  return fd_exec_instr_ctx_try_borrow_account( ctx, 
                                               0UL,
                                               ctx->instr->program_id,
                                               account );
}

int
fd_exec_instr_ctx_get_signers( fd_exec_instr_ctx_t const * ctx,
                               fd_pubkey_t const *         signers[static FD_TXN_SIG_MAX] ) {
  ulong j = 0UL;
  for( uchar i = 0; i < ctx->instr->acct_cnt && j < FD_TXN_SIG_MAX; i++ )
    if( fd_instr_acc_is_signer_idx( ctx->instr, i ) ) {
      int err = fd_exec_txn_ctx_get_key_of_account_at_index( ctx->txn_ctx, i, &signers[j]);
      if( FD_UNLIKELY( err ) ) return err;
    }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_exec_instr_ctx_any_signed( fd_exec_instr_ctx_t const * ctx,
                              fd_pubkey_t const *         pubkey ) {
  int is_signer = 0;
  for( ushort j=0UL; j < ctx->instr->acct_cnt; j++ ) {
    is_signer |=
      ( ( !!fd_instr_acc_is_signer_idx( ctx->instr, j ) ) &
        ( 0==memcmp( pubkey->key, ctx->txn_ctx->account_keys[ ctx->instr->accts[ j ].index_in_transaction ].key, sizeof(fd_pubkey_t) ) ) );
  }
  return is_signer;
}

int
fd_exec_instr_ctx_get_key_of_account_at_index( fd_exec_instr_ctx_t const * ctx,
                                               ushort                      instr_acc_idx,
                                               fd_pubkey_t const * *       key ) {
  ushort idx_in_txn;
  int err = fd_exec_instr_ctx_get_index_of_instr_account_in_transaction( ctx, instr_acc_idx, &idx_in_txn );
  if( FD_UNLIKELY( err ) ) return err;

  return fd_exec_txn_ctx_get_key_of_account_at_index( ctx->txn_ctx, idx_in_txn, key );
}
