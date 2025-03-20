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
                                      ulong                       idx,
                                      fd_txn_account_t *          txn_account,
                                      fd_borrowed_account_t *     account ) {
  /* TODO this is slightly wrong. Agave returns NotEnoughAccountKeys when the account index is
     out of bounds in the transaction context and MissingAccount when the account index is out of
     bounds in the instruction context. */

  /* Return an AccountBorrowFailed error if the write is not acquirable.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L605 */
  int acquire_result = fd_txn_account_acquire_write( txn_account );
  if( FD_UNLIKELY( !acquire_result ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* Create a BorrowedAccount upon success.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L606 */
  fd_borrowed_account_init( account, txn_account, ctx, (int)idx );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_exec_instr_ctx_try_borrow_instr_account( fd_exec_instr_ctx_t const * ctx,
                                                  ulong                       idx,
                                                  fd_borrowed_account_t *     account ) {
  /* Return a NotEnoughAccountKeys error if the idx is out of bounds.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L603 */
  if( FD_UNLIKELY( idx >= ctx->instr->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  fd_txn_account_t * instr_account = ctx->instr->accounts[idx];

  return fd_exec_instr_ctx_try_borrow_account( ctx, idx, instr_account, account );
}

int
fd_exec_instr_ctx_try_borrow_instr_account_with_key( fd_exec_instr_ctx_t *   ctx,
                                               fd_pubkey_t const *     pubkey,
                                               fd_borrowed_account_t * account ) {
  for( ulong i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      return fd_exec_instr_ctx_try_borrow_instr_account( ctx, i, account );
    }
  }
  return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
}

int
fd_exec_instr_ctx_find_idx_of_instr_account( fd_exec_instr_ctx_t const * ctx,
                                             fd_pubkey_t const *         pubkey ) {
  for( int i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      return i;
    }
  }
  return -1;
}

int
fd_exec_instr_ctx_try_borrow_last_program_account( fd_exec_instr_ctx_t const * ctx,
                                                   fd_borrowed_account_t * account ) {
  fd_txn_account_t * program_account = NULL;
  fd_exec_txn_ctx_get_account_at_index( ctx->txn_ctx, 
                                        ctx->instr->program_id,
                                        &program_account );

  return fd_exec_instr_ctx_try_borrow_account( ctx, 
                                               ctx->instr->program_id,
                                               program_account,
                                               account );
}
