#include "fd_exec_instr_ctx.h"
#include "../fd_borrowed_account.h"

int
fd_exec_instr_ctx_find_idx_of_instr_account( fd_exec_instr_ctx_t const * ctx,
                                             fd_pubkey_t const *         pubkey ) {
  for( int i=0; i<ctx->instr->acct_cnt; i++ ) {
    ushort idx_in_txn = ctx->instr->accounts[ i ].index_in_transaction;
    if( memcmp( pubkey->uc, ctx->txn_ctx->account_keys[ idx_in_txn ].uc, sizeof(fd_pubkey_t) )==0 ) {
      return i;
    }
  }
  return -1;
}

int
fd_exec_instr_ctx_get_key_of_account_at_index( fd_exec_instr_ctx_t const * ctx,
                                               ushort                      idx_in_instr,
                                               fd_pubkey_t const * *       key ) {
  ushort idx_in_txn;
  int err = fd_exec_instr_ctx_get_index_of_instr_account_in_transaction( ctx,
                                                                         idx_in_instr,
                                                                         &idx_in_txn );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  return fd_exec_txn_ctx_get_key_of_account_at_index( ctx->txn_ctx,
                                                      idx_in_txn,
                                                      key );
}

int
fd_exec_instr_ctx_get_last_program_key( fd_exec_instr_ctx_t const * ctx,
                                        fd_pubkey_t const * *       key ) {
  return fd_exec_txn_ctx_get_key_of_account_at_index( ctx->txn_ctx,
                                                      ctx->instr->program_id,
                                                      key );
}

int
fd_exec_instr_ctx_try_borrow_account( fd_exec_instr_ctx_t const * ctx,
                                      ushort                      idx_in_instr,
                                      ushort                      idx_in_txn,
                                      fd_borrowed_account_t *     account ) {
  /* Get the account from the transaction context using idx_in_txn.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L600-L602 */
  fd_txn_account_t * txn_account = NULL;
  int err = fd_exec_txn_ctx_get_account_at_index( ctx->txn_ctx,
                                                  idx_in_txn,
                                                  &txn_account,
                                                  NULL );
  if( FD_UNLIKELY( err ) ) {
    /* Return a MissingAccount error if the account is not found.
       https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L603 */
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  /* Return an AccountBorrowFailed error if the write is not acquirable.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L605 */
  int borrow_res = fd_txn_account_try_borrow_mut( txn_account );
  if( FD_UNLIKELY( !borrow_res ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* Create a BorrowedAccount upon success.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L606 */
  fd_borrowed_account_init( account,
                            txn_account,
                            ctx,
                            idx_in_instr );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_exec_instr_ctx_try_borrow_instr_account( fd_exec_instr_ctx_t const * ctx,
                                            ushort                      idx,
                                            fd_borrowed_account_t *     account ) {
  /* Find the index of the account in the transaction context.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L649-L650 */
  ushort idx_in_txn;
  int err = fd_exec_instr_ctx_get_index_of_instr_account_in_transaction( ctx,
                                                                         idx,
                                                                         &idx_in_txn );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  return fd_exec_instr_ctx_try_borrow_account( ctx,
                                               idx,
                                               idx_in_txn,
                                               account );
}

int
fd_exec_instr_ctx_try_borrow_instr_account_with_key( fd_exec_instr_ctx_t const * ctx,
                                                     fd_pubkey_t const *         pubkey,
                                                     fd_borrowed_account_t *     account ) {
  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    ushort idx_in_txn = ctx->instr->accounts[ i ].index_in_transaction;
    if( memcmp( pubkey->uc, ctx->txn_ctx->account_keys[ idx_in_txn ].uc, sizeof(fd_pubkey_t) )==0 ) {
      return fd_exec_instr_ctx_try_borrow_instr_account( ctx, i, account );
    }
  }

  /* Return a NotEnoughAccountKeys error if the account is not found
     in the instruction context to match the error code returned by
     fd_exec_instr_ctx_try_borrow_instr_account. */
  return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
}

int
fd_exec_instr_ctx_try_borrow_last_program_account( fd_exec_instr_ctx_t const * ctx,
                                                   fd_borrowed_account_t *     account ) {
  /* The index_in_instruction for a borrowed program account is invalid,
     so it is set to a sentinel value of USHORT_MAX. */
  return fd_exec_instr_ctx_try_borrow_account( ctx,
                                               USHORT_MAX,
                                               ctx->instr->program_id,
                                               account );
}

int
fd_exec_instr_ctx_get_signers( fd_exec_instr_ctx_t const * ctx,
                               fd_pubkey_t const *         signers[static FD_TXN_SIG_MAX] ) {
  ulong j = 0UL;
  for( ushort i=0; i<ctx->instr->acct_cnt && j<FD_TXN_SIG_MAX; i++ )
    if( fd_instr_acc_is_signer_idx( ctx->instr, i ) ) {
      ushort idx_in_txn = ctx->instr->accounts[i].index_in_transaction;
      int err = fd_exec_txn_ctx_get_key_of_account_at_index( ctx->txn_ctx,
                                                             idx_in_txn,
                                                             &signers[j++] );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_exec_instr_ctx_any_signed( fd_exec_instr_ctx_t const * ctx,
                              fd_pubkey_t const *         pubkey ) {
  int is_signer = 0;
  for( ushort j=0; j<ctx->instr->acct_cnt; j++ ) {
    ushort idx_in_txn = ctx->instr->accounts[ j ].index_in_transaction;
    is_signer |=
      ( ( !!fd_instr_acc_is_signer_idx( ctx->instr, j ) ) &
        ( 0==memcmp( pubkey->key, ctx->txn_ctx->account_keys[ idx_in_txn ].key, sizeof(fd_pubkey_t) ) ) );
  }
  return is_signer;
}
