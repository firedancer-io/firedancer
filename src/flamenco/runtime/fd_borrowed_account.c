#include "fd_borrowed_account.h"

int
fd_borrowed_account_get_data_mut( fd_borrowed_account_t * borrowed_acct,
                                  uchar * *               data_out,
                                  ulong *                 dlen_out ) {
  fd_txn_account_t * acct = borrowed_acct->acct;

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L824 */
  int err;
  fd_borrowed_account_can_data_be_changed( borrowed_acct, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  if ( data_out != NULL )
    *data_out = acct->data;
  if ( dlen_out != NULL )
    *dlen_out = acct->meta->dlen;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_borrowed_account_set_owner( fd_borrowed_account_t * borrowed_acct,
                               fd_pubkey_t const *     owner ) {
  fd_txn_account_t * acct = borrowed_acct->acct;

  /* Only the owner can assign a new owner
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L741 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_owned_by_current_program( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }

  /* And only if the account is writable
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L745 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_writable( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }

  /* And only if the account is not executable
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L749 */
  if( FD_UNLIKELY( fd_borrowed_account_is_executable_internal( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }

  /* And only if the data is zero-initialized or empty
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L753 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_zeroed( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }

  /* Don't copy the account if the owner does not change
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L757 */
  if( !memcmp( acct->const_meta->info.owner, owner, sizeof( fd_pubkey_t ) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* Agave self.touch() is a no-op */

  /* Copy into owner
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L761 */
  memcpy( acct->meta->info.owner, owner, sizeof(fd_pubkey_t) );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Overwrites the number of lamports of this account (transaction wide)
   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L773 */
int
fd_borrowed_account_set_lamports( fd_borrowed_account_t * borrowed_acct,
                                  ulong                   lamports ) {
  fd_txn_account_t * acct = borrowed_acct->acct;

  /* An account not owned by the program cannot have its blanace decrease
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L775 */
  if( FD_UNLIKELY( ( !fd_borrowed_account_is_owned_by_current_program( borrowed_acct ) ) &&
                   ( lamports < acct->const_meta->info.lamports ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND;
  }

  /* The balance of read-only may not change
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L779 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_writable( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE;
  }

  /* The balance of executable accounts may not change
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L783 */
  if( FD_UNLIKELY( fd_borrowed_account_is_executable_internal( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;
  }

  /* Don't copy the account if the lamports do not change
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L787 */
  if( fd_txn_account_get_lamports( acct ) == lamports ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* Agave self.touch() is a no-op */

  fd_txn_account_set_lamports( acct, lamports );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_borrowed_account_set_data_from_slice( fd_borrowed_account_t * borrowed_acct,
                                         uchar const *           data,
                                         ulong                   data_sz ) {
  fd_txn_account_t * acct = borrowed_acct->acct;

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L865 */
  int err;
  if ( FD_UNLIKELY( !fd_borrowed_account_can_data_be_resized( borrowed_acct, data_sz, &err ) ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L866 */
  if( FD_UNLIKELY( !fd_borrowed_account_can_data_be_changed( borrowed_acct, &err ) ) ) {
    return err;
  }

  /* Agave self.touch() is a no-op */

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L868 */
  if( FD_UNLIKELY( !fd_borrowed_account_update_accounts_resize_delta( borrowed_acct, data_sz, &err ) ) ) {
    return err;
  }

  /* AccountSharedData::set_data_from_slice() */
  acct->meta->dlen = data_sz;
  fd_memcpy( acct->data, data, data_sz );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_borrowed_account_set_data_length( fd_borrowed_account_t * borrowed_acct,
                                     ulong                   new_len ) {
  fd_txn_account_t * acct = borrowed_acct->acct;
  int                err  = FD_EXECUTOR_INSTR_SUCCESS;

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L883 */
  if( FD_UNLIKELY( !fd_borrowed_account_can_data_be_resized( borrowed_acct, new_len, &err ) ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L884 */
  if( FD_UNLIKELY( !fd_borrowed_account_can_data_be_changed( borrowed_acct, &err ) ) ) {
    return err;
  }

  ulong old_len = acct->const_meta->dlen;

  /* Don't copy the account if the length does not change
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L886 */
  if( old_len==new_len ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* Agave self.touch() is a no-op */

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L890 */
  if( FD_UNLIKELY( !fd_borrowed_account_update_accounts_resize_delta( borrowed_acct, new_len, &err ) ) ) {
    return err;
  }

  /* Resize the account
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L891 */
  fd_txn_account_resize( acct, new_len );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_borrowed_account_set_executable( fd_borrowed_account_t * borrowed_acct,
                                    int                     is_executable ) {
  fd_txn_account_t * acct = borrowed_acct->acct;

  /* To become executable an account must be rent exempt
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1003-L1006 */
  fd_rent_t const * rent = &borrowed_acct->instr_ctx->txn_ctx->epoch_bank->rent;
  if( FD_UNLIKELY( acct->const_meta->info.lamports < fd_rent_exempt_minimum_balance( rent, acct->const_meta->dlen ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT;
  }

  /* Only the owner can set the exectuable flag
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1011 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_owned_by_current_program( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  /* And only if the account is writable
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1015 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_writable( borrowed_acct ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  /* One can not clear the executable flag
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1019 */
  if( FD_UNLIKELY( fd_borrowed_account_is_executable_internal( borrowed_acct ) && !is_executable ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  /* Don't copy the account if the exectuable flag does not change
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1023 */
  if( fd_borrowed_account_is_executable( borrowed_acct ) == is_executable ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* Agave self.touch() is a no-op */

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1027 */
  fd_txn_account_set_executable( acct, is_executable );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_borrowed_account_update_accounts_resize_delta( fd_borrowed_account_t * borrowed_acct,
                                                  ulong                   new_len,
                                                  int *                   err ) {
  fd_exec_instr_ctx_t const * instr_ctx  = borrowed_acct->instr_ctx;
  fd_txn_account_t *          acct       = borrowed_acct->acct;
  ulong                       size_delta = fd_ulong_sat_sub( new_len, acct->const_meta->dlen );

  /* TODO: The size delta should never exceed the value of ULONG_MAX so this
     could be replaced with a normal addition. However to match execution with
     the agave client, this is being left as a sat add */
  instr_ctx->txn_ctx->accounts_resize_delta = fd_ulong_sat_add( instr_ctx->txn_ctx->accounts_resize_delta, size_delta );
  *err = FD_EXECUTOR_INSTR_SUCCESS;
  return 1;
}
