#include "fd_account.h"
#include "context/fd_exec_instr_ctx.h"

/* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L740-L767 */
/* Assignes the owner of this account (transaction wide) */
int
fd_account_set_owner( fd_exec_instr_ctx_t const * ctx,
                      ulong                       instr_acc_idx,
                      fd_pubkey_t const *         owner ) {

  fd_instr_info_t const * instr = ctx->instr;
  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  fd_account_meta_t const * meta = account->const_meta;

  /* Only the owner can assign a new owner */
  if( !fd_account_is_owned_by_current_program( instr, meta ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  /* And only if the account is writable */
  if( !fd_instr_acc_is_writable_idx( instr, instr_acc_idx ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  /* And only if the account is not executable */
  if( fd_account_is_executable( meta ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  /* And only if the data is zero-initialized or empty */
  if( !fd_account_is_zeroed( meta ) ) {
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  /* Don't touch the account if the owner does not change */
  if( !memcmp( account->const_meta->info.owner, owner, sizeof( fd_pubkey_t ) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  /* self.touch()? */
  account->meta->slot = ctx->slot_ctx->slot_bank.slot;

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  account->meta->slot = ctx->slot_ctx->slot_bank.slot;
  memcpy( account->meta->info.owner, owner, sizeof(fd_pubkey_t) );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L774-L796 */
/* Overwrites the number of lamports of this account (transaction wide) */
int
fd_account_set_lamports( fd_exec_instr_ctx_t const * ctx,
                         ulong                       instr_acc_idx,
                         ulong                       lamports ) {

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);
  
  /* An account not owned by the program cannot have its blanace decrease */
  if( FD_UNLIKELY( ( !fd_account_is_owned_by_current_program( ctx->instr, account->const_meta ) ) &&
                   ( lamports < account->const_meta->info.lamports ) ) )
    return FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND;

  /* The balance of read-only may not change */
  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) )
    return FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE;

  /* The balance of executable accounts may not change */
  if( FD_UNLIKELY( fd_account_is_executable( account->const_meta ) ) )
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;

  /* Don't touch the account if the lamports do not change */
  if( lamports==account->const_meta->info.lamports ) {
   return FD_EXECUTOR_INSTR_SUCCESS;
  }

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  /* self.touch()? */
  account->meta->slot = ctx->slot_ctx->slot_bank.slot;

  account->meta->info.lamports = lamports;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int 
fd_account_get_data_mut( fd_exec_instr_ctx_t const * ctx, 
                         ulong                       instr_acc_idx,
                         uchar * *                   data_out,
                         ulong *                     dlen_out ) {
  
  int err;
  if( FD_UNLIKELY( !fd_account_can_data_be_changed( ctx->instr, instr_acc_idx, &err ) ) ) {
    return err;
  }

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  /* self.touch() */
  account->meta->slot = ctx->slot_ctx->slot_bank.slot;

  *data_out = account->data;
  *dlen_out = account->meta->dlen;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_account_set_data_from_slice( fd_exec_instr_ctx_t const * ctx,
                                ulong                       instr_acc_idx,
                                uchar const *               data,
                                ulong                       data_sz ) {

  int err = FD_EXECUTOR_INSTR_SUCCESS;

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  if( !fd_account_can_data_be_resized( ctx, account->const_meta, data_sz, &err ) ) {
    return err;
  }

  if( !fd_account_can_data_be_changed( ctx->instr, instr_acc_idx, &err ) ) {
    return err;
  }

  if( !fd_account_update_accounts_resize_delta( ctx, instr_acc_idx, data_sz, &err ) ) {
    return err;
  }

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, data_sz, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  /* self.touch() */
  account->meta->slot = ctx->slot_ctx->slot_bank.slot;

  assert( account->meta->dlen >= data_sz );
  fd_memcpy( account->data, data, data_sz );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_account_set_data_length( fd_exec_instr_ctx_t const * ctx,
                            ulong                       instr_acc_idx,
                            ulong                       new_len ) {

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  int err = FD_EXECUTOR_INSTR_SUCCESS;
  if( !fd_account_can_data_be_resized( ctx, account->const_meta, new_len, &err ) ) {
    return err;
  }

  if( !fd_account_can_data_be_changed( ctx->instr, instr_acc_idx, &err ) ) {
    return err;
  }

  ulong old_len = account->const_meta->dlen;

  /* Don't touch the account if the length does not change */
  if( old_len==new_len ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* self.touch() */
  account->meta->slot = ctx->slot_ctx->slot_bank.slot;

  if( !fd_account_update_accounts_resize_delta( ctx, instr_acc_idx, new_len, &err ) ) {
    return err;
  }

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, new_len, &account );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  if( new_len>old_len ) {
    fd_memset( account->data+old_len, 0, new_len-old_len );
  }

  account->meta->dlen = new_len;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_account_set_executable( fd_exec_instr_ctx_t const * ctx,
                           ulong                       instr_acc_idx,
                           int                         is_executable ) {

  fd_instr_info_t const * instr = ctx->instr;

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  fd_account_meta_t const * meta = account->const_meta;

  /* To become executable an account must be rent exempt */
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( ctx->epoch_ctx );
  fd_rent_t const * rent = &epoch_bank->rent;
  if( FD_UNLIKELY( !fd_rent_exempt_minimum_balance2( rent, meta->dlen ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT;
  }

  /* Only the owner can set the exectuable flag */
  if( FD_UNLIKELY( !fd_account_is_owned_by_current_program( instr, meta ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  /* And only if the account is writable */
  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( instr, instr_acc_idx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  /* One can not clear the executable flag  */
  if( FD_UNLIKELY( fd_account_is_executable( meta ) && !is_executable ) ) {
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  }

  /* Don't touch the account if the exectuable flag does not change */
  if( fd_account_is_executable( meta ) == is_executable ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  /* self.touch()? */
  account->meta->slot = ctx->slot_ctx->slot_bank.slot;

  account->meta->info.executable = !!is_executable;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1128-L1138 */
int
fd_account_update_accounts_resize_delta( fd_exec_instr_ctx_t const * ctx,
                                         ulong                       instr_acc_idx,
                                         ulong                       new_len,
                                         int *                       err ) {
                                          
  fd_borrowed_account_t * account = NULL;
  *err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
  if( FD_UNLIKELY( *err ) ) {
    return 0;
  }

  ulong size_delta = fd_ulong_sat_sub( new_len, account->const_meta->dlen );

  /* TODO: The size delta should never exceed the value of ULONG_MAX so this 
     could be replaced with a normal addition. However to match execution with
     the agave client, this is being left as a sat add */
  ctx->txn_ctx->accounts_resize_delta = fd_ulong_sat_add( ctx->txn_ctx->accounts_resize_delta, size_delta );
  *err = FD_EXECUTOR_INSTR_SUCCESS;
  return 1;
}
