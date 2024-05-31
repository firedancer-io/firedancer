#include "fd_account.h"
#include "context/fd_exec_instr_ctx.h"
#include "fd_acc_mgr.h"
#include "fd_borrowed_account.h"
#include "fd_executor.h"
#include "info/fd_instr_info.h"
#include "sysvar/fd_sysvar_rent.h"

int
fd_account_set_executable( fd_exec_instr_ctx_t const * ctx,
                           ulong                       instr_acc_idx,
                           int                         executable ) {

  fd_instr_info_t const * instr = ctx->instr;

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  fd_account_meta_t const * meta = account->const_meta;

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( ctx->epoch_ctx );
  fd_rent_t const * rent = &epoch_bank->rent;
  if( FD_UNLIKELY( !fd_rent_exempt_minimum_balance2( rent, meta->dlen ) ) )
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT;

  if( !fd_account_is_owned_by_current_program( instr, meta ) )
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  if( !fd_instr_acc_is_writable_idx( instr, instr_acc_idx ) )
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  if( fd_account_is_executable( meta ) && !executable )
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED;
  if( fd_account_is_executable( meta ) == executable )
    return FD_EXECUTOR_INSTR_SUCCESS;

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  account->meta->info.executable = !!executable;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

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

  if( !fd_account_is_owned_by_current_program( instr, meta ) ) {
    FD_LOG_WARNING(("HERE"));
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  if( !fd_instr_acc_is_writable_idx( instr, instr_acc_idx ) ) {
    FD_LOG_WARNING(("HERE"));
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  if( fd_account_is_executable( meta ) ) {
    FD_LOG_WARNING(("HERE"));
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  if( !fd_account_is_zeroed( meta ) ) {
    FD_LOG_WARNING(("HERE"));
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  }
  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  memcpy( account->meta->info.owner, owner, sizeof(fd_pubkey_t) );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

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

  /* An account not owned by the program cannot have its balance decreased*/
  if( FD_UNLIKELY( ( !fd_account_is_owned_by_current_program( ctx->instr, account->const_meta ) ) &&
                   ( lamports<account->const_meta->info.lamports ) ) )
    return FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND;

  /* The balance of read-only may not change */
  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) )
    return FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE;

  /* The balance of executable accounts may not change */
  if( FD_UNLIKELY( fd_account_is_executable( account->const_meta ) ) )
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;

  /* Don't touch the account if the lamports do not change */
  if( lamports == account->const_meta->info.lamports ) { 
    return 0;
  }

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  account->meta->info.lamports = lamports;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_account_set_data_from_slice( fd_exec_instr_ctx_t const * ctx,
                                ulong                       instr_acc_idx,
                                uchar const *               data,
                                ulong                       data_sz ) {

  int err = 0;

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( !fd_account_can_data_be_resized( ctx->instr, account->const_meta, data_sz, &err ) )
    return err;

  if( !fd_account_can_data_be_changed( ctx->instr, instr_acc_idx, &err ) )
    return err;

  /* TODO update_accounts_resize_delta */
  /* TODO make_data_mut */

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, data_sz, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  assert( account->meta->dlen >= data_sz );
  fd_memcpy( account->data, data, data_sz );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_account_set_data_length( fd_exec_instr_ctx_t const * ctx,
                            ulong                       instr_acc_idx,
                            ulong                       new_len,
                            int *                       err ) {

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( !fd_account_can_data_be_resized( ctx->instr, account->const_meta, new_len, err ) )
    return 0;

  if( !fd_account_can_data_be_changed( ctx->instr, instr_acc_idx, err ) )
    return 0;

  ulong old_len = account->const_meta->dlen;

  if( old_len == new_len )
    return 1;

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, new_len, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( new_len > old_len ) {
    fd_memset( account->data + old_len, 0, new_len - old_len );
  }

  account->meta->dlen = new_len;

  return 1;
}
