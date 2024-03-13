#include "fd_account.h"
#include "context/fd_exec_instr_ctx.h"
#include "fd_acc_mgr.h"
#include "fd_borrowed_account.h"
#include "info/fd_instr_info.h"

int
fd_account_set_owner( fd_exec_instr_ctx_t * ctx,
                      ulong                 instr_acc_idx,
                      fd_pubkey_t const *   owner ) {

  fd_instr_info_t const * instr = ctx->instr;

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  fd_account_meta_t const * meta = account->const_meta;

  if( !fd_account_is_owned_by_current_program( instr, meta ) )
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  if( !fd_instr_acc_is_writable_idx( instr, instr_acc_idx ) )
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  if( fd_account_is_executable( meta ) )
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  if( !fd_account_is_zeroed( meta ) )
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
  if( 0==memcmp( meta->info.owner, owner, sizeof(fd_pubkey_t) ) )
    return FD_EXECUTOR_INSTR_SUCCESS;
  if( 0!=memcmp( meta->info.owner, fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) )
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  memcpy( account->meta->info.owner, owner, sizeof(fd_pubkey_t) );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_account_set_lamports( fd_exec_instr_ctx_t * ctx,
                         ulong                 instr_acc_idx,
                         ulong                 lamports ) {

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( ( !fd_account_is_owned_by_current_program( ctx->instr, account->const_meta ) ) &
                  ( lamports < account->const_meta->info.lamports ) ) )
    return FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND;

  /* TODO: This is a slow O(n) search through the account access list
          Consider caching the access flags in fd_borrowed_account_t. */
  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) )
    return FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE;

  if( FD_UNLIKELY( fd_account_is_executable( account->const_meta ) ) )
    return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;

  if( lamports == account->const_meta->info.lamports ) return 0;

  /* TODO: Call fd_account_touch.  This seems to have some side effect
          checking the number of accounts?  Unclear... */

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  account->meta->info.lamports = lamports;
  return 0;
}

int
fd_account_set_data_from_slice( fd_exec_instr_ctx_t * ctx,
                                ulong                 instr_acc_idx,
                                uchar const *         data,
                                ulong                 data_sz,
                                int *                 err ) {

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( !fd_account_can_data_be_resized( ctx->instr, account->const_meta, data_sz, err ) )
    return 0;

  if( !fd_account_can_data_be_changed( ctx->instr, instr_acc_idx, err ) )
    return 0;

  /* TODO update_accounts_resize_delta */
  /* TODO make_data_mut */

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  assert( account->meta->dlen >= data_sz );
  fd_memcpy( account->data, data, data_sz );
  return 1;
}

int
fd_account_set_data_length( fd_exec_instr_ctx_t * ctx,
                            ulong                 instr_acc_idx,
                            ulong                 new_len,
                            int *                 err ) {

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

  if( new_len > old_len )
    fd_memset( account->data + account->meta->dlen, 0, new_len - old_len );

  account->meta->dlen = new_len;

  return 1;
}
