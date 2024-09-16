#ifndef HEADER_fd_src_flamenco_runtime_fd_account_h
#define HEADER_fd_src_flamenco_runtime_fd_account_h

/* fd_account.h contains safe API helpers for accounts.

   ### Account Existence

   "Does an account exist?" is not trivial to answer.  We can instead
   look at qualifiers:

     A: Does a database record exist?
     B: Is the native (lamport) balance greater than zero?
     C: Is the account "dead"?

   From the on-chain program's perspective, even addresses that have
   never been interacted with can be read.  That account would show up
   as zero balance, zero owner (system program), and has no data.  This
   means, logically, for all possible 2^256 account addresses, it
   appears that an account exists.  We call such accounts "dead"
   accounts (C).

   C also implies B.  There are may be intermediate account states
   however where an account has zero balance, but is still owned by a
   program.  Thus, B does not necessarily imply C.

   Obviously, we only have finite database space.  Whenever an account
   becomes dead, we try to free the record.  If no funk record for
   an account exists (C), it is dead (A).  This doesn't always work, so
   sometimes there is a leftover record containing a dead account.
   (Also called a "tombstone")

   For the on-chain program developer this means:  DO NOT assume a funk
   record exists for all accounts.  DO NOT look at the funk record
   pointer, as its existence is U.B. for dead accounts.

   See fd_acc_exists and the below helper functions for safe use in
   native programs. */

#include "fd_executor_err.h"
#include "fd_system_ids.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_txn_ctx.h"
#include "program/fd_program_util.h"
#include "sysvar/fd_sysvar_rent.h"
#include <assert.h>  /* TODO remove */

/* FD_ACC_SZ_MAX is the hardcoded size limit of a Solana account. */

#define MAX_PERMITTED_DATA_LENGTH                 (10UL<<20) /* 10MiB */
#define MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN (10UL<<21) /* 20MiB */

FD_PROTOTYPES_BEGIN

/* Instruction account APIs *******************************************/

/* Assert that enougha ccounts were supplied to this instruction. Returns 
   FD_EXECUTOR_INSTR_SUCCESS if the number of accounts is as expected and 
   FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS otherwise.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L492-L503 */
static inline int
fd_account_check_num_insn_accounts( fd_exec_instr_ctx_t * ctx,
                                    uint                  expected_accounts ) {

  if( FD_UNLIKELY( ctx->instr->acct_cnt<expected_accounts ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_account_get_owner mirrors Anza function 
   solana_sdk::transaction_context:Borrowed_account::get_owner.  Returns 0
   iff the owner is retrieved successfully.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L734-L738 */
static inline fd_pubkey_t const *
fd_account_get_owner( fd_exec_instr_ctx_t const * ctx,
                      ulong                       instr_acc_idx ) {
  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  return (fd_pubkey_t const *) account->const_meta->info.owner;
}

/* fd_account_set_owner mirrors Anza function 
   solana_sdk::transaction_context:Borrowed_account::set_owner.  Returns 0
   iff the owner is set successfully.  Acquires a writable handle. */
int
fd_account_set_owner( fd_exec_instr_ctx_t const * ctx,
                      ulong                       instr_acc_idx,
                      fd_pubkey_t const *         owner );

/* fd_account_get_lamports mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::get_lamports.
   Returns current number of lamports in account.  Well behaved if meta
   is NULL. */

static inline ulong
fd_account_get_lamports( fd_account_meta_t const * meta ) {
  if( FD_UNLIKELY( !meta ) ) return 0UL;  /* (!meta) considered an internal error */
  return meta->info.lamports;
}

static inline ulong
fd_account_get_lamports2( fd_exec_instr_ctx_t const * ctx,
                          ulong                       instr_acc_idx ) {
  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) {
      return 0UL;
    }
  } while(0);

  return account->const_meta->info.lamports;
}

/* fd_account_set_lamports mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::set_lamports.
   Runs through a sequence of permission checks, then sets the account
   balance.  Does not update global capitalization.  On success, returns
   0 and updates meta->lamports.  On failure, returns an
   FD_EXECUTOR_INSTR_ERR_{...} code.  Acquires a writable handle. */

int
fd_account_set_lamports( fd_exec_instr_ctx_t const * ctx,
                         ulong                       instr_acc_idx,
                         ulong                       lamports );

/* 
  fd_account_checked_{add,sub}_lamports mirros Anza 
   add/removes lamports to/from an
   account.  Does not update global capitalization.  Returns 0 on
   success or an FD_EXECUTOR_INSTR_ERR_{...} code on failure.
   Gracefully handles underflow.  Acquires a writable handle. 
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L798-L817 */

static inline int
fd_account_checked_add_lamports( fd_exec_instr_ctx_t const * ctx,
                                 ulong                       instr_acc_idx,
                                 ulong                       lamports ) {

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  ulong balance_post = 0UL;
  int err = fd_ulong_checked_add( account->const_meta->info.lamports, lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  return fd_account_set_lamports( ctx, instr_acc_idx, balance_post );
}

static inline int
fd_account_checked_sub_lamports( fd_exec_instr_ctx_t const * ctx,
                                 ulong                       instr_acc_idx,
                                 ulong                       lamports ) {

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)instr_acc_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) { 
      FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
    }
  } while(0);

  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( account->const_meta->info.lamports, lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  return fd_account_set_lamports( ctx, instr_acc_idx, balance_post );
}

/* fd_account_get_data_mut mirrors Anza function 
   solana_sdk::transaction_context::BorrowedAccount::set_lamports. 
   Returns a writable slice of the account data (transaction wide).
   Acquires a writable handle. This function assumes that the relevant
   borrowed has already acquired exclusive write access.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L824-L831 */
int 
fd_account_get_data_mut( fd_exec_instr_ctx_t const * ctx, 
                         ulong                       instr_acc_idx,
                         uchar * *                   data_out,
                         ulong *                     dlen_out );
              
/* TODO: Implement fd_account_spare_data_capacity_mut which is used in direct mapping */

/* fd_account_set_data_from_slice mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::set_data_from_slice.
   In the firedancer client, it also mirrors the Anza function
   solana_sdk::transaction_context::BorrowedAccount::set_data.
   Assumes that destination account already has enough space to fit
   data.  Acquires a writable handle.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L867-882 */

int
fd_account_set_data_from_slice( fd_exec_instr_ctx_t const * ctx,
                                ulong                       instr_acc_idx,
                                uchar const *               data,
                                ulong                       data_sz );

/* fd_account_set_data_length mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::set_data_length.
   Acquires a writable handle. Returns 0 on success.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L994-L900 */

int
fd_account_set_data_length( fd_exec_instr_ctx_t const * ctx,
                            ulong                       instr_acc_idx,
                            ulong                       new_len );

/* fd_account_is_rent_exempt_at_data_length mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::is_rent_exempt_at_data_length.
   Returns 1 if an account is rent exempt at it's current data length.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L990-997 */

static inline int
fd_account_is_rent_exempt_at_data_length( fd_exec_instr_ctx_t const * ctx,
                                          fd_account_meta_t   const * meta ) {
  assert( meta != NULL );
  fd_rent_t rent     = ctx->epoch_ctx->epoch_bank.rent;
  ulong min_balanace = fd_rent_exempt_minimum_balance2( &rent, meta->dlen );
  return meta->info.lamports >= min_balanace; 
}

/* fd_account_is_executable returns 1 if the given account has the
   executable flag set.  Otherwise, returns 0.  Mirrors Anza's
   solana_sdk::transaction_context::BorrowedAccount::is_executable.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1001-1003 */

FD_FN_PURE static inline int
fd_account_is_executable( fd_account_meta_t const * meta ) {
  return !!meta->info.executable;
}

/* fd_account_set_executable mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::set_executable.
   Returns FD_EXECUTOR_INSTR_SUCCESS if the set is successful.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1007-1035 */

int
fd_account_set_executable( fd_exec_instr_ctx_t const * ctx,
                           ulong                       instr_acc_idx,
                           int                         is_executable );

/* fd_account_get_rent_epoch mirrors Anza function 
   solana_sdk::transaction_context::BorrowedAccount::get_rent_epoch. 
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1040-1042 */

static inline ulong
fd_account_get_rent_epoch( fd_account_meta_t const * meta ) {
  assert( meta != NULL );
  return meta->info.rent_epoch;
}

/* fd_account_is_{signer,writable} mirror the Anza functions
   solana_sdk::transaction_context::BorrowedAccount::is_{signer,writer}.
   Returns 1 if the account is a signer or is writable and 0 otherwise.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1044-1068 */

static inline int
fd_account_is_signer( fd_exec_instr_ctx_t const * ctx,
                      ulong                       instr_acc_idx ) {
  if( FD_UNLIKELY( instr_acc_idx >= ctx->instr->acct_cnt ) ) {
    return 0;
  }
  return fd_instr_acc_is_signer_idx( ctx->instr, instr_acc_idx );
}

static inline int
fd_account_is_writable( fd_exec_instr_ctx_t const * ctx,
                        ulong                       instr_acc_idx ) {
  if( FD_UNLIKELY( instr_acc_idx >= ctx->instr->acct_cnt ) ) {
    return 0;
  }

  return fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx );
}

/* fd_account_is_owned_by_current_program returns 1 if the given
   account is owned by the program invoked in the current instruction.
   Otherwise, returns 0.  Mirrors Anza's
   solana_sdk::transaction_context::BorrowedAccount::is_owned_by_current_program */

FD_FN_PURE static inline int
fd_account_is_owned_by_current_program( fd_instr_info_t const *   info,
                                        fd_account_meta_t const * acct ) {
  return 0==memcmp( info->program_id_pubkey.key, acct->info.owner, sizeof(fd_pubkey_t) );
}

/* fd_account_can_data_be changed mirrors Anza function 
   solana_sdk::transaction_context::BorrowedAccount::can_data_be_changed.
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1078-L1094 */
static inline int
fd_account_can_data_be_changed( fd_instr_info_t const * instr,
                                ulong                   instr_acc_idx,
                                int *                   err ) {

  assert( instr_acc_idx < instr->acct_cnt );
  fd_account_meta_t const * meta = instr->borrowed_accounts[ instr_acc_idx ]->const_meta;

  if( FD_UNLIKELY( fd_account_is_executable( meta ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED;
    return 0;
  }

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( instr, instr_acc_idx ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED;
    return 0;
  }

  if( FD_UNLIKELY( !fd_account_is_owned_by_current_program( instr, meta ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED;
    return 0;
  }

  err = FD_EXECUTOR_INSTR_SUCCESS;
  return 1;
}

/* fd_account_can_data_be_resized mirrors Anza function 
   solana_sdk::transaction_context::BorrowedAccount::can_data_be_resized 
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1096-L1119
*/
static inline int
fd_account_can_data_be_resized( fd_exec_instr_ctx_t const * instr_ctx,
                                fd_account_meta_t const *   acct,
                                ulong                       new_length,
                                int *                       err ) {
  /* Only the owner can change the length of the data */
  if( FD_UNLIKELY( ( acct->dlen != new_length ) &
                   ( !fd_account_is_owned_by_current_program( instr_ctx->instr, acct ) ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED;
    return 0;
  }

  /* The new length can not exceed the maximum permitted length */
  if( FD_UNLIKELY( new_length>MAX_PERMITTED_DATA_LENGTH ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    return 0;
  }

  /* The resize can not exceed the per-transaction maximum
     https://github.com/firedancer-io/agave/blob/1e460f466da60a63c7308e267c053eec41dc1b1c/sdk/src/transaction_context.rs#L1107-L1111 */
  ulong length_delta = fd_ulong_sat_sub( new_length, acct->dlen );
  ulong new_accounts_resize_delta = fd_ulong_sat_add( instr_ctx->txn_ctx->accounts_resize_delta, length_delta );
  if( FD_UNLIKELY( new_accounts_resize_delta>MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED;
    return 0;
  }

  *err = FD_EXECUTOR_INSTR_SUCCESS;
  return 1;
}

/* fd_account_update_acounts_resize_delta mirrors Anza function
   solana_sdk::transaction_context:BorrowedAccount::update_accounts_resize_delta. 
   https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/sdk/src/transaction_context.rs#L1128-L1138 */

int
fd_account_update_accounts_resize_delta( fd_exec_instr_ctx_t const * ctx,
                                         ulong                       instr_acc_idx,
                                         ulong                       new_len,
                                         int *                       err );

FD_FN_PURE static inline int
fd_account_is_zeroed( fd_account_meta_t const * acct ) {
  // TODO: optimize this
  uchar const * data = ((uchar *) acct) + acct->hlen;
  for( ulong i=0UL; i < acct->dlen; i++ )
    if( data[i] != 0 )
      return 0;
  return 1;
}

/* fd_account_find_idx_of_insn_account returns the idx of the instruction account
    or -1 if the account is not found
    https://github.com/anza-xyz/agave/blob/d5a84daebd2a7225684aa3f722b330e9d5381e76/sdk/src/transaction_context.rs#L527
 */
static inline int
fd_account_find_idx_of_insn_account( fd_exec_instr_ctx_t const * ctx,
                                     fd_pubkey_t *               pubkey ) {
  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    if( 0==memcmp( pubkey, &ctx->instr->acct_pubkeys[i], sizeof(fd_pubkey_t) ) ) {
      return (int)i;
    }
  }
  return -1;
}

/* Transaction account APIs *******************************************/

/* https://github.com/anza-xyz/agave/blob/92ad51805862fbb47dc40968dff9f93b57395b51/sdk/program/src/message/legacy.rs#L636 */
static inline int
fd_txn_account_is_writable_idx( fd_exec_txn_ctx_t const * txn_ctx, int idx ) {
  int acct_addr_cnt = txn_ctx->txn_descriptor->acct_addr_cnt;
  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    acct_addr_cnt += txn_ctx->txn_descriptor->addr_table_adtl_cnt;
  }

  if( idx==acct_addr_cnt ) {
    return 0;
  }

  if( fd_pubkey_is_active_reserved_key(&txn_ctx->accounts[idx] ) 
      || ( FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, add_new_reserved_account_keys ) && fd_pubkey_is_pending_reserved_key( &txn_ctx->accounts[idx] ) )) {
    return 0;
  }

  if( fd_txn_account_is_demotion( txn_ctx, idx ) ) {
    return 0;
  }

  return fd_txn_is_writable( txn_ctx->txn_descriptor, idx );
}

FD_PROTOTYPES_END

#include "fd_account_old.h"

#endif /* HEADER_fd_src_flamenco_runtime_fd_account_h */
