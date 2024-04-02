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

#include "../../ballet/txn/fd_txn.h"
#include "fd_executor.h"
#include "info/fd_instr_info.h"
#include "fd_system_ids.h"
#include "fd_runtime.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include <assert.h>  /* TODO remove */

/* FD_ACC_SZ_MAX is the hardcoded size limit of a Solana account. */

#define FD_ACC_SZ_MAX (10UL<<20) /* 10MiB */

FD_PROTOTYPES_BEGIN

/* fd_account_is_executable returns 1 if the given account has the
   executable flag set.  Otherwise, returns 0.  Mirrors Anza's
   solana_sdk::transaction_context::BorrowedAccount::is_executable. */

FD_FN_PURE static inline int
fd_account_is_executable( fd_account_meta_t const * meta ) {
  return !!meta->info.executable;
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

FD_FN_PURE static inline int
fd_account_can_data_be_resized( fd_instr_info_t const *   instr,
                                fd_account_meta_t const * acct,
                                ulong                     new_length,
                                int *                     err ) {

  if( FD_UNLIKELY( ( acct->dlen != new_length ) &
                   ( !fd_account_is_owned_by_current_program( instr, acct ) ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED;
    return 0;
  }

  if( FD_UNLIKELY( new_length > FD_ACC_SZ_MAX ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    return 0;
  }

  *err = FD_EXECUTOR_INSTR_SUCCESS;
  return 1;
}

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

FD_FN_PURE static inline int
fd_account_is_zeroed( fd_account_meta_t const * acct ) {
  // TODO optimize this...
  uchar const * data = ((uchar *) acct) + acct->hlen;
  for( ulong i=0UL; i < acct->dlen; i++ )
    if( data[i] != 0 )
      return 0;
  return 1;
}

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

/* fd_account_checked_{add,sub}_lamports add/removes lamports to/from an
   account.  Does not update global capitalization.  Returns 0 on
   success or an FD_EXECUTOR_INSTR_ERR_{...} code on failure.
   Gracefully handles underflow.  Acquires a writable handle. */

static inline int
fd_account_checked_add_lamports( fd_exec_instr_ctx_t const * ctx,
                                 ulong                       instr_acc_idx,
                                 ulong                       add_amount ) {

  assert( instr_acc_idx < ctx->instr->acct_cnt );
  fd_account_meta_t const * meta = ctx->instr->borrowed_accounts[ instr_acc_idx ]->const_meta;

  ulong const balance_pre  = meta->info.lamports;
  ulong const balance_post = balance_pre + add_amount;
  if( FD_UNLIKELY( balance_post < balance_pre ) )
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;

  return fd_account_set_lamports( ctx, instr_acc_idx, balance_post );
}

static inline int
fd_account_checked_sub_lamports( fd_exec_instr_ctx_t const * ctx,
                                 ulong                       instr_acc_idx,
                                 ulong                       sub_amount ) {

  assert( instr_acc_idx < ctx->instr->acct_cnt );
  fd_account_meta_t const * meta = ctx->instr->borrowed_accounts[ instr_acc_idx ]->const_meta;

  ulong const balance_pre  = meta->info.lamports;
  ulong const balance_post = balance_pre - sub_amount;
  if( FD_UNLIKELY( balance_post > balance_pre ) )
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;

  return fd_account_set_lamports( ctx, instr_acc_idx, balance_post );
}

/* fd_account_set_data_from_slice mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::set_data_from_slice.
   Assumes that destination account already has enough space to fit
   data.  Acquires a writable handle.

   https://github.com/solana-labs/solana/blob/v1.17.25/sdk/src/transaction_context.rs#L903-L923 */

int
fd_account_set_data_from_slice( fd_exec_instr_ctx_t const * ctx,
                                ulong                       instr_acc_idx,
                                uchar const *               data,
                                ulong                       data_sz,
                                int *                       err );

/* fd_account_set_data_length mirrors Anza function
   solana_sdk::transaction_context::BorrowedAccount::set_data_length.
   Acquires a writable handle.
   https://github.com/solana-labs/solana/blob/v1.17.25/sdk/src/transaction_context.rs#L925-L940 */

int
fd_account_set_data_length( fd_exec_instr_ctx_t const * ctx,
                            ulong                       instr_acc_idx,
                            ulong                       new_len,
                            int *                       err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_account_h */
