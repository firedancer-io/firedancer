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

/* FD_ACC_SZ_MAX is the hardcoded size limit of a Solana account. */

#define FD_ACC_SZ_MAX (10UL<<20) /* 10MiB */

FD_PROTOTYPES_BEGIN

/* fd_account_is_executable returns 1 if the given account has the
   executable flag set.  Otherwise, returns 0.  Mirrors Anza's
   solana_sdk::transaction_context::BorrowedAccount::is_executable. */

static inline int
fd_account_is_executable( fd_account_meta_t const * meta ) {
  return !!meta->info.executable;
}

static inline int
fd_account_can_data_be_resized( fd_exec_instr_ctx_t *     ctx,
                                fd_account_meta_t const * acct,
                                ulong                     new_length,
                                int *                     err ) {

  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_early_verification_of_account_modifications ) )
    return 1;

  if( acct->dlen != new_length && !fd_instr_acc_is_owned_by_current_program( ctx->instr, acct ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED;
    return 0;
  }

  if( new_length > FD_ACC_SZ_MAX ) {
    *err = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    return 0;
  }

  return 1;
}

static inline int
fd_account_can_data_be_changed( fd_exec_instr_ctx_t *     ctx,
                                fd_account_meta_t const * acct,
                                fd_pubkey_t const *       key,
                                int *                     err ) {

  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_early_verification_of_account_modifications ) )
    return 1;

  if( fd_account_is_executable( acct ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED;
    return 0;
  }

  if( !fd_instr_acc_is_writable( ctx->instr, key ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED;
    return 0;
  }

  if (!fd_instr_acc_is_owned_by_current_program( ctx->instr, acct )) {
    *err = FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED;
    return 0;
  }

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

static inline int
fd_account_set_owner( fd_exec_instr_ctx_t * ctx,
                      fd_account_meta_t *   acct,
                      fd_pubkey_t const *   key,
                      fd_pubkey_t const *   owner ) {

  if( FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_early_verification_of_account_modifications ) ) {

    if( !fd_instr_acc_is_owned_by_current_program( ctx->instr, acct ) )
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if( !fd_instr_acc_is_writable( ctx->instr, key ) )
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if( fd_account_is_executable( acct ) )
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if( !fd_account_is_zeroed( acct ) )
      return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;
    if( 0==memcmp( &acct->info.owner, owner, sizeof(fd_pubkey_t) ) )
      return FD_EXECUTOR_INSTR_SUCCESS;
    if( 0!=memcmp( acct->info.owner, fd_solana_system_program_id.key, sizeof(acct->info.owner) ) )
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  }

  memcpy( &acct->info.owner, owner, sizeof(fd_pubkey_t) );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

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
   FD_EXECUTOR_INSTR_ERR_{...} code.

   Assumes acct has previously been upgraded to a writable handle. */

static inline int
fd_account_set_lamports( fd_exec_instr_ctx_t * ctx,
                         fd_account_meta_t *   meta,
                         fd_pubkey_t const *   key,
                         ulong                 lamports ) {

  if( FD_UNLIKELY( !meta ) ) FD_LOG_CRIT(( "NULL meta" ));

  if( FD_FEATURE_ACTIVE( ctx->slot_ctx, enable_early_verification_of_account_modifications ) ) {

    if( FD_UNLIKELY( ( !fd_instr_acc_is_owned_by_current_program( ctx->instr, meta ) ) &
                    ( lamports < meta->info.lamports ) ) )
      return FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND;

    /* TODO: This is a slow O(n) search through the account access list
            Consider caching the access flags in fd_borrowed_account_t. */
    if( FD_UNLIKELY( !fd_instr_acc_is_writable( ctx->instr, key ) ) )
      return FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE;

    if( FD_UNLIKELY( fd_account_is_executable( meta ) ) )
      return FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE;

    if( lamports == meta->info.lamports ) return 0;

    /* TODO: Call fd_account_touch.  This seems to have some side effect
            checking the number of accounts?  Unclear... */

  }

  meta->info.lamports = lamports;
  return 0;
}

/* fd_account_checked_{add,sub}_lamports add/removes lamports to/from an
   account.  Does not update global capitalization.  Returns 0 on
   success or an FD_EXECUTOR_INSTR_ERR_{...} code on failure.
   Gracefully handles underflow. */

static inline int
fd_account_checked_add_lamports( fd_exec_instr_ctx_t * const ctx,
                                 fd_account_meta_t *   const meta,
                                 fd_pubkey_t const *   const key,
                                 ulong                 const add_amount ) {

  if( FD_UNLIKELY( !meta ) ) FD_LOG_CRIT(( "NULL meta" ));

  ulong const balance_pre  = meta->info.lamports;
  ulong const balance_post = balance_pre + add_amount;
  if( FD_UNLIKELY( balance_post < balance_pre ) )
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;

  return fd_account_set_lamports( ctx, meta, key, balance_post );
}

static inline int
fd_account_checked_sub_lamports( fd_exec_instr_ctx_t * const ctx,
                                 fd_account_meta_t *   const meta,
                                 fd_pubkey_t const *   const key,
                                 ulong                 const sub_amount ) {

  if( FD_UNLIKELY( !meta ) ) FD_LOG_CRIT(( "NULL meta" ));

  ulong const balance_pre  = meta->info.lamports;
  ulong const balance_post = balance_pre - sub_amount;
  if( FD_UNLIKELY( balance_post > balance_pre ) )
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;

  return fd_account_set_lamports( ctx, meta, key, balance_post );
}

static inline int
fd_account_set_data_length( fd_exec_instr_ctx_t * ctx,
                            fd_account_meta_t *   acct,
                            fd_pubkey_t const *   key,
                            ulong                 new_len,
                            int *                 err ) {
  if( !fd_account_can_data_be_resized( ctx, acct, new_len, err ) )
    return 0;

  if( !fd_account_can_data_be_changed( ctx, acct, key, err ) )
    return 0;

  ulong old_len = acct->dlen;

  if( old_len == new_len )
    return 1;

  uchar * data = ((uchar *) acct) + acct->hlen;

  if( new_len > old_len )
    fd_memset( data + acct->dlen, 0, new_len - old_len );

  acct->dlen = new_len;

  return 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_account_h */
