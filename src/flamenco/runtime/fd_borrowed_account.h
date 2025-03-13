#ifndef HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h
#define HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h

#include "fd_executor_err.h"
#include "fd_system_ids.h"
#include "fd_runtime.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_txn_ctx.h"
#include "sysvar/fd_sysvar_rent.h"

/* FD_ACC_SZ_MAX is the hardcoded size limit of a Solana account. */

#define MAX_PERMITTED_DATA_LENGTH                 (10UL<<20) /* 10MiB */
#define MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN (10L<<21 ) /* 20MiB */

/* TODO: Not all Agave Borrowed Account API functions are implemented here */

struct fd_borrowed_account {
  ulong                       magic;
  fd_txn_account_t *          acct;
  fd_exec_instr_ctx_t const * instr_ctx;
  int                         instr_acc_idx;
};
typedef struct fd_borrowed_account fd_borrowed_account_t;

#define FD_BORROWED_ACCOUNT_MAGIC (0xFDB07703ACC736C0UL) /* FD BORROW ACCT MGC version 0 */
/* prevents borrowed accounts from going out of scope without releasing a borrow */
#define fd_guarded_borrowed_account_t __attribute__((cleanup(fd_borrowed_account_destroy))) fd_borrowed_account_t

FD_PROTOTYPES_BEGIN

/* Constructor */

static inline void
fd_borrowed_account_init( fd_borrowed_account_t *     borrowed_acct,
                          fd_txn_account_t *          acct,
                          fd_exec_instr_ctx_t const * instr_ctx,
                          int                         instr_acc_idx ) {
  borrowed_acct->acct = acct;
  borrowed_acct->instr_ctx = instr_ctx;
  borrowed_acct->instr_acc_idx = instr_acc_idx;

  FD_COMPILER_MFENCE();
  borrowed_acct->magic = FD_BORROWED_ACCOUNT_MAGIC;
  FD_COMPILER_MFENCE();
}

/* Drop mirrors the behavior of rust's std::mem::drop on mutable borrows.
   Releases the acquired write on the borrowed account object. */

static inline void
fd_borrowed_account_drop( fd_borrowed_account_t * borrowed_acct ) {
  fd_txn_account_release_write_private( borrowed_acct->acct );
}

/* Destructor  */

static inline void
fd_borrowed_account_destroy( fd_borrowed_account_t * borrowed_acct ) {
  if( FD_LIKELY( borrowed_acct->magic == FD_BORROWED_ACCOUNT_MAGIC ) ) {
    fd_txn_account_release_write_private( borrowed_acct->acct );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( borrowed_acct->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  borrowed_acct = NULL;
}

/* Getters */

/* fd_borrowed_account_get_data mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::get_data.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L817 */

static inline void const *
fd_borrowed_account_get_data( fd_borrowed_account_t const * borrowed_acct ) {
  return borrowed_acct->acct->const_data;
}

/* fd_borrowed_account_get_data_mut mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::get_data_mut.

   Returns a writable slice of the account data (transaction wide).
   Acquires a writable handle. This function assumes that the relevant
   borrowed has already acquired exclusive write access.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L823 */

int
fd_borrowed_account_get_data_mut( fd_borrowed_account_t * borrowed_acct,
                                  uchar * *               data_out,
                                  ulong *                 dlen_out );

static inline fd_pubkey_t const *
fd_borrowed_account_get_owner( fd_borrowed_account_t * borrowed_acct ) {
  return (fd_pubkey_t const *) borrowed_acct->acct->const_meta->info.owner;
}

/* fd_borrowed_account_get_lamports mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::get_lamports.

   Returns current number of lamports in account.  Well behaved if meta
   is NULL.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L767 */

static inline ulong
fd_borrowed_account_get_lamports( fd_borrowed_account_t const * borrowed_acct ) {
  return fd_txn_account_get_lamports( borrowed_acct->acct );
}

/* fd_borrowed_account_get_rent_epoch mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::get_rent_epoch.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1034 */

static inline ulong
fd_borrowed_account_get_rent_epoch( fd_borrowed_account_t const * borrowed_acct ) {
  FD_TEST( borrowed_acct->acct->const_meta != NULL );
  /* TODO: rent_epoch should be a property of fd_txn_account_t */
  return borrowed_acct->acct->const_meta->info.rent_epoch;
}

/* Setters */

/* fd_borrowed_account_set_owner mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::set_owner.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L739 */

int
fd_borrowed_account_set_owner( fd_borrowed_account_t * borrowed_acct,
                               fd_pubkey_t const *     owner );

/* fd_borrowed_account_set_lamports mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::set_lamports.

   Runs through a sequence of permission checks, then sets the account
   balance.  Does not update global capitalization.  On success, returns
   0 and updates meta->lamports.  On failure, returns an
   FD_EXECUTOR_INSTR_ERR_{...} code.  Acquires a writable handle.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L773 */

int
fd_borrowed_account_set_lamports( fd_borrowed_account_t * borrowed_acct,
                                  ulong                   lamports );

/* fd_borrowed_account_set_data_from_slice mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::set_data_from_slice.

   In the firedancer client, it also mirrors the Agave function
   solana_sdk::transaction_context::BorrowedAccount::set_data.
   Assumes that destination account already has enough space to fit
   data.  Acquires a writable handle.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L864 */

int
fd_borrowed_account_set_data_from_slice( fd_borrowed_account_t * borrowed_acct,
                                         uchar const *           data,
                                         ulong                   data_sz );

/* fd_borrowed_account_set_data_length mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::set_data_length.

   Acquires a writable handle. Returns 0 on success.
   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L882 */

int
fd_borrowed_account_set_data_length( fd_borrowed_account_t * borrowed_acct,
                                     ulong                   new_len );

/* fd_borrowed_account_set_executable mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::set_executable.

   Returns FD_EXECUTOR_INSTR_SUCCESS if the set is successful.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L10015 */

int
fd_borrowed_account_set_executable( fd_borrowed_account_t * borrowed_acct,
                                    int                     is_executable );

/* Operators */

/* fd_borrowed_account_checked_add_lamports mirros Agave function
   solana_sdk::transaction_context::BorrowedAccount::checked_add_lamports.

   Does not update global capitalization. Returns 0 on
   success or an FD_EXECUTOR_INSTR_ERR_{...} code on failure.
   Gracefully handles underflow.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L797 */

static inline int
fd_borrowed_account_checked_add_lamports( fd_borrowed_account_t * borrowed_acct,
                                          ulong                   lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_add( borrowed_acct->acct->const_meta->info.lamports,
                                  lamports,
                                  &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  return fd_borrowed_account_set_lamports( borrowed_acct, balance_post );
}

/* fd_borrowed_account_checked_sub_lamports mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::checked_sub_lamports.

   Does not update global capitalization. Returns 0 on
   success or an FD_EXECUTOR_INSTR_ERR_{...} code on failure.
   Gracefully handles underflow.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L807 */

static inline int
fd_borrowed_account_checked_sub_lamports( fd_borrowed_account_t * borrowed_acct,
                                          ulong                   lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( borrowed_acct->acct->const_meta->info.lamports,
                                  lamports,
                                  &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  return fd_borrowed_account_set_lamports( borrowed_acct, balance_post );
}

/* fd_borrowed_account_update_acounts_resize_delta mirrors Agave function
   solana_sdk::transaction_context:BorrowedAccount::update_accounts_resize_delta.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1123 */

int
fd_borrowed_account_update_accounts_resize_delta( fd_borrowed_account_t * borrowed_acct,
                                                  ulong                         new_len,
                                                  int *                         err );

/* Accessors */

/* fd_borrowed_account_is_rent_exempt_at_data_length mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::is_rent_exempt_at_data_length.

   Returns 1 if an account is rent exempt at it's current data length.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L987 */

static inline int
fd_borrowed_account_is_rent_exempt_at_data_length( fd_borrowed_account_t const * borrowed_acct ) {
  fd_txn_account_t * acct = borrowed_acct->acct;
  FD_TEST( acct->const_meta != NULL );

  /* TODO: Add an is_exempt rent API to better match Agave and clean up code
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L990 */
  fd_rent_t rent    = borrowed_acct->instr_ctx->txn_ctx->epoch_bank->rent;
  ulong min_balance = fd_rent_exempt_minimum_balance( &rent, acct->const_meta->dlen );
  return acct->const_meta->info.lamports >= min_balance;
}

/* fd_borrowed_account_is_executable mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::is_executable.

   Returns 1 if the given account has the
   executable flag set.  Otherwise, returns 0.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L995 */

FD_FN_PURE static inline int
fd_borrowed_account_is_executable( fd_borrowed_account_t const * borrowed_acct ) {
  return fd_txn_account_is_executable( borrowed_acct->acct );
}

/* fd_borrowed_account_is_executable_internal is a private function for deprecating the `is_executable` flag.
   It returns true if the `remove_accounts_executable_flag_checks` feature is inactive AND fd_account_is_executable
   return true. This is newly used in account modification logic to eventually allow "executable" accounts to be
   modified.

   https://github.com/anza-xyz/agave/blob/89872fdb074e6658646b2b57a299984f0059cc84/sdk/transaction-context/src/lib.rs#L1052-L1060 */

FD_FN_PURE static inline int
fd_borrowed_account_is_executable_internal( fd_borrowed_account_t const * borrowed_acct ) {
  return !FD_FEATURE_ACTIVE( borrowed_acct->instr_ctx->txn_ctx->slot_bank->slot, borrowed_acct->instr_ctx->txn_ctx->features, remove_accounts_executable_flag_checks ) &&
          fd_borrowed_account_is_executable( borrowed_acct );
}

/* fd_borrowed_account_is_signer mirror the Agave functions
   solana_sdk::transaction_context::BorrowedAccount::is_signer.
   Returns 1 if the account is a signer or is writable and 0 otherwise.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1039 */

static inline int
fd_borrowed_account_is_signer( fd_borrowed_account_t const * borrowed_acct ) {
  fd_exec_instr_ctx_t const * instr_ctx = borrowed_acct->instr_ctx;
  if( FD_UNLIKELY( borrowed_acct->instr_acc_idx >= instr_ctx->instr->acct_cnt ) ) {
    return 0;
  }

  fd_instr_info_t const * instr = instr_ctx->instr;
  return fd_instr_acc_is_signer_idx( instr, (ulong)borrowed_acct->instr_acc_idx );
}

/* fd_borrowed_account_is_writer mirror the Agave functions
   solana_sdk::transaction_context::BorrowedAccount::is_writer.
   Returns 1 if the account is a signer or is writable and 0 otherwise.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1052 */

static inline int
fd_borrowed_account_is_writable( fd_borrowed_account_t const * borrowed_acct ) {
  fd_exec_instr_ctx_t const * instr_ctx = borrowed_acct->instr_ctx;
  if( FD_UNLIKELY( borrowed_acct->instr_acc_idx >= instr_ctx->instr->acct_cnt ) ) {
    return 0;
  }

  fd_instr_info_t const * instr = instr_ctx->instr;
  return fd_instr_acc_is_writable_idx( instr, (ulong)borrowed_acct->instr_acc_idx );
}

/* fd_borrowed_account_is_owned_by_current_program mirrors Agave's
   solana_sdk::transaction_context::BorrowedAccount::is_owned_by_current_program.

   Returns 1 if the given
   account is owned by the program invoked in the current instruction.
   Otherwise, returns 0.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1065 */

FD_FN_PURE static inline int
fd_borrowed_account_is_owned_by_current_program( fd_borrowed_account_t const * borrowed_acct ) {
  return memcmp( borrowed_acct->instr_ctx->instr->program_id_pubkey.key,
                 borrowed_acct->acct->const_meta->info.owner, sizeof(fd_pubkey_t) ) == 0;
}

/* fd_borrowed_account_can_data_be changed mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::can_data_be_changed.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1074 */

static inline int
fd_borrowed_account_can_data_be_changed( fd_borrowed_account_t const * borrowed_acct,
                                         int *                       err ) {
  fd_instr_info_t const * instr = borrowed_acct->instr_ctx->instr;
  FD_TEST( borrowed_acct->instr_acc_idx < instr->acct_cnt );

  /* Only non-executable accounts data can be changed
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1076 */
  if( FD_UNLIKELY( fd_borrowed_account_is_executable_internal( borrowed_acct ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED;
    return 0;
  }

  /* And only if the account is writable
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1080 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_writable( borrowed_acct ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED;
    return 0;
  }

  /* And only if we are the owner
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1084 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_owned_by_current_program( borrowed_acct ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED;
    return 0;
  }

  *err = FD_EXECUTOR_INSTR_SUCCESS;
  return 1;
}

/* fd_borrowed_account_can_data_be_resized mirrors Agave function
   solana_sdk::transaction_context::BorrowedAccount::can_data_be_resized

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1092 */

static inline int
fd_borrowed_account_can_data_be_resized( fd_borrowed_account_t const * borrowed_acct,
                                         ulong                         new_length,
                                         int *                         err ) {
  fd_txn_account_t * acct = borrowed_acct->acct;

  /* Only the owner can change the length of the data
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1095 */
  if( FD_UNLIKELY( ( acct->const_meta->dlen != new_length ) &
                   ( !fd_borrowed_account_is_owned_by_current_program( borrowed_acct ) ) ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED;
    return 0;
  }

  /* The new length can not exceed the maximum permitted length
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1099 */
  if( FD_UNLIKELY( new_length>MAX_PERMITTED_DATA_LENGTH ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
    return 0;
  }

  /* The resize can not exceed the per-transaction maximum
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L1104-L1108 */
  long length_delta = fd_long_sat_sub( (long)new_length, (long)acct->const_meta->dlen );
  long new_accounts_resize_delta = fd_long_sat_add( (long)borrowed_acct->instr_ctx->txn_ctx->accounts_resize_delta, length_delta );
  if( FD_UNLIKELY( new_accounts_resize_delta > MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED;
    return 0;
  }

  *err = FD_EXECUTOR_INSTR_SUCCESS;
  return 1;
}

FD_FN_PURE static inline int
fd_borrowed_account_is_zeroed( fd_borrowed_account_t const * borrowed_acct ) {
  fd_txn_account_t * acct = borrowed_acct->acct;
  /* TODO: optimize this */
  uchar const * data = ((uchar *) acct->const_meta) + acct->const_meta->hlen;
  for( ulong i=0UL; i < acct->const_meta->dlen; i++ )
    if( data[i] != 0 )
      return 0;
  return 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_borrowed_account_h */
