#include "fd_borrowed_account.h"
#include "context/fd_exec_instr_ctx.h"
#include "context/fd_exec_slot_ctx.h"

/* fd_account_is_executable_internal is a private function for deprecating the `is_executable` flag.
   It returns true if the `remove_accounts_executable_flag_checks` feature is inactive AND fd_account_is_executable
   return true. This is newly used in account modification logic to eventually allow "executable" accounts to be
   modified.

   https://github.com/anza-xyz/agave/blob/89872fdb074e6658646b2b57a299984f0059cc84/sdk/transaction-context/src/lib.rs#L1052-L1060 */

FD_FN_PURE static inline int
fd_account_is_executable_internal( fd_borrowed_account_t const * borrowed_acct ) {
  return !FD_FEATURE_ACTIVE( borrowed_acct->instr_ctx->slot_ctx, remove_accounts_executable_flag_checks ) &&
          fd_borrowed_account_is_executable( borrowed_acct );
}