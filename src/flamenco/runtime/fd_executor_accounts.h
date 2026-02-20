#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_accounts_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_accounts_h

#include "fd_runtime.h"
#include "../../ballet/lthash/fd_lthash.h"

FD_PROTOTYPES_BEGIN

/* fd_exec_accounts_setup acquires references to all accounts that may
   be used during transaction execution.

   This includes:
   - Transaction accounts
   - Program data accounts
   - Owners of program accounts
   - Rollback accounts (fee payer and nonce account)

   If txn_in indicates bundle execution, uses the account overlay. */

void
fd_exec_accounts_setup( fd_runtime_t *      runtime,
                        fd_bank_t *         bank,
                        fd_txn_in_t const * txn_in,
                        fd_txn_out_t *      txn_out );

/* Transaction success case *******************************************/

/* fd_exec_accounts_lthash calculates the LtHash of all writable
   accounts. */

void
fd_exec_accounts_lthash( fd_txn_out_t const * txn,
                         fd_lthash_value_t *  lthash_out );

/* fd_exec_accounts_commit writes all modified transaction accounts back
   to the account database. */

void
fd_exec_accounts_commit( fd_runtime_t * runtime,
                         fd_txn_out_t * txn_out );

/* Transaction failure case *******************************************/

/* fd_exec_accounts_lthash_fail calculates the LtHash of the "rollback"
   fee payer and nonce account.  (After advancing the nonce account and
   debiting the fee payer.) */

void
fd_exec_accounts_lthash_fail( fd_txn_out_t const * txn,
                              fd_lthash_value_t *  lthash_out );

/* fd_exec_accounts_commit_fail writes the "rollback" fee payer and
   nonce account back to the account database.  (transaction failure
   case) */

void
fd_exec_accounts_commit_fail( fd_runtime_t * runtime,
                              fd_txn_out_t * txn_out );

/* Transaction revert *************************************************/

/* fd_exec_accounts_cancel releases all accounts without making changes
   to the account database. */

void
fd_exec_accounts_cancel( fd_runtime_t * runtime,
                         fd_txn_out_t * txn_out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_accounts_h */
