#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_setup_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_setup_h

#include "../fd_flamenco_base.h"
#include "context/fd_exec_txn_ctx.h"

/* Functions in fd_executor_setup are responsible for setting up
   transaction execution context such as...
   - Core txn ctx fields
   - Loading in statically-referenced accounts from the serialized
     transaction message from funk
   - Resolving address lookup tables and loading referenced accounts
     from funk
   -  */

FD_PROTOTYPES_BEGIN

void
fd_executor_setup_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

/* Simply unpacks the account keys from the serialized transaction and sets them in the txn_ctx. */
void
fd_executor_setup_txn_account_keys( fd_exec_txn_ctx_t * txn_ctx );

/* Resolves any address lookup tables referenced in the transaction and adds
   them to the transaction's account keys. Returns 0 on success or if the transaction
   is a legacy transaction, and 1 on failure. */
int
fd_executor_setup_txn_alut_account_keys( fd_exec_txn_ctx_t * txn_ctx );

void
fd_executor_setup_txn_ctx_from_slot_ctx( fd_exec_slot_ctx_t const * slot_ctx,
                                         fd_exec_txn_ctx_t *        ctx,
                                         fd_wksp_t const *          funk_wksp,
                                         fd_wksp_t const *          runtime_pub_wksp,
                                         ulong                      funk_txn_gaddr,
                                         ulong                      funk_gaddr,
                                         fd_bank_hash_cmp_t *       bank_hash_cmp );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_setup_h */
