#ifndef HEADER_fd_src_flamenco_runtime_fd_txn_loader_h
#define HEADER_fd_src_flamenco_runtime_fd_txn_loader_h

#include "../fd_flamenco_base.h"

/* The functions in fd_txn_loader mimic Agave's
   `load_transaction_accounts()` functions and helpers. This file name
   is a bit of a misnomer - we don't actually "load" accounts here from
   our accounts db, but instead replicate the surrounding data size
   checks and program account validations that take place in
   `load_transaction_accounts()`. See function docs and comments for
   more details. */

FD_PROTOTYPES_BEGIN

/* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L518-L548 */
int
fd_executor_load_transaction_accounts( fd_exec_txn_ctx_t * txn_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txn_loader_h */
