#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_setup_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_setup_h

#include "fd_executor.h"
#include "program/fd_bpf_loader_program.h"

#define FD_FEE_PAYER_TXN_IDX (0UL)

FD_PROTOTYPES_BEGIN

void
fd_executor_setup_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

void
fd_executor_setup_txn_account_keys( fd_exec_txn_ctx_t * txn_ctx );

int
fd_executor_setup_txn_alut_account_keys( fd_exec_txn_ctx_t * txn_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_setup_h */
