#ifndef HEADER_fd_src_flamenco_runtime_program_fd_system_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_system_program_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

/* Entry-point for the Solana System Program */
int fd_executor_system_program_execute_instruction( fd_exec_instr_ctx_t ctx ) ;

void fd_durable_nonce_from_blockhash(fd_hash_t *hash, fd_hash_t *out);
int  fd_load_nonce_account(fd_exec_txn_ctx_t * txn_ctx, fd_txn_t const * txn_descriptor, fd_rawtxn_b_t const * txn_raw, fd_nonce_state_versions_t *state, int *opt_err);
int  fd_advance_nonce_account   (fd_exec_instr_ctx_t ctx);
int  fd_withdraw_nonce_account  (fd_exec_instr_ctx_t ctx, unsigned long      withdraw_nonce_account);
int  fd_initialize_nonce_account(fd_exec_instr_ctx_t ctx, fd_pubkey_t        *initialize_nonce_account);
int  fd_authorize_nonce_account (fd_exec_instr_ctx_t ctx, fd_pubkey_t        *authorize_nonce_account);
int  fd_upgrade_nonce_account   (fd_exec_instr_ctx_t ctx);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_system_program_h */
