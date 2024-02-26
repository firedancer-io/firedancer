#include "fd_system_program.h"

int
fd_system_program_exec_advance_nonce_account( fd_exec_instr_ctx_t * ctx ) {
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}

int
fd_system_program_exec_withdraw_nonce_account( fd_exec_instr_ctx_t * ctx,
                                               ulong                 requested_lamports ) {
  (void)ctx;
  (void)requested_lamports;
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}

int
fd_system_program_exec_initialize_nonce_account( fd_exec_instr_ctx_t * ctx,
                                                 fd_pubkey_t const *   initialize_nonce_account ) {
  (void)ctx;
  (void)initialize_nonce_account;
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}

int
fd_system_program_exec_authorize_nonce_account( fd_exec_instr_ctx_t * ctx,
                                                fd_pubkey_t const *   authorize_nonce_account ) {
  (void)ctx;
  (void)authorize_nonce_account;
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}

int
fd_system_program_exec_upgrade_nonce_account( fd_exec_instr_ctx_t * ctx ) {
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}
