#ifndef HEADER_fd_src_flamenco_runtime_program_fd_native_program_cpi_h
#define HEADER_fd_src_flamenco_runtime_program_fd_native_program_cpi_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

int 
fd_native_cpi_execute_system_program_instruction( fd_exec_instr_ctx_t * ctx,
                                                  fd_system_program_instruction_t const * instr,
                                                  fd_vm_rust_account_meta_t const * acct_metas,
                                                  ulong acct_metas_len,
                                                  fd_pubkey_t const * signers,
                                                  ulong signers_cnt );

void
fd_native_cpi_create_account_meta( fd_pubkey_t const * key, uchar is_signer, 
                                   uchar is_writable, fd_vm_rust_account_meta_t * meta );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_native_program_cpi_h */
