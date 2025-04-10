#ifndef HEADER_fd_src_flamenco_runtime_program_fd_native_program_cpi_h
#define HEADER_fd_src_flamenco_runtime_program_fd_native_program_cpi_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../../vm/syscall/fd_vm_syscall.h"

FD_PROTOTYPES_BEGIN

/* Equivalent to Agave's `native_invoke()` function. Used by native
   programs to CPI into other native programs.

   https://github.com/anza-xyz/agave/blob/v2.2.6/program-runtime/src/invoke_context.rs#L307-L323 */
int
fd_native_cpi_native_invoke( fd_exec_instr_ctx_t *             ctx,
                             fd_pubkey_t const *               native_program_id,
                             uchar *                           instr_data,
                             ulong                             instr_data_len,
                             fd_vm_rust_account_meta_t const * acct_metas,
                             ulong                             acct_metas_len,
                             fd_pubkey_t const *               signers,
                             ulong                             signers_cnt );

void
fd_native_cpi_create_account_meta( fd_pubkey_t const * key, uchar is_signer,
                                   uchar is_writable, fd_vm_rust_account_meta_t * meta );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_native_program_cpi_h */
