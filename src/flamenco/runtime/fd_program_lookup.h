#ifndef HEADER_fd_src_flamenco_runtime_fd_program_lookup
#define HEADER_fd_src_flamenco_runtime_fd_program_lookup

#include "../fd_flamenco_base.h"
#include "context/fd_exec_txn_ctx.h"

/* fd_program_lookup contains functions for querying information about
   program IDs and getting their associated entrypoints. */

/* fd_exec_instr_fn_t processes an instruction.  Returns an error code
   in FD_EXECUTOR_INSTR_{ERR_{...},SUCCESS}. */

typedef int (* fd_exec_instr_fn_t)( fd_exec_instr_ctx_t * ctx );

FD_PROTOTYPES_BEGIN

/* `fd_program_lookup_precompile_entrypoint()` looks up a precompile's
   entrypoint (the verify function) for a given pubkey. */
fd_exec_instr_fn_t
fd_program_lookup_precompile_entrypoint( fd_pubkey_t const * pubkey );

/* `fd_program_lookup_native_entrypoint()` returns the appropriate
   instruction processor for the given native program ID. Returns NULL
   if given ID is not a recognized native program.
   https://github.com/anza-xyz/agave/blob/v2.2.6/program-runtime/src/invoke_context.rs#L520-L544 */
int
fd_program_lookup_native_entrypoint( fd_txn_account_t const * prog_acc,
                                     fd_exec_txn_ctx_t *      txn_ctx,
                                     fd_exec_instr_fn_t *     native_prog_fn,
                                     uchar *                  is_precompile );

/* `fd_pubkey_is_bpf_loader()` returns 1 if the given pubkey
   matches one of the BPF loader v1/v2/v3/v4 program IDs, and 0
   otherwise. */
uchar
fd_pubkey_is_bpf_loader( fd_pubkey_t const * pubkey );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_program_lookup */
