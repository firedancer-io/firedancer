#ifndef HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h
#define HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h

#include "../fd_runtime.h"
#include "../context/fd_exec_txn_ctx.h"

FD_PROTOTYPES_BEGIN

/* fd_precompile_ed25519_verify is the instruction processing entrypoint
   for the Ed25519 precompile. */

int
fd_precompile_ed25519_verify( fd_exec_instr_ctx_t ctx );

/* fd_precompile_secp256k1_verify is the instruction processing entrypoint
   for the Secp256k1 precompile. */

int
fd_precompile_secp256k1_verify( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h */
