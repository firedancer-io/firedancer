#ifndef HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h
#define HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h

#include "../fd_runtime.h"
#include "../context/fd_exec_instr_ctx.h"

/* PrecompileError
   https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/precompiles.rs#L16
   Agave distinguishes between 5 errors and the returned one depends on
   the order they decided to write their code.
   These are all fatal errors, so the specific errors don't matter for
   consensus.
   To simplify our fuzzers, we return the same error code for all errors. */
#define FD_EXECUTOR_PRECOMPILE_ERR_PUBLIC_KEY                    ( 0 )
#define FD_EXECUTOR_PRECOMPILE_ERR_RECOVERY_ID                   ( 1 )
#define FD_EXECUTOR_PRECOMPILE_ERR_SIGNATURE                     ( 2 )
#define FD_EXECUTOR_PRECOMPILE_ERR_DATA_OFFSET                   ( 3 )
#define FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE               ( 4 )

FD_PROTOTYPES_BEGIN

/* fd_precompile_ed25519_verify is the instruction processing entrypoint
   for the Ed25519 precompile. */

int
fd_precompile_ed25519_verify( fd_exec_instr_ctx_t * ctx );

/* fd_precompile_secp256k1_verify is the instruction processing entrypoint
   for the Secp256k1 precompile. */

int
fd_precompile_secp256k1_verify( fd_exec_instr_ctx_t * ctx );

/* fd_precompile_secp256r1_verify is the instruction processing entrypoint
   for the Secp256r1 precompile (SIMD-0075). */

int
fd_precompile_secp256r1_verify( fd_exec_instr_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h */
