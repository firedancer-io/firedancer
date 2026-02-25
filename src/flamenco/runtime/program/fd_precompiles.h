#ifndef HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h
#define HEADER_fd_src_flamenco_runtime_program_fd_precompiles_h

/* fd_precompiles.h provides APIs for "precompiled"-type builtin
   programs.  These programs undergo special treatment during cost
   tracking and transaction execution.

   The current set of precompiles requires external cryptography code
   in Firedancer (installed via ./deps.sh), namely s2n-bignum.  In some
   testing scenarios, the developer may not have this dependency
   installed because it won't be used.  To avoid link errors in such a
   situation, precompiles are resolved at runtime (as opposed to
   compile-time). */

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

#define NO_ENABLE_FEATURE_ID ULONG_MAX

struct fd_precompile_program {
  fd_pubkey_t const * pubkey;
  ulong               feature_offset;
  int                 (* verify_fn )( fd_exec_instr_ctx_t * ctx );
};
typedef struct fd_precompile_program fd_precompile_program_t;

struct fd_native_prog_info {
  fd_pubkey_t        key;
  fd_exec_instr_fn_t fn;
  uchar              is_bpf_loader;
  ulong              feature_enable_offset; /* offset to the feature that enables this program, if any */
};
typedef struct fd_native_prog_info fd_native_prog_info_t;

FD_PROTOTYPES_BEGIN

/* High-level precompile API

   These symbols are always available.  If precompiles are requested but
   the user has not installed them / does not have necessary deps,
   terminates with FD_LOG_ERR. */

fd_precompile_program_t const *
fd_precompiles( void );

fd_exec_instr_fn_t
fd_executor_lookup_native_precompile_program( fd_pubkey_t const * pubkey );

/* Raw precompile symbols

   These might not be linked into the binary depending on build
   configuration. */

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
