#ifndef HEADER_fd_src_flamenco_runtime_program_fd_zk_elgamal_proof_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_zk_elgamal_proof_program_h

/*
 * ZK ElGamal Proof Program
 */

#include "../context/fd_exec_instr_ctx.h"

/* FD_ZKSDK_INSTR_{...}_COMPUTE_UNITS
   https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs */
#define FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE_COMPUTE_UNITS                                  (  3300UL)
#define FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS                               (  6000UL)
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS                (  8000UL)
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS                (  6400UL)
#define FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS                               (  2600UL)
#define FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS                           (  6500UL)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS                       (111000UL)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS                      (200000UL)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS                      (368000UL)
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS         (  6400UL)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS ( 13000UL)
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS         (  8100UL)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS ( 16400UL)

/* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L33 */
#define FD_ZKSDK_INSTR_DATA_LENGTH_WITH_PROOF_ACCOUNT (5UL)

FD_PROTOTYPES_BEGIN

/* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L174 */
int
fd_executor_zk_elgamal_proof_program_execute( fd_exec_instr_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_zk_elgamal_proof_program_h */
