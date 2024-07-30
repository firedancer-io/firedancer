#ifndef HEADER_fd_src_flamenco_runtime_program_fd_zk_elgamal_proof_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_zk_elgamal_proof_program_h

/*
 * ZK ElGamal Proof Program
 */

#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_txn_ctx.h"

/* TODO: the following belong to a more generic header */

#define FD_RUNTIME_CU_UPDATE( ctx, cost ) do {            \
  fd_exec_instr_ctx_t * _ctx = &(ctx);                    \
  int err = fd_exec_consume_cus( _ctx->txn_ctx, (cost) ); \
  if( FD_UNLIKELY( err ) ) return err;                    \
  } while(0);

#define FD_RUNTIME_LOG_APPEND( ctx, log ) do { \
  } while(0);

/* FD_ZKSDK_INSTR_{...} identify ZK ElGamal Proof Program instructions.
   https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/instruction.rs#L48 */

#define FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE                   ((uchar) 0)
#define FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT                ((uchar) 1)
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY ((uchar) 2)
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY ((uchar) 3)
#define FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY                ((uchar) 4)
#define FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP            ((uchar) 5)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64        ((uchar) 6)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128       ((uchar) 7)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256       ((uchar) 8)
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY         ((uchar) 9)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY ((uchar)10)
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY         ((uchar)11)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY ((uchar)12)

/* FD_ZKSDK_INSTR_{...}_COMPUTE_UNITS
   https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L16 */

#define FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE_COMPUTE_UNITS                                    3300UL
#define FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS                                 6000UL
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS                  8000UL
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS                  6400UL
#define FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS                                 2600UL
#define FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS                             6500UL
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS                       111000UL
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS                      200000UL
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS                      368000UL
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS           6400UL
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS  13000UL
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS           8100UL
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS  16400UL

FD_PROTOTYPES_BEGIN

int
fd_executor_zk_elgamal_proof_program_execute( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_zk_elgamal_proof_program_h */
