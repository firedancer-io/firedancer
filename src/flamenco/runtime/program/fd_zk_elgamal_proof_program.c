#include "fd_zk_elgamal_proof_program.h"
#include "zksdk/fd_zksdk.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

/*
 * ZK ElGamal Proof Program
 */

int
fd_executor_zk_elgamal_proof_program_execute( fd_exec_instr_ctx_t ctx ) {
  uchar const * instr_data    = ctx.instr->data;
  ulong         instr_data_sz = ctx.instr->data_sz;

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L172-L176 */
  if( FD_UNLIKELY( instr_data_sz<1UL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  switch( instr_data[0] ) {
  case FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE:
    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L179-L185 */
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "CloseContextState" );
    return fd_zksdk_process_close_context_state( ctx );

  case FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyZeroCiphertext" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyCiphertextCiphertextEquality" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyCiphertextCommitmentEquality" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyPubkeyValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyPercentageWithCap" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyBatchedRangeProofU64" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyBatchedRangeProofU128" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyBatchedRangeProofU256" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyGroupedCiphertext2HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyBatchedGroupedCiphertext2HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyGroupedCiphertext3HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    FD_RUNTIME_CU_UPDATE ( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS );
    FD_RUNTIME_LOG_APPEND( ctx, "VerifyBatchedGroupedCiphertext3HandlesValidity" );
    break;

  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  return fd_zksdk_process_verify_proof( ctx );
}
