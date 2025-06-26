#include "fd_zk_elgamal_proof_program.h"
#include "zksdk/fd_zksdk.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

/*
 * ZK ElGamal Proof Program
 */

int
fd_executor_zk_elgamal_proof_program_execute( fd_exec_instr_ctx_t * ctx ) {
  /* Feature-gate program activation */
  if( FD_UNLIKELY( !FD_FEATURE_ACTIVE( ctx->txn_ctx->slot, &ctx->txn_ctx->features, zk_elgamal_proof_program_enabled ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.16/programs/zk-elgamal-proof/src/lib.rs#L175-L187 */
  if( FD_LIKELY(  FD_FEATURE_ACTIVE( ctx->txn_ctx->slot, &ctx->txn_ctx->features, disable_zk_elgamal_proof_program )
              && !FD_FEATURE_ACTIVE( ctx->txn_ctx->slot, &ctx->txn_ctx->features, reenable_zk_elgamal_proof_program ) ) ) {
    fd_log_collector_msg_literal( ctx, "zk-elgamal-proof program is temporarily disabled" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  uchar const * instr_data    = ctx->instr->data;
  ulong         instr_data_sz = ctx->instr->data_sz;

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L172-L176 */
  if( FD_UNLIKELY( instr_data_sz==0UL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  switch( instr_data[0] ) {
  case FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE:
    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L179-L185 */
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "CloseContextState" );
    return fd_zksdk_process_close_context_state( ctx );

  case FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyZeroCiphertext" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyCiphertextCiphertextEquality" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyCiphertextCommitmentEquality" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyPubkeyValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyPercentageWithCap" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedRangeProofU64" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedRangeProofU128" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedRangeProofU256" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyGroupedCiphertext2HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedGroupedCiphertext2HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyGroupedCiphertext3HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedGroupedCiphertext3HandlesValidity" );
    break;

  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  return fd_zksdk_process_verify_proof( ctx );
}
