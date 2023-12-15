#include "fd_zk_token_proof_program.h"
#include "zk_token/fd_zktpp.h"
#include "../fd_executor.h"

int
fd_executor_zk_token_proof_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {

  uchar const * instr_data    = ctx.instr->data;
  ulong         instr_data_sz = ctx.instr->data_sz;

  if( FD_UNLIKELY( instr_data_sz<1UL ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* TODO pre-checks:
     - check feature_set.is_active
     - check invoke context stack height
     https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/src/lib.rs#L134-L154 */

  switch( instr_data[0] ) {
  case FD_ZKTPP_INSTR_CLOSE_CONTEXT_STATE:
    /* TODO:
       - consume CU
       - Log "CloseContextState"
       https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/src/lib.rs#L158-L163 */
    return fd_zktpp_process_close_proof_context( ctx );
  case FD_ZKTPP_INSTR_VERIFY_ZERO_BALANCE:
  case FD_ZKTPP_INSTR_VERIFY_WITHDRAW:
  case FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY:
  case FD_ZKTPP_INSTR_VERIFY_TRANSFER:
  case FD_ZKTPP_INSTR_VERIFY_TRANSFER_WITH_FEE:
  case FD_ZKTPP_INSTR_VERIFY_PUBKEY_VALIDITY:
  case FD_ZKTPP_INSTR_VERIFY_RANGE_PROOF_U64:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256:
  case FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY:
  case FD_ZKTPP_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
  case FD_ZKTPP_INSTR_VERIFY_FEE_SIGMA:
    // TODO: consume CU + Log
    return fd_zktpp_process_verify_proof( ctx );
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
}
