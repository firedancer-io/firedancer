#include "../fd_zksdk_private.h"

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u256.rs#L90 */
int
fd_zksdk_instr_verify_proof_batched_range_proof_u256( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_batched_range_proof_context_t const * context = _context;
  fd_zksdk_range_proof_u256_proof_t const *      proof   = _proof;

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u256.rs#L91 */
  uchar batch_len = 0;
  int val = batched_range_proof_context_try_into( &batch_len, context );
  if( FD_UNLIKELY( val != FD_ZKSDK_VERIFY_PROOF_SUCCESS ) ) {
    return val;
  }

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u256.rs#L99-L104
     This is already checked in batched_range_proof_context_try_into() */

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u256.rs#L106-L108
     This can never happen: `commitments: [PodPedersenCommitment; MAX_COMMITMENTS]` */

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u256.rs#L110-L117
     We validate this inside fd_rangeproofs_verify() */

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u256.rs#L119 */
  batched_range_proof_context_new_transcript( transcript, context );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u256.rs#L122-L124 */
  const fd_rangeproofs_ipp_proof_t ipp_proof = {
    8,
    proof->ipp_lr_vec,
    proof->ipp_a,
    proof->ipp_b,
  };
  int res = fd_rangeproofs_verify(
    &proof->range_proof,
    &ipp_proof,
    context->commitments,
    context->bit_lengths,
    batch_len,
    transcript
  );

  if( FD_LIKELY( res == FD_RANGEPROOFS_SUCCESS ) ) {
    return FD_ZKSDK_VERIFY_PROOF_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}
