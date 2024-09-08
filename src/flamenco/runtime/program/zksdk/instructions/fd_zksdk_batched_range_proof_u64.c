#include "../fd_zksdk_private.h"

static inline int
fd_zksdk_verify_proof_range_u64(
  fd_zksdk_range_proof_u64_proof_t const * proof,
  uchar const                               commitments [ 32 ],
  uchar const                               bit_lengths [ 1 ],
  uchar const                               batch_len,
  fd_zksdk_transcript_t *                   transcript ) {

  const fd_rangeproofs_ipp_proof_t ipp_proof = {
    6,
    proof->ipp_lr_vec,
    proof->ipp_a,
    proof->ipp_b,
  };
  int res = fd_rangeproofs_verify(
    &proof->range_proof,
    &ipp_proof,
    commitments,
    bit_lengths,
    batch_len,
    transcript
  );

  if( FD_LIKELY( res == FD_RANGEPROOFS_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

int
fd_zksdk_instr_verify_proof_batched_range_proof_u64( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_batched_range_proof_context_t const * context = _context;
  fd_zksdk_range_proof_u64_proof_t const *       proof   = _proof;

  uchar batch_len = 0;
  /* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u64.rs#L82-L91 */
  int val = batched_range_proof_init_and_validate( &batch_len, context, transcript );
  if( FD_UNLIKELY( val != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return val;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_range_proof/batched_range_proof_u64.rs#L93-L95 */
  return fd_zksdk_verify_proof_range_u64( proof, context->commitments, context->bit_lengths, batch_len, transcript );
}
