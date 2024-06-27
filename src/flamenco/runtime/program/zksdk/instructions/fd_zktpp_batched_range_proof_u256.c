#include "../fd_zktpp_private.h"

int
fd_zktpp_verify_proof_range_u256(
  fd_zktpp_range_proof_u256_proof_t const * proof,
  uchar const                               commitments [ static 32 ],
  uchar const                               bit_lengths [ static 1 ],
  uchar const                               batch_len,
  fd_zktpp_transcript_t *                   transcript ) {

  const fd_bulletproofs_ipp_proof_t ipp_proof = {
    6,
    proof->ipp_lr_vec,
    proof->ipp_a,
    proof->ipp_b,
  };
  int res = fd_bulletproofs_range_proof_verify(
    &proof->range_proof,
    &ipp_proof,
    commitments,
    bit_lengths,
    batch_len,
    transcript
  );

  if( FD_LIKELY( res == FD_BULLETPROOFS_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_ZKTPP_VERIFY_PROOF_ERROR;
}

int
fd_zktpp_instr_verify_proof_batched_range_proof_u256( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_batched_range_proof_context_t const * context = _context;
  fd_zktpp_range_proof_u256_proof_t const *      proof   = _proof;

  FD_LOG_DEBUG(( "fd_zktpp_instr_verify_proof_batched_range_proof_u256" ));

  batched_range_proof_transcript_init( transcript, context );

  uchar len = 0;
  int val = batched_range_proof_validate_context( &len, context );
  if( FD_UNLIKELY( val != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  return fd_zktpp_verify_proof_range_u256( proof, context->commitments, context->bit_lengths, len, transcript );
}
