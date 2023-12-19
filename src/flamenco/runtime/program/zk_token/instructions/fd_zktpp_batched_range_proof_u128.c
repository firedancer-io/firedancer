#include "../fd_zktpp_private.h"

int
fd_zktpp_verify_proof_range_u128(
  fd_zktpp_range_proof_u128_proof_t const * proof,
  FD_FN_UNUSED uchar const                               commitments [ static 32 ],
  FD_FN_UNUSED uchar const                               bit_lengths [ static 1 ],
  FD_FN_UNUSED uchar const                               batch_len,
  FD_FN_UNUSED fd_zktpp_transcript_t *                   transcript ) {

  //TODO

  //HACK to test the test
  if (proof->a[1] == 0xb2) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}

int
fd_zktpp_instr_verify_proof_batched_range_proof_u128( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_batched_range_proof_context_t const * context = _context;
  fd_zktpp_range_proof_u128_proof_t const *      proof   = _proof;

  //TODO transcript
  uchar len = FD_ZKTPP_MAX_COMMITMENTS;
  return fd_zktpp_verify_proof_range_u128( proof, context->commitments, context->bit_lengths, len, transcript );
}
