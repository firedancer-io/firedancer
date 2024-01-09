#include "../fd_zktpp_private.h"

int
fd_zktpp_verify_proof_range_u64(
  FD_FN_UNUSED fd_zktpp_range_proof_u64_proof_t const * proof,
  FD_FN_UNUSED uchar const                              commitments [ static 32 ],
  FD_FN_UNUSED uchar const                              bit_lengths [ static 1 ],
  FD_FN_UNUSED uchar const                              batch_len,
  FD_FN_UNUSED fd_zktpp_transcript_t *                  transcript ) {
  FD_LOG_DEBUG(( "fd_zktpp_verify_proof_range_u64" ));
  //TODO

  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_zktpp_instr_verify_proof_range_proof_u64( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_single_range_proof_context_t const * context = _context;
  fd_zktpp_range_proof_u64_proof_t const *      proof   = _proof;

  //TODO transcript

  const uchar bit_lengths[1] = { 64 };
  return fd_zktpp_verify_proof_range_u64( proof, context->commitment, bit_lengths, 1, transcript );
}
