#include "../fd_zktpp_private.h"

int
fd_zktpp_verify_proof_batched_grouped_ciphertext_validity(
  fd_zktpp_batched_grp_ciph_val_proof_t const * proof,
  FD_FN_UNUSED uchar const                                   dst_pubkey    [ static 32 ],
  FD_FN_UNUSED uchar const                                   aud_pubkey    [ static 32 ],
  FD_FN_UNUSED uchar const                                   comm_lo       [ static 32 ],
  FD_FN_UNUSED uchar const                                   comm_hi       [ static 32 ],
  FD_FN_UNUSED uchar const                                   dst_handle_lo [ static 32 ],
  FD_FN_UNUSED uchar const                                   dst_handle_hi [ static 32 ],
  FD_FN_UNUSED uchar const                                   aud_handle_lo [ static 32 ],
  FD_FN_UNUSED uchar const                                   aud_handle_hi [ static 32 ],
  FD_FN_UNUSED fd_zktpp_transcript_t *                       transcript ) {

  //TODO

  //HACK to test the test
  if (proof->y0[1] == 0xad) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  FD_LOG_WARNING(( "Not implemented" ));
  return FD_ZKTPP_VERIFY_PROOF_ERROR;
}

int
fd_zktpp_instr_verify_proof_batched_grouped_ciphertext_validity( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_batched_grp_ciph_val_context_t const * context = _context;
  fd_zktpp_batched_grp_ciph_val_proof_t const *   proof   = _proof;

  //TODO transcript

  return fd_zktpp_verify_proof_batched_grouped_ciphertext_validity(
    proof,
    context->destination_pubkey,
    context->auditor_pubkey,
    context->grouped_ciphertext_lo.commitment,
    context->grouped_ciphertext_hi.commitment,
    context->grouped_ciphertext_lo.destination_handle,
    context->grouped_ciphertext_hi.destination_handle,
    context->grouped_ciphertext_lo.auditor_handle,
    context->grouped_ciphertext_hi.auditor_handle,
    transcript
  );
}
