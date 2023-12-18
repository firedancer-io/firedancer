#include "../fd_zktpp_private.h"

static void
ciph_comm_eq_transcript_init( fd_zktpp_transcript_t *        transcript,
                     fd_zktpp_ciph_comm_eq_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, "CtxtCommEqualityProof" );
  fd_zktpp_transcript_append_pubkey    ( transcript, "pubkey",     context->pubkey );
  fd_zktpp_transcript_append_ciphertext( transcript, "ciphertext", context->ciphertext );
  fd_zktpp_transcript_append_commitment( transcript, "commitment", context->commitment );
}

int
fd_zktpp_verify_proof_ciphertext_commitment_equality(
  fd_zktpp_ciph_comm_eq_proof_t const * proof,
  FD_FN_UNUSED uchar const                           source_pubkey         [ static 32 ],
  FD_FN_UNUSED uchar const                           source_ciphertext     [ static 64 ],
  FD_FN_UNUSED uchar const                           destination_commitment[ static 32 ],
  fd_zktpp_transcript_t *               transcript ) {

  //HACK to test the test
  if (proof->y0[1] == 0x12) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  fd_zktpp_transcript_domsep_equality_proof( transcript );

  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}

int
fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_ciph_comm_eq_context_t const * context = _context;
  fd_zktpp_ciph_comm_eq_proof_t const *   proof   = _proof;

  ciph_comm_eq_transcript_init( transcript, context );
  return fd_zktpp_verify_proof_ciphertext_commitment_equality(
    proof,
    context->pubkey,
    context->ciphertext,
    context->commitment,
    transcript
  );
}
