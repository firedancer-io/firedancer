#include "../fd_zktpp_private.h"
#include "../encryption/fd_zktpp_encryption.h"

static void
grouped_ciphertext_validity_transcript_init(
  fd_zktpp_transcript_t *                 transcript,
  fd_zktpp_grp_ciph_val_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("BatchedGroupedCiphertextValidityProof") );
  fd_zktpp_transcript_append_pubkey( transcript, FD_TRANSCRIPT_LITERAL("destination-pubkey"), context->destination_pubkey );
  fd_zktpp_transcript_append_pubkey( transcript, FD_TRANSCRIPT_LITERAL("auditor-pubkey"), context->auditor_pubkey );
  fd_zktpp_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext"), (uchar *)&context->grouped_ciphertext, sizeof(fd_zktpp_grouped_ciphertext_dst_aud_t) );
}

int
fd_zktpp_instr_verify_proof_grouped_ciphertext_validity( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_grp_ciph_val_context_t const * context = _context;
  fd_zktpp_grp_ciph_val_proof_t const *   proof   = _proof;

  grouped_ciphertext_validity_transcript_init( transcript, context );
  return fd_zktpp_verify_proof_batched_grouped_ciphertext_validity(
    proof,
    context->destination_pubkey,
    context->auditor_pubkey,
    context->grouped_ciphertext.commitment,
    context->grouped_ciphertext.destination_handle,
    context->grouped_ciphertext.auditor_handle,
    NULL,
    NULL,
    NULL,
    false,
    transcript
  );
}
