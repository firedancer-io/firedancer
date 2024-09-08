#include "../fd_zksdk_private.h"

static inline void
grouped_ciphertext_validity_transcript_init(
  fd_zksdk_transcript_t *                    transcript,
  fd_zksdk_grp_ciph_3h_val_context_t const * context ) {
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-validity-3-handles-instruction") );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("first-pubkey"),  context->pubkey1 );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("second-pubkey"), context->pubkey2 );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("third-pubkey"),  context->pubkey3 );
  fd_zksdk_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext"), (uchar *)&context->grouped_ciphertext, sizeof(grp_ciph_3h_t) );
}

int
fd_zksdk_instr_verify_proof_grouped_ciphertext_3_handles_validity( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_grp_ciph_3h_val_context_t const * context = _context;
  fd_zksdk_grp_ciph_3h_val_proof_t const *   proof   = _proof;

  grouped_ciphertext_validity_transcript_init( transcript, context );

  return fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity(
    proof,
    context->pubkey1,
    context->pubkey2,
    context->pubkey3,
    context->grouped_ciphertext.commitment,
    context->grouped_ciphertext.handles[0].handle,
    context->grouped_ciphertext.handles[1].handle,
    context->grouped_ciphertext.handles[2].handle,
    NULL,
    NULL,
    NULL,
    NULL,
    false,
    transcript
  );
}
