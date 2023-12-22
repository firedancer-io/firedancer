#include "../fd_zktpp_private.h"

static void
withdraw_transcript_init( fd_zktpp_transcript_t *             transcript,
                          fd_zktpp_withdraw_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("WithdrawProof") );
  fd_zktpp_transcript_append_pubkey(     transcript, FD_TRANSCRIPT_LITERAL("pubkey"),     context->pubkey );
  fd_zktpp_transcript_append_ciphertext( transcript, FD_TRANSCRIPT_LITERAL("ciphertext"), context->final_ciphertext );
}

int
fd_zktpp_instr_verify_proof_withdraw( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_withdraw_context_t const * context = _context;
  fd_zktpp_withdraw_proof_t const *   proof   = _proof;
  int zkp_res = 0;

  withdraw_transcript_init( transcript, context );
  fd_zktpp_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("commitment"), proof->commitment );

  zkp_res = fd_zktpp_verify_proof_ciphertext_commitment_equality(
    &proof->equality_proof,
    context->pubkey,
    context->final_ciphertext,
    proof->commitment,
    transcript
  );
  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  uchar bit_lengths[1] = { 64 };
  zkp_res = fd_zktpp_verify_proof_range_u64(
    &proof->range_proof,
    proof->commitment,
    bit_lengths,
    1,
    transcript
  );
  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
