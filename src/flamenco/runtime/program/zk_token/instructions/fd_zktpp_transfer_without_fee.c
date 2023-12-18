#include "../fd_zktpp_private.h"
#include "fd_zktpp_ciphertext_commitment_equality.h"

int
fd_zktpp_instr_verify_proof_transfer_without_fee( void const * _context, void const *_proof ) {
  fd_zktpp_transcript_t               transcript[1];
  fd_zktpp_transfer_context_t const * context = _context;
  fd_zktpp_transfer_proof_t const *   proof = _proof;
  int zkp_res = 0;

  zkp_res = fd_zktpp_verify_proof_ciphertext_commitment_equality(
    &proof->equality_proof,
    context->transfer_pubkeys.source,
    context->new_source_ciphertext,
    proof->new_source_commitment,
    transcript
  );
  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}
