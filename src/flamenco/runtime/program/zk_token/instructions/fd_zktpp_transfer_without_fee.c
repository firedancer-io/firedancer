#include "../fd_zktpp_private.h"
#include "../transcript/fd_zktpp_transcript.h"
// #include "../bulletproofs/fd_bulletproofs.h"
// #include "../encryption/fd_zktpp_encryption.h"
// #include "../twisted_elgamal/fd_twisted_elgamal.h"

typedef struct fd_zktpp_transfer_pubkeys {
  uchar source[ 32 ];      // point
  uchar destination[ 32 ]; // point
  uchar auditor[ 32 ];     // point
} fd_zktpp_transfer_pubkeys_t;

typedef struct fd_zktpp_transfer_context {
  uchar                       ciphertext_lo[ 128 ];        // 4x points
  uchar                       ciphertext_hi[ 128 ];        // 4x points
  fd_zktpp_transfer_pubkeys_t transfer_pubkeys;            // 3x points: source, destination, auditor
  uchar                       new_source_ciphertext[ 64 ]; // 2x points
} fd_zktpp_transfer_context_t;

typedef struct fd_zktpp_transfer_proof {
  uchar                new_source_commitment[ 32 ]; // point
  fd_zktpp_cce_proof_t equality_proof;              // ciphertext_commitment_equality == 192 bytes
  uchar                validity_proof[ 32 ];        // TODO
  uchar                range_proof[ 32 ];           // TODO
} fd_zktpp_transfer_proof_t;

int
fd_zktpp_verify_proof_transfer_without_fee( void * _context, void *_proof ) {
  fd_zktpp_transcript_t         transcript[1];
  fd_zktpp_transfer_context_t * context = _context;
  fd_zktpp_transfer_proof_t *   proof = _proof;
  int zkp_res = 0;

  zkp_res = fd_zktpp_ciphertext_commitment_equality_zkp_verify(
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
