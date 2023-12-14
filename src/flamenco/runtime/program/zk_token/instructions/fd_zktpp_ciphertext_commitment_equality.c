#include "../fd_zktpp_private.h"
#include "../transcript/fd_zktpp_transcript.h"
// #include "../bulletproofs/fd_bulletproofs.h"
// #include "../encryption/fd_zktpp_encryption.h"
// #include "../twisted_elgamal/fd_twisted_elgamal.h"

typedef struct fd_zktpp_cce_context {
  uchar pubkey[ 32 ];     // point
  uchar ciphertext[ 64 ]; // 2x points
  uchar commitment[ 32 ]; // point
} fd_zktpp_cce_context_t;

// typedef struct fd_zktpp_cce_proof {
//   uchar y0[ 32 ]; // point
//   uchar y1[ 32 ]; // point
//   uchar y2[ 32 ]; // point
//   uchar zs[ 32 ]; // scalar
//   uchar zx[ 32 ]; // scalar
//   uchar zr[ 32 ]; // scalar
// } fd_zktpp_cce_proof_t;

static void
cce_transcript_init( fd_zktpp_transcript_t * transcript, 
                     fd_zktpp_cce_context_t * context ) {
  fd_zktpp_transcript_init( transcript, "CtxtCommEqualityProof" );
  fd_zktpp_transcript_append_pubkey    ( transcript, "pubkey",     context->pubkey );
  fd_zktpp_transcript_append_ciphertext( transcript, "ciphertext", context->ciphertext );
  fd_zktpp_transcript_append_commitment( transcript, "commitment", context->commitment );
}

int
fd_zktpp_ciphertext_commitment_equality_zkp_verify( FD_FN_UNUSED fd_zktpp_cce_proof_t const * proof,
                                                    FD_FN_UNUSED uchar const                  source_pubkey[ static 32 ],
                                                    FD_FN_UNUSED uchar const                  source_ciphertext[ static 64 ],
                                                    FD_FN_UNUSED uchar const                  destination_commitment[ static 32 ],
                                                    fd_zktpp_transcript_t *      transcript ) {
  fd_zktpp_transcript_domsep_equality_proof( transcript );
  FD_LOG_WARNING(( "Not implemented" ));
  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}

int
fd_zktpp_verify_proof_ciphertext_commitment_equality( void * _context, void * _proof ) {
  fd_zktpp_transcript_t    transcript[1];
  fd_zktpp_cce_context_t * context = _context;
  fd_zktpp_cce_proof_t *   proof = _proof;

  cce_transcript_init( transcript, context );
  return fd_zktpp_ciphertext_commitment_equality_zkp_verify(
    proof,
    context->pubkey,
    context->ciphertext,
    context->commitment,
    transcript
  );
}
