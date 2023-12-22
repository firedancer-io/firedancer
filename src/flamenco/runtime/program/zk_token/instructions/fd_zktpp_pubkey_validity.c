#include "../fd_zktpp_private.h"
#include "../encryption/fd_zktpp_encryption.h"

static void
pubkey_validity_transcript_init( fd_zktpp_transcript_t *                    transcript,
                                 fd_zktpp_pubkey_validity_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("PubkeyProof") );
  fd_zktpp_transcript_append_pubkey( transcript, FD_TRANSCRIPT_LITERAL("pubkey"), context->pubkey );
}

static int
fd_zktpp_verify_proof_pubkey_validity(
  fd_zktpp_pubkey_validity_proof_t const * proof,
  uchar const                              pubkey         [ static 32 ],
  fd_zktpp_transcript_t *                  transcript ) {

  /*
    We need to verify the following equivalence:
        z H =?= c P + Y
    or:
        Y =?= z H - c P
  */

  /* Validate all inputs */
  fd_ristretto255_point_t points[2];
  fd_ristretto255_point_t y[1];
  fd_ristretto255_point_t res[1];
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y, proof->y )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[0], pubkey )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  fd_memcpy( &points[1], fd_zktpp_basepoint_H, sizeof(fd_ristretto255_point_t) );

  uchar scalars[ 2 * 32 ];
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( proof->z )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  /* Finalize transcript and extract challenges */
  fd_zktpp_transcript_domsep_pubkey_proof( transcript );
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zktpp_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y"), proof->y);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  uchar c[ 32 ];
  fd_zktpp_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  /* Compute scalars */
  fd_ed25519_sc_neg( &scalars[ 0*32 ], c );    // -c
  fd_memcpy( &scalars[ 1*32 ], proof->z, 32 ); // z

  /* Compute the final MSM */
  fd_ristretto255_multiscalar_mul( res, scalars, points, 2 );
  if( FD_UNLIKELY( fd_ristretto255_point_eq( res, y )==0 ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_zktpp_instr_verify_proof_pubkey_validity( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_pubkey_validity_context_t const * context = _context;
  fd_zktpp_pubkey_validity_proof_t const *   proof   = _proof;

  pubkey_validity_transcript_init( transcript, context );
  return fd_zktpp_verify_proof_pubkey_validity(
    proof,
    context->pubkey,
    transcript
  );
}
