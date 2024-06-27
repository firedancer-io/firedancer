#include "../fd_zktpp_private.h"

static inline void
ciph_comm_eq_transcript_init( fd_zktpp_transcript_t *        transcript,
                     fd_zktpp_ciph_comm_eq_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("CtxtCommEqualityProof") );
  fd_zktpp_transcript_append_pubkey    ( transcript, FD_TRANSCRIPT_LITERAL("pubkey"),     context->pubkey );
  fd_zktpp_transcript_append_ciphertext( transcript, FD_TRANSCRIPT_LITERAL("ciphertext"), context->ciphertext );
  fd_zktpp_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("commitment"), context->commitment );
}

int
fd_zktpp_verify_proof_ciphertext_commitment_equality(
  fd_zktpp_ciph_comm_eq_proof_t const * proof,
  uchar const                           source_pubkey         [ static 32 ],
  uchar const                           source_ciphertext     [ static 64 ],
  uchar const                           destination_commitment[ static 32 ],
  fd_zktpp_transcript_t *               transcript ) {
  /*
    We need to verify the 3 following equivalences.
    Instead of verifying them one by one, it's more efficient to pack
    them up in a single MSM (and to do so we have to mul by 1, w, w^2).

    (         z_s P_src =?= c H + Y_0     ) * w^2
    ( z_x G + z_s D_src =?= c C_src + Y_1 ) * w
    (     z_x G + z_r H =?= c C_dst + Y_2 ) * 1

    We store points and scalars in the following arrays:

        points  scalars
    0   G       z_x w + z_x
    1   H       z_r - c w^2
    2   Y_0     -w^2
    3   Y_1     -w
    4   P_src   z_s w^2
    5   C_src   -c w
    6   D_src   z_s w
    7   C_dst   -c
    ----------------------- MSM
        Y_2
  */

  /* Validate all inputs */
  uchar scalars[ 8 * 32 ];
  fd_ristretto255_point_t points[8];
  fd_ristretto255_point_t y2[1];
  fd_ristretto255_point_t res[1];
  fd_ristretto255_point_set( &points[0], fd_zktpp_basepoint_G );
  fd_ristretto255_point_set( &points[1], fd_zktpp_basepoint_H );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], proof->y0 )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], proof->y1 )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y2, proof->y2 )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], source_pubkey )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], source_ciphertext )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[6], &source_ciphertext[32] )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[7], destination_commitment )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zs )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zx )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zr )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  /* Finalize transcript and extract challenges */
  fd_zktpp_transcript_domsep_equality_proof( transcript );
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zktpp_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_0"), proof->y0);
  val |= fd_zktpp_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_1"), proof->y1);
  val |= fd_zktpp_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_2"), proof->y2);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zktpp_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );
  fd_zktpp_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );

  /* Compute scalars */
  fd_curve25519_scalar_neg(    &scalars[ 7*32 ], c );                              // -c
  fd_curve25519_scalar_mul(    &scalars[ 6*32 ], proof->zs, w );                   // z_s w
  fd_curve25519_scalar_mul(    &scalars[ 5*32 ], &scalars[ 7*32 ], w );            // -c w
  fd_curve25519_scalar_mul(    &scalars[ 4*32 ], &scalars[ 6*32 ], w );            // z_s w^2
  fd_curve25519_scalar_neg(    &scalars[ 3*32 ], w );                              // -w
  fd_curve25519_scalar_mul(    &scalars[ 2*32 ], &scalars[ 3*32 ], w );            // -w^2
  fd_curve25519_scalar_muladd( &scalars[ 1*32 ], &scalars[ 5*32 ], w, proof->zr ); // z_r - c w^2
  fd_curve25519_scalar_muladd( &scalars[ 0*32 ], proof->zx, w, proof->zx );        // z_x w + z_x

  /* Compute the final MSM */
  fd_ristretto255_multi_scalar_mul( res, scalars, points, 8 );

  if( FD_LIKELY( fd_ristretto255_point_eq( res, y2 ) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_ZKTPP_VERIFY_PROOF_ERROR;
}

int
fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_ciph_comm_eq_context_t const * context = _context;
  fd_zktpp_ciph_comm_eq_proof_t const *   proof   = _proof;

  FD_LOG_DEBUG(( "fd_zktpp_instr_verify_proof_ciphertext_commitment_equality" ));

  ciph_comm_eq_transcript_init( transcript, context );
  return fd_zktpp_verify_proof_ciphertext_commitment_equality(
    proof,
    context->pubkey,
    context->ciphertext,
    context->commitment,
    transcript
  );
}
