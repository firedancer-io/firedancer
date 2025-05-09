#include "../fd_zksdk_private.h"

static inline void
zero_ciphertext_transcript_init( fd_zksdk_transcript_t *                    transcript,
                                 fd_zksdk_zero_ciphertext_context_t const * context ) {
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("zero-ciphertext-instruction") );
  fd_zksdk_transcript_append_pubkey    ( transcript, FD_TRANSCRIPT_LITERAL("pubkey"),     context->pubkey );
  fd_zksdk_transcript_append_ciphertext( transcript, FD_TRANSCRIPT_LITERAL("ciphertext"), context->ciphertext );
}

/* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L102 */
static inline int
fd_zksdk_verify_proof_zero_ciphertext(
  fd_zksdk_zero_ciphertext_proof_t const * proof,
  uchar const                              pubkey    [ 32 ],
  uchar const                              ciphertext[ 64 ],
  fd_zksdk_transcript_t *                  transcript ) {
  /*
    We need to verify the 2 following equivalences.
    Instead of verifying them one by one, it's more efficient to pack
    them up in a single MSM (and to do so we have to mul by 1, w).

    (         z P =?= c H + Y_P         ) * 1
    (         z D =?= c C + Y_D         ) * w

    We store points and scalars in the following arrays:

        points  scalars
    0   H       -c
    1   P        z
    2   C       -wc
    3   D        wz
    4   Y_D     -w
    ----------------------- MSM
        Y_P
  */

  /* Validate all inputs */
  uchar scalars[ 5 * 32 ];
  fd_ristretto255_point_t points[5];
  fd_ristretto255_point_t y[1];
  fd_ristretto255_point_t res[1];

  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->z )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  fd_ristretto255_point_set( &points[0], fd_zksdk_basepoint_H );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[1], pubkey )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], &ciphertext[0] )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], &ciphertext[32] )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], proof->yd )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y, proof->yp )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* Finalize transcript and extract challenges */
  fd_zksdk_transcript_domsep_zero_ciphertext_proof( transcript );
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_P"), proof->yp);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  fd_zksdk_transcript_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_D"), proof->yd);

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zksdk_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z"), proof->z );

  fd_zksdk_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );

  /* Compute scalars */
  fd_curve25519_scalar_neg( &scalars[ 0*32 ], c );                   // -c
  fd_curve25519_scalar_set( &scalars[ 1*32 ], proof->z );            //  z
  fd_curve25519_scalar_mul( &scalars[ 2*32 ], &scalars[ 0*32 ], w ); // -wc
  fd_curve25519_scalar_mul( &scalars[ 3*32 ], w, proof->z );         //  wz
  fd_curve25519_scalar_neg( &scalars[ 4*32 ], w );                   // -w

  /* Compute the final MSM */
  fd_ristretto255_multi_scalar_mul( res, scalars, points, 5 );

  if( FD_LIKELY( fd_ristretto255_point_eq( res, y ) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/zero_ciphertext.rs#L81 */
int
fd_zksdk_instr_verify_proof_zero_ciphertext( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_zero_ciphertext_context_t const * context = _context;
  fd_zksdk_zero_ciphertext_proof_t const *   proof   = _proof;

  zero_ciphertext_transcript_init( transcript, context );
  return fd_zksdk_verify_proof_zero_ciphertext(
    proof,
    context->pubkey,
    context->ciphertext,
    transcript
  );
}
