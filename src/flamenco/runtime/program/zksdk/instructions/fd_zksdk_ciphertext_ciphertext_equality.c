#include "../fd_zksdk_private.h"

static inline void
ciphertext_ciphertext_equality_transcript_init( fd_zksdk_transcript_t *                 transcript,
                                                fd_zksdk_ciph_ciph_eq_context_t const * context ) {
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("ciphertext-ciphertext-equality-instruction") );
  fd_zksdk_transcript_append_pubkey    ( transcript, FD_TRANSCRIPT_LITERAL("first-pubkey"),      context->pubkey1 );
  fd_zksdk_transcript_append_pubkey    ( transcript, FD_TRANSCRIPT_LITERAL("second-pubkey"),     context->pubkey2 );
  fd_zksdk_transcript_append_ciphertext( transcript, FD_TRANSCRIPT_LITERAL("first-ciphertext"),  context->ciphertext1 );
  fd_zksdk_transcript_append_ciphertext( transcript, FD_TRANSCRIPT_LITERAL("second-ciphertext"), context->ciphertext2 );
}

/* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/sigma_proofs/ciphertext_ciphertext_equality.rs#L136 */
static inline int
fd_zksdk_verify_proof_ciphertext_ciphertext_equality(
  fd_zksdk_ciph_ciph_eq_proof_t const * proof,
  uchar const                           pubkey1    [ 32 ],
  uchar const                           pubkey2    [ 32 ],
  uchar const                           ciphertext1[ 64 ],
  uchar const                           ciphertext2[ 64 ],
  fd_zksdk_transcript_t *               transcript ) {
  /*
    We store points and scalars in the following arrays:

        points  scalars
    0   G        z_x (w + ww)
    1   H       -c + z_r ww
    2   P1       z_s
    3   D1       z_s w
    4   Y_1     -w
    5   C1      -w c
    6   Y_2     -ww
    7   C2      -ww c
    8   Y_3     -www
    9   D2      -www c
   10   P2       www z_r
   ------------------------ MSM
        Y_0
  */

  /* Validate all inputs */
  uchar scalars[ 11 * 32 ];
  fd_ristretto255_point_t points[11];
  fd_ristretto255_point_t y0[1];
  fd_ristretto255_point_t res[1];

  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zs )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zx )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zr )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  fd_ristretto255_point_set( &points[0], fd_zksdk_basepoint_G );
  fd_ristretto255_point_set( &points[1], fd_zksdk_basepoint_H );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y0, proof->y0 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], pubkey1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], &ciphertext1[32] )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], proof->y1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], ciphertext1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[6], proof->y2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[7], ciphertext2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[8], proof->y3 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[9], &ciphertext2[32] )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[10], pubkey2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* Finalize transcript and extract challenges */
  fd_zksdk_transcript_domsep_ciph_ciph_eq_proof( transcript );
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_0"), proof->y0);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_1"), proof->y1);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_2"), proof->y2);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_3"), proof->y3);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zksdk_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_s"), proof->zs );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_x"), proof->zx );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_r"), proof->zr );

  fd_zksdk_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );

  uchar ww[ 32 ];
  fd_curve25519_scalar_mul( ww, w, w );

  /* Compute scalars */
  fd_curve25519_scalar_add( &scalars[  0*32 ], w, ww );                //  z_x (w + ww)
  fd_curve25519_scalar_mul( &scalars[  0*32 ], &scalars[ 0*32 ], proof->zx );
  fd_curve25519_scalar_mul( &scalars[  1*32 ], proof->zr, ww );        // -c + z_r ww
  fd_curve25519_scalar_sub( &scalars[  1*32 ], &scalars[ 1*32 ], c );
  fd_curve25519_scalar_set( &scalars[  2*32 ], proof->zs );            //  z_s
  fd_curve25519_scalar_mul( &scalars[  3*32 ], &scalars[ 2*32 ], w );  //  z_s w
  fd_curve25519_scalar_neg( &scalars[  4*32 ], w );                    // -w
  fd_curve25519_scalar_mul( &scalars[  5*32 ], &scalars[ 4*32 ], c );  // -w c
  fd_curve25519_scalar_neg( &scalars[  6*32 ], ww );                   // -ww
  fd_curve25519_scalar_mul( &scalars[  7*32 ], &scalars[ 6*32 ], c );  // -ww c
  fd_curve25519_scalar_mul( ww, ww, w );
  fd_curve25519_scalar_neg( &scalars[  8*32 ], ww );                   // -www
  fd_curve25519_scalar_mul( &scalars[  9*32 ], &scalars[ 8*32 ], c );  // -www c
  fd_curve25519_scalar_mul( &scalars[ 10*32 ], proof->zr, ww );        //  www z_r

  /* Compute the final MSM */
  fd_ristretto255_multi_scalar_mul( res, scalars, points, 11 );

  if( FD_LIKELY( fd_ristretto255_point_eq( res, y0 ) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/ciphertext_ciphertext_equality.rs#L105 */
int
fd_zksdk_instr_verify_proof_ciphertext_ciphertext_equality( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_ciph_ciph_eq_context_t const * context = _context;
  fd_zksdk_ciph_ciph_eq_proof_t const *   proof   = _proof;

  ciphertext_ciphertext_equality_transcript_init( transcript, context );
  return fd_zksdk_verify_proof_ciphertext_ciphertext_equality(
    proof,
    context->pubkey1,
    context->pubkey2,
    context->ciphertext1,
    context->ciphertext2,
    transcript
  );
}
