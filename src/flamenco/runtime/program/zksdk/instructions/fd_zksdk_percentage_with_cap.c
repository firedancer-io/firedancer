#include "../fd_zksdk_private.h"

static inline void
percentage_with_cap_transcript_init( fd_zksdk_transcript_t *                        transcript,
                                     fd_zksdk_percentage_with_cap_context_t const * context ) {
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("percentage-with-cap-instruction") );
  fd_zksdk_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("percentage-commitment"), context->percentage_commitment );
  fd_zksdk_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("delta-commitment"), context->delta_commitment );
  fd_zksdk_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("claimed-commitment"), context->claimed_commitment );
  fd_merlin_transcript_append_u64      ( transcript, FD_TRANSCRIPT_LITERAL("max-value"), context->max_value );
}

/* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/sigma_proofs/percentage_with_cap.rs#L339 */
static inline int
fd_zksdk_verify_proof_percentage_with_cap(
  fd_zksdk_percentage_with_cap_proof_t const * proof,
  uchar const                                  percentage_commitment[ 32 ],
  uchar const                                  delta_commitment     [ 32 ],
  uchar const                                  claimed_commitment   [ 32 ],
  ulong const                                  max_value,
  fd_zksdk_transcript_t *                      transcript ) {
  /*
    We store points and scalars in the following arrays:

        points  scalars
    0   G        c_max * m - (w + ww) z_x
    1   H        z_max - (w z_delta + ww z_claimed)
    2   C_max   -c_max
    3   Y_delta  w
    4   C_delta  w c_eq
    5   Y_claim  ww
    6   C_claim  ww c_eq
   ------------------------ MSM
        Y_max
  */

  /* Validate all inputs */
  uchar scalars[ 7 * 32 ];
  fd_ristretto255_point_t points[7];
  fd_ristretto255_point_t y[1];
  fd_ristretto255_point_t res[1];

  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->percentage_max_proof.z_max )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->percentage_max_proof.c_max )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->percentage_equality_proof.z_x )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->percentage_equality_proof.z_delta )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->percentage_equality_proof.z_claimed )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  fd_ristretto255_point_set( &points[0], fd_zksdk_basepoint_G );
  fd_ristretto255_point_set( &points[1], fd_zksdk_basepoint_H );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], percentage_commitment )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], proof->percentage_equality_proof.y_delta )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], delta_commitment )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], proof->percentage_equality_proof.y_claimed )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[6], claimed_commitment )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y, proof->percentage_max_proof.y_max )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* Finalize transcript and extract challenges */
  fd_zksdk_transcript_domsep_percentage_with_cap_proof( transcript );
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_max_proof"), proof->percentage_max_proof.y_max);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_delta"), proof->percentage_equality_proof.y_delta);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_claimed"), proof->percentage_equality_proof.y_claimed);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zksdk_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_max"), proof->percentage_max_proof.z_max );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("c_max_proof"), proof->percentage_max_proof.c_max );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_x"), proof->percentage_equality_proof.z_x );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_delta_real"), proof->percentage_equality_proof.z_delta );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_claimed"), proof->percentage_equality_proof.z_claimed );

  fd_zksdk_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );

  uchar ww[ 32 ];
  fd_curve25519_scalar_mul( ww, w, w );
  uchar m[ 32 ];
  fd_curve25519_scalar_from_u64( m, max_value );

  uchar const * c_max = proof->percentage_max_proof.c_max;
  uchar * c_eq = c;
  fd_curve25519_scalar_sub( c_eq, c, c_max );

  /* Compute scalars */

  // G: c_max * m - (w + ww) z_x
  fd_curve25519_scalar_mul( m, m, c_max );
  fd_curve25519_scalar_add( &scalars[ 0*32 ], w, ww );
  fd_curve25519_scalar_mul( &scalars[ 0*32 ], &scalars[ 0*32 ], proof->percentage_equality_proof.z_x );
  fd_curve25519_scalar_sub( &scalars[ 0*32 ], m, &scalars[ 0*32 ] );

  // H: z_max - (w z_delta + ww z_claimed)
  fd_curve25519_scalar_mul( m, w, proof->percentage_equality_proof.z_delta );
  fd_curve25519_scalar_muladd( &scalars[ 1*32 ], ww, proof->percentage_equality_proof.z_claimed, m );
  fd_curve25519_scalar_sub( &scalars[ 1*32 ], proof->percentage_max_proof.z_max, &scalars[ 1*32 ] );

  // remaining scalars
  fd_curve25519_scalar_neg( &scalars[ 2*32 ], c_max );                  // -c_max
  fd_curve25519_scalar_set( &scalars[ 3*32 ], w );                      //  w
  fd_curve25519_scalar_mul( &scalars[ 4*32 ], &scalars[ 3*32 ], c_eq ); //  w c_eq
  fd_curve25519_scalar_set( &scalars[ 5*32 ], ww );                     //  ww
  fd_curve25519_scalar_mul( &scalars[ 6*32 ], &scalars[ 5*32 ], c_eq ); //  ww c_eq

  /* Compute the final MSM */
  fd_ristretto255_multi_scalar_mul( res, scalars, points, 7 );

  if( FD_LIKELY( fd_ristretto255_point_eq( res, y ) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/percentage_with_cap.rs#L118 */
int
fd_zksdk_instr_verify_proof_percentage_with_cap( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_percentage_with_cap_context_t const * context = _context;
  fd_zksdk_percentage_with_cap_proof_t const *   proof   = _proof;

  percentage_with_cap_transcript_init( transcript, context );
  return fd_zksdk_verify_proof_percentage_with_cap(
    proof,
    context->percentage_commitment,
    context->delta_commitment,
    context->claimed_commitment,
    context->max_value,
    transcript
  );
}
