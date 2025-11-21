#include "../fd_zksdk_private.h"

static inline void
batched_grouped_ciphertext_validity_transcript_init(
  fd_zksdk_transcript_t *                            transcript,
  fd_zksdk_batched_grp_ciph_2h_val_context_t const * context ) {
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("batched-grouped-ciphertext-validity-2-handles-instruction") );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("first-pubkey"),  context->pubkey1 );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("second-pubkey"), context->pubkey2 );
  fd_zksdk_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-lo"), (uchar *)&context->grouped_ciphertext_lo, sizeof(grp_ciph_2h_t) );
  fd_zksdk_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-hi"), (uchar *)&context->grouped_ciphertext_hi, sizeof(grp_ciph_2h_t) );
}

int
fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity(
  fd_zksdk_grp_ciph_2h_val_proof_t const * proof,
  uchar const                              pubkey1    [ 32 ],
  uchar const                              pubkey2    [ 32 ],
  uchar const                              comm       [ 32 ],
  uchar const                              handle1    [ 32 ],
  uchar const                              handle2    [ 32 ],
  uchar const                              comm_hi    [ 32 ],
  uchar const                              handle1_hi [ 32 ],
  uchar const                              handle2_hi [ 32 ],
  int   const                              batched,
  fd_zksdk_transcript_t *                  transcript ) {
  /*
    We need to verify the 3 following equivalences.
    Instead of verifying them one by one, it's more efficient to pack
    them up in a single MSM (and to do so we have to mul by 1, w, w^2).

    ( z_r H + z_x G =?= c C + Y_0 ) * 1
    (      z_r pub1 =?= c h1 + Y_1 ) * w
    (      z_r pub2 =?= c h2 + Y_2 ) * w^2

    When batched==false, C, h1, h2 are given and C_hi, h1_hi, h2_hi are NULL.
    When batched==true, they are computed as C = C_lo + t C_hi.

    When pubkey2 is 0, also proof->y2, handle2 and handle2_hi should be 0.

    Because of batched and pubkey2_not_zero, the length of the MSM varies
    between 6 and 12.
    Points/scalars from 7 to 12 are only computed when required.

    We store points and scalars in the following arrays:

         points  scalars
     0   G       z_x
     1   H       z_r
     2   Y_1     -w
     3   Y_2     -w^2
     4   pub1    z_r w
     5   C       -c
     6   h1      -c w
     7   C_hi    -c t      (if batched)
     8   h1_hi   -c w t    (if batched)
     9   pub2    z_r w^2   (if pubkey2_not_zero)
    10   h2      -c w^2    (if pubkey2_not_zero)
    11   h2_hi   -c w^2 t  (if batched && pubkey2_not_zero)
    ----------------------- MSM
         Y_0
  */

  /* pubkey2 extra check: if pubkey2 is 0, then handle2,
     handle2_hi (when set) and proof->y2 must all be 0. */
  int pubkey2_not_zero = 1;
  if ( fd_memeq( pubkey2, fd_ristretto255_compressed_zero, 32 ) ) {
    pubkey2_not_zero = 0;
    if (
      !fd_memeq( handle2, fd_ristretto255_compressed_zero, 32 )
      || !fd_memeq( proof->y2, fd_ristretto255_compressed_zero, 32 )
      || ( batched && !fd_memeq( handle2_hi, fd_ristretto255_compressed_zero, 32 ) )
    ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
  }

  /* Validate all inputs */
  uchar scalars[ 12 * 32 ];
  fd_ristretto255_point_t points[12];
  fd_ristretto255_point_t y0[1];
  fd_ristretto255_point_t res[1];

  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zr )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->zx )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  fd_ristretto255_point_set( &points[0], fd_zksdk_basepoint_G );
  fd_ristretto255_point_set( &points[1], fd_zksdk_basepoint_H );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y0, proof->y0 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], proof->y1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], proof->y2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], pubkey1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], comm )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[6], handle1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  ulong idx = 7;
  if( batched ) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], comm_hi )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], handle1_hi )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
  }

  if( pubkey2_not_zero ) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], pubkey2 )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], handle2 )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
  }

  if( batched && pubkey2_not_zero ) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], handle2_hi )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
  }

  /* Finalize transcript and extract challenges */
  uchar t[ 32 ];
  if( batched ) {
    fd_zksdk_transcript_domsep_batched_grp_ciph_val_proof( transcript, 2 );
    fd_zksdk_transcript_challenge_scalar( t, transcript, FD_TRANSCRIPT_LITERAL("t") );
  }

  fd_zksdk_transcript_domsep_grp_ciph_val_proof( transcript, 2 );
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_0"), proof->y0);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_1"), proof->y1);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  /* Y_2 can be an all zero point if the pubkey2 is all zero */
  fd_zksdk_transcript_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_2"), proof->y2);

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zksdk_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_x"), proof->zx );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_r"), proof->zr );

  fd_zksdk_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );

  /* Compute scalars */
  fd_curve25519_scalar_set( &scalars[ 0*32 ], proof->zx );           //  z_x
  fd_curve25519_scalar_set( &scalars[ 1*32 ], proof->zr );           //  z_r
  fd_curve25519_scalar_neg( &scalars[ 2*32 ], w );                   // -w
  fd_curve25519_scalar_mul( &scalars[ 3*32 ], &scalars[ 2*32 ], w ); // -w^2
  fd_curve25519_scalar_mul( &scalars[ 4*32 ], proof->zr, w );        //  z_r w
  fd_curve25519_scalar_neg( &scalars[ 5*32 ], c );                   // -c
  fd_curve25519_scalar_mul( &scalars[ 6*32 ], &scalars[ 5*32 ], w ); // -c w
  idx = 7;
  if( batched ) {
    fd_curve25519_scalar_mul( &scalars[ (idx++)*32 ], &scalars[ 5*32 ], t ); // -c t
    fd_curve25519_scalar_mul( &scalars[ (idx++)*32 ], &scalars[ 6*32 ], t ); // -c w t
  }
  if( pubkey2_not_zero ) {
    fd_curve25519_scalar_mul( &scalars[ (idx++)*32 ], &scalars[ 4*32 ], w ); // z_r w^2
    fd_curve25519_scalar_mul( &scalars[ (idx++)*32 ], &scalars[ 6*32 ], w ); // -c w^2
  }
  if( batched && pubkey2_not_zero ) {
    fd_curve25519_scalar_mul( &scalars[ (idx++)*32 ], &scalars[ 8*32 ], w ); // -c w^2 t
  }

  /* Compute the final MSM */
  fd_ristretto255_multi_scalar_mul( res, scalars, points, idx );

  if( FD_LIKELY( fd_ristretto255_point_eq( res, y0 ) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

int
fd_zksdk_instr_verify_proof_batched_grouped_ciphertext_2_handles_validity( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_batched_grp_ciph_2h_val_context_t const * context = _context;
  fd_zksdk_batched_grp_ciph_2h_val_proof_t const *   proof   = _proof;

  batched_grouped_ciphertext_validity_transcript_init( transcript, context );
  return fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity(
    proof,
    context->pubkey1,
    context->pubkey2,
    context->grouped_ciphertext_lo.commitment,
    context->grouped_ciphertext_lo.handles[0].handle,
    context->grouped_ciphertext_lo.handles[1].handle,
    context->grouped_ciphertext_hi.commitment,
    context->grouped_ciphertext_hi.handles[0].handle,
    context->grouped_ciphertext_hi.handles[1].handle,
    1,
    transcript
  );
}
