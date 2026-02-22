#include "../fd_zksdk_private.h"

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L299 */
static inline void
grouped_ciphertext_validity_hash_context(
  fd_zksdk_transcript_t * transcript,
  uchar const             pubkey1 [ 32 ],
  uchar const             pubkey2 [ 32 ],
  uchar const             pubkey3 [ 32 ],
  grp_ciph_3h_t const *   grouped_ciphertext ) {
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("first-pubkey"),  pubkey1 );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("second-pubkey"), pubkey2 );
  fd_zksdk_transcript_append_pubkey ( transcript, FD_TRANSCRIPT_LITERAL("third-pubkey"),  pubkey3 );
  fd_zksdk_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext"), (uchar *)grouped_ciphertext, sizeof(grp_ciph_3h_t) );
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L163 */
static inline int
fd_zksdk_verify_proof_grouped_ciphertext_3_handles_validity(
  fd_zksdk_grp_ciph_3h_val_proof_t const * proof,
  uchar const                              pubkey1    [ 32 ],
  uchar const                              pubkey2    [ 32 ],
  uchar const                              pubkey3    [ 32 ],
  grp_ciph_3h_t const *                    grouped_ciphertext,
  fd_zksdk_transcript_t *                  transcript ) {

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L174-L179 */
  if( FD_UNLIKELY( fd_memeq( pubkey1,                        fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( pubkey2,                        fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( grouped_ciphertext->commitment, fd_ristretto255_compressed_zero, 32 ) ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L181-187 */
  grouped_ciphertext_validity_hash_context( transcript, pubkey1, pubkey2, pubkey3, grouped_ciphertext );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L188-194 */
  return fd_zksdk_verify_proof_direct_grouped_ciphertext_3_handles_validity(
    proof,
    pubkey1,
    pubkey2,
    pubkey3,
    grouped_ciphertext->commitment,
    grouped_ciphertext->handles[0].handle,
    grouped_ciphertext->handles[1].handle,
    grouped_ciphertext->handles[2].handle,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0,
    transcript
  );
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L198 */
int
fd_zksdk_verify_proof_direct_grouped_ciphertext_3_handles_validity(
  fd_zksdk_grp_ciph_3h_val_proof_t const * proof,
  uchar const                              pubkey1    [ 32 ],
  uchar const                              pubkey2    [ 32 ],
  uchar const                              pubkey3    [ 32 ],
  uchar const                              comm       [ 32 ],
  uchar const                              handle1    [ 32 ],
  uchar const                              handle2    [ 32 ],
  uchar const                              handle3    [ 32 ],
  uchar const                              comm_hi    [ 32 ],
  uchar const                              handle1_hi [ 32 ],
  uchar const                              handle2_hi [ 32 ],
  uchar const                              handle3_hi [ 32 ],
  uchar const                              challenge_t[ 32 ],
  int   const                              batched,
  fd_zksdk_transcript_t *                  transcript ) {
  /*
    When batched==false, C, h1, h2 are given and C_hi, h1_hi, h2_hi, h3_hi are NULL.
    When batched==true, they are computed as C = C_lo + t C_hi.

    We store points and scalars in the following arrays:

         points  scalars
     0   G        z_x
     1   H        z_r
     2   C       -c
     3   pub1     w z_r
     4   Y_1     -w
     5   h1      -w c
     6   pub2     ww z_r
     7   Y_2     -ww
     8   h2      -ww c
     9   pub3     www z_r
    10   Y_3     -www
    11   h3      -www c
    12   C_hi    -c t      (if batched)
    13   h1_hi   -c w t    (if batched)
    14   h2_hi   -c ww t   (if batched)
    15   h3_hi   -c www t  (if batched)
    ----------------------- MSM
         Y_0
  */

  /* Validate all inputs */
  uchar scalars[ 16 * 32 ];
  fd_ristretto255_point_t points[16];
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
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], comm )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], pubkey1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], proof->y1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], handle1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[6], pubkey2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[7], proof->y2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[8], handle2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[9], pubkey3 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[10], proof->y3 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[11], handle3 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  if (batched) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[12], comm_hi )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[13], handle1_hi )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[14], handle2_hi )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[15], handle3_hi )==NULL ) ) {
      return FD_ZKSDK_VERIFY_PROOF_ERROR;
    }
  }

  /* Finalize transcript and extract challenges */

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L206 */
  fd_zksdk_transcript_domsep_grp_ciph_val_proof( transcript, 3 );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L208-L220 */
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_0"), proof->y0);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_1"), proof->y1);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_2"), proof->y2);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  /* Y_3 can be zero */
  fd_zksdk_transcript_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_3"), proof->y3);

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zksdk_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_x"), proof->zx );
  fd_zksdk_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("z_r"), proof->zr );

  fd_zksdk_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L221-L290
     Note: we use a slightly different MSM but they're equivalent. */

  /* Compute scalars */
  fd_curve25519_scalar_set( &scalars[  0*32 ], proof->zx );              //  z_x
  fd_curve25519_scalar_set( &scalars[  1*32 ], proof->zr );              //  z_r
  fd_curve25519_scalar_neg( &scalars[  2*32 ], c );                      // -c
  fd_curve25519_scalar_mul( &scalars[  3*32 ], proof->zr, w );           //  w z_r
  fd_curve25519_scalar_neg( &scalars[  4*32 ], w );                      // -w
  fd_curve25519_scalar_mul( &scalars[  5*32 ], &scalars[ 2*32 ], w );    // -w c
  fd_curve25519_scalar_mul( &scalars[  6*32 ], &scalars[ 3*32 ], w );    //  ww z_r
  fd_curve25519_scalar_mul( &scalars[  7*32 ], &scalars[ 4*32 ], w );    // -ww
  fd_curve25519_scalar_mul( &scalars[  8*32 ], &scalars[ 5*32 ], w );    // -ww c
  fd_curve25519_scalar_mul( &scalars[  9*32 ], &scalars[ 6*32 ], w );    //  www z_r
  fd_curve25519_scalar_mul( &scalars[ 10*32 ], &scalars[ 7*32 ], w );    // -www
  fd_curve25519_scalar_mul( &scalars[ 11*32 ], &scalars[ 8*32 ], w );    // -www c
  if( batched ) {
    fd_curve25519_scalar_mul( &scalars[ 12*32 ], &scalars[  2*32 ], challenge_t ); // -c t
    fd_curve25519_scalar_mul( &scalars[ 13*32 ], &scalars[  5*32 ], challenge_t ); // -c w t
    fd_curve25519_scalar_mul( &scalars[ 14*32 ], &scalars[  8*32 ], challenge_t ); // -c ww t
    fd_curve25519_scalar_mul( &scalars[ 15*32 ], &scalars[ 11*32 ], challenge_t ); // -c www t
  }

  /* Compute the final MSM */
  fd_ristretto255_multi_scalar_mul( res, scalars, points, batched ? 16 : 12 );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L292-L296 */
  if( FD_LIKELY( fd_ristretto255_point_eq( res, y0 ) ) ) {
    return FD_ZKSDK_VERIFY_PROOF_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/grouped_ciphertext_validity/handles_3.rs#L118 */
int
fd_zksdk_instr_verify_proof_grouped_ciphertext_3_handles_validity( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-validity-3-handles-instruction") );

  fd_zksdk_grp_ciph_3h_val_context_t const * context = _context;
  fd_zksdk_grp_ciph_3h_val_proof_t const *   proof   = _proof;
  return fd_zksdk_verify_proof_grouped_ciphertext_3_handles_validity(
    proof,
    context->pubkey1,
    context->pubkey2,
    context->pubkey3,
    context->grouped_ciphertext,
    transcript
  );
}
