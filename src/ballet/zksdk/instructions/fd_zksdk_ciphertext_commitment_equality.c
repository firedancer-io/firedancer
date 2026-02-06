#include "../fd_zksdk_private.h"

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L229 */
static inline void
ciph_comm_eq_hash_context( fd_zksdk_transcript_t * transcript,
                           uchar const             pubkey    [ 32 ],
                           uchar const             ciphertext[ 64 ],
                           uchar const             commitment[ 32 ] ) {
  fd_zksdk_transcript_append_pubkey    ( transcript, FD_TRANSCRIPT_LITERAL("pubkey"),     pubkey );
  fd_zksdk_transcript_append_ciphertext( transcript, FD_TRANSCRIPT_LITERAL("ciphertext"), ciphertext );
  fd_zksdk_transcript_append_commitment( transcript, FD_TRANSCRIPT_LITERAL("commitment"), commitment );
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L139 */
int
fd_zksdk_verify_proof_ciphertext_commitment_equality(
  fd_zksdk_ciph_comm_eq_proof_t const * proof,
  uchar const                           pubkey     [ 32 ],
  uchar const                           ciphertext [ 64 ],
  uchar const                           commitment [ 32 ],
  fd_zksdk_transcript_t *               transcript ) {
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

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L146-L152 */
  if( FD_UNLIKELY( fd_memeq( pubkey,          fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( &ciphertext[0],  fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( &ciphertext[32], fd_ristretto255_compressed_zero, 32 )
                || fd_memeq( commitment,      fd_ristretto255_compressed_zero, 32 ) ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

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
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], proof->y0 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], proof->y1 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y2, proof->y2 )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], pubkey )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], ciphertext )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[6], &ciphertext[32] )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[7], commitment )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* Finalize transcript and extract challenges */

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L154-L155 */
  ciph_comm_eq_hash_context( transcript, pubkey, ciphertext, commitment );
  fd_zksdk_transcript_domsep_ciph_comm_eq_proof( transcript );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L158-L173 */
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_0"), proof->y0);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_1"), proof->y1);
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_2"), proof->y2);
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

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L174-L220
     Note: we use a slightly different MSM but they're equivalent. */

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

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L222-L226 */
  if( FD_LIKELY( fd_ristretto255_point_eq( res, y2 ) ) ) {
    return FD_ZKSDK_VERIFY_PROOF_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

int
fd_zksdk_instr_verify_proof_ciphertext_commitment_equality( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("ciphertext-commitment-equality-instruction") );

  fd_zksdk_ciph_comm_eq_context_t const * context = _context;
  fd_zksdk_ciph_comm_eq_proof_t const *   proof   = _proof;
  return fd_zksdk_verify_proof_ciphertext_commitment_equality(
    proof,
    context->pubkey,
    context->ciphertext,
    context->commitment,
    transcript
  );
}
