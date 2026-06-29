#include "../fd_zksdk_private.h"

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L128 */
static inline void
pubkey_validity_hash_context( fd_zksdk_transcript_t * transcript,
                              uchar const             pubkey[ 32 ] ) {
  fd_zksdk_transcript_append_pubkey( transcript, FD_TRANSCRIPT_LITERAL("pubkey"), pubkey );
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L91 */
static inline int
fd_zksdk_verify_proof_pubkey_validity(
  fd_zksdk_pubkey_validity_proof_t const * proof,
  uchar const                              pubkey[ 32 ],
  fd_zksdk_transcript_t *                  transcript ) {
  /*
    We need to verify the following equivalence:
        z H =?= c P + Y
    or:
        Y =?= z H - c P
  */

  /* Validate all inputs */
  uchar scalars[ 2 * 32 ];
  fd_ristretto255_point_t points[2];
  fd_ristretto255_point_t y[1];
  fd_ristretto255_point_t res[1];

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L96-L97 */
  pubkey_validity_hash_context( transcript, pubkey );
  fd_zksdk_transcript_domsep_pubkey_proof( transcript );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L102-L104 */
  if( FD_UNLIKELY( fd_memeq( pubkey, fd_ristretto255_compressed_zero, 32 ) ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* Validate scalar and decompress all points.
     Note: Agave does this in various places, but any failure simply results in an invalid proof. */
  if( FD_UNLIKELY( fd_curve25519_scalar_validate( proof->z )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  fd_ristretto255_point_set( &points[0], fd_zksdk_basepoint_H );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[1], pubkey )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y, proof->y )==NULL ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  /* Finalize transcript and extract challenges
     https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L107-L108 */
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zksdk_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y"), proof->y);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKSDK_VERIFY_PROOF_ERROR;
  }

  uchar c[ 32 ];
  fd_zksdk_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L111-L119
     Note: we use a slightly different MSM but they're equivalent. */

  /* Compute scalars */
  fd_curve25519_scalar_set( &scalars[ 0*32 ], proof->z ); //  z
  fd_curve25519_scalar_neg( &scalars[ 1*32 ], c );        // -c

  /* Compute the final MSM */
  fd_ristretto255_multi_scalar_mul( res, scalars, points, 2 );

  /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L121-L125 */
  if( FD_LIKELY( fd_ristretto255_point_eq( res, y ) ) ) {
    return FD_ZKSDK_VERIFY_PROOF_SUCCESS;
  }
  return FD_ZKSDK_VERIFY_PROOF_ERROR;
}

/* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/proof_data/pubkey_validity.rs#L73 */
int
fd_zksdk_instr_verify_proof_pubkey_validity( void const * _context, void const * _proof ) {
  fd_zksdk_transcript_t transcript[1];
  fd_zksdk_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("pubkey-validity-instruction") );

  fd_zksdk_pubkey_validity_context_t const * context = _context;
  fd_zksdk_pubkey_validity_proof_t const *   proof   = _proof;
  return fd_zksdk_verify_proof_pubkey_validity(
    proof,
    context->pubkey,
    transcript
  );
}
