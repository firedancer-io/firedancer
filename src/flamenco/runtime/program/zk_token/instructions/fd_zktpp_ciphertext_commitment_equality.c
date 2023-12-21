#include "../fd_zktpp_private.h"
#include "../encryption/fd_zktpp_encryption.h"
#include "../../../../../ballet/ed25519/fd_ristretto255_ge.h"
#include <stdio.h>

static void
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
    0   Y_0     -w^2
    1   Y_1     -w
    2   P_src   z_s w^2
    3   C_src   -c w
    4   D_src   z_s w
    5   C_dst   -c
    6   G       z_x w + z_x
    7   H       z_r - c w^2
    ----------------------- MSM
        Y_2
  */

  /* Validate all inputs */
  fd_ristretto255_point_t points[8];
  fd_ristretto255_point_t y2[1];
  fd_ristretto255_point_t res[1];
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[0], proof->y0 )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  //TODO check that neither y0, y1, y2 is identity
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[1], proof->y1 )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y2, proof->y2 )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], source_pubkey )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], source_ciphertext )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], &source_ciphertext[32] )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], destination_commitment )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  fd_memcpy( &points[6], fd_zktpp_basepoint_G, sizeof(fd_ristretto255_point_t) );
  fd_memcpy( &points[7], fd_zktpp_basepoint_H, sizeof(fd_ristretto255_point_t) );

  uchar scalars[ 8 * 32 ];
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( proof->zs )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( proof->zx )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( proof->zr )==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  /* Finalize transcript and extract challenges */
  fd_zktpp_transcript_domsep_equality_proof( transcript );
  fd_zktpp_transcript_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_0"), proof->y0 );
  fd_zktpp_transcript_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_1"), proof->y1 );
  fd_zktpp_transcript_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_2"), proof->y2 );

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zktpp_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );
  // printf("c = "); for (ulong i=0; i<32; i++) { printf("%02x ", c[i]); } printf("\n");
  fd_zktpp_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );
  // printf("w = "); for (ulong i=0; i<32; i++) { printf("%02x ", w[i]); } printf("\n");

  /* Compute scalars */
  fd_ed25519_sc_muladd( &scalars[ 6*32 ], proof->zx, w, proof->zx );   // z_x w + z_x
  fd_ed25519_sc_neg(    &scalars[ 5*32 ], c );                         // -c
  fd_ed25519_sc_mul(    &scalars[ 4*32 ], proof->zs, w );              // z_s w
  fd_ed25519_sc_mul(    &scalars[ 3*32 ], &scalars[ 5*32 ], w );            // -c w
  fd_ed25519_sc_mul(    &scalars[ 2*32 ], &scalars[ 4*32 ], w );            // z_s w^2
  fd_ed25519_sc_neg(    &scalars[ 1*32 ], w );                         // -w
  fd_ed25519_sc_mul(    &scalars[ 0*32 ], &scalars[ 1*32 ], w );            // -w^2
  fd_ed25519_sc_muladd( &scalars[ 7*32 ], &scalars[ 3*32 ], w, proof->zr ); // z_r - c w^2

  /* Compute the final MSM */
  fd_ristretto255_multiscalar_mul( res, scalars, points, 8 );
  if( FD_UNLIKELY( fd_ristretto255_point_eq( res, y2 )==0 ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_zktpp_instr_verify_proof_ciphertext_commitment_equality( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_ciph_comm_eq_context_t const * context = _context;
  fd_zktpp_ciph_comm_eq_proof_t const *   proof   = _proof;

  ciph_comm_eq_transcript_init( transcript, context );
  return fd_zktpp_verify_proof_ciphertext_commitment_equality(
    proof,
    context->pubkey,
    context->ciphertext,
    context->commitment,
    transcript
  );
}
