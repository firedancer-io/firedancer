#include "../fd_zktpp_private.h"
#include "../encryption/fd_zktpp_encryption.h"

static void
batched_grouped_ciphertext_validity_transcript_init(
  fd_zktpp_transcript_t *                         transcript,
  fd_zktpp_batched_grp_ciph_val_context_t const * context ) {
  fd_zktpp_transcript_init( transcript, FD_TRANSCRIPT_LITERAL("BatchedGroupedCiphertextValidityProof") );
  fd_zktpp_transcript_append_pubkey( transcript, FD_TRANSCRIPT_LITERAL("destination-pubkey"), context->destination_pubkey );
  fd_zktpp_transcript_append_pubkey( transcript, FD_TRANSCRIPT_LITERAL("auditor-pubkey"), context->auditor_pubkey );
  fd_zktpp_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-lo"), (uchar *)&context->grouped_ciphertext_lo, sizeof(fd_zktpp_grouped_ciphertext_dst_aud_t) );
  fd_zktpp_transcript_append_message( transcript, FD_TRANSCRIPT_LITERAL("grouped-ciphertext-hi"), (uchar *)&context->grouped_ciphertext_hi, sizeof(fd_zktpp_grouped_ciphertext_dst_aud_t) );
}

int
fd_zktpp_verify_proof_batched_grouped_ciphertext_validity(
  fd_zktpp_batched_grp_ciph_val_proof_t const * proof,
  uchar const                                   dst_pubkey    [ static 32 ],
  uchar const                                   aud_pubkey    [ static 32 ],
  uchar const                                   comm          [ static 32 ],
  uchar const                                   dst_handle    [ static 32 ],
  uchar const                                   aud_handle    [ static 32 ],
  uchar const                                   comm_hi       [ static 32 ],
  uchar const                                   dst_handle_hi [ static 32 ],
  uchar const                                   aud_handle_hi [ static 32 ],
  bool const                                    batched,
  fd_zktpp_transcript_t *                       transcript ) {

  /*
    We need to verify the 3 following equivalences.
    Instead of verifying them one by one, it's more efficient to pack
    them up in a single MSM (and to do so we have to mul by 1, w, w^2).

    ( z_r H + z_x G =?= c C + Y_0 ) * 1
    (     z_r D_pub =?= c D + Y_1 ) * w
    (     z_r A_pub =?= c A + Y_2 ) * w^2

    When batched==false, C, D, A are given and C_hi, D_hi, A_hi are NULL.
    When batched==true, they are computed as C = C_lo + t C_hi.

    When aud_pubkey is 0 (no auditor), so should be all aud_handle and aud_handle_hi.

    Because of batched and auditor, the length of the MSM varies between 6 and 12.
    Points/scalars from 7 to 12 are only computed when required.

    We store points and scalars in the following arrays:

         points  scalars
     0   G       z_x
     1   H       z_r
     2   Y_1     -w
     3   Y_2     -w^2
     4   D_pub   z_r w
     5   C       -c
     6   D       -c w
     7   C_hi    -c t      (if batched)
     8   D_hi    -c w t    (if batched)
     9   A_pub   z_r w^2   (if auditor)
    10   A       -c w^2    (if auditor)
    11   A_hi    -c w^2 t  (if batched && auditor)
    ----------------------- MSM
         Y_0
  */

  /* Auditor extra check: if auditor pubkey is 0, then aud_handle,
     aud_handle_hi (when set) and proof->y2 must all be 0. */
  bool auditor = true;
  if ( fd_memeq( aud_pubkey, fd_ristretto255_compressed_zero, 32 ) ) {
    auditor = false;
    if (
      !fd_memeq( aud_handle, fd_ristretto255_compressed_zero, 32 )
      || !fd_memeq( proof->y2, fd_ristretto255_compressed_zero, 32 )
      || ( batched && !fd_memeq( aud_pubkey, fd_ristretto255_compressed_zero, 32 ) )
    ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
  }

  /* Validate all inputs */
  fd_ristretto255_point_t points[12];
  fd_ristretto255_point_t y0[1];
  fd_ristretto255_point_t res[1];
  fd_memcpy( &points[0], fd_zktpp_basepoint_G, sizeof(fd_ristretto255_point_t) );
  fd_memcpy( &points[1], fd_zktpp_basepoint_H, sizeof(fd_ristretto255_point_t) );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( y0, proof->y0 )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], proof->y1 )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], proof->y2 )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], dst_pubkey )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[5], comm )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[6], dst_handle )==NULL ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  ulong idx = 7;
  if (batched) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], comm_hi )==NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], dst_handle_hi )==NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
    idx += 2;
  } else {
    if( FD_UNLIKELY( comm_hi!=NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( dst_handle_hi!=NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( aud_handle_hi!=NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
  }

  if (auditor) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], aud_pubkey )==NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], aud_handle )==NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
  }

  if (batched && auditor) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[idx++], aud_handle_hi )==NULL ) ) {
      return FD_ZKTPP_VERIFY_PROOF_ERROR;
    }
  }

  uchar scalars[ 12 * 32 ];

  /* Finalize transcript and extract challenges */
  uchar t[ 32 ];
  if (batched) {
    fd_zktpp_transcript_domsep_batched_grp_ciph_val_proof( transcript );
    fd_zktpp_transcript_challenge_scalar( t, transcript, FD_TRANSCRIPT_LITERAL("t") );
  }

  fd_zktpp_transcript_domsep_grp_ciph_val_proof( transcript );
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_zktpp_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_0"), proof->y0);
  val |= fd_zktpp_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_1"), proof->y1);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }
  /* Y_2 can be an all zero point if the auditor public key is all zero */
  fd_zktpp_transcript_append_point( transcript, FD_TRANSCRIPT_LITERAL("Y_2"), proof->y2);

  uchar c[ 32 ];
  uchar w[ 32 ];
  fd_zktpp_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );
  fd_zktpp_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );

  /* Compute scalars */
  fd_memcpy( &scalars[ 0*32 ], proof->zx, 32 );                          // z_x
  fd_memcpy( &scalars[ 1*32 ], proof->zr, 32 );                          // z_r
  fd_ed25519_sc_neg( &scalars[ 2*32 ], w );                              // -w
  fd_ed25519_sc_mul( &scalars[ 3*32 ], &scalars[ 2*32 ], w );            // -w^2
  fd_ed25519_sc_mul( &scalars[ 4*32 ], proof->zr, w );                   // z_r w
  fd_ed25519_sc_neg( &scalars[ 5*32 ], c );                              // -c
  fd_ed25519_sc_mul( &scalars[ 6*32 ], &scalars[ 5*32 ], w );            // -c w
  idx = 7;
  if (batched) {
    fd_ed25519_sc_mul( &scalars[ (idx++)*32 ], &scalars[ 5*32 ], t );    // -c t
    fd_ed25519_sc_mul( &scalars[ (idx++)*32 ], &scalars[ 6*32 ], t );    // -c w t
  }
  if (auditor) {
    fd_ed25519_sc_mul( &scalars[ (idx++)*32 ], &scalars[ 4*32 ], w );    // z_r w^2
    fd_ed25519_sc_mul( &scalars[ (idx++)*32 ], &scalars[ 6*32 ], w );    // -c w^2
  }
  if (batched && auditor) {
    ulong last = idx - 1;
    fd_ed25519_sc_mul( &scalars[ (idx++)*32 ], &scalars[ last*32 ], w ); // -c w^2 t
  }

  /* Compute the final MSM */
  fd_ristretto255_multiscalar_mul( res, scalars, points, idx );
  if( FD_UNLIKELY( fd_ristretto255_point_eq( res, y0 )==0 ) ) {
    return FD_ZKTPP_VERIFY_PROOF_ERROR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_zktpp_instr_verify_proof_batched_grouped_ciphertext_validity( void const * _context, void const * _proof ) {
  fd_zktpp_transcript_t transcript[1];
  fd_zktpp_batched_grp_ciph_val_context_t const * context = _context;
  fd_zktpp_batched_grp_ciph_val_proof_t const *   proof   = _proof;

  batched_grouped_ciphertext_validity_transcript_init( transcript, context );
  return fd_zktpp_verify_proof_batched_grouped_ciphertext_validity(
    proof,
    context->destination_pubkey,
    context->auditor_pubkey,
    context->grouped_ciphertext_lo.commitment,
    context->grouped_ciphertext_lo.destination_handle,
    context->grouped_ciphertext_lo.auditor_handle,
    context->grouped_ciphertext_hi.commitment,
    context->grouped_ciphertext_hi.destination_handle,
    context->grouped_ciphertext_hi.auditor_handle,
    true,
    transcript
  );
}
