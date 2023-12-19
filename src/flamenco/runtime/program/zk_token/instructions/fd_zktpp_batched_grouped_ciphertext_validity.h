#ifndef HEADER_fd_zktpp_batched_grouped_ciphertext_validity_h
#define HEADER_fd_zktpp_batched_grouped_ciphertext_validity_h

typedef struct fd_zktpp_batched_grp_ciph_val_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar zr[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
} fd_zktpp_batched_grp_ciph_val_proof_t;

typedef struct fd_zktpp_grouped_ciphertext_dst_aud {
  uchar commitment         [ 32 ]; // point
  uchar destination_handle [ 32 ]; // point
  uchar auditor_handle     [ 32 ]; // points
} fd_zktpp_grouped_ciphertext_dst_aud_t;

typedef struct fd_zktpp_batched_grp_ciph_val_context {
  uchar destination_pubkey [ 32 ]; // point
  uchar auditor_pubkey     [ 32 ]; // point
  fd_zktpp_grouped_ciphertext_dst_aud_t grouped_ciphertext_lo; // 3x points
  fd_zktpp_grouped_ciphertext_dst_aud_t grouped_ciphertext_hi; // 3x points
} fd_zktpp_batched_grp_ciph_val_context_t;

int
fd_zktpp_verify_proof_batched_grouped_ciphertext_validity(
  fd_zktpp_batched_grp_ciph_val_proof_t const * proof,
  uchar const                                   dst_pubkey    [ static 32 ],
  uchar const                                   aud_pubkey    [ static 32 ],
  uchar const                                   comm_lo       [ static 32 ],
  uchar const                                   comm_hi       [ static 32 ],
  uchar const                                   dst_handle_lo [ static 32 ],
  uchar const                                   dst_handle_hi [ static 32 ],
  uchar const                                   aud_handle_lo [ static 32 ],
  uchar const                                   aud_handle_hi [ static 32 ],
  fd_zktpp_transcript_t *                       transcript );

#endif /* HEADER_fd_zktpp_batched_grp_ciph_val_h */
