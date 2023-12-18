#ifndef HEADER_fd_zktpp_batched_grouped_ciphertext_validity_h
#define HEADER_fd_zktpp_batched_grouped_ciphertext_validity_h

typedef struct fd_zktpp_batched_grp_ciph_val_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar zr[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
} fd_zktpp_batched_grp_ciph_val_proof_t;

typedef struct fd_zktpp_batched_grp_ciph_val_context {
  uchar destination_pubkey   [ 32 ]; // point
  uchar auditor_pubkey       [ 32 ]; // point
  uchar grouped_ciphertext_lo[ 96 ]; // 3x points
  uchar grouped_ciphertext_hi[ 96 ]; // 3x points
} fd_zktpp_batched_grp_ciph_val_context_t;

#endif /* HEADER_fd_zktpp_batched_grp_ciph_val_h */
