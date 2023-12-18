#ifndef HEADER_fd_zktpp_range_proofs_h
#define HEADER_fd_zktpp_range_proofs_h

typedef struct fd_zktpp_range_proof_u64_proof {
  uchar a           [ 32 ]; // point
  uchar s           [ 32 ]; // point
  uchar t1          [ 32 ]; // point
  uchar t2          [ 32 ]; // point
  uchar tx          [ 32 ]; // scalar
  uchar t_x_blinding[ 32 ]; // scalar
  uchar e_blinding  [ 32 ]; // scalar
  uchar ipp_proof  [ 448 ];
} fd_zktpp_range_proof_u64_proof_t;

typedef struct fd_zktpp_range_proof_u128_proof {
  uchar a           [ 32 ]; // point
  uchar s           [ 32 ]; // point
  uchar t1          [ 32 ]; // point
  uchar t2          [ 32 ]; // point
  uchar tx          [ 32 ]; // scalar
  uchar t_x_blinding[ 32 ]; // scalar
  uchar e_blinding  [ 32 ]; // scalar
  uchar ipp_proof  [ 512 ];
} fd_zktpp_range_proof_u128_proof_t;

typedef struct fd_zktpp_range_proof_u256_proof {
  uchar a           [ 32 ]; // point
  uchar s           [ 32 ]; // point
  uchar t1          [ 32 ]; // point
  uchar t2          [ 32 ]; // point
  uchar tx          [ 32 ]; // scalar
  uchar t_x_blinding[ 32 ]; // scalar
  uchar e_blinding  [ 32 ]; // scalar
  uchar ipp_proof  [ 576 ];
} fd_zktpp_range_proof_u256_proof_t;

#define MAX_COMMITMENTS 8
typedef struct fd_zktpp_batched_range_proof_context {
  uchar commitments[ MAX_COMMITMENTS * 32 ]; // points
  uchar bit_lengths[ MAX_COMMITMENTS ];
} fd_zktpp_batched_range_proof_context_t;

typedef struct fd_zktpp_single_range_proof_context {
  uchar commitment[ 32 ]; // point
} fd_zktpp_single_range_proof_context_t;

#endif /* HEADER_fd_zktpp_range_proofs_h */
