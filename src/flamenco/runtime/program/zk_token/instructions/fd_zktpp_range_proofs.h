#ifndef HEADER_fd_zktpp_range_proofs_h
#define HEADER_fd_zktpp_range_proofs_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zktpp_range_proof_u64_proof {
  uchar a           [ 32 ]; // point
  uchar s           [ 32 ]; // point
  uchar t1          [ 32 ]; // point
  uchar t2          [ 32 ]; // point
  uchar tx          [ 32 ]; // scalar
  uchar t_x_blinding[ 32 ]; // scalar
  uchar e_blinding  [ 32 ]; // scalar
  uchar ipp_proof  [ 448 ];
};
typedef struct fd_zktpp_range_proof_u64_proof fd_zktpp_range_proof_u64_proof_t;

struct __attribute__((packed)) fd_zktpp_range_proof_u128_proof {
  uchar a           [ 32 ]; // point
  uchar s           [ 32 ]; // point
  uchar t1          [ 32 ]; // point
  uchar t2          [ 32 ]; // point
  uchar tx          [ 32 ]; // scalar
  uchar t_x_blinding[ 32 ]; // scalar
  uchar e_blinding  [ 32 ]; // scalar
  uchar ipp_proof  [ 512 ];
};
typedef struct fd_zktpp_range_proof_u128_proof fd_zktpp_range_proof_u128_proof_t;

struct __attribute__((packed)) fd_zktpp_range_proof_u256_proof {
  uchar a           [ 32 ]; // point
  uchar s           [ 32 ]; // point
  uchar t1          [ 32 ]; // point
  uchar t2          [ 32 ]; // point
  uchar tx          [ 32 ]; // scalar
  uchar t_x_blinding[ 32 ]; // scalar
  uchar e_blinding  [ 32 ]; // scalar
  uchar ipp_proof  [ 576 ];
};
typedef struct fd_zktpp_range_proof_u256_proof fd_zktpp_range_proof_u256_proof_t;

#define FD_ZKTPP_MAX_COMMITMENTS 8
struct __attribute__((packed)) fd_zktpp_batched_range_proof_context {
  uchar commitments[ FD_ZKTPP_MAX_COMMITMENTS * 32 ]; // points
  uchar bit_lengths[ FD_ZKTPP_MAX_COMMITMENTS ];
};
typedef struct fd_zktpp_batched_range_proof_context fd_zktpp_batched_range_proof_context_t;

struct __attribute__((packed)) fd_zktpp_single_range_proof_context {
  uchar commitment[ 32 ]; // point
};
typedef struct fd_zktpp_single_range_proof_context fd_zktpp_single_range_proof_context_t;

int
fd_zktpp_verify_proof_range_u64(
  fd_zktpp_range_proof_u64_proof_t const * proof,
  uchar const                              commitments [ static 32 ],
  uchar const                              bit_lengths [ static 1 ],
  uchar const                              batch_len,
  fd_zktpp_transcript_t *                  transcript );

int
fd_zktpp_verify_proof_range_u128(
  fd_zktpp_range_proof_u128_proof_t const * proof,
  uchar const                               commitments [ static 32 ],
  uchar const                               bit_lengths [ static 1 ],
  uchar const                               batch_len,
  fd_zktpp_transcript_t *                   transcript );

#endif /* HEADER_fd_zktpp_range_proofs_h */
