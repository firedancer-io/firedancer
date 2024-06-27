#ifndef HEADER_fd_src_flamenco_runtime_program_zksdk_fd_rangeproofs_h
#define HEADER_fd_src_flamenco_runtime_program_zksdk_fd_rangeproofs_h

#include "../../../../fd_flamenco_base.h"
#include "./fd_rangeproofs_transcript.h"

#if FD_HAS_AVX512
#include "./fd_rangeproofs_table_avx512.c"
#else
#include "./fd_rangeproofs_table_ref.c"
#endif

/* Rangeproofs constants. These are imported from fd_rangeproofs_table_{arch}.c.
   they are (re)defined here to avoid breaking compilation when the table needs
   to be rebuilt. */
static const fd_ristretto255_point_t fd_rangeproofs_basepoint_G[1];
static const fd_ristretto255_point_t fd_rangeproofs_basepoint_H[1];
static const fd_ristretto255_point_t fd_rangeproofs_generators_G[256];
static const fd_ristretto255_point_t fd_rangeproofs_generators_H[256];

#define FD_RANGEPROOFS_SUCCESS 0
#define FD_RANGEPROOFS_ERROR  -1

#define FD_RANGEPROOFS_MAX_COMMITMENTS 8

struct __attribute__((packed)) fd_rangeproofs_ipp_vecs {
  uchar l[ 32 ]; // point
  uchar r[ 32 ]; // point
};
typedef struct fd_rangeproofs_ipp_vecs fd_rangeproofs_ipp_vecs_t;

struct __attribute__((packed)) fd_rangeproofs_range_proof {
  uchar a          [ 32 ]; // point
  uchar s          [ 32 ]; // point
  uchar t1         [ 32 ]; // point
  uchar t2         [ 32 ]; // point
  uchar tx         [ 32 ]; // scalar
  uchar tx_blinding[ 32 ]; // scalar
  uchar e_blinding [ 32 ]; // scalar
};
typedef struct fd_rangeproofs_range_proof fd_rangeproofs_range_proof_t;

struct fd_rangeproofs_ipp_proof {
  const uchar                       logn; // log(bit_length): 6 for u64, 7 for u128, 8 for u256
  const fd_rangeproofs_ipp_vecs_t * vecs; // log(bit_length) points
  const uchar *                     a;    // scalar
  const uchar *                     b;    // scalar
};
typedef struct fd_rangeproofs_ipp_proof fd_rangeproofs_ipp_proof_t;

FD_PROTOTYPES_BEGIN

int
fd_rangeproofs_range_proof_verify(
  fd_rangeproofs_range_proof_t const * range_proof,
  fd_rangeproofs_ipp_proof_t const *   ipp_proof,
  uchar const                          commitments [ static 32 ],
  uchar const                          bit_lengths [ static 1 ],
  uchar const                          batch_len,
  fd_merlin_transcript_t *             transcript );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zksdk_fd_rangeproofs_h */
