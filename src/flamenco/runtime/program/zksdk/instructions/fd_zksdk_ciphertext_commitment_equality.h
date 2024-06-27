#ifndef HEADER_fd_zksdk_ciphertext_commitment_equality_h
#define HEADER_fd_zksdk_ciphertext_commitment_equality_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zksdk_ciph_comm_eq_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar zs[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
  uchar zr[ 32 ]; // scalar
};
typedef struct fd_zksdk_ciph_comm_eq_proof fd_zksdk_ciph_comm_eq_proof_t;

struct __attribute__((packed)) fd_zksdk_ciph_comm_eq_context {
  uchar pubkey[ 32 ];     // point
  uchar ciphertext[ 64 ]; // 2x points
  uchar commitment[ 32 ]; // point
};
typedef struct fd_zksdk_ciph_comm_eq_context fd_zksdk_ciph_comm_eq_context_t;

int
fd_zksdk_verify_proof_ciphertext_commitment_equality(
  fd_zksdk_ciph_comm_eq_proof_t const * proof,
  uchar const                           source_pubkey         [ 32 ],
  uchar const                           source_ciphertext     [ 64 ],
  uchar const                           destination_commitment[ 32 ],
  fd_zksdk_transcript_t *               transcript );

#endif /* HEADER_fd_zksdk_ciphertext_commitment_equality_h */
