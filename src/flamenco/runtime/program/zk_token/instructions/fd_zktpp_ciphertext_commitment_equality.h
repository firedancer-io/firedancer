#ifndef HEADER_fd_zktpp_ciphertext_commitment_equality_h
#define HEADER_fd_zktpp_ciphertext_commitment_equality_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zktpp_ciph_comm_eq_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar zs[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
  uchar zr[ 32 ]; // scalar
};
typedef struct fd_zktpp_ciph_comm_eq_proof fd_zktpp_ciph_comm_eq_proof_t;

struct __attribute__((packed)) fd_zktpp_ciph_comm_eq_context {
  uchar pubkey[ 32 ];     // point
  uchar ciphertext[ 64 ]; // 2x points
  uchar commitment[ 32 ]; // point
};
typedef struct fd_zktpp_ciph_comm_eq_context fd_zktpp_ciph_comm_eq_context_t;

int
fd_zktpp_verify_proof_ciphertext_commitment_equality(
  fd_zktpp_ciph_comm_eq_proof_t const * proof,
  uchar const                           source_pubkey         [ static 32 ],
  uchar const                           source_ciphertext     [ static 64 ],
  uchar const                           destination_commitment[ static 32 ],
  fd_zktpp_transcript_t *               transcript );

#endif /* HEADER_fd_zktpp_ciphertext_commitment_equality_h */
