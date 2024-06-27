#ifndef HEADER_fd_zksdk_ciphertext_ciphertext_equality_h
#define HEADER_fd_zksdk_ciphertext_ciphertext_equality_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zksdk_ciph_ciph_eq_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar y3[ 32 ]; // point
  uchar zs[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
  uchar zr[ 32 ]; // scalar
};
typedef struct fd_zksdk_ciph_ciph_eq_proof fd_zksdk_ciph_ciph_eq_proof_t;

struct __attribute__((packed)) fd_zksdk_ciph_ciph_eq_context {
  uchar pubkey1[ 32 ];     // point
  uchar pubkey2[ 32 ];     // point
  uchar ciphertext1[ 64 ]; // 2x points
  uchar ciphertext2[ 64 ]; // 2x points
};
typedef struct fd_zksdk_ciph_ciph_eq_context fd_zksdk_ciph_ciph_eq_context_t;

#endif /* HEADER_fd_zksdk_ciphertext_ciphertext_equality_h */
