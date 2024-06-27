#ifndef HEADER_fd_zksdk_zero_ciphertext_h
#define HEADER_fd_zksdk_zero_ciphertext_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zksdk_zero_ciphertext_proof {
  uchar yp[ 32 ]; // point
  uchar yd[ 32 ]; // point
  uchar z [ 32 ]; // scalar
};
typedef struct fd_zksdk_zero_ciphertext_proof fd_zksdk_zero_ciphertext_proof_t;

struct __attribute__((packed)) fd_zksdk_zero_ciphertext_context {
  uchar pubkey    [ 32 ]; // point
  uchar ciphertext[ 64 ]; // 2x points
};
typedef struct fd_zksdk_zero_ciphertext_context fd_zksdk_zero_ciphertext_context_t;

#endif /* HEADER_fd_zksdk_zero_ciphertext_h */
