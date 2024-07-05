#ifndef HEADER_fd_zksdk_percentage_with_cap_h
#define HEADER_fd_zksdk_percentage_with_cap_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) percentage_max_proof {
  uchar y_max[ 32 ]; // point
  uchar z_max[ 32 ]; // scalar
  uchar c_max[ 32 ]; // scalar
};
typedef struct percentage_max_proof percentage_max_proof_t;

struct __attribute__((packed)) percentage_equality_proof {
  uchar y_delta  [ 32 ]; // point
  uchar y_claimed[ 32 ]; // point
  uchar z_x      [ 32 ]; // scalar
  uchar z_delta  [ 32 ]; // scalar
  uchar z_claimed[ 32 ]; // scalar
};
typedef struct percentage_equality_proof percentage_equality_proof_t;

struct __attribute__((packed)) fd_zksdk_percentage_with_cap_proof {
  percentage_max_proof_t      percentage_max_proof;
  percentage_equality_proof_t percentage_equality_proof;
};
typedef struct fd_zksdk_percentage_with_cap_proof fd_zksdk_percentage_with_cap_proof_t;

struct __attribute__((packed)) fd_zksdk_percentage_with_cap_context {
  uchar percentage_commitment[ 32 ]; // point
  uchar delta_commitment     [ 32 ]; // point
  uchar claimed_commitment   [ 32 ]; // point
  ulong max_value;
};
typedef struct fd_zksdk_percentage_with_cap_context fd_zksdk_percentage_with_cap_context_t;

#endif /* HEADER_fd_zksdk_percentage_with_cap_h */
