#ifndef HEADER_fd_zktpp_pubkey_validity_h
#define HEADER_fd_zktpp_pubkey_validity_h

#include "../../../../fd_flamenco_base.h"

struct __attribute__((packed)) fd_zktpp_pubkey_validity_proof {
  uchar y[ 32 ]; // point
  uchar z[ 32 ]; // scalar
};
typedef struct fd_zktpp_pubkey_validity_proof fd_zktpp_pubkey_validity_proof_t;

struct __attribute__((packed)) fd_zktpp_pubkey_validity_context {
  uchar pubkey[ 32 ]; // point
};
typedef struct fd_zktpp_pubkey_validity_context fd_zktpp_pubkey_validity_context_t;

#endif /* HEADER_fd_zktpp_pubkey_validity_h */
