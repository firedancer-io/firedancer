#ifndef HEADER_fd_zktpp_pubkey_validity_h
#define HEADER_fd_zktpp_pubkey_validity_h

typedef struct fd_zktpp_pubkey_validity_proof {
  uchar y[ 32 ]; // point
  uchar z[ 32 ]; // scalar
} fd_zktpp_pubkey_validity_proof_t;

typedef struct fd_zktpp_pubkey_validity_context {
  uchar pubkey[ 32 ]; // point
} fd_zktpp_pubkey_validity_context_t;

#endif /* HEADER_fd_zktpp_pubkey_validity_h */
