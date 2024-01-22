#ifndef HEADER_fd_zktpp_withdraw_h
#define HEADER_fd_zktpp_withdraw_h

#include "../../../../fd_flamenco_base.h"
#include "fd_zktpp_ciphertext_commitment_equality.h"
#include "fd_zktpp_range_proofs.h"

struct __attribute__((packed)) fd_zktpp_withdraw_proof {
  uchar commitment[ 32 ]; // point
  fd_zktpp_ciph_comm_eq_proof_t equality_proof;
  fd_zktpp_range_proof_u64_proof_t range_proof;
};
typedef struct fd_zktpp_withdraw_proof fd_zktpp_withdraw_proof_t;

struct __attribute__((packed)) fd_zktpp_withdraw_context {
  uchar pubkey[ 32 ];           // point
  uchar final_ciphertext[ 64 ]; // 2x points
};
typedef struct fd_zktpp_withdraw_context fd_zktpp_withdraw_context_t;

#endif /* HEADER_fd_zktpp_withdraw_h */
