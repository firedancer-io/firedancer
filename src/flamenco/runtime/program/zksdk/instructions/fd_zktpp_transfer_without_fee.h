#ifndef HEADER_fd_zktpp_transfer_without_fee_h
#define HEADER_fd_zktpp_transfer_without_fee_h

#include "../../../../fd_flamenco_base.h"
#include "fd_zktpp_ciphertext_commitment_equality.h"
#include "fd_zktpp_batched_grouped_ciphertext_validity.h"
#include "fd_zktpp_range_proofs.h"

struct __attribute__((packed)) fd_zktpp_transfer_pubkeys {
  uchar source[ 32 ];      // point
  uchar destination[ 32 ]; // point
  uchar auditor[ 32 ];     // point
};
typedef struct fd_zktpp_transfer_pubkeys fd_zktpp_transfer_pubkeys_t;

struct __attribute__((packed)) fd_zktpp_grouped_ciphertext_src_dst_aud {
  uchar commitment         [ 32 ]; // point
  uchar source_handle      [ 32 ]; // point
  uchar destination_handle [ 32 ]; // point
  uchar auditor_handle     [ 32 ]; // point
};
typedef struct fd_zktpp_grouped_ciphertext_src_dst_aud fd_zktpp_grouped_ciphertext_src_dst_aud_t;

struct __attribute__((packed)) fd_zktpp_transfer_context {
  fd_zktpp_grouped_ciphertext_src_dst_aud_t ciphertext_lo; // 4x points
  fd_zktpp_grouped_ciphertext_src_dst_aud_t ciphertext_hi; // 4x points
  fd_zktpp_transfer_pubkeys_t transfer_pubkeys;            // 3x points: source, destination, auditor
  uchar                       new_source_ciphertext[ 64 ]; // 2x points
};
typedef struct fd_zktpp_transfer_context fd_zktpp_transfer_context_t;

struct __attribute__((packed)) fd_zktpp_transfer_proof {
  uchar                                 new_source_commitment[ 32 ]; // point
  fd_zktpp_ciph_comm_eq_proof_t         equality_proof;              // ciphertext_commitment_equality == 192 bytes
  fd_zktpp_batched_grp_ciph_val_proof_t validity_proof;              // batched_grouped_ciphertext_validity == 160 bytes
  fd_zktpp_range_proof_u128_proof_t     range_proof;                 // (batched) range proof u128 == 736 bytes
};
typedef struct fd_zktpp_transfer_proof fd_zktpp_transfer_proof_t;

#endif /* HEADER_fd_zktpp_transfer_without_fee_h */
