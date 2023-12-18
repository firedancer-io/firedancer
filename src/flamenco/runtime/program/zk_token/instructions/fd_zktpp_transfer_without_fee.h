#ifndef HEADER_fd_zktpp_transfer_without_fee_h
#define HEADER_fd_zktpp_transfer_without_fee_h

typedef struct fd_zktpp_transfer_pubkeys {
  uchar source[ 32 ];      // point
  uchar destination[ 32 ]; // point
  uchar auditor[ 32 ];     // point
} fd_zktpp_transfer_pubkeys_t;

typedef struct fd_zktpp_transfer_context {
  uchar                       ciphertext_lo[ 128 ];        // 4x points
  uchar                       ciphertext_hi[ 128 ];        // 4x points
  fd_zktpp_transfer_pubkeys_t transfer_pubkeys;            // 3x points: source, destination, auditor
  uchar                       new_source_ciphertext[ 64 ]; // 2x points
} fd_zktpp_transfer_context_t;

typedef struct fd_zktpp_transfer_proof {
  uchar                         new_source_commitment[ 32 ]; // point
  fd_zktpp_ciph_comm_eq_proof_t equality_proof;              // ciphertext_commitment_equality == 192 bytes
  uchar                         validity_proof[ 32 ];        // TODO
  uchar                         range_proof[ 32 ];           // TODO
} fd_zktpp_transfer_proof_t;

#endif /* HEADER_fd_zktpp_transfer_without_fee_h */
