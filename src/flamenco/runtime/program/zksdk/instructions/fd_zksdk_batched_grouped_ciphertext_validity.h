#ifndef HEADER_fd_zksdk_batched_grouped_ciphertext_validity_h
#define HEADER_fd_zksdk_batched_grouped_ciphertext_validity_h

#include "../../../../fd_flamenco_base.h"

/*
 * Proof
 */

/* https://github.com/anza-xyz/agave/blob/master/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs */
struct __attribute__((packed)) fd_zksdk_grp_ciph_2h_val_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar zr[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
};
typedef struct fd_zksdk_grp_ciph_2h_val_proof fd_zksdk_grp_ciph_2h_val_proof_t;
#define fd_zksdk_batched_grp_ciph_2h_val_proof_t fd_zksdk_grp_ciph_2h_val_proof_t

/* https://github.com/anza-xyz/agave/blob/master/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L46 */
struct __attribute__((packed)) fd_zksdk_grp_ciph_3h_val_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar y3[ 32 ]; // point
  uchar zr[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
};
typedef struct fd_zksdk_grp_ciph_3h_val_proof fd_zksdk_grp_ciph_3h_val_proof_t;
#define fd_zksdk_batched_grp_ciph_3h_val_proof_t fd_zksdk_grp_ciph_3h_val_proof_t

/*
 * Context
 */

struct __attribute__((packed)) grp_ciph_handle {
  uchar handle [ 32 ]; // point
};
typedef struct grp_ciph_handle grp_ciph_handle_t;

struct __attribute__((packed)) grp_ciph_2h {
  uchar commitment         [ 32 ]; // point
  grp_ciph_handle_t handles [ 2 ]; // 2x points
};
typedef struct grp_ciph_2h grp_ciph_2h_t;

struct __attribute__((packed)) grp_ciph_3h {
  uchar commitment         [ 32 ]; // point
  grp_ciph_handle_t handles [ 3 ]; // 3x points
};
typedef struct grp_ciph_3h grp_ciph_3h_t;


/* https://github.com/anza-xyz/agave/blob/master/zk-sdk/src/zk_elgamal_proof_program/proof_data/grouped_ciphertext_validity/handles_2.rs */
struct __attribute__((packed)) fd_zksdk_grp_ciph_2h_val_context {
  uchar pubkey1 [ 32 ]; // point
  uchar pubkey2 [ 32 ]; // point
  grp_ciph_2h_t grouped_ciphertext; // 3x points
};
typedef struct fd_zksdk_grp_ciph_2h_val_context fd_zksdk_grp_ciph_2h_val_context_t;

/* https://github.com/anza-xyz/agave/blob/master/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_grouped_ciphertext_validity/handles_2.rs#L47 */
struct __attribute__((packed)) fd_zksdk_batched_grp_ciph_2h_val_context {
  uchar pubkey1 [ 32 ]; // point
  uchar pubkey2 [ 32 ]; // point
  grp_ciph_2h_t grouped_ciphertext_lo; // 3x points
  grp_ciph_2h_t grouped_ciphertext_hi; // 3x points
};
typedef struct fd_zksdk_batched_grp_ciph_2h_val_context fd_zksdk_batched_grp_ciph_2h_val_context_t;

/* https://github.com/anza-xyz/agave/blob/master/zk-sdk/src/zk_elgamal_proof_program/proof_data/grouped_ciphertext_validity/handles_3.rs#L47 */
struct __attribute__((packed)) fd_zksdk_grp_ciph_3h_val_context {
  uchar pubkey1 [ 32 ]; // point
  uchar pubkey2 [ 32 ]; // point
  uchar pubkey3 [ 32 ]; // point
  grp_ciph_3h_t grouped_ciphertext; // 4x points
};
typedef struct fd_zksdk_grp_ciph_3h_val_context fd_zksdk_grp_ciph_3h_val_context_t;

/* https://github.com/anza-xyz/agave/blob/master/zk-sdk/src/zk_elgamal_proof_program/proof_data/batched_grouped_ciphertext_validity/handles_3.rs */
struct __attribute__((packed)) fd_zksdk_batched_grp_ciph_3h_val_context {
  uchar pubkey1 [ 32 ]; // point
  uchar pubkey2 [ 32 ]; // point
  uchar pubkey3 [ 32 ]; // point
  grp_ciph_3h_t grouped_ciphertext_lo; // 4x points
  grp_ciph_3h_t grouped_ciphertext_hi; // 4x points
};
typedef struct fd_zksdk_batched_grp_ciph_3h_val_context fd_zksdk_batched_grp_ciph_3h_val_context_t;

int
fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity(
  fd_zksdk_grp_ciph_2h_val_proof_t const * proof,
  uchar const                              pubkey1    [ 32 ],
  uchar const                              pubkey2    [ 32 ],
  uchar const                              comm       [ 32 ],
  uchar const                              handle1    [ 32 ],
  uchar const                              handle2    [ 32 ],
  uchar const                              comm_hi    [ 32 ],
  uchar const                              handle1_hi [ 32 ],
  uchar const                              handle2_hi [ 32 ],
  int   const                              batched,
  fd_zksdk_transcript_t *                  transcript );

int
fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity(
  fd_zksdk_grp_ciph_3h_val_proof_t const * proof,
  uchar const                              pubkey1    [ 32 ],
  uchar const                              pubkey2    [ 32 ],
  uchar const                              pubkey3    [ 32 ],
  uchar const                              comm       [ 32 ],
  uchar const                              handle1    [ 32 ],
  uchar const                              handle2    [ 32 ],
  uchar const                              handle3    [ 32 ],
  uchar const                              comm_hi    [ 32 ],
  uchar const                              handle1_hi [ 32 ],
  uchar const                              handle2_hi [ 32 ],
  uchar const                              handle3_hi [ 32 ],
  int  const                               batched,
  fd_zksdk_transcript_t *                  transcript );

#endif /* HEADER_fd_zksdk_batched_grouped_ciphertext_validity_h */
