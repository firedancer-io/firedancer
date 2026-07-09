#ifndef HEADER_fd_src_ballet_zksdk_fd_zksdk_h
#define HEADER_fd_src_ballet_zksdk_fd_zksdk_h

#include "fd_zksdk_common.h"

/* FD_ZKSDK_INSTR_{...} identify ZK ElGamal Proof Program instructions.
   https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/instruction.rs#L53 */

#define FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE                                  ((uchar) 0)
#define FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT                               ((uchar) 1)
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY                ((uchar) 2)
#define FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY                ((uchar) 3)
#define FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY                               ((uchar) 4)
#define FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP                           ((uchar) 5)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64                       ((uchar) 6)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128                      ((uchar) 7)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256                      ((uchar) 8)
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY         ((uchar) 9)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY ((uchar)10)
#define FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY         ((uchar)11)
#define FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY ((uchar)12)

/* Instruction context struct, proof struct, and in some cases
   ZKP verify function. */
#include "instructions/fd_zksdk_zero_ciphertext.h"
#include "instructions/fd_zksdk_ciphertext_ciphertext_equality.h"
#include "instructions/fd_zksdk_ciphertext_commitment_equality.h"
#include "instructions/fd_zksdk_pubkey_validity.h"
#include "instructions/fd_zksdk_percentage_with_cap.h"
#include "instructions/fd_zksdk_batched_range_proofs.h"
#include "instructions/fd_zksdk_batched_grouped_ciphertext_validity.h"

/* Size of the context struct for each verify_proof instruction. */
static const ulong fd_zksdk_context_sz[] = {
  0, // (placeholder/unused)                             FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE
  sizeof(fd_zksdk_zero_ciphertext_context_t),         // FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT
  sizeof(fd_zksdk_ciph_ciph_eq_context_t),            // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY
  sizeof(fd_zksdk_ciph_comm_eq_context_t),            // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY
  sizeof(fd_zksdk_pubkey_validity_context_t),         // FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY
  sizeof(fd_zksdk_percentage_with_cap_context_t),     // FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP
  sizeof(fd_zksdk_batched_range_proof_context_t),     // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64
  sizeof(fd_zksdk_batched_range_proof_context_t),     // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128
  sizeof(fd_zksdk_batched_range_proof_context_t),     // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256
  sizeof(fd_zksdk_grp_ciph_2h_val_context_t),         // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  sizeof(fd_zksdk_batched_grp_ciph_2h_val_context_t), // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  sizeof(fd_zksdk_grp_ciph_3h_val_context_t),         // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
  sizeof(fd_zksdk_batched_grp_ciph_3h_val_context_t), // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
};

/* Size of the proof struct for each verify_proof instruction. */
static const ulong fd_zksdk_proof_sz[] = {
  0, // (placeholder/unused)                             FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE
  sizeof(fd_zksdk_zero_ciphertext_proof_t),           // FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT
  sizeof(fd_zksdk_ciph_ciph_eq_proof_t),              // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY
  sizeof(fd_zksdk_ciph_comm_eq_proof_t),              // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY
  sizeof(fd_zksdk_pubkey_validity_proof_t),           // FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY
  sizeof(fd_zksdk_percentage_with_cap_proof_t),       // FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP
  sizeof(fd_zksdk_range_proof_u64_proof_t),           // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64
  sizeof(fd_zksdk_range_proof_u128_proof_t),          // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128
  sizeof(fd_zksdk_range_proof_u256_proof_t),          // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256
  sizeof(fd_zksdk_grp_ciph_2h_val_proof_t),           // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  sizeof(fd_zksdk_batched_grp_ciph_2h_val_proof_t),   // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  sizeof(fd_zksdk_grp_ciph_3h_val_proof_t),           // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
  sizeof(fd_zksdk_batched_grp_ciph_3h_val_proof_t),   // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
};

/* ProofContextStateMeta
   https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/state.rs#L71 */
struct __attribute__((packed)) fd_zksdk_proof_ctx_state_meta {
  uchar ctx_state_authority[ 32 ];
  uchar proof_type;
};
typedef struct fd_zksdk_proof_ctx_state_meta fd_zksdk_proof_ctx_state_meta_t;

/* Define all the fd_zksdk_instr_verify_proof_* functions with a macro
   so it's easy to keep the interface. */
#define DEFINE_VERIFY_PROOF(name)                                \
    int                                                          \
    fd_zksdk_instr_verify_proof_ ## name( void const * context,  \
                                          void const * proof );

FD_PROTOTYPES_BEGIN

DEFINE_VERIFY_PROOF(zero_ciphertext)
DEFINE_VERIFY_PROOF(ciphertext_ciphertext_equality)
DEFINE_VERIFY_PROOF(ciphertext_commitment_equality)
DEFINE_VERIFY_PROOF(pubkey_validity)
DEFINE_VERIFY_PROOF(percentage_with_cap)
DEFINE_VERIFY_PROOF(batched_range_proof_u64)
DEFINE_VERIFY_PROOF(batched_range_proof_u128)
DEFINE_VERIFY_PROOF(batched_range_proof_u256)
DEFINE_VERIFY_PROOF(grouped_ciphertext_2_handles_validity)
DEFINE_VERIFY_PROOF(batched_grouped_ciphertext_2_handles_validity)
DEFINE_VERIFY_PROOF(grouped_ciphertext_3_handles_validity)
DEFINE_VERIFY_PROOF(batched_grouped_ciphertext_3_handles_validity)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_zksdk_fd_zksdk_h */
