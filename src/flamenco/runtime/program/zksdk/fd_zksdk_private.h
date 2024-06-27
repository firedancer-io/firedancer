#ifndef HEADER_fd_src_flamenco_runtime_program_zksdk_fd_zksdk_private_h
#define HEADER_fd_src_flamenco_runtime_program_zksdk_fd_zksdk_private_h

#include "fd_zksdk.h"
#include "transcript/fd_zksdk_transcript.h"
#include "rangeproofs/fd_rangeproofs.h"
#include "../fd_zk_elgamal_proof_program.h"
#include "../../fd_executor.h"

/* Instruction context struct, proof struct, and in some cases
   ZKP verify function. */
// #include "instructions/fd_zksdk_range_proofs.h"
// #include "instructions/fd_zksdk_batched_grouped_ciphertext_validity.h"
// #include "instructions/fd_zksdk_ciphertext_ciphertext_equality.h"
// #include "instructions/fd_zksdk_ciphertext_commitment_equality.h"
// #include "instructions/fd_zksdk_fee_sigma.h"
// #include "instructions/fd_zksdk_grouped_ciphertext_validity.h"
#include "instructions/fd_zksdk_pubkey_validity.h"
// #include "instructions/fd_zksdk_transfer_with_fee.h"
// #include "instructions/fd_zksdk_transfer_without_fee.h"
// #include "instructions/fd_zksdk_withdraw.h"
// #include "instructions/fd_zksdk_zero_balance.h"

/* Internal error for ZKP verify_proof instructions, to distinguish
   from the external error which is FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA. */
#define FD_ZKSDK_VERIFY_PROOF_ERROR FD_EXECUTOR_INSTR_ERR_GENERIC_ERR

/* Basepoints for Pedersen commitments.
   They're the same as rangeproofs, but some ZKP don't use rangeproofs. */
#define fd_zksdk_basepoint_G fd_rangeproofs_basepoint_G
#define fd_zksdk_basepoint_H fd_rangeproofs_basepoint_H

/* Size of the context struct for each verify_proof instruction. */
static const ulong fd_zksdk_context_sz[] = {
  0, // FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE
  0, // FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT
  0, // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY
  0, // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY
  sizeof(fd_zksdk_pubkey_validity_context_t), // FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY
  0, // FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256
  0, // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
};

/* Size of the proof struct for each verify_proof instruction. */
static const ulong fd_zksdk_proof_sz[] = {
  0, // FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE
  0, // FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT
  0, // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY
  0, // FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY
  sizeof(fd_zksdk_pubkey_validity_proof_t), // FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY
  0, // FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256
  0, // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKSDK_INSTR_VERFIY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
  0, // FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY
};

/* Define all the fd_zksdk_instr_verify_proof_* functions with a macro
   so it's easy to keep the interface. */
#define DEFINE_VERIFY_PROOF(name)                                \
    int                                                          \
    fd_zksdk_instr_verify_proof_ ## name( void const * context,  \
                                          void const * proof );

FD_PROTOTYPES_BEGIN

// DEFINE_VERIFY_PROOF(zero_ciphertext)
// DEFINE_VERIFY_PROOF(ciphertext_ciphertext_equality)
// DEFINE_VERIFY_PROOF(ciphertext_commitment_equality)
DEFINE_VERIFY_PROOF(pubkey_validity)
// DEFINE_VERIFY_PROOF(batched_range_proof_u64)
// DEFINE_VERIFY_PROOF(batched_range_proof_u128)
// DEFINE_VERIFY_PROOF(batched_range_proof_u256)
// DEFINE_VERIFY_PROOF(grouped_ciphertext_validity)
// DEFINE_VERIFY_PROOF(batched_grouped_ciphertext_validity)

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zksdk_fd_zksdk_private_h */
