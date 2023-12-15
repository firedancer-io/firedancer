#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_private_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_private_h

#include "fd_zktpp.h"
#include "transcript/fd_zktpp_transcript.h"
#include "../fd_zk_token_proof_program.h"
#include "../../fd_executor.h"

#include "instructions/fd_zktpp_ciphertext_commitment_equality.h"


static const ulong fd_zktpp_context_sz[] = {
  0, // FD_ZKTPP_INSTR_CLOSE_CONTEXT_STATE
  0, // FD_ZKTPP_INSTR_VERIFY_ZERO_BALANCE
  0, // FD_ZKTPP_INSTR_VERIFY_WITHDRAW
  0, // FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY
  0, // FD_ZKTPP_INSTR_VERIFY_TRANSFER
  0, // FD_ZKTPP_INSTR_VERIFY_TRANSFER_WITH_FEE
  0, // FD_ZKTPP_INSTR_VERIFY_PUBKEY_VALIDITY
  0, // FD_ZKTPP_INSTR_VERIFY_RANGE_PROOF_U64
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256
  sizeof(fd_zktpp_ciph_comm_eq_context_t), // FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY
  0, // FD_ZKTPP_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKTPP_INSTR_VERIFY_FEE_SIGMA
};

static const ulong fd_zktpp_proof_sz[] = {
  0, // FD_ZKTPP_INSTR_CLOSE_CONTEXT_STATE
  0, // FD_ZKTPP_INSTR_VERIFY_ZERO_BALANCE
  0, // FD_ZKTPP_INSTR_VERIFY_WITHDRAW
  0, // FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY
  0, // FD_ZKTPP_INSTR_VERIFY_TRANSFER
  0, // FD_ZKTPP_INSTR_VERIFY_TRANSFER_WITH_FEE
  0, // FD_ZKTPP_INSTR_VERIFY_PUBKEY_VALIDITY
  0, // FD_ZKTPP_INSTR_VERIFY_RANGE_PROOF_U64
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256
  sizeof(fd_zktpp_ciph_comm_eq_proof_t), // FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY
  0, // FD_ZKTPP_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKTPP_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY
  0, // FD_ZKTPP_INSTR_VERIFY_FEE_SIGMA
};

/* Define all the fd_zktpp_instr_verify_proof_* functions with a macro
   so it's easy to keep the interface. */
#define DEFINE_VERIFY_PROOF(name)                                \
    int                                                          \
    fd_zktpp_instr_verify_proof_ ## name( void const * context,  \
                                          void const * proof );

FD_PROTOTYPES_BEGIN

/* Zero-Knowledge Proofs: fd_zktpp_verify_proof_*

   Some ZKP are reused across instructions, for example a transfer
   (without fee) internally uses:
   1. ciphertext_commitment_equality
   2. batched_grouped_ciphertext_validity
   3. batched_range_proof_u128

   Here we only declare the functions that are reused across ZKPs,
   all the ones that are not reused are defined as static inside
   each individual instructions/ file. */

/* Instructions: fd_zktpp_instr_verify_proof_* */

DEFINE_VERIFY_PROOF(withdraw)
DEFINE_VERIFY_PROOF(zero_balance)
DEFINE_VERIFY_PROOF(ciphertext_ciphertext_equality)
DEFINE_VERIFY_PROOF(transfer_without_fee)
DEFINE_VERIFY_PROOF(transfer_with_fee)
DEFINE_VERIFY_PROOF(pubkey_validity)
DEFINE_VERIFY_PROOF(range_proof_u64)
DEFINE_VERIFY_PROOF(batched_range_proof_u64)
DEFINE_VERIFY_PROOF(batched_range_proof_u128)
DEFINE_VERIFY_PROOF(batched_range_proof_u256)
DEFINE_VERIFY_PROOF(ciphertext_commitment_equality)
DEFINE_VERIFY_PROOF(grouped_ciphertext_validity)
DEFINE_VERIFY_PROOF(batched_grouped_ciphertext_validity)
DEFINE_VERIFY_PROOF(fee_sigma)

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_private_h */
