#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_private_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_private_h

#include "fd_zktpp.h"
#include "../../fd_executor.h"

/* define all the fd_zktpp_verify_proof_* functions with a macro
   so it's easy to keep them consistent. */
#define DEFINE_VERIFY_PROOF(name)                    \
    int                                              \
    fd_zktpp_verify_proof_ ## name( void * context,  \
                                    void * proof );

FD_PROTOTYPES_BEGIN

DEFINE_VERIFY_PROOF(withdraw)
DEFINE_VERIFY_PROOF(zero_balance)
DEFINE_VERIFY_PROOF(ciphertext_ciphertext_equality)
DEFINE_VERIFY_PROOF(transfer)
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
