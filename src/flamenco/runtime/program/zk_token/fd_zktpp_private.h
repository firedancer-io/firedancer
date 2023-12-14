#ifndef HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_private_h
#define HEADER_fd_src_flamenco_runtime_program_zk_token_fd_zktpp_private_h

#include "fd_zktpp.h"
#include "transcript/fd_zktpp_transcript.h"
#include "../../fd_executor.h"

typedef struct fd_zktpp_cce_proof {
  uchar y0[ 32 ]; // point
  uchar y1[ 32 ]; // point
  uchar y2[ 32 ]; // point
  uchar zs[ 32 ]; // scalar
  uchar zx[ 32 ]; // scalar
  uchar zr[ 32 ]; // scalar
} fd_zktpp_cce_proof_t;

/* define all the fd_zktpp_verify_proof_* functions with a macro
   so it's easy to keep them consistent. */
#define DEFINE_VERIFY_PROOF(name)                    \
    int                                              \
    fd_zktpp_verify_proof_ ## name( void * context,  \
                                    void * proof );

FD_PROTOTYPES_BEGIN

int
fd_zktpp_ciphertext_commitment_equality_zkp_verify( fd_zktpp_cce_proof_t const * proof,
                                                    uchar const                  source_pubkey[ static 32 ],
                                                    uchar const                  source_ciphertext[ static 64 ],
                                                    uchar const                  destination_commitment[ static 32 ],
                                                    fd_zktpp_transcript_t *      transcript );

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
