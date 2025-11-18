#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_common_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_common_h

#include "../../../types/fd_types.h"
#include "../../fd_executor.h"

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L985
int
fd_vote_verify_authorized_signer( fd_pubkey_t const * authorized,
                                  fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] );

// lambda function: https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L873
int
fd_vote_signature_verify( fd_pubkey_t *       epoch_authorized_voter,
                          int                 authorized_withdrawer_signer,
                          fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] );

uchar
fd_vote_compute_vote_latency( ulong voted_for_slot, ulong current_slot );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L673
ulong
fd_vote_credits_for_vote_at_index( fd_landed_vote_t const * votes,
                                   ulong                    index );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L773-L778 */
uchar
fd_vote_contains_slot( fd_landed_vote_t const * votes,
                       ulong                    slot );

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_common_h */

