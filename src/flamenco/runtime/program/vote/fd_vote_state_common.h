#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_common_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_common_h

#include "../../../types/fd_types.h"
#include "../../fd_executor.h"

// https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L985
int
fd_vote_state_verify_authorized_signer( fd_pubkey_t const * authorized,
                                        fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] );

// lambda function: https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L873
int
fd_vote_state_verify( fd_pubkey_t *       epoch_authorized_voter,
                      int                 authorized_withdrawer_signer,
                      fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] );

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_common_h */

