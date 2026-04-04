#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_utils_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_utils_h

#include "fd_vote_codec.h"
#include "../../fd_executor.h"

/* Vote utility functions shared across vote program logic.
   Merged from the former fd_vote_common.h and fd_vote_lockout.h. */

FD_PROTOTYPES_BEGIN

/**********************************************************************/
/* Lockout utilities                                                  */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L104 */
ulong
fd_vote_lockout_get_lockout( fd_vote_lockout_t * self );

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L110 */
ulong
fd_vote_lockout_last_locked_out_slot( fd_vote_lockout_t * self );

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L114 */
ulong
fd_vote_lockout_is_locked_out_at_slot( fd_vote_lockout_t * self, ulong slot );

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L122 */
void
fd_vote_lockout_increase_confirmation_count( fd_vote_lockout_t * self, uint by );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L1009-L1011 */
fd_landed_vote_t *
fd_vote_lockout_landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                                            uchar *             mem );

/**********************************************************************/
/* Vote state utilities                                               */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L985 */
int
fd_vote_verify_authorized_signer( fd_pubkey_t const * authorized,
                                  fd_pubkey_t const * signers[static FD_TXN_SIG_MAX],
                                  ulong               signers_cnt );

/* lambda function: https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L873 */
int
fd_vote_signature_verify( fd_pubkey_t *       epoch_authorized_voter,
                          int                 authorized_withdrawer_signer,
                          fd_pubkey_t const * signers[static FD_TXN_SIG_MAX],
                          ulong               signers_cnt );

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L668 */
uchar
fd_vote_compute_vote_latency( ulong voted_for_slot,
                              ulong current_slot );

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L673 */
ulong
fd_vote_credits_for_vote_at_index( fd_landed_vote_t const * votes,
                                   ulong                    index );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L773-L778 */
int
fd_vote_contains_slot( fd_landed_vote_t const * votes,
                       ulong                    slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_utils_h */
