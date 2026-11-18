#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_utils_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_utils_h

#include "fd_vote_codec.h"
#include "../../../../ballet/txn/fd_txn.h"
#include "../../fd_runtime_const.h"

/* Vote utility functions shared across vote program logic.
   Merged from the former fd_vote_common.h and fd_vote_lockout.h. */

FD_PROTOTYPES_BEGIN

/**********************************************************************/
/* Lockout utilities                                                  */
/**********************************************************************/

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/state/mod.rs#L81-L84 */
ulong
fd_vote_lockout_get_lockout( fd_vote_lockout_t * self );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/state/mod.rs#L90 */
ulong
fd_vote_lockout_last_locked_out_slot( fd_vote_lockout_t * self );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/state/mod.rs#L94 */
ulong
fd_vote_lockout_is_locked_out_at_slot( fd_vote_lockout_t * self, ulong slot );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/state/mod.rs#L106 */
void
fd_vote_lockout_increase_confirmation_count( fd_vote_lockout_t * self, uint by );

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L735-L737 */
fd_landed_vote_t *
fd_vote_lockout_landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                                            uchar *             mem );

/**********************************************************************/
/* Vote state utilities                                               */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L1004 */
int
fd_vote_verify_authorized_signer( fd_pubkey_t const * authorized,
                                  fd_pubkey_t const * signers[static FD_INSTR_SIGNERS_MAX],
                                  ulong               signers_cnt );

/* lambda function: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/mod.rs#L723 */
int
fd_vote_signature_verify( fd_pubkey_t *       epoch_authorized_voter,
                          int                 authorized_withdrawer_signer,
                          fd_pubkey_t const * signers[static FD_INSTR_SIGNERS_MAX],
                          ulong               signers_cnt );

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L691 */
uchar
fd_vote_compute_vote_latency( ulong voted_for_slot,
                              ulong current_slot );

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L447 */
ulong
fd_vote_credits_for_vote_at_index( fd_landed_vote_t const * votes,
                                   ulong                    index );

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L283-L290 */
int
fd_vote_contains_slot( fd_landed_vote_t const * votes,
                       ulong                    slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_utils_h */
