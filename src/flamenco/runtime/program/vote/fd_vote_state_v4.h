#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v4_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v4_h

#include "../../fd_borrowed_account.h"

/* fd_vote_state_v4 mirrors Agave's VoteStateV4 methods. */

FD_PROTOTYPES_BEGIN

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.0.0/vote-interface/src/state/vote_state_v4.rs#L80 */
void
fd_vote_state_v4_create_new_with_defaults( fd_pubkey_t const *           vote_pubkey,
                                           fd_vote_init_t const *     vote_init,
                                           fd_sol_sysvar_clock_t const * clock,
                                           uchar *                       authorized_voters_mem,
                                           fd_vote_state_versioned_t *   versioned /* out */ );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.0.0/vote-interface/src/state/vote_state_v4.rs#L95 */
void
fd_vote_state_v4_create_new( fd_vote_init_v2_t const *     vote_init_v2,
                             fd_sol_sysvar_clock_t const * clock,
                             uchar *                       authorized_voters_mem,
                             fd_vote_state_versioned_t *   versioned /* out */ );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L576-L595 */
int
fd_vote_state_v4_set_vote_account_state( fd_exec_instr_ctx_t const * ctx,
                                         fd_borrowed_account_t *     vote_account,
                                         fd_vote_state_versioned_t * versioned );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L323-L334 */
int
fd_vote_state_v4_get_and_update_authorized_voter( fd_vote_state_v4_t * self,
                                                  ulong                current_epoch,
                                                  fd_pubkey_t **       pubkey /* out */ );

/* authorized_withdrawer_signer and signers are parameters to a closure
   called verify, which is passed into the associated Agave method.
   https://github.com/anza-xyz/agave/blob/v4.0.0-alpha.0/programs/vote/src/vote_state/handler.rs#L500 */
int
fd_vote_state_v4_set_new_authorized_voter( fd_exec_instr_ctx_t *              ctx,
                                           fd_vote_state_v4_t *               self,
                                           fd_pubkey_t const *                authorized_pubkey,
                                           ulong                              current_epoch,
                                           ulong                              target_epoch,
                                           fd_bls_pubkey_compressed_t const * bls_pubkey,
                                           int                                authorized_withdrawer_signer,
                                           fd_pubkey_t const *                signers[ FD_TXN_SIG_MAX ],
                                           ulong                              signers_cnt );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v4_h */

