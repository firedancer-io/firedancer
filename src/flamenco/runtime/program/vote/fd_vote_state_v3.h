#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v3_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v3_h

#include "../../fd_borrowed_account.h"
#include "../../fd_executor.h"
#include "../../../types/fd_types.h"
#include "../../sysvar/fd_sysvar.h"

FD_PROTOTYPES_BEGIN

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_v3.rs#L65-L73 */
void
fd_vote_program_v3_create_new( fd_vote_init_t * const        vote_init,
                               fd_sol_sysvar_clock_t const * clock,
                               uchar *                       authorized_voters_mem,
                              fd_vote_state_versioned_t *    versioned /* out */ );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L414-L434 */
int
fd_vote_state_v3_set_vote_account_state( fd_exec_instr_ctx_t const * ctx,
                                         fd_borrowed_account_t *     vote_account,
                                         fd_vote_state_versioned_t * versioned,
                                         uchar *                     vote_lockout_mem );

/* This is more than just a deserialization - this function attempts
   to deserialize whatever vote state version the vote account has,
   and then tries to convert it into a v3 vote account (unless its a
   v4 account, where it fails automatically).
   https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_v3.rs#L119-L124 */
int
fd_vote_state_v3_deserialize( fd_borrowed_account_t const * vote_account,
                              uchar *                       vote_state_mem,
                              uchar *                       authorized_voters_mem,
                              uchar *                       landed_votes_mem );

/* https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L828 */
int
fd_vote_state_v3_get_and_update_authorized_voter( fd_vote_state_v3_t * self,
                                                  ulong                current_epoch,
                                                  fd_pubkey_t **       pubkey /* out */ );

/* authorized_withdrawer_signer and signers are parameters to a closure
   called verify, which is passed into the associated Agave method.
   https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L263-L321 */
int
fd_vote_state_v3_set_new_authorized_voter( fd_exec_instr_ctx_t * ctx,
                                           fd_vote_state_v3_t *  self,
                                           fd_pubkey_t const *   authorized_pubkey,
                                           ulong                 current_epoch,
                                           ulong                 target_epoch,
                                           int                   authorized_withdrawer_signer,
                                           fd_pubkey_t const *   signers[static FD_TXN_SIG_MAX] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v3_h */

