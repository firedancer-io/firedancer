#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_versioned_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_versioned_h

#include "../../fd_borrowed_account.h"
#include "../../../types/fd_types.h"

/* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1074 */
int
fd_vsv_get_state( fd_txn_account_t const * self,
                  uchar *                  res );

int
fd_vsv_set_state( fd_borrowed_account_t *     self,
                  fd_vote_state_versioned_t * state );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L673-L678 */
void
fd_vsv_set_authorized_withdrawer( fd_vote_state_versioned_t * self,
                                  fd_pubkey_t const *         authorized_withdrawer );

/* Sets the authorized withdrawer for the appropriate vote state
   version.  Only supported for v3 and v4 vote states. */
int
fd_vsv_set_new_authorized_voter( fd_exec_instr_ctx_t *                      ctx,
                                 fd_vote_state_versioned_t *                self,
                                 fd_pubkey_t const *                        authorized_pubkey,
                                 ulong                                      current_epoch,
                                 ulong                                      target_epoch,
                                 /* "verify" closure */ int                 authorized_withdrawer_signer,
                                 /* "verify" closure */ fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L40-L98 */
int
fd_vsv_try_convert_to_v3( fd_vote_state_versioned_t * self,
                          uchar *                     authorized_voters_mem,
                          uchar *                     landed_votes_mem );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L966-L1007 */
int
fd_vsv_try_convert_to_v4( fd_vote_state_versioned_t * self,
                          fd_pubkey_t const *         vote_pubkey,
                          uchar *                     landed_votes_mem );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L843-L851 */
int
fd_vsv_set_vote_account_state( fd_borrowed_account_t *     vote_account,
                               fd_vote_state_versioned_t * versioned,
                               fd_exec_instr_ctx_t const * ctx,
                               uchar *                     vote_lockout_mem );

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_versioned_h */

