#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v4_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v4_h

#include "../../fd_borrowed_account.h"
#include "../../fd_executor.h"
#include "../../../types/fd_types.h"
#include "../../sysvar/fd_sysvar.h"

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L600-L619 */
void
fd_vote_state_v4_create_new( fd_pubkey_t const *           vote_pubkey,
                             fd_vote_init_t const *        vote_init,
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

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L450-L478 */
int
fd_vote_state_v4_set_new_authorized_voter( fd_exec_instr_ctx_t *                      ctx,
                                           fd_vote_state_v4_t *                       self,
                                           fd_pubkey_t const *                        authorized_pubkey,
                                           ulong                                      current_epoch,
                                           ulong                                      target_epoch,
                                           /* "verify" closure */ int                 authorized_withdrawer_signer,
                                           /* "verify" closure */ fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] );

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v4_h */

