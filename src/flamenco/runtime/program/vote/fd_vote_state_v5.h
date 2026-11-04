#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v5_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v5_h

#include "../../fd_borrowed_account.h"
#include "fd_vote_codec.h"

FD_PROTOTYPES_BEGIN

int
fd_vote_state_v5_get_and_update_authorized_voter( fd_vote_state_v5_t * self,
                                                  ulong                current_epoch,
                                                  fd_pubkey_t **       pubkey );

int
fd_vote_state_v5_set_new_authorized_voter( fd_exec_instr_ctx_t * ctx,
                                           fd_vote_state_v5_t *  self,
                                           fd_pubkey_t const *   authorized_pubkey,
                                           ulong                 current_epoch,
                                           ulong                 target_epoch,
                                           uchar const *         bls_pubkey,
                                           int                   authorized_withdrawer_signer,
                                           fd_pubkey_t const *   signers[ FD_INSTR_SIGNERS_MAX ],
                                           ulong                 signers_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_v5_h */
