#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_versioned_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_versioned_h

#include "../../fd_borrowed_account.h"
#include "../../../types/fd_types.h"

/* fd_vote_state_versioned contains common logic for all supported vote
   state versions, and implements most methods from Agave's
   VoteStateHandle. */

FD_PROTOTYPES_BEGIN

/**********************************************************************/
/* Getters                                                            */
/**********************************************************************/

/* Decodes the vote account data and stores the decoded state in
   vote_state_mem. The caller must provide a buffer at vote_state_mem
   that is aligned to FD_VOTE_STATE_VERSIONED_ALIGN and has at least
   FD_VOTE_STATE_VERSIONED_FOOTPRINT bytes of space.  Returns
   FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA if decoding fails.
   https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L1074 */
int
fd_vsv_get_state( fd_account_meta_t const * meta,
                  uchar *                   vote_state_mem );

/* Returns a const pointer to the authorized withdrawer for the
   appropriate vote state version.*/
fd_pubkey_t const *
fd_vsv_get_authorized_withdrawer( fd_vote_state_versioned_t * self );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L717-L722 */
uchar
fd_vsv_get_commission( fd_vote_state_versioned_t * self );

fd_vote_epoch_credits_t const *
fd_vsv_get_epoch_credits( fd_vote_state_versioned_t * self );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L752-L757 */
fd_landed_vote_t const *
fd_vsv_get_votes( fd_vote_state_versioned_t * self );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L787-L792 */
ulong const *
fd_vsv_get_last_voted_slot( fd_vote_state_versioned_t * self );

ulong const *
fd_vsv_get_root_slot( fd_vote_state_versioned_t * self );

fd_vote_block_timestamp_t const *
fd_vsv_get_last_timestamp( fd_vote_state_versioned_t * self );

/**********************************************************************/
/* Mutable getters                                                    */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L815-L820 */
fd_vote_epoch_credits_t *
fd_vsv_get_epoch_credits_mutable( fd_vote_state_versioned_t * self );

fd_landed_vote_t *
fd_vsv_get_votes_mutable( fd_vote_state_versioned_t * self );

/**********************************************************************/
/* Setters                                                            */
/**********************************************************************/

int
fd_vsv_set_state( fd_borrowed_account_t *     self,
                  fd_vote_state_versioned_t * state );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L673-L678 */
void
fd_vsv_set_authorized_withdrawer( fd_vote_state_versioned_t * self,
                                  fd_pubkey_t const *         authorized_withdrawer );

/* Sets the authorized withdrawer for the appropriate vote state
   version.  Only supported for v3 and v4 vote states.
   authorized_withdrawer_signer and signers are parameters to a closure
   called verify, which is passed into the associated Agave method.
   https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L855-L870 */
int
fd_vsv_set_new_authorized_voter( fd_exec_instr_ctx_t *       ctx,
                                 fd_vote_state_versioned_t * self,
                                 fd_pubkey_t const *         authorized_pubkey,
                                 ulong                       current_epoch,
                                 ulong                       target_epoch,
                                 int                         authorized_withdrawer_signer,
                                 fd_pubkey_t const *         signers[static FD_TXN_SIG_MAX] );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L738-L743 */
void
fd_vsv_set_node_pubkey( fd_vote_state_versioned_t * self,
                        fd_pubkey_t const *         node_pubkey );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L745-L750 */
void
fd_vsv_set_block_revenue_collector( fd_vote_state_versioned_t * self,
                                    fd_pubkey_t const *         block_revenue_collector );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L724-L729 */
void
fd_vsv_set_commission( fd_vote_state_versioned_t * self,
                        uchar                      commission );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L386-L388 */
void
fd_vsv_set_root_slot( fd_vote_state_versioned_t * self, ulong * root_slot );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L843-L851 */
int
fd_vsv_set_vote_account_state( fd_exec_instr_ctx_t const * ctx,
                               fd_borrowed_account_t *     vote_account,
                               fd_vote_state_versioned_t * versioned,
                               uchar *                     vote_lockout_mem );

/**********************************************************************/
/* General functions                                                  */
/**********************************************************************/

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/vote-interface/src/state/vote_state_v3.rs#L282-L309 */
void
fd_vsv_increment_credits( fd_vote_state_versioned_t * self,
                          ulong                       epoch,
                          ulong                       credits );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L159-L170 */
int
fd_vsv_process_timestamp( fd_exec_instr_ctx_t *       ctx,
                          fd_vote_state_versioned_t * self,
                          ulong                       slot,
                          long                        timestamp );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L172-L180 */
void
fd_vsv_pop_expired_votes( fd_vote_state_versioned_t * self, ulong next_vote_slot );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/mod.rs#L638-L651 */
void
fd_vsv_process_next_vote_slot( fd_vote_state_versioned_t * self,
                               ulong                       next_vote_slot,
                               ulong                       epoch,
                               ulong                       current_slot );

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

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L872C12-L886 */
int
fd_vsv_deinitialize_vote_account_state( fd_exec_instr_ctx_t *   ctx,
                                        fd_borrowed_account_t * vote_account,
                                        int                     target_version,
                                        uchar *                 vote_lockout_mem );

/* This function is essentially just a call to get_state, additionally
   erroring out if the account is a v_0_23_5 account.  Decodes the
   vote account data and stores the decoded state in vote_state_mem.
   The caller must provide a buffer at vote_state_mem that is aligned to
   FD_VOTE_STATE_VERSIONED_ALIGN and has at least
   FD_VOTE_STATE_VERSIONED_FOOTPRINT bytes of space.  Returns an error
   if decoding fails or if the account is a v_0_23_5 account.
   https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L195-L246 */
int
fd_vsv_deserialize( fd_borrowed_account_t const * vote_account,
                    uchar *                       vote_state_mem );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L176-L187 */
int
fd_vsv_is_uninitialized( fd_vote_state_versioned_t * self );

/* Returns 1 if the vote account is the correct size and initialized,
   0 otherwise.
   https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v4.0.4/vote-interface/src/state/vote_state_versions.rs#L189-L193 */
int
fd_vsv_is_correct_size_and_initialized( fd_account_meta_t const * meta );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_state_versioned_h */

