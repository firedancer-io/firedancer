#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_authorized_voters_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_authorized_voters_h

#include "fd_vote_codec.h"
#include "../../../../util/fd_util_base.h"

/* fd_authorized_voters mirrors Agave's AuthorizedVoters methods. */

FD_PROTOTYPES_BEGIN

int
fd_authorized_voters_is_empty( fd_vote_authorized_voters_t * self );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/authorized_voters.rs#L110 */
int
fd_authorized_voters_contains( fd_vote_authorized_voters_t * self, ulong epoch );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/authorized_voters.rs#L102 */
fd_vote_authorized_voter_t *
fd_authorized_voters_last( fd_vote_authorized_voters_t * self );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/authorized_voters.rs#L73 */
void
fd_authorized_voters_purge_authorized_voters( fd_vote_authorized_voters_t * self,
                                              ulong                         current_epoch );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/authorized_voters.rs#L122 */
fd_vote_authorized_voter_t *
fd_authorized_voters_get_or_calculate_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                                  ulong                         epoch,
                                                                  int *                         existed );

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v7.3.0/vote-interface/src/authorized_voters.rs#L49 */
fd_vote_authorized_voter_t *
fd_authorized_voters_get_and_cache_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                               ulong                         epoch );

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/vote/src/vote_state/handler.rs#L166-L184 */
int
fd_authorized_voters_get_and_update_authorized_voter( fd_vote_state_versioned_t * self,
                                                      ulong                       current_epoch,
                                                      fd_pubkey_t **              pubkey /* out */ );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_authorized_voters_h */

