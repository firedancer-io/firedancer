#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_authorized_voters_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_authorized_voters_h

#include "../../../types/fd_types.h"
#include "../../../../util/fd_util_base.h"

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L17
fd_vote_authorized_voters_t *
fd_authorized_voters_new( ulong               epoch,
                          fd_pubkey_t const * pubkey,
                          uchar *             mem );

// Helper to create an empty AuthorizedVoters structure (for default/uninitialized states)
fd_vote_authorized_voters_t *
fd_authorized_voters_new_empty( uchar * mem );

int
fd_authorized_voters_is_empty( fd_vote_authorized_voters_t * self );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L80
int
fd_authorized_voters_contains( fd_vote_authorized_voters_t * self, ulong epoch );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L72
fd_vote_authorized_voter_t *
fd_authorized_voters_last( fd_vote_authorized_voters_t * self );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L43
void
fd_authorized_voters_purge_authorized_voters( fd_vote_authorized_voters_t * self,
                                              ulong                         current_epoch );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L91
fd_vote_authorized_voter_t *
fd_authorized_voters_get_or_calculate_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                                  ulong                         epoch,
                                                                  int *                         existed );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/authorized_voters.rs#L28
fd_vote_authorized_voter_t *
fd_authorized_voters_get_and_cache_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                               ulong                         epoch );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L707-L715 */
int
fd_authorized_voters_get_and_update_authorized_voter( fd_vote_state_versioned_t * self,
                                                      ulong                       current_epoch,
                                                      fd_pubkey_t **              pubkey /* out */ );

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_authorized_voters_h */

