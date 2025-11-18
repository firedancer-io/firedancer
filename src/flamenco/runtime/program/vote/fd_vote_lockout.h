#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_lockout_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_lockout_h

#include "../../../types/fd_types.h"
#include "../../../../util/fd_util_base.h"

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L104
ulong
fd_vote_lockout_get_lockout( fd_vote_lockout_t * self );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L110
ulong
fd_vote_lockout_last_locked_out_slot( fd_vote_lockout_t * self );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L114
ulong
fd_vote_lockout_is_locked_out_at_slot( fd_vote_lockout_t * self, ulong slot );

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L122
void
fd_vote_lockout_increase_confirmation_count( fd_vote_lockout_t * self, uint by );

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L1009-L1011 */
fd_landed_vote_t *
fd_vote_lockout_landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                                            uchar *             mem );

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_lockout_h */

