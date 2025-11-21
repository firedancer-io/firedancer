#include "fd_vote_lockout.h"
#include "../fd_vote_program.h"

/**********************************************************************/
/* impl Lockout                                                       */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L104
ulong
fd_vote_lockout_get_lockout( fd_vote_lockout_t * self ) {
  /* Confirmation count can never be greater than MAX_LOCKOUT_HISTORY, preventing overflow.
     Although Agave does not consider overflow, we do for fuzzing conformance. */
  ulong confirmation_count = fd_ulong_min( self->confirmation_count, MAX_LOCKOUT_HISTORY );
  return 1UL<<confirmation_count;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L110
ulong
fd_vote_lockout_last_locked_out_slot( fd_vote_lockout_t * self ) {
  return fd_ulong_sat_add( self->slot, fd_vote_lockout_get_lockout( self ) );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L114
ulong
fd_vote_lockout_is_locked_out_at_slot( fd_vote_lockout_t * self, ulong slot ) {
  return fd_vote_lockout_last_locked_out_slot( self ) >= slot;
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L122
void
fd_vote_lockout_increase_confirmation_count( fd_vote_lockout_t * self, uint by ) {
  self->confirmation_count = fd_uint_sat_add( self->confirmation_count, by );
}

