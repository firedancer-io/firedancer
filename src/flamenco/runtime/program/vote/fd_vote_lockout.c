#include "fd_vote_lockout.h"
#include "../fd_vote_program.h"

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

fd_landed_vote_t *
fd_vote_lockout_landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                                            uchar *             mem ) {
  if( !lockouts ) return NULL;

  /* Allocate MAX_LOCKOUT_HISTORY (sane case) by default.  In case the
     vote account is corrupt, allocate as many entries are needed. */

  ulong cnt = deq_fd_vote_lockout_t_cnt( lockouts );
        cnt = fd_ulong_max( cnt, MAX_LOCKOUT_HISTORY );

  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_join( deq_fd_landed_vote_t_new( mem, cnt ) );
  if( FD_UNLIKELY( !landed_votes ) ) {
    FD_LOG_CRIT(( "failed to join landed votes" ));
  }

  for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( lockouts );
       !deq_fd_vote_lockout_t_iter_done( lockouts, iter );
       iter = deq_fd_vote_lockout_t_iter_next( lockouts, iter ) ) {
    fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( lockouts, iter );

    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( landed_votes );
    fd_landed_vote_new( elem );

    elem->latency                    = 0;
    elem->lockout.slot               = ele->slot;
    elem->lockout.confirmation_count = ele->confirmation_count;
  }

  return landed_votes;
}
