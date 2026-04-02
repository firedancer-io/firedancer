#include "fd_vote_utils.h"
#include "fd_vote_codec.h"
#include "../fd_vote_program.h"
#include "../fd_program_util.h"

/**********************************************************************/
/* Lockout utilities                                                  */
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

fd_landed_vote_t *
fd_vote_lockout_landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                                            uchar *             mem ) {
  if( !lockouts ) return NULL;

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

    elem->latency                    = 0;
    elem->lockout.slot               = ele->slot;
    elem->lockout.confirmation_count = ele->confirmation_count;
  }

  return landed_votes;
}

/**********************************************************************/
/* Vote state utilities                                               */
/**********************************************************************/

int
fd_vote_verify_authorized_signer( fd_pubkey_t const * authorized,
                                  fd_pubkey_t const * signers[static FD_TXN_SIG_MAX],
                                  ulong               signers_cnt ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L989
  return fd_signers_contains( signers, signers_cnt, authorized ) ?
    FD_EXECUTOR_INSTR_SUCCESS :
    FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

int
fd_vote_signature_verify( fd_pubkey_t *       epoch_authorized_voter,
                          int                 authorized_withdrawer_signer,
                          fd_pubkey_t const * signers[static FD_TXN_SIG_MAX],
                          ulong               signers_cnt ) {
  return authorized_withdrawer_signer ? 0 : fd_vote_verify_authorized_signer( epoch_authorized_voter, signers, signers_cnt );
}

uchar
fd_vote_compute_vote_latency( ulong voted_for_slot,
                              ulong current_slot ) {
  return (uchar)fd_ulong_min( fd_ulong_sat_sub( current_slot, voted_for_slot ), UCHAR_MAX );
}

ulong
fd_vote_credits_for_vote_at_index( fd_landed_vote_t const * votes,
                                   ulong                    index ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L679
  fd_landed_vote_t const * landed_vote = deq_fd_landed_vote_t_peek_index_const( votes, index );
  ulong                    latency     = landed_vote == NULL ? 0 : landed_vote->latency;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L683
  ulong                    max_credits =  VOTE_CREDITS_MAXIMUM_PER_SLOT;

  /* If latency is 0, this means that the Lockout was created and stored
     from a software version that did not store vote latencies; in this
     case, 1 credit is awarded.
     https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L691 */
  if( FD_UNLIKELY( latency==0UL ) ) {
    return 1;
  }

  ulong diff = 0;
  int   cf   = fd_ulong_checked_sub( latency, VOTE_CREDITS_GRACE_SLOTS, &diff );
  if( cf || diff==0UL ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L697
    return max_credits;
  }

  ulong credits = 0;
  cf = fd_ulong_checked_sub( max_credits, diff, &credits );
  if( cf != 0 || credits == 0 ) {
    // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L705
    return 1;
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L707
  return credits;
}

int
fd_vote_contains_slot( fd_landed_vote_t const * votes,
                       ulong                    slot ) {
  /* Logic is copied from slice::binary_search_by() in Rust. While not fully optimized,
     it aims to achieve fuzzing conformance for both sorted and unsorted inputs. */
  ulong size = deq_fd_landed_vote_t_cnt( votes );
  if( FD_UNLIKELY( size==0UL ) ) return 0;

  ulong base = 0UL;
  while( size>1UL ) {
    ulong half = size / 2UL;
    ulong mid = base + half;
    ulong mid_slot = deq_fd_landed_vote_t_peek_index_const( votes, mid )->lockout.slot;
    base = (slot<mid_slot) ? base : mid;
    size -= half;
  }

  return deq_fd_landed_vote_t_peek_index_const( votes, base )->lockout.slot==slot;
}
