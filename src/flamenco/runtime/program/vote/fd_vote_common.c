#include "fd_vote_common.h"
#include "../fd_vote_program.h"
#include "../fd_program_util.h"

int
fd_vote_verify_authorized_signer( fd_pubkey_t const * authorized,
                                  fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L989
  return fd_signers_contains( signers, authorized ) ?
    FD_EXECUTOR_INSTR_SUCCESS :
    FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

int
fd_vote_signature_verify( fd_pubkey_t *       epoch_authorized_voter,
                          int                 authorized_withdrawer_signer,
                          fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] ) {
  return authorized_withdrawer_signer ? 0 : fd_vote_verify_authorized_signer( epoch_authorized_voter, signers );
}

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L668
uchar
fd_vote_compute_vote_latency( ulong voted_for_slot, ulong current_slot ) {
  return (uchar)fd_ulong_min( fd_ulong_sat_sub( current_slot, voted_for_slot ), UCHAR_MAX );
}

ulong
fd_vote_credits_for_vote_at_index( fd_landed_vote_t const * votes,
                                   ulong                    index ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L679
  fd_landed_vote_t const * landed_vote = deq_fd_landed_vote_t_peek_index_const( votes, index );
  ulong                    latency     = landed_vote == NULL ? 0 : landed_vote->latency;
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L683
  ulong              max_credits =  VOTE_CREDITS_MAXIMUM_PER_SLOT;

  // If latency is 0, this means that the Lockout was created and stored from a software version
  // that did not store vote latencies; in this case, 1 credit is awarded
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L691
  if( FD_UNLIKELY( latency == 0 ) ) {
    return 1;
  }

  ulong diff = 0;
  int   cf   = fd_ulong_checked_sub( latency, VOTE_CREDITS_GRACE_SLOTS, &diff );
  if( cf != 0 || diff == 0 ) {
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

uchar
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
