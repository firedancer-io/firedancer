#include "fd_vote_common.h"

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

