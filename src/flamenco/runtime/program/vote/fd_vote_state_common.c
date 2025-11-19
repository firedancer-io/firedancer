#include "fd_vote_state_common.h"

int
fd_vote_state_verify_authorized_signer( fd_pubkey_t const * authorized,
                                        fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] ) {
  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_state/mod.rs#L989
  return fd_signers_contains( signers, authorized ) ?
    FD_EXECUTOR_INSTR_SUCCESS :
    FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

int
fd_vote_state_verify( fd_pubkey_t *       epoch_authorized_voter,
                      int                 authorized_withdrawer_signer,
                      fd_pubkey_t const * signers[static FD_TXN_SIG_MAX] ) {
  if( authorized_withdrawer_signer )
    return 0;
  else
    return fd_vote_state_verify_authorized_signer( epoch_authorized_voter, signers );
}

