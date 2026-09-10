#ifndef HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h
#define HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h

#include "fd_stake_delegations.h"

/* Test-only introspection.  Production code should depend on delegation
   behavior, not the selected storage tier. */

static inline ulong
fd_stake_delegations_base_cnt( fd_stake_delegations_t const * stake_delegations ) {
  ulong cnt = 0UL;
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter =
         fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    cnt++;
  }
  return cnt;
}

static inline ulong
fd_stake_delegations_disk_cnt( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegations->disk_root_cnt_ + stake_delegations->disk_delta_cnt_;
}

static inline fd_stake_delegation_t const *
fd_stake_delegation_root_query( fd_stake_delegations_t const * stake_delegations,
                                fd_pubkey_t const *            stake_account ) {
  static FD_TL fd_stake_delegation_t delegation;
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter =
         fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * ele = fd_stake_delegations_iter_ele( iter );
    if( FD_LIKELY( memcmp( ele->stake_account.key, stake_account->key, sizeof(fd_pubkey_t) ) ) ) continue;
    delegation = *ele;
    return &delegation;
  }
  return NULL;
}

#endif /* HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h */
