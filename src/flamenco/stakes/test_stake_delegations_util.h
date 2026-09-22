#ifndef HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h
#define HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h

#include "fd_stake_delegations.h"

/* Root helpers own a view.  Boundary tests which already hold a view
   use the view helpers to avoid nested structural read admission. */
static inline ulong
test_stake_delegations_view_cnt( fd_stake_delegations_view_t * view ) {
  ulong cnt = 0UL;
  fd_stake_delegations_iter_t iter[1];
  for( fd_stake_delegations_iter_init( iter, view ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) cnt++;
  return cnt;
}

static inline int
test_stake_delegations_view_find_copy( fd_stake_delegations_view_t * view,
                                        fd_pubkey_t const *         stake_account,
                                        fd_stake_delegation_t *      out ) {
  fd_stake_delegations_iter_t iter[1];
  for( fd_stake_delegations_iter_init( iter, view ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
    if( memcmp( &d->stake_account, stake_account, sizeof(fd_pubkey_t) ) ) continue;
    if( out ) *out = *d;
    return 1;
  }
  return 0;
}

static inline int
test_stake_delegations_view_contains( fd_stake_delegations_view_t * view, fd_pubkey_t const * stake_account ) {
  return test_stake_delegations_view_find_copy( view, stake_account, NULL );
}

static inline ulong
test_stake_delegations_base_cnt( fd_stake_delegations_t * sd ) {
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, fd_stake_delegations_root_fork_id( sd ) );
  ulong cnt = test_stake_delegations_view_cnt( view );
  fd_stake_delegations_view_end( view );
  return cnt;
}

static inline int
test_stake_delegations_find_copy( fd_stake_delegations_t * sd, fd_pubkey_t const * stake_account, fd_stake_delegation_t * out ) {
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, sd, fd_stake_delegations_root_fork_id( sd ) );
  int found = test_stake_delegations_view_find_copy( view, stake_account, out );
  fd_stake_delegations_view_end( view );
  return found;
}

static inline int
test_stake_delegations_contains( fd_stake_delegations_t * sd, fd_pubkey_t const * stake_account ) {
  return test_stake_delegations_find_copy( sd, stake_account, NULL );
}

#endif /* HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h */
