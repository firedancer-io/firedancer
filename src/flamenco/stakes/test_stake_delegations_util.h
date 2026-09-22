#ifndef HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h
#define HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h

#include "fd_stake_delegations_private.h"
#include <sys/stat.h>

/* Allocation inspection requires quiescent writers.  Count actual
   descriptors rather than maintaining production telemetry for tests. */
static inline ulong
test_stake_delegations_record_cnt( fd_stake_delegations_t const * stake_delegations,
                                   uchar                          role ) {
  page_t const * pages = (page_t const *)((uchar const *)stake_delegations + stake_delegations->pages_offset);
  ulong cnt = 0UL;
  for( uint i=0U; i<stake_delegations->page_wmk; i++ ) {
    if( pages[i].role==role ) cnt += (ulong)fd_ulong_popcnt( pages[i].used[0] ) + (ulong)fd_ulong_popcnt( pages[i].used[1] );
  }
  return cnt;
}

static inline ulong
test_stake_delegations_page_cnt( fd_stake_delegations_t const * stake_delegations,
                                 int                            resident_only ) {
  page_t const * pages = (page_t const *)((uchar const *)stake_delegations + stake_delegations->pages_offset);
  ulong cnt = 0UL;
  for( uint i=0U; i<stake_delegations->page_wmk; i++ ) cnt += (ulong)(pages[i].role!=PAGE_FREE && (!resident_only || pages[i].frame!=UINT_MAX));
  return cnt;
}

static inline ulong
test_stake_delegations_fork_cnt( fd_stake_delegations_t const * stake_delegations ) {
  fork_t const * forks = (fork_t const *)((uchar const *)stake_delegations + stake_delegations->forks_offset);
  ulong cnt = 0UL;
  for( ulong i=0UL; i<stake_delegations->max_live_slots; i++ ) cnt += (ulong)!!forks[i].in_use;
  return cnt;
}

static inline ulong
test_stake_delegations_file_sz( fd_stake_delegations_t const * stake_delegations ) {
  struct stat st;
  FD_TEST( !fstat( stake_delegations->disk_fd, &st ) );
  return (ulong)st.st_size;
}

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
test_stake_delegations_base_cnt( fd_stake_delegations_t * stake_delegations ) {
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, stake_delegations, fd_stake_delegations_root_fork_id( stake_delegations ) );
  ulong cnt = test_stake_delegations_view_cnt( view );
  fd_stake_delegations_view_end( view );
  return cnt;
}

static inline int
test_stake_delegations_find_copy( fd_stake_delegations_t * stake_delegations, fd_pubkey_t const * stake_account, fd_stake_delegation_t * out ) {
  fd_stake_delegations_view_t view[1];
  fd_stake_delegations_view_begin( view, stake_delegations, fd_stake_delegations_root_fork_id( stake_delegations ) );
  int found = test_stake_delegations_view_find_copy( view, stake_account, out );
  fd_stake_delegations_view_end( view );
  return found;
}

static inline int
test_stake_delegations_contains( fd_stake_delegations_t * stake_delegations, fd_pubkey_t const * stake_account ) {
  return test_stake_delegations_find_copy( stake_delegations, stake_account, NULL );
}

#endif /* HEADER_fd_src_flamenco_stakes_test_stake_delegations_util_h */
