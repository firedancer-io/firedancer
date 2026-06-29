#ifndef HEADER_fd_src_discof_backup_fd_backup_visited_h
#define HEADER_fd_src_discof_backup_fd_backup_visited_h

#include "../../util/fd_util.h"

#define SET_NAME visited_set
#include "../../util/tmpl/fd_set_dynamic.c"

static inline int
fd_backup_visited_test( visited_set_t const * set,
                        ulong                 idx ) {
  FD_DCHECK_CRIT( visited_set_valid_idx( set, idx ), "idx out of bounds" );
  ulong word = __atomic_load_n( &set[ idx>>6 ], __ATOMIC_ACQUIRE );
  return (int)( ( word >> (idx & 63UL) ) & 1UL );
}

static inline void
fd_backup_visited_insert( visited_set_t * set,
                          ulong           idx ) {
  FD_DCHECK_CRIT( visited_set_valid_idx( set, idx ), "idx out of bounds" );
  FD_ATOMIC_FETCH_AND_OR( &set[ idx>>6 ], 1UL << (idx & 63UL) );
}

static inline void
fd_backup_visited_remove( visited_set_t * set,
                          ulong           idx ) {
  FD_DCHECK_CRIT( visited_set_valid_idx( set, idx ), "idx out of bounds" );
  FD_ATOMIC_FETCH_AND_AND( &set[ idx>>6 ], ~(1UL << (idx & 63UL)) );
}

#endif /* HEADER_fd_src_discof_backup_fd_backup_visited_h */
