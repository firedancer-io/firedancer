#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_lineage_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_lineage_h

/* fd_progcache_lineage.h provides an API for filtering program cache
   records by fork graph lineage. */

#include "fd_progcache_base.h"

struct fd_progcache_lineage {

  /* Current fork cache */
  fd_progcache_fork_id_t fork[ FD_PROGCACHE_DEPTH_MAX ];
  ulong                  fork_depth;
  fd_progcache_fork_id_t root;

  uint txn_idx[ FD_PROGCACHE_DEPTH_MAX ];

  /* Cache of XIDs on fork */
  ulong tip_txn_idx; /* ==ULONG_MAX if tip is root */

  ulong max_depth;
};

#define FD_PROGCACHE_LINEAGE_FOOTPRINT (sizeof(fd_progcache_lineage_t))

typedef struct fd_progcache_lineage fd_progcache_lineage_t;

FD_PROTOTYPES_BEGIN

/* fd_progcache_lineage_has_xid returns 1 if the given record XID is part of
   the current lineage, otherwise 0. */

FD_FN_UNUSED static int
fd_progcache_lineage_has_xid( fd_progcache_lineage_t const * lineage,
                              fd_progcache_fork_id_t         rec_xid ) {
  ulong const fork_depth = lineage->fork_depth;
  if( rec_xid <= lineage->root ) return 1;
  for( ulong i=0UL; i<fork_depth; i++ ) {
    if( lineage->fork[i]==rec_xid ) return 1;
  }
  return 0;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_lineage_h */
