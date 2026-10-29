#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h

#include "fd_progcache.h"
#include "../accdb/fd_accdb.h"

union fd_features;
typedef union fd_features fd_features_t;

struct fd_progcache_admin_metrics {
  ulong root_cnt;
};

typedef struct fd_progcache_admin_metrics fd_progcache_admin_metrics_t;

extern FD_TL fd_progcache_admin_metrics_t fd_progcache_admin_metrics_g;

FD_PROTOTYPES_BEGIN

/* Fork-level operations **********************************************

   progcache does not keep a fork graph: forks are accdb forks, created
   with fd_accdb_attach_child.  The caller reports rooting and
   cancellation so progcache can retire a fork's records.  Both must be
   reported before the matching accdb call (fd_accdb_advance_root /
   fd_accdb_purge), while the fork ids involved are still live in accdb.
   accdb may recycle a fork id only after that, and progcache relies on
   that ordering to never mistake a recycled fork id for the old fork.

   txn.rwlock (write) serializes these against inserts and eviction. */

/* fd_progcache_root_fork detaches the records inserted on fork_id: they
   become rooted and visible on every fork.  fork_id is the accdb fork
   being rooted, i.e. a direct child of the current accdb root.  Its
   siblings (and their subtrees) are not rooted; the caller cancels
   them separately with fd_progcache_cancel_fork, the same way accdb
   purges them implicitly. */

void
fd_progcache_root_fork( fd_progcache_join_t * cache,
                        fd_accdb_t const *    accdb,
                        fd_accdb_fork_id_t    fork_id );

/* fd_progcache_cancel_fork removes the records inserted on fork_id and
   on every live descendant of fork_id. */

void
fd_progcache_cancel_fork( fd_progcache_join_t * cache,
                          fd_accdb_t const *    accdb,
                          fd_accdb_fork_id_t    fork_id );

/* fd_progcache_advance_root roots fork_id and cancels every fork that
   does not descend from it (fork_id's siblings and their subtrees).
   fork_id must be a direct child of the current accdb root.  This is
   the progcache counterpart of fd_accdb_advance_root and must be
   called right before it. */

void
fd_progcache_advance_root( fd_progcache_join_t * cache,
                           fd_accdb_t const *    accdb,
                           fd_accdb_fork_id_t    fork_id );

/* fd_progcache_reset removes all cache entries and clears the fork
   table.  Does not support concurrent usage. */

void
fd_progcache_reset( fd_progcache_join_t * cache );

/* fd_progcache_verify checks the structural integrity of the program
   cache.  Returns 0 on success, -1 on failure.  Logs warnings
   describing the first detected issue.  Assumes no concurrent
   modifications. */

__attribute__((warn_unused_result))
int
fd_progcache_verify( fd_progcache_join_t * join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h */
