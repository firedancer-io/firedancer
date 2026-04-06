#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h

#include "fd_progcache.h"

struct fd_account_meta;
typedef struct fd_account_meta fd_account_meta_t;

union fd_features;
typedef union fd_features fd_features_t;

struct fd_progcache_admin_metrics {
  ulong gc_root_cnt;
  ulong root_cnt;
};

typedef struct fd_progcache_admin_metrics fd_progcache_admin_metrics_t;

extern FD_TL fd_progcache_admin_metrics_t fd_progcache_admin_metrics_g;

FD_PROTOTYPES_BEGIN

/* Constructors *******************************************************/

/* fd_progcache_est_rec_max estimates the fd_funk rec_max parameter
   given the cache's wksp footprint and mean cache entry heap
   utilization. */

ulong
fd_progcache_est_rec_max( ulong wksp_footprint,
                          ulong mean_cache_entry_size );

/* Transaction-level operations ***************************************/

/* fd_progcache_attach_child creates a new program cache fork node
   off some parent.

   It is assumed that less than txn_max non-root transactions exist when
   this is called. */

void
fd_progcache_attach_child( fd_progcache_join_t * cache,
                           fd_xid_t const *      xid_parent,
                           fd_xid_t const *      xid_new );

/* fd_progcache_advance_root advances the fork graph root to the
   given xid.  (In funk terminology, this is the "last publish")

   xid must be the first nonrooted slot: its parent in the fork graph
   must be the current root (no parent nodes).  Aborts on violation. */

void
fd_progcache_advance_root( fd_progcache_join_t * cache,
                           fd_xid_t const *      xid );

/* fd_progcache_cancel removes a fork graph node by XID and its
   children (recursively). */

void
fd_progcache_cancel( fd_progcache_join_t * cache,
                     fd_xid_t const *      xid );

/* Reset operations ***************************************************/

/* fd_progcache_reset removes all cache entries while leaving the txn
   graph intact.  Does not support concurrent usage. */

void
fd_progcache_reset( fd_progcache_join_t * cache );

/* fd_progcache_clear removes all cache entries and destroys the txn
   graph.  Does not support concurrent usage. */

void
fd_progcache_clear( fd_progcache_join_t * cache );

/* fd_progcache_verify checks the structural integrity of the program
   cache.  Returns 0 on success, -1 on failure.  Logs warnings
   describing the first detected issue.  Assumes no concurrent
   modifications. */

__attribute__((warn_unused_result))
int
fd_progcache_verify( fd_progcache_join_t * join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h */
