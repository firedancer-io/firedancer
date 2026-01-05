#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h

#include "../../funk/fd_funk.h"

struct fd_account_meta;
typedef struct fd_account_meta fd_account_meta_t;

union fd_features;
typedef union fd_features fd_features_t;

struct fd_progcache_admin {
  fd_funk_t funk[1];

  struct {
    ulong root_cnt;
    ulong gc_root_cnt;
  } metrics;
};

typedef struct fd_progcache_admin fd_progcache_admin_t;

FD_PROTOTYPES_BEGIN

/* Constructors *******************************************************/

/* fd_progcache_est_rec_max estimates the fd_funk rec_max parameter
   given the cache's wksp footprint and mean cache entry heap
   utilization. */

ulong
fd_progcache_est_rec_max( ulong wksp_footprint,
                          ulong mean_cache_entry_size );

/* fd_progcache_join joins the caller to a program cache funk instance. */

fd_progcache_admin_t *
fd_progcache_admin_join( fd_progcache_admin_t * ljoin,
                         void *                 shfunk );

/* fd_progcache_admin_leave detaches the caller from a program cache. */

void *
fd_progcache_admin_leave( fd_progcache_admin_t * cache,
                          void **                opt_shfunk );

/* Transaction-level operations ***************************************/

/* fd_progcache_txn_attach_child creates a new program cache fork node
   off some parent.

   It is assumed that less than txn_max non-root transactions exist when
   this is called. */

void
fd_progcache_txn_attach_child( fd_progcache_admin_t *    cache,
                               fd_funk_txn_xid_t const * xid_parent,
                               fd_funk_txn_xid_t const * xid_new );

/* fd_progcache_txn_advance_root advances the fork graph root to the
   given xid.  (In funk terminology, this is the "last publish")

   Assumes that the xid's parent is the fork graph root. */

void
fd_progcache_txn_advance_root( fd_progcache_admin_t *    cache,
                               fd_funk_txn_xid_t const * xid );

/* fd_progcache_txn_cancel removes a fork graph node by XID and its
   children (recursively). */

void
fd_progcache_txn_cancel( fd_progcache_admin_t *    cache,
                         fd_funk_txn_xid_t const * xid );

/* Reset operations ***************************************************/

/* fd_progcache_flush removes all cache entries while leaving the txn
   graph intact.  Does not support concurrent usage. */

void
fd_progcache_reset( fd_progcache_admin_t * cache );

/* fd_progcache_clear removes all cache entries and destroys the txn
   graph.  Does not support concurrent usage. */

void
fd_progcache_clear( fd_progcache_admin_t * cache );

/* fd_progcache_verify does various expensive data structure integrity
   checks.  Assumes no concurrent users of progcache.  Collects stats
   along the way. */

void
fd_progcache_verify( fd_progcache_admin_t * cache );

/* TODO:FIXME: Add documentation. */

void
fd_progcache_inject_rec( fd_progcache_admin_t *    cache,
                         void const *              prog_addr,
                         fd_account_meta_t const * progdata_meta,
                         fd_features_t const *     features,
                         ulong                     slot,
                         uchar *                   scratch,
                         ulong                     scratch_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_admin_h */
