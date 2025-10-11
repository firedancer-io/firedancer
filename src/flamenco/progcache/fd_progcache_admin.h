#ifndef HEADER_fd_src_flamenco_fd_progcache_admin_h
#define HEADER_fd_src_flamenco_fd_progcache_admin_h

#include "../../funk/fd_funk.h"

struct fd_progcache_admin {
  fd_funk_t funk[1];
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

void
fd_progcache_txn_prepare( fd_progcache_admin_t *    cache,
                          fd_funk_txn_xid_t const * xid_parent,
                          fd_funk_txn_xid_t const * xid_new );

void
fd_progcache_txn_cancel( fd_progcache_admin_t * cache,
                         fd_funk_txn_xid_t const * xid );

void
fd_progcache_txn_publish( fd_progcache_admin_t *    cache,
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

FD_PROTOTYPES_END

/* Verify operations **************************************************/

struct fd_progcache_verify_stat {
  ulong txn_cnt;
  ulong rec_cnt;
};

typedef struct fd_progcache_verify_stat fd_progcache_verify_stat_t;

FD_PROTOTYPES_BEGIN

/* fd_progcache_verify does various expensive data structure integrity
   checks.  Assumes no concurrent users of progcache.  Collects stats
   along the way. */

void
fd_progcache_verify( fd_progcache_admin_t *       cache,
                     fd_progcache_verify_stat_t * out_stat );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_progcache_admin_h */
