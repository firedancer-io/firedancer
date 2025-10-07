#ifndef HEADER_fd_src_flamenco_fd_progcache_h
#define HEADER_fd_src_flamenco_fd_progcache_h

/* fd_progcache.h provides an API for managing a cache of loaded
   Solana on-chain program.

   ### Background

   Solana on-chain programs are rarely updated but frequently executed.
   Before a program can be executed, it must be loaded and verified,
   which is costly.

   ### Fork management

   The program cache is fork-aware (using funk transactions).  Txn-level
   operations take an exclusive lock over the cache (record ops are
   stalled indefinitely until the txn completes).

   ### Cache entry

   Each Solana program can have a number of program cache entries
   (typically only zero or one, in rare cases where the program content
   differs across forks multiple).

   A cache entry consists of a funk_rec object (from a preallocated
   object pool), and a variable-sized fd_progcache_entry struct
   (from an fd_alloc heap).

   ### Cache fill policy

   fd_progcache is lazily filled on reads, and eagerly invalidated
   if underlying programs are written to.

   ### Cache evict policy

   Cache eviction (i.e. force removal of potentially useful records)
   happens on fill.  Specifically, cache eviction is triggered when a
   cache fill fails to allocate from the wksp (fd_alloc) heap.

   fd_progcache further has a concept of "generations" (gen).  Each
   cache fill operation specifies a 'gen' number.  Only entries with a
   lower 'gen' number may get evicted.

   ### Garbage collect policy

   fd_progcache cleans up unused entries eagerly when:

   1. a database fork is cancelled (e.g. slot is rooted and competing
      history dies, or consensus layer prunes a fork)
   2. a cache entry is orphaned (updated or invalidated by an epoch
      boundary)

   ### Concurrency

   fd_progcache does not support concurrent access.  This may change in
   the future. */

#include "../fd_flamenco_base.h"
#include "fd_progcache_rec.h"
#include "../../funk/fd_funk.h"

struct fd_progcache {
  fd_funk_t funk[1];
};

typedef struct fd_progcache fd_progcache_t;

struct fd_progcache_metrics {
  ulong rec_oom;
  ulong val_oom;
  ulong evict_scan;
  ulong evict;
};

typedef struct fd_progcache_metrics fd_progcache_metrics_t;

FD_PROTOTYPES_BEGIN

extern FD_TL fd_progcache_metrics_t   fd_progcache_metrics_default;
extern FD_TL fd_progcache_metrics_t * fd_progcache_metrics_cur; /* = &fd_progcache_metrics_default; */

/* fd_progcache_est_rec_max estimates the fd_funk rec_max parameter
   given the cache's wksp footprint and mean cache entry heap
   utilization. */

ulong
fd_progcache_est_rec_max( ulong wksp_footprint,
                          ulong mean_cache_entry_size );

/* fd_progcache_join joins the caller to a program cache funk instance. */

fd_progcache_t *
fd_progcache_join( fd_progcache_t * ljoin,
                   void *           shfunk );

/* fd_progcache_leave detaches the caller from a program cache. */

void *
fd_progcache_leave( fd_progcache_t * cache,
                    void **          opt_shfunk );

/* fd_progcache_peek queries the program cache for an existing cache
   entry.  Does not fill the cache.  Returns a pointer to the entry on
   cache hit (invalidated by the next non-const API call).  Returns NULL
   on cache miss. */

fd_progcache_rec_t const *
fd_progcache_peek( fd_progcache_t const *    cache,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr );

/* fd_progcache_pull does a cache fill (on cache miss) or returns an
   existing cache entry (on cache hit).  Returns a pointer to the cache
   entry (invalidated by an API call with a higher gen number). */

fd_progcache_rec_t const *
fd_progcache_pull( fd_progcache_t *          cache,
                   fd_funk_t *               accdb,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr,
                   ulong                     gen,
                   fd_bank_t const *         bank );

/* fd_progcache_invalidate marks the program at the given address as
   invalidated (typically due to a change of program content).  This
   creates a non-executable cache entry at the given xid. */

fd_progcache_rec_t const *
fd_progcache_invalidate( fd_progcache_t *          cache,
                         fd_funk_txn_xid_t const * xid,
                         void const *              prog_addr,
                         ulong                     slot,
                         ulong                     gen );

/* fd_progcache_flush removes all cache entries while leaving the txn
   graph intact. */

void
fd_progcache_reset( fd_progcache_t * cache );

/* fd_progcache_clear removes all cache entries and destroys the txn
   graph. */

void
fd_progcache_clear( fd_progcache_t * cache );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_progcache_h */
