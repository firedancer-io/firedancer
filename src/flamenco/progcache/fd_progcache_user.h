#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_user_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_user_h

/* fd_progcache_user.h provides an API for managing a cache of loaded
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
      boundary) */

#include "fd_progcache.h"
#include "fd_prog_load.h"
#include "../runtime/fd_runtime_const.h"

struct fd_progcache_metrics {
  ulong lookup_cnt;
  ulong hit_cnt;
  ulong miss_cnt;
  ulong oom_heap_cnt;
  ulong oom_desc_cnt;
  ulong fill_cnt;
  ulong fill_tot_sz;
  ulong spill_cnt;
  ulong spill_tot_sz;
  ulong evict_cnt;
  ulong evict_tot_sz;
  ulong cum_pull_ticks;
  ulong cum_load_ticks;
};

typedef struct fd_progcache_metrics fd_progcache_metrics_t;

/* fd_progcache_t is a thread-local client to a program cache funk
   instance.  This struct is quite large and therefore not local/stack
   declaration-friendly. */

struct fd_progcache {
  fd_progcache_join_t join[1];
  fd_accdb_lineage_t  lineage[1];

  fd_progcache_metrics_t * metrics;

  uchar * scratch;
  ulong   scratch_sz;

  uint spill_active;
};

FD_PROTOTYPES_BEGIN

extern FD_TL fd_progcache_metrics_t fd_progcache_metrics_default;

/* Constructor */

static inline ulong
fd_progcache_align( void ) {
  return alignof(fd_progcache_t);
}

static inline ulong
fd_progcache_footprint( void ) {
  return sizeof(fd_progcache_t);
}

static inline fd_progcache_t *
fd_progcache_new( void * ljoin ) {
  return ljoin;
}

static inline void *
fd_progcache_delete( void * ljoin ) {
  return ljoin;
}

/* fd_progcache_join joins the caller to a program cache shmem instance.
   scratch points to a FD_PROGCACHE_SCRATCH_ALIGN aligned scratch buffer
   and scratch_sz is the size of the largest program/ELF binary that is
   going to be loaded (typically max account data sz). */

fd_progcache_t *
fd_progcache_join( fd_progcache_t *       ljoin,
                   fd_progcache_shmem_t * shmem,
                   uchar *                scratch,
                   ulong                  scratch_sz );

#define FD_PROGCACHE_SCRATCH_ALIGN     (64UL)
#define FD_PROGCACHE_SCRATCH_FOOTPRINT FD_RUNTIME_ACC_SZ_MAX

/* fd_progcache_leave detaches the caller from a program cache. */

void *
fd_progcache_leave( fd_progcache_t *        cache,
                    fd_progcache_shmem_t ** opt_shmem );

/* fd_progcache_revision_slot returns the slot number under which a
   progcache entry is indexed at.  epoch_slot0 is the first slot number
   of the epoch.  deploy_slot is the slot at which the program was
   deployed using the program loader. */

static inline ulong
fd_progcache_revision_slot( ulong epoch_slot0,
                            ulong deploy_slot ) {
  return fd_ulong_max( epoch_slot0, deploy_slot );
}

/* fd_progcache_peek queries the program cache for an existing cache
   entry.  Does not fill the cache.  Returns a pointer to the entry on
   cache hit.  Returns NULL on cache miss.  It is the caller's
   responsibility to release the returned record with
   fd_progcache_rec_close. */

fd_progcache_rec_t * /* read locked */
fd_progcache_peek( fd_progcache_t *          cache,
                   fd_xid_t const * xid,
                   void const *              prog_addr,
                   ulong                     revision_slot );

/* fd_progcache_pull loads a program from cache, filling the cache if
   necessary.  The load operation can have a number of outcomes:
   - Returns a pointer to an existing cache entry (cache hit, state
     either "Loaded" or "FailedVerification")
   - Returns a pointer to a newly created cache entry (cache fill,
     state either "Loaded" or "FailedVerification")
   - Returns NULL if the requested program account is not deployed (i.e.
     account is missing, the program is under visibility delay, or user
     has not finished uploading the program)
   In other words, this method guarantees to return a cache entry if a
   deployed program was found in the account database, and the program
   either loaded successfully, or failed ELF/bytecode verification.
   It is the caller's responsibility to release the returned record with
   fd_progcache_rec_close. */

fd_progcache_rec_t * /* read locked */
fd_progcache_pull( fd_progcache_t *           cache,
                   fd_xid_t const *           xid,
                   void const *               prog_addr,
                   fd_prog_load_env_t const * env,
                   fd_accdb_ro_t *            progdata_ro );

/* fd_progcache_rec_close releases a cache record handle returned by
   fd_progcache_{pull,peek}. */

void
fd_progcache_rec_close( fd_progcache_t *     cache,
                        fd_progcache_rec_t * rec );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_user_h */
