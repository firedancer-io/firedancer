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

#include "fd_progcache_rec.h"
#include "fd_prog_load.h"
#include "../accdb/fd_accdb_base.h"
#include "../runtime/fd_runtime_const.h"
#include "../../funk/fd_funk.h"

#define FD_PROGCACHE_DEPTH_MAX (128UL)

struct fd_progcache_metrics {
  ulong fork_switch_cnt;
  ulong miss_cnt;
  ulong hit_cnt;
  ulong hit_tot_sz;
  ulong fill_cnt;
  ulong fill_tot_sz;
  ulong fill_fail_cnt;
  ulong dup_insert_cnt;
  ulong invalidate_cnt;
};

typedef struct fd_progcache_metrics fd_progcache_metrics_t;

/* fd_progcache_t is a thread-local client to a program cache funk
   instance.  This struct is quite large and therefore not local/stack
   declaration-friendly. */

struct fd_progcache {
  fd_funk_t funk[1];

  /* Current fork cache */
  fd_funk_txn_xid_t fork[ FD_PROGCACHE_DEPTH_MAX ];
  ulong             fork_depth;

  fd_progcache_metrics_t * metrics;

  uchar * scratch;
  ulong   scratch_sz;
};

typedef struct fd_progcache fd_progcache_t;

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

/* fd_progcache_join joins the caller to a program cache funk instance.
   scratch points to a FD_PROGCACHE_SCRATCH_ALIGN aligned scratch buffer
   and scratch_sz is the size of the largest program/ELF binary that is
   going to be loaded (typically max account data sz). */

fd_progcache_t *
fd_progcache_join( fd_progcache_t * ljoin,
                   void *           shfunk,
                   uchar *          scratch,
                   ulong            scratch_sz );

#define FD_PROGCACHE_SCRATCH_ALIGN     (64UL)
#define FD_PROGCACHE_SCRATCH_FOOTPRINT FD_RUNTIME_ACC_SZ_MAX

/* fd_progcache_leave detaches the caller from a program cache. */

void *
fd_progcache_leave( fd_progcache_t * cache,
                    void **          opt_shfunk );

/* Record-level operations ********************************************/

/* fd_progcache_peek queries the program cache for an existing cache
   entry.  Does not fill the cache.  Returns a pointer to the entry on
   cache hit (invalidated by the next non-const API call).  Returns NULL
   on cache miss. */

fd_progcache_rec_t const *
fd_progcache_peek( fd_progcache_t *          cache,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr,
                   ulong                     epoch_slot0 );

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
   Or it returns  */

fd_progcache_rec_t const *
fd_progcache_pull( fd_progcache_t *           cache,
                   fd_accdb_user_t *          accdb,
                   fd_funk_txn_xid_t const *  xid,
                   void const *               prog_addr,
                   fd_prog_load_env_t const * env );

/* fd_progcache_invalidate marks the program at the given address as
   invalidated (typically due to a change of program content).  This
   creates a non-executable cache entry at the given xid.

   After a program has been invalidated at xid, it is forbidden to pull
   the same entry at the same xid.  (Invalidations should happen after
   replaying transactions).

   Assumes that xid is a valid fork graph node (not rooted) until
   invalidate returns. */

fd_progcache_rec_t const *
fd_progcache_invalidate( fd_progcache_t *          cache,
                         fd_funk_txn_xid_t const * xid,
                         void const *              prog_addr,
                         ulong                     slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_progcache_h */
