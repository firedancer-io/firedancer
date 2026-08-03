#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_user_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_user_h

/* fd_progcache_user.h provides an API for managing a cache of loaded
   Solana on-chain program.

   ### Background

   Solana on-chain programs are rarely updated but frequently executed.
   Before a program can be executed, it must be loaded and verified,
   which is costly.

   ### Fork management

   The program cache is fork-aware (using transactions).  Txn-level
   operations (attach/publish/cancel) take the fork graph's exclusive
   lock; record reads never block on it, and inserts hold it shared only
   while publishing.

   ### Cache entry

   Each Solana program can have a number of program cache entries
   (typically only zero or one, in rare cases where the program content
   differs across forks multiple).

   A cache entry is a progcache_rec object.  Records are partitioned by
   size class and double as value slots: an executable entry's program
   data lives in its own class's arena slot (see fd_progcache.h).

   ### Cache fill policy

   fd_progcache is lazily filled on reads.  Writes do not invalidate
   the cache; coherence comes from keying records on deploy_slot plus
   fork cancel, and from the BPF loader's pd_write gate failing an
   invoke before fd_progcache_pull if the programdata was superseded
   this slot.

   ### Cache evict policy

   Cache eviction (i.e. force removal of potentially useful records)
   happens on fill: when a fill finds its size class full, it evicts
   within that class (per-class CLOCK), and falls back to the spill
   scratch if no record frees up.

   ### Garbage collect policy

   fd_progcache cleans up unused entries eagerly when:

   1. a database fork is cancelled (e.g. slot is rooted and competing
      history dies, or consensus layer prunes a fork)
   2. a cache entry is orphaned (updated or invalidated by an epoch
      boundary) */

#include "fd_progcache.h"
#include "fd_prog_load.h"
#include "fd_progcache_lineage.h"
#include "../runtime/fd_runtime_const.h"

struct fd_progcache_metrics {
  ulong lookup_cnt;
  ulong hit_cnt;
  ulong miss_cnt;
  ulong class_full_cnt;
  ulong fill_cnt;
  ulong fill_tot_sz;
  ulong spill_cnt;
  ulong spill_tot_sz;
  ulong evict_cnt;
  ulong evict_tot_sz;
  ulong cum_pull_ticks;
  ulong cum_load_ticks;

  /* Per-size-class breakdowns.  Non-executable entries are attributed to
     the nx class, so all four arrays span the same classes. */
  ulong hit_per_class  [ FD_PROGCACHE_CLASS_CNT ];
  ulong fill_per_class [ FD_PROGCACHE_CLASS_CNT ];
  ulong evict_per_class[ FD_PROGCACHE_CLASS_CNT ];
  ulong spill_per_class[ FD_PROGCACHE_CLASS_CNT ];
};

typedef struct fd_progcache_metrics fd_progcache_metrics_t;

/* FD_PROGCACHE_METRICS_WRITE publishes the per-joiner progcache metrics
   for tile prefix TILE.  TILE must declare the ProgcacheLookup/... and
   ProgcacheClass* counters in metrics.xml (e.g. EXECLE, EXECRP).  m must
   be a fd_progcache_metrics_t const * for the joiner whose counters
   should be published.  The caller supplies fd_metrics.h. */

#define FD_PROGCACHE_METRICS_WRITE( TILE, m ) do {                                    \
    fd_progcache_metrics_t const * _m = (m);                                          \
    FD_MCNT_SET( TILE, PROGCACHE_LOOKUP,                _m->lookup_cnt      );        \
    FD_MCNT_SET( TILE, PROGCACHE_HIT,                   _m->hit_cnt         );        \
    FD_MCNT_SET( TILE, PROGCACHE_MISS,                  _m->miss_cnt        );        \
    FD_MCNT_SET( TILE, PROGCACHE_CLASS_FULL,            _m->class_full_cnt  );        \
    FD_MCNT_SET( TILE, PROGCACHE_FILL,                  _m->fill_cnt        );        \
    FD_MCNT_SET( TILE, PROGCACHE_FILL_BYTES,            _m->fill_tot_sz     );        \
    FD_MCNT_SET( TILE, PROGCACHE_SPILL,                 _m->spill_cnt       );        \
    FD_MCNT_SET( TILE, PROGCACHE_SPILL_BYTES,           _m->spill_tot_sz    );        \
    FD_MCNT_SET( TILE, PROGCACHE_EVICTION,              _m->evict_cnt       );        \
    FD_MCNT_SET( TILE, PROGCACHE_EVICTION_BYTES,        _m->evict_tot_sz    );        \
    FD_MCNT_SET( TILE, PROGCACHE_DURATION_SECONDS,      _m->cum_pull_ticks  );        \
    FD_MCNT_SET( TILE, PROGCACHE_LOAD_DURATION_SECONDS, _m->cum_load_ticks  );        \
    FD_MCNT_ENUM_COPY( TILE, PROGCACHE_CLASS_HIT,      _m->hit_per_class   );         \
    FD_MCNT_ENUM_COPY( TILE, PROGCACHE_CLASS_FILL,     _m->fill_per_class  );         \
    FD_MCNT_ENUM_COPY( TILE, PROGCACHE_CLASS_EVICTION, _m->evict_per_class );         \
    FD_MCNT_ENUM_COPY( TILE, PROGCACHE_CLASS_SPILL,    _m->spill_per_class );         \
  } while(0)

/* fd_progcache_t is a thread-local client to a program cache instance.
   This struct is quite large and therefore not local/stack
   declaration-friendly. */

struct fd_progcache {
  fd_progcache_join_t join[1];
  fd_progcache_lineage_t lineage[1];

  fd_progcache_metrics_t * metrics;

  uchar * scratch;
  ulong   scratch_sz;

  uint spill_active;
};

FD_PROTOTYPES_BEGIN

extern FD_TL fd_progcache_metrics_t fd_progcache_metrics_default;

/* Constructor */

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

/* fd_progcache_leave detaches the caller from a program cache, first draining
   the shared reclaim list so no record is left orphaned outside the map.
   Long-lived tiles never detach; workspace teardown releases the cache. */

void *
fd_progcache_leave( fd_progcache_t *        cache,
                    fd_progcache_shmem_t ** opt_shmem );

/* fd_progcache_peek queries the program cache for an existing cache
   entry.  Does not fill the cache.  Returns a pointer to the entry on
   cache hit.  Returns NULL on cache miss.  It is the caller's
   responsibility to release the returned record with
   fd_progcache_rec_close. */

fd_progcache_rec_t * /* read locked */
fd_progcache_peek( fd_progcache_t *       cache,
                   fd_progcache_fork_id_t fork_id,
                   fd_pubkey_t const *    prog_addr,
                   ulong                  feature_slot,
                   ulong                  deploy_slot );

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
                   fd_progcache_fork_id_t     fork_id,
                   fd_pubkey_t const *        prog_addr,
                   fd_prog_load_env_t const * env,
                   fd_acc_t const *           progdata_ro );

/* fd_progcache_rec_close releases a cache record handle returned by
   fd_progcache_{pull,peek}. */

void
fd_progcache_rec_close( fd_progcache_t *     cache,
                        fd_progcache_rec_t * rec );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_user_h */
