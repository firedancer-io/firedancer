#include "fd_cost_tracker_store.h"

#include <errno.h>
#include <unistd.h>

#define FD_COST_TRACKER_STORE_MAGIC (0xF17EDA2CC057B000UL) /* FIREDANCER COST TRACKER STORE V0 */

/* set_t is the metadata of one fork's cost tracker.  An acquired cost
   tracker that is not cached is on disk. */
struct set {
  ushort next;
  ushort cache_idx; /* USHORT_MAX if the cost tracker is not cached */
};
typedef struct set set_t;

#define POOL_NAME  set_pool
#define POOL_T     set_t
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

/* cache_ent_t is an in-memory slot holding one cost tracker, plus the
   bookkeeping needed to pin and evict it. */
struct cache_ent {
  ulong set_idx; /* ULONG_MAX if the entry is empty */
  ulong pin_cnt;
  ulong lru;
  uchar data[ FD_COST_TRACKER_FOOTPRINT ] __attribute__((aligned(FD_COST_TRACKER_ALIGN)));
};
typedef struct cache_ent cache_ent_t;

struct fd_cost_tracker_store {
  ulong magic;
  ulong cache_cnt;
  int   disk_fd;
  ulong bench_max_cost_per_block;
  ulong seed;
  ulong set_off;
  ulong cache_off;
  ulong lru;
};

static inline set_t *
sets( fd_cost_tracker_store_t const * store ) {
  return fd_type_pun( (uchar *)store + store->set_off );
}

static inline cache_ent_t *
cache( fd_cost_tracker_store_t const * store ) {
  return fd_type_pun( (uchar *)store + store->cache_off );
}

static inline set_t *
set_query( fd_cost_tracker_store_t const * store,
           ulong                           set_idx ) {
  set_t * pool = sets( store );
  FD_CHECK_CRIT( set_idx<set_pool_max( pool ), "invariant violation: invalid cost tracker set index" );
  return pool + set_idx;
}

static void
disk_read( fd_cost_tracker_store_t * store,
           void *                    dst,
           ulong                     set_idx ) {
  ulong off = set_idx * FD_COST_TRACKER_FOOTPRINT;
  ulong sz  = FD_COST_TRACKER_FOOTPRINT;
  ulong got = 0UL;
  while( got<sz ) {
    long n = pread( store->disk_fd, (uchar *)dst+got, sz-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(cost tracker spill file, fd=%d) failed (%i-%s)", store->disk_fd, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) {
      FD_LOG_CRIT(( "unexpected EOF in cost tracker spill file (set=%lu offset=%lu size=%lu)", set_idx, off+got, sz-got ));
    }
    got += (ulong)n;
  }
}

static void
disk_write( fd_cost_tracker_store_t * store,
            void const *              src,
            ulong                     set_idx ) {
  ulong off = set_idx * FD_COST_TRACKER_FOOTPRINT;
  ulong sz  = FD_COST_TRACKER_FOOTPRINT;
  ulong put = 0UL;
  while( put<sz ) {
    long n = pwrite( store->disk_fd, (uchar const *)src+put, sz-put, (long)(off+put) );
    if( FD_LIKELY( n>0L ) ) {
      put += (ulong)n;
      continue;
    }
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !n ) ) errno = EIO;
    FD_LOG_CRIT(( "pwrite(cost tracker spill file, fd=%d) failed (%i-%s)", store->disk_fd, errno, fd_io_strerror( errno ) ));
  }
}

/* cache_evict frees the least recently used unpinned cache entry for
   the cost tracker of set_idx, writing its previous cost tracker back
   to disk. */

static cache_ent_t *
cache_evict( fd_cost_tracker_store_t * store,
             ulong                     set_idx ) {
  set_t *       set = sets( store );
  cache_ent_t * ent = cache( store );

  cache_ent_t * victim = NULL;
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    if( !ent[i].pin_cnt && (!victim || ent[i].lru<victim->lru) ) victim = ent+i;
  }
  FD_CHECK_CRIT( victim, "every cost tracker cache entry is pinned" );

  if( victim->set_idx!=ULONG_MAX ) {
    disk_write( store, victim->data, victim->set_idx );
    set[ victim->set_idx ].cache_idx = USHORT_MAX;
  }
  victim->set_idx          = set_idx;
  set[ set_idx ].cache_idx = (ushort)( victim - ent );
  return victim;
}

static cache_ent_t *
cache_get( fd_cost_tracker_store_t * store,
           ulong                     set_idx ) {
  set_t * set = set_query( store, set_idx );
  if( set->cache_idx!=USHORT_MAX ) return cache( store ) + set->cache_idx;

  cache_ent_t * ent = cache_evict( store, set_idx );
  disk_read( store, ent->data, set_idx );
  return ent;
}

static cache_ent_t *
cached_ent( fd_cost_tracker_store_t const * store,
            ulong                           set_idx ) {
  set_t const * set = set_query( store, set_idx );
  FD_CHECK_CRIT( set->cache_idx<store->cache_cnt, "invariant violation: cost tracker is not cached" );
  return cache( store ) + set->cache_idx;
}

ulong
fd_cost_tracker_store_align( void ) {
  return FD_COST_TRACKER_STORE_ALIGN;
}

ulong
fd_cost_tracker_store_footprint( ulong max_live_slots,
                                 ulong cache_cnt ) {
  if( FD_UNLIKELY( !max_live_slots || max_live_slots>=USHORT_MAX || !cache_cnt ) ) return 0UL;
  cache_cnt = fd_ulong_min( cache_cnt, max_live_slots );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_COST_TRACKER_STORE_ALIGN, sizeof(fd_cost_tracker_store_t)      );
  l = FD_LAYOUT_APPEND( l, set_pool_align(),            set_pool_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, alignof(cache_ent_t),        sizeof(cache_ent_t)*cache_cnt        );
  return FD_LAYOUT_FINI( l, FD_COST_TRACKER_STORE_ALIGN );
}

void *
fd_cost_tracker_store_new( void * shmem,
                           int    disk_fd,
                           ulong  max_live_slots,
                           ulong  cache_cnt,
                           ulong  bench_max_cost_per_block,
                           ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_cost_tracker_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( disk_fd<0 ) ) {
    FD_LOG_WARNING(( "invalid disk_fd %d", disk_fd ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_cost_tracker_store_footprint( max_live_slots, cache_cnt ) ) ) {
    FD_LOG_WARNING(( "invalid max_live_slots %lu or cache_cnt %lu", max_live_slots, cache_cnt ));
    return NULL;
  }

  cache_cnt = fd_ulong_min( cache_cnt, max_live_slots );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_cost_tracker_store_t * store     = FD_SCRATCH_ALLOC_APPEND( l, FD_COST_TRACKER_STORE_ALIGN, sizeof(fd_cost_tracker_store_t)      );
  void *                    set_mem   = FD_SCRATCH_ALLOC_APPEND( l, set_pool_align(),            set_pool_footprint( max_live_slots ) );
  cache_ent_t *             cache_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(cache_ent_t),        sizeof(cache_ent_t)*cache_cnt        );
  FD_SCRATCH_ALLOC_FINI( l, FD_COST_TRACKER_STORE_ALIGN );

  set_t * set_pool = set_pool_join( set_pool_new( set_mem, max_live_slots ) );
  if( FD_UNLIKELY( !set_pool ) ) {
    FD_LOG_WARNING(( "failed to create cost tracker set pool" ));
    return NULL;
  }

  store->cache_cnt                = cache_cnt;
  store->disk_fd                  = disk_fd;
  store->bench_max_cost_per_block = bench_max_cost_per_block;
  store->seed                     = seed;
  store->set_off                  = (ulong)set_pool  - (ulong)store;
  store->cache_off                = (ulong)cache_mem - (ulong)store;
  for( ulong i=0UL; i<cache_cnt; i++ ) cache_mem[ i ].pin_cnt = 0UL;
  fd_cost_tracker_store_reset( store );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = FD_COST_TRACKER_STORE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_cost_tracker_store_t *
fd_cost_tracker_store_join( void * shmem,
                            int    disk_fd ) {
  fd_cost_tracker_store_t * store = shmem;

  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)store, fd_cost_tracker_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( store->magic!=FD_COST_TRACKER_STORE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( store->disk_fd!=disk_fd ) ) {
    FD_LOG_WARNING(( "disk_fd mismatch (store=%d join=%d)", store->disk_fd, disk_fd ));
    return NULL;
  }

  return store;
}

void
fd_cost_tracker_store_reset( fd_cost_tracker_store_t * store ) {
  set_t * pool = sets( store );
  ulong   max  = set_pool_max( pool );
  for( ulong i=0UL; i<max; i++ ) pool[ i ] = (set_t){ .cache_idx = USHORT_MAX };
  set_pool_reset( pool );
  store->lru = 0UL;
  cache_ent_t * ent = cache( store );
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    FD_CHECK_CRIT( !ent[i].pin_cnt, "invariant violation: resetting pinned cost tracker cache" );
    ent[i].set_idx = ULONG_MAX;
    ent[i].lru     = 0UL;
  }
}

ushort
fd_cost_tracker_store_new_fork( fd_cost_tracker_store_t * store,
                                ushort                    old_fork_id ) {
  if( FD_LIKELY( old_fork_id!=USHORT_MAX ) ) fd_cost_tracker_store_release( store, old_fork_id );

  set_t * pool = sets( store );
  FD_CHECK_CRIT( set_pool_free( pool ), "invariant violation: no free cost tracker sets" );
  ulong         set_idx = set_pool_idx_acquire( pool );
  cache_ent_t * ent     = cache_evict( store, set_idx );
  FD_TEST( fd_cost_tracker_join( fd_cost_tracker_new( ent->data, store->bench_max_cost_per_block, store->seed ) ) );
  ent->lru = ++store->lru;
  return (ushort)set_idx;
}

void
fd_cost_tracker_store_release( fd_cost_tracker_store_t * store,
                               ushort                    fork_id ) {
  set_t * set = set_query( store, (ulong)fork_id );
  if( set->cache_idx!=USHORT_MAX ) {
    cache_ent_t * ent = cache( store ) + set->cache_idx;
    FD_CHECK_CRIT( !ent->pin_cnt, "invariant violation: releasing a pinned cost tracker" );
    ent->set_idx   = ULONG_MAX;
    ent->lru       = 0UL;
    set->cache_idx = USHORT_MAX;
  }
  set_pool_idx_release( sets( store ), (ulong)fork_id );
}

fd_cost_tracker_t *
fd_cost_tracker_store_pin( fd_cost_tracker_store_t * store,
                           ushort                    fork_id ) {
  cache_ent_t * ent = cache_get( store, (ulong)fork_id );
  ent->pin_cnt++;
  ent->lru = ++store->lru;
  return fd_type_pun( ent->data );
}

void
fd_cost_tracker_store_unpin( fd_cost_tracker_store_t * store,
                             ushort                    fork_id ) {
  cache_ent_t * ent = cached_ent( store, (ulong)fork_id );
  FD_CHECK_CRIT( ent->pin_cnt, "invariant violation: unpinning an unpinned cost tracker" );
  ent->pin_cnt--;
}

fd_cost_tracker_t *
fd_cost_tracker_store_peek( fd_cost_tracker_store_t const * store,
                            ushort                          fork_id ) {
  return fd_type_pun( cached_ent( store, (ulong)fork_id )->data );
}
