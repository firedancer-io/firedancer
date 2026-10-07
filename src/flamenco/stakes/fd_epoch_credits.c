#include "fd_epoch_credits.h"
#include "../runtime/fd_runtime_const.h"

#include <errno.h>
#include <unistd.h>

#define FD_EPOCH_CREDITS_STORE_MAGIC (0xF17EDA2CEC5E7000UL) /* FIREDANCER EPOCH CREDITS STORE V0 */

/* set_t is the metadata for each fork.  This is always in-memory. */
#define SET_SZ (sizeof(fd_epoch_credits_t)*FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS)
struct set {
  ulong  len;
  ulong  refcnt;
  ushort next;
  ushort cache_idx; /* USHORT_MAX if the set is not cached */
};
typedef struct set set_t;

#define POOL_NAME  set_pool
#define POOL_T     set_t
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

/* cache_ent_t is in-memory slot holding the epoch credits of one set */
struct cache_ent {
  ulong              set_idx; /* ULONG_MAX if the entry is empty */
  ulong              pin_cnt;
  ulong              lru;
  fd_epoch_credits_t credits[ FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ];
};
typedef struct cache_ent cache_ent_t;

struct fd_epoch_credits_store {
  ulong magic;
  ulong cache_cnt;
  int   disk_fd;
  ulong set_off;
  ulong cache_off;
  ulong lru;
};
typedef struct fd_epoch_credits_store fd_epoch_credits_store_t;

static inline set_t *
sets( fd_epoch_credits_store_t * store ) {
  return fd_type_pun( (uchar *)store + store->set_off );
}

static inline cache_ent_t *
cache( fd_epoch_credits_store_t * store ) {
  return fd_type_pun( (uchar *)store + store->cache_off );
}

static inline set_t *
set_query( fd_epoch_credits_store_t * store,
           ulong                      set_idx ) {
  set_t * pool = sets( store );
  FD_CHECK_CRIT( set_idx<set_pool_max( pool ), "invariant violation: invalid epoch credits set index" );
  return pool + set_idx;
}

static void
disk_read( fd_epoch_credits_store_t * store,
           void *                     dst,
           ulong                      set_idx,
           ulong                      sz ) {
  ulong off = set_idx * SET_SZ;
  ulong got = 0UL;
  while( got<sz ) {
    long n = pread( store->disk_fd, (uchar *)dst+got, sz-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(epoch credits spill file, fd=%d) failed (%i-%s)", store->disk_fd, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) {
      FD_LOG_CRIT(( "unexpected EOF in epoch credits spill file (set=%lu offset=%lu size=%lu)", set_idx, off+got, sz-got ));
    }
    got += (ulong)n;
  }
}

static void
disk_write( fd_epoch_credits_store_t * store,
            void const *               src,
            ulong                      set_idx,
            ulong                      sz ) {
  ulong off = set_idx * SET_SZ;
  ulong put = 0UL;
  while( put<sz ) {
    long n = pwrite( store->disk_fd, (uchar const *)src+put, sz-put, (long)(off+put) );
    if( FD_LIKELY( n>0L ) ) {
      put += (ulong)n;
      continue;
    }
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !n ) ) errno = EIO;
    FD_LOG_CRIT(( "pwrite(epoch credits spill file, fd=%d) failed (%i-%s)", store->disk_fd, errno, fd_io_strerror( errno ) ));
  }
}

static cache_ent_t *
cache_get( fd_epoch_credits_store_t * store,
           ulong                      set_idx ) {
  set_t *       set = sets( store );
  cache_ent_t * ent = cache( store );
  if( set[ set_idx ].cache_idx!=USHORT_MAX ) return ent + set[ set_idx ].cache_idx;

  /* Pick cache eviction victim.  Can evict anything that's not pinned
     and is the LRU.  TODO: consider replacing scan with DLL. */
  cache_ent_t * victim = NULL;
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    if( !ent[i].pin_cnt && (!victim || ent[i].lru<victim->lru) ) victim = ent+i;
  }
  FD_CHECK_CRIT( victim, "every epoch credits cache entry is pinned" );

  /* Write back cache entry to disk */
  if( victim->set_idx!=ULONG_MAX ) {
    disk_write( store, victim->credits, victim->set_idx, set[ victim->set_idx ].len*sizeof(fd_epoch_credits_t) );
    set[ victim->set_idx ].cache_idx = USHORT_MAX;
  }
  if( set[ set_idx ].len ) disk_read( store, victim->credits, set_idx, set[ set_idx ].len*sizeof(fd_epoch_credits_t) );
  victim->set_idx          = set_idx;
  set[ set_idx ].cache_idx = (ushort)( victim - ent );
  return victim;
}

ulong
fd_epoch_credits_store_align( void ) {
  return FD_EPOCH_CREDITS_STORE_ALIGN;
}

ulong
fd_epoch_credits_store_footprint( ulong max_live_slots,
                                  ulong cache_cnt ) {
  if( FD_UNLIKELY( !max_live_slots || max_live_slots>=USHORT_MAX || !cache_cnt ) ) return 0UL;
  cache_cnt = fd_ulong_min( cache_cnt, max_live_slots );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_EPOCH_CREDITS_STORE_ALIGN, sizeof(fd_epoch_credits_store_t)     );
  l = FD_LAYOUT_APPEND( l, set_pool_align(),             set_pool_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, alignof(cache_ent_t),         sizeof(cache_ent_t)*cache_cnt        );
  return FD_LAYOUT_FINI( l, FD_EPOCH_CREDITS_STORE_ALIGN );
}

void *
fd_epoch_credits_store_new( void * shmem,
                            int    disk_fd,
                            ulong  max_live_slots,
                            ulong  cache_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_epoch_credits_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( disk_fd<0 ) ) {
    FD_LOG_WARNING(( "invalid disk_fd %d", disk_fd ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_epoch_credits_store_footprint( max_live_slots, cache_cnt ) ) ) {
    FD_LOG_WARNING(( "invalid max_live_slots %lu or cache_cnt %lu", max_live_slots, cache_cnt ));
    return NULL;
  }

  cache_cnt = fd_ulong_min( cache_cnt, max_live_slots );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_epoch_credits_store_t * store     = FD_SCRATCH_ALLOC_APPEND( l, FD_EPOCH_CREDITS_STORE_ALIGN, sizeof(fd_epoch_credits_store_t)     );
  void *                     set_mem   = FD_SCRATCH_ALLOC_APPEND( l, set_pool_align(),             set_pool_footprint( max_live_slots ) );
  cache_ent_t *              cache_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(cache_ent_t),         sizeof(cache_ent_t)*cache_cnt        );
  FD_SCRATCH_ALLOC_FINI( l, FD_EPOCH_CREDITS_STORE_ALIGN );

  set_t * set_pool = set_pool_join( set_pool_new( set_mem, max_live_slots ) );
  if( FD_UNLIKELY( !set_pool ) ) {
    FD_LOG_WARNING(( "failed to create epoch credits set pool" ));
    return NULL;
  }

  store->cache_cnt = cache_cnt;
  store->disk_fd   = disk_fd;
  store->set_off   = (ulong)set_pool  - (ulong)store;
  store->cache_off = (ulong)cache_mem - (ulong)store;
  for( ulong i=0UL; i<cache_cnt; i++ ) cache_mem[ i ].pin_cnt = 0UL;
  fd_epoch_credits_store_reset( store );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = FD_EPOCH_CREDITS_STORE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_epoch_credits_store_t *
fd_epoch_credits_store_join( void * shmem,
                             int    disk_fd ) {
  fd_epoch_credits_store_t * store = shmem;

  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)store, fd_epoch_credits_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( store->magic!=FD_EPOCH_CREDITS_STORE_MAGIC ) ) {
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
fd_epoch_credits_store_reset( fd_epoch_credits_store_t * store ) {
  set_t * pool = sets( store );
  ulong   max  = set_pool_max( pool );
  for( ulong i=0UL; i<max; i++ ) pool[ i ] = (set_t){ .cache_idx = USHORT_MAX };
  set_pool_reset( pool );
  store->lru = 0UL;
  cache_ent_t * ent = cache( store );
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    FD_CHECK_CRIT( !ent[i].pin_cnt, "invariant violation: resetting pinned epoch credits cache" );
    ent[i].set_idx = ULONG_MAX;
    ent[i].lru     = 0UL;
  }
}

ushort
fd_epoch_credits_store_new_fork( fd_epoch_credits_store_t * store,
                                 ushort                     old_fork_id ) {
  if( FD_LIKELY( old_fork_id!=USHORT_MAX ) ) fd_epoch_credits_store_release( store, old_fork_id );

  set_t * pool = sets( store );
  FD_CHECK_CRIT( set_pool_free( pool ), "invariant violation: no free epoch credits sets" );
  ulong set_idx = set_pool_idx_acquire( pool );
  pool[ set_idx ].refcnt = 1UL;
  return (ushort)set_idx;
}

void
fd_epoch_credits_store_acquire( fd_epoch_credits_store_t * store,
                                ushort                     fork_id ) {
  set_t * set = set_query( store, (ulong)fork_id );
  FD_CHECK_CRIT( set->refcnt, "invariant violation: acquiring an unreferenced epoch credits set" );
  set->refcnt++;
}

void
fd_epoch_credits_store_release( fd_epoch_credits_store_t * store,
                                ushort                     fork_id ) {
  set_t * set = set_query( store, (ulong)fork_id );
  FD_CHECK_CRIT( set->refcnt, "invariant violation: releasing an unreferenced epoch credits set" );
  if( --set->refcnt ) return;

  set->len = 0UL;
  if( set->cache_idx!=USHORT_MAX ) {
    cache_ent_t * ent = cache( store ) + set->cache_idx;
    ent->set_idx   = ULONG_MAX;
    ent->lru       = 0UL;
    set->cache_idx = USHORT_MAX;
  }
  set_pool_idx_release( sets( store ), (ulong)fork_id );
}

fd_epoch_credits_view_t *
fd_epoch_credits_view_init( fd_epoch_credits_view_t *  view,
                            fd_epoch_credits_store_t * store,
                            ushort                     fork_id ) {
  if( FD_UNLIKELY( !view || !store ) ) return NULL;

  ulong         set_idx = (ulong)fork_id;
  set_t *       set     = set_query( store, set_idx );
  cache_ent_t * ent     = cache_get( store, set_idx );

  set->refcnt++;
  ent->pin_cnt++;
  ent->lru = ++store->lru;
  if( FD_UNLIKELY( !set->len ) ) fd_memset( ent->credits, 0, SET_SZ );

  *view = (fd_epoch_credits_view_t) {
    .credits = ent->credits,
    .store   = store,
    .len     = set->len,
    .set_idx = set_idx
  };
  return view;
}

void
fd_epoch_credits_view_fini( fd_epoch_credits_view_t * view ) {
  if( FD_UNLIKELY( !view || !view->credits ) ) return;

  fd_epoch_credits_store_t * store = view->store;
  set_t *                    set   = set_query( store, view->set_idx );
  FD_CHECK_CRIT( set->cache_idx<store->cache_cnt, "invariant violation: invalid epoch credits view" );
  cache_ent_t *              ent   = cache( store ) + set->cache_idx;
  FD_CHECK_CRIT( ent->set_idx==view->set_idx && ent->pin_cnt, "invariant violation: invalid epoch credits view" );

  FD_CHECK_CRIT( view->len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, "invariant violation: invalid epoch credits length" );
  set->len = view->len;

  ent->pin_cnt--;
  fd_epoch_credits_store_release( store, (ushort)view->set_idx );

  view->credits = NULL;
  view->store   = NULL;
}

fd_epoch_credits_t const *
fd_epoch_credits_store_peek( fd_epoch_credits_store_t const * store,
                             ushort                           fork_id,
                             ulong *                          len ) {
  fd_epoch_credits_store_t * s   = (fd_epoch_credits_store_t *)store;
  set_t const *              set = set_query( s, (ulong)fork_id );
  FD_CHECK_CRIT( set->cache_idx<store->cache_cnt, "invariant violation: epoch credits set is not cached" );
  cache_ent_t const *        ent = cache( s ) + set->cache_idx;
  FD_CHECK_CRIT( ent->set_idx==(ulong)fork_id && ent->pin_cnt, "invariant violation: epoch credits set is not pinned" );
  *len = set->len;
  return ent->credits;
}
