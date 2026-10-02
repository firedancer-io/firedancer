#include "fd_epoch_credits.h"
#include "../runtime/fd_runtime_const.h"

#include <errno.h>
#include <unistd.h>

#define FD_EPOCH_CREDITS_STORE_MAGIC (0xF17EDA2CEC5E7000UL) /* FIREDANCER EPOCH CREDITS STORE V0 */

#define SET_SZ (sizeof(fd_epoch_credits_t)*FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS)

/* Only a write view makes len nonzero, and it marks its cache entry
   dirty.  So a set with a nonzero len that is not cached is on disk. */

struct set {
  ulong len;
  ulong refcnt;
};
typedef struct set set_t;

struct cache_ent {
  ulong              set_idx; /* ULONG_MAX if the entry is empty */
  ulong              pin_cnt;
  ulong              lru;
  int                dirty;
  fd_epoch_credits_t credits[ FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ];
};
typedef struct cache_ent cache_ent_t;

struct fd_epoch_credits_store {
  ulong magic;
  ulong set_cnt;
  ulong cache_cnt;
  int   disk_fd;
  ulong set_off;
  ulong cache_off;
  ulong lru;
};

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
  FD_CHECK_CRIT( set_idx<store->set_cnt, "invariant violation: invalid epoch credits set index" );
  return sets( store ) + set_idx;
}

static inline void
cache_ent_clear( cache_ent_t * ent ) {
  ent->set_idx = ULONG_MAX;
  ent->lru     = 0UL;
  ent->dirty   = 0;
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

/* cache_get returns the cache entry holding set_idx.  On a miss it
   reuses the least recently used unpinned entry, writing its set back
   first if dirty. */

static cache_ent_t *
cache_get( fd_epoch_credits_store_t * store,
           ulong                      set_idx ) {
  cache_ent_t * ent    = cache( store );
  cache_ent_t * victim = NULL;
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    if( ent[i].set_idx==set_idx ) return ent+i;
    if( !ent[i].pin_cnt && ( !victim || ent[i].lru<victim->lru ) ) victim = ent+i;
  }
  FD_CHECK_CRIT( victim, "every epoch credits cache entry is pinned" );

  set_t * set = sets( store );
  if( victim->dirty ) disk_write( store, victim->credits, victim->set_idx, set[ victim->set_idx ].len*sizeof(fd_epoch_credits_t) );
  if( set[ set_idx ].len ) disk_read( store, victim->credits, set_idx, set[ set_idx ].len*sizeof(fd_epoch_credits_t) );
  victim->set_idx = set_idx;
  victim->dirty   = 0;
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
  l = FD_LAYOUT_APPEND( l, FD_EPOCH_CREDITS_STORE_ALIGN, sizeof(fd_epoch_credits_store_t) );
  l = FD_LAYOUT_APPEND( l, alignof(set_t),               sizeof(set_t)*max_live_slots      );
  l = FD_LAYOUT_APPEND( l, alignof(cache_ent_t),         sizeof(cache_ent_t)*cache_cnt     );
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
  fd_epoch_credits_store_t * store     = FD_SCRATCH_ALLOC_APPEND( l, FD_EPOCH_CREDITS_STORE_ALIGN, sizeof(fd_epoch_credits_store_t) );
  set_t *                    set_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(set_t),               sizeof(set_t)*max_live_slots      );
  cache_ent_t *              cache_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(cache_ent_t),         sizeof(cache_ent_t)*cache_cnt     );
  FD_SCRATCH_ALLOC_FINI( l, FD_EPOCH_CREDITS_STORE_ALIGN );

  fd_memset( store, 0, sizeof(fd_epoch_credits_store_t) );
  store->set_cnt   = max_live_slots;
  store->cache_cnt = cache_cnt;
  store->disk_fd   = disk_fd;
  store->set_off   = (ulong)set_mem   - (ulong)store;
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
  fd_memset( sets( store ), 0, sizeof(set_t)*store->set_cnt );
  store->lru = 0UL;
  cache_ent_t * ent = cache( store );
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    FD_CHECK_CRIT( !ent[i].pin_cnt, "invariant violation: resetting pinned epoch credits cache" );
    cache_ent_clear( ent+i );
  }
}

ushort
fd_epoch_credits_store_new_fork( fd_epoch_credits_store_t * store ) {
  set_t * set     = sets( store );
  ulong   set_idx = 0UL;
  while( set_idx<store->set_cnt && set[ set_idx ].refcnt ) set_idx++;
  FD_CHECK_CRIT( set_idx<store->set_cnt, "invariant violation: no free epoch credits sets" );
  set[ set_idx ].refcnt = 1UL;
  return (ushort)set_idx;
}

void
fd_epoch_credits_store_acquire( fd_epoch_credits_store_t * store,
                                ushort                     fork_id ) {
  set_query( store, (ulong)fork_id )->refcnt++;
}

/* Freeing a set drops its cache entry, which cannot be pinned because
   every pin holds a reference. */

void
fd_epoch_credits_store_release( fd_epoch_credits_store_t * store,
                                ushort                     fork_id ) {
  set_t * set = set_query( store, (ulong)fork_id );
  FD_CHECK_CRIT( set->refcnt, "invariant violation: releasing an unreferenced epoch credits set" );
  if( --set->refcnt ) return;

  set->len = 0UL;
  cache_ent_t * ent = cache( store );
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    if( ent[i].set_idx==(ulong)fork_id ) {
      cache_ent_clear( ent+i );
      break;
    }
  }
}

fd_epoch_credits_view_t *
fd_epoch_credits_view_init( fd_epoch_credits_view_t *  view,
                            fd_epoch_credits_store_t * store,
                            ushort                     fork_id,
                            int                        write ) {
  if( FD_UNLIKELY( !view || !store ) ) return NULL;

  ulong   set_idx = (ulong)fork_id;
  set_t * set     = set_query( store, set_idx );
  FD_CHECK_CRIT( set->refcnt, "invariant violation: viewing unreferenced epoch credits set" );
  cache_ent_t * ent = cache_get( store, set_idx );

  set->refcnt++;
  ent->pin_cnt++;
  ent->lru = ++store->lru;
  if( FD_UNLIKELY( write && !set->len ) ) fd_memset( ent->credits, 0, SET_SZ );

  *view = (fd_epoch_credits_view_t) {
    .credits   = ent->credits,
    .store     = store,
    .len       = set->len,
    .set_idx   = set_idx,
    .cache_idx = (ulong)( ent - cache( store ) ),
    .write     = !!write
  };
  return view;
}

void
fd_epoch_credits_view_fini( fd_epoch_credits_view_t * view ) {
  if( FD_UNLIKELY( !view || !view->credits ) ) return;

  fd_epoch_credits_store_t * store = view->store;
  cache_ent_t *              ent   = cache( store ) + view->cache_idx;
  FD_CHECK_CRIT( view->cache_idx<store->cache_cnt && ent->set_idx==view->set_idx && ent->pin_cnt,
                 "invariant violation: invalid epoch credits view" );

  if( view->write ) {
    FD_CHECK_CRIT( view->len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, "invariant violation: invalid epoch credits length" );
    sets( store )[ view->set_idx ].len = view->len;
    ent->dirty = 1;
  }

  ent->pin_cnt--;
  fd_epoch_credits_store_release( store, (ushort)view->set_idx );

  view->credits = NULL;
  view->store   = NULL;
}
