#include "fd_epoch_credits.h"
#include "../fd_rwlock.h"
#include "../runtime/fd_runtime_const.h"

#include <errno.h>
#include <unistd.h>

#define FD_EPOCH_CREDITS_STORE_MAGIC (0xF17EDA2CEC5E7000UL) /* FIREDANCER EPOCH CREDITS STORE V0 */

struct fd_epoch_credits_store {
  ulong magic;
  ulong set_cnt;
  ulong cache_cnt;
  int   disk_fd;

  ulong cache_off;
  ulong len_off;
  ulong refcnt_off;
  ulong disk_valid_off;

  fd_rwlock_t lock;
  ulong       lru;
  ulong       cache_set_idx[ FD_EPOCH_CREDITS_CACHE_CNT ];
  ulong       cache_pin_cnt[ FD_EPOCH_CREDITS_CACHE_CNT ];
  ulong       cache_lru    [ FD_EPOCH_CREDITS_CACHE_CNT ];
  uchar       cache_dirty  [ FD_EPOCH_CREDITS_CACHE_CNT ];
};

static inline ulong
set_sz( void ) {
  return sizeof(fd_epoch_credits_t) * FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS;
}

static inline ulong
cache_cnt_for( ulong max_live_slots ) {
  return fd_ulong_min( max_live_slots, FD_EPOCH_CREDITS_CACHE_CNT );
}

static inline fd_epoch_credits_t *
cache_set( fd_epoch_credits_store_t * store,
           ulong                      cache_idx ) {
  return fd_type_pun( (uchar *)store + store->cache_off + cache_idx*set_sz() );
}

static inline ulong *
set_len( fd_epoch_credits_store_t * store ) {
  return fd_type_pun( (uchar *)store + store->len_off );
}

static inline ulong *
set_refcnt( fd_epoch_credits_store_t * store ) {
  return fd_type_pun( (uchar *)store + store->refcnt_off );
}

static inline uchar *
set_disk_valid( fd_epoch_credits_store_t * store ) {
  return fd_type_pun( (uchar *)store + store->disk_valid_off );
}

static void
disk_read( fd_epoch_credits_store_t * store,
           void *                     dst,
           ulong                      set_idx,
           ulong                      sz ) {
  ulong off = set_idx * set_sz();
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
  ulong off = set_idx * set_sz();
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

static void
reset_locked( fd_epoch_credits_store_t * store ) {
  fd_memset( set_len       ( store ), 0, sizeof(ulong)*store->set_cnt );
  fd_memset( set_refcnt    ( store ), 0, sizeof(ulong)*store->set_cnt );
  fd_memset( set_disk_valid( store ), 0, sizeof(uchar)*store->set_cnt );
  store->lru = 0UL;
  for( ulong i=0UL; i<FD_EPOCH_CREDITS_CACHE_CNT; i++ ) {
    FD_CHECK_CRIT( !store->cache_pin_cnt[i], "invariant violation: resetting pinned epoch credits cache" );
    store->cache_set_idx[i] = ULONG_MAX;
    store->cache_lru    [i] = 0UL;
    store->cache_dirty  [i] = 0U;
  }
}

static void
invalidate_locked( fd_epoch_credits_store_t * store,
                   ulong                      set_idx ) {
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    if( store->cache_set_idx[i]!=set_idx ) continue;
    FD_CHECK_CRIT( !store->cache_pin_cnt[i], "invariant violation: invalidating pinned epoch credits set" );
    store->cache_set_idx[i] = ULONG_MAX;
    store->cache_lru    [i] = 0UL;
    store->cache_dirty  [i] = 0U;
    break;
  }

  set_len       ( store )[set_idx] = 0UL;
  set_disk_valid( store )[set_idx] = 0U;
}

static void
acquire_locked( fd_epoch_credits_store_t * store,
                ulong                      set_idx ) {
  FD_CHECK_CRIT( set_idx<store->set_cnt, "invariant violation: invalid epoch credits set index" );
  set_refcnt( store )[set_idx]++;
}

static void
release_locked( fd_epoch_credits_store_t * store,
                ulong                      set_idx ) {
  FD_CHECK_CRIT( set_idx<store->set_cnt, "invariant violation: invalid epoch credits set index" );
  ulong * refcnt = set_refcnt( store ) + set_idx;
  FD_CHECK_CRIT( *refcnt, "invariant violation: releasing an unreferenced epoch credits set" );
  (*refcnt)--;
  if( FD_UNLIKELY( !*refcnt ) ) invalidate_locked( store, set_idx );
}

ulong
fd_epoch_credits_store_align( void ) {
  return FD_EPOCH_CREDITS_STORE_ALIGN;
}

ulong
fd_epoch_credits_store_footprint( ulong max_live_slots ) {
  if( FD_UNLIKELY( !max_live_slots || max_live_slots>=USHORT_MAX ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_EPOCH_CREDITS_STORE_ALIGN, sizeof(fd_epoch_credits_store_t)         );
  l = FD_LAYOUT_APPEND( l, alignof(fd_epoch_credits_t),  set_sz()*cache_cnt_for( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),               sizeof(ulong)*max_live_slots              );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),               sizeof(ulong)*max_live_slots              );
  l = FD_LAYOUT_APPEND( l, alignof(uchar),               sizeof(uchar)*max_live_slots              );
  return FD_LAYOUT_FINI( l, FD_EPOCH_CREDITS_STORE_ALIGN );
}

void *
fd_epoch_credits_store_new( void * shmem,
                            int    disk_fd,
                            ulong  max_live_slots ) {
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

  if( FD_UNLIKELY( !fd_epoch_credits_store_footprint( max_live_slots ) ) ) {
    FD_LOG_WARNING(( "invalid max_live_slots %lu", max_live_slots ));
    return NULL;
  }

  ulong cache_cnt = cache_cnt_for( max_live_slots );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_epoch_credits_store_t * store = FD_SCRATCH_ALLOC_APPEND( l, FD_EPOCH_CREDITS_STORE_ALIGN, sizeof(fd_epoch_credits_store_t) );
  void * cache_mem      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_epoch_credits_t), set_sz()*cache_cnt           );
  void * len_mem        = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              sizeof(ulong)*max_live_slots );
  void * refcnt_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              sizeof(ulong)*max_live_slots );
  void * disk_valid_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),              sizeof(uchar)*max_live_slots );
  FD_SCRATCH_ALLOC_FINI( l, FD_EPOCH_CREDITS_STORE_ALIGN );

  fd_memset( store, 0, sizeof(fd_epoch_credits_store_t) );
  store->set_cnt        = max_live_slots;
  store->cache_cnt      = cache_cnt;
  store->disk_fd        = disk_fd;
  store->cache_off      = (ulong)cache_mem      - (ulong)store;
  store->len_off        = (ulong)len_mem        - (ulong)store;
  store->refcnt_off     = (ulong)refcnt_mem     - (ulong)store;
  store->disk_valid_off = (ulong)disk_valid_mem - (ulong)store;
  fd_rwlock_new( &store->lock );
  reset_locked( store );

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
  fd_rwlock_write( &store->lock );
  reset_locked( store );
  fd_rwlock_unwrite( &store->lock );
}

ushort
fd_epoch_credits_store_new_fork( fd_epoch_credits_store_t * store,
                                 ushort                     prev_fork_id ) {
  fd_rwlock_write( &store->lock );

  if( FD_LIKELY( prev_fork_id!=USHORT_MAX ) ) release_locked( store, (ulong)prev_fork_id );

  ulong * refcnt   = set_refcnt( store );
  ulong   free_idx = ULONG_MAX;
  for( ulong i=0UL; i<store->set_cnt; i++ ) {
    if( FD_UNLIKELY( !refcnt[i] ) ) {
      free_idx = i;
      break;
    }
  }
  FD_CHECK_CRIT( free_idx!=ULONG_MAX, "invariant violation: no free epoch credits sets" );

  acquire_locked( store, free_idx );
  set_len       ( store )[free_idx] = 0UL;
  set_disk_valid( store )[free_idx] = 0U;

  fd_rwlock_unwrite( &store->lock );
  return (ushort)free_idx;
}

void
fd_epoch_credits_store_acquire( fd_epoch_credits_store_t * store,
                                ushort                     fork_id ) {
  fd_rwlock_write( &store->lock );
  acquire_locked( store, (ulong)fork_id );
  fd_rwlock_unwrite( &store->lock );
}

void
fd_epoch_credits_store_release( fd_epoch_credits_store_t * store,
                                ushort                     fork_id ) {
  fd_rwlock_write( &store->lock );
  release_locked( store, (ulong)fork_id );
  fd_rwlock_unwrite( &store->lock );
}

void
fd_epoch_credits_store_clear( fd_epoch_credits_store_t * store,
                              ushort                     fork_id ) {
  ulong set_idx = (ulong)fork_id;

  fd_rwlock_write( &store->lock );
  FD_CHECK_CRIT( set_idx<store->set_cnt && set_refcnt( store )[set_idx],
                 "invariant violation: clearing unreferenced epoch credits set" );

  set_len       ( store )[set_idx] = 0UL;
  set_disk_valid( store )[set_idx] = 0U;
  for( ulong i=0UL; i<store->cache_cnt; i++ ) {
    if( store->cache_set_idx[i]==set_idx ) {
      store->cache_dirty[i] = 0U;
      break;
    }
  }
  fd_rwlock_unwrite( &store->lock );
}

fd_epoch_credits_view_t *
fd_epoch_credits_view_init( fd_epoch_credits_view_t *  view,
                            fd_epoch_credits_store_t * store,
                            ushort                     fork_id,
                            int                        write ) {
  if( FD_UNLIKELY( !view || !store ) ) return NULL;

  ulong set_idx = (ulong)fork_id;

  for(;;) {
    fd_rwlock_write( &store->lock );

    FD_CHECK_CRIT( set_idx<store->set_cnt && set_refcnt( store )[set_idx],
                   "invariant violation: viewing unreferenced epoch credits set" );

    ulong cache_idx = ULONG_MAX;
    for( ulong i=0UL; i<store->cache_cnt; i++ ) {
      if( store->cache_set_idx[i]==set_idx ) {
        cache_idx = i;
        break;
      }
    }

    if( FD_UNLIKELY( cache_idx==ULONG_MAX ) ) {
      ulong oldest_lru = ULONG_MAX;
      for( ulong i=0UL; i<store->cache_cnt; i++ ) {
        if( store->cache_pin_cnt[i] ) continue;
        if( store->cache_set_idx[i]==ULONG_MAX ) {
          cache_idx = i;
          break;
        }
        if( store->cache_lru[i]<oldest_lru ) {
          oldest_lru = store->cache_lru[i];
          cache_idx  = i;
        }
      }

      if( FD_UNLIKELY( cache_idx==ULONG_MAX ) ) {
        fd_rwlock_unwrite( &store->lock );
        FD_SPIN_PAUSE();
        continue;
      }

      fd_epoch_credits_t * cache           = cache_set( store, cache_idx );
      ulong                evicted_set_idx = store->cache_set_idx[cache_idx];
      if( FD_LIKELY( evicted_set_idx!=ULONG_MAX && store->cache_dirty[cache_idx] ) ) {
        ulong evicted_len = set_len( store )[evicted_set_idx];
        FD_CHECK_CRIT( evicted_len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS,
                       "invariant violation: invalid epoch credits length" );
        disk_write( store, cache, evicted_set_idx, evicted_len*sizeof(fd_epoch_credits_t) );
        set_disk_valid( store )[evicted_set_idx] = 1U;
      }

      ulong len = set_len( store )[set_idx];
      FD_CHECK_CRIT( len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS,
                     "invariant violation: invalid epoch credits length" );
      if( set_disk_valid( store )[set_idx] ) {
        disk_read( store, cache, set_idx, len*sizeof(fd_epoch_credits_t) );
      } else {
        FD_CHECK_CRIT( !len, "invariant violation: epoch credits set has no resident or disk data" );
      }

      store->cache_set_idx[cache_idx] = set_idx;
      store->cache_dirty  [cache_idx] = 0U;
    }

    store->cache_pin_cnt[cache_idx]++;
    store->cache_lru    [cache_idx] = ++store->lru;
    acquire_locked( store, set_idx );

    fd_epoch_credits_t * credits = cache_set( store, cache_idx );
    ulong                len     = set_len( store )[set_idx];
    if( FD_UNLIKELY( write && !len ) ) fd_memset( credits, 0, set_sz() );

    *view = (fd_epoch_credits_view_t) {
      .credits   = credits,
      .store     = store,
      .len       = len,
      .set_idx   = set_idx,
      .cache_idx = cache_idx,
      .write     = !!write
    };

    fd_rwlock_unwrite( &store->lock );
    return view;
  }
}

void
fd_epoch_credits_view_fini( fd_epoch_credits_view_t * view ) {
  if( FD_UNLIKELY( !view || !view->credits ) ) return;

  fd_epoch_credits_store_t * store = view->store;
  fd_rwlock_write( &store->lock );

  FD_CHECK_CRIT( view->cache_idx<store->cache_cnt &&
                 store->cache_set_idx[view->cache_idx]==view->set_idx &&
                 store->cache_pin_cnt[view->cache_idx],
                 "invariant violation: invalid epoch credits view" );

  if( view->write ) {
    FD_CHECK_CRIT( view->len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS,
                   "invariant violation: invalid epoch credits length" );
    set_len       ( store )[view->set_idx] = view->len;
    set_disk_valid( store )[view->set_idx] = 0U;
    store->cache_dirty[view->cache_idx]    = 1U;
  }

  store->cache_pin_cnt[view->cache_idx]--;
  release_locked( store, view->set_idx );
  fd_rwlock_unwrite( &store->lock );

  view->credits = NULL;
  view->store   = NULL;
}
