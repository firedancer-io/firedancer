#include "fd_txncache.h"
#include "fd_txncache_private.h"
#include "../../util/log/fd_log.h"
#include "../../util/racesan/fd_racesan_target.h"

#include <unistd.h>
#include <errno.h>

FD_FN_CONST ulong
fd_txncache_align( void ) {
  return FD_TXNCACHE_ALIGN;
}

FD_FN_CONST ulong
fd_txncache_footprint( ulong max_live_slots ) {
  ulong max_active_slots = FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+max_live_slots;

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_TXNCACHE_ALIGN,     sizeof(fd_txncache_t)                 );
  l = FD_LAYOUT_APPEND( l, alignof(blockcache_t), max_active_slots*sizeof(blockcache_t) );
  return FD_LAYOUT_FINI( l, FD_TXNCACHE_ALIGN );
}

void *
fd_txncache_new( void *                ljoin,
                 fd_txncache_shmem_t * shmem,
                 int                   spill_fd ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  ulong max_active_slots = shmem->active_slots_max;
  ulong blockhash_map_chains = fd_ulong_pow2_up( 2UL*shmem->active_slots_max );
  ulong bucket_cnt = shmem->bucket_cnt;

  /* Page counts come from the shmem header rather than being
     re-derived, so the layout walk below cannot desync from the one in
     fd_txncache_shmem_new. */
  ulong _txnpages_max   = shmem->txnpages_max;

  ulong _descends_footprint = descends_set_footprint( max_active_slots );
  if( FD_UNLIKELY( !_descends_footprint ) ) {
    FD_LOG_WARNING(( "invalid max_active_slots" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_txncache_shmem_t * tc    = FD_SCRATCH_ALLOC_APPEND( l, FD_TXNCACHE_SHMEM_ALIGN,          sizeof(fd_txncache_shmem_t)                                  );
  void * _blockhash_map       = FD_SCRATCH_ALLOC_APPEND( l, blockhash_map_align(),            blockhash_map_footprint( blockhash_map_chains )              );
  void * _blockcache_pool     = FD_SCRATCH_ALLOC_APPEND( l, blockcache_pool_align(),          blockcache_pool_footprint( max_active_slots )                );
  void * _blockcache_heads    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    max_active_slots*bucket_cnt*sizeof(uint)                     );
  void * _blockcache_descends = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),             max_active_slots*_descends_footprint                         );
  void * _txnpages_free       = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    _txnpages_max*sizeof(uint)                                   );
  void * _page_meta           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_page_meta_t), _txnpages_max*sizeof(fd_txncache_page_meta_t)                );
  void * _frame_page          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    shmem->frames_max*sizeof(uint)                               );
  void * _frames_free         = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    shmem->frames_max*sizeof(uint)                               );
  void * _txnpages            = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),   shmem->frames_max*sizeof(fd_txncache_txnpage_t)              );
  void * _scratch_heads       = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    bucket_cnt*sizeof(uint)                                      );
  void * _scratch_txnpage     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),   sizeof(fd_txncache_txnpage_t)                                );
  void * _scratch_input       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),   sizeof(fd_txncache_txnpage_t)                                );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_txncache_t * ltc           = FD_SCRATCH_ALLOC_APPEND( l2, FD_TXNCACHE_ALIGN,     sizeof(fd_txncache_t)                 );
  void * _local_blockcache_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(blockcache_t), max_active_slots*sizeof(blockcache_t) );

  ltc->shmem = tc;

  ltc->blockcache_pool = (blockcache_t*)_local_blockcache_pool;
  ltc->blockcache_shmem_pool = blockcache_pool_join( _blockcache_pool );

  for( ulong i=0UL; i<shmem->active_slots_max; i++ ) {
    ltc->blockcache_pool[ i ].heads    = (uint *)_blockcache_heads + i*bucket_cnt;
    ltc->blockcache_pool[ i ].descends = descends_set_join( (uchar *)_blockcache_descends + i*_descends_footprint );
    ltc->blockcache_pool[ i ].shmem    = ltc->blockcache_shmem_pool + i;
    FD_TEST( ltc->blockcache_pool[ i ].shmem );
  }

  FD_TEST( ltc->blockcache_shmem_pool );

  ltc->blockhash_map = blockhash_map_join( _blockhash_map );
  FD_TEST( ltc->blockhash_map );

  ltc->txnpages_free   = _txnpages_free;
  ltc->page_meta       = _page_meta;
  ltc->frame_page      = _frame_page;
  ltc->frames_free     = _frames_free;
  ltc->txnpages        = (fd_txncache_txnpage_t *)_txnpages;
  ltc->scratch_heads   = _scratch_heads;
  ltc->scratch_txnpage = _scratch_txnpage;
  ltc->scratch_input   = _scratch_input;
  ltc->spill_fd        = spill_fd;

  memset( ltc->metrics, 0, sizeof(ltc->metrics) );
  fd_histf_join( fd_histf_new( ltc->metrics->query_ticks,  1UL, 1UL<<30 ) );
  fd_histf_join( fd_histf_new( ltc->metrics->insert_ticks, 1UL, 1UL<<30 ) );

  return (void *)ltc;
}

fd_txncache_join_metrics_t *
fd_txncache_join_metrics( fd_txncache_t * tc ) {
  return tc->metrics;
}

fd_txncache_t *
fd_txncache_join( void * ljoin ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  fd_txncache_t * tc = (fd_txncache_t *)ljoin;

  return tc;
}

/* lock_read and lock_write take the txncache lock, adding the time
   spent waiting to the lock wait metrics.  Uncontended acquisitions
   are not timed. */

static inline void
lock_read( fd_txncache_t * tc ) FD_ACQUIRE_SHARED( tc->shmem->lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  if( FD_LIKELY( fd_rwlock_tryread( tc->shmem->lock ) ) ) return;
  long t0 = fd_tickcount();
  fd_rwlock_read( tc->shmem->lock );
  FD_ATOMIC_FETCH_AND_ADD( &tc->shmem->lock_read_wait_ticks, (ulong)(fd_tickcount()-t0) );
}

static inline void
lock_write( fd_txncache_t * tc ) FD_ACQUIRE( tc->shmem->lock ) FD_NO_THREAD_SAFETY_ANALYSIS {
  if( FD_LIKELY( fd_rwlock_trywrite( tc->shmem->lock ) ) ) return;
  long t0 = fd_tickcount();
  fd_rwlock_write( tc->shmem->lock );
  tc->shmem->lock_write_wait_ticks += (ulong)(fd_tickcount()-t0);
}

static void
spill_rw( fd_txncache_t * tc,
          ulong           off,
          uchar *         buf,
          ulong           sz,
          int             write ) {
  FD_TEST( tc->spill_fd>=0 );
  while( sz ) {
    long n = write ? pwrite( tc->spill_fd, buf, sz, (off_t)off )
                   : pread ( tc->spill_fd, buf, sz, (off_t)off );
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( n<0L ) ) FD_LOG_CRIT(( "txncache spill %s failed at offset %lu (%ld, errno %d)", write ? "write" : "read", off, n, errno ));
    if( FD_UNLIKELY( !n ) ) FD_LOG_CRIT(( "txncache spill %s at offset %lu", write ? "write made no progress" : "read reached unexpected EOF", off ));
    sz -= (ulong)n;
    if( FD_UNLIKELY( sz && !fd_ulong_is_aligned( (ulong)n, FD_TXNCACHE_TXNPAGE_ALIGN ) ) ) {
      FD_LOG_CRIT(( "txncache spill %s returned an unaligned short transfer at offset %lu", write ? "write" : "read", off ));
    }
    buf += (ulong)n;
    off += (ulong)n;
  }
}

static void
spill_io( fd_txncache_t *         tc,
          ulong                   page,
          fd_txncache_txnpage_t * data,
          int                     write ) {
  long t0 = fd_tickcount();
  spill_rw( tc, page*sizeof(*data), (uchar *)data, sizeof(*data), write );
  if( write ) FD_ATOMIC_FETCH_AND_ADD( &tc->shmem->page_spilled_cnt,    1UL );
  else        FD_ATOMIC_FETCH_AND_ADD( &tc->shmem->page_spill_read_cnt, 1UL );
  FD_ATOMIC_FETCH_AND_ADD( &tc->shmem->spill_ticks, (ulong)(fd_tickcount()-t0) );
}

/* Waits until no fetch is moving the page.  Fetches publish without the
   lock, so this may be called with the lock held. */

static inline void
page_wait_idle( fd_txncache_page_meta_t const * meta ) {
  while( FD_UNLIKELY( FD_VOLATILE_CONST( meta->io ) ) ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
}

/* Takes a frame to load a page into, under the write lock.  Uses a free
   frame, or evicts by CLOCK: the sweep spares, once, each frame
   accessed since it last passed, and skips frames a fetch is filling.
   On eviction *victim is the evicted page, which is no longer resident
   and whose dirty contents are still in the frame, otherwise UINT_MAX.
   Returns UINT_MAX if every frame is being filled. */

static uint
frame_take( fd_txncache_t * tc,
            uint *          victim ) {
  fd_txncache_shmem_t * shmem = tc->shmem;
  *victim = UINT_MAX;
  if( FD_LIKELY( shmem->frames_free_cnt ) ) return tc->frames_free[ --shmem->frames_free_cnt ];
  for( ulong i=0UL; i<2UL*shmem->frames_max; i++ ) {
    uint frame = (uint)shmem->evict_next;
    shmem->evict_next = (shmem->evict_next+1UL)%shmem->frames_max;
    uint owner = tc->frame_page[ frame ];
    FD_TEST( owner!=UINT_MAX );
    fd_txncache_page_meta_t * old = &tc->page_meta[ owner ];
    if( FD_VOLATILE_CONST( old->io ) ) continue;
    if( old->ref ) {
      old->ref = 0U;
      continue;
    }
    old->frame = UINT_MAX;
    shmem->frame_evicted_cnt++;
    *victim = owner;
    return frame;
  }
  return UINT_MAX;
}

static inline fd_txncache_txnpage_t *
page_io( fd_txncache_t * tc,
         ulong           page,
         int             write_lock ) {
  /* Fast path: the page is resident.  A fetch may publish the frame
     concurrently. */
  fd_txncache_page_meta_t * meta = &tc->page_meta[ page ];
  uint resident = FD_VOLATILE_CONST( meta->frame );
  if( FD_LIKELY( resident!=UINT_MAX ) ) {
    if( FD_UNLIKELY( !meta->ref ) ) meta->ref = 1U;
    return &tc->txnpages[ resident ];
  }

  /* Loading changes the frame cache, which needs the write lock. */
  if( FD_LIKELY( !write_lock ) ) {
    FD_ATOMIC_FETCH_AND_ADD( &tc->shmem->page_miss_cnt, 1UL );
    return NULL;
  }
  FD_TEST( page<tc->shmem->txnpages_max );

  /* A fetch may be loading or writing back the page. */
  page_wait_idle( meta );
  if( FD_UNLIKELY( meta->frame!=UINT_MAX ) ) {
    if( FD_UNLIKELY( !meta->ref ) ) meta->ref = 1U;
    return &tc->txnpages[ meta->frame ];
  }

  uint victim;
  uint frame;
  while( FD_UNLIKELY( (frame=frame_take( tc, &victim ))==UINT_MAX ) ) FD_SPIN_PAUSE();
  if( victim!=UINT_MAX ) {
    fd_txncache_page_meta_t * old = &tc->page_meta[ victim ];
    if( old->dirty ) {
      spill_io( tc, victim, &tc->txnpages[ frame ], 1 );
      old->dirty      = 0U;
      old->disk_valid = 1;
    }
  }

  /* Read the page back, or start it empty if it was never written. */
  fd_txncache_txnpage_t * data = &tc->txnpages[ frame ];
  if( meta->disk_valid ) {
    spill_io( tc, page, data, 0 );
  } else {
    data->free = FD_TXNCACHE_TXNS_PER_PAGE;
  }
  tc->frame_page[ frame ] = (uint)page;
  meta->frame = frame;
  meta->ref   = 1U;
  return data;
}

/* page_fetch loads page into a frame for a caller that does not hold
   the lock, so that its spill I/O does not block other threads.  It
   takes the write lock only to reserve the frame, marking the page and
   any dirty evicted page busy, and publishes them without the lock.
   seq is the release_seq the caller saw while it held the lock and
   found page in use.  If any page has been released since, page may
   no longer be in use and the fetch is abandoned.  The caller retakes
   the lock and checks again, since another thread may evict page
   before then. */

static void
page_fetch( fd_txncache_t * tc,
            ulong           page,
            ulong           seq ) {
  fd_txncache_page_meta_t * meta = &tc->page_meta[ page ];
  lock_write( tc );
  if( FD_UNLIKELY( tc->shmem->release_seq!=seq || meta->frame!=UINT_MAX ) ) {
    fd_rwlock_unwrite( tc->shmem->lock );
    return;
  }
  if( FD_UNLIKELY( meta->io ) ) {
    fd_rwlock_unwrite( tc->shmem->lock );
    page_wait_idle( meta );
    return;
  }
  uint victim;
  uint frame = frame_take( tc, &victim );
  if( FD_UNLIKELY( frame==UINT_MAX ) ) {
    fd_rwlock_unwrite( tc->shmem->lock );
    FD_SPIN_PAUSE();
    return;
  }
  fd_txncache_page_meta_t * old = victim!=UINT_MAX ? &tc->page_meta[ victim ] : NULL;
  int write = old && old->dirty;
  if( write ) {
    old->dirty = 0U;
    old->io    = 1U;
  }
  int read = meta->disk_valid;
  meta->io = 1U;
  tc->frame_page[ frame ] = (uint)page;
  fd_rwlock_unwrite( tc->shmem->lock );

  fd_racesan_hook( "txncache:fetch_io" );
  fd_txncache_txnpage_t * data = &tc->txnpages[ frame ];
  if( write ) spill_io( tc, victim, data, 1 );
  if( read  ) spill_io( tc, page, data, 0 );
  else        data->free = FD_TXNCACHE_TXNS_PER_PAGE;

  /* Publish without the lock, as write lock holders may be waiting for
     these pages to become idle. */
  if( write ) {
    old->disk_valid = 1;
    FD_HW_MFENCE_ST();
    FD_VOLATILE( old->io ) = 0U;
  }
  meta->ref = 1U;
  FD_HW_MFENCE_ST();
  FD_VOLATILE( meta->frame ) = frame;
  FD_HW_MFENCE_ST();
  FD_VOLATILE( meta->io ) = 0U;
}

/* A freed logical page must never reload contents from its former owner. */
static void
release_page( fd_txncache_t * tc,
              ulong           page ) {
  fd_txncache_page_meta_t * meta = &tc->page_meta[ page ];
  page_wait_idle( meta );
  tc->shmem->release_seq++;
  if( meta->frame!=UINT_MAX ) {
    tc->frame_page[ meta->frame ] = UINT_MAX;
    tc->frames_free[ tc->shmem->frames_free_cnt++ ] = meta->frame;
    meta->frame = UINT_MAX;
  }
  meta->dirty      = 0U;
  meta->disk_valid = 0;
  meta->next       = UINT_MAX;
  tc->txnpages_free[ tc->shmem->txnpages_free_cnt++ ] = (uint)page;
}

void
fd_txncache_reset( fd_txncache_t * tc ) {
  lock_write( tc );

  tc->shmem->root_cnt = 0UL;
  root_slist_remove_all( tc->shmem->root_ll, tc->blockcache_shmem_pool );

  tc->shmem->txnpages_free_cnt = tc->shmem->txnpages_max;
  tc->shmem->frames_free_cnt = tc->shmem->frames_max;
  tc->shmem->evict_next      = 0UL;
  tc->shmem->release_seq++;
  for( ulong i=0UL; i<tc->shmem->txnpages_max; i++ ) page_wait_idle( &tc->page_meta[ i ] );
  for( ulong i=0UL; i<tc->shmem->txnpages_max; i++ ) {
    tc->txnpages_free[ i ] = (uint)i;
    tc->page_meta[ i ].frame      = UINT_MAX;
    tc->page_meta[ i ].dirty      = 0U;
    tc->page_meta[ i ].disk_valid = 0;
    tc->page_meta[ i ].next       = UINT_MAX;
  }
  for( ulong i=0UL; i<tc->shmem->frames_max; i++ ) {
    tc->frame_page[ i ]  = UINT_MAX;
    tc->frames_free[ i ] = (uint)i;
  }

  blockcache_pool_reset( tc->blockcache_shmem_pool );
  blockhash_map_reset( tc->blockhash_map );

  fd_rwlock_unwrite( tc->shmem->lock );
}

void
fd_txncache_metrics_snap( fd_txncache_t const *   tc,
                          fd_txncache_metrics_t * out ) {
  fd_txncache_shmem_t const * shmem = tc->shmem;
  out->page_miss_cnt         = FD_VOLATILE_CONST( shmem->page_miss_cnt         );
  out->page_spilled_cnt      = FD_VOLATILE_CONST( shmem->page_spilled_cnt      );
  out->page_spill_read_cnt   = FD_VOLATILE_CONST( shmem->page_spill_read_cnt   );
  out->frame_evicted_cnt     = FD_VOLATILE_CONST( shmem->frame_evicted_cnt     );
  out->spill_ticks           = FD_VOLATILE_CONST( shmem->spill_ticks           );
  out->lock_read_wait_ticks  = FD_VOLATILE_CONST( shmem->lock_read_wait_ticks  );
  out->lock_write_wait_ticks = FD_VOLATILE_CONST( shmem->lock_write_wait_ticks );
  out->page_capacity         = shmem->txnpages_max;
  out->page_used             = shmem->txnpages_max-fd_ulong_min( FD_VOLATILE_CONST( shmem->txnpages_free_cnt ), shmem->txnpages_max );
  out->frame_capacity        = shmem->frames_max;
  out->frame_used            = shmem->frames_max-fd_ulong_min( FD_VOLATILE_CONST( shmem->frames_free_cnt ), shmem->frames_max );
}

FD_STATIC_ASSERT( !(sizeof(fd_txncache_txnpage_t)%FD_TXNCACHE_SNAPIN_STAGE_ALIGN), snapin_stage_align );

void
fd_txncache_snapin_stage( fd_txncache_t * tc,
                          ulong           off,
                          void *          buf,
                          ulong           sz,
                          int             write ) {
  FD_TEST_ERR( tc->shmem->txnpages_free_cnt==tc->shmem->txnpages_max );
  FD_TEST( fd_ulong_is_aligned( off,        FD_TXNCACHE_SNAPIN_STAGE_ALIGN ) );
  FD_TEST( fd_ulong_is_aligned( sz,         FD_TXNCACHE_SNAPIN_STAGE_ALIGN ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)buf, FD_TXNCACHE_SNAPIN_STAGE_ALIGN ) );

  ulong   mem_sz = tc->shmem->frames_max*sizeof(fd_txncache_txnpage_t);
  uchar * p      = (uchar *)buf;
  if( off<mem_sz ) {
    ulong   n   = fd_ulong_min( sz, mem_sz-off );
    uchar * mem = (uchar *)tc->txnpages+off;
    if( write ) fd_memcpy( mem, p, n );
    else        fd_memcpy( p, mem, n );
    off += n;
    p   += n;
    sz  -= n;
  }
  if( sz ) spill_rw( tc, off-mem_sz, p, sz, write );
}

FD_FN_PURE static inline ulong
fd_txncache_bucket( fd_txncache_t const * tc,
                    uchar const *         txnhash ) {
  return fd_ulong_hash( FD_LOAD( ulong, txnhash )^tc->shmem->seed )%tc->shmem->bucket_cnt;
}

/* Returns a resident page of blockcache with room, with its index in
   *out_idx.  Without the write lock, returns NULL with the index of a
   page of blockcache to fetch in *out_idx, or ULONG_MAX if the caller
   must retry under the write lock. */

static fd_txncache_txnpage_t *
fd_txncache_ensure_txnpage( fd_txncache_t * tc,
                            blockcache_t *  blockcache,
                            int             write,
                            ulong *         out_idx ) {
  fd_txncache_shmem_t * shmem = tc->shmem;
  for(;;) {
    /* Use the newest page if it has room. */
    uint head = FD_VOLATILE_CONST( blockcache->shmem->page_head );
    if( FD_LIKELY( head!=UINT_MAX ) ) {
      fd_txncache_txnpage_t * page = page_io( tc, head, write );
      *out_idx = head;
      if( FD_UNLIKELY( !page ) ) return NULL;
      if( FD_LIKELY( FD_VOLATILE_CONST( page->free ) ) ) return page;
    }

    /* Need a new page.  Try to make sure we can safely take the lock
       and that there's enough capacity. */
    if( !write ) {
      fd_rwlock_write( shmem->alloc_lock );
      if( FD_UNLIKELY( FD_VOLATILE_CONST( blockcache->shmem->page_head )!=head ) ) {
        fd_rwlock_unwrite( shmem->alloc_lock );
        continue;
      }
    }

    ulong page_cnt = blockcache->shmem->pages_cnt;
    if( FD_UNLIKELY( page_cnt>=shmem->txnpages_per_blockhash_max || !shmem->txnpages_free_cnt ) ) {
      if( !write ) fd_rwlock_unwrite( shmem->alloc_lock );
      *out_idx = ULONG_MAX;
      return NULL;
    }

    /* We have safe and exclusive access to allocating a new page.
       Without the write lock and a free frame, the page is allocated
       not resident, and fetching it starts it empty. */
    ulong idx = tc->txnpages_free[ --shmem->txnpages_free_cnt ];
    fd_txncache_txnpage_t * page = NULL;
    if( write ) {
      page = page_io( tc, idx, 1 );
    } else if( FD_LIKELY( shmem->frames_free_cnt ) ) {
      uint frame = tc->frames_free[ --shmem->frames_free_cnt ];
      tc->frame_page[ frame ]    = (uint)idx;
      tc->page_meta[ idx ].frame = frame;
      page = &tc->txnpages[ frame ];
    }
    if( FD_LIKELY( page ) ) page->free = FD_TXNCACHE_TXNS_PER_PAGE;
    tc->page_meta[ idx ].next    = head;
    blockcache->shmem->pages_cnt = page_cnt+1UL;
    FD_HW_MFENCE_ST();
    FD_VOLATILE( blockcache->shmem->page_head ) = (uint)idx;
    if( !write ) fd_rwlock_unwrite( shmem->alloc_lock );
    *out_idx = idx;
    return page;
  }
}

static inline int
fd_txncache_insert_txn( fd_txncache_t *         tc,
                        blockcache_t *          blockcache,
                        fd_txncache_txnpage_t * txnpage,
                        ulong                   txnpage_idx,
                        fd_txncache_fork_id_t   fork_id,
                        uchar const *           txnhash ) {
  for(;;) {
    ushort txnpage_free = txnpage->free;
    if( FD_UNLIKELY( !txnpage_free ) ) return 0;
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &txnpage->free, txnpage_free, txnpage_free-1UL )!=txnpage_free ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-txnpage_free;
    ulong txnhash_offset = blockcache->shmem->txnhash_offset;
    memcpy( txnpage->txns[ txn_idx ]->txnhash, txnhash+txnhash_offset, 20UL );
    txnpage->txns[ txn_idx ]->fork_id = fork_id;
    txnpage->txns[ txn_idx ]->generation = tc->blockcache_pool[ fork_id.val ].shmem->generation;
    FD_COMPILER_MFENCE();

    ulong txn_bucket = fd_txncache_bucket( tc, txnhash+txnhash_offset );
    for(;;) {
      uint head = blockcache->heads[ txn_bucket ];
      txnpage->txns[ txn_idx ]->blockcache_next = head;
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->heads[ txn_bucket ], head, (uint)(FD_TXNCACHE_TXNS_PER_PAGE*txnpage_idx+txn_idx) )==head ) ) break;
      FD_SPIN_PAUSE();
    }

    /* This races, but we expect x86 stores to be atomic. */
    if( FD_UNLIKELY( !tc->page_meta[ txnpage_idx ].dirty ) ) tc->page_meta[ txnpage_idx ].dirty = 1U;
    return 1;
  }
}

fd_txncache_fork_id_t
fd_txncache_attach_child( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t parent_fork_id ) {
  lock_write( tc );

  FD_TEST( blockcache_pool_free( tc->blockcache_shmem_pool ) );
  ulong idx = blockcache_pool_idx_acquire( tc->blockcache_shmem_pool );

  blockcache_t * fork = &tc->blockcache_pool[ idx ];
  fd_txncache_fork_id_t fork_id = { .val = (ushort)idx };

  fork->shmem->generation = tc->shmem->blockcache_generation++;
  fork->shmem->child_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    FD_TEST( blockcache_pool_free( tc->blockcache_shmem_pool )==blockcache_pool_max( tc->blockcache_shmem_pool )-1UL );
    fork->shmem->parent_id  = (fd_txncache_fork_id_t){ .val = USHORT_MAX };
    fork->shmem->sibling_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

    descends_set_null( fork->descends );
    root_slist_ele_push_tail( tc->shmem->root_ll, fork->shmem, tc->blockcache_shmem_pool );
  } else {
    blockcache_t * parent = &tc->blockcache_pool[ parent_fork_id.val ];
    /* We might be tempted to freeze the parent here, and it's valid to
       do this ordinarily, but not when loading from a snapshot, when
       we need to load many transactions into a root parent chain at
       once. */
    fork->shmem->sibling_id = parent->shmem->child_id;
    fork->shmem->parent_id  = parent_fork_id;
    parent->shmem->child_id = fork_id;

    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );
  }

  fork->shmem->txnhash_offset = 0UL;
  fork->shmem->frozen = 0;
  memset( fork->heads, 0xFF, tc->shmem->bucket_cnt*sizeof(uint) );
  fork->shmem->pages_cnt = 0UL;
  fork->shmem->page_head = UINT_MAX;

  fd_rwlock_unwrite( tc->shmem->lock );
  return fork_id;
}

void
fd_txncache_attach_blockhash( fd_txncache_t *       tc,
                              fd_txncache_fork_id_t fork_id,
                              uchar const *         blockhash ) {
  lock_write( tc );

  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( !fork->shmem->frozen );
  fork->shmem->frozen = 1;

  memcpy( fork->shmem->blockhash.uc, blockhash, 32UL );

  blockhash_map_ele_insert( tc->blockhash_map, fork->shmem, tc->blockcache_shmem_pool );

  fd_rwlock_unwrite( tc->shmem->lock );
}

void
fd_txncache_finalize_fork( fd_txncache_t *       tc,
                           fd_txncache_fork_id_t fork_id,
                           ulong                 txnhash_offset,
                           uchar const *         blockhash ) {
  lock_write( tc );

  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->frozen<=1 );
  FD_TEST( fork->shmem->frozen>=0 );
  fork->shmem->txnhash_offset = txnhash_offset;

  memcpy( fork->shmem->blockhash.uc, blockhash, 32UL );

  if( FD_LIKELY( !fork->shmem->frozen ) ) blockhash_map_ele_insert( tc->blockhash_map, fork->shmem, tc->blockcache_shmem_pool );
  fork->shmem->frozen = 2;

  fd_rwlock_unwrite( tc->shmem->lock );
}

static inline void
remove_blockcache( fd_txncache_t * tc,
                   blockcache_t *  blockcache ) {
  FD_TEST( blockcache->shmem->frozen>=0 );
  for( uint page=blockcache->shmem->page_head; page!=UINT_MAX; ) {
    uint next = tc->page_meta[ page ].next;
    release_page( tc, page );
    page = next;
  }
  blockcache->shmem->page_head = UINT_MAX;
  blockcache->shmem->pages_cnt = 0UL;

  ulong idx = blockcache_pool_idx( tc->blockcache_shmem_pool, blockcache->shmem );
  for( ulong i=0UL; i<tc->shmem->active_slots_max; i++ ) descends_set_remove( tc->blockcache_pool[ i ].descends, idx );

  if( FD_LIKELY( blockcache->shmem->frozen ) ) blockhash_map_ele_remove_fast( tc->blockhash_map, blockcache->shmem, tc->blockcache_shmem_pool );
  blockcache->shmem->frozen = -1;
  blockcache_pool_ele_release( tc->blockcache_shmem_pool, blockcache->shmem );
}

static inline void
remove_children( fd_txncache_t *      tc,
                 blockcache_t const * fork,
                 blockcache_t const * except ) {
  fd_txncache_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    blockcache_t * sibling = &tc->blockcache_pool[ sibling_idx.val ];

    sibling_idx = sibling->shmem->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    remove_children( tc, sibling, except );
    remove_blockcache( tc, sibling );
  }
}

void
fd_txncache_cancel_fork( fd_txncache_t *       tc,
                         fd_txncache_fork_id_t fork_id ) {
  lock_write( tc );
  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val!=USHORT_MAX );

  /* The soon-to-be-pruned subtree must be unrooted. */
  fd_txncache_blockcache_shmem_t const * latest_root = root_slist_ele_peek_tail_const( tc->shmem->root_ll, tc->blockcache_shmem_pool );
  FD_TEST( latest_root );
  FD_TEST( descends_set_test( fork->descends, blockcache_pool_idx( tc->blockcache_shmem_pool, latest_root ) ) );

  remove_children( tc, fork, NULL );
  remove_blockcache( tc, fork );
  ushort * fork_id_p = &(tc->blockcache_pool[ fork->shmem->parent_id.val ].shmem->child_id.val);
  while( *fork_id_p!=fork_id.val ) {
    fork_id_p = &(tc->blockcache_pool[ *fork_id_p ].shmem->sibling_id.val);
  }
  *fork_id_p = fork->shmem->sibling_id.val;
  fd_rwlock_unwrite( tc->shmem->lock );
}

void
fd_txncache_advance_root( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t fork_id ) {
  lock_write( tc );

  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val!=USHORT_MAX );

  blockcache_t * parent_fork = &tc->blockcache_pool[ fork->shmem->parent_id.val ];
  if( FD_UNLIKELY( root_slist_ele_peek_tail( tc->shmem->root_ll, tc->blockcache_shmem_pool )!=parent_fork->shmem ) ) {
    FD_BASE58_ENCODE_32_BYTES( parent_fork->shmem->blockhash.uc, parent_blockhash_b58 );
    FD_BASE58_ENCODE_32_BYTES( fork->shmem->blockhash.uc, fork_blockhash_b58 );
    FD_BASE58_ENCODE_32_BYTES( root_slist_ele_peek_tail( tc->shmem->root_ll, tc->blockcache_shmem_pool )->blockhash.uc, root_blockhash_b58 );
    FD_LOG_CRIT(( "advancing root from %s to %s but that is not valid, last root is %s",
                  parent_blockhash_b58,
                  fork_blockhash_b58,
                  root_blockhash_b58 ));
  }

  FD_BASE58_ENCODE_32_BYTES( parent_fork->shmem->blockhash.uc, parent_blockhash_b58 );
  FD_BASE58_ENCODE_32_BYTES( fork->shmem->blockhash.uc, fork_blockhash_b58 );
  FD_LOG_DEBUG(( "advancing root from %s to %s",
                 parent_blockhash_b58,
                 fork_blockhash_b58 ));

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( tc, parent_fork, fork );
  parent_fork->shmem->child_id = fork_id;
  fork->shmem->sibling_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

  /* Now, the earliest known rooted fork can likely be removed since its
     blockhashes cannot be referenced anymore (they are older than 151
     blockhashes away). */
  tc->shmem->root_cnt++;
  root_slist_ele_push_tail( tc->shmem->root_ll, fork->shmem, tc->blockcache_shmem_pool );
  if( FD_LIKELY( tc->shmem->root_cnt>FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE ) ) {
    fd_txncache_blockcache_shmem_t * old_root_shmem = root_slist_ele_pop_head( tc->shmem->root_ll, tc->blockcache_shmem_pool );
    FD_TEST( old_root_shmem );
    blockcache_t * old_root = &tc->blockcache_pool[ blockcache_pool_idx( tc->blockcache_shmem_pool, old_root_shmem ) ];

    root_slist_ele_peek_head( tc->shmem->root_ll, tc->blockcache_shmem_pool )->parent_id.val = USHORT_MAX;

    remove_blockcache( tc, old_root );
    tc->shmem->root_cnt--;
  }

  fd_rwlock_unwrite( tc->shmem->lock );
}

static inline blockcache_t *
blockhash_on_fork( fd_txncache_t *      tc,
                   blockcache_t const * fork,
                   uchar const *        blockhash ) {
  fd_txncache_blockcache_shmem_t const * candidate = blockhash_map_ele_query_const( tc->blockhash_map, fd_type_pun_const( blockhash ), NULL, tc->blockcache_shmem_pool );
  if( FD_UNLIKELY( !candidate ) ) return NULL;

  while( candidate ) {
    ulong candidate_idx = blockcache_pool_idx( tc->blockcache_shmem_pool, candidate );
    if( FD_LIKELY( descends_set_test( fork->descends, candidate_idx ) ) ) return &tc->blockcache_pool[ candidate_idx ];
    candidate = blockhash_map_ele_next_const( candidate, NULL, tc->blockcache_shmem_pool );
  }
  return NULL;
}

static void
purge_stale_on_blockcache( fd_txncache_t * tc,
                           blockcache_t *  blockcache ) {
  FD_TEST( blockcache->shmem->frozen>=0 );
  memset( tc->scratch_heads, 0xFF, tc->shmem->bucket_cnt*sizeof(tc->scratch_heads[ 0 ]) );
  uint  scratch_page_head = UINT_MAX;
  ulong scratch_pages_cnt = 0UL;
  ulong scratch_txnpage_idx = ULONG_MAX;
  tc->scratch_txnpage->free = 0;
  uint next_txnpage_idx = blockcache->shmem->page_head;
  while( next_txnpage_idx!=UINT_MAX ) {
    ulong curr_txnpage_idx = next_txnpage_idx;
    next_txnpage_idx = tc->page_meta[ curr_txnpage_idx ].next;
    fd_txncache_txnpage_t * input = tc->scratch_input;
    memcpy( input, page_io( tc, curr_txnpage_idx, 1 ), sizeof(*input) );
    ulong curr_txn_cnt = FD_TXNCACHE_TXNS_PER_PAGE-input->free;
    for( ulong j=0UL; j<curr_txn_cnt; j++ ) {
      fd_txncache_single_txn_t const * curr_txn = input->txns[ curr_txn_cnt-j-1UL ];
      blockcache_t const * txn_fork = &tc->blockcache_pool[ curr_txn->fork_id.val ];
      if( FD_LIKELY( txn_fork->shmem->frozen>=0 && txn_fork->shmem->generation==curr_txn->generation ) ) {
        /* Valid transaction.  Keep. */
        if( FD_UNLIKELY( !tc->scratch_txnpage->free ) ) {
          FD_TEST( scratch_txnpage_idx!=curr_txnpage_idx );
          if( FD_LIKELY( scratch_txnpage_idx!=ULONG_MAX ) ) {
            memcpy( page_io( tc, scratch_txnpage_idx, 1 ), tc->scratch_txnpage, sizeof(fd_txncache_txnpage_t) );
            tc->page_meta[ scratch_txnpage_idx ].dirty = 1U;
          }
          scratch_txnpage_idx = curr_txnpage_idx;
          tc->scratch_txnpage->free = FD_TXNCACHE_TXNS_PER_PAGE;
          tc->page_meta[ scratch_txnpage_idx ].next = scratch_page_head;
          scratch_page_head = (uint)scratch_txnpage_idx;
          scratch_pages_cnt++;
        }
        ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-tc->scratch_txnpage->free;
        memcpy( tc->scratch_txnpage->txns[ txn_idx ], curr_txn, sizeof(*curr_txn) );
        ulong txn_bucket = fd_txncache_bucket( tc, curr_txn->txnhash );
        uint head = tc->scratch_heads[ txn_bucket ];
        tc->scratch_txnpage->txns[ txn_idx ]->blockcache_next = head;
        ulong txn_gidx = FD_TXNCACHE_TXNS_PER_PAGE*scratch_txnpage_idx+txn_idx;
        FD_TEST( txn_gidx<UINT_MAX );
        tc->scratch_heads[ txn_bucket ] = (uint)txn_gidx;
        tc->scratch_txnpage->free--;
      } else {
        /* Stale transaction.  Drop. */
        continue;
      }
    }
    if( FD_UNLIKELY( curr_txnpage_idx!=scratch_txnpage_idx ) ) {
      /* The txnpage is not being used for compaction, free it up. */
      release_page( tc, curr_txnpage_idx );
    }
  }
  if( FD_LIKELY( scratch_txnpage_idx!=ULONG_MAX ) ) {
    memcpy( page_io( tc, scratch_txnpage_idx, 1 ), tc->scratch_txnpage, sizeof(fd_txncache_txnpage_t) );
    tc->page_meta[ scratch_txnpage_idx ].dirty = 1U;
  }
  blockcache->shmem->page_head = scratch_page_head;
  blockcache->shmem->pages_cnt = scratch_pages_cnt;
  memcpy( blockcache->heads, tc->scratch_heads, tc->shmem->bucket_cnt*sizeof(blockcache->heads[0]) );
}

static void
purge_stale_on_fork( fd_txncache_t * tc,
                     blockcache_t *  fork ) {
  purge_stale_on_blockcache( tc, fork );

  fd_txncache_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    blockcache_t * sibling = &tc->blockcache_pool[ sibling_idx.val ];
    purge_stale_on_fork( tc, sibling );
    sibling_idx = sibling->shmem->sibling_id;
  }
}

static void
purge_stale( fd_txncache_t * tc ) {
  fd_txncache_blockcache_shmem_t * root_shmem = root_slist_ele_peek_head( tc->shmem->root_ll, tc->blockcache_shmem_pool );
  FD_TEST( root_shmem );
  blockcache_t * root = &tc->blockcache_pool[ blockcache_pool_idx( tc->blockcache_shmem_pool, root_shmem ) ];
  ulong free_before = tc->shmem->txnpages_free_cnt;
  /* One might think that an optimization here is to stop the descent on
     the latest rooted blockcache.  There could be no pruned minority
     forks from that point on.  As a result, there could be no stale
     transactions in any blockcache descending from that.
     Unfortunately, frontier eviction means that any blockcache in the
     fork tree can have stale transactions. */
  purge_stale_on_fork( tc, root );
  FD_LOG_WARNING(( "purge_stale: txnpages_free %lu -> %lu", free_before, tc->shmem->txnpages_free_cnt ));
}

void
fd_txncache_insert( fd_txncache_t *       tc,
                    fd_txncache_fork_id_t fork_id,
                    uchar const *         blockhash,
                    uchar const *         txnhash ) {
  long t0 = fd_tickcount();
  lock_read( tc );

  blockcache_t const * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->frozen<=1 );
  FD_TEST( fork->shmem->frozen>=0 );
  blockcache_t * blockcache = blockhash_on_fork( tc, fork, blockhash );
  FD_TEST( blockcache );

  ulong fetch_cnt = 0UL;
  int   miss      = 0;
  int   write     = 0;
  for(;;) {
    /* First look for an in-memory page (write==0) */
    ulong                   txnpage_idx;
    fd_txncache_txnpage_t * txnpage = fd_txncache_ensure_txnpage( tc, blockcache, 0, &txnpage_idx );
    if( FD_UNLIKELY( !txnpage && txnpage_idx!=ULONG_MAX ) ) miss = 1;
    if( FD_UNLIKELY( !txnpage && txnpage_idx!=ULONG_MAX && fetch_cnt<FD_TXNCACHE_FETCH_MAX ) ) {
      /* The page is not resident.  Load it without blocking others. */
      ulong seq = tc->shmem->release_seq;
      fd_rwlock_unread( tc->shmem->lock );
      page_fetch( tc, txnpage_idx, seq );
      fetch_cnt++;
      lock_read( tc );
      blockcache = blockhash_on_fork( tc, fork, blockhash );
      FD_TEST( blockcache );
      continue;
    }
    if( FD_UNLIKELY( !txnpage ) ) {
      /* Because of sizing invariants when creating the structure, it is
         not typically possible to fill it, unless there are stale
         transactions from minority forks that were purged floating
         around, in which case we can purge them here and try again.
         Under the write lock there are no concurrent allocators, so a
         page still unavailable after the purge means the cache is
         undersized for the caller's usage. */
      fd_rwlock_unread( tc->shmem->lock );
      lock_write( tc );
      blockcache = blockhash_on_fork( tc, fork, blockhash );
      FD_TEST( blockcache );
      /* Load or allocate a frame under exclusive access. */
      txnpage = fd_txncache_ensure_txnpage( tc, blockcache, 1, &txnpage_idx );
      if( FD_UNLIKELY( !txnpage ) ) {
        /* Slow path: there is no available txnpage in-memory or on
           disk.  Try to purge any stale entries and try one more time.
           If that fails, capacity has been reached. */
        purge_stale( tc );
        txnpage = fd_txncache_ensure_txnpage( tc, blockcache, 1, &txnpage_idx );
        if( FD_UNLIKELY( !txnpage ) )
          FD_LOG_ERR(( "txncache full after purging stale entries: blockcache holds %lu of %lu txnpages, pool has %lu of %lu free (active_slots_max=%lu txn_per_slot_max=%lu)",
                       blockcache->shmem->pages_cnt, tc->shmem->txnpages_per_blockhash_max,
                       tc->shmem->txnpages_free_cnt, tc->shmem->txnpages_max,
                       tc->shmem->active_slots_max,  tc->shmem->txn_per_slot_max ));
      }
      FD_TEST( fd_txncache_insert_txn( tc, blockcache, txnpage, txnpage_idx, fork_id, txnhash ) );
      write = 1;
      break;
    }

    /* Fast path: insert the transaction into an in-memory page.  */
    int success = fd_txncache_insert_txn( tc, blockcache, txnpage, txnpage_idx, fork_id, txnhash );
    if( FD_LIKELY( success ) ) break;

    FD_SPIN_PAUSE();
  }

  if( FD_UNLIKELY( write ) ) fd_rwlock_unwrite( tc->shmem->lock );
  else                       fd_rwlock_unread ( tc->shmem->lock );

  tc->metrics->insert_miss_cnt += (ulong)miss;
  tc->metrics->stalled_cnt     += (ulong)write;
  fd_histf_sample( tc->metrics->insert_ticks, (ulong)(fd_tickcount()-t0) );
}

int
fd_txncache_query( fd_txncache_t *       tc,
                   fd_txncache_fork_id_t fork_id,
                   uchar const *         blockhash,
                   uchar const *         txnhash ) {
  long t0 = fd_tickcount();
  /* Prevent fork removal and pruning while allowing inserts. */
  lock_read( tc );

  /* Find the blockhash cache visible from the requested fork. */
  blockcache_t const * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->frozen>=0 );
  blockcache_t const * blockcache = blockhash_on_fork( tc, fork, blockhash );
  FD_TEST( blockcache );
  FD_TEST( blockcache->shmem->frozen==2 );

  int   found     = 0;
  int   write     = 0;
  int   miss      = 0;
  ulong fetch_cnt = 0UL;

  /* Select the bucket using the stored portion of the txn hash. */
  ulong txnhash_offset = blockcache->shmem->txnhash_offset;
  ulong head_hash = fd_txncache_bucket( tc, txnhash+txnhash_offset );
  /* Walk the bucket's list.  UINT_MAX marks the end. */
  for( uint head=blockcache->heads[ head_hash ]; head!=UINT_MAX; ) {
    /* If the page is not resident, load it without the lock and walk
       again, or after too many loads walk under the write lock, which
       loads pages in place. */
    fd_txncache_txnpage_t * page = page_io( tc, head/FD_TXNCACHE_TXNS_PER_PAGE, write );
    if( FD_UNLIKELY( !page ) ) {
      miss = 1;
      ulong seq = tc->shmem->release_seq;
      fd_rwlock_unread( tc->shmem->lock );
      if( FD_LIKELY( fetch_cnt<FD_TXNCACHE_FETCH_MAX ) ) {
        page_fetch( tc, head/FD_TXNCACHE_TXNS_PER_PAGE, seq );
        fetch_cnt++;
        lock_read( tc );
      } else {
        lock_write( tc );
        write = 1;
      }
      blockcache = blockhash_on_fork( tc, fork, blockhash );
      FD_TEST( blockcache );
      head = blockcache->heads[ head_hash ];
      continue;
    }
    fd_txncache_single_txn_t const * txn = page->txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];
    head = txn->blockcache_next;

    /* Accept transactions from this fork or its ancestors.  Reject
       removed forks and old records whose fork ID has been reused. */
    blockcache_t const * txn_fork = &tc->blockcache_pool[ txn->fork_id.val ];
    int descends = (txn->fork_id.val==fork_id.val || descends_set_test( fork->descends, txn->fork_id.val )) && txn_fork->shmem->frozen>=0 && txn_fork->shmem->generation==txn->generation;
    /* Different hashes can share a bucket, so compare the stored hash. */
    if( FD_LIKELY( descends && !memcmp( txnhash+txnhash_offset, txn->txnhash, 20UL ) ) ) {
      found = 1;
      break;
    }
  }

  if( FD_UNLIKELY( write ) ) fd_rwlock_unwrite( tc->shmem->lock );
  else                       fd_rwlock_unread ( tc->shmem->lock );

  tc->metrics->query_miss_cnt += (ulong)miss;
  tc->metrics->stalled_cnt    += (ulong)write;
  fd_histf_sample( tc->metrics->query_ticks, (ulong)(fd_tickcount()-t0) );
  return found;
}

ulong
fd_txncache_snapshot_roots( fd_txncache_t *      tc,
                            fd_txncache_root_t * out ) {
  lock_read( tc );
  ulong cnt = 0UL;
  for( ulong it = root_slist_iter_init( tc->shmem->root_ll, tc->blockcache_shmem_pool );
       !root_slist_iter_done( it, tc->shmem->root_ll, tc->blockcache_shmem_pool );
       it = root_slist_iter_next( it, tc->shmem->root_ll, tc->blockcache_shmem_pool ) ) {
    ulong blockcache_idx = root_slist_iter_idx( it, tc->shmem->root_ll, tc->blockcache_shmem_pool );
    fd_txncache_blockcache_shmem_t const * blockcache_shmem = &tc->blockcache_shmem_pool[ blockcache_idx ];
    FD_TEST( cnt<FD_TXNCACHE_MAX_ROOTS );
    fd_txncache_root_t * root = &out[ cnt++ ];
    root->blockcache_idx = blockcache_idx;
    root->txnhash_offset = blockcache_shmem->txnhash_offset;
    root->generation     = blockcache_shmem->generation;
    memcpy( root->blockhash, blockcache_shmem->blockhash.uc, 32UL );
  }
  fd_rwlock_unread( tc->shmem->lock );
  return cnt;
}

static fd_txncache_single_txn_t const *
bucket_chain_txn( fd_txncache_t * tc,
                  uint            txn_gidx,
                  int             write_lock ) {
  if( FD_UNLIKELY( txn_gidx==UINT_MAX ) ) return NULL;
  fd_txncache_txnpage_t const * page = page_io( tc, txn_gidx/FD_TXNCACHE_TXNS_PER_PAGE, write_lock );
  FD_TEST( page );
  return page->txns[ txn_gidx%FD_TXNCACHE_TXNS_PER_PAGE ];
}

/* Locks tc and positions iter at the head of its current bucket. */

static void
blockcache_iter_bucket_open( fd_txncache_blockcache_iter_t * iter ) {
  fd_txncache_t * tc     = iter->tc;
  fd_rwlock_t *   lock   = tc->shmem->lock;
  uint const *    heads  = tc->blockcache_pool[ iter->blockcache_idx ].heads;
  ulong           bucket = iter->bucket;

  fd_racesan_hook( "txncache:bucket_started" );
  lock_read( tc );

  uint head;
  int  write_lock = 0;
  for( ulong fetch_cnt=0UL;; fetch_cnt++ ) {
    /* Inserts may publish a new head concurrently under the read lock.
       The chain below the head loaded here is immutable until unlock. */
    head = FD_VOLATILE_CONST( heads[ bucket ] );

    /* Check that every page of the chain is resident. */
    ulong miss = ULONG_MAX;
    for( uint idx=head; idx!=UINT_MAX; ) {
      fd_txncache_txnpage_t const * page = page_io( tc, idx/FD_TXNCACHE_TXNS_PER_PAGE, 0 );
      if( FD_UNLIKELY( !page ) ) {
        miss = idx/FD_TXNCACHE_TXNS_PER_PAGE;
        break;
      }
      idx = page->txns[ idx%FD_TXNCACHE_TXNS_PER_PAGE ]->blockcache_next;
    }
    if( FD_LIKELY( miss==ULONG_MAX ) ) break;

    /* Load the missing page without the lock and check again, or after
       too many loads hold the write lock, which loads pages in place.
       The chain may be compacted while unlocked, so the head is
       reloaded. */
    ulong seq = tc->shmem->release_seq;
    fd_rwlock_unread( lock );
    if( !fetch_cnt ) { fd_racesan_hook( "txncache:bucket_iter_miss" ); }
    if( FD_LIKELY( fetch_cnt<FD_TXNCACHE_FETCH_MAX ) ) {
      page_fetch( tc, miss, seq );
      lock_read( tc );
      continue;
    }
    lock_write( tc );
    write_lock = 1;
    head = heads[ bucket ];
    break;
  }

  iter->write_lock = write_lock;
  iter->txn        = bucket_chain_txn( tc, head, write_lock );
}

static void
blockcache_iter_bucket_close( fd_txncache_blockcache_iter_t * iter ) {
  if( iter->write_lock ) fd_rwlock_unwrite( iter->tc->shmem->lock );
  else                   fd_rwlock_unread ( iter->tc->shmem->lock );
}

/* Moves past empty buckets, holding the lock of one bucket at a time. */

static void
blockcache_iter_skip_empty( fd_txncache_blockcache_iter_t * iter ) {
  while( !iter->txn && iter->bucket+1UL<iter->tc->shmem->bucket_cnt ) {
    blockcache_iter_bucket_close( iter );
    iter->bucket++;
    blockcache_iter_bucket_open( iter );
  }
}

fd_txncache_blockcache_iter_t *
fd_txncache_blockcache_iter_init( fd_txncache_blockcache_iter_t * iter,
                                  fd_txncache_t *                 tc,
                                  ulong                           blockcache_idx ) {
  iter->tc             = tc;
  iter->blockcache_idx = blockcache_idx;
  iter->bucket         = 0UL;
  blockcache_iter_bucket_open( iter );
  blockcache_iter_skip_empty( iter );
  return iter;
}

void
fd_txncache_blockcache_iter_next( fd_txncache_blockcache_iter_t * iter ) {
  /* Under the write lock, loading the next page may evict the current
     transaction's frame, so read the link first. */
  uint next = iter->txn->blockcache_next;
  iter->txn = bucket_chain_txn( iter->tc, next, iter->write_lock );
  blockcache_iter_skip_empty( iter );
}

void
fd_txncache_blockcache_iter_fini( fd_txncache_blockcache_iter_t * iter ) {
  blockcache_iter_bucket_close( iter );
}
