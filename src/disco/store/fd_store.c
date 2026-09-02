#define _GNU_SOURCE
#include "fd_store.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/falloc.h>
#include <sys/mman.h>

#define FD_STORE_FEC_DATA_VIEW_SPILL (1U)

enum {
  FD_STORE_FILE_UNINITIALIZED = 0,
  FD_STORE_FILE_INITIALIZING  = 1,
  FD_STORE_FILE_READY         = 2,
  FD_STORE_FILE_FAILED        = 3
};

static int
store_file_wait( fd_store_t const * store,
                 int                state ) {
  while( state==FD_STORE_FILE_UNINITIALIZED || state==FD_STORE_FILE_INITIALIZING ) {
    FD_SPIN_PAUSE();
    state = atomic_load_explicit( &store->file_init_state, memory_order_acquire );
  }
  if( FD_UNLIKELY( state!=FD_STORE_FILE_READY ) ) {
    errno = store->file_init_errno ? store->file_init_errno : EIO;
    return -1;
  }
  return 0;
}

static int
store_pwrite_all( int          fd,
                  void const * buf,
                  ulong        sz,
                  off_t        off ) {
  ulong written = 0UL;
  while( written<sz ) {
    long res = pwrite( fd, (uchar const *)buf + written, sz-written, off+(off_t)written );
    if( FD_LIKELY( res>0L ) ) { written += (ulong)res; continue; }
    if( FD_UNLIKELY( res<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !res ) ) errno = EIO;
    return -1;
  }
  return 0;
}

static int
store_pread_all( int    fd,
                 void * buf,
                 ulong  sz,
                 off_t  off ) {
  ulong read_sz = 0UL;
  while( read_sz<sz ) {
    long res = pread( fd, (uchar *)buf + read_sz, sz-read_sz, off+(off_t)read_sz );
    if( FD_LIKELY( res>0L ) ) { read_sz += (ulong)res; continue; }
    if( FD_UNLIKELY( res<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !res ) ) errno = EIO;
    return -1;
  }
  return 0;
}

static inline fd_shredb_shred_entry_t *
disk_shred_pool_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->shred_pool_gaddr );
}

static inline fd_shredb_shred_map_t *
disk_shred_map_ljoin( fd_store_t const * store,
                      fd_shredb_shred_map_t * join ) {
  fd_wksp_t * wksp = fd_store_wksp( store );
  return fd_shredb_shred_map_join( join,
                                   fd_wksp_laddr_fast( wksp, store->shred_map_gaddr ),
                                   disk_shred_pool_laddr( store ),
                                   store->disk_max_shreds );
}

static inline atomic_ulong *
disk_slot_hint_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->slot_hint_gaddr );
}

static inline uchar *
cache_data_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->cache_data_gaddr );
}

static inline ulong *
cache_free_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->cache_free_gaddr );
}

static inline uint *
spill_free_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->spill_free_gaddr );
}

static inline uint *
spill_reclaim_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->spill_reclaim_gaddr );
}

static inline uchar *
spill_read_data_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->spill_read_data_gaddr );
}

static inline fd_store_fec_t *
pool_ele_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_ele_gaddr );
}

static inline fd_store_pool_t
pool_ljoin( fd_store_t const * store ) {
  return (fd_store_pool_t){
    .pool    = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_mem_gaddr ),
    .ele     = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_ele_gaddr ),
    .ele_max = store->fec_max
  };
}

static fd_store_fec_t *
fd_store_fec_acquire( fd_store_t * store ) {
  fd_store_pool_t pool = pool_ljoin( store );
  fd_store_fec_t * fec = fd_store_pool_acquire( &pool );
  if( FD_LIKELY( fec ) ) {
    fec->data_sz              = 0UL;
    fec->data_off             = 0UL;
    fec->cache_prev           = UINT_MAX;
    fec->cache_next           = UINT_MAX;
    fec->data_pin_cnt         = 0U;
    fec->data_state           = FD_STORE_FEC_DATA_EMPTY;
    fec->data_consume_pending = 0U;
  }
  return fec;
}

static void
cache_slot_release_locked( fd_store_t * store,
                           ulong        data_off ) {
  FD_TEST( data_off<store->cache_slot_cnt*store->payload_slot_sz );
  FD_TEST( !(data_off % store->payload_slot_sz) );
  FD_TEST( store->cache_free_cnt<store->cache_slot_cnt );
  cache_free_laddr( store )[ store->cache_free_cnt++ ] = data_off / store->payload_slot_sz;
}

static inline uint
cache_fec_idx( fd_store_t const *     store,
               fd_store_fec_t const * fec ) {
  ulong off = (ulong)fec - (ulong)pool_ele_laddr( store );
  FD_TEST( !(off % sizeof(fd_store_fec_t)) );
  ulong idx = off / sizeof(fd_store_fec_t);
  FD_TEST( idx<store->fec_max );
  return (uint)idx;
}

static void
cache_lru_remove_locked( fd_store_t *     store,
                         fd_store_fec_t * fec ) {
  uint idx = cache_fec_idx( store, fec );
  uint prev = fec->cache_prev;
  uint next = fec->cache_next;

  if( prev==UINT_MAX ) { FD_TEST( store->cache_lru_head==idx ); store->cache_lru_head = next; }
  else                 pool_ele_laddr( store )[ prev ].cache_next = next;
  if( next==UINT_MAX ) { FD_TEST( store->cache_lru_tail==idx ); store->cache_lru_tail = prev; }
  else                 pool_ele_laddr( store )[ next ].cache_prev = prev;

  fec->cache_prev = UINT_MAX;
  fec->cache_next = UINT_MAX;
}

static void
cache_lru_push_head_locked( fd_store_t *     store,
                            fd_store_fec_t * fec ) {
  uint idx = cache_fec_idx( store, fec );
  FD_TEST( fec->cache_prev==UINT_MAX && fec->cache_next==UINT_MAX );

  fec->cache_next = store->cache_lru_head;
  if( store->cache_lru_head==UINT_MAX ) store->cache_lru_tail = idx;
  else pool_ele_laddr( store )[ store->cache_lru_head ].cache_prev = idx;
  store->cache_lru_head = idx;
}

static void
cache_lru_push_tail_locked( fd_store_t *     store,
                            fd_store_fec_t * fec ) {
  uint idx = cache_fec_idx( store, fec );
  FD_TEST( fec->cache_prev==UINT_MAX && fec->cache_next==UINT_MAX );

  fec->cache_prev = store->cache_lru_tail;
  if( store->cache_lru_tail==UINT_MAX ) store->cache_lru_head = idx;
  else pool_ele_laddr( store )[ store->cache_lru_tail ].cache_next = idx;
  store->cache_lru_tail = idx;
}

static void
spill_reclaim_push_locked( fd_store_t * store,
                           uint         spill_slot ) {
  FD_TEST( spill_slot<store->spill_slot_cnt );
  FD_TEST( store->spill_reclaim_cnt+store->spill_reclaiming_cnt+store->spill_reuse_cnt<store->fec_max );
  spill_reclaim_laddr( store )[ store->spill_reclaim_cnt++ ] = spill_slot;
}

static void
spill_reuse_push_locked( fd_store_t * store,
                         uint         spill_slot ) {
  FD_TEST( spill_slot<store->spill_slot_cnt );
  FD_TEST( store->spill_reclaim_cnt+store->spill_reclaiming_cnt+store->spill_reuse_cnt<store->fec_max );
  spill_reclaim_laddr( store )[ store->fec_max-1UL-store->spill_reuse_cnt++ ] = spill_slot;
}

static uint
spill_reuse_pop_locked( fd_store_t * store ) {
  FD_TEST( store->spill_reuse_cnt );
  return spill_reclaim_laddr( store )[ store->fec_max-store->spill_reuse_cnt-- ];
}

static void
cache_consume_locked( fd_store_t *     store,
                      fd_store_fec_t * fec ) {
  if( FD_LIKELY( !fec->data_consume_pending ) ) return;
  if( FD_UNLIKELY( fec->data_pin_cnt || fec->data_state==FD_STORE_FEC_DATA_SPILLING ) ) return;

  if( FD_LIKELY( fec->data_state==FD_STORE_FEC_DATA_RAM_WRITING ||
                 fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) ) {
    if( fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) cache_lru_remove_locked( store, fec );
    cache_slot_release_locked( store, fec->data_off );
  } else if( fec->data_state==FD_STORE_FEC_DATA_DISK ) {
    FD_TEST( fd_ulong_is_aligned( fec->data_off, store->payload_slot_sz ) );
    ulong spill_slot = fec->data_off / store->payload_slot_sz;
    FD_TEST( spill_slot<store->spill_slot_cnt && atomic_load_explicit( &store->spill_live_cnt, memory_order_relaxed ) );
    atomic_fetch_sub_explicit( &store->spill_live_cnt, 1UL, memory_order_relaxed );
    spill_reclaim_push_locked( store, (uint)spill_slot );
  }

  fec->data_off             = 0UL;
  fec->cache_prev           = UINT_MAX;
  fec->cache_next           = UINT_MAX;
  fec->data_state           = FD_STORE_FEC_DATA_CONSUMED;
  fec->data_consume_pending = 0U;
}

static void
fd_store_fec_release( fd_store_t * store,
                      fd_store_fec_t * fec ) {
  (void)cache_fec_idx( store, fec );
  for(;;) {
    fd_rwlock_write( &store->cache_lock );
    fec->data_consume_pending = 1U;
    cache_consume_locked( store, fec );
    int consumed = fec->data_state==FD_STORE_FEC_DATA_CONSUMED;
    fd_rwlock_unwrite( &store->cache_lock );
    if( FD_LIKELY( consumed ) ) break;
    FD_SPIN_PAUSE();
  }
  fd_store_pool_t pool = pool_ljoin( store );
  fd_store_pool_release( &pool, fec );
}

static int
spill_one_locked( fd_store_t * store,
                  int          disk_fd ) {
  if( FD_UNLIKELY( disk_fd<0 ) ) return 0;

  fd_store_fec_t * fec0 = pool_ele_laddr( store );
  uint victim_idx = store->cache_lru_head;
  if( FD_UNLIKELY( victim_idx==UINT_MAX ) ) return 0;
  fd_store_fec_t * victim = fec0 + victim_idx;
  FD_TEST( victim->data_state==FD_STORE_FEC_DATA_RAM_READY && !victim->data_pin_cnt );
  FD_TEST( victim->data_sz<=store->fec_data_max );

  uint spill_slot;
  int  spill_slot_allocated;
  if( FD_LIKELY( store->spill_reuse_cnt ) ) {
    spill_slot           = spill_reuse_pop_locked( store );
    spill_slot_allocated = 1;
  } else if( FD_LIKELY( store->spill_reclaim_cnt ) ) {
    spill_slot           = spill_reclaim_laddr( store )[ --store->spill_reclaim_cnt ];
    spill_slot_allocated = 1;
  } else if( FD_LIKELY( store->spill_free_cnt ) ) {
    spill_slot           = spill_free_laddr( store )[ --store->spill_free_cnt ];
    spill_slot_allocated = 0;
  } else {
    if( FD_UNLIKELY( store->spill_slot_cnt>=store->fec_max ) )
      return store->spill_reclaiming_cnt ? -1 : 0;
    spill_slot           = (uint)store->spill_slot_cnt++;
    spill_slot_allocated = 0;
  }

  ulong ram_off   = victim->data_off;
  ulong spill_off = (ulong)spill_slot * store->payload_slot_sz;
  ulong data_sz   = victim->data_sz;

  cache_lru_remove_locked( store, victim );
  victim->data_state = FD_STORE_FEC_DATA_SPILLING;
  fd_rwlock_unwrite( &store->cache_lock );

  if( FD_UNLIKELY( store_pwrite_all( disk_fd, cache_data_laddr( store ) + ram_off, data_sz, (off_t)spill_off ) ) )
    FD_LOG_ERR(( "error spilling FEC payload to disk: (%d-%s)", errno, fd_io_strerror( errno ) ));

  fd_rwlock_write( &store->cache_lock );
  FD_TEST( victim->data_state==FD_STORE_FEC_DATA_SPILLING );
  if( FD_UNLIKELY( victim->data_pin_cnt || victim->data_consume_pending ) ) {
    int try_next = !!victim->data_pin_cnt;
    atomic_fetch_add_explicit( &store->spill_allocated_cnt, (ulong)!spill_slot_allocated, memory_order_relaxed );
    spill_reclaim_push_locked( store, spill_slot );
    victim->data_state = victim->data_consume_pending && !victim->data_pin_cnt
                       ? FD_STORE_FEC_DATA_RAM_WRITING
                       : FD_STORE_FEC_DATA_RAM_READY;
    if( FD_LIKELY( !victim->data_pin_cnt && !victim->data_consume_pending ) )
      cache_lru_push_tail_locked( store, victim );
    cache_consume_locked( store, victim );
    return try_next || !!store->cache_free_cnt;
  }

  victim->data_off   = spill_off;
  victim->data_state = FD_STORE_FEC_DATA_DISK;
  atomic_fetch_add_explicit( &store->spill_live_cnt, 1UL, memory_order_relaxed );
  atomic_fetch_add_explicit( &store->spill_allocated_cnt, (ulong)!spill_slot_allocated, memory_order_relaxed );
  atomic_fetch_add_explicit( &store->fec_spill_cnt, 1UL, memory_order_relaxed );
  atomic_fetch_add_explicit( &store->fec_spill_bytes, data_sz, memory_order_relaxed );
  cache_slot_release_locked( store, ram_off );
  return 1;
}


void *
fd_store_new( void       * shmem,
              ulong        fec_max,
              ulong        fec_data_max,
              ulong        shred_storage_gib,
              ulong        shred_cache_bytes,
              ulong        fec_set_cnt,
              char const * db_path,
              ulong        seed ) {

  if( FD_UNLIKELY( !shmem ) ) { FD_LOG_WARNING(( "NULL shmem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned shmem" )); return NULL; }
  if( FD_UNLIKELY( !db_path || !db_path[0] ) ) { FD_LOG_WARNING(( "NULL db_path" )); return NULL; }
  if( FD_UNLIKELY( fd_cstr_nlen( db_path, PATH_MAX )>=PATH_MAX ) ) { FD_LOG_WARNING(( "db_path too long" )); return NULL; }
  if( FD_UNLIKELY( !fec_max ) ) { FD_LOG_WARNING(( "fec_max must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( fec_max>UINT_MAX ) ) { FD_LOG_WARNING(( "fec_max must fit in uint" )); return NULL; }
  if( FD_UNLIKELY( !fec_data_max ) ) { FD_LOG_WARNING(( "fec_data_max must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( shred_storage_gib>FD_SHREDB_MAX_SIZE_GIB ) ) {
    FD_LOG_ERR(( "shred database size limit is %lu GiB, but the maximum supported size is %lu GiB",
                 shred_storage_gib, FD_SHREDB_MAX_SIZE_GIB ));
  }

  ulong footprint = fd_store_footprint( fec_max, fec_data_max, shred_storage_gib, shred_cache_bytes, fec_set_cnt );
  if( FD_UNLIKELY( !footprint ) ) { FD_LOG_WARNING(( "invalid or overflowing store footprint" )); return NULL; }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "shmem must be part of a workspace" )); return NULL; }

  ulong chain_cnt       = fd_store_map_chain_cnt_est( fec_max );
  ulong payload_slot_sz = fd_store_payload_slot_sz( fec_data_max );
  ulong cache_slot_cnt = shred_cache_bytes
                       ? fd_ulong_min( fec_max, fd_ulong_max( 1UL, shred_cache_bytes / payload_slot_sz ) )
                       : fec_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_store_t *   store          = FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(),         sizeof(fd_store_t)                  );
  void *         map            = FD_SCRATCH_ALLOC_APPEND( l, fd_store_map_align(),     fd_store_map_footprint( chain_cnt ) );
  void *         shpool         = FD_SCRATCH_ALLOC_APPEND( l, fd_store_pool_align(),    fd_store_pool_footprint()           );
  void *         shele          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_fec_t),  sizeof(fd_store_fec_t)*fec_max      );
  uchar *        cache_mem      = FD_SCRATCH_ALLOC_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ, payload_slot_sz*cache_slot_cnt      );
  ulong *        cache_free     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),           sizeof(ulong)*cache_slot_cnt        );
  uint *         spill_free     = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            sizeof(uint)*fec_max                );
  uint *         spill_reclaim  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            sizeof(uint)*fec_max                );
  uchar *        spill_read_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ, payload_slot_sz                      );
  fd_fec_set_t * fec_sets       = fec_set_cnt
                                ? FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fec_set_t), sizeof(fd_fec_set_t)*fec_set_cnt )
                                : NULL;

  void *         shred_map_mem  = NULL;
  void *         shred_pool_mem = NULL;
  atomic_ulong * slot_hint_mem = NULL;
  ulong          max_shreds     = 0UL;
  ulong          max_slots      = 0UL;
  ulong          disk_chain_cnt = 0UL;

  if( shred_storage_gib ) {
    max_shreds     = fd_shredb_max_shreds( shred_storage_gib );
    max_slots      = fd_shredb_max_slots( shred_storage_gib );
    disk_chain_cnt = fd_shredb_shred_map_chain_cnt_est( max_shreds );

    shred_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_shred_map_align(),      fd_shredb_shred_map_footprint( disk_chain_cnt ) );
    shred_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shredb_shred_entry_t), max_shreds * sizeof(fd_shredb_shred_entry_t)    );
    slot_hint_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(atomic_ulong),            max_slots * sizeof(atomic_ulong)                );
  }

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_store_align() )==(ulong)shmem + footprint );

  ulong payload_sz;
  ulong wire_sz;
  ulong file_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( payload_slot_sz, fec_max, &payload_sz ) ||
                   __builtin_umull_overflow( max_shreds, sizeof(fd_shredb_entry_t), &wire_sz ) ||
                   __builtin_uaddl_overflow( payload_sz, wire_sz, &file_sz ) ||
                   file_sz>(ulong)LONG_MAX ) ) {
    FD_LOG_WARNING(( "store backing file size overflows off_t" ));
    return NULL;
  }

  fd_memset( store, 0, sizeof(fd_store_t) );
  store->fec_max               = fec_max;
  store->fec_data_max          = fec_data_max;
  store->store_gaddr           = fd_wksp_gaddr_fast( wksp, store );
  store->pool_mem_gaddr        = fd_wksp_gaddr_fast( wksp, shpool );
  store->pool_ele_gaddr        = fd_wksp_gaddr_fast( wksp, shele  );
  store->payload_slot_sz       = payload_slot_sz;
  store->payload_sz            = payload_sz;
  store->wire_off              = payload_sz; /* wire region begins after the payload region (page-aligned) */
  store->cache_slot_cnt        = cache_slot_cnt;
  store->cache_data_gaddr      = fd_wksp_gaddr_fast( wksp, cache_mem );
  store->cache_free_gaddr      = fd_wksp_gaddr_fast( wksp, cache_free );
  store->cache_free_cnt        = cache_slot_cnt;
  store->cache_lru_head        = UINT_MAX;
  store->cache_lru_tail        = UINT_MAX;
  store->spill_free_gaddr      = fd_wksp_gaddr_fast( wksp, spill_free );
  store->spill_reclaim_gaddr   = fd_wksp_gaddr_fast( wksp, spill_reclaim );
  store->spill_read_data_gaddr = fd_wksp_gaddr_fast( wksp, spill_read_mem );
  store->fec_set_cnt           = fec_set_cnt;
  store->fec_sets_gaddr        = fec_set_cnt ? fd_wksp_gaddr_fast( wksp, fec_sets ) : 0UL;
  fd_rwlock_new( &store->cache_lock );
  fd_rwlock_new( &store->spill_read_lock );
  fd_rwlock_new( &store->fec_lock );
  atomic_init( &store->fec_spill_cnt, 0UL );
  atomic_init( &store->spill_live_cnt, 0UL );
  atomic_init( &store->spill_allocated_cnt, 0UL );
  atomic_init( &store->fec_spill_bytes, 0UL );
  atomic_init( &store->fec_spill_read_cnt, 0UL );
  atomic_init( &store->fec_spill_read_bytes, 0UL );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( store->db_path ), db_path, PATH_MAX-1UL ) );
  atomic_init( &store->file_init_state, 0 );
  store->file_init_errno = 0;

  void * shmap = fd_store_map_new( map, chain_cnt, seed );
  if( FD_UNLIKELY( !shmap ) ) { FD_LOG_WARNING(( "fd_store_map_new failed" )); return NULL; }
  store->map_gaddr = fd_wksp_gaddr_fast( wksp, shmap );

  if( FD_UNLIKELY( !fd_store_pool_new( shpool ) ) ) { FD_LOG_WARNING(( "fd_store_pool_new failed" )); return NULL; }
  fd_store_pool_t pool_ljoin;
  fd_store_pool_reset( fd_store_pool_join( &pool_ljoin, shpool, shele, fec_max ) );

  for( ulong i=0UL; i<cache_slot_cnt; i++ ) cache_free[ i ] = cache_slot_cnt - 1UL - i;

  /* FEC metadata starts without a payload location. */
  fd_store_fec_t * fec0 = (fd_store_fec_t *)shele;
  for( ulong i=0UL; i<fec_max; i++ ) {
    fec0[ i ].data_off     = 0UL;
    fec0[ i ].cache_prev   = UINT_MAX;
    fec0[ i ].cache_next   = UINT_MAX;
    fec0[ i ].data_pin_cnt = 0U;
    fec0[ i ].data_state   = FD_STORE_FEC_DATA_EMPTY;
    fec0[ i ].data_consume_pending = 0U;
  }

  if( shred_storage_gib ) {
    void * shred_shmap = fd_shredb_shred_map_new( shred_map_mem, disk_chain_cnt, seed );
    FD_TEST( shred_shmap );
    store->shred_map_gaddr     = fd_wksp_gaddr_fast( wksp, shred_shmap );
    store->shred_pool_gaddr    = fd_wksp_gaddr_fast( wksp, shred_pool_mem );
    store->slot_hint_gaddr     = fd_wksp_gaddr_fast( wksp, slot_hint_mem );
    store->disk_max_shreds     = max_shreds;
    store->disk_max_slots      = max_slots;

    fd_shredb_shred_entry_t * cell = (fd_shredb_shred_entry_t *)shred_pool_mem;
    for( ulong i=0UL; i<max_shreds; i++ ) {
      cell[ i ].key  = 0UL;
      cell[ i ].next = UINT_MAX;
      atomic_init( &cell[ i ].tag, 0UL );
    }
    for( ulong i=0UL; i<max_slots; i++ ) {
      atomic_init( slot_hint_mem+i, 0UL );
    }

    atomic_init( &store->disk_reservation_head, 0UL );
    atomic_init( &store->disk_cnt,              0UL );
    atomic_init( &store->disk_insert_cnt,       0UL );
    atomic_init( &store->disk_write_bytes,      0UL );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = FD_STORE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_store_t *
fd_store_join( void * shstore ) {
  if( FD_UNLIKELY( !shstore ) ) { FD_LOG_WARNING(( "NULL store" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned store" )); return NULL; }

  fd_wksp_t * wksp = fd_wksp_containing( shstore );
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "store must be part of a workspace" )); return NULL; }

  fd_store_t * store = (fd_store_t *)shstore;
  if( FD_UNLIKELY( store->magic!=FD_STORE_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }

  return store;
}

int
fd_store_file_init( fd_store_t * store ) {
  if( FD_UNLIKELY( !store || store->magic!=FD_STORE_MAGIC ) ) {
    errno = EINVAL;
    return -1;
  }

  int state = atomic_load_explicit( &store->file_init_state, memory_order_acquire );
  if( state==FD_STORE_FILE_UNINITIALIZED ) {
    int expected = FD_STORE_FILE_UNINITIALIZED;
    if( atomic_compare_exchange_strong_explicit( &store->file_init_state, &expected, FD_STORE_FILE_INITIALIZING,
                                                 memory_order_acq_rel, memory_order_acquire ) ) {
      int fd = open( store->db_path, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600 );
      int err = fd<0 ? errno : 0;
      if( FD_LIKELY( fd>=0 ) ) {
        ulong wire_sz = store->disk_max_shreds*sizeof(fd_shredb_entry_t);
        ulong file_sz = store->wire_off + wire_sz;
        if( FD_UNLIKELY( ftruncate( fd, (off_t)file_sz ) ) ) err = errno;
        else if( FD_UNLIKELY( wire_sz && fallocate( fd, 0, (off_t)store->wire_off, (off_t)wire_sz ) ) ) err = errno;
        close( fd );
      }
      store->file_init_errno = err;
      state = err ? FD_STORE_FILE_FAILED : FD_STORE_FILE_READY;
      atomic_store_explicit( &store->file_init_state, state, memory_order_release );
    } else {
      state = expected;
    }
  }

  return store_file_wait( store, state );
}

int
fd_store_file_open( fd_store_t * store,
                    int          flags ) {
  if( FD_UNLIKELY( !store || store->magic!=FD_STORE_MAGIC ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( flags & (O_CREAT | O_EXCL | O_TRUNC) ) ) {
    errno = EINVAL;
    return -1;
  }

  int state = atomic_load_explicit( &store->file_init_state, memory_order_acquire );
  if( FD_UNLIKELY( store_file_wait( store, state ) ) ) return -1;
  return open( store->db_path, flags, (mode_t)0600 );
}

void *
fd_store_leave( fd_store_t const * store ) {
  if( FD_UNLIKELY( !store ) ) { FD_LOG_WARNING(( "NULL store" )); return NULL; }
  return (void *)store;
}

void *
fd_store_delete( void * shstore ) {
  if( FD_UNLIKELY( !shstore ) ) { FD_LOG_WARNING(( "NULL store" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned store" )); return NULL; }

  fd_store_t * store = (fd_store_t *)shstore;
  if( FD_UNLIKELY( store->magic!=FD_STORE_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shstore;
}


uchar *
fd_store_fec_data_acquire( fd_store_t     * store,
                           int              disk_fd,
                           fd_store_fec_t * fec ) {
  if( FD_UNLIKELY( !store || !fec ) ) return NULL;

  fd_store_fec_t * fec0 = pool_ele_laddr( store );
  if( FD_UNLIKELY( fec<fec0 || fec>=fec0+store->fec_max ) ) return NULL;

  fd_rwlock_write( &store->cache_lock );

  if( FD_UNLIKELY( fec->data_state==FD_STORE_FEC_DATA_RAM_WRITING ) ) {
    uchar * data = cache_data_laddr( store ) + fec->data_off;
    fd_rwlock_unwrite( &store->cache_lock );
    return data;
  }

  if( FD_UNLIKELY( fec->data_state!=FD_STORE_FEC_DATA_EMPTY &&
                   fec->data_state!=FD_STORE_FEC_DATA_CONSUMED ) ) {
    fd_rwlock_unwrite( &store->cache_lock );
    return NULL;
  }

  while( FD_UNLIKELY( !store->cache_free_cnt ) ) {
    if( FD_UNLIKELY( store->cache_lru_head==UINT_MAX ) ) {
      fd_rwlock_unwrite( &store->cache_lock );
      FD_SPIN_PAUSE();
      fd_rwlock_write( &store->cache_lock );
      continue;
    }
    int spill_result = spill_one_locked( store, disk_fd );
    if( FD_UNLIKELY( spill_result<0 ) ) {
      fd_rwlock_unwrite( &store->cache_lock );
      FD_SPIN_PAUSE();
      fd_rwlock_write( &store->cache_lock );
      continue;
    }
    if( FD_UNLIKELY( !spill_result ) ) {
      fd_rwlock_unwrite( &store->cache_lock );
      return NULL;
    }
  }

  ulong * free = cache_free_laddr( store );
  ulong slot = free[ --store->cache_free_cnt ];
  fec->data_off     = slot * store->payload_slot_sz;
  fec->cache_prev   = UINT_MAX;
  fec->cache_next   = UINT_MAX;
  fec->data_pin_cnt = 0U;
  fec->data_state   = FD_STORE_FEC_DATA_RAM_WRITING;

  uchar * data = cache_data_laddr( store ) + fec->data_off;
  fd_rwlock_unwrite( &store->cache_lock );
  return data;
}

void
fd_store_fec_data_publish( fd_store_t     * store,
                           fd_store_fec_t * fec ) {
  fd_rwlock_write( &store->cache_lock );
  FD_TEST( fec->data_state==FD_STORE_FEC_DATA_RAM_WRITING );
  FD_TEST( fec->data_sz<=store->fec_data_max );
  fec->data_state = FD_STORE_FEC_DATA_RAM_READY;
  cache_lru_push_tail_locked( store, fec );
  fd_rwlock_unwrite( &store->cache_lock );
}

static void
cache_pin_locked( fd_store_t *     store,
                  fd_store_fec_t * fec ) {
  if( FD_UNLIKELY( !fec->data_pin_cnt && fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) )
    cache_lru_remove_locked( store, fec );
  FD_TEST( fec->data_pin_cnt<UINT_MAX );
  fec->data_pin_cnt++;
  store->cache_pinned_cnt++;
}

static void
cache_unpin_locked( fd_store_t *     store,
                    fd_store_fec_t * fec ) {
  FD_TEST( fec->data_pin_cnt && store->cache_pinned_cnt );
  fec->data_pin_cnt--;
  store->cache_pinned_cnt--;
  /* Prefer spilling payloads that a reader has already copied while
     retaining their disk copy for replay backfill. */
  if( FD_UNLIKELY( !fec->data_pin_cnt && fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) )
    cache_lru_push_head_locked( store, fec );
}

int
fd_store_fec_data_view( fd_store_t *               store,
                        int                        disk_fd,
                        fd_store_fec_t *           fec,
                        fd_store_fec_data_view_t * view ) {
  if( FD_UNLIKELY( !view ) ) return -1;
  view->data  = NULL;
  view->fec   = NULL;
  view->flags = 0U;
  if( FD_UNLIKELY( !store || !fec ) ) return -1;
  fd_store_fec_t * fec0 = pool_ele_laddr( store );
  if( FD_UNLIKELY( fec<fec0 || fec>=fec0+store->fec_max ) ) return -1;

  fd_rwlock_write( &store->cache_lock );

  if( FD_UNLIKELY( fec->data_sz>store->fec_data_max ) ) {
    fd_rwlock_unwrite( &store->cache_lock );
    return -1;
  }

  if( FD_LIKELY( fec->data_state==FD_STORE_FEC_DATA_RAM_READY ||
                 fec->data_state==FD_STORE_FEC_DATA_SPILLING ) ) {
    cache_pin_locked( store, fec );
    view->data = cache_data_laddr( store ) + fec->data_off;
    view->fec  = fec;
    fd_rwlock_unwrite( &store->cache_lock );
    return 0;
  }

  if( FD_LIKELY( fec->data_state==FD_STORE_FEC_DATA_DISK ) ) {
    if( FD_UNLIKELY( disk_fd<0 ) ) {
      fd_rwlock_unwrite( &store->cache_lock );
      return -1;
    }
    if( FD_UNLIKELY( !fd_rwlock_trywrite( &store->spill_read_lock ) ) ) {
      fd_rwlock_unwrite( &store->cache_lock );
      return -1;
    }
    ulong data_sz  = fec->data_sz;
    ulong data_off = fec->data_off;
    uchar * spill_read_data = spill_read_data_laddr( store );
    cache_pin_locked( store, fec );
    fd_rwlock_unwrite( &store->cache_lock );

    if( FD_UNLIKELY( store_pread_all( disk_fd, spill_read_data, data_sz, (off_t)data_off ) ) )
      FD_LOG_ERR(( "error reading spilled FEC payload: (%d-%s)", errno, fd_io_strerror( errno ) ));

    atomic_fetch_add_explicit( &store->fec_spill_read_cnt, 1UL, memory_order_relaxed );
    atomic_fetch_add_explicit( &store->fec_spill_read_bytes, data_sz, memory_order_relaxed );

    view->data  = spill_read_data;
    view->fec   = fec;
    view->flags = FD_STORE_FEC_DATA_VIEW_SPILL;
    return 0;
  }

  fd_rwlock_unwrite( &store->cache_lock );
  return -1;
}

void
fd_store_fec_data_view_release( fd_store_t *               store,
                                fd_store_fec_data_view_t * view ) {
  if( FD_UNLIKELY( !store || !view || !view->fec ) ) return;
  if( view->flags & FD_STORE_FEC_DATA_VIEW_SPILL ) fd_rwlock_unwrite( &store->spill_read_lock );

  fd_rwlock_write( &store->cache_lock );
  cache_unpin_locked( store, view->fec );
  cache_consume_locked( store, view->fec );
  fd_rwlock_unwrite( &store->cache_lock );

  view->data  = NULL;
  view->fec   = NULL;
  view->flags = 0U;
}

fd_store_fec_t *
fd_store_query( fd_store_map_t *  map,
                fd_hash_t const * merkle_root ) {
  for(;;) {
    fd_store_map_query_t query[1];
    int err = fd_store_map_query_try( map, merkle_root, NULL, query, 0 );
    if( FD_UNLIKELY( err==FD_MAP_ERR_AGAIN ) ) continue;
    if( FD_UNLIKELY( err ) ) return NULL;

    fd_store_fec_t * fec = fd_store_map_query_ele( query );
    err = fd_store_map_query_test( query );
    if( FD_LIKELY( !err ) ) return fec;
    if( FD_UNLIKELY( err!=FD_MAP_ERR_AGAIN ) ) return NULL;
  }
}

int
fd_store_insert( fd_store_t *       store,
                 fd_store_map_t *   map,
                 fd_hash_t const *  merkle_root,
                 fd_store_fec_t **  fec ) {
  FD_TEST( store && map && merkle_root && fec );
  *fec = NULL;
  fd_rwlock_read( &store->fec_lock );

  struct {
    fd_store_map_txn_t              txn [1];
    fd_store_map_txn_private_info_t info[1];
  } map_txn_mem;
  fd_store_map_txn_t * txn = fd_store_map_txn_init( map_txn_mem.txn, map, 1UL );
  FD_TEST( !fd_store_map_txn_add( txn, merkle_root, 1 ) );
  FD_TEST( !fd_store_map_txn_try( txn, FD_MAP_FLAG_BLOCKING ) );

  fd_store_map_query_t query[1];
  int err = fd_store_map_txn_query( map, merkle_root, NULL, query, 0 );
  if( FD_LIKELY( err==FD_MAP_ERR_KEY ) ) {
    fd_store_fec_t * new_fec = fd_store_fec_acquire( store );
    FD_TEST( new_fec );
    new_fec->key = *merkle_root;
    FD_TEST( !fd_store_map_txn_insert( map, new_fec ) );
    *fec = new_fec;
    err  = FD_MAP_SUCCESS;
  } else {
    FD_TEST( err==FD_MAP_SUCCESS );
    err = FD_MAP_ERR_KEY;
  }

  FD_TEST( !fd_store_map_txn_test( txn ) );
  fd_store_map_txn_fini( txn );
  fd_rwlock_unread( &store->fec_lock );
  return err;
}

int
fd_store_remove( fd_store_t *      store,
                 fd_store_map_t *  map,
                 fd_hash_t const * merkle_root ) {
  fd_rwlock_write( &store->fec_lock );
  fd_store_map_query_t query[1];
  int err = fd_store_map_remove( map, merkle_root, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_LIKELY( !err ) ) fd_store_fec_release( store, fd_store_map_query_ele( query ) );
  else FD_TEST( err==FD_MAP_ERR_KEY );
  fd_rwlock_unwrite( &store->fec_lock );
  return !err;
}


static inline ulong
disk_cell_tag( ulong ticket,
               ulong state ) {
  return (ticket<<2) | state;
}

static inline ulong
disk_cell_state( ulong tag ) {
  return tag & FD_SHREDB_CELL_STATE_MASK;
}

static inline ulong
disk_cell_ticket( ulong tag ) {
  return tag >> 2;
}

enum {
  DISK_PUBLISH_ERR     = -1,
  DISK_PUBLISH_NOOP    =  0,
  DISK_PUBLISH_SUCCESS =  1
};

static void
disk_slot_hint_publish( fd_store_t * store,
                        ulong        slot,
                        uint         shred_idx ) {
  atomic_ulong * hint = disk_slot_hint_laddr( store ) + (slot % store->disk_max_slots);
  ulong desired = fd_shredb_key_pack( slot, shred_idx ) | (1UL<<15);
  ulong current = atomic_load_explicit( hint, memory_order_acquire );
  for(;;) {
    if( FD_LIKELY( current & (1UL<<15) ) ) {
      uint current_idx = (uint)(current & (FD_SHRED_BLK_MAX-1UL));
      if( current_idx>=shred_idx ) return;
    }
    if( atomic_compare_exchange_strong_explicit( hint, &current, desired,
                                                 memory_order_release, memory_order_acquire ) ) return;
  }
}

static int
disk_exact_publish( fd_store_t *               store,
                    fd_shredb_shred_entry_t * cell,
                    ulong                      old_key,
                    ulong                      new_key ) {
  fd_shredb_shred_map_t map[1];
  FD_TEST( disk_shred_map_ljoin( store, map ) );
  struct {
    fd_shredb_shred_map_txn_t              txn [1];
    fd_shredb_shred_map_txn_private_info_t info[2];
  } txn_mem;
  fd_shredb_shred_map_txn_t * txn = fd_shredb_shred_map_txn_init( txn_mem.txn, map, 2UL );
  FD_TEST( !fd_shredb_shred_map_txn_add( txn, &old_key, 1 ) );
  FD_TEST( !fd_shredb_shred_map_txn_add( txn, &new_key, 1 ) );
  FD_TEST( !fd_shredb_shred_map_txn_try( txn, FD_MAP_FLAG_BLOCKING ) );

  fd_shredb_shred_map_query_t old_query[1];
  fd_shredb_shred_map_query_t new_query[1];
  int old_err = fd_shredb_shred_map_txn_query( map, &old_key, NULL, old_query, 0 );
  int new_err = fd_shredb_shred_map_txn_query( map, &new_key, NULL, new_query, 0 );
  FD_TEST( old_err==FD_MAP_SUCCESS || old_err==FD_MAP_ERR_KEY );
  FD_TEST( new_err==FD_MAP_SUCCESS || new_err==FD_MAP_ERR_KEY );
  fd_shredb_shred_entry_t * old_ele = old_err ? NULL : fd_shredb_shred_map_query_ele( old_query );

  int result = DISK_PUBLISH_SUCCESS;
  if( FD_UNLIKELY( !new_err ) ) {
    fd_shredb_shred_entry_t * new_ele = fd_shredb_shred_map_query_ele( new_query );
    if( new_ele!=cell ) {
      ulong state = disk_cell_state( atomic_load_explicit( &new_ele->tag, memory_order_acquire ) );
      if( FD_LIKELY( state==FD_SHREDB_CELL_READY ) ) result = DISK_PUBLISH_NOOP;
      else if( FD_UNLIKELY( state==FD_SHREDB_CELL_WRITING ) ) result = DISK_PUBLISH_ERR;
      else FD_TEST( !fd_shredb_shred_map_txn_remove( map, &new_key, NULL, new_query, 0 ) );
    }
  }

  if( old_ele==cell ) {
    fd_shredb_shred_map_query_t remove_query[1];
    FD_TEST( !fd_shredb_shred_map_txn_remove( map, &old_key, NULL, remove_query, 0 ) );
  }

  if( FD_LIKELY( result==DISK_PUBLISH_SUCCESS ) ) {
    cell->key = new_key;
    FD_TEST( !fd_shredb_shred_map_txn_insert( map, cell ) );
  }
  FD_TEST( !fd_shredb_shred_map_txn_test( txn ) );
  fd_shredb_shred_map_txn_fini( txn );
  return result;
}

int
fd_store_disk_insert( fd_store_t       * store,
                      int                disk_fd,
                      fd_shred_t const * shred ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !shred || !fd_store_has_disk( store ) ) )
    return FD_STORE_DISK_INSERT_ERR;

  ulong slot      = shred->slot;
  uint  shred_idx = shred->idx;
  if( FD_UNLIKELY( (slot>>48) || shred_idx>=FD_SHRED_BLK_MAX ) ) return FD_STORE_DISK_INSERT_ERR;
  ulong key = fd_shredb_key_pack( slot, shred_idx );

  ulong ticket = atomic_fetch_add_explicit( &store->disk_reservation_head, 1UL, memory_order_relaxed ) + 1UL;
  if( FD_UNLIKELY( !ticket || ticket>(ULONG_MAX>>2) ) ) return FD_STORE_DISK_INSERT_ERR;
  ulong ring_idx = (ticket-1UL) % store->disk_max_shreds;

  fd_shredb_shred_entry_t * cell = disk_shred_pool_laddr( store ) + ring_idx;
  ulong old_tag = atomic_load_explicit( &cell->tag, memory_order_acquire );
  ulong old_state = disk_cell_state( old_tag );
  if( FD_UNLIKELY( old_state==FD_SHREDB_CELL_WRITING || disk_cell_ticket( old_tag )>=ticket ) )
    return FD_STORE_DISK_INSERT_ERR;
  ulong writing_tag = disk_cell_tag( ticket, FD_SHREDB_CELL_WRITING );
  if( FD_UNLIKELY( !atomic_compare_exchange_strong_explicit( &cell->tag, &old_tag, writing_tag,
                                                              memory_order_acq_rel, memory_order_acquire ) ) )
    return FD_STORE_DISK_INSERT_ERR;
  old_state = disk_cell_state( old_tag );
  ulong old_key = cell->key;

  fd_shredb_entry_t wr_entry[1];
  ulong shred_sz = fd_ulong_min( fd_shred_sz( shred ), FD_SHRED_MAX_SZ );
  fd_memset( wr_entry, 0, sizeof(wr_entry) );
  wr_entry->tag      = disk_cell_tag( ticket, FD_SHREDB_CELL_READY );
  wr_entry->key      = key;
  wr_entry->shred_sz = (ushort)shred_sz;
  fd_memcpy( wr_entry->shred, shred, shred_sz );

  off_t off = (off_t)(store->wire_off + ring_idx*sizeof(fd_shredb_entry_t));
  if( FD_UNLIKELY( store_pwrite_all( disk_fd, wr_entry, sizeof(wr_entry), off ) ) )
    FD_LOG_ERR(( "error writing to disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
  atomic_fetch_add_explicit( &store->disk_write_bytes, sizeof(wr_entry), memory_order_relaxed );

  int publish_result = disk_exact_publish( store, cell, old_key, key );
  if( FD_LIKELY( publish_result==DISK_PUBLISH_SUCCESS ) ) {
    disk_slot_hint_publish( store, slot, shred_idx );
    atomic_store_explicit( &cell->tag, wr_entry->tag, memory_order_release );
    if( old_state!=FD_SHREDB_CELL_READY )
      atomic_fetch_add_explicit( &store->disk_cnt, 1UL, memory_order_relaxed );
    atomic_fetch_add_explicit( &store->disk_insert_cnt, 1UL, memory_order_relaxed );
    return FD_STORE_DISK_INSERT_SUCCESS;
  }

  atomic_store_explicit( &cell->tag, disk_cell_tag( ticket, FD_SHREDB_CELL_INVALID ), memory_order_release );
  if( old_state==FD_SHREDB_CELL_READY )
    atomic_fetch_sub_explicit( &store->disk_cnt, 1UL, memory_order_relaxed );
  if( publish_result==DISK_PUBLISH_NOOP ) return FD_STORE_DISK_INSERT_SUCCESS;
  return FD_STORE_DISK_INSERT_ERR;
}

#define FD_STORE_DISK_READ_RETRY_CNT (8UL)

static int
disk_read_key_once( fd_store_t const * store,
                    int                disk_fd,
                    ulong              key,
                    fd_shredb_entry_t * rd_entry ) {
  fd_shredb_shred_map_t map[1];
  FD_TEST( disk_shred_map_ljoin( store, map ) );
  fd_shredb_shred_map_query_t query[1];
  int err = fd_shredb_shred_map_query_try( map, &key, NULL, query, 0 );
  if( FD_UNLIKELY( err==FD_MAP_ERR_AGAIN || err==FD_MAP_ERR_CORRUPT ) ) return FD_STORE_DISK_QUERY_BUSY;
  if( FD_UNLIKELY( err==FD_MAP_ERR_KEY ) ) return FD_STORE_DISK_QUERY_MISS;
  FD_TEST( !err );

  fd_shredb_shred_entry_t const * cell = fd_shredb_shred_map_query_ele_const( query );
  ulong ring_idx = (ulong)(cell-disk_shred_pool_laddr( store ));
  ulong tag = atomic_load_explicit( &cell->tag, memory_order_acquire );
  if( FD_UNLIKELY( disk_cell_state( tag )!=FD_SHREDB_CELL_READY ) ) {
    int query_err = fd_shredb_shred_map_query_test( query );
    if( FD_UNLIKELY( query_err || disk_cell_state( tag )==FD_SHREDB_CELL_WRITING ) ) return FD_STORE_DISK_QUERY_BUSY;
    return FD_STORE_DISK_QUERY_MISS;
  }

  off_t off = (off_t)(store->wire_off + ring_idx*sizeof(fd_shredb_entry_t));
  if( FD_UNLIKELY( store_pread_all( disk_fd, rd_entry, sizeof(fd_shredb_entry_t), off ) ) )
    FD_LOG_ERR(( "error reading disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
  ulong tag_after = atomic_load_explicit( &cell->tag, memory_order_acquire );
  int query_err = fd_shredb_shred_map_query_test( query );
  if( FD_UNLIKELY( query_err || tag_after!=tag ) ) return FD_STORE_DISK_QUERY_BUSY;
  if( FD_UNLIKELY( rd_entry->tag!=tag || rd_entry->key!=key ) ) return FD_STORE_DISK_QUERY_BUSY;
  return (int)fd_ulong_min( rd_entry->shred_sz, FD_SHRED_MAX_SZ );
}

int
fd_store_disk_query( fd_store_t const * store,
                     int                disk_fd,
                     ulong              slot,
                     uint               shred_idx,
                     uchar              out[ FD_SHRED_MAX_SZ ] ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !out || !fd_store_has_disk( store ) ||
                   (slot>>48) || shred_idx>=FD_SHRED_BLK_MAX ) ) return FD_STORE_DISK_QUERY_MISS;
  ulong key = fd_shredb_key_pack( slot, shred_idx );
  for( ulong retry=0UL; retry<FD_STORE_DISK_READ_RETRY_CNT; retry++ ) {
    fd_shredb_entry_t rd_entry[1];
    int result = disk_read_key_once( store, disk_fd, key, rd_entry );
    if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_BUSY ) ) { FD_SPIN_PAUSE(); continue; }
    if( FD_UNLIKELY( result<0 ) ) return result;
    fd_memcpy( out, rd_entry->shred, (ulong)result );
    return result;
  }
  return FD_STORE_DISK_QUERY_BUSY;
}

int
fd_store_disk_query_highest( fd_store_t const * store,
                             int                disk_fd,
                             ulong              slot,
                             uint               min_shred_idx,
                             uchar              out[ FD_SHRED_MAX_SZ ] ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !out || !fd_store_has_disk( store ) || (slot>>48) ) )
    return FD_STORE_DISK_QUERY_MISS;
  for( ulong retry=0UL; retry<FD_STORE_DISK_READ_RETRY_CNT; retry++ ) {
    atomic_ulong const * hint_ptr = disk_slot_hint_laddr( store ) + (slot % store->disk_max_slots);
    ulong hint = atomic_load_explicit( hint_ptr, memory_order_acquire );
    if( FD_UNLIKELY( !(hint & (1UL<<15)) ) ) return FD_STORE_DISK_QUERY_MISS;
    if( FD_UNLIKELY( fd_shredb_key_slot( hint )!=slot ) ) return FD_STORE_DISK_QUERY_BUSY;
    uint idx = (uint)(hint & (FD_SHRED_BLK_MAX-1UL));

    fd_shredb_entry_t rd_entry[1];
    int result = disk_read_key_once( store, disk_fd, fd_shredb_key_pack( slot, idx ), rd_entry );
    ulong hint_after = atomic_load_explicit( hint_ptr, memory_order_acquire );
    if( FD_UNLIKELY( hint_after!=hint || result==FD_STORE_DISK_QUERY_BUSY ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
    if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_MISS ) ) return FD_STORE_DISK_QUERY_SCAN_LIMIT;
    if( FD_UNLIKELY( result<0 ) ) return result;

    fd_shred_t const * shred = (fd_shred_t const *)fd_type_pun_const( rd_entry->shred );
    if( FD_UNLIKELY( idx < min_shred_idx && !(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) ) )
      return FD_STORE_DISK_QUERY_MISS;
    fd_memcpy( out, rd_entry->shred, (ulong)result );
    return result;
  }
  return FD_STORE_DISK_QUERY_BUSY;
}

static int
spill_reclaim_one( fd_store_t * store,
                   int          disk_fd ) {
  if( FD_LIKELY( !FD_VOLATILE_CONST( store->spill_reclaim_cnt ) ) ) return 0;

  fd_rwlock_write( &store->cache_lock );
  if( FD_LIKELY( !store->spill_reclaim_cnt ) ) {
    fd_rwlock_unwrite( &store->cache_lock );
    return 0;
  }
  uint spill_slot = spill_reclaim_laddr( store )[ --store->spill_reclaim_cnt ];
  store->spill_reclaiming_cnt++;
  fd_rwlock_unwrite( &store->cache_lock );

  off_t off = (off_t)((ulong)spill_slot*store->payload_slot_sz);
  int err = fallocate( disk_fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off, (off_t)store->payload_slot_sz );
  int err_no = errno;

  fd_rwlock_write( &store->cache_lock );
  FD_TEST( store->spill_reclaiming_cnt );
  store->spill_reclaiming_cnt--;
  if( FD_LIKELY( !err ) ) {
    FD_TEST( atomic_load_explicit( &store->spill_allocated_cnt, memory_order_relaxed ) );
    atomic_fetch_sub_explicit( &store->spill_allocated_cnt, 1UL, memory_order_relaxed );
    FD_TEST( store->spill_free_cnt<store->spill_slot_cnt );
    spill_free_laddr( store )[ store->spill_free_cnt++ ] = spill_slot;
  } else {
    spill_reuse_push_locked( store, spill_slot );
  }
  fd_rwlock_unwrite( &store->cache_lock );
  if( FD_UNLIKELY( err ) )
    FD_LOG_WARNING(( "error reclaiming spilled FEC page: (%d-%s)", err_no, fd_io_strerror( err_no ) ));
  return 1;
}

int
fd_store_disk_maintain( fd_store_t * store,
                        int          disk_fd ) {
  if( FD_UNLIKELY( !store || disk_fd<0 ) ) return 0;
  return spill_reclaim_one( store, disk_fd );
}

int
fd_store_disk_stats_query( fd_store_t const *      store,
                           fd_store_disk_stats_t * stats ) {
  if( FD_UNLIKELY( !store || !stats || !fd_store_has_disk( store ) ) ) return FD_STORE_DISK_QUERY_MISS;
  stats->shred_cnt       = atomic_load_explicit( &store->disk_cnt, memory_order_relaxed );
  stats->current_bytes   = stats->shred_cnt*sizeof(fd_shredb_entry_t)
                         + atomic_load_explicit( &store->spill_live_cnt, memory_order_relaxed )*store->payload_slot_sz;
  stats->allocated_bytes = store->disk_max_shreds*sizeof(fd_shredb_entry_t)
                         + atomic_load_explicit( &store->spill_allocated_cnt, memory_order_relaxed )*store->payload_slot_sz;
  stats->insert_cnt      = atomic_load_explicit( &store->disk_insert_cnt, memory_order_relaxed );
  stats->write_bytes     = atomic_load_explicit( &store->disk_write_bytes, memory_order_relaxed );
  return 0;
}
