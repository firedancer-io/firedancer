#define _GNU_SOURCE
#include "fd_store.h"

#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define FD_STORE_FEC_DATA_VIEW_SPILL (1U)

enum {
  FD_STORE_SPILL_RETRY    = -1,
  FD_STORE_SPILL_NONE     =  0,
  FD_STORE_SPILL_COMPLETE =  1
};

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

static inline fd_shredb_ring_entry_t *
disk_ring_pool_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->ring_pool_gaddr );
}

static inline fd_shredb_slot_map_t *
disk_slot_map_join( fd_store_t const * store ) {
  void * shmap = fd_wksp_laddr_fast( fd_store_wksp( store ), store->shred_map_gaddr );
  return fd_shredb_slot_map_join( shmap );
}

static inline uint *
disk_tbl_cnt_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->tbl_cnt_gaddr );
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

static inline fd_store_lru_t *
cache_lru_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->cache_lru_gaddr );
}

static inline uint *
spill_free_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->spill_free_gaddr );
}

static inline uchar *
spill_read_data_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->spill_read_data_gaddr );
}

static inline fd_store_fec_t *
pool_ele_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_ele_gaddr );
}

static inline fd_store_slot_to_fecs_t *
slot_to_fecs_laddr( fd_store_t const * store,
                    ulong              part ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->slot_to_fecs_gaddr + part*store->slot_to_fecs_sz );
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
    fec->data_idx             = 0U;
    fec->data_pin_cnt         = 0U;
    fec->data_state           = FD_STORE_FEC_DATA_EMPTY;
    fec->data_consume_pending = 0U;
  }
  return fec;
}

static void
cache_slot_release_locked( fd_store_t * store,
                           ulong        cache_slot ) {
  FD_TEST( cache_slot<store->cache_slot_cnt );
  FD_TEST( store->cache_free_cnt<store->cache_slot_cnt );
  cache_free_laddr( store )[ store->cache_free_cnt++ ] = cache_slot;
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

/* A FEC is on the LRU only while RAM_READY and unpinned, so it is
   linked by its RAM cache slot data_idx. */

static void
cache_lru_remove_locked( fd_store_t *     store,
                         fd_store_fec_t * fec ) {
  fd_store_lru_t * lru  = cache_lru_laddr( store );
  uint             slot = fec->data_idx;
  FD_TEST( slot<store->cache_slot_cnt && lru[ slot ].fec==cache_fec_idx( store, fec ) );
  uint prev = lru[ slot ].prev;
  uint next = lru[ slot ].next;

  if( prev==UINT_MAX ) { FD_TEST( store->cache_lru_head==slot ); store->cache_lru_head = next; }
  else                 lru[ prev ].next = next;
  if( next==UINT_MAX ) { FD_TEST( store->cache_lru_tail==slot ); store->cache_lru_tail = prev; }
  else                 lru[ next ].prev = prev;

  lru[ slot ] = (fd_store_lru_t){ .prev = UINT_MAX, .next = UINT_MAX, .fec = UINT_MAX };
}

static void
cache_lru_push_head_locked( fd_store_t *     store,
                            fd_store_fec_t * fec ) {
  fd_store_lru_t * lru  = cache_lru_laddr( store );
  uint             slot = fec->data_idx;
  FD_TEST( slot<store->cache_slot_cnt && lru[ slot ].fec==UINT_MAX );

  lru[ slot ] = (fd_store_lru_t){ .prev = UINT_MAX, .next = store->cache_lru_head, .fec = cache_fec_idx( store, fec ) };
  if( store->cache_lru_head==UINT_MAX ) store->cache_lru_tail = slot;
  else lru[ store->cache_lru_head ].prev = slot;
  store->cache_lru_head = slot;
}

static void
cache_lru_push_tail_locked( fd_store_t *     store,
                            fd_store_fec_t * fec ) {
  fd_store_lru_t * lru  = cache_lru_laddr( store );
  uint             slot = fec->data_idx;
  FD_TEST( slot<store->cache_slot_cnt && lru[ slot ].fec==UINT_MAX );

  lru[ slot ] = (fd_store_lru_t){ .prev = store->cache_lru_tail, .next = UINT_MAX, .fec = cache_fec_idx( store, fec ) };
  if( store->cache_lru_tail==UINT_MAX ) store->cache_lru_head = slot;
  else lru[ store->cache_lru_tail ].next = slot;
  store->cache_lru_tail = slot;
}

static void
spill_free_push_locked( fd_store_t * store,
                        uint         spill_slot ) {
  FD_TEST( spill_slot<store->spill_slot_cnt && store->spill_free_cnt<store->spill_slot_cnt );
  spill_free_laddr( store )[ store->spill_free_cnt++ ] = spill_slot;
}

static void
cache_consume_locked( fd_store_t *     store,
                      fd_store_fec_t * fec ) {
  if( FD_LIKELY( !fec->data_consume_pending ) ) return;
  if( FD_UNLIKELY( fec->data_pin_cnt || fec->data_state==FD_STORE_FEC_DATA_SPILLING ) ) return;

  if( FD_LIKELY( fec->data_state==FD_STORE_FEC_DATA_RAM_WRITING ||
                 fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) ) {
    if( fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) cache_lru_remove_locked( store, fec );
    cache_slot_release_locked( store, fec->data_idx );
  } else if( fec->data_state==FD_STORE_FEC_DATA_DISK ) {
    ulong spill_slot = fec->data_idx;
    FD_TEST( spill_slot<store->spill_slot_cnt && atomic_load_explicit( &store->spill_live_cnt, memory_order_relaxed ) );
    atomic_fetch_sub_explicit( &store->spill_live_cnt, 1UL, memory_order_relaxed );
    spill_free_push_locked( store, (uint)spill_slot );
  }

  fec->data_idx             = 0U;
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
spill_one_locked( fd_store_t                 * store,
                  int                          disk_fd,
                  fd_store_fec_spill_stats_t * spill ) {
  if( FD_UNLIKELY( disk_fd<0 ) ) return FD_STORE_SPILL_NONE;

  fd_store_fec_t * fec0 = pool_ele_laddr( store );
  uint victim_slot = store->cache_lru_head;
  if( FD_UNLIKELY( victim_slot==UINT_MAX ) ) return FD_STORE_SPILL_NONE;
  fd_store_fec_t * victim = fec0 + cache_lru_laddr( store )[ victim_slot ].fec;
  FD_TEST( victim->data_state==FD_STORE_FEC_DATA_RAM_READY && !victim->data_pin_cnt );
  FD_TEST( victim->data_sz<=store->fec_data_max );

  uint spill_slot;
  if( FD_LIKELY( store->spill_free_cnt ) ) {
    spill_slot = spill_free_laddr( store )[ --store->spill_free_cnt ];
  } else {
    if( FD_UNLIKELY( store->spill_slot_cnt>=store->fec_max ) ) return FD_STORE_SPILL_NONE;
    spill_slot = (uint)store->spill_slot_cnt++;
  }

  ulong ram_slot  = victim->data_idx;
  ulong ram_off   = ram_slot * store->payload_slot_sz;
  ulong spill_off = (ulong)spill_slot * store->payload_slot_sz;
  ulong data_sz   = victim->data_sz;

  cache_lru_remove_locked( store, victim );
  victim->data_state = FD_STORE_FEC_DATA_SPILLING;
  long evict_ticks = -fd_tickcount();
  fd_rwlock_unwrite( &store->cache_lock );

  if( FD_UNLIKELY( store_pwrite_all( disk_fd, cache_data_laddr( store ) + ram_off, FD_STORE_PAYLOAD_HDR_SZ+data_sz, (off_t)spill_off ) ) )
    FD_LOG_ERR(( "error spilling FEC payload to disk: (%d-%s)", errno, fd_io_strerror( errno ) ));

  fd_rwlock_write( &store->cache_lock );
  FD_TEST( victim->data_state==FD_STORE_FEC_DATA_SPILLING );
  int result;
  if( FD_UNLIKELY( victim->data_pin_cnt || victim->data_consume_pending ) ) {
    int try_next = !!victim->data_pin_cnt;
    spill_free_push_locked( store, spill_slot );
    victim->data_state = victim->data_consume_pending && !victim->data_pin_cnt
                       ? FD_STORE_FEC_DATA_RAM_WRITING
                       : FD_STORE_FEC_DATA_RAM_READY;
    if( FD_LIKELY( !victim->data_pin_cnt && !victim->data_consume_pending ) )
      cache_lru_push_tail_locked( store, victim );
    cache_consume_locked( store, victim );
    result = try_next ? FD_STORE_SPILL_RETRY :
             store->cache_free_cnt ? FD_STORE_SPILL_COMPLETE : FD_STORE_SPILL_NONE;
  } else {
    victim->data_idx   = spill_slot;
    victim->data_state = FD_STORE_FEC_DATA_DISK;
    atomic_fetch_add_explicit( &store->spill_live_cnt, 1UL, memory_order_relaxed );
    atomic_fetch_add_explicit( &store->fec_spill_cnt, 1UL, memory_order_relaxed );
    atomic_fetch_add_explicit( &store->fec_spill_bytes, data_sz, memory_order_relaxed );
    cache_slot_release_locked( store, ram_slot );
    result = FD_STORE_SPILL_COMPLETE;
  }

  evict_ticks += fd_tickcount();
  if( FD_LIKELY( spill ) ) {
    spill->write_cnt++;
    spill->write_bytes += data_sz;
    spill->write_ticks += (ulong)evict_ticks;
  }
  return result;
}


void *
fd_store_new( void       * shmem,
              ulong        fec_max,
              ulong        fec_data_max,
              ulong        shred_storage_gib,
              ulong        shred_cache_bytes,
              ulong        fec_set_cnt,
              ulong        max_shreds_per_block,
              ulong        seed,
              ulong        shred_tile_cnt ) {

  if( FD_UNLIKELY( !shmem ) ) { FD_LOG_WARNING(( "NULL shmem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned shmem" )); return NULL; }
  if( FD_UNLIKELY( !fec_max ) ) { FD_LOG_WARNING(( "fec_max must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( fec_max>UINT_MAX ) ) { FD_LOG_WARNING(( "fec_max must fit in uint" )); return NULL; }
  if( FD_UNLIKELY( !fec_data_max ) ) { FD_LOG_WARNING(( "fec_data_max must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( fec_data_max>UINT_MAX ) ) { FD_LOG_WARNING(( "fec_data_max must fit in uint" )); return NULL; }
  if( FD_UNLIKELY( !max_shreds_per_block || max_shreds_per_block>FD_SHREDB_HINT_VALID ) ) { FD_LOG_WARNING(( "bad max_shreds_per_block (%lu)", max_shreds_per_block )); return NULL; }
  if( FD_UNLIKELY( !shred_tile_cnt ) ) { FD_LOG_WARNING(( "shred_tile_cnt must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( shred_storage_gib>FD_SHREDB_MAX_SIZE_GIB ) ) {
    FD_LOG_ERR(( "shred database size limit is %lu GiB, but the maximum supported size is %lu GiB",
                 shred_storage_gib, FD_SHREDB_MAX_SIZE_GIB ));
  }

  ulong footprint = fd_store_footprint( fec_max, fec_data_max, shred_storage_gib, shred_cache_bytes, fec_set_cnt, shred_tile_cnt );
  if( FD_UNLIKELY( !footprint ) ) { FD_LOG_WARNING(( "invalid or overflowing store footprint" )); return NULL; }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "shmem must be part of a workspace" )); return NULL; }

  ulong chain_cnt       = fd_store_map_chain_cnt_est( fec_max>>1 );
  ulong part_cnt        = shred_tile_cnt;
  ulong slot_chain_cnt  = fd_store_slot_to_fecs_chain_cnt_est( 8UL*(fec_max/FD_FEC_BLK_MAX) );
  ulong slot_to_fecs_sz = fd_ulong_align_up( fd_store_slot_to_fecs_footprint( slot_chain_cnt ), fd_store_slot_to_fecs_align() );
  ulong payload_slot_sz = fd_store_payload_slot_sz( fec_data_max );
  ulong cache_slot_cnt = shred_cache_bytes
                       ? fd_ulong_min( fec_max, fd_ulong_max( 1UL, shred_cache_bytes / payload_slot_sz ) )
                       : fec_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_store_t *   store          = FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(),         sizeof(fd_store_t)                  );
  void *         map            = FD_SCRATCH_ALLOC_APPEND( l, fd_store_map_align(),     fd_store_map_footprint( chain_cnt ) );
  void *         shpool         = FD_SCRATCH_ALLOC_APPEND( l, fd_store_pool_align(),    fd_store_pool_footprint()           );
  void *         shele          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_fec_t),  sizeof(fd_store_fec_t)*fec_max      );
  uchar *        slot_to_fecs   = FD_SCRATCH_ALLOC_APPEND( l, fd_store_slot_to_fecs_align(), slot_to_fecs_sz*part_cnt );
  uchar *        cache_mem      = FD_SCRATCH_ALLOC_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ, payload_slot_sz*cache_slot_cnt      );
  ulong *        cache_free     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),           sizeof(ulong)*cache_slot_cnt        );
  fd_store_lru_t * cache_lru    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_lru_t),  sizeof(fd_store_lru_t)*cache_slot_cnt );
  uint *         spill_free     = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            sizeof(uint)*fec_max                );
  uchar *        spill_read_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ, payload_slot_sz                      );
  fd_fec_set_t * fec_sets       = fec_set_cnt
                                ? FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fec_set_t), sizeof(fd_fec_set_t)*fec_set_cnt )
                                : NULL;

  void *                   shred_map_mem  = NULL;
  fd_shredb_ring_entry_t * ring_pool_mem  = NULL;
  atomic_ulong *           slot_hint_mem  = NULL;
  uint *                   tbl_cnt_mem    = NULL;
  ulong                    max_shreds     = 0UL;
  ulong                    max_slots      = 0UL;
  ulong                    disk_chain_cnt = 0UL;

  if( shred_storage_gib ) {
    max_shreds     = fd_shredb_max_shreds( shred_storage_gib );
    max_slots      = fd_shredb_max_slots( shred_storage_gib );
    disk_chain_cnt = fd_shredb_disk_chain_cnt( max_shreds );

    shred_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_slot_map_align(),      fd_shredb_slot_map_footprint( disk_chain_cnt ) );
    ring_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shredb_ring_entry_t), max_shreds*sizeof(fd_shredb_ring_entry_t) );
    slot_hint_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(atomic_ulong),           max_slots*sizeof(atomic_ulong) );
    tbl_cnt_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   max_slots*sizeof(uint) );
  }

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_store_align() )==(ulong)shmem + footprint );

  ulong payload_sz;
  ulong wire_sz;
  ulong tbl_sz;
  ulong file_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( payload_slot_sz, fec_max, &payload_sz ) ||
                   __builtin_umull_overflow( max_shreds, sizeof(fd_shredb_entry_t), &wire_sz ) ||
                   __builtin_umull_overflow( fd_shredb_tbl_rec_cnt( max_shreds ), sizeof(fd_shredb_tbl_rec_t), &tbl_sz ) ||
                   __builtin_uaddl_overflow( payload_sz, wire_sz, &file_sz ) ||
                   __builtin_uaddl_overflow( file_sz, tbl_sz, &file_sz ) ||
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
  store->shred_tile_cnt        = shred_tile_cnt;
  store->slot_to_fecs_gaddr    = fd_wksp_gaddr_fast( wksp, slot_to_fecs );
  store->slot_to_fecs_sz       = slot_to_fecs_sz;
  atomic_init( &store->slot_lo, ULONG_MAX );
  store->payload_slot_sz       = payload_slot_sz;
  store->payload_sz            = payload_sz;
  store->wire_off              = payload_sz; /* wire region begins after the payload region (page-aligned) */
  store->cache_slot_cnt        = cache_slot_cnt;
  store->cache_data_gaddr      = fd_wksp_gaddr_fast( wksp, cache_mem );
  store->cache_free_gaddr      = fd_wksp_gaddr_fast( wksp, cache_free );
  store->cache_free_cnt        = cache_slot_cnt;
  store->cache_lru_gaddr       = fd_wksp_gaddr_fast( wksp, cache_lru );
  ulong free_cap               = fd_ulong_min( 8192UL, (64UL<<20) / payload_slot_sz );
  ulong burst_floor            = fd_ulong_min( 512UL, cache_slot_cnt/2UL );
  ulong free_target            = fd_ulong_max( cache_slot_cnt/10UL, burst_floor );
  store->cache_free_target     = fd_ulong_max( 1UL, fd_ulong_min( free_cap, free_target ) );
  store->cache_free_low_water  = fd_ulong_max( 1UL, (store->cache_free_target*3UL)/4UL );
  store->cache_lru_head        = UINT_MAX;
  store->cache_lru_tail        = UINT_MAX;
  store->spill_free_gaddr      = fd_wksp_gaddr_fast( wksp, spill_free );
  store->spill_read_data_gaddr = fd_wksp_gaddr_fast( wksp, spill_read_mem );
  store->fec_set_cnt           = fec_set_cnt;
  store->fec_sets_gaddr        = fec_set_cnt ? fd_wksp_gaddr_fast( wksp, fec_sets ) : 0UL;
  store->max_shreds_per_block  = max_shreds_per_block;
  fd_rwlock_new( &store->cache_lock );
  fd_rwlock_new( &store->spill_read_lock );
  fd_rwlock_new( &store->fec_lock );
  atomic_init( &store->fec_spill_cnt, 0UL );
  atomic_init( &store->spill_live_cnt, 0UL );
  atomic_init( &store->fec_spill_bytes, 0UL );
  atomic_init( &store->fec_spill_read_cnt, 0UL );
  atomic_init( &store->fec_spill_read_bytes, 0UL );

  void * shmap = fd_store_map_new( map, chain_cnt, seed );
  if( FD_UNLIKELY( !shmap ) ) { FD_LOG_WARNING(( "fd_store_map_new failed" )); return NULL; }
  store->map_gaddr = fd_wksp_gaddr_fast( wksp, shmap );

  if( FD_UNLIKELY( !fd_store_pool_new( shpool ) ) ) { FD_LOG_WARNING(( "fd_store_pool_new failed" )); return NULL; }
  fd_store_pool_t pool_ljoin;
  fd_store_pool_reset( fd_store_pool_join( &pool_ljoin, shpool, shele, fec_max ) );

  for( ulong i=0UL; i<cache_slot_cnt; i++ ) {
    cache_free[ i ] = cache_slot_cnt - 1UL - i;
    cache_lru [ i ] = (fd_store_lru_t){ .prev = UINT_MAX, .next = UINT_MAX, .fec = UINT_MAX };
  }

  /* FEC metadata starts without a payload location. */
  fd_store_fec_t * fec0 = (fd_store_fec_t *)shele;
  for( ulong i=0UL; i<fec_max; i++ ) {
    fec0[ i ].data_idx     = 0U;
    fec0[ i ].data_pin_cnt = 0U;
    fec0[ i ].data_state   = FD_STORE_FEC_DATA_EMPTY;
    fec0[ i ].data_consume_pending = 0U;
  }

  for( ulong i=0UL; i<part_cnt; i++ ) FD_TEST( fd_store_slot_to_fecs_new( slot_to_fecs + i*slot_to_fecs_sz, slot_chain_cnt, seed ) );

  if( shred_storage_gib ) {
    void * slot_map = fd_shredb_slot_map_new( shred_map_mem, disk_chain_cnt, seed );
    FD_TEST( slot_map );
    store->shred_map_gaddr = fd_wksp_gaddr_fast( wksp, slot_map );
    store->ring_pool_gaddr = fd_wksp_gaddr_fast( wksp, ring_pool_mem );
    store->slot_hint_gaddr = fd_wksp_gaddr_fast( wksp, slot_hint_mem );
    store->disk_max_shreds = max_shreds;
    store->disk_max_slots  = max_slots;
    store->tbl_cnt_gaddr   = fd_wksp_gaddr_fast( wksp, tbl_cnt_mem );
    store->disk_root_seed  = seed;
    store->disk_tbl_gen    = (uint)fd_ulong_hash( seed ) | 1U; /* records of other boots read as empty */
    fd_rwlock_new( &store->disk_lock );
    fd_rwlock_new( &store->tbl_lock );

    /* Unlink examines the old key even for a never-used cell.  Initialize
       the key and the INVALID tag; chain links are set on insertion. */
    fd_memset( ring_pool_mem, 0, max_shreds*sizeof(fd_shredb_ring_entry_t) );
    for( ulong i=0UL; i<max_slots; i++ ) {
      atomic_init( slot_hint_mem+i, 0UL );
      tbl_cnt_mem[ i ] = 0U;
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
fd_store_file_create( char const * path,
                      ulong        wire_off,
                      ulong        disk_max_shreds,
                      ulong        tail_sz ) {
  if( FD_UNLIKELY( !path ) ) {
    errno = EINVAL;
    return -1;
  }

  ulong wire_sz;
  ulong tbl_sz;
  ulong file_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( disk_max_shreds, sizeof(fd_shredb_entry_t), &wire_sz ) ||
                   __builtin_umull_overflow( fd_shredb_tbl_rec_cnt( disk_max_shreds ), sizeof(fd_shredb_tbl_rec_t), &tbl_sz ) ||
                   __builtin_uaddl_overflow( wire_off, wire_sz, &file_sz ) ||
                   __builtin_uaddl_overflow( file_sz, tbl_sz, &file_sz ) ||
                   __builtin_uaddl_overflow( file_sz, tail_sz, &file_sz ) ||
                   file_sz>(ulong)LONG_MAX ) ) {
    errno = EOVERFLOW;
    return -1;
  }

  /* No O_TRUNC it frees a previous run's extents and page cache
     synchronously. */
  int fd = open( path, O_RDWR|O_CREAT, (mode_t)0600 );
  if( FD_UNLIKELY( fd<0 ) ) return -1;

  int err = 0;
  if( FD_UNLIKELY( ftruncate( fd, (off_t)file_sz ) ) ) err = errno;
  if( FD_UNLIKELY( err ) ) {
    if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_WARNING(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    errno = err;
    return -1;
  }
  return fd;
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
fd_store_fec_data_reserve( fd_store_t                 * store,
                           int                          disk_fd,
                           uint                       * data_idx,
                           fd_store_fec_spill_stats_t * spill ) {
  if( FD_LIKELY( spill ) ) *spill = (fd_store_fec_spill_stats_t){0};
  if( FD_UNLIKELY( !store || !data_idx ) ) return NULL;

  /* Pops a free RAM cache slot, spilling LRU payloads as needed. */
  fd_rwlock_write( &store->cache_lock );

  while( FD_UNLIKELY( !store->cache_free_cnt ) ) {
    if( FD_UNLIKELY( store->cache_lru_head==UINT_MAX ) ) {
      fd_rwlock_unwrite( &store->cache_lock );
      FD_SPIN_PAUSE();
      fd_rwlock_write( &store->cache_lock );
      continue;
    }
    int spill_result = spill_one_locked( store, disk_fd, spill );
    if( FD_UNLIKELY( spill_result==FD_STORE_SPILL_RETRY ) ) {
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

  ulong slot = cache_free_laddr( store )[ --store->cache_free_cnt ];
  fd_rwlock_unwrite( &store->cache_lock );

  *data_idx = (uint)slot;
  return cache_data_laddr( store ) + slot*store->payload_slot_sz + FD_STORE_PAYLOAD_HDR_SZ;
}

int
fd_store_fec_data_preevict( fd_store_t                  * store,
                            int                           disk_fd,
                            fd_store_fec_spill_stats_t * spill ) {
  fd_store_fec_spill_stats_t local_spill[1];
  if( FD_UNLIKELY( !spill ) ) spill = local_spill;
  *spill = (fd_store_fec_spill_stats_t){0};
  if( FD_UNLIKELY( !store || disk_fd<0 ) ) return 0;

  /* called every pass: don't take the write lock for nothing */
  if( FD_LIKELY( !FD_VOLATILE_CONST( store->cache_preevict_active ) &&
                 FD_VOLATILE_CONST( store->cache_free_cnt )>=store->cache_free_low_water ) ) return 0;

  fd_rwlock_write( &store->cache_lock );
  if( FD_UNLIKELY( !store->cache_preevict_active && store->cache_free_cnt<store->cache_free_low_water ) )
    store->cache_preevict_active = 1U;
  if( FD_UNLIKELY( store->cache_preevict_active && store->cache_free_cnt>=store->cache_free_target ) )
    store->cache_preevict_active = 0U;

  if( FD_LIKELY( !store->cache_preevict_active ) ) {
    fd_rwlock_unwrite( &store->cache_lock );
    return 0;
  }

  spill_one_locked( store, disk_fd, spill );
  if( FD_UNLIKELY( store->cache_free_cnt>=store->cache_free_target ) )
    store->cache_preevict_active = 0U;
  fd_rwlock_unwrite( &store->cache_lock );
  return !!spill->write_cnt;
}

void
fd_store_fec_cache_stats_query( fd_store_t                 * store,
                                fd_store_fec_cache_stats_t * stats ) {
  if( FD_UNLIKELY( !store || !stats ) ) return;
  fd_rwlock_read( &store->cache_lock );
  stats->free_cnt = store->cache_free_cnt;
  stats->max       = store->cache_slot_cnt;
  stats->target    = store->cache_free_target;
  stats->low_water = store->cache_free_low_water;
  fd_rwlock_unread( &store->cache_lock );
}

static void
cache_pin_locked( fd_store_t *     store,
                  fd_store_fec_t * fec ) {
  if( FD_UNLIKELY( !fec->data_pin_cnt && fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) )
    cache_lru_remove_locked( store, fec );
  FD_TEST( fec->data_pin_cnt<USHORT_MAX );
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
  view->data     = NULL;
  view->shred_sz = NULL;
  view->fec      = NULL;
  view->flags    = 0U;
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
    uchar * slot   = cache_data_laddr( store ) + (ulong)fec->data_idx*store->payload_slot_sz;
    view->shred_sz = (ushort const *)slot;
    view->data     = slot + FD_STORE_PAYLOAD_HDR_SZ;
    view->fec      = fec;
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
    ulong data_off = (ulong)fec->data_idx*store->payload_slot_sz;
    uchar * spill_read_data = spill_read_data_laddr( store );
    cache_pin_locked( store, fec );
    fd_rwlock_unwrite( &store->cache_lock );

    if( FD_UNLIKELY( store_pread_all( disk_fd, spill_read_data, FD_STORE_PAYLOAD_HDR_SZ+data_sz, (off_t)data_off ) ) )
      FD_LOG_ERR(( "error reading spilled FEC payload: (%d-%s)", errno, fd_io_strerror( errno ) ));

    atomic_fetch_add_explicit( &store->fec_spill_read_cnt, 1UL, memory_order_relaxed );
    atomic_fetch_add_explicit( &store->fec_spill_read_bytes, data_sz, memory_order_relaxed );

    view->shred_sz = (ushort const *)spill_read_data;
    view->data     = spill_read_data + FD_STORE_PAYLOAD_HDR_SZ;
    view->fec      = fec;
    view->flags    = FD_STORE_FEC_DATA_VIEW_SPILL;
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

  view->data     = NULL;
  view->shred_sz = NULL;
  view->fec      = NULL;
  view->flags    = 0U;
}

fd_store_fec_t *
fd_store_query( fd_store_map_t *  map,
                fd_hash_t const * merkle_root ) {
  fd_mr20_t key; memcpy( key.uc, merkle_root->uc, sizeof(fd_mr20_t) );
  for(;;) {
    fd_store_map_query_t query[1];
    int err = fd_store_map_query_try( map, &key, NULL, query, 0 );
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
                 ulong              slot,
                 ulong              part,
                 uint               data_idx,
                 uint               data_sz,
                 ushort const       shred_sz[ FD_FEC_SHRED_CNT ],
                 fd_store_fec_t **  fec ) {
  FD_TEST( store && map && merkle_root && shred_sz && fec );
  FD_TEST( data_idx<store->cache_slot_cnt && data_sz<=store->fec_data_max );
  *fec = NULL;
  fd_mr20_t key; memcpy( key.uc, merkle_root->uc, sizeof(fd_mr20_t) );
  fd_rwlock_read( &store->fec_lock );

  struct {
    fd_store_map_txn_t              txn [1];
    fd_store_map_txn_private_info_t info[1];
  } map_txn_mem;
  fd_store_map_txn_t * txn = fd_store_map_txn_init( map_txn_mem.txn, map, 1UL );
  FD_TEST( !fd_store_map_txn_add( txn, &key, 1 ) );
  FD_TEST( !fd_store_map_txn_try( txn, FD_MAP_FLAG_BLOCKING ) );

  fd_store_map_query_t query[1];
  int err = fd_store_map_txn_query( map, &key, NULL, query, 0 );
  if( FD_LIKELY( err==FD_MAP_ERR_KEY ) ) {
    fd_store_fec_t * new_fec = fd_store_fec_acquire( store );
    FD_TEST( new_fec );
    new_fec->key     = key;
    new_fec->data_sz = data_sz;
    memcpy( cache_data_laddr( store ) + (ulong)data_idx*store->payload_slot_sz, shred_sz, FD_STORE_PAYLOAD_HDR_SZ );

    /* RAM_READY before it is linked: fd_store_publish (exclusive
       fec_lock) never sees it mid-write. */
    fd_rwlock_write( &store->cache_lock );
    new_fec->data_idx   = data_idx;
    new_fec->data_state = FD_STORE_FEC_DATA_RAM_READY;
    cache_lru_push_tail_locked( store, new_fec );
    fd_rwlock_unwrite( &store->cache_lock );

    FD_TEST( part<store->shred_tile_cnt );
    new_fec->slot = (uint)fd_ulong_max( slot, store->root );
    ulong lo = atomic_load_explicit( &store->slot_lo, memory_order_relaxed );
    while( new_fec->slot<lo && !atomic_compare_exchange_weak_explicit( &store->slot_lo, &lo, new_fec->slot, memory_order_relaxed, memory_order_relaxed ) );
    fd_store_slot_to_fecs_ele_insert( fd_store_slot_to_fecs_join( slot_to_fecs_laddr( store, part ) ), new_fec, pool_ele_laddr( store ) );
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

  if( FD_UNLIKELY( err==FD_MAP_ERR_KEY ) ) {
    fd_rwlock_write( &store->cache_lock );
    cache_slot_release_locked( store, data_idx );
    fd_rwlock_unwrite( &store->cache_lock );
  }
  return err;
}

ulong
fd_store_publish( fd_store_t *     store,
                  fd_store_map_t * map,
                  ulong            root ) {
  fd_store_fec_t * fec0 = pool_ele_laddr( store );
  ulong            cnt  = 0UL;
  fd_rwlock_write( &store->fec_lock );
  ulong            lo   = atomic_load_explicit( &store->slot_lo, memory_order_relaxed );
  for( ulong part=0UL; part<store->shred_tile_cnt; part++ ) {
    fd_store_slot_to_fecs_t * slot_to_fecs = fd_store_slot_to_fecs_join( slot_to_fecs_laddr( store, part ) );
    for( ulong slot=lo; slot<root; slot++ ) {
      uint key = (uint)slot;
      for( ulong idx = fd_store_slot_to_fecs_idx_remove( slot_to_fecs, &key, ULONG_MAX, fec0 );
                 idx!=ULONG_MAX;
                 idx = fd_store_slot_to_fecs_idx_remove( slot_to_fecs, &key, ULONG_MAX, fec0 ) ) {
        fd_store_map_query_t query[1];
        FD_TEST( !fd_store_map_remove( map, &fec0[ idx ].key, NULL, query, FD_MAP_FLAG_BLOCKING ) );
        fd_store_fec_release( store, fd_store_map_query_ele( query ) );
        cnt++;
      }
    }
  }
  if( FD_LIKELY( lo<root ) ) atomic_store_explicit( &store->slot_lo, root, memory_order_relaxed );
  store->root = fd_ulong_max( store->root, root );
  fd_rwlock_unwrite( &store->fec_lock );
  return cnt;
}


/* Cells, the slot map, tbl_cnt and reservation decisions use disk_lock,
   which is never held across I/O; WRITING cells reserve their keys while
   their pwrite runs unlocked.  An insert that needs the version table
   (another version of its key is stored, or it overwrites a NONFIRST
   cell) holds tbl_lock exclusively for the whole insert, so NONFIRST
   cells and table records are stable under a shared tbl_lock.  Every
   READY or WRITING cell is linked in the slot map or recorded and
   counted in tbl_cnt.  Production has one rserve tile, the sole disk_*
   caller. */
#define FD_STORE_DISK_READ_RETRY_CNT (8UL)

static inline uint
disk_cell_lap( ulong ticket,
               ulong max_shreds ) {
  return (uint)((ticket/max_shreds) & FD_SHREDB_LAP_MASK);
}

static inline uint
disk_cell_tag( uint lap,
               uint state ) {
  return (lap<<2) | state;
}

static inline ulong
disk_cell_state( ulong tag ) {
  return tag & FD_SHREDB_CELL_STATE_MASK;
}

static inline off_t
disk_cell_off( fd_store_t const * store,
               ulong              ring_idx ) {
  return (off_t)(store->wire_off + ring_idx*sizeof(fd_shredb_entry_t));
}

#define FD_SHREDB_ENTRY_HDR_SZ (__builtin_offsetof( fd_shredb_entry_t, shred ))

static void
disk_slot_hint_publish_locked( fd_store_t * store,
                               ulong        slot,
                               uint         shred_idx ) {
  atomic_ulong * hint = disk_slot_hint_laddr( store ) + (slot % store->disk_max_slots);
  ulong current = atomic_load_explicit( hint, memory_order_relaxed );
  if( FD_LIKELY( current & FD_SHREDB_HINT_VALID ) ) {
    uint current_idx = fd_shredb_key_shred_idx( current & ~FD_SHREDB_HINT_VALID );
    if( FD_LIKELY( fd_shredb_key_slot( current )==slot ) && current_idx>=shred_idx ) return;
  }
  ulong desired = fd_shredb_key_pack( slot, shred_idx ) | FD_SHREDB_HINT_VALID;
  atomic_store_explicit( hint, desired, memory_order_release );
}

/* The slot map is an fd_map_chain over the ring pool; all helpers
   require disk_lock.  Lookups use the _const query so concurrent readers
   (shared disk_lock) are safe; link/unlink mutate and run only under the
   exclusive write lock.  UINT_MAX is the miss sentinel (no ring index can
   equal it since disk_max_shreds < UINT_MAX). */
static inline uint
disk_slot_lookup_locked( fd_store_t const * store,
                         ulong              key ) {
  fd_shredb_slot_map_t * map = disk_slot_map_join( store );
  return (uint)fd_shredb_slot_map_idx_query_const( map, &key, UINT_MAX, disk_ring_pool_laddr( store ) );
}

static void
disk_invalidate_locked( fd_store_t * store,
                        uint         ring_idx ) {
  fd_shredb_ring_entry_t * pool = disk_ring_pool_laddr( store );
  fd_shredb_ring_entry_t * cell = pool + ring_idx;
  FD_TEST( disk_cell_state( cell->tag )!=FD_SHREDB_CELL_WRITING );

  fd_shredb_slot_map_t * slot_map = disk_slot_map_join( store );
  if( (uint)fd_shredb_slot_map_idx_query( slot_map, &cell->key, UINT_MAX, pool )==ring_idx ) {
    fd_shredb_slot_map_idx_remove( slot_map, &cell->key, UINT_MAX, pool );
  }

  if( disk_cell_state( cell->tag )==FD_SHREDB_CELL_READY ) {
    ulong disk_cnt = atomic_load_explicit( &store->disk_cnt, memory_order_relaxed );
    FD_TEST( disk_cnt!=0UL );
    atomic_store_explicit( &store->disk_cnt, disk_cnt-1UL, memory_order_relaxed );
  }
  cell->tag = (cell->tag & ~(uint)FD_SHREDB_CELL_STATE_MASK) | (uint)FD_SHREDB_CELL_INVALID;
}

/* A snapshot of a cell's tag kept after releasing the rwlock.
   This view is only held on the caller's stack across disk I/O. */
struct disk_view {
  uint lap;
  uint ring_idx;
  int  linked;
};
typedef struct disk_view disk_view_t;

/* disk_cell_recorded_locked returns whether ring_idx holds a NONFIRST
   shred, which has a table record. */
static inline int
disk_cell_recorded_locked( fd_store_t const * store,
                           uint               ring_idx ) {
  fd_shredb_ring_entry_t const * cell = disk_ring_pool_laddr( store ) + ring_idx;
  return disk_cell_state( cell->tag )==FD_SHREDB_CELL_READY && disk_slot_lookup_locked( store, cell->key )!=ring_idx;
}

/* disk_insert_prepare_write_locked reserves the next cell for key, of
   kind FIRST (linked) or NONFIRST (counted in tbl_cnt).  *old_recorded
   is set if the cell held a NONFIRST shred, whose table record and
   count the caller must retire. */
static int
disk_insert_prepare_write_locked( fd_store_t  * store,
                                  ulong         key,
                                  int           kind,
                                  disk_view_t * view,
                                  int         * old_recorded ) {
  fd_shredb_ring_entry_t * pool = disk_ring_pool_laddr( store );

  /* Grab a ticket & ring_idx to write to.
     May wrap around and overwrite an existing cell that's not mid-write. */
  ulong ticket   = atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed );
  uint  ring_idx = (uint)(ticket % store->disk_max_shreds);
  atomic_store_explicit( &store->disk_reservation_head, ticket + 1UL, memory_order_relaxed );
  fd_shredb_ring_entry_t * cell = pool + ring_idx;
  if( FD_UNLIKELY( disk_cell_state( cell->tag )==FD_SHREDB_CELL_WRITING ) ) return FD_STORE_DISK_INSERT_ERR;
  *old_recorded = disk_cell_recorded_locked( store, ring_idx );

  /* Retire the ring cell's old key before changing it. */
  disk_invalidate_locked( store, ring_idx );

  uint lap  = disk_cell_lap( ticket, store->disk_max_shreds );
  cell->tag = disk_cell_tag( lap, FD_SHREDB_CELL_WRITING );
  cell->key = key;
  if( kind==FD_SHREDB_KIND_FIRST ) fd_shredb_slot_map_idx_insert( disk_slot_map_join( store ), ring_idx, pool );
  else                             disk_tbl_cnt_laddr( store )[ fd_shredb_key_slot( key ) % store->disk_max_slots ]++;

  view->lap      = lap;
  view->ring_idx = ring_idx;
  view->linked   = kind==FD_SHREDB_KIND_FIRST;
  return FD_STORE_DISK_INSERT_SUCCESS;
}

static int
disk_insert_finish_write_locked( fd_store_t * store,
                                 disk_view_t  view ) {
  fd_shredb_ring_entry_t * cell = disk_ring_pool_laddr( store ) + view.ring_idx;
  FD_TEST( cell->tag==disk_cell_tag( view.lap, FD_SHREDB_CELL_WRITING ) );

  ulong disk_cnt = atomic_load_explicit( &store->disk_cnt, memory_order_relaxed );
  atomic_store_explicit( &store->disk_cnt, disk_cnt+1UL, memory_order_relaxed );
  cell->tag = disk_cell_tag( view.lap, FD_SHREDB_CELL_READY );

  if( view.linked ) disk_slot_hint_publish_locked( store, fd_shredb_key_slot( cell->key ), fd_shredb_key_shred_idx( cell->key ) );
  return FD_STORE_DISK_INSERT_SUCCESS;
}

FD_STATIC_ASSERT( __builtin_offsetof( fd_shredb_entry_t, shred )==__builtin_offsetof( fd_shredb_entry_t, shred_sz )+sizeof(ushort), shredb_entry_hdr_packed );

/* The map entries remain WRITING while the pwrite runs unlocked. */
static int
disk_insert_write( fd_store_t *       store,
                   int                disk_fd,
                   fd_shred_t const * shred,
                   fd_hash_t const *  merkle_root,
                   disk_view_t        view ) {
  fd_shredb_entry_t wr_entry[1];
  ulong shred_sz = fd_ulong_min( fd_shred_sz( shred ), FD_SHRED_MAX_SZ );
  ulong tail_off = FD_SHREDB_ENTRY_HDR_SZ+shred_sz;
  wr_entry->tag      = disk_cell_tag( view.lap, FD_SHREDB_CELL_READY );
  wr_entry->key      = fd_shredb_key_pack( shred->slot, shred->idx );
  wr_entry->shred_sz = (ushort)shred_sz;
  memcpy( wr_entry->root, merkle_root->uc, FD_SHRED_MERKLE_NODE_SZ );
  fd_memcpy( wr_entry->shred, shred, shred_sz );
  fd_memset( (uchar *)wr_entry+tail_off, 0, sizeof(wr_entry)-tail_off );

  if( FD_UNLIKELY( store_pwrite_all( disk_fd, wr_entry, sizeof(wr_entry), disk_cell_off( store, view.ring_idx ) ) ) )
    FD_LOG_ERR(( "error writing to disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
  atomic_fetch_add_explicit( &store->disk_write_bytes, sizeof(wr_entry), memory_order_relaxed );

  fd_rwlock_write( &store->disk_lock );
  int result = disk_insert_finish_write_locked( store, view );
  fd_rwlock_unwrite( &store->disk_lock );
  if( FD_UNLIKELY( result!=FD_STORE_DISK_INSERT_SUCCESS ) ) return result;

  atomic_fetch_add_explicit( &store->disk_insert_cnt, 1UL, memory_order_relaxed );
  return FD_STORE_DISK_INSERT_SUCCESS;
}

static int
disk_view_locked( fd_store_t const * store,
                  uint               ring_idx,
                  disk_view_t      * view ) {
  uint tag = disk_ring_pool_laddr( store )[ ring_idx ].tag;
  if( FD_UNLIKELY( disk_cell_state( tag )!=FD_SHREDB_CELL_READY ) ) {
    if( disk_cell_state( tag )==FD_SHREDB_CELL_WRITING ) return FD_STORE_DISK_QUERY_BUSY;
    return FD_STORE_DISK_QUERY_MISS;
  }
  view->lap      = tag>>2;
  view->ring_idx = ring_idx;
  view->linked   = 0;
  return 0;
}

static int
disk_query_prepare_read_locked( fd_store_t  const * store,
                                ulong               key,
                                disk_view_t *       view ) {
  uint ring_idx = disk_slot_lookup_locked( store, key );
  if( FD_UNLIKELY( ring_idx==UINT_MAX ) ) return FD_STORE_DISK_QUERY_MISS;
  return disk_view_locked( store, ring_idx, view );
}

static int
disk_query_finish_read_locked( fd_store_t  const * store,
                               disk_view_t         view ) {
  fd_shredb_ring_entry_t const * cell = disk_ring_pool_laddr( store ) + view.ring_idx;
  if( FD_UNLIKELY( cell->tag!=disk_cell_tag( view.lap, FD_SHREDB_CELL_READY ) ) ) return FD_STORE_DISK_QUERY_BUSY;
  return 0;
}

/* disk_read_view preads the first sz bytes of view's cell, releasing
   disk_lock for the I/O.  The tag checks reject a torn read if the
   cell was overwritten meanwhile. */
static int
disk_read_view( fd_store_t const *  store,
                int                 disk_fd,
                disk_view_t         view,
                fd_shredb_entry_t * rd_entry,
                ulong               sz ) {
  /* need mutable rwlock to read, even under a const ptr */
  fd_rwlock_t * rwlock = (fd_rwlock_t *)fd_type_pun_const( &store->disk_lock );
  if( FD_UNLIKELY( store_pread_all( disk_fd, rd_entry, sz, disk_cell_off( store, view.ring_idx ) ) ) ) {
    FD_LOG_ERR(( "error reading disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
    return FD_STORE_DISK_QUERY_BUSY;
  }
  fd_rwlock_read( rwlock );
  int result = disk_query_finish_read_locked( store, view );
  fd_rwlock_unread( rwlock );
  if( FD_UNLIKELY( result ) ) return result;
  if( FD_UNLIKELY( rd_entry->tag!=disk_cell_tag( view.lap, FD_SHREDB_CELL_READY ) ) ) return FD_STORE_DISK_QUERY_BUSY;
  return 0;
}

/* disk_read_once reads the first version of key, snapshotting and
   validating under disk_lock and releasing it only for pread. */
static int
disk_read_once( fd_store_t const *  store,
                int                 disk_fd,
                ulong               key,
                fd_shredb_entry_t * rd_entry ) {
  fd_rwlock_t * rwlock = (fd_rwlock_t *)fd_type_pun_const( &store->disk_lock );

  disk_view_t view;
  fd_rwlock_read( rwlock );
  int result = disk_query_prepare_read_locked( store, key, &view );
  fd_rwlock_unread( rwlock );
  if( FD_UNLIKELY( result ) ) return result;

  result = disk_read_view( store, disk_fd, view, rd_entry, sizeof(fd_shredb_entry_t) );
  if( FD_UNLIKELY( result ) ) return result;
  if( FD_UNLIKELY( rd_entry->key!=key ) ) return FD_STORE_DISK_QUERY_BUSY;
  return (int)fd_ulong_min( rd_entry->shred_sz, FD_SHRED_MAX_SZ );
}

/* Version table record I/O, pos in [0,fd_shredb_tbl_rec_cnt).  Callers
   hold tbl_lock, exclusively to write. */

static void
disk_tbl_read( fd_store_t const *    store,
               int                   disk_fd,
               ulong                 pos,
               fd_shredb_tbl_rec_t * rec ) {
  off_t off = (off_t)(fd_store_tbl_off( store ) + pos*sizeof(fd_shredb_tbl_rec_t));
  if( FD_UNLIKELY( store_pread_all( disk_fd, rec, sizeof(fd_shredb_tbl_rec_t), off ) ) )
    FD_LOG_ERR(( "error reading disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
}

static void
disk_tbl_write( fd_store_t const *          store,
                int                         disk_fd,
                ulong                       pos,
                fd_shredb_tbl_rec_t const * rec ) {
  off_t off = (off_t)(fd_store_tbl_off( store ) + pos*sizeof(fd_shredb_tbl_rec_t));
  if( FD_UNLIKELY( store_pwrite_all( disk_fd, rec, sizeof(fd_shredb_tbl_rec_t), off ) ) )
    FD_LOG_ERR(( "error writing to disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
}

/* disk_tbl_find reads the recorded version (key,merkle_root) into
   rd_entry.  Returns its byte count, MISS, or BUSY. */

static int
disk_tbl_find( fd_store_t const *  store,
               int                 disk_fd,
               ulong               fp,
               ulong               key,
               uchar const *       merkle_root,
               fd_shredb_entry_t * rd_entry ) {
  fd_rwlock_t * rwlock = (fd_rwlock_t *)fd_type_pun_const( &store->disk_lock );
  ulong mask = fd_shredb_tbl_rec_cnt( store->disk_max_shreds )-1UL;
  for( ulong pos=fp&mask, i=0UL; i<=mask; pos=(pos+1UL)&mask, i++ ) {
    fd_shredb_tbl_rec_t rec[1];
    disk_tbl_read( store, disk_fd, pos, rec );
    if( rec->gen!=store->disk_tbl_gen ) return FD_STORE_DISK_QUERY_MISS;
    if( rec->fp!=fp || rec->ring_idx>=store->disk_max_shreds ) continue;
    disk_view_t view;
    fd_rwlock_read( rwlock );
    int result = disk_view_locked( store, rec->ring_idx, &view );
    fd_rwlock_unread( rwlock );
    if( FD_UNLIKELY( result ) ) continue;
    result = disk_read_view( store, disk_fd, view, rd_entry, sizeof(fd_shredb_entry_t) );
    if( FD_UNLIKELY( result ) ) return result;
    if( rd_entry->key!=key || memcmp( rd_entry->root, merkle_root, FD_SHRED_MERKLE_NODE_SZ ) ) continue;
    return (int)fd_ulong_min( rd_entry->shred_sz, FD_SHRED_MAX_SZ );
  }
  return FD_STORE_DISK_QUERY_MISS;
}

static void
disk_tbl_insert( fd_store_t * store,
                 int          disk_fd,
                 ulong        fp,
                 ulong        ring_idx ) {
  ulong mask = fd_shredb_tbl_rec_cnt( store->disk_max_shreds )-1UL;
  fd_shredb_tbl_rec_t rec[1];
  ulong pos = fp&mask;
  for( disk_tbl_read( store, disk_fd, pos, rec ); rec->gen==store->disk_tbl_gen; disk_tbl_read( store, disk_fd, pos, rec ) ) pos = (pos+1UL)&mask;
  *rec = (fd_shredb_tbl_rec_t){ .fp = fp, .ring_idx = (uint)ring_idx, .gen = store->disk_tbl_gen };
  disk_tbl_write( store, disk_fd, pos, rec );
}

/* Backward-shift deletion of the record (fp,ring_idx). */

static void
disk_tbl_remove( fd_store_t * store,
                 int          disk_fd,
                 ulong        fp,
                 ulong        ring_idx ) {
  ulong mask = fd_shredb_tbl_rec_cnt( store->disk_max_shreds )-1UL;
  fd_shredb_tbl_rec_t rec[1];
  ulong hole = fp&mask;
  for(;; hole=(hole+1UL)&mask ) {
    disk_tbl_read( store, disk_fd, hole, rec );
    FD_TEST( rec->gen==store->disk_tbl_gen );
    if( rec->fp==fp && rec->ring_idx==ring_idx ) break;
  }
  for( ulong pos=(hole+1UL)&mask;; pos=(pos+1UL)&mask ) {
    disk_tbl_read( store, disk_fd, pos, rec );
    if( rec->gen!=store->disk_tbl_gen ) break;
    ulong home = rec->fp&mask;
    /* rec stays if home is cyclically in (hole,pos] */
    if( ((pos-home)&mask) < ((pos-hole)&mask) ) continue;
    disk_tbl_write( store, disk_fd, hole, rec );
    hole = pos;
  }
  *rec = (fd_shredb_tbl_rec_t){ 0 };
  disk_tbl_write( store, disk_fd, hole, rec );
}

/* disk_insert_versioned is the insert path that uses the version table.
   Requires tbl_lock exclusively.  The first version's root is read off
   disk; a fast-path insert that relinks the key meanwhile is caught at
   reservation and retried.  A WRITING first version belongs to a fast
   path insert, which finishes without tbl_lock, so it is waited for. */

static int
disk_insert_versioned( fd_store_t *       store,
                       int                disk_fd,
                       fd_shred_t const * shred,
                       ulong              key,
                       fd_hash_t const *  merkle_root ) {
  ulong slot = shred->slot;
  ulong fp   = fd_shredb_root_fp( store->disk_root_seed, slot, merkle_root->uc, shred->idx );
  uint  tcnt = disk_tbl_cnt_laddr( store )[ slot % store->disk_max_slots ]; /* only changes under tbl_lock */
  for( ulong retry=0UL; retry<FD_STORE_DISK_READ_RETRY_CNT; retry++ ) {
    disk_view_t holder = { .ring_idx = UINT_MAX };
    int         result;
    uint        holder_idx;
    do {
      fd_rwlock_read( &store->disk_lock );
      holder_idx = disk_slot_lookup_locked( store, key );
      result     = holder_idx==UINT_MAX ? 0 : disk_view_locked( store, holder_idx, &holder );
      fd_rwlock_unread( &store->disk_lock );
      if( FD_UNLIKELY( result ) ) FD_SPIN_PAUSE();
    } while( result==FD_STORE_DISK_QUERY_BUSY );
    FD_TEST( !result ); /* a linked cell is WRITING or READY */

    fd_shredb_entry_t rd_entry[1];
    if( holder_idx!=UINT_MAX ) {
      if( FD_UNLIKELY( disk_read_view( store, disk_fd, holder, rd_entry, FD_SHREDB_ENTRY_HDR_SZ ) || rd_entry->key!=key ) ) continue;
      if( !memcmp( rd_entry->root, merkle_root->uc, FD_SHRED_MERKLE_NODE_SZ ) ) return FD_STORE_DISK_INSERT_DUP;
    }
    if( tcnt ) {
      result = disk_tbl_find( store, disk_fd, fp, key, merkle_root->uc, rd_entry );
      if( result>0 ) return FD_STORE_DISK_INSERT_DUP;
      if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_BUSY ) ) continue;
    }

    /* A later version while the first is stored and not being replaced */
    disk_view_t view;
    int old_recorded;
    fd_shredb_ring_entry_t * cell;
    ulong old_key;
    fd_rwlock_write( &store->disk_lock );
    if( FD_UNLIKELY( disk_slot_lookup_locked( store, key )!=holder_idx ||
                     ( holder_idx!=UINT_MAX && disk_query_finish_read_locked( store, holder ) ) ) ) {
      fd_rwlock_unwrite( &store->disk_lock );
      continue;
    }
    uint next_idx = (uint)(atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed ) % store->disk_max_shreds);
    int  kind     = holder_idx==UINT_MAX || holder_idx==next_idx ? FD_SHREDB_KIND_FIRST : FD_SHREDB_KIND_NONFIRST;
    cell    = disk_ring_pool_laddr( store ) + next_idx;
    old_key = cell->key;
    result  = disk_insert_prepare_write_locked( store, key, kind, &view, &old_recorded );
    fd_rwlock_unwrite( &store->disk_lock );
    if( FD_UNLIKELY( result!=FD_STORE_DISK_INSERT_SUCCESS ) ) return result;

    /* The overwritten cell's record goes first, its shred is still on disk */
    if( FD_UNLIKELY( old_recorded ) ) {
      if( FD_UNLIKELY( store_pread_all( disk_fd, rd_entry, FD_SHREDB_ENTRY_HDR_SZ, disk_cell_off( store, view.ring_idx ) ) ) )
        FD_LOG_ERR(( "error reading disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
      FD_TEST( rd_entry->key==old_key );
      ulong old_slot = fd_shredb_key_slot( old_key );
      disk_tbl_remove( store, disk_fd, fd_shredb_root_fp( store->disk_root_seed, old_slot, rd_entry->root, fd_shredb_key_shred_idx( old_key ) ), view.ring_idx );
      fd_rwlock_write( &store->disk_lock );
      disk_tbl_cnt_laddr( store )[ old_slot % store->disk_max_slots ]--;
      fd_rwlock_unwrite( &store->disk_lock );
    }
    if( kind==FD_SHREDB_KIND_NONFIRST ) disk_tbl_insert( store, disk_fd, fp, view.ring_idx );
    return disk_insert_write( store, disk_fd, shred, merkle_root, view );
  }
  return FD_STORE_DISK_INSERT_ERR;
}

int
fd_store_disk_insert( fd_store_t *       store,
                      int                disk_fd,
                      fd_shred_t const * shred,
                      fd_hash_t const *  merkle_root ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !shred || !merkle_root || !fd_store_has_disk( store ) ) )
    return FD_STORE_DISK_INSERT_ERR;

  ulong slot      = shred->slot;
  uint  shred_idx = shred->idx;
  if( FD_UNLIKELY( slot>=FD_SHREDB_KEY_SLOT_MAX || shred_idx>=store->max_shreds_per_block ) ) return FD_STORE_DISK_INSERT_ERR;
  ulong key = fd_shredb_key_pack( slot, shred_idx );

  /* No version of key stored and no record in the next cell: a plain
     slot-map insert, the only path without equivocation or duplicates. */
  disk_view_t view;
  int old_recorded = 0;
  int result       = FD_STORE_DISK_INSERT_DUP;
  fd_rwlock_write( &store->disk_lock );
  ulong next_idx = atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed ) % store->disk_max_shreds;
  int   fast     = disk_slot_lookup_locked( store, key )==UINT_MAX &&
                   !disk_tbl_cnt_laddr( store )[ slot % store->disk_max_slots ] &&
                   !disk_cell_recorded_locked( store, (uint)next_idx );
  if( FD_LIKELY( fast ) ) result = disk_insert_prepare_write_locked( store, key, FD_SHREDB_KIND_FIRST, &view, &old_recorded );
  fd_rwlock_unwrite( &store->disk_lock );
  if( FD_LIKELY( fast ) ) {
    if( FD_UNLIKELY( result!=FD_STORE_DISK_INSERT_SUCCESS ) ) return result;
    FD_TEST( !old_recorded );
    return disk_insert_write( store, disk_fd, shred, merkle_root, view );
  }

  fd_rwlock_write( &store->tbl_lock );
  result = disk_insert_versioned( store, disk_fd, shred, key, merkle_root );
  fd_rwlock_unwrite( &store->tbl_lock );
  return result;
}

int
fd_store_disk_query( fd_store_t const * store,
                     int                disk_fd,
                     ulong              slot,
                     uint               shred_idx,
                     uchar              out[ FD_SHRED_MAX_SZ ] ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !out || !fd_store_has_disk( store ) ||
                   slot>=FD_SHREDB_KEY_SLOT_MAX || shred_idx>=store->max_shreds_per_block ) ) return FD_STORE_DISK_QUERY_MISS;
  ulong key = fd_shredb_key_pack( slot, shred_idx );
  for( ulong retry=0UL; retry<FD_STORE_DISK_READ_RETRY_CNT; retry++ ) {
    fd_shredb_entry_t entry[1];
    int result = disk_read_once( store, disk_fd, key, entry );
    if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_BUSY ) ) { FD_SPIN_PAUSE(); continue; }
    if( FD_UNLIKELY( result<0 ) ) return result;
    fd_memcpy( out, entry->shred, (ulong)result );
    return result;
  }
  return FD_STORE_DISK_QUERY_BUSY;
}

int
fd_store_disk_query_root( fd_store_t const * store,
                          int                disk_fd,
                          ulong              slot,
                          uchar const *      merkle_root,
                          uint               shred_idx,
                          uchar              out[ FD_SHRED_MAX_SZ ] ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !merkle_root || !out || !fd_store_has_disk( store ) ||
                   slot>=FD_SHREDB_KEY_SLOT_MAX || shred_idx>=store->max_shreds_per_block ) ) return FD_STORE_DISK_QUERY_MISS;
  fd_rwlock_t * disk_lock = (fd_rwlock_t *)fd_type_pun_const( &store->disk_lock );
  fd_rwlock_t * tbl_lock  = (fd_rwlock_t *)fd_type_pun_const( &store->tbl_lock  );
  ulong key = fd_shredb_key_pack( slot, shred_idx );
  for( ulong retry=0UL; retry<FD_STORE_DISK_READ_RETRY_CNT; retry++ ) {
    fd_shredb_entry_t entry[1];
    int result = disk_read_once( store, disk_fd, key, entry );
    if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_BUSY ) ) { FD_SPIN_PAUSE(); continue; }
    if( result<0 || memcmp( entry->root, merkle_root, FD_SHRED_MERKLE_NODE_SZ ) ) {
      fd_rwlock_read( disk_lock );
      uint tcnt = disk_tbl_cnt_laddr( store )[ slot % store->disk_max_slots ];
      fd_rwlock_unread( disk_lock );
      if( FD_LIKELY( !tcnt ) ) return FD_STORE_DISK_QUERY_MISS;
      fd_rwlock_read( tbl_lock );
      result = disk_tbl_find( store, disk_fd, fd_shredb_root_fp( store->disk_root_seed, slot, merkle_root, shred_idx ), key, merkle_root, entry );
      fd_rwlock_unread( tbl_lock );
      if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_BUSY ) ) { FD_SPIN_PAUSE(); continue; }
      if( FD_UNLIKELY( result<0 ) ) return result;
    }
    fd_memcpy( out, entry->shred, (ulong)result );
    return result;
  }
  return FD_STORE_DISK_QUERY_BUSY;
}

int
fd_store_disk_probe( fd_store_t const * store,
                     ulong              slot,
                     uint               shred_idx ) {
  if( FD_UNLIKELY( !store || !fd_store_has_disk( store ) || slot>=FD_SHREDB_KEY_SLOT_MAX ) ) return 0;
  if( FD_UNLIKELY( shred_idx==UINT_MAX ) ) {
    return !!(atomic_load_explicit( disk_slot_hint_laddr( store ) + (slot % store->disk_max_slots), memory_order_acquire ) & FD_SHREDB_HINT_VALID);
  }
  if( FD_UNLIKELY( shred_idx>=store->max_shreds_per_block ) ) return 0;

  fd_rwlock_t * rwlock = (fd_rwlock_t *)fd_type_pun_const( &store->disk_lock );
  fd_rwlock_read( rwlock );
  int present = disk_slot_lookup_locked( store, fd_shredb_key_pack( slot, shred_idx ) )!=UINT_MAX;
  fd_rwlock_unread( rwlock );
  return present;
}

int
fd_store_disk_query_highest( fd_store_t const * store,
                             int                disk_fd,
                             ulong              slot,
                             uint               min_shred_idx,
                             uchar              out[ FD_SHRED_MAX_SZ ] ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !out || !fd_store_has_disk( store ) || slot>=FD_SHREDB_KEY_SLOT_MAX ) )
    return FD_STORE_DISK_QUERY_MISS;
  for( ulong retry=0UL; retry<FD_STORE_DISK_READ_RETRY_CNT; retry++ ) {
    atomic_ulong const * hint_ptr = disk_slot_hint_laddr( store ) + (slot % store->disk_max_slots);
    ulong hint = atomic_load_explicit( hint_ptr, memory_order_relaxed );
    if( FD_UNLIKELY( !(hint & FD_SHREDB_HINT_VALID) ) ) return FD_STORE_DISK_QUERY_MISS;
    if( FD_UNLIKELY( fd_shredb_key_slot( hint )!=slot ) ) return FD_STORE_DISK_QUERY_BUSY;
    uint idx = fd_shredb_key_shred_idx( hint & ~FD_SHREDB_HINT_VALID );
    if( FD_UNLIKELY( idx>=store->max_shreds_per_block ) ) return FD_STORE_DISK_QUERY_MISS;

    fd_shredb_entry_t entry[1];
    int result = disk_read_once( store, disk_fd, fd_shredb_key_pack( slot, idx ), entry );
    ulong hint_after = atomic_load_explicit( hint_ptr, memory_order_acquire );
    if( FD_UNLIKELY( hint_after!=hint || result==FD_STORE_DISK_QUERY_BUSY ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
    if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_MISS ) ) return FD_STORE_DISK_QUERY_SCAN_LIMIT;
    if( FD_UNLIKELY( result<0 ) ) return result;

    fd_shred_t const * shred = (fd_shred_t const *)fd_type_pun_const( entry->shred );
    if( idx<min_shred_idx && !(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) ) return FD_STORE_DISK_QUERY_MISS;
    fd_memcpy( out, entry->shred, (ulong)result );
    return result;
  }
  return FD_STORE_DISK_QUERY_BUSY;
}

int
fd_store_disk_stats_query( fd_store_t const *      store,
                           fd_store_disk_stats_t * stats ) {
  if( FD_UNLIKELY( !store || !stats || !fd_store_has_disk( store ) ) ) return FD_STORE_DISK_QUERY_MISS;
  stats->shred_cnt       = atomic_load_explicit( &store->disk_cnt, memory_order_relaxed );
  stats->current_bytes   = stats->shred_cnt*sizeof(fd_shredb_entry_t)
                         + atomic_load_explicit( &store->spill_live_cnt, memory_order_relaxed )*store->payload_slot_sz;
  stats->allocated_bytes = fd_ulong_min( atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed ),
                                        store->disk_max_shreds )*sizeof(fd_shredb_entry_t)
                         + FD_VOLATILE_CONST( store->spill_slot_cnt )*store->payload_slot_sz;
  stats->insert_cnt      = atomic_load_explicit( &store->disk_insert_cnt, memory_order_relaxed );
  stats->write_bytes     = atomic_load_explicit( &store->disk_write_bytes, memory_order_relaxed );
  return 0;
}
