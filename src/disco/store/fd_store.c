#define _GNU_SOURCE
#include "fd_store.h"

#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>


/* The FEC map key is the first FD_SHRED_MERKLE_NODE_SZ bytes of the
   merkle root: the FEC identity repair (fd_mr20_t) and the disk shred
   index (fd_shredb_root_key_t) use. */

struct fd_store_key {
  uchar uc[ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_store_key fd_store_key_t;

FD_STATIC_ASSERT( sizeof(fd_store_key_t)==20UL, fd_store_key_sz );

/* FEC states (data.state).  See fec_map / slot_ring membership:

     FREE             not in fec_map, owns nothing
     ACQUIRED         in fec_map, waiting for a cache slot
     RESERVED         owns a cache slot, caller filling, not in slot_ring
     CACHED           cache slot, in LRU and slot_ring
     SPILLING         cache slot, disk slot held by the spiller
     SPILLING_DEAD    unlinked by publish, the spiller frees it
     PINNED           cache slot pinned by replay
     PINNED_SPILLING  pinned during a spill, cache slot stays valid
     PINNED_SPILLED   disk slot pinned by replay
     SPILLED          disk slot, in slot_ring

   ACQUIRED, RESERVED and SPILLING_DEAD are query misses but still
   duplicates for insert. */

#define FD_STORE_STATE_FREE            (0U)
#define FD_STORE_STATE_ACQUIRED        (1U)
#define FD_STORE_STATE_RESERVED        (2U)
#define FD_STORE_STATE_CACHED          (3U)
#define FD_STORE_STATE_SPILLING        (4U)
#define FD_STORE_STATE_SPILLING_DEAD   (5U)
#define FD_STORE_STATE_PINNED          (6U)
#define FD_STORE_STATE_PINNED_SPILLING (7U)
#define FD_STORE_STATE_PINNED_SPILLED  (8U)
#define FD_STORE_STATE_SPILLED         (9U)

#define FD_STORE_DATA_IDX_MASK ((uint)(FD_STORE_IDX_MAX-1UL))

FD_FN_CONST static inline uint data_pack ( uint idx, uint state ) { return idx | (state<<28); }
FD_FN_CONST static inline uint data_idx  ( uint data )            { return data & FD_STORE_DATA_IDX_MASK; }
FD_FN_CONST static inline uint data_state( uint data )            { return data>>28; }

struct fd_store_fec_meta {
  fd_store_key_t key;       /* fec_map key */
  uint           slot;
  uint           next;      /* fec_map chain / pool free list */
  uint           slot_next; /* slot_ring bucket chain */
  uint           data;      /* idx:28 (cache or disk slot) | state:4 */
  uint           data_sz;   /* total payload bytes incl. overflow shreds.  Own
                               word: query_read reads it lock-free while the
                               spiller writes data under the lock. */
};
typedef struct fd_store_fec_meta fd_store_fec_meta_t;

FD_STATIC_ASSERT( sizeof(fd_store_fec_meta_t)==40UL, fd_store_fec_meta_sz );
FD_STATIC_ASSERT( sizeof(fd_store_view_t)==8UL,      fd_store_view_sz     );

#define POOL_NAME  fd_store_meta_pool
#define POOL_T     fd_store_fec_meta_t
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

/* If StoreFecMapProbes shows that it is needed, the next step is a
   custom map that prefetches the chain head before taking the lock. */

#define MAP_NAME               fd_store_fec_map
#define MAP_ELE_T              fd_store_fec_meta_t
#define MAP_KEY_T              fd_store_key_t
#define MAP_KEY                key
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0)->uc, (k1)->uc, FD_SHRED_MERKLE_NODE_SZ ))
#define MAP_KEY_HASH(key,seed) fd_hash( (seed), (key)->uc, FD_SHRED_MERKLE_NODE_SZ ) /* as fd_shredb_root_map */
#include "../../util/tmpl/fd_map_chain.c"

/* One per cache slot.  The payload record is at cache_mem+idx*fec_slot_sz,
   kept separate so it stays page aligned. */

struct fd_store_fec_cache {
  uint prev;     /* LRU */
  uint next;     /* LRU / pool free list */
  uint meta_idx; /* owner */
};
typedef struct fd_store_fec_cache fd_store_fec_cache_t;

#define POOL_NAME  fd_store_cache_pool
#define POOL_T     fd_store_fec_cache_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_store_cache_lru
#define DLIST_ELE_T fd_store_fec_cache_t
#define DLIST_IDX_T uint
#include "../../util/tmpl/fd_dlist.c"

#define FD_STORE_NULL (UINT_MAX)

/* FD_STORE_SPILL_TEST_HOOK runs in cache_spill with the lock dropped,
   before the write.  Unit tests define it to interleave other store
   operations with an in-flight spill deterministically. */

#ifndef FD_STORE_SPILL_TEST_HOOK
#define FD_STORE_SPILL_TEST_HOOK( store ) (void)(store)
#endif


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

/* store_preadv_all reads every iovec in order starting at off,
   retrying EINTR and completing short reads.  Clobbers iov.  Returns 0
   on success and -1 on error or unexpected EOF (errno EIO). */

static int
store_preadv_all( int            fd,
                  struct iovec * iov,
                  int            iov_cnt,
                  off_t          off ) {
  for(;;) {
    while( iov_cnt && !iov->iov_len ) { iov++; iov_cnt--; }
    if( !iov_cnt ) return 0;
    long res = preadv2( fd, iov, iov_cnt, off, 0 );
    if( FD_UNLIKELY( res<0L ) ) {
      if( errno==EINTR ) continue;
      return -1;
    }
    if( FD_UNLIKELY( !res ) ) { errno = EIO; return -1; }
    off += (off_t)res;
    ulong rem = (ulong)res;
    while( iov_cnt && rem>=iov->iov_len ) { rem -= iov->iov_len; iov++; iov_cnt--; }
    if( rem ) {
      iov->iov_base = (uchar *)iov->iov_base + rem;
      iov->iov_len -= rem;
    }
  }
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

static inline fd_shredb_root_map_t *
disk_root_map_join( fd_store_t const * store ) {
  void * shmap = fd_wksp_laddr_fast( fd_store_wksp( store ), store->root_map_gaddr );
  return fd_shredb_root_map_join( shmap );
}

static inline atomic_ulong *
disk_slot_hint_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->slot_hint_gaddr );
}

static inline fd_store_fec_meta_t *
meta_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->meta_gaddr );
}

static inline uchar *
cache_data_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->cache_data_gaddr );
}

static inline fd_store_fec_t *
cache_fec( fd_store_t const * store,
           uchar *            cache_mem,
           ulong              cache_idx ) {
  return (fd_store_fec_t *)( cache_mem + cache_idx*store->fec_slot_sz );
}

/* store_ljoin gathers local addresses of every FEC container. */

struct store_ljoin {
  fd_store_fec_meta_t *  meta;
  fd_store_fec_map_t *   map;
  fd_store_fec_cache_t * cache;
  fd_store_cache_lru_t * lru;
  uint *                 slot_ring;
  uint *                 disk_free;
  uchar *                cache_mem;
};
typedef struct store_ljoin store_ljoin_t;

static inline store_ljoin_t
store_ljoin( fd_store_t const * store ) {
  fd_wksp_t * wksp = fd_store_wksp( store );
  return (store_ljoin_t){
    .meta      = fd_wksp_laddr_fast( wksp, store->meta_gaddr       ),
    .map       = fd_wksp_laddr_fast( wksp, store->fec_map_gaddr    ),
    .cache     = fd_wksp_laddr_fast( wksp, store->cache_gaddr      ),
    .lru       = fd_wksp_laddr_fast( wksp, store->cache_lru_gaddr  ),
    .slot_ring = fd_wksp_laddr_fast( wksp, store->slot_ring_gaddr  ),
    .disk_free = fd_wksp_laddr_fast( wksp, store->disk_free_gaddr  ),
    .cache_mem = fd_wksp_laddr_fast( wksp, store->cache_data_gaddr )
  };
}

/* stat_add and stat_sub update a gauge or counter that has one writer
   at a time: the lock holder, or for spill_read_*, the pinning thread.
   The atomic is only so lock-free metric readers see whole values, so a
   relaxed load and store suffice (no locked RMW).  Return the new
   value. */

static inline ulong
stat_add( atomic_ulong * stat,
          ulong          delta ) {
  ulong val = atomic_load_explicit( stat, memory_order_relaxed ) + delta;
  atomic_store_explicit( stat, val, memory_order_relaxed );
  return val;
}

static inline ulong
stat_sub( atomic_ulong * stat,
          ulong          delta ) {
  ulong val = atomic_load_explicit( stat, memory_order_relaxed ) - delta;
  atomic_store_explicit( stat, val, memory_order_relaxed );
  return val;
}


static int
store_layout_append( ulong * l,
                     ulong   align,
                     ulong   cnt,
                     ulong   ele_sz ) {
  ulong bytes;
  ulong rounded;
  ulong next;
  if( FD_UNLIKELY( !align || !fd_ulong_is_pow2( align ) ) ) return -1;
  if( FD_UNLIKELY( __builtin_umull_overflow( cnt, ele_sz, &bytes ) ) ) return -1;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( *l, align-1UL, &rounded ) ) ) return -1;
  rounded &= ~(align-1UL);
  if( FD_UNLIKELY( __builtin_uaddl_overflow( rounded, bytes, &next ) ) ) return -1;
  *l = next;
  return 0;
}

/* store_sizing holds every size derived from the footprint arguments. */

struct store_sizing {
  ulong fec_slot_sz;
  ulong cache_max;
  ulong disk_max;
  ulong chain_cnt;
  ulong slot_ring_len;
  ulong max_shreds;
  ulong max_slots;
  ulong disk_chain_cnt;
};
typedef struct store_sizing store_sizing_t;

static int
store_sizing( store_sizing_t * sz,
              ulong            fec_max,
              ulong            fec_data_max,
              ulong            shred_storage_gib,
              ulong            shred_cache_bytes,
              ulong            shred_tile_cnt,
              ulong            max_live_slots ) {
  if( FD_UNLIKELY( !fec_max || fec_max>FD_STORE_IDX_MAX ) ) return -1;
  if( FD_UNLIKELY( !fec_data_max || fec_data_max>FD_STORE_MAX_FEC_DATA_SZ ) ) return -1;
  if( FD_UNLIKELY( shred_storage_gib>FD_SHREDB_MAX_SIZE_GIB ) ) return -1;
  if( FD_UNLIKELY( !shred_tile_cnt || shred_tile_cnt>64UL ) ) return -1;
  if( FD_UNLIKELY( !max_live_slots || max_live_slots>(1UL<<32) ) ) return -1;

  sz->fec_slot_sz   = fd_store_fec_slot_sz( fec_data_max );
  sz->cache_max     = shred_cache_bytes
                    ? fd_ulong_min( fec_max, fd_ulong_max( 1UL, shred_cache_bytes / sz->fec_slot_sz ) )
                    : fec_max;
  sz->disk_max      = fec_max;
  sz->chain_cnt     = fd_store_fec_map_chain_cnt_est( fec_max );
  sz->slot_ring_len = fd_ulong_pow2_up( max_live_slots );
  sz->max_shreds     = 0UL;
  sz->max_slots      = 0UL;
  sz->disk_chain_cnt = 0UL;
  if( shred_storage_gib ) {
    sz->max_shreds     = fd_shredb_max_shreds( shred_storage_gib );
    sz->max_slots      = fd_shredb_max_slots( shred_storage_gib );
    sz->disk_chain_cnt = fd_shredb_disk_chain_cnt( sz->max_shreds );
    if( FD_UNLIKELY( !sz->max_shreds || !sz->max_slots ) ) return -1;
  }
  return 0;
}

ulong
fd_store_footprint( ulong fec_max,
                    ulong fec_data_max,
                    ulong shred_storage_gib,
                    ulong shred_cache_bytes,
                    ulong fec_set_cnt,
                    ulong shred_tile_cnt,
                    ulong max_live_slots ) {
  store_sizing_t sz[1];
  if( FD_UNLIKELY( store_sizing( sz, fec_max, fec_data_max, shred_storage_gib, shred_cache_bytes, shred_tile_cnt, max_live_slots ) ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  if( FD_UNLIKELY( store_layout_append( &l, fd_store_align(),               1UL,               sizeof(fd_store_t) ) ||
                   store_layout_append( &l, fd_store_fec_map_align(),       1UL,               fd_store_fec_map_footprint( sz->chain_cnt ) ) ||
                   store_layout_append( &l, fd_store_meta_pool_align(),     1UL,               fd_store_meta_pool_footprint( fec_max ) ) ||
                   store_layout_append( &l, fd_store_cache_pool_align(),    1UL,               fd_store_cache_pool_footprint( sz->cache_max ) ) ||
                   store_layout_append( &l, fd_store_cache_lru_align(),     1UL,               fd_store_cache_lru_footprint() ) ||
                   store_layout_append( &l, alignof(uint),                  sz->slot_ring_len, sizeof(uint) ) ||
                   store_layout_append( &l, alignof(uint),                  sz->disk_max,      sizeof(uint) ) ||
                   store_layout_append( &l, FD_STORE_PAYLOAD_PAGE_SZ,       sz->cache_max,     sz->fec_slot_sz ) ) ) return 0UL;
  if( FD_UNLIKELY( !fd_store_meta_pool_footprint( fec_max ) || !fd_store_cache_pool_footprint( sz->cache_max ) ) ) return 0UL;
  if( FD_UNLIKELY( fec_set_cnt && store_layout_append( &l, alignof(fd_fec_set_t), fec_set_cnt, sizeof(fd_fec_set_t) ) ) ) return 0UL;
  if( shred_storage_gib ) {
    if( FD_UNLIKELY( store_layout_append( &l, fd_shredb_slot_map_align(),      1UL,            fd_shredb_slot_map_footprint( sz->disk_chain_cnt ) ) ||
                     store_layout_append( &l, alignof(fd_shredb_ring_entry_t), sz->max_shreds, sizeof(fd_shredb_ring_entry_t) ) ||
                     store_layout_append( &l, alignof(atomic_ulong),           sz->max_slots,  sizeof(atomic_ulong) ) ||
                     store_layout_append( &l, fd_shredb_root_map_align(),      1UL,            fd_shredb_root_map_footprint( sz->disk_chain_cnt ) ) ) ) return 0UL;
  }
  if( FD_UNLIKELY( store_layout_append( &l, fd_store_align(), 0UL, 1UL ) ) ) return 0UL;
  return l;
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
              ulong        shred_tile_cnt,
              ulong        max_live_slots ) {

  if( FD_UNLIKELY( !shmem ) ) { FD_LOG_WARNING(( "NULL shmem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned shmem" )); return NULL; }
  if( FD_UNLIKELY( !fec_max ) ) { FD_LOG_WARNING(( "fec_max must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( fec_max>FD_STORE_IDX_MAX ) ) { FD_LOG_WARNING(( "fec_max must be at most 2^28" )); return NULL; }
  if( FD_UNLIKELY( !fec_data_max ) ) { FD_LOG_WARNING(( "fec_data_max must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( fec_data_max>FD_STORE_MAX_FEC_DATA_SZ ) ) { FD_LOG_WARNING(( "fec_data_max exceeds legacy FEC payload limit" )); return NULL; }
  if( FD_UNLIKELY( !max_shreds_per_block || max_shreds_per_block>FD_SHREDB_HINT_VALID ) ) { FD_LOG_WARNING(( "bad max_shreds_per_block (%lu)", max_shreds_per_block )); return NULL; }
  if( FD_UNLIKELY( !shred_tile_cnt || shred_tile_cnt>64UL ) ) { FD_LOG_WARNING(( "shred_tile_cnt must be in [1,64]" )); return NULL; }
  if( FD_UNLIKELY( !max_live_slots ) ) { FD_LOG_WARNING(( "max_live_slots must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( shred_storage_gib>FD_SHREDB_MAX_SIZE_GIB ) ) {
    FD_LOG_ERR(( "shred database size limit is %lu GiB, but the maximum supported size is %lu GiB",
                 shred_storage_gib, FD_SHREDB_MAX_SIZE_GIB ));
  }

  ulong footprint = fd_store_footprint( fec_max, fec_data_max, shred_storage_gib, shred_cache_bytes, fec_set_cnt, shred_tile_cnt, max_live_slots );
  if( FD_UNLIKELY( !footprint ) ) { FD_LOG_WARNING(( "invalid or overflowing store footprint" )); return NULL; }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "shmem must be part of a workspace" )); return NULL; }

  store_sizing_t sz[1];
  FD_TEST( !store_sizing( sz, fec_max, fec_data_max, shred_storage_gib, shred_cache_bytes, shred_tile_cnt, max_live_slots ) );
  FD_TEST( sz->cache_max<=fec_max && sz->cache_max<=FD_STORE_IDX_MAX && sz->disk_max<=FD_STORE_IDX_MAX );
  FD_TEST( FD_STORE_FEC_HDR_SZ+fec_data_max<=sz->fec_slot_sz );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_store_t *   store      = FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(),            sizeof(fd_store_t)                                  );
  void *         map_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_store_fec_map_align(),    fd_store_fec_map_footprint( sz->chain_cnt )          );
  void *         meta_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_store_meta_pool_align(),  fd_store_meta_pool_footprint( fec_max )              );
  void *         cache_pmem = FD_SCRATCH_ALLOC_APPEND( l, fd_store_cache_pool_align(), fd_store_cache_pool_footprint( sz->cache_max )      );
  void *         lru_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_store_cache_lru_align(),  fd_store_cache_lru_footprint()                       );
  uint *         slot_ring  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),               sizeof(uint)*sz->slot_ring_len                       );
  uint *         disk_free  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),               sizeof(uint)*sz->disk_max                            );
  uchar *        cache_mem  = FD_SCRATCH_ALLOC_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ,    sz->fec_slot_sz*sz->cache_max                            );
  fd_fec_set_t * fec_sets   = fec_set_cnt
                            ? FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fec_set_t), sizeof(fd_fec_set_t)*fec_set_cnt )
                            : NULL;

  void *                   shred_map_mem = NULL;
  fd_shredb_ring_entry_t * ring_pool_mem = NULL;
  void *                   root_map_mem  = NULL;
  atomic_ulong *           slot_hint_mem = NULL;

  if( shred_storage_gib ) {
    shred_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_slot_map_align(),      fd_shredb_slot_map_footprint( sz->disk_chain_cnt ) );
    ring_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shredb_ring_entry_t), sz->max_shreds*sizeof(fd_shredb_ring_entry_t) );
    slot_hint_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(atomic_ulong),           sz->max_slots*sizeof(atomic_ulong) );
    root_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_root_map_align(),      fd_shredb_root_map_footprint( sz->disk_chain_cnt ) );
  }

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_store_align() )==(ulong)shmem + footprint );

  ulong payload_sz;
  ulong wire_sz;
  ulong file_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( sz->fec_slot_sz, sz->disk_max, &payload_sz ) ||
                   __builtin_umull_overflow( sz->max_shreds, sizeof(fd_shredb_entry_t), &wire_sz ) ||
                   __builtin_uaddl_overflow( payload_sz, wire_sz, &file_sz ) ||
                   file_sz>(ulong)LONG_MAX ) ) {
    FD_LOG_WARNING(( "store backing file size overflows off_t" ));
    return NULL;
  }

  fd_memset( store, 0, sizeof(fd_store_t) );
  store->fec_max              = fec_max;
  store->fec_data_max         = fec_data_max;
  store->store_gaddr          = fd_wksp_gaddr_fast( wksp, store );
  store->shred_tile_cnt       = shred_tile_cnt;
  store->max_live_slots       = max_live_slots;
  store->fec_slot_sz          = sz->fec_slot_sz;
  store->cache_max            = sz->cache_max;
  store->disk_max             = sz->disk_max;
  store->slot_ring_len        = sz->slot_ring_len;
  store->payload_sz           = payload_sz;
  store->wire_off             = payload_sz; /* wire region begins after the payload region (page-aligned) */
  ulong free_cap              = fd_ulong_min( 8192UL, (64UL<<20) / sz->fec_slot_sz );
  ulong burst_floor           = fd_ulong_min( 512UL, sz->cache_max/2UL );
  ulong free_target           = fd_ulong_max( sz->cache_max/10UL, burst_floor );
  store->cache_free_target    = fd_ulong_max( 1UL, fd_ulong_min( free_cap, free_target ) );
  store->cache_free_low_water = fd_ulong_max( 1UL, (store->cache_free_target*3UL)/4UL );
  store->fec_set_cnt          = fec_set_cnt;
  store->fec_sets_gaddr       = fec_set_cnt ? fd_wksp_gaddr_fast( wksp, fec_sets ) : 0UL;
  store->max_shreds_per_block = max_shreds_per_block;

  void * shmap = fd_store_fec_map_new( map_mem, sz->chain_cnt, seed );
  FD_TEST( shmap );
  store->fec_map_gaddr = fd_wksp_gaddr_fast( wksp, fd_store_fec_map_join( shmap ) );

  fd_store_fec_meta_t * meta = fd_store_meta_pool_join( fd_store_meta_pool_new( meta_mem, fec_max ) );
  FD_TEST( meta );
  store->meta_gaddr = fd_wksp_gaddr_fast( wksp, meta );

  fd_store_fec_cache_t * cache = fd_store_cache_pool_join( fd_store_cache_pool_new( cache_pmem, sz->cache_max ) );
  FD_TEST( cache );
  store->cache_gaddr = fd_wksp_gaddr_fast( wksp, cache );

  fd_store_cache_lru_t * lru = fd_store_cache_lru_join( fd_store_cache_lru_new( lru_mem ) );
  FD_TEST( lru );
  store->cache_lru_gaddr = fd_wksp_gaddr_fast( wksp, lru );

  for( ulong i=0UL; i<sz->slot_ring_len; i++ ) slot_ring[ i ] = FD_STORE_NULL;
  store->slot_ring_gaddr  = fd_wksp_gaddr_fast( wksp, slot_ring );
  store->disk_free_gaddr  = fd_wksp_gaddr_fast( wksp, disk_free );
  store->cache_data_gaddr = fd_wksp_gaddr_fast( wksp, cache_mem );

  fd_rwlock_new( &store->lock );
  store->min_root      = 0UL;
  store->pin_view      = FD_STORE_VIEW_NULL;
  store->disk_free_cnt = 0U;
  atomic_init( &store->cache_parked,     0UL );
  atomic_init( &store->disk_bump,        0UL );
  atomic_init( &store->cache_free_cnt,   sz->cache_max );
  atomic_init( &store->fec_live_cnt,     0UL );
  atomic_init( &store->fec_live_peak,    0UL );
  atomic_init( &store->disk_live_cnt,    0UL );
  atomic_init( &store->spill_cnt,        0UL );
  atomic_init( &store->spill_bytes,      0UL );
  atomic_init( &store->spill_read_cnt,   0UL );
  atomic_init( &store->spill_read_bytes, 0UL );
  atomic_init( &store->spill_cancel_cnt, 0UL );

  if( shred_storage_gib ) {
    void * slot_map = fd_shredb_slot_map_new( shred_map_mem, sz->disk_chain_cnt, seed );
    FD_TEST( slot_map );
    store->shred_map_gaddr = fd_wksp_gaddr_fast( wksp, slot_map );
    store->ring_pool_gaddr = fd_wksp_gaddr_fast( wksp, ring_pool_mem );
    store->slot_hint_gaddr = fd_wksp_gaddr_fast( wksp, slot_hint_mem );
    store->disk_max_shreds = sz->max_shreds;
    store->disk_max_slots  = sz->max_slots;
    fd_rwlock_new( &store->disk_lock );

    void * root_map = fd_shredb_root_map_new( root_map_mem, sz->disk_chain_cnt, seed );
    FD_TEST( root_map );
    store->root_map_gaddr = fd_wksp_gaddr_fast( wksp, root_map );

    /* Unlink examines the old keys even for a never-used cell.  Initialize
       both keys and the INVALID tag; chain links are set on insertion. */
    fd_memset( ring_pool_mem, 0, sz->max_shreds*sizeof(fd_shredb_ring_entry_t) );
    for( ulong i=0UL; i<sz->max_slots; i++ ) atomic_init( slot_hint_mem+i, 0UL );

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
                      ulong        disk_max_shreds ) {
  if( FD_UNLIKELY( !path ) ) {
    errno = EINVAL;
    return -1;
  }

  ulong wire_sz;
  ulong file_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( disk_max_shreds, sizeof(fd_shredb_entry_t), &wire_sz ) ||
                   __builtin_uaddl_overflow( wire_off, wire_sz, &file_sz ) ||
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




static inline fd_store_key_t
store_key( fd_hash_t const * merkle_root ) {
  fd_store_key_t key;
  memcpy( key.uc, merkle_root->uc, FD_SHRED_MERKLE_NODE_SZ );
  return key;
}

/* map_find returns the meta idx of key or FD_STORE_NULL, counting every
   chain hop into lookup_stats (optional).  Unlike fd_map_chain's query,
   it does not reorder the chain.  Lock held. */

static uint
map_find( store_ljoin_t const *     ljoin,
          fd_store_key_t const *    key,
          fd_store_lookup_stats_t * lookup_stats ) {
  fd_store_fec_map_private_t const * map   = fd_store_fec_map_private_const( ljoin->map );
  uint const *                       chain = fd_store_fec_map_private_chain_const( map );
  ulong probe_cnt = 0UL;
  uint  f         = chain[ fd_store_fec_map_private_chain_idx( key, map->seed, map->chain_cnt ) ];
  while( f!=FD_STORE_NULL ) {
    probe_cnt++;
    if( FD_LIKELY( fd_store_fec_map_key_eq( key, &ljoin->meta[ f ].key ) ) ) break;
    f = ljoin->meta[ f ].next;
  }
  if( lookup_stats ) lookup_stats->probe_cnt = probe_cnt;
  return f;
}

/* cache_unpark wakes the parked inserter of the lowest set partition
   bit.  Lock held: only lock holders modify cache_parked. */

static inline void
cache_unpark( fd_store_t * store ) {
  ulong bits = atomic_load_explicit( &store->cache_parked, memory_order_relaxed );
  if( FD_UNLIKELY( bits ) ) atomic_store_explicit( &store->cache_parked, bits & (bits-1UL), memory_order_relaxed );
}

/* cache_park waits, with the lock dropped, until a waker clears bit
   part.  Called only when the cache pool and LRU are both empty: every
   cache slot is then RESERVED (commit pushes it to the LRU), PINNED
   (release pushes it), or SPILLING (completion frees it), so a waker
   always comes.  Enter and return with the lock held. */

static void
cache_park( fd_store_t *              store,
            ulong                     part,
            fd_store_insert_stats_t * insert_stats ) {
  ulong mask = 1UL<<part;
  ulong bits = atomic_load_explicit( &store->cache_parked, memory_order_relaxed );
  FD_TEST( !(bits & mask) );
  atomic_store_explicit( &store->cache_parked, bits | mask, memory_order_relaxed );
  long start = fd_tickcount();
  fd_rwlock_unwrite( &store->lock );
  while( atomic_load_explicit( &store->cache_parked, memory_order_relaxed ) & mask ) FD_SPIN_PAUSE();
  fd_rwlock_write( &store->lock );
  if( insert_stats ) {
    insert_stats->park_cnt++;
    insert_stats->park_ticks += (ulong)( fd_tickcount() - start );
  }
}

static inline uint
cache_acquire( fd_store_t *          store,
               store_ljoin_t const * ljoin ) {
  if( FD_UNLIKELY( !fd_store_cache_pool_free( ljoin->cache ) ) ) return FD_STORE_NULL;
  uint cache_idx = (uint)fd_store_cache_pool_idx_acquire( ljoin->cache );
  atomic_store_explicit( &store->cache_free_cnt, fd_store_cache_pool_free( ljoin->cache ), memory_order_relaxed );
  return cache_idx;
}

static inline void
cache_release( fd_store_t *          store,
               store_ljoin_t const * ljoin,
               uint                  cache_idx,
               int                   wake ) {
  ljoin->cache[ cache_idx ].meta_idx = FD_STORE_NULL;
  fd_store_cache_pool_idx_release( ljoin->cache, cache_idx );
  atomic_store_explicit( &store->cache_free_cnt, fd_store_cache_pool_free( ljoin->cache ), memory_order_relaxed );
  if( wake ) cache_unpark( store );
}

/* lru_push_head and lru_push_tail wake a parked inserter: it parked
   because the pool and LRU were empty, and the pushed slot is now a
   spill victim it can take. */

static inline void
lru_push_head( fd_store_t * store, store_ljoin_t const * ljoin, uint cache_idx ) {
  fd_store_cache_lru_idx_push_head( ljoin->lru, cache_idx, ljoin->cache );
  cache_unpark( store );
}

static inline void
lru_push_tail( fd_store_t * store, store_ljoin_t const * ljoin, uint cache_idx ) {
  fd_store_cache_lru_idx_push_tail( ljoin->lru, cache_idx, ljoin->cache );
  cache_unpark( store );
}

static inline uint
disk_acquire( fd_store_t *          store,
              store_ljoin_t const * ljoin ) {
  uint disk_idx;
  if( FD_LIKELY( store->disk_free_cnt ) ) {
    disk_idx = ljoin->disk_free[ --store->disk_free_cnt ];
  } else {
    ulong bump = atomic_load_explicit( &store->disk_bump, memory_order_relaxed );
    FD_TEST( bump<store->disk_max ); /* disk_max==fec_max: every disk slot has its own FEC */
    atomic_store_explicit( &store->disk_bump, bump+1UL, memory_order_relaxed );
    disk_idx = (uint)bump;
  }
  stat_add( &store->disk_live_cnt, 1UL );
  return disk_idx;
}

static inline void
disk_release( fd_store_t *          store,
              store_ljoin_t const * ljoin,
              uint                  disk_idx ) {
  FD_TEST( store->disk_free_cnt<store->disk_max );
  ljoin->disk_free[ store->disk_free_cnt++ ] = disk_idx;
  stat_sub( &store->disk_live_cnt, 1UL );
}

/* fec_release removes f from fec_map and frees it.  f must already be
   out of slot_ring and own no slot.  Lock held. */

static void
fec_release( fd_store_t *          store,
             store_ljoin_t const * ljoin,
             uint                  f ) {
  FD_TEST( fd_store_fec_map_idx_remove( ljoin->map, &ljoin->meta[ f ].key, FD_STORE_NULL, ljoin->meta )==f );
  ljoin->meta[ f ].data = data_pack( 0U, FD_STORE_STATE_FREE );
  fd_store_meta_pool_idx_release( ljoin->meta, f );
  stat_sub( &store->fec_live_cnt, 1UL );
}

#define FD_STORE_SPILL_NO_VICTIM (0)
#define FD_STORE_SPILL_FREED     (1)
#define FD_STORE_SPILL_CANCELLED (2)

/* cache_spill spills the LRU head to a disk slot, writing with the
   lock dropped.  Returns FREED if a cache slot was freed, CANCELLED if
   replay pinned the victim during the write, or NO_VICTIM if the LRU
   is empty.  Enter and return with the lock held. */

static int
cache_spill( fd_store_t *             store,
             store_ljoin_t const *    ljoin,
             int                      disk_fd,
             fd_store_spill_stats_t * spill_stats,
             int                      wake ) {
  if( FD_UNLIKELY( fd_store_cache_lru_is_empty( ljoin->lru, ljoin->cache ) ) ) return FD_STORE_SPILL_NO_VICTIM;
  uint cache_idx = (uint)fd_store_cache_lru_idx_pop_head( ljoin->lru, ljoin->cache );
  uint f         = ljoin->cache[ cache_idx ].meta_idx;
  FD_TEST( ljoin->meta[ f ].data==data_pack( cache_idx, FD_STORE_STATE_CACHED ) );

  uint  disk_idx = disk_acquire( store, ljoin );
  ulong bytes    = ljoin->meta[ f ].data_sz;
  ljoin->meta[ f ].data = data_pack( cache_idx, FD_STORE_STATE_SPILLING );

  /* Write whole pages covering only the header and payload: query_read
     reads exactly the header plus data_sz, so the stale tail of a
     reused disk slot is never read. */
  ulong wr_sz = fd_ulong_align_up( FD_STORE_FEC_HDR_SZ+bytes, FD_STORE_PAYLOAD_PAGE_SZ );
  long  ticks = -fd_tickcount();
  fd_rwlock_unwrite( &store->lock );
  FD_STORE_SPILL_TEST_HOOK( store );

  fd_store_fec_t const * rec = cache_fec( store, ljoin->cache_mem, cache_idx );
  if( FD_UNLIKELY( store_pwrite_all( disk_fd, rec, wr_sz, (off_t)( (ulong)disk_idx*store->fec_slot_sz ) ) ) )
    FD_LOG_ERR(( "error spilling FEC payload to disk: (%d-%s)", errno, fd_io_strerror( errno ) ));

  fd_rwlock_write( &store->lock );
  ticks += fd_tickcount();
  if( spill_stats ) {
    spill_stats->write_cnt++;
    spill_stats->write_bytes += bytes;
    spill_stats->write_ticks += (ulong)ticks;
  }

  uint state = data_state( ljoin->meta[ f ].data );
  FD_TEST( data_idx( ljoin->meta[ f ].data )==cache_idx );
  switch( state ) {
  case FD_STORE_STATE_SPILLING: /* disk copy is authoritative, free the cache slot */
    ljoin->meta[ f ].data = data_pack( disk_idx, FD_STORE_STATE_SPILLED );
    cache_release( store, ljoin, cache_idx, wake );
    stat_add( &store->spill_cnt,   1UL   );
    stat_add( &store->spill_bytes, bytes );
    return FD_STORE_SPILL_FREED;
  case FD_STORE_STATE_SPILLING_DEAD: /* published during the write */
    disk_release( store, ljoin, disk_idx );
    cache_release( store, ljoin, cache_idx, wake );
    fec_release( store, ljoin, f );
    return FD_STORE_SPILL_FREED;
  case FD_STORE_STATE_PINNED_SPILLING: /* replay pinned the cache copy, discard the disk copy */
    disk_release( store, ljoin, disk_idx );
    ljoin->meta[ f ].data = data_pack( cache_idx, FD_STORE_STATE_PINNED );
    stat_add( &store->spill_cancel_cnt, 1UL );
    return FD_STORE_SPILL_CANCELLED;
  default:
    FD_LOG_CRIT(( "invariant violation: spilled FEC %u in state %u", f, state ));
  }
}

int
fd_store_insert_begin( fd_store_t *              store,
                       int                       disk_fd,
                       fd_hash_t const *         merkle_root,
                       ulong                     slot,
                       ulong                     part,
                       fd_store_insert_stats_t * insert_stats,
                       fd_store_insert_t *       out ) {
  *out = FD_STORE_INSERT_NULL;
  if( insert_stats ) memset( insert_stats, 0, sizeof(fd_store_insert_stats_t) );
  FD_TEST( slot<=UINT_MAX && part<store->shred_tile_cnt );

  fd_store_key_t key   = store_key( merkle_root );
  store_ljoin_t  ljoin = store_ljoin( store );

  fd_rwlock_write( &store->lock );

  if( FD_UNLIKELY( slot<store->min_root ) ) {
    fd_rwlock_unwrite( &store->lock );
    return FD_STORE_ERR_EXPIRED;
  }
  if( FD_UNLIKELY( map_find( &ljoin, &key, insert_stats ? &insert_stats->lookup : NULL )!=FD_STORE_NULL ) ) {
    fd_rwlock_unwrite( &store->lock );
    return FD_STORE_ERR_DUPLICATE;
  }
  if( FD_UNLIKELY( !fd_store_meta_pool_free( ljoin.meta ) ) ) {
    fd_rwlock_unwrite( &store->lock );
    return FD_STORE_ERR_FEC_FULL;
  }

  uint f = (uint)fd_store_meta_pool_idx_acquire( ljoin.meta );
  fd_store_fec_meta_t * meta = ljoin.meta + f;
  meta->key       = key;
  meta->slot      = (uint)slot;
  meta->slot_next = FD_STORE_NULL;
  meta->data      = data_pack( 0U, FD_STORE_STATE_ACQUIRED );
  meta->data_sz   = 0U;
  fd_store_fec_map_idx_insert( ljoin.map, f, ljoin.meta );
  ulong live = stat_add( &store->fec_live_cnt, 1UL );
  if( live>atomic_load_explicit( &store->fec_live_peak, memory_order_relaxed ) )
    atomic_store_explicit( &store->fec_live_peak, live, memory_order_relaxed );

  uint cache_idx;
  for(;;) {
    cache_idx = cache_acquire( store, &ljoin );
    if( FD_LIKELY( cache_idx!=FD_STORE_NULL ) ) break;

    if( FD_UNLIKELY( disk_fd<0 ) ) {
      fec_release( store, &ljoin, f );
      fd_rwlock_unwrite( &store->lock );
      return FD_STORE_ERR_CACHE_FULL;
    }

    /* A freed slot is reclaimed by the next cache_acquire in this lock
       hold, so it needs no wake.  A cancelled spill dropped the lock, so
       retry the acquire before spilling again. */
    int res = cache_spill( store, &ljoin, disk_fd, insert_stats ? &insert_stats->spill : NULL, 0 );
    if( res==FD_STORE_SPILL_NO_VICTIM ) cache_park( store, part, insert_stats );
  }

  ljoin.cache[ cache_idx ].meta_idx = f;
  meta->data = data_pack( cache_idx, FD_STORE_STATE_RESERVED );
  memset( cache_fec( store, ljoin.cache_mem, cache_idx )->shred_sz, 0, FD_STORE_FEC_HDR_SZ );

  fd_rwlock_unwrite( &store->lock );
  *out = f;
  return FD_STORE_SUCCESS;
}

fd_store_fec_t *
fd_store_insert_data( fd_store_t *      store,
                      fd_store_insert_t ins ) {
  FD_TEST( ins<store->fec_max );
  /* Only the inserter touches a RESERVED FEC: it is in neither the LRU
     nor slot_ring. */
  uint data = meta_laddr( store )[ ins ].data;
  FD_TEST( data_state( data )==FD_STORE_STATE_RESERVED );
  return cache_fec( store, cache_data_laddr( store ), data_idx( data ) );
}

int
fd_store_insert_commit( fd_store_t *      store,
                        fd_store_insert_t ins,
                        ulong             data_sz ) {
  FD_TEST( ins<store->fec_max );
  fd_store_fec_t const * rec = fd_store_insert_data( store, ins );
  ulong tracked_sz = 0UL;
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) tracked_sz += rec->shred_sz[ i ];
  FD_TEST( data_sz<=store->fec_data_max );
  FD_TEST( tracked_sz<=data_sz );

  store_ljoin_t ljoin = store_ljoin( store );
  fd_store_fec_meta_t * meta = ljoin.meta + ins;

  fd_rwlock_write( &store->lock );
  FD_TEST( data_state( meta->data )==FD_STORE_STATE_RESERVED );
  uint cache_idx = data_idx( meta->data );

  if( FD_UNLIKELY( meta->slot<store->min_root ) ) {
    cache_release( store, &ljoin, cache_idx, 1 );
    fec_release( store, &ljoin, ins );
    fd_rwlock_unwrite( &store->lock );
    return FD_STORE_ERR_EXPIRED;
  }

  meta->data_sz = (uint)data_sz;

  uint * bucket = ljoin.slot_ring + ( meta->slot & (store->slot_ring_len-1UL) );
  meta->slot_next = *bucket;
  *bucket         = ins;

  meta->data = data_pack( cache_idx, FD_STORE_STATE_CACHED );
  lru_push_tail( store, &ljoin, cache_idx );

  fd_rwlock_unwrite( &store->lock );
  return FD_STORE_SUCCESS;
}

fd_store_view_t
fd_store_query_acquire( fd_store_t *              store,
                        fd_hash_t const *         merkle_root,
                        fd_store_lookup_stats_t * lookup_stats ) {
  fd_store_key_t key   = store_key( merkle_root );
  store_ljoin_t  ljoin = store_ljoin( store );

  fd_rwlock_write( &store->lock );
  FD_TEST( store->pin_view==FD_STORE_VIEW_NULL ); /* single pinner, single view */

  uint f = map_find( &ljoin, &key, lookup_stats );
  if( FD_UNLIKELY( f==FD_STORE_NULL || ljoin.meta[ f ].slot<store->min_root ) ) {
    fd_rwlock_unwrite( &store->lock );
    return FD_STORE_VIEW_NULL;
  }

  fd_store_fec_meta_t * meta = ljoin.meta + f;
  uint idx = data_idx( meta->data );
  int  spilled = 0;
  switch( data_state( meta->data ) ) {
  case FD_STORE_STATE_CACHED: /* off the LRU while replay reads it */
    fd_store_cache_lru_idx_remove( ljoin.lru, idx, ljoin.cache );
    meta->data = data_pack( idx, FD_STORE_STATE_PINNED );
    break;
  case FD_STORE_STATE_SPILLING: /* keep the cache slot while the write runs */
    meta->data = data_pack( idx, FD_STORE_STATE_PINNED_SPILLING );
    break;
  case FD_STORE_STATE_SPILLED:
    meta->data = data_pack( idx, FD_STORE_STATE_PINNED_SPILLED );
    spilled = 1;
    break;
  default: /* not committed, or being torn down */
    fd_rwlock_unwrite( &store->lock );
    return FD_STORE_VIEW_NULL;
  }

  fd_store_view_t view = fd_store_view_pack( f, idx, spilled );
  store->pin_view = view;
  fd_rwlock_unwrite( &store->lock );
  return view;
}

ulong
fd_store_query_data_sz( fd_store_t const * store,
                        fd_store_view_t    view ) {
  /* No lock: only replay writes pin_view, and this runs on its thread.
     The pin keeps data_sz fixed. */
  FD_TEST( view!=FD_STORE_VIEW_NULL && store->pin_view==view );
  return meta_laddr( store )[ fd_store_view_meta_idx( view ) ].data_sz;
}

long
fd_store_query_read( fd_store_t *    store,
                     int             disk_fd,
                     fd_store_view_t view,
                     uchar *         payload,
                     ulong           payload_cap,
                     ushort          shred_sz[ FD_FEC_SHRED_CNT ],
                     int *           opt_spilled ) {
  /* No lock: the pin keeps the FEC, its data_sz and the slot named by
     the view fixed until release.  A concurrent spill of a pinned FEC
     is cancelled, never completed, so the cache slot stays valid. */
  FD_TEST( view!=FD_STORE_VIEW_NULL && store->pin_view==view );
  ulong n       = meta_laddr( store )[ fd_store_view_meta_idx( view ) ].data_sz;
  int   spilled = fd_store_view_spilled( view );
  ulong idx     = fd_store_view_data_idx( view );
  FD_TEST( n<=store->fec_data_max );
  if( opt_spilled ) *opt_spilled = spilled;
  if( FD_UNLIKELY( n>payload_cap ) ) return FD_STORE_ERR_TOO_BIG;

  if( FD_LIKELY( !spilled ) ) {
    fd_store_fec_t const * rec = cache_fec( store, cache_data_laddr( store ), idx );
    memcpy( shred_sz, rec->shred_sz, FD_STORE_FEC_HDR_SZ );
    fd_memcpy( payload, rec->payload, n );
  } else {
    struct iovec iov[ 2 ] = {
      { .iov_base = shred_sz, .iov_len = FD_STORE_FEC_HDR_SZ },
      { .iov_base = payload,  .iov_len = n                   }
    };
    if( FD_UNLIKELY( store_preadv_all( disk_fd, iov, 2, (off_t)( idx*store->fec_slot_sz ) ) ) )
      FD_LOG_ERR(( "error reading spilled FEC payload: (%d-%s)", errno, fd_io_strerror( errno ) ));
    stat_add( &store->spill_read_cnt,   1UL );
    stat_add( &store->spill_read_bytes, n   );
  }

  ulong tracked_sz = 0UL;
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) tracked_sz += shred_sz[ i ];
  FD_TEST( tracked_sz<=n );
  return (long)n;
}

void
fd_store_query_release( fd_store_t *    store,
                        fd_store_view_t view ) {
  store_ljoin_t ljoin = store_ljoin( store );
  uint f = fd_store_view_meta_idx( view );

  fd_rwlock_write( &store->lock );
  FD_TEST( view!=FD_STORE_VIEW_NULL && store->pin_view==view );
  fd_store_fec_meta_t * meta = ljoin.meta + f;
  uint idx = data_idx( meta->data );
  switch( data_state( meta->data ) ) {
  case FD_STORE_STATE_PINNED: /* already consumed, so spill it first */
    meta->data = data_pack( idx, FD_STORE_STATE_CACHED );
    lru_push_head( store, &ljoin, idx );
    break;
  case FD_STORE_STATE_PINNED_SPILLING: /* the spill may now complete */
    meta->data = data_pack( idx, FD_STORE_STATE_SPILLING );
    break;
  case FD_STORE_STATE_PINNED_SPILLED:
    meta->data = data_pack( idx, FD_STORE_STATE_SPILLED );
    break;
  default:
    FD_LOG_CRIT(( "invariant violation: released FEC %u in state %u", f, data_state( meta->data ) ));
  }
  store->pin_view = FD_STORE_VIEW_NULL;
  fd_rwlock_unwrite( &store->lock );
}

void
fd_store_publish( fd_store_t *               store,
                  ulong                      root,
                  fd_store_publish_stats_t * publish_stats ) {
  if( publish_stats ) publish_stats->removed_cnt = 0UL;
  FD_TEST( root<=UINT_MAX );
  store_ljoin_t ljoin = store_ljoin( store );

  /* Never drops the lock or waits for spill I/O. */
  fd_rwlock_write( &store->lock );
  if( FD_UNLIKELY( root<=store->min_root ) ) {
    fd_rwlock_unwrite( &store->lock );
    return;
  }
  ulong old = store->min_root;
  store->min_root = root;

  /* Every live FEC has slot>=old, so those below root are in the
     buckets of slots [old,root). */
  ulong removed = 0UL;
  ulong mask    = store->slot_ring_len-1UL;
  ulong n       = fd_ulong_min( root-old, store->slot_ring_len );
  for( ulong i=0UL; i<n; i++ ) {
    uint * link = ljoin.slot_ring + ( (old+i) & mask );
    while( *link!=FD_STORE_NULL ) {
      uint f = *link;
      fd_store_fec_meta_t * meta = ljoin.meta + f;
      if( FD_UNLIKELY( meta->slot>=root ) ) { /* aliased later slot */
        link = &meta->slot_next;
        continue;
      }
      
      /* Replay is the only pinner and publisher, and never holds a view
         across publish.  Waiting here would deadlock. */
      uint state = data_state( meta->data );
      uint idx   = data_idx  ( meta->data );
      FD_TEST( state!=FD_STORE_STATE_PINNED &&
               state!=FD_STORE_STATE_PINNED_SPILLING &&
               state!=FD_STORE_STATE_PINNED_SPILLED );
      *link = meta->slot_next;
      meta->slot_next = FD_STORE_NULL;
      removed++;

      switch( state ) {
      case FD_STORE_STATE_CACHED:
        fd_store_cache_lru_idx_remove( ljoin.lru, idx, ljoin.cache );
        cache_release( store, &ljoin, idx, 1 );
        fec_release( store, &ljoin, f );
        break;
      case FD_STORE_STATE_SPILLED:
        disk_release( store, &ljoin, idx );
        fec_release( store, &ljoin, f );
        break;
      case FD_STORE_STATE_SPILLING: /* the spiller frees it after its write */
        meta->data = data_pack( idx, FD_STORE_STATE_SPILLING_DEAD );
        break;
      default:
        FD_LOG_CRIT(( "invariant violation: published FEC %u in state %u", f, state ));
      }
    }
  }
  fd_rwlock_unwrite( &store->lock );
  if( publish_stats ) publish_stats->removed_cnt = removed;
}

int
fd_store_preevict( fd_store_t *             store,
                   int                      disk_fd,
                   int *                    active,
                   fd_store_spill_stats_t * spill_stats ) {
  if( spill_stats ) memset( spill_stats, 0, sizeof(fd_store_spill_stats_t) );
  if( FD_UNLIKELY( disk_fd<0 ) ) return 0;

  /* Called every pass: don't take the lock for nothing. */
  if( FD_LIKELY( !*active &&
                 atomic_load_explicit( &store->cache_free_cnt, memory_order_relaxed )>=store->cache_free_low_water ) ) return 0;

  store_ljoin_t ljoin = store_ljoin( store );
  fd_rwlock_write( &store->lock );

  /* First, make sure preevict is active */
  if( !*active ) {
    if( fd_store_cache_pool_free( ljoin.cache )>=store->cache_free_low_water ) {
      fd_rwlock_unwrite( &store->lock );
      return 0;
    }
    *active = 1;
  }
  /* Hitting the target means we can deactivate */
  if( fd_store_cache_pool_free( ljoin.cache )>=store->cache_free_target ) {
    *active = 0;
    fd_rwlock_unwrite( &store->lock );
    return 0;
  }
  /* Not at the target yet.  Spill one, reporting if progress was made */
  int res = cache_spill( store, &ljoin, disk_fd, spill_stats, 1 );
  *active = fd_store_cache_pool_free( ljoin.cache )<store->cache_free_target;
  fd_rwlock_unwrite( &store->lock );
  return res==FD_STORE_SPILL_FREED;
}

void
fd_store_fec_cache_stats_query( fd_store_t const *           store,
                                fd_store_fec_cache_stats_t * stats ) {
  stats->free_cnt  = atomic_load_explicit( &store->cache_free_cnt, memory_order_relaxed );
  stats->max       = store->cache_max;
  stats->target    = store->cache_free_target;
  stats->low_water = store->cache_free_low_water;
}

/* Both chain maps, their keys and links, tags, and reservation decisions
   use disk_lock.  Production has one rserve tile, the sole disk_* caller,
   so map access has little contention.  Disk I/O runs without the lock;
   WRITING entries reserve keys and prevent reuse until the write finishes. */
#define FD_STORE_DISK_READ_RETRY_CNT (8UL)

static inline ulong
disk_cell_tag( ulong ticket,
               uint  state ) {
  return ((ticket & FD_SHREDB_TAG_SEQ_MASK)<<2) | state;
}

static inline ulong
disk_cell_state( ulong tag ) {
  return tag & FD_SHREDB_CELL_STATE_MASK;
}

static inline ulong
disk_cell_ticket( ulong tag ) {
  return (tag>>2) & FD_SHREDB_TAG_SEQ_MASK;
}

/* The tag is split across seven bytes in the ring, but is a ulong on
   disk.  All ring accesses to these fields hold disk_lock. */
static inline ulong
disk_cell_tag_load( fd_shredb_ring_entry_t const * cell ) {
  return (ulong)cell->tag
       | ((ulong)cell->tag_hi[0]<<32)
       | ((ulong)cell->tag_hi[1]<<40)
       | ((ulong)cell->tag_hi[2]<<48);
}

static inline void
disk_cell_tag_store( fd_shredb_ring_entry_t * cell,
                     ulong                     tag ) {
  cell->tag       = (uint)tag;
  cell->tag_hi[0] = (uchar)(tag>>32);
  cell->tag_hi[1] = (uchar)(tag>>40);
  cell->tag_hi[2] = (uchar)(tag>>48);
}

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

/* The slot and root maps are fd_map_chain instances over the shared ring
   pool; all helpers require disk_lock.  Lookups use the _const query so
   concurrent readers (shared disk_lock) are safe; link/unlink mutate and
   run only under the exclusive write lock.  UINT_MAX is the miss sentinel
   (no ring index can equal it since disk_max_shreds < UINT_MAX).  The root
   comparison uses the complete 21-byte key. */
static inline uint
disk_slot_lookup_locked( fd_store_t const * store,
                         ulong              key ) {
  fd_shredb_slot_map_t * map = disk_slot_map_join( store );
  return (uint)fd_shredb_slot_map_idx_query_const( map, &key, UINT_MAX, disk_ring_pool_laddr( store ) );
}

static inline uint
disk_root_lookup_locked( fd_store_t const *           store,
                         fd_shredb_root_key_t const * key ) {
  fd_shredb_root_map_t * map = disk_root_map_join( store );
  return (uint)fd_shredb_root_map_idx_query_const( map, key, UINT_MAX, disk_ring_pool_laddr( store ) );
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

  fd_shredb_root_map_t * root_map = disk_root_map_join( store );
  if( (uint)fd_shredb_root_map_idx_query( root_map, &cell->root_key, UINT_MAX, pool )==ring_idx ) {
    fd_shredb_root_map_idx_remove( root_map, &cell->root_key, UINT_MAX, pool );
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
  ulong ticket;
  uint  ring_idx;
  int   linked;
};
typedef struct disk_view disk_view_t;

static int
disk_insert_prepare_write_locked( fd_store_t                 * store,
                                  ulong                        key,
                                  fd_shredb_root_key_t const * root_key,
                                  disk_view_t                * view ) {
  fd_shredb_ring_entry_t * pool = disk_ring_pool_laddr( store );

  /* A READY root-map key wins even when the new shred has a different
     full index. */
  uint exist_idx = disk_root_lookup_locked( store, root_key );
  if( exist_idx!=UINT_MAX ) {
    ulong state = disk_cell_state( pool[exist_idx].tag );
    if( FD_UNLIKELY( state==FD_SHREDB_CELL_WRITING ) ) return FD_STORE_DISK_INSERT_ERR;
    FD_TEST( state==FD_SHREDB_CELL_READY );
    return FD_STORE_DISK_INSERT_DUP;
  }

  /* Grab a ticket & ring_idx to write to.
     May wrap around and overwrite an existing cell that's not mid-write. */
  ulong ticket   = atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed );
  uint  ring_idx = (uint)(ticket % store->disk_max_shreds);
  atomic_store_explicit( &store->disk_reservation_head, ticket + 1UL, memory_order_relaxed );
  if( FD_UNLIKELY( disk_cell_state( pool[ring_idx].tag )==FD_SHREDB_CELL_WRITING ) ) return FD_STORE_DISK_INSERT_ERR;

  /* Retire the ring cell's old keys before changing either key field. */
  disk_invalidate_locked( store, ring_idx );

  fd_shredb_ring_entry_t * cell = pool + ring_idx;
  disk_cell_tag_store( cell, disk_cell_tag( ticket, FD_SHREDB_CELL_WRITING ) );
  cell->key = key;
  int linked = disk_slot_lookup_locked( store, key )==UINT_MAX;
  if( linked ) fd_shredb_slot_map_idx_insert( disk_slot_map_join( store ), ring_idx, pool );
  cell->root_key = *root_key;
  fd_shredb_root_map_idx_insert( disk_root_map_join( store ), ring_idx, pool );

  view->ticket   = ticket;
  view->ring_idx = ring_idx;
  view->linked   = linked;
  return FD_STORE_DISK_INSERT_SUCCESS;
}

static int
disk_insert_finish_write_locked( fd_store_t * store,
                                 disk_view_t  view ) {
  fd_shredb_ring_entry_t * cell = disk_ring_pool_laddr( store ) + view.ring_idx;
  FD_TEST( disk_cell_tag_load( cell )==disk_cell_tag( view.ticket, FD_SHREDB_CELL_WRITING ) );

  ulong disk_cnt = atomic_load_explicit( &store->disk_cnt, memory_order_relaxed );
  atomic_store_explicit( &store->disk_cnt, disk_cnt+1UL, memory_order_relaxed );
  disk_cell_tag_store( cell, disk_cell_tag( view.ticket, FD_SHREDB_CELL_READY ) );

  if( view.linked ) disk_slot_hint_publish_locked( store, fd_shredb_key_slot( cell->key ), fd_shredb_key_shred_idx( cell->key ) );
  return FD_STORE_DISK_INSERT_SUCCESS;
}

FD_STATIC_ASSERT( __builtin_offsetof( fd_shredb_entry_t, shred )==__builtin_offsetof( fd_shredb_entry_t, shred_sz )+sizeof(ushort), shredb_entry_hdr_packed );

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
  ulong                key      = fd_shredb_key_pack( slot, shred_idx );
  fd_shredb_root_key_t root_key = fd_shredb_root_key( merkle_root->uc, shred_idx );

  disk_view_t view;
  fd_rwlock_write( &store->disk_lock );
  int result = disk_insert_prepare_write_locked( store, key, &root_key, &view );
  fd_rwlock_unwrite( &store->disk_lock );
  if( FD_UNLIKELY( result!=FD_STORE_DISK_INSERT_SUCCESS ) ) return result;

  /* The map entries remain WRITING while the syscall runs unlocked. */
  fd_shredb_entry_t wr_entry[1];
  ulong shred_sz = fd_ulong_min( fd_shred_sz( shred ), FD_SHRED_MAX_SZ );
  ulong tail_off = __builtin_offsetof( fd_shredb_entry_t, shred )+shred_sz;
  wr_entry->tag      = disk_cell_tag( view.ticket, FD_SHREDB_CELL_READY );
  wr_entry->key      = key;
  wr_entry->shred_sz = (ushort)shred_sz;
  memcpy( wr_entry->root, merkle_root->uc, FD_SHRED_MERKLE_NODE_SZ );
  fd_memcpy( wr_entry->shred, shred, shred_sz );
  fd_memset( (uchar *)wr_entry+tail_off, 0, sizeof(wr_entry)-tail_off );

  off_t off = (off_t)(store->wire_off + (ulong)view.ring_idx*sizeof(fd_shredb_entry_t));
  if( FD_UNLIKELY( store_pwrite_all( disk_fd, wr_entry, sizeof(wr_entry), off ) ) )
    FD_LOG_ERR(( "error writing to disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
  atomic_fetch_add_explicit( &store->disk_write_bytes, sizeof(wr_entry), memory_order_relaxed );

  fd_rwlock_write( &store->disk_lock );
  result = disk_insert_finish_write_locked( store, view );
  fd_rwlock_unwrite( &store->disk_lock );
  if( FD_UNLIKELY( result!=FD_STORE_DISK_INSERT_SUCCESS ) ) return result;

  atomic_fetch_add_explicit( &store->disk_insert_cnt, 1UL, memory_order_relaxed );
  return FD_STORE_DISK_INSERT_SUCCESS;
}

static int
disk_query_prepare_read_locked( fd_store_t           const * store,
                                ulong                        key,
                                fd_shredb_root_key_t const * root_key,
                                uint                         shred_idx,
                                disk_view_t                * view ) {
  uint ring_idx = root_key ? disk_root_lookup_locked( store, root_key ) : disk_slot_lookup_locked( store, key );
  if( FD_UNLIKELY( ring_idx==UINT_MAX ) ) return FD_STORE_DISK_QUERY_MISS;

  fd_shredb_ring_entry_t const * cell = disk_ring_pool_laddr( store ) + ring_idx;
  ulong tag = disk_cell_tag_load( cell );
  if( FD_UNLIKELY( disk_cell_state( tag )!=FD_SHREDB_CELL_READY ) ) {
    if( disk_cell_state( tag )==FD_SHREDB_CELL_WRITING ) return FD_STORE_DISK_QUERY_BUSY;
    return FD_STORE_DISK_QUERY_MISS;
  }
  if( FD_UNLIKELY( root_key && fd_shredb_key_shred_idx( cell->key )!=shred_idx ) ) {
    return FD_STORE_DISK_QUERY_MISS;
  }

  view->ticket   = disk_cell_ticket( tag );
  view->ring_idx = ring_idx;
  view->linked   = 0;
  return 0;
}

static int
disk_query_finish_read_locked( fd_store_t  const * store,
                               disk_view_t         view ) {
  fd_shredb_ring_entry_t const * cell = disk_ring_pool_laddr( store ) + view.ring_idx;
  if( FD_UNLIKELY( disk_cell_tag_load( cell )!=disk_cell_tag( view.ticket, FD_SHREDB_CELL_READY ) ) ) return FD_STORE_DISK_QUERY_BUSY;
  return 0;
}

/* disk_read_once snapshots and validates under disk_lock, releasing it
   only for pread. The tag and mapping checks reject a torn read if the
   cell was overwritten during I/O. */
static int
disk_read_once( fd_store_t const *           store,
                int                          disk_fd,
                ulong                        key,
                fd_shredb_root_key_t const * root_key,
                uint                         shred_idx,
                fd_shredb_entry_t *          rd_entry ) {
  /* need mutable rwlock to read, even under a const ptr */
  fd_rwlock_t * rwlock = (fd_rwlock_t *)fd_type_pun_const( &store->disk_lock );

  disk_view_t view;
  fd_rwlock_read( rwlock );
  int result = disk_query_prepare_read_locked( store, key, root_key, shred_idx, &view );
  fd_rwlock_unread( rwlock );
  if( FD_UNLIKELY( result ) ) return result;

  off_t off = (off_t)(store->wire_off + (ulong)view.ring_idx*sizeof(fd_shredb_entry_t));
  if( FD_UNLIKELY( store_pread_all( disk_fd, rd_entry, sizeof(*rd_entry), off ) ) ) {
    FD_LOG_ERR(( "error reading disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));
    return FD_STORE_DISK_QUERY_BUSY;
  }

  fd_rwlock_read( rwlock );
  result = disk_query_finish_read_locked( store, view );
  fd_rwlock_unread( rwlock );
  if( FD_UNLIKELY( result ) ) return result;

  ulong tag = disk_cell_tag( view.ticket, FD_SHREDB_CELL_READY );
  if( root_key ) {
    if( FD_UNLIKELY( rd_entry->tag!=tag ||
                     memcmp( rd_entry->root, root_key->root, FD_SHRED_MERKLE_NODE_SZ ) ||
                     fd_shredb_key_shred_idx( rd_entry->key )%FD_FEC_SHRED_CNT!=root_key->off ) ) return FD_STORE_DISK_QUERY_BUSY;
    if( FD_UNLIKELY( fd_shredb_key_shred_idx( rd_entry->key )!=shred_idx ) ) return FD_STORE_DISK_QUERY_MISS;
  } else {
    if( FD_UNLIKELY( rd_entry->tag!=tag || rd_entry->key!=key ) ) return FD_STORE_DISK_QUERY_BUSY;
  }
  return (int)fd_ulong_min( rd_entry->shred_sz, FD_SHRED_MAX_SZ );
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
    int result = disk_read_once( store, disk_fd, key, NULL, shred_idx, entry );
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
                          uchar const *      merkle_root,
                          uint               shred_idx,
                          uchar              out[ FD_SHRED_MAX_SZ ] ) {
  if( FD_UNLIKELY( !store || disk_fd<0 || !merkle_root || !out || !fd_store_has_disk( store ) ||
                   shred_idx>=store->max_shreds_per_block ) ) return FD_STORE_DISK_QUERY_MISS;
  fd_shredb_root_key_t rk = fd_shredb_root_key( merkle_root, shred_idx );
  for( ulong retry=0UL; retry<FD_STORE_DISK_READ_RETRY_CNT; retry++ ) {
    fd_shredb_entry_t entry[1];
    int result = disk_read_once( store, disk_fd, 0UL, &rk, shred_idx, entry );
    if( FD_UNLIKELY( result==FD_STORE_DISK_QUERY_BUSY ) ) { FD_SPIN_PAUSE(); continue; }
    if( FD_UNLIKELY( result<0 ) ) return result;
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
    int result = disk_read_once( store, disk_fd, fd_shredb_key_pack( slot, idx ), NULL, idx, entry );
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
                         + atomic_load_explicit( &store->disk_live_cnt, memory_order_relaxed )*store->fec_slot_sz;
  stats->allocated_bytes = fd_ulong_min( atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed ),
                                        store->disk_max_shreds )*sizeof(fd_shredb_entry_t)
                         + atomic_load_explicit( &store->disk_bump, memory_order_relaxed )*store->fec_slot_sz;
  stats->insert_cnt      = atomic_load_explicit( &store->disk_insert_cnt, memory_order_relaxed );
  stats->write_bytes     = atomic_load_explicit( &store->disk_write_bytes, memory_order_relaxed );
  return 0;
}
