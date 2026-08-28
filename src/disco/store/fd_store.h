#ifndef HEADER_fd_src_disco_store_fd_store_h
#define HEADER_fd_src_disco_store_fd_store_h

#include "../../disco/shred/fd_fec_set.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/fd_rwlock.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/hist/fd_histf.h"
#include "../../util/shmem/fd_shmem.h"

#define FD_STORE_ALIGN (128UL)

/* FD_STORE_PAYLOAD_PAGE_SZ is the granularity at which FEC payload
   slots are aligned in the RAM cache and spill file. */
#define FD_STORE_PAYLOAD_PAGE_SZ (FD_SHMEM_NORMAL_PAGE_SZ)

/* fd_store_payload_slot_sz returns fec_data_max rounded up to a whole
   number of pages. */
FD_FN_CONST static inline ulong
fd_store_payload_slot_sz( ulong fec_data_max ) {
  return fd_ulong_align_up( fec_data_max, FD_STORE_PAYLOAD_PAGE_SZ );
}
#define FD_STORE_MAGIC (0xf17eda2ce75702e4UL) /* firedancer store version 4 */

#define FD_STORE_FEC_DATA_EMPTY       (0U)
#define FD_STORE_FEC_DATA_RAM_WRITING (1U)
#define FD_STORE_FEC_DATA_RAM_READY   (2U)
#define FD_STORE_FEC_DATA_DISK        (3U)
#define FD_STORE_FEC_DATA_CONSUMED    (4U)

FD_FN_CONST static inline ulong
fd_shredb_key_pack( ulong slot, uint shred_idx ) {
  return (slot << 16) | (ulong)(ushort)shred_idx;
}

FD_FN_CONST static inline ulong
fd_shredb_key_slot( ulong key ) {
  return fd_ulong_extract( key, 16, 63 );
}

FD_FN_CONST static inline uint
fd_shredb_key_shred_idx( ulong key ) {
  return (uint)fd_ulong_extract( key, 0, 15 );
}

struct fd_shredb_shred_entry {
  ulong key;
  uint  next;
  uint  prev;
};
typedef struct fd_shredb_shred_entry fd_shredb_shred_entry_t;

#define MAP_NAME                           fd_shredb_shred_map
#define MAP_ELE_T                          fd_shredb_shred_entry_t
#define MAP_KEY_T                          ulong
#define MAP_KEY                            key
#define MAP_IDX_T                          uint
#define MAP_NEXT                           next
#define MAP_PREV                           prev
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_shredb_slot_entry {
  ulong key;
  uint  highest_shred_idx;
  ulong cnt;
};
typedef struct fd_shredb_slot_entry fd_shredb_slot_entry_t;

#define MAP_NAME              fd_shredb_slot_map
#define MAP_T                 fd_shredb_slot_entry_t
#define MAP_KEY_T             ulong
#define MAP_KEY_NULL          ULONG_MAX
#define MAP_KEY_INVAL(k)      ((k)==ULONG_MAX)
#define MAP_KEY_EQUAL(k0,k1)  ((k0)==(k1))
#define MAP_KEY_HASH(k,seed)  ((uint)fd_ulong_hash( (k) ^ (seed) ))
#define MAP_MEMOIZE           0
#define MAP_KEY_EQUAL_IS_SLOW 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(64))) fd_shredb_entry {
  ushort shred_sz;
  uchar  shred[FD_SHRED_MAX_SZ];
};
typedef struct fd_shredb_entry fd_shredb_entry_t;

#define FD_SHREDB_MAX_SIZE_GIB (((ulong)UINT_MAX*sizeof(fd_shredb_entry_t))/(1UL<<30))

FD_FN_CONST static inline ulong
fd_shredb_max_shreds( ulong gib ) {
  return gib ? (gib*1024UL*1024UL*1024UL) / sizeof(fd_shredb_entry_t) : 0UL;
}

FD_FN_CONST static inline ulong
fd_shredb_max_slots( ulong gib ) {
  return fd_shredb_max_shreds( gib ) / 32UL;
}


/* Exactly 128 bytes.  Offsets are cumulative sizes <= fec_data_max
   (63985) so they fit ushort, and payload locations are stored as
   payload_slot_sz-granular slot indices (< fec_max <= UINT_MAX) rather
   than byte offsets so they fit uint. */

struct __attribute__((aligned(FD_STORE_ALIGN))) fd_store_fec {
  fd_hash_t key;
  ulong     next;                            /* managed by fd_pool / fd_map_chain_para */
  ushort    shred_offs[FD_FEC_SHRED_CNT];    /* shred_offs[i] = cumulative size of data shreds [0..i] */
  uint      data_sz;                         /* sz of the FEC set payload, <= fec_data_max */
  uint      data_idx;                        /* RAM cache slot idx when RAM_*, spill-file slot idx when DISK */
  uint      cache_prev;                      /* RAM_READY LRU links, UINT_MAX when unlinked */
  uint      cache_next;
  uint      data_pin_cnt;                    /* active payload views */
  uint      data_state;                      /* FD_STORE_FEC_DATA_* */
};
typedef struct fd_store_fec fd_store_fec_t;

FD_STATIC_ASSERT( sizeof(struct fd_store_fec)==FD_STORE_ALIGN, fd_store_fec );


#define POOL_NAME  fd_store_pool
#define POOL_ELE_T fd_store_fec_t
#include "../../util/tmpl/fd_pool_para.c"


#define MAP_NAME               fd_store_map
#define MAP_ELE_T              fd_store_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash( (key)->ul[0] ^ (seed) )
#include "../../util/tmpl/fd_map_chain_para.c"


struct fd_store {
  ulong magic;
  ulong fec_max;
  ulong fec_data_max;
  ulong store_gaddr;
  ulong map_gaddr;
  ulong pool_mem_gaddr;
  ulong pool_ele_gaddr;

  ulong payload_slot_sz;
  ulong payload_sz;                          /* logical spill region size: payload_slot_sz*fec_max */
  ulong wire_off;                            /* byte offset where the rserve wire region begins */
  char  db_path[ PATH_MAX ];

  /* RAM FEC payload cache.  cache_slot_cnt is usually much smaller than
     fec_max.  cache_free is a stack of slot indices protected by
     cache_lock. */
  ulong       cache_slot_cnt;
  ulong       cache_data_gaddr;
  ulong       cache_free_gaddr;
  ulong       cache_free_cnt;
  uint        cache_lru_head;
  uint        cache_lru_tail;
  ulong       cache_pinned_cnt;
  ulong       fec_spill_cnt;
  ulong       fec_spill_bytes;
  ulong       fec_spill_read_cnt;
  ulong       fec_spill_read_bytes;
  ulong       fec_spill_read_fail_cnt;
  fd_rwlock_t cache_lock;

  /* Spilled payloads are read into this buffer under spill_read_lock. */
  ulong       spill_read_data_gaddr;
  fd_rwlock_t spill_read_lock;

  /* Arena used by shred tiles for assembly and recovery. */
  ulong       fec_set_cnt;
  ulong       fec_sets_gaddr;

  /* On-disk shred index. Lives in the wire region of the shared file
     at byte offset wire_off + ring_idx*sizeof(entry).
     
     cache_shreds optionally bounds page residency of the wire region.
     The tail behind that window is released with FADV_DONTNEED. */
  ulong       shred_map_gaddr;
  ulong       shred_pool_gaddr;
  ulong       slot_map_gaddr;
  ulong       evict_occ_gaddr;
  ulong       disk_max_shreds;
  ulong       disk_write_head;
  ulong       disk_cnt;
  ulong       disk_file_shreds;
  ulong       cache_shreds;
  ulong       disk_insert_cnt;
  ulong       disk_duplicate_cnt;
  ulong       disk_write_bytes;
  atomic_ulong disk_write_seq;
  atomic_ulong disk_writer_cnt;
  fd_rwlock_t  disk_lock;
};
typedef struct fd_store fd_store_t;

FD_PROTOTYPES_BEGIN


FD_FN_CONST static inline ulong
fd_store_align( void ) {
  return FD_STORE_PAYLOAD_PAGE_SZ;
}

FD_FN_CONST static inline ulong
fd_store_footprint( ulong fec_max,
                    ulong fec_data_max,
                    ulong shred_storage_gib,
                    ulong shred_cache_bytes,
                    ulong fec_set_cnt ) {
  if( FD_UNLIKELY( fec_max>UINT_MAX || shred_storage_gib>FD_SHREDB_MAX_SIZE_GIB ) ) return 0UL;
  ulong chain_cnt = fd_store_map_chain_cnt_est( fec_max );
  ulong payload_slot_sz = fd_store_payload_slot_sz( fec_data_max );
  ulong cache_slot_cnt = shred_cache_bytes
                       ? fd_ulong_min( fec_max, fd_ulong_max( 1UL, shred_cache_bytes / payload_slot_sz ) )
                       : fec_max;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_store_align(),         sizeof(fd_store_t)                   );
  l = FD_LAYOUT_APPEND( l, fd_store_map_align(),      fd_store_map_footprint( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_store_pool_align(),     fd_store_pool_footprint()           );
  l = FD_LAYOUT_APPEND( l, alignof(fd_store_fec_t),   sizeof(fd_store_fec_t)*fec_max      );
  l = FD_LAYOUT_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ,  payload_slot_sz*cache_slot_cnt      );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),            sizeof(ulong)*cache_slot_cnt        );
  l = FD_LAYOUT_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ,  payload_slot_sz                     );
  if( fec_set_cnt ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_fec_set_t),   sizeof(fd_fec_set_t)*fec_set_cnt    );
  }
  if( shred_storage_gib ) {
    ulong max_shreds   = fd_shredb_max_shreds( shred_storage_gib );
    ulong max_slots    = fd_shredb_max_slots ( shred_storage_gib );
    ulong chain_cnt    = fd_shredb_shred_map_chain_cnt_est( max_shreds );
    int   lg_slot_cnt  = fd_ulong_find_msb( fd_ulong_pow2_up( max_slots + 1UL ) );
    ulong bitset_words = (max_shreds + 63UL) / 64UL;
    l = FD_LAYOUT_APPEND( l, fd_shredb_shred_map_align(),      fd_shredb_shred_map_footprint( chain_cnt )   );
    l = FD_LAYOUT_APPEND( l, fd_shredb_slot_map_align(),       fd_shredb_slot_map_footprint ( lg_slot_cnt ) );
    l = FD_LAYOUT_APPEND( l, alignof(fd_shredb_shred_entry_t), max_shreds * sizeof(fd_shredb_shred_entry_t) );
    l = FD_LAYOUT_APPEND( l, alignof(ulong),                   bitset_words * sizeof(ulong)                 );
  }
  return FD_LAYOUT_FINI( l, fd_store_align() );
}

/* fd_store_new formats a region of memory as a store.  db_path is the
   path to the backing file; fd_store_new creates (or truncates) it,
   reserves a sparse spill region large enough to hold all FECs, and
   (when shred_storage_gib>0) fallocates an initial wire region at
   wire_off. */

void *
fd_store_new( void       * shmem,
              ulong        fec_max,
              ulong        fec_data_max,
              ulong        shred_storage_gib,
              ulong        shred_cache_bytes,
              ulong        fec_set_cnt,
              char const * db_path,
              ulong        seed );

fd_store_t * fd_store_join ( void * shstore );
void *       fd_store_leave( fd_store_t const * store );
void *       fd_store_delete( void * shstore );


FD_FN_PURE static inline fd_wksp_t *
fd_store_wksp( fd_store_t const * store ) {
  return (fd_wksp_t *)( ( (ulong)store ) - store->store_gaddr );
}

/* Store-owned transient FEC-set arena.  The caller is responsible for
   slicing the arena by tile kind_id. */

FD_FN_PURE static inline fd_fec_set_t *
fd_store_fec_sets( fd_store_t const * store ) {
  return store->fec_set_cnt ? fd_wksp_laddr_fast( fd_store_wksp( store ), store->fec_sets_gaddr ) : NULL;
}

/* fd_store_map_ljoin creates a local join to the store's concurrent
   map.  Each tile must call this during unprivileged_init and keep
   the result.  ljoin points to a local fd_store_map_t scratch. */

static inline fd_store_map_t *
fd_store_map_ljoin( fd_store_t * store, fd_store_map_t * ljoin ) {
  fd_wksp_t * wksp = fd_store_wksp( store );
  return fd_store_map_join( ljoin,
                            fd_wksp_laddr_fast( wksp, store->map_gaddr ),
                            fd_wksp_laddr_fast( wksp, store->pool_ele_gaddr ),
                            store->fec_max );
}

/* FEC data pointer for writers.  Only valid in RAM_WRITING. */

FD_FN_PURE static inline uchar *
fd_store_fec_data( fd_store_t const *     store,
                   fd_store_fec_t const * fec ) {
  return (uchar *)( (ulong)store - store->store_gaddr + store->cache_data_gaddr + (ulong)fec->data_idx*store->payload_slot_sz );
}

struct fd_store_fec_data_view {
  uchar          * data;
  fd_store_fec_t * fec;
  uint             flags;
};
typedef struct fd_store_fec_data_view fd_store_fec_data_view_t;

/* Views pin one FEC payload without holding the cache lock.  Release
   every successful view before consuming its FEC. */

uchar *
fd_store_fec_data_acquire( fd_store_t     * store,
                           int              disk_fd,
                           fd_store_fec_t * fec );

void
fd_store_fec_data_publish( fd_store_t     * store,
                           fd_store_fec_t * fec );

int
fd_store_fec_data_view( fd_store_t *               store,
                        int                        disk_fd,
                        fd_store_fec_t *           fec,
                        fd_store_fec_data_view_t * view );

void
fd_store_fec_data_view_release( fd_store_t *               store,
                                fd_store_fec_data_view_t * view );

void
fd_store_fec_data_consumed( fd_store_t     * store,
                            fd_store_fec_t * fec );


/* fd_store_insert inserts a pre-acquired FEC element into the map.
   Caller must have set fec->key to the merkle root. 
   Returns FD_MAP_SUCCESS on success. */

static inline int
fd_store_insert( fd_store_map_t * join,
                 fd_store_fec_t * fec ) {
  return fd_store_map_insert( join, fec, FD_MAP_FLAG_BLOCKING );
}

/* fd_store_query does a lockless query by merkle_root, retrying if a
   concurrent chain update invalidates the speculative read.  Returns
   an element pointer or NULL when the key is not present.  The returned
   pointer is valid as long as the element is in the map. */

fd_store_fec_t *
fd_store_query( fd_store_map_t *  join,
                fd_hash_t const * merkle_root );

/* fd_store_remove removes the FEC with the given merkle_root.
   Returns the removed element (ownership transfers to caller, who
   must call fd_store_fec_release) or NULL if not found. */

fd_store_fec_t *
fd_store_remove( fd_store_map_t *  join,
                 fd_hash_t const * merkle_root );


fd_store_fec_t * fd_store_fec_acquire( fd_store_t * store );
void             fd_store_fec_release( fd_store_t * store, fd_store_fec_t * fec );


FD_FN_PURE static inline int
fd_store_has_disk( fd_store_t const * store ) {
  return store->disk_max_shreds > 0UL;
}

#define FD_STORE_DISK_INSERT_ERR       (-1)
#define FD_STORE_DISK_INSERT_DUPLICATE ( 0)
#define FD_STORE_DISK_INSERT_SUCCESS   ( 1)

#define FD_STORE_DISK_QUERY_BUSY       (-2)
#define FD_STORE_DISK_QUERY_MISS       (-1)

struct fd_store_disk_stats {
  ulong shred_cnt;
  ulong file_shred_cnt;
  ulong insert_cnt;
  ulong duplicate_cnt;
  ulong write_bytes;
};
typedef struct fd_store_disk_stats fd_store_disk_stats_t;

/* Disk writes block and take priority.  Queries are try-only and return
   FD_STORE_DISK_QUERY_BUSY while a writer is pending or active. */

int
fd_store_disk_insert( fd_store_t       * store,
                      int                disk_fd,
                      fd_shred_t const * shred );

int
fd_store_disk_query( fd_store_t * store,
                     int          disk_fd,
                     ulong        slot,
                     uint         shred_idx,
                     uchar        out[ FD_SHRED_MAX_SZ ] );

/* Given a (slot, min_shred_idx), returns the highest shred the store
   knows of for that slot.  A shred below min_shred_idx is returned if
   it is marked as the last shred in its slot.

   Returns FD_STORE_DISK_QUERY_MISS when unavailable,
   FD_STORE_DISK_QUERY_BUSY on write contention, or the byte count. */
int
fd_store_disk_query_highest( fd_store_t * store,
                             int          disk_fd,
                             ulong        slot,
                             uint         min_shred_idx,
                             uchar        out[ FD_SHRED_MAX_SZ ] );

/* Stats follow the query contention policy and return 0 on success. */

int
fd_store_disk_stats_query( fd_store_t            * store,
                           fd_store_disk_stats_t * stats );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_store_fd_store_h */
