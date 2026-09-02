#ifndef HEADER_fd_src_disco_store_fd_store_h
#define HEADER_fd_src_disco_store_fd_store_h

#include "../../disco/shred/fd_fec_set.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/fd_rwlock.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/fd_hash32.h"
#include "../../util/hist/fd_histf.h"
#include "../../util/shmem/fd_shmem.h"
#include "../../util/tile/fd_tile.h"

#define FD_STORE_ALIGN (128UL)

/* The launcher creates the Store backing file before starting any tile
   and passes these descriptors through exec.  Keep them adjacent to the
   accdb descriptor range, but distinct from it. */
#define FD_STORE_FD_RW (123459)
#define FD_STORE_FD_RO (123458)

/* Spill and cache slots are page aligned. */
#define FD_STORE_PAYLOAD_PAGE_SZ (FD_SHMEM_NORMAL_PAGE_SZ)

FD_FN_CONST static inline ulong
fd_store_payload_slot_sz( ulong fec_data_max ) {
  ulong rounded;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( fec_data_max, FD_STORE_PAYLOAD_PAGE_SZ-1UL, &rounded ) ) ) return 0UL;
  return rounded & ~(FD_STORE_PAYLOAD_PAGE_SZ-1UL);
}
#define FD_STORE_MAGIC (0xf17eda2ce75702e9UL) /* firedancer store version 9 */

#define FD_STORE_FEC_DATA_EMPTY       (0U)
#define FD_STORE_FEC_DATA_RAM_WRITING (1U)
#define FD_STORE_FEC_DATA_RAM_READY   (2U)
#define FD_STORE_FEC_DATA_DISK        (3U)
#define FD_STORE_FEC_DATA_CONSUMED    (4U)
#define FD_STORE_FEC_DATA_SPILLING    (5U)

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
  ulong        key;
  atomic_ulong tag;
  uint         next;
};
typedef struct fd_shredb_shred_entry fd_shredb_shred_entry_t;

#define MAP_NAME   fd_shredb_shred_map
#define MAP_ELE_T  fd_shredb_shred_entry_t
#define MAP_KEY_T  ulong
#define MAP_KEY    key
#define MAP_IDX_T  uint
#define MAP_NEXT   next
#include "../../util/tmpl/fd_map_chain_para.c"

#define FD_SHREDB_CELL_INVALID    (0UL)
#define FD_SHREDB_CELL_WRITING    (1UL)
#define FD_SHREDB_CELL_READY      (2UL)
#define FD_SHREDB_CELL_STATE_MASK (3UL)

struct __attribute__((aligned(64))) fd_shredb_entry {
  ulong  tag;
  ulong  key;
  ushort shred_sz;
  uchar  shred[ FD_SHRED_MAX_SZ ];
};
typedef struct fd_shredb_entry fd_shredb_entry_t;

FD_STATIC_ASSERT( sizeof(fd_shredb_entry_t)==1280UL, shred_disk_entry_footprint );

#define FD_SHREDB_MAX_SIZE_GIB (((ulong)UINT_MAX*sizeof(fd_shredb_entry_t))/(1UL<<30))

FD_FN_CONST static inline ulong
fd_shredb_max_shreds( ulong gib ) {
  if( FD_UNLIKELY( !gib || gib>(ULONG_MAX>>30) ) ) return 0UL;
  return (gib<<30) / sizeof(fd_shredb_entry_t);
}

FD_FN_CONST static inline ulong
fd_shredb_max_slots( ulong gib ) {
  return fd_ulong_max( !!gib, fd_shredb_max_shreds( gib )/FD_FEC_SHRED_CNT );
}

struct __attribute__((aligned(FD_STORE_ALIGN))) fd_store_fec {
  fd_hash_t key;
  ulong     next;                            /* managed by fd_pool / fd_map_chain_para */
  uint      shred_offs[ FD_FEC_SHRED_CNT ];  /* shred_offs[i] = cumulative size of data shreds [0..i] */
  ulong     data_sz;                         /* sz of the FEC set payload, <= fec_data_max */
  ulong     data_off;                        /* RAM cache offset when RAM_*, spill-file offset when DISK */
  uint      cache_prev;                      /* RAM_READY LRU links, UINT_MAX when unlinked */
  uint      cache_next;
  uint      data_pin_cnt;                    /* active payload views */
  uint      data_state;                      /* FD_STORE_FEC_DATA_* */
  uint      data_consume_pending;
};
typedef struct fd_store_fec fd_store_fec_t;


#define POOL_NAME  fd_store_pool
#define POOL_ELE_T fd_store_fec_t
#include "../../util/tmpl/fd_pool_para.c"


#define MAP_NAME               fd_store_map
#define MAP_ELE_T              fd_store_fec_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) fd_hash32( (key)->uc, (seed) )
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

  /* RAM FEC payload cache.  cache_slot_cnt is usually much smaller than
     fec_max.  cache_free is a stack of slot indices protected by
     cache_lock. */
  ulong        cache_slot_cnt;
  ulong        cache_data_gaddr;
  ulong        cache_free_gaddr;
  ulong        cache_free_cnt;
  ulong        cache_free_target;
  ulong        cache_free_low_water;
  uint         cache_preevict_active;
  uint         cache_lru_head;
  uint         cache_lru_tail;
  ulong        cache_pinned_cnt;
  ulong        spill_free_gaddr;
  ulong        spill_free_cnt;
  ulong        spill_reclaim_gaddr;
  ulong        spill_reclaim_cnt;
  ulong        spill_reclaiming_cnt;
  ulong        spill_reuse_cnt;
  ulong        spill_slot_cnt;
  atomic_ulong spill_live_cnt;
  atomic_ulong spill_allocated_cnt;
  atomic_ulong fec_spill_cnt;
  atomic_ulong fec_spill_bytes;
  atomic_ulong fec_spill_read_cnt;
  atomic_ulong fec_spill_read_bytes;
  fd_rwlock_t cache_lock;

  /* Spilled payloads are read into this buffer under spill_read_lock. */
  ulong        spill_read_data_gaddr;
  fd_rwlock_t  spill_read_lock;

  /* Reassembly removal returns metadata synchronously, matching the
     original Store capacity contract. */
  fd_rwlock_t  fec_lock;

  /* Arena used by shred tiles for assembly and recovery. */
  ulong        fec_set_cnt;
  ulong        fec_sets_gaddr;

  /* On-disk shred index. Lives in the wire region of the shared file
     at byte offset wire_off + ring_idx*sizeof(entry). */
  ulong        shred_map_gaddr;
  ulong        shred_pool_gaddr;
  ulong        slot_hint_gaddr;
  ulong        disk_max_shreds;
  ulong        disk_max_slots;
  atomic_ulong disk_reservation_head;
  atomic_ulong disk_cnt;
  atomic_ulong disk_insert_cnt;
  atomic_ulong disk_write_bytes;
};
typedef struct fd_store fd_store_t;

FD_PROTOTYPES_BEGIN

/* Store contains a Merkle-root keyed FEC map, a payload cache, and an
   on-disk shred ring.

   Shred inserts a FEC, fills its payload, publishes it, and then notifies
   Replay.  The corresponding reassembly node owns the FEC until removal.
   Removal waits for payload users, then returns the payload and metadata
   synchronously.  fec_max therefore covers reassembly and complete-FEC
   messages in flight.

   Payloads enter the RAM cache and spill by LRU to page-sized file slots.
   Freed slots are immediately eligible for reuse.  The file layout is:

    [ sparse spill slots (payload_slot_sz*fec_max) ][ shred ring ]

    wire_off is the fixed start of the shred ring.  Unused spill slots
    do not consume disk blocks.

    Shred-ring writers reserve cells and mark only the target cell WRITING
    while its pwrite is in progress. */

FD_FN_CONST static inline ulong
fd_store_align( void ) {
  return FD_STORE_PAYLOAD_PAGE_SZ;
}

static inline int
fd_store_layout_append( ulong * l,
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

FD_FN_CONST static inline ulong
fd_store_footprint( ulong fec_max,
                    ulong fec_data_max,
                    ulong shred_storage_gib,
                    ulong shred_cache_bytes,
                    ulong fec_set_cnt ) {
  if( FD_UNLIKELY( !fec_max || !fec_data_max || fec_max>UINT_MAX || shred_storage_gib>FD_SHREDB_MAX_SIZE_GIB ) ) return 0UL;
  ulong chain_cnt = fd_store_map_chain_cnt_est( fec_max );
  ulong payload_slot_sz = fd_store_payload_slot_sz( fec_data_max );
  if( FD_UNLIKELY( !payload_slot_sz ) ) return 0UL;
  ulong cache_slot_cnt = shred_cache_bytes
                       ? fd_ulong_min( fec_max, fd_ulong_max( 1UL, shred_cache_bytes / payload_slot_sz ) )
                       : fec_max;
  ulong l = FD_LAYOUT_INIT;
  if( FD_UNLIKELY( fd_store_layout_append( &l, fd_store_align(),        1UL,            sizeof(fd_store_t) ) ||
                   fd_store_layout_append( &l, fd_store_map_align(),     1UL,            fd_store_map_footprint( chain_cnt ) ) ||
                   fd_store_layout_append( &l, fd_store_pool_align(),    1UL,            fd_store_pool_footprint() ) ||
                   fd_store_layout_append( &l, alignof(fd_store_fec_t),  fec_max,         sizeof(fd_store_fec_t) ) ||
                   fd_store_layout_append( &l, FD_STORE_PAYLOAD_PAGE_SZ, cache_slot_cnt, payload_slot_sz ) ||
                   fd_store_layout_append( &l, alignof(ulong),           cache_slot_cnt, sizeof(ulong) ) ||
                   fd_store_layout_append( &l, alignof(uint),            fec_max,         sizeof(uint) ) ||
                   fd_store_layout_append( &l, alignof(uint),            fec_max,         sizeof(uint) ) ||
                   fd_store_layout_append( &l, FD_STORE_PAYLOAD_PAGE_SZ, 1UL,             payload_slot_sz ) ) ) return 0UL;
  if( FD_UNLIKELY( fec_set_cnt && fd_store_layout_append( &l, alignof(fd_fec_set_t), fec_set_cnt, sizeof(fd_fec_set_t) ) ) ) return 0UL;
  if( shred_storage_gib ) {
    ulong max_shreds   = fd_shredb_max_shreds( shred_storage_gib );
    ulong max_slots    = fd_shredb_max_slots( shred_storage_gib );
    ulong disk_chain_cnt = fd_shredb_shred_map_chain_cnt_est( max_shreds );
    if( FD_UNLIKELY( !max_shreds || !max_slots ||
                     fd_store_layout_append( &l, fd_shredb_shred_map_align(),     1UL,         fd_shredb_shred_map_footprint( disk_chain_cnt ) ) ||
                     fd_store_layout_append( &l, alignof(fd_shredb_shred_entry_t), max_shreds, sizeof(fd_shredb_shred_entry_t) ) ||
                     fd_store_layout_append( &l, alignof(atomic_ulong),            max_slots,   sizeof(atomic_ulong) ) ) ) return 0UL;
  }
  if( FD_UNLIKELY( fd_store_layout_append( &l, fd_store_align(), 0UL, 1UL ) ) ) return 0UL;
  return l;
}

/* Formats a footprint-sized, fd_store_align()-aligned region.  fec_max
   bounds live FECs; fec_data_max bounds each payload.  The remaining size
   arguments configure the shred ring, RAM cache, and shred-tile arena.
   Does not create the backing file. */

void *
fd_store_new( void       * shmem,
              ulong        fec_max,
              ulong        fec_data_max,
              ulong        shred_storage_gib,
              ulong        shred_cache_bytes,
              ulong        fec_set_cnt,
              ulong        seed );

fd_store_t * fd_store_join ( void * shstore );
void *       fd_store_leave( fd_store_t const * store );
void *       fd_store_delete( void * shstore );

/* Creates, truncates, and sizes the Store backing file. */

int fd_store_file_create( char const * path,
                          ulong        wire_off,
                          ulong        disk_max_shreds );

/* Reclaims one spill slot.  Returns non-zero if there was work. */

int fd_store_disk_maintain( fd_store_t * store, int disk_fd );


FD_FN_PURE static inline fd_wksp_t *
fd_store_wksp( fd_store_t const * store ) {
  return (fd_wksp_t *)( ( (ulong)store ) - store->store_gaddr );
}

/* Optional FEC-set arena, partitioned among shred tile kind_ids. */

FD_FN_PURE static inline fd_fec_set_t *
fd_store_fec_sets( fd_store_t const * store ) {
  return store->fec_set_cnt ? fd_wksp_laddr_fast( fd_store_wksp( store ), store->fec_sets_gaddr ) : NULL;
}

/* Joins the FEC map using caller-owned local scratch. */

static inline fd_store_map_t *
fd_store_map_ljoin( fd_store_t const * store,
                    fd_store_map_t *   map ) {
  fd_wksp_t * wksp = fd_store_wksp( store );
  return fd_store_map_join( map,
                            fd_wksp_laddr_fast( wksp, store->map_gaddr ),
                            fd_wksp_laddr_fast( wksp, store->pool_ele_gaddr ),
                            store->fec_max );
}

/* Writable RAM buffer between data_acquire and data_publish. */

FD_FN_PURE static inline uchar *
fd_store_fec_data( fd_store_t const *     store,
                   fd_store_fec_t const * fec ) {
  return (uchar *)( (ulong)store - store->store_gaddr + store->cache_data_gaddr + fec->data_off );
}

struct fd_store_fec_data_view {
  uchar          * data;
  fd_store_fec_t * fec;
  uint             flags;
};
typedef struct fd_store_fec_data_view fd_store_fec_data_view_t;

struct fd_store_fec_spill_stats {
  ulong write_cnt;
  ulong write_bytes;
  ulong write_ticks;
};
typedef struct fd_store_fec_spill_stats fd_store_fec_spill_stats_t;

struct fd_store_fec_cache_stats {
  ulong free_cnt;
  ulong max;
  ulong target;
  ulong low_water;
};
typedef struct fd_store_fec_cache_stats fd_store_fec_cache_stats_t;

/* Reserves a payload.  Fill it, data_sz, and shred_offs, then publish.
   The _ex form also reports synchronous fallback spills. */

uchar *
fd_store_fec_data_acquire( fd_store_t     * store,
                           int              disk_fd,
                           fd_store_fec_t * fec );

uchar *
fd_store_fec_data_acquire_ex( fd_store_t                  * store,
                              int                           disk_fd,
                              fd_store_fec_t              * fec,
                              fd_store_fec_spill_stats_t * spill );

void
fd_store_fec_data_publish( fd_store_t     * store,
                           fd_store_fec_t * fec );

/* Spills at most one LRU payload while refilling the free reserve. */

int
fd_store_fec_data_preevict( fd_store_t                  * store,
                            int                           disk_fd,
                            fd_store_fec_spill_stats_t * spill );

void
fd_store_fec_cache_stats_query( fd_store_t                 * store,
                                fd_store_fec_cache_stats_t * stats );

/* Pins a published payload.  Returns 0 on success and -1 with an empty
   view on failure.  The store has one spill-read buffer, so a second
   spilled view returns -1 while the first is active.  RAM views can
   coexist.  Release every successful view; remove waits for pins. */

int
fd_store_fec_data_view( fd_store_t *               store,
                        int                        disk_fd,
                        fd_store_fec_t *           fec,
                        fd_store_fec_data_view_t * view );

void
fd_store_fec_data_view_release( fd_store_t *               store,
                                fd_store_fec_data_view_t * view );

/* Atomically inserts merkle_root.  Returns FD_MAP_SUCCESS with the new
   FEC, or FD_MAP_ERR_KEY with *fec==NULL if present.  Pool exhaustion is
   a topology invariant violation. */

int
fd_store_insert( fd_store_t *       store,
                 fd_store_map_t *   map,
                 fd_hash_t const *  merkle_root,
                 fd_store_fec_t **  fec );

/* Lockless lookup; returns NULL if absent.  The returned pointer is
   borrowed.  Retain the corresponding reassembly node or otherwise
   exclude remove while using it. */

fd_store_fec_t *
fd_store_query( fd_store_map_t *  map,
                fd_hash_t const * merkle_root );

/* Removes merkle_root after active views and spill I/O finish.  Returns
   its payload and metadata before returning.  Returns 1 if found and 0
   otherwise. */

int
fd_store_remove( fd_store_t *      store,
                 fd_store_map_t *  map,
                 fd_hash_t const * merkle_root );


FD_FN_PURE static inline int
fd_store_has_disk( fd_store_t const * store ) {
  return store->disk_max_shreds > 0UL;
}

#define FD_STORE_DISK_INSERT_ERR       (-1)
#define FD_STORE_DISK_INSERT_SUCCESS   ( 1)

#define FD_STORE_DISK_QUERY_BUSY       (-2)
#define FD_STORE_DISK_QUERY_MISS       (-1)
#define FD_STORE_DISK_QUERY_SCAN_LIMIT  (-4)

struct fd_store_disk_stats {
  ulong shred_cnt;
  ulong current_bytes;
  ulong allocated_bytes;
  ulong insert_cnt;
  ulong write_bytes;
};
typedef struct fd_store_disk_stats fd_store_disk_stats_t;

/* Persists one (slot,idx) shred, where idx is below FD_SHRED_BLK_MAX.
   The caller guarantees that the shred has not previously been inserted.
   Returns FD_STORE_DISK_INSERT_SUCCESS or FD_STORE_DISK_INSERT_ERR. */

int
fd_store_disk_insert( fd_store_t       * store,
                      int                disk_fd,
                      fd_shred_t const * shred );

/* Copies (slot,shred_idx) to out, where shred_idx is below
   FD_SHRED_BLK_MAX.  Returns its positive byte count, MISS, or retryable
   BUSY. */

int
fd_store_disk_query( fd_store_t const * store,
                     int                disk_fd,
                     ulong              slot,
                     uint               shred_idx,
                     uchar              out[ FD_SHRED_MAX_SZ ] );

/* Copies the cached highest stored shred in slot to out.  A shred below
   min_shred_idx is returned only if it completes the slot.  The compact
   hint is conservative and never lowered: a collision can keep returning
   BUSY and a stale upper bound can keep returning SCAN_LIMIT instead of
   risking a lower, incorrect answer.  Exact queries are unaffected.
   Otherwise returns a positive byte count or MISS. */
int
fd_store_disk_query_highest( fd_store_t const * store,
                             int                disk_fd,
                             ulong              slot,
                             uint               min_shred_idx,
                             uchar              out[ FD_SHRED_MAX_SZ ] );

/* Takes an approximate telemetry snapshot.  Returns 0 or MISS. */

int
fd_store_disk_stats_query( fd_store_t const *      store,
                           fd_store_disk_stats_t * stats );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_store_fd_store_h */
