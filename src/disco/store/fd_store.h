#ifndef HEADER_fd_src_disco_store_fd_store_h
#define HEADER_fd_src_disco_store_fd_store_h

#include "../../disco/shred/fd_fec_set.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/fd_rwlock.h"
#include "../../flamenco/fd_flamenco_base.h"
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

/* Includes variable-length FECs in legacy backtest ledgers.  Sched's
   per-FEC buffer must accommodate every payload the store accepts. */
#define FD_STORE_MAX_FEC_DATA_SZ (63985UL)

/* Payload record: one per cache slot and one per disk slot.  The
   header holds the payload size of the first FD_FEC_SHRED_CNT data
   shreds; legacy FECs can have more data shreds than that, so the
   total payload size (data_sz) is kept in the store's FEC metadata
   instead.  The record is spilled and read back whole. */

struct fd_store_fec {
  ushort shred_sz[ FD_FEC_SHRED_CNT ]; /* payload size of each tracked data shred */
  uchar  payload[];                    /* fec_data_max bytes */
};
typedef struct fd_store_fec fd_store_fec_t;

#define FD_STORE_FEC_HDR_SZ (64UL)
FD_STATIC_ASSERT( __builtin_offsetof( fd_store_fec_t, payload )==FD_STORE_FEC_HDR_SZ, fd_store_fec_hdr_sz );

/* fd_store_fec_slot_sz returns the stride of a cache or disk slot
   holding a payload record (shred_sz header and up to fec_data_max
   payload bytes), or 0 on overflow.  Cache slot i is at
   cache_mem + i*fec_slot_sz; disk slot i is at file offset
   i*fec_slot_sz. */

FD_FN_CONST static inline ulong
fd_store_fec_slot_sz( ulong fec_data_max ) {
  ulong rounded;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( fec_data_max, FD_STORE_FEC_HDR_SZ+FD_STORE_PAYLOAD_PAGE_SZ-1UL, &rounded ) ) ) return 0UL;
  return rounded & ~(FD_STORE_PAYLOAD_PAGE_SZ-1UL);
}

#define FD_STORE_MAGIC (0xf17eda2ce75702efUL) /* firedancer store version 15 */

#define FD_STORE_SUCCESS          ( 0)
#define FD_STORE_ERR_DUP          (-1) /* committed key already in the FEC map */
#define FD_STORE_ERR_EXPIRED      (-2) /* slot is below the last published root */
#define FD_STORE_ERR_FEC_FULL     (-3) /* no free FEC metadata: fec_max exhausted */
#define FD_STORE_ERR_CACHE_FULL   (-4) /* no free payload cache slot and no spill disk */
#define FD_STORE_ERR_TOO_BIG      (-5) /* query_read: data_sz exceeds the caller's buffer */
#define FD_STORE_ERR_PENDING_DUP  (-6) /* key present, but insert has not committed */

/* Bounds of the packed 28-bit metadata and slot indices. */
#define FD_STORE_IDX_MAX (1UL<<28)

/* Insert handle: the FEC metadata index. */
typedef uint fd_store_insert_t;
#define FD_STORE_INSERT_NULL (UINT_MAX)

/* Query view: bits 0-31 FEC metadata index, 32-59 data index (cache or
   disk slot, fixed while pinned), 60 spilled, 61-63 zero.  Packed so
   the reader needs no store lookup.  FD_STORE_VIEW_NULL is never a
   valid view. */
typedef ulong fd_store_view_t;
#define FD_STORE_VIEW_NULL (ULONG_MAX)

FD_FN_CONST static inline fd_store_view_t
fd_store_view_pack( uint meta_idx, uint data_idx, int spilled ) {
  return (ulong)meta_idx | ((ulong)data_idx<<32) | ((ulong)!!spilled<<60);
}
FD_FN_CONST static inline uint fd_store_view_meta_idx( fd_store_view_t v ) { return (uint)v; }
FD_FN_CONST static inline uint fd_store_view_data_idx( fd_store_view_t v ) { return (uint)fd_ulong_extract( v, 32, 59 ); }
FD_FN_CONST static inline int  fd_store_view_spilled ( fd_store_view_t v ) { return (int)fd_ulong_extract_bit( v, 60 ); }

/* Shred ring keys are slot<<32 | shred_idx, so slot<2^32 and shred_idx
   <2^32.  The per-slot hint reuses the key with bit 31 as the valid
   flag, which further bounds shred_idx<2^31 (see FD_SHREDB_HINT_VALID). */

#define FD_SHREDB_KEY_SLOT_MAX  (1UL<<32)
#define FD_SHREDB_HINT_VALID    (1UL<<31)

FD_FN_CONST static inline ulong
fd_shredb_key_pack( ulong slot, uint shred_idx ) {
  return (slot << 32) | (ulong)shred_idx;
}

FD_FN_CONST static inline ulong
fd_shredb_key_slot( ulong key ) {
  return fd_ulong_extract( key, 32, 63 );
}

FD_FN_CONST static inline uint
fd_shredb_key_shred_idx( ulong key ) {
  return (uint)fd_ulong_extract( key, 0, 31 );
}

typedef __attribute__((aligned(4))) ulong fd_shredb_map_key_t;

FD_STATIC_ASSERT( sizeof(fd_shredb_map_key_t)==8UL, shredb_map_key_footprint );
FD_STATIC_ASSERT( alignof(fd_shredb_map_key_t)==4UL, shredb_map_key_align );

struct fd_shredb_root_key {
  uchar root[ FD_SHRED_MERKLE_NODE_SZ ];
  uchar off; /* 0 <= off < 32 */
};
typedef struct fd_shredb_root_key fd_shredb_root_key_t;

FD_STATIC_ASSERT( sizeof(fd_shredb_root_key_t)==21UL, shredb_root_key_footprint );

static inline fd_shredb_root_key_t
fd_shredb_root_key( uchar const * merkle_root,
                    uint          shred_idx ) {
  fd_shredb_root_key_t key;
  memcpy( key.root, merkle_root, FD_SHRED_MERKLE_NODE_SZ );
  key.off = (uchar)(shred_idx % FD_FEC_SHRED_CNT);
  return key;
}

/* One ring entry provides keys and chain links to both maps.  Its
   seven-byte tag and 21-byte root key leave no padding in 44 bytes.
   tag_hi extends the low 30 ticket bits in tag by 24 bits; the bottom
   two tag bits hold the cell state.  All fields use disk_lock. */
struct fd_shredb_ring_entry {
  uint                 tag;
  uchar                tag_hi[ 3 ];
  fd_shredb_root_key_t root_key;
  fd_shredb_map_key_t  key;
  uint                 slot_next;
  uint                 root_next;
};
typedef struct fd_shredb_ring_entry fd_shredb_ring_entry_t;
FD_STATIC_ASSERT( sizeof(fd_shredb_ring_entry_t)==44UL, shredb_ring_entry_footprint );

#define FD_SHREDB_TAG_SEQ_MASK ((1UL<<54)-1UL)

#define FD_SHREDB_CELL_INVALID    (0UL)
#define FD_SHREDB_CELL_WRITING    (1UL)
#define FD_SHREDB_CELL_READY      (2UL)
#define FD_SHREDB_CELL_STATE_MASK (3UL)

/* The slot and root maps are non-concurrent separately-chained hash maps
   (fd_map_chain) over the shared ring pool.  Each has its own bucket-head
   array and threads collisions through its corresponding next field.
   All access is serialized by the store's disk_lock. */

#define MAP_NAME   fd_shredb_slot_map
#define MAP_ELE_T  fd_shredb_ring_entry_t
#define MAP_KEY_T  fd_shredb_map_key_t
#define MAP_KEY    key
#define MAP_NEXT   slot_next
#define MAP_IDX_T  uint
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               fd_shredb_root_map
#define MAP_ELE_T              fd_shredb_ring_entry_t
#define MAP_KEY_T              fd_shredb_root_key_t
#define MAP_KEY                root_key
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0), (k1), sizeof(fd_shredb_root_key_t) ))
#define MAP_KEY_HASH(key,seed) fd_hash( (seed), (key), sizeof(fd_shredb_root_key_t) )
#define MAP_NEXT               root_next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct __attribute__((aligned(64))) fd_shredb_entry {
  ulong  tag;
  ulong  key;
  uchar  root[ FD_SHRED_MERKLE_NODE_SZ ]; /* merkle root prefix of the shred's FEC set */
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

/* The chain count estimator halves its input, so dividing by four
   targets max_shreds/8 buckets.  This reduces bucket memory at the
   expense of longer chains. */
FD_FN_CONST static inline ulong
fd_shredb_disk_chain_cnt( ulong max_shreds ) {
  return fd_shredb_slot_map_chain_cnt_est( max_shreds/4UL );
}

struct fd_store {
  ulong magic;
  ulong fec_max;
  ulong fec_data_max;
  ulong store_gaddr;
  ulong shred_tile_cnt;
  ulong max_live_slots;

  /* Sizing, immutable after new. */
  ulong fec_slot_sz;            /* fd_store_fec_slot_sz( fec_data_max ) */
  ulong cache_max;              /* payload cache slots, <= fec_max */
  ulong disk_max;               /* spill disk slots, == fec_max */
  ulong slot_ring_len;          /* pow2_up( max_live_slots ) */
  ulong payload_sz;             /* logical spill region size: disk_max*fec_slot_sz */
  ulong wire_off;               /* byte offset where the rserve wire region begins */
  ulong cache_free_low_water;   /* preevict starts below this */
  ulong cache_free_target;      /* preevict stops at this */

  /* Containers, private to fd_store.c */
  ulong fec_map_gaddr;
  ulong meta_gaddr;             /* fd_pool join, element 0 */
  ulong cache_gaddr;            /* fd_pool join, element 0 */
  ulong cache_lru_gaddr;
  ulong slot_ring_gaddr;
  ulong disk_free_gaddr;
  ulong cache_data_gaddr;

  /* FEC state.  lock is only used on the write side. */
  fd_rwlock_t     lock;
  ulong           min_root;     /* last published root, lock */
  fd_store_view_t pin_view;     /* the single outstanding pinned view; written
                                   under lock, only by replay */
  uint            disk_free_cnt;  /* lock */
  atomic_ulong    cache_parked; /* one bit per partition, set and cleared under lock */
  atomic_ulong    disk_bump;    /* disk slot high-water mark, written under lock */
  atomic_ulong    cache_free_cnt; /* mirrors the cache pool's free count */

  /* Gauges and counters, read lock-free by metrics.  One writer at a
     time (the lock holder; spill_read_* the pinning thread), so they
     are updated with a relaxed load and store. */
  atomic_ulong fec_live_cnt;
  atomic_ulong fec_live_peak;
  atomic_ulong disk_live_cnt;
  atomic_ulong spill_cnt;
  atomic_ulong spill_bytes;
  atomic_ulong spill_read_cnt;
  atomic_ulong spill_read_bytes;
  atomic_ulong spill_cancel_cnt;

  /* Arena used by shred tiles for assembly and recovery. */
  ulong        fec_set_cnt;
  ulong        fec_sets_gaddr;

  /* On-disk shred index. Lives in the wire region of the shared file
     at byte offset wire_off + ring_idx*sizeof(entry).  shred_map keys
     cells by (slot,idx), first version wins.  root_map keys every cell
     by (root,idx%32).  Both maps share the ring pool and disk_lock. */
  ulong        shred_map_gaddr; /* fd_shredb_slot_map over the ring pool */
  ulong        ring_pool_gaddr;
  ulong        root_map_gaddr;  /* fd_shredb_root_map over the ring pool */
  fd_rwlock_t  disk_lock;
  ulong        slot_hint_gaddr;
  ulong        disk_max_shreds;
  ulong        disk_max_slots;
  ulong        max_shreds_per_block; /* bounds shred idxs, <=FD_SHREDB_HINT_VALID */
  atomic_ulong disk_reservation_head;
  atomic_ulong disk_cnt;
  atomic_ulong disk_insert_cnt;
  atomic_ulong disk_write_bytes;
};
typedef struct fd_store fd_store_t;

FD_PROTOTYPES_BEGIN

/* Store maps (merkle root, slot) to a FEC payload, plus an on-disk
   shred ring.

   FECs are keyed by the first FD_SHRED_MERKLE_NODE_SZ bytes of the
   merkle root, the FEC identity repair and the disk shred index use.
   Each FEC has 40 bytes of resident metadata; its payload record lives
   in a RAM cache slot or, once spilled by LRU, in a disk slot of the
   backing file.  One rwlock (write side only) protects all FEC state.

   Shred tiles (and backtest) insert with begin / fill / commit, then
   notify replay.  Replay is the only reader: it pins one FEC at a time
   with query_acquire, reads it (possibly via sched, on replay's
   thread) without the lock, and releases it.  Replay also publishes
   roots; publish frees every FEC below the root without waiting on
   I/O, and must not be called while a view is pinned.

   The backing file layout is:

    [ sparse spill slots (fec_slot_sz*disk_max) ][ shred ring ]

    wire_off is the fixed start of the shred ring.  Spill slots that
    were never used do not consume disk blocks.  Freed slots are reused
    before new ones.

    Shred-ring writers reserve cells and mark only the target cell WRITING
    while its pwrite is in progress. */

FD_FN_CONST static inline ulong
fd_store_align( void ) {
  return FD_STORE_PAYLOAD_PAGE_SZ;
}

/* fd_store_footprint returns the footprint of a store, or 0 if the
   arguments are invalid.  fec_max bounds live FECs (<=2^28);
   fec_data_max bounds each payload (<=FD_STORE_MAX_FEC_DATA_SZ).
   shred_cache_bytes sizes the RAM payload cache; 0 sizes it for
   fec_max payloads.  shred_tile_cnt (<=64) is the number of insert
   partitions.  max_live_slots sizes the slot index used by publish. */

ulong
fd_store_footprint( ulong fec_max,
                    ulong fec_data_max,
                    ulong shred_storage_gib,
                    ulong shred_cache_bytes,
                    ulong fec_set_cnt,
                    ulong shred_tile_cnt,
                    ulong max_live_slots );

/* Formats a footprint-sized, fd_store_align()-aligned region.  fec_max
   bounds live FECs; fec_data_max bounds each payload.  The remaining size
   arguments configure the shred ring, RAM cache, and shred-tile arena.
   max_shreds_per_block bounds shred idxs in the shred ring, in
   [1,FD_SHREDB_HINT_VALID].  shred_tile_cnt and max_live_slots must
   match the footprint.  Does not create the backing file. */

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
              ulong        max_live_slots );

fd_store_t * fd_store_join ( void * shstore );
void *       fd_store_leave( fd_store_t const * store );
void *       fd_store_delete( void * shstore );

/* Creates and sizes the Store backing file */

int
fd_store_file_create( char const * path,
                      ulong        wire_off,
                      ulong        disk_max_shreds );


FD_FN_PURE static inline fd_wksp_t *
fd_store_wksp( fd_store_t const * store ) {
  return (fd_wksp_t *)( ( (ulong)store ) - store->store_gaddr );
}

/* Optional FEC-set arena, partitioned among shred tile kind_ids. */

FD_FN_PURE static inline fd_fec_set_t *
fd_store_fec_sets( fd_store_t const * store ) {
  return store->fec_set_cnt ? fd_wksp_laddr_fast( fd_store_wksp( store ), store->fec_sets_gaddr ) : NULL;
}

struct fd_store_lookup_stats {
  ulong probe_cnt; /* FEC map chain hops */
};
typedef struct fd_store_lookup_stats fd_store_lookup_stats_t;

struct fd_store_spill_stats {
  ulong write_ticks;   /* total I/O time, including cancelled/expired writes */
  ulong spilled_cnt;   /* live FECs actually moved to disk */
  ulong spilled_bytes;
};
typedef struct fd_store_spill_stats fd_store_spill_stats_t;

struct fd_store_insert_stats {
  fd_store_lookup_stats_t lookup; /* duplicate check */
  fd_store_spill_stats_t  spill;  /* synchronous fallback spills */
  ulong                   park_cnt;
  ulong                   park_ticks;
};
typedef struct fd_store_insert_stats fd_store_insert_stats_t;

struct fd_store_publish_stats {
  ulong removed_cnt; /* FECs freed, or left for an in-flight spill to free */
};
typedef struct fd_store_publish_stats fd_store_publish_stats_t;

struct fd_store_fec_cache_stats {
  ulong free_cnt;
  ulong max;
  ulong target;
  ulong low_water;
};
typedef struct fd_store_fec_cache_stats fd_store_fec_cache_stats_t;

/* fd_store_insert_begin starts inserting the FEC with merkle_root in
   slot from partition part (< shred_tile_cnt, one thread per
   partition).  On success, *out is the insert handle, which owns a
   cache slot whose payload record the caller fills through
   fd_store_insert_data and then publishes with fd_store_insert_commit.
   The record header is zeroed.

   If no cache slot is free, spills the LRU payload to disk_fd
   (synchronously, without the lock held), or waits for a cache slot if
   none can be spilled.  Without a disk (disk_fd<0), returns
   ERR_CACHE_FULL instead.

   Returns SUCCESS, ERR_EXPIRED (slot below the published root),
   ERR_DUP (committed key, including FECs being torn down),
   ERR_PENDING_DUP (key still being inserted), ERR_FEC_FULL or
   ERR_CACHE_FULL.  On error nothing is held and *out is
   FD_STORE_INSERT_NULL.  insert_stats is optional. */

int
fd_store_insert_begin( fd_store_t *              store,
                       int                       disk_fd,
                       fd_hash_t const *         merkle_root,
                       ulong                     slot,
                       ulong                     part,
                       fd_store_insert_stats_t * insert_stats,
                       fd_store_insert_t *       out );

/* fd_store_insert_data returns the payload record of an insert handle.
   Valid until commit. */

fd_store_fec_t *
fd_store_insert_data( fd_store_t *      store,
                      fd_store_insert_t ins );

/* fd_store_insert_commit makes the FEC queryable.  data_sz is the
   total payload bytes copied (including untracked overflow shreds of
   legacy FECs), <= fec_data_max and >= the sum of the tracked shred
   sizes.  Fence non-temporal stores before committing.  Returns
   SUCCESS, or ERR_EXPIRED if a publish since begin made the slot
   expire, in which case the FEC is discarded.  The handle is invalid
   on return. */

int
fd_store_insert_commit( fd_store_t *      store,
                        fd_store_insert_t ins,
                        ulong             data_sz );

/* fd_store_query_acquire looks up merkle_root and pins it, returning
   its view, or FD_STORE_VIEW_NULL on a miss (absent, not committed, or
   below the published root).  Replay only: at most one view may be
   pinned at a time, and none across fd_store_publish.  lookup_stats
   is optional. */

fd_store_view_t
fd_store_query_acquire( fd_store_t *              store,
                        fd_hash_t const *         merkle_root,
                        fd_store_lookup_stats_t * lookup_stats );

/* fd_store_query_read copies the pinned FEC's tracked shred sizes to
   shred_sz and its payload to payload, reading it from disk_fd if
   spilled.  Takes no lock; must run on the pinning thread.  Returns
   data_sz, or ERR_TOO_BIG without touching payload or shred_sz if
   data_sz>payload_cap.  *opt_spilled reports whether it read from
   disk.  Call at most once per view. */

long
fd_store_query_read( fd_store_t *    store,
                     int             disk_fd,
                     fd_store_view_t view,
                     uchar *         payload,
                     ulong           payload_cap,
                     ushort          shred_sz[ FD_FEC_SHRED_CNT ],
                     int *           opt_spilled );

/* fd_store_query_data_sz returns the pinned FEC's total payload size.
   Takes no lock; must run on the pinning thread. */

ulong
fd_store_query_data_sz( fd_store_t const * store,
                        fd_store_view_t    view );

/* fd_store_query_release unpins view. */

void
fd_store_query_release( fd_store_t *    store,
                        fd_store_view_t view );

/* fd_store_publish frees every FEC of a slot below root.  FECs being
   spilled are made invisible and freed by the spiller.  On return no
   FEC below root is queryable.  A no-op if root is not above the last
   published root.  Must not be called with a view pinned.
   publish_stats is optional. */

void
fd_store_publish( fd_store_t *               store,
                  ulong                      root,
                  fd_store_publish_stats_t * publish_stats );

/* fd_store_preevict spills at most one LRU payload while the free
   cache slot count is below the refill target.  *active is the
   caller's hysteresis state (initially 0): spilling starts below the
   low water mark and stops at the target.  Returns 1 if a payload was
   spilled.  spill_stats is optional. */

int
fd_store_preevict( fd_store_t *             store,
                   int                      disk_fd,
                   int *                    active,
                   fd_store_spill_stats_t * spill_stats );

void
fd_store_fec_cache_stats_query( fd_store_t const *           store,
                                fd_store_fec_cache_stats_t * stats );


FD_FN_PURE static inline int
fd_store_has_disk( fd_store_t const * store ) {
  return store->disk_max_shreds > 0UL;
}

#define FD_STORE_DISK_INSERT_ERR       (-1)
#define FD_STORE_DISK_INSERT_DUP       ( 0)
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

/* Persists one (slot,idx) shred, where idx is below max_shreds_per_block,
   whose FEC set has merkle root merkle_root (only the first
   FD_SHRED_MERKLE_NODE_SZ bytes are used).  Every version is indexed by
   (root,idx%FD_FEC_SHRED_CNT) and inserting a key already held by a
   READY cell is a no-op, so a different idx that aliases the same
   offset is dropped too.  The first version stored for a (slot,idx) is
   also indexed by (slot,idx).  Returns FD_STORE_DISK_INSERT_SUCCESS if
   written, FD_STORE_DISK_INSERT_DUP if already stored or dropped, or
   FD_STORE_DISK_INSERT_ERR. */

int
fd_store_disk_insert( fd_store_t       * store,
                      int                disk_fd,
                      fd_shred_t const * shred,
                      fd_hash_t const  * merkle_root );

/* Copies (slot,shred_idx) to out, where shred_idx is below
   max_shreds_per_block.  Returns its positive byte count, MISS, or
   retryable BUSY.  Only finds the first version stored. */

int
fd_store_disk_query( fd_store_t const * store,
                     int                disk_fd,
                     ulong              slot,
                     uint               shred_idx,
                     uchar              out[ FD_SHRED_MAX_SZ ] );

/* fd_store_disk_query_root copies the shred at shred_idx of the FEC set
   whose merkle root starts with the FD_SHRED_MERKLE_NODE_SZ bytes at
   merkle_root to out.  Finds any stored version.  Returns its positive
   byte count, MISS, or retryable BUSY. */

int
fd_store_disk_query_root( fd_store_t const * store,
                          int                disk_fd,
                          uchar const *      merkle_root,
                          uint               shred_idx,
                          uchar              out[ FD_SHRED_MAX_SZ ] );

/* Returns 0 if a query for (slot,shred_idx), or for the highest shred
   of slot when shred_idx is UINT_MAX, would certainly miss. */

int
fd_store_disk_probe( fd_store_t const * store,
                     ulong              slot,
                     uint               shred_idx );

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
