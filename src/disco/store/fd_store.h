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

/* The launcher creates the Store backing file before starting any tile
   and passes these descriptors through exec.  Keep them adjacent to the
   accdb descriptor range, but distinct from it. */
#define FD_STORE_FD_RW (123459)
#define FD_STORE_FD_RO (123458)

/* Spill and cache slots are page aligned.  Each slot is
   [ ushort shred_sz[FD_FEC_SHRED_CNT] ][ payload ]. */
#define FD_STORE_PAYLOAD_PAGE_SZ (FD_SHMEM_NORMAL_PAGE_SZ)
#define FD_STORE_PAYLOAD_HDR_SZ  (FD_FEC_SHRED_CNT*sizeof(ushort))

FD_FN_CONST static inline ulong
fd_store_payload_slot_sz( ulong fec_data_max ) {
  ulong rounded;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( fec_data_max, FD_STORE_PAYLOAD_HDR_SZ+FD_STORE_PAYLOAD_PAGE_SZ-1UL, &rounded ) ) ) return 0UL;
  return rounded & ~(FD_STORE_PAYLOAD_PAGE_SZ-1UL);
}
#define FD_STORE_MAGIC (0xf17eda2ce75702f1UL) /* firedancer store version 17 */

#define FD_STORE_FEC_DATA_EMPTY       (0U)
#define FD_STORE_FEC_DATA_RAM_WRITING (1U)
#define FD_STORE_FEC_DATA_RAM_READY   (2U)
#define FD_STORE_FEC_DATA_DISK        (3U)
#define FD_STORE_FEC_DATA_CONSUMED    (4U)
#define FD_STORE_FEC_DATA_SPILLING    (5U)

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

/* Versions of a (slot,idx) the slot map can't serve are found through
   an on-disk linear-probing table of (fp,ring_idx) records placed after
   the shred ring: later versions by a seeded hash of (slot,root
   prefix,idx), and first versions whose map key an alias holds by a
   seeded hash of (slot,idx).  A cell has at most one record.  Records of another gen (an earlier
   boot) are empty; the table has more than 2x as many records as ring
   cells, so even a gen collision with a full earlier boot never fills
   it. */

static inline ulong
fd_shredb_root_fp( ulong         seed,
                   ulong         slot,
                   uchar const * merkle_root,
                   uint          shred_idx ) {
  uchar buf[ FD_SHRED_MERKLE_NODE_SZ+sizeof(uint)+sizeof(ulong) ];
  memcpy( buf,                                      merkle_root, FD_SHRED_MERKLE_NODE_SZ );
  memcpy( buf+FD_SHRED_MERKLE_NODE_SZ,              &shred_idx,  sizeof(uint)            );
  memcpy( buf+FD_SHRED_MERKLE_NODE_SZ+sizeof(uint), &slot,       sizeof(ulong)           );
  return fd_hash( seed, buf, sizeof(buf) );
}

struct fd_shredb_tbl_rec {
  ulong fp;
  uint  ring_idx;
  uint  gen;
};
typedef struct fd_shredb_tbl_rec fd_shredb_tbl_rec_t;

FD_STATIC_ASSERT( sizeof(fd_shredb_tbl_rec_t)==16UL, shredb_tbl_rec_footprint );

FD_FN_CONST static inline ulong
fd_shredb_tbl_rec_cnt( ulong max_shreds ) {
  return max_shreds ? fd_ulong_pow2_up( 2UL*max_shreds+1UL ) : 0UL;
}

/* Cell kinds, kept in the on-disk entry tag above bit 32 */
#define FD_SHREDB_KIND_FIRST    (0) /* linked in the slot map while live */
#define FD_SHREDB_KIND_NONFIRST (1) /* later version, has a table record */
#define FD_SHREDB_KIND_ALIAS    (2) /* first version an alias keeps out of the slot map, has a table record */

/* One ring entry per cell, its 2-bit state packed 32 per ulong
   beside the pool.  key is (slot<<key_idx_bits | idx) truncated to 32
   bits, so slots 2^(32-key_idx_bits) apart alias; reads check the full
   key on disk.  A READY cell has a record iff the slot map does not
   link it.  All fields and states use disk_lock. */
struct fd_shredb_ring_entry {
  uint key;
  uint slot_next;
};
typedef struct fd_shredb_ring_entry fd_shredb_ring_entry_t;
FD_STATIC_ASSERT( sizeof(fd_shredb_ring_entry_t)==8UL, shredb_ring_entry_footprint );

FD_FN_CONST static inline ulong
fd_shredb_state_word_cnt( ulong max_shreds ) {
  return (max_shreds+31UL)/32UL;
}

#define FD_SHREDB_CELL_INVALID    (0UL)
#define FD_SHREDB_CELL_WRITING    (1UL)
#define FD_SHREDB_CELL_READY      (2UL)
#define FD_SHREDB_CELL_STATE_MASK (3UL)

/* The slot map is a non-concurrent separately-chained hash map
   (fd_map_chain) over the ring pool, serialized by the store's
   disk_lock. */

#define MAP_NAME   fd_shredb_slot_map
#define MAP_ELE_T  fd_shredb_ring_entry_t
#define MAP_KEY_T  uint
#define MAP_KEY    key
#define MAP_NEXT   slot_next
#define MAP_IDX_T  uint
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

/* The chain count estimator halves its input, so dividing by eight
   targets max_shreds/16 buckets.  This reduces bucket memory at the
   expense of longer chains. */
FD_FN_CONST static inline ulong
fd_shredb_disk_chain_cnt( ulong max_shreds ) {
  return fd_shredb_slot_map_chain_cnt_est( max_shreds/8UL );
}

struct fd_store_fec {
  fd_mr20_t key;                            /* merkle root prefix */
  uint      data_idx;                       /* RAM cache slot when RAM_*, spill-file slot when DISK */
  uint      next;                           /* managed by fd_pool / fd_map_chain_para */
  uint      data_sz;                        /* sz of the FEC set payload, <= fec_data_max */
  uint      slot;                           /* slot_to_fecs key, raised to the last published root */
  uint      slot_next;                      /* managed by slot_to_fecs */
  ushort    data_pin_cnt;                   /* active payload views */
  uchar     data_state;                     /* FD_STORE_FEC_DATA_* */
  uchar     data_consume_pending;
};
typedef struct fd_store_fec fd_store_fec_t;

FD_STATIC_ASSERT( sizeof(fd_store_fec_t)==44UL, fd_store_fec_footprint );

/* RAM_READY LRU links, indexed by RAM cache slot.  fec is the linked
   FEC, UINT_MAX when the slot is unlinked. */

struct fd_store_lru {
  uint prev;
  uint next;
  uint fec;
};
typedef struct fd_store_lru fd_store_lru_t;

#define POOL_NAME  fd_store_pool
#define POOL_ELE_T fd_store_fec_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool_para.c"

#define MAP_NAME               fd_store_map
#define MAP_ELE_T              fd_store_fec_t
#define MAP_KEY_T              fd_mr20_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_mr20_t)))
#define MAP_KEY_HASH(key,seed) fd_hash( (seed), (key)->uc, sizeof(fd_mr20_t) )
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain_para.c"

/* slot_to_fecs has one partition per shred tile.  Each inserter
   appends only to its own partition, so concurrent inserts under the
   shared fec_lock never touch the same chain.  Only fd_store_publish
   removes, under the exclusive fec_lock.  Keys are slots, so chains are
   sized by the blocks fec_max covers. */

#define MAP_NAME     fd_store_slot_to_fecs
#define MAP_ELE_T    fd_store_fec_t
#define MAP_KEY_T    uint
#define MAP_KEY      slot
#define MAP_NEXT     slot_next
#define MAP_IDX_T    uint
#define MAP_MULTI    1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_store {
  ulong magic;
  ulong fec_max;
  ulong fec_data_max;
  ulong store_gaddr;
  ulong map_gaddr;
  ulong pool_mem_gaddr;
  ulong pool_ele_gaddr;
  ulong shred_tile_cnt;
  ulong slot_to_fecs_gaddr;                 /* shred_tile_cnt maps, slot_to_fecs_sz apart */
  ulong slot_to_fecs_sz;
  ulong root;                               /* last published root */
  atomic_ulong slot_lo;                     /* no FEC is linked below it, ULONG_MAX before the first insert */

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
  ulong        cache_lru_gaddr;              /* fd_store_lru_t[ cache_slot_cnt ] */
  uint         cache_lru_head;               /* cache slots */
  uint         cache_lru_tail;
  ulong        cache_pinned_cnt;
  ulong        spill_free_gaddr;
  ulong        spill_free_cnt;
  ulong        spill_slot_cnt;
  atomic_ulong spill_live_cnt;
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
     at byte offset wire_off + ring_idx*sizeof(entry).  shred_map keys
     cells by (slot,idx), first version wins.  Other versions are in the
     on-disk table; tbl_cnt counts its records per slot%disk_max_slots.
     disk_lock guards cells, the slot map, tbl_cnt and reservations and
     is never held across I/O.  tbl_lock is held across table I/O; NONFIRST
     cells and records change only under it exclusively.  Lock order is
     tbl_lock, then disk_lock. */
  ulong        shred_map_gaddr; /* fd_shredb_slot_map over the ring pool */
  ulong        ring_pool_gaddr;
  ulong        ring_state_gaddr;
  fd_rwlock_t  disk_lock;
  fd_rwlock_t  tbl_lock;
  ulong        slot_hint_gaddr;
  ulong        tbl_cnt_gaddr;
  ulong        disk_max_shreds;
  ulong        disk_max_slots;
  ulong        disk_root_seed;
  uint         disk_tbl_gen;    /* non-zero, per boot */
  ulong        key_idx_bits;    /* bits of idx in slot map keys */
  ulong        max_shreds_per_block; /* bounds shred idxs, <=FD_SHREDB_HINT_VALID */
  atomic_ulong disk_reservation_head;
  atomic_ulong disk_cnt;
  atomic_ulong disk_insert_cnt;
  atomic_ulong disk_write_bytes;
};
typedef struct fd_store fd_store_t;

FD_PROTOTYPES_BEGIN

/* Store contains a FEC map keyed by merkle root prefix (fd_mr20_t), a
   payload cache, and an on-disk shred ring.

   Shred reserves a payload, fills it, inserts the FEC, and then notifies
   Replay.  The corresponding reassembly node owns the FEC until
   removal.
   Removal waits for payload users, then returns the payload and metadata
   synchronously.  fec_max therefore covers reassembly and complete-FEC
   messages in flight.

   Payloads enter the RAM cache and spill by LRU to page-sized file slots.
   Freed slots are immediately eligible for reuse and keep their disk
   blocks; a new slot is only used when none is free.  The file layout
   is:

    [ sparse spill slots (payload_slot_sz*fec_max) ][ shred ring ][ version table ][ tail ]

    wire_off is the fixed start of the shred ring.  Spill slots that
    were never used do not consume disk blocks.

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
                    ulong fec_set_cnt,
                    ulong shred_tile_cnt ) {
  if( FD_UNLIKELY( !fec_max || !fec_data_max || fec_max>UINT_MAX || fec_data_max>UINT_MAX ||
                   shred_storage_gib>FD_SHREDB_MAX_SIZE_GIB ) ) return 0UL;
  ulong chain_cnt = fd_store_map_chain_cnt_est( fec_max>>1 );
  ulong slot_to_fecs_sz = fd_ulong_align_up( fd_store_slot_to_fecs_footprint( fd_store_slot_to_fecs_chain_cnt_est( 8UL*(fec_max/FD_FEC_BLK_MAX) ) ), fd_store_slot_to_fecs_align() );
  ulong payload_slot_sz = fd_store_payload_slot_sz( fec_data_max );
  if( FD_UNLIKELY( !payload_slot_sz ) ) return 0UL;
  ulong cache_slot_cnt = shred_cache_bytes
                       ? fd_ulong_min( fec_max, fd_ulong_max( 1UL, shred_cache_bytes / payload_slot_sz ) )
                       : fec_max;
  ulong l = FD_LAYOUT_INIT;
  if( FD_UNLIKELY( fd_store_layout_append( &l, fd_store_align(),         1UL,            sizeof(fd_store_t) ) ||
                   fd_store_layout_append( &l, fd_store_map_align(),     1UL,            fd_store_map_footprint( chain_cnt ) ) ||
                   fd_store_layout_append( &l, fd_store_pool_align(),    1UL,            fd_store_pool_footprint() ) ||
                   fd_store_layout_append( &l, alignof(fd_store_fec_t),  fec_max,         sizeof(fd_store_fec_t) ) ||
                   fd_store_layout_append( &l, fd_store_slot_to_fecs_align(), shred_tile_cnt, slot_to_fecs_sz ) ||
                   fd_store_layout_append( &l, FD_STORE_PAYLOAD_PAGE_SZ, cache_slot_cnt, payload_slot_sz ) ||
                   fd_store_layout_append( &l, alignof(ulong),           cache_slot_cnt, sizeof(ulong) ) ||
                   fd_store_layout_append( &l, alignof(fd_store_lru_t),  cache_slot_cnt, sizeof(fd_store_lru_t) ) ||
                   fd_store_layout_append( &l, alignof(uint),            fec_max,         sizeof(uint) ) ||
                   fd_store_layout_append( &l, FD_STORE_PAYLOAD_PAGE_SZ, 1UL,             payload_slot_sz ) ) ) return 0UL;
  if( FD_UNLIKELY( fec_set_cnt && fd_store_layout_append( &l, alignof(fd_fec_set_t), fec_set_cnt, sizeof(fd_fec_set_t) ) ) ) return 0UL;
  if( shred_storage_gib ) {
    ulong max_shreds     = fd_shredb_max_shreds( shred_storage_gib );
    ulong max_slots      = fd_shredb_max_slots( shred_storage_gib );
    ulong disk_chain_cnt = fd_shredb_disk_chain_cnt( max_shreds );
    if( FD_UNLIKELY( !max_shreds || !max_slots ||
                     fd_store_layout_append( &l, fd_shredb_slot_map_align(),      1UL,        fd_shredb_slot_map_footprint( disk_chain_cnt ) ) ||
                     fd_store_layout_append( &l, alignof(fd_shredb_ring_entry_t), max_shreds, sizeof(fd_shredb_ring_entry_t) ) ||
                     fd_store_layout_append( &l, alignof(ulong),                  fd_shredb_state_word_cnt( max_shreds ), sizeof(ulong) ) ||
                     fd_store_layout_append( &l, alignof(atomic_ulong),           max_slots,  sizeof(atomic_ulong) ) ||
                     fd_store_layout_append( &l, alignof(uint),                   max_slots,  sizeof(uint) ) ) ) return 0UL;
  }
  if( FD_UNLIKELY( fd_store_layout_append( &l, fd_store_align(), 0UL, 1UL ) ) ) return 0UL;
  return l;
}

/* Formats a footprint-sized, fd_store_align()-aligned region.  fec_max
   bounds live FECs; fec_data_max bounds each payload.  The remaining size
   arguments configure the shred ring, RAM cache, and shred-tile arena.
   max_shreds_per_block bounds shred idxs in the shred ring, in
   [1,FD_SHREDB_HINT_VALID].  shred_tile_cnt is the number of
   slot_to_fecs partitions, must be non-zero and match the footprint.
   Does not create the backing file. */

void *
fd_store_new( void       * shmem,
              ulong        fec_max,
              ulong        fec_data_max,
              ulong        shred_storage_gib,
              ulong        shred_cache_bytes,
              ulong        fec_set_cnt,
              ulong        max_shreds_per_block,
              ulong        seed,
              ulong        shred_tile_cnt );

fd_store_t * fd_store_join ( void * shstore );
void *       fd_store_leave( fd_store_t const * store );
void *       fd_store_delete( void * shstore );

/* Creates and sizes the Store backing file, with tail_sz bytes after
   the shred ring and version table for other explicit-I/O users
   (rserve blockdb). */

int
fd_store_file_create( char const * path,
                      ulong        wire_off,
                      ulong        disk_max_shreds,
                      ulong        tail_sz );


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


struct fd_store_fec_data_view {
  uchar          * data;
  ushort const   * shred_sz; /* FD_FEC_SHRED_CNT data shred payload sizes */
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

/* Reserves a RAM payload not yet bound to any FEC and returns it (past
   the slot header), with its cache slot in *data_idx, or NULL if nothing can be spilled to
   make room.  Fill it, then hand data_idx to fd_store_insert, which
   takes ownership of the slot.  spill is optional and reports
   synchronous fallback spills. */

uchar *
fd_store_fec_data_reserve( fd_store_t                  * store,
                           int                           disk_fd,
                           uint                        * data_idx,
                           fd_store_fec_spill_stats_t * spill );

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
   coexist.  Release every successful view; publish waits for pins. */

int
fd_store_fec_data_view( fd_store_t *               store,
                        int                        disk_fd,
                        fd_store_fec_t *           fec,
                        fd_store_fec_data_view_t * view );

void
fd_store_fec_data_view_release( fd_store_t *               store,
                                fd_store_fec_data_view_t * view );

/* Atomically inserts merkle_root, a FEC set of slot, into the caller's
   slot_to_fecs partition part (the shred tile's).  The new FEC takes
   the payload reserved by fd_store_fec_data_reserve at data_idx,
   data_sz bytes split by shred_sz, and is RAM_READY when linked.  Returns
   FD_MAP_SUCCESS with the new FEC, or FD_MAP_ERR_KEY with *fec==NULL if
   its fd_mr20_t prefix is present, in which case the cache slot is
   freed. Pool exhaustion is a topology invariant violation. */

int
fd_store_insert( fd_store_t *       store,
                 fd_store_map_t *   map,
                 fd_hash_t const *  merkle_root,
                 ulong              slot,
                 ulong              part,
                 uint               data_idx,
                 uint               data_sz,
                 ushort const       shred_sz[ FD_FEC_SHRED_CNT ],
                 fd_store_fec_t **  fec );

/* Lockless lookup by merkle_root's fd_mr20_t prefix; returns NULL if
   absent.  The returned pointer is borrowed.  Retain the corresponding
   reassembly node or otherwise exclude publish while using it. */

fd_store_fec_t *
fd_store_query( fd_store_map_t *  map,
                fd_hash_t const * merkle_root );

/* Removes every FEC of a slot below root after its active views and
   spill I/O finish, returning its payload and metadata.  Walks the
   slots from the lowest inserted one to root.  Returns how many it
   removed. */

ulong
fd_store_publish( fd_store_t *     store,
                  fd_store_map_t * map,
                  ulong            root );


FD_FN_PURE static inline int
fd_store_has_disk( fd_store_t const * store ) {
  return store->disk_max_shreds > 0UL;
}

FD_FN_PURE static inline ulong
fd_store_tbl_off( fd_store_t const * store ) {
  return store->wire_off + store->disk_max_shreds*sizeof(fd_shredb_entry_t);
}

FD_FN_PURE static inline ulong
fd_store_tail_off( fd_store_t const * store ) {
  return fd_store_tbl_off( store ) + fd_shredb_tbl_rec_cnt( store->disk_max_shreds )*sizeof(fd_shredb_tbl_rec_t);
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
   FD_SHRED_MERKLE_NODE_SZ bytes are used).  Every version is findable
   by (slot,root,idx) and re-inserting a stored one is a no-op.  The
   first version stored for a (slot,idx) is indexed by (slot,idx) in
   RAM, later ones in the on-disk table.  Returns
   FD_STORE_DISK_INSERT_SUCCESS if written, FD_STORE_DISK_INSERT_DUP if
   already stored, or FD_STORE_DISK_INSERT_ERR. */

int
fd_store_disk_insert( fd_store_t       * store,
                      int                disk_fd,
                      fd_shred_t const * shred,
                      fd_hash_t const  * merkle_root );

/* Persists shred_cnt shreds (at most FD_STORE_DISK_INSERT_BATCH_MAX),
   shreds[ i ] of the FEC set with merkle root merkle_roots[ i ], with
   the same result per shred as shred_cnt calls of fd_store_disk_insert
   in order, and the same bytes on disk, but the
   entries of consecutive ring cells go out in one pwrite.  entries is
   caller scratch for shred_cnt disk entries; results[ i ] receives the
   result for shreds[ i ].  Returns how many succeeded. */

#define FD_STORE_DISK_INSERT_BATCH_MAX (64UL)

ulong
fd_store_disk_insert_batch( fd_store_t               * store,
                            int                        disk_fd,
                            fd_shred_t const * const * shreds,
                            fd_hash_t const * const  * merkle_roots,
                            ulong                      shred_cnt,
                            fd_shredb_entry_t        * entries,
                            int                      * results );

/* Copies (slot,shred_idx) to out, where shred_idx is below
   max_shreds_per_block.  Returns its positive byte count, MISS, or
   retryable BUSY.  Only finds the first version stored. */

int
fd_store_disk_query( fd_store_t const * store,
                     int                disk_fd,
                     ulong              slot,
                     uint               shred_idx,
                     uchar              out[ FD_SHRED_MAX_SZ ] );

/* fd_store_disk_query_root copies the shred (slot,shred_idx) of the FEC
   set whose merkle root starts with the FD_SHRED_MERKLE_NODE_SZ bytes at
   merkle_root to out.  Finds any stored version.  Returns its positive
   byte count, MISS, or retryable BUSY. */

int
fd_store_disk_query_root( fd_store_t const * store,
                          int                disk_fd,
                          ulong              slot,
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
