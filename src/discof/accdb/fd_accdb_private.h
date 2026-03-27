#ifndef HEADER_fd_src_accdb_fd_accdb_private_h
#define HEADER_fd_src_accdb_fd_accdb_private_h

#include "fd_accdb_shmem.h"
#include "fd_accdb_cache.h"
#include "../../flamenco/fd_rwlock.h"
#include "../../util/log/fd_log.h"

#ifndef FD_ACCDB_NO_FORK_ID
struct fd_accdb_fork_id { ushort val; };
typedef struct fd_accdb_fork_id fd_accdb_fork_id_t;
#endif

struct __attribute__((packed)) fd_accdb_disk_meta {
  uchar pubkey[ 32UL ];
  uint  size;
};

typedef struct fd_accdb_disk_meta fd_accdb_disk_meta_t;

struct fd_accdb_txn {
  struct {
    uint next;
  } pool;

  struct {
    uint next;
  } fork;

  uint acc_map_idx;
  uint acc_pool_idx;
};

typedef struct fd_accdb_txn fd_accdb_txn_t;

#define POOL_NAME       txn_pool
#define POOL_T          fd_accdb_txn_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      uint
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

#define SET_NAME       descends_set
#define SET_IMPL_STYLE 1
#include "../../util/tmpl/fd_set_dynamic.c"

struct fd_accdb_fork_shmem {
  ulong generation;

  fd_accdb_fork_id_t parent_id;
  fd_accdb_fork_id_t child_id;
  fd_accdb_fork_id_t sibling_id;

  struct {
    ulong next;
  } pool;

  uint txn_head;
};

typedef struct fd_accdb_fork_shmem fd_accdb_fork_shmem_t;

#define POOL_NAME       fork_pool
#define POOL_T          fd_accdb_fork_shmem_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      ulong
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

struct fd_accdb_partition {
  ulong marked_compaction;
  ulong write_offset;
  ulong compaction_offset;

  ulong bytes_freed;

  uchar layer; /* compaction tier this partition belongs to */

  /* Epoch at which this partition was enqueued for deferred freeing.
     Set by compaction when the partition finishes compaction, and
     checked by the reclamation scan to determine when it is safe
     to release the partition back to the pool. */
  ulong epoch_tag;

  ulong pool_next;

  ulong dlist_prev;
  ulong dlist_next;
};

typedef struct fd_accdb_partition fd_accdb_partition_t;

#define POOL_NAME       partition_pool
#define POOL_T          fd_accdb_partition_t
#define POOL_NEXT       pool_next
#define POOL_IDX_T      ulong
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME       compaction_dlist
#define DLIST_ELE_T      fd_accdb_partition_t
#define DLIST_PREV       dlist_prev
#define DLIST_NEXT       dlist_next
#define DLIST_IMPL_STYLE 1

#include "../../util/tmpl/fd_dlist.c"

/* deferred_free_dlist reuses the same prev/next fields as
   compaction_dlist.  A partition is in at most one of the two lists at
   any time: it is popped from compaction_dlist before being pushed onto
   deferred_free_dlist. */

#define DLIST_NAME       deferred_free_dlist
#define DLIST_ELE_T      fd_accdb_partition_t
#define DLIST_PREV       dlist_prev
#define DLIST_NEXT       dlist_next
#define DLIST_IMPL_STYLE 1

#include "../../util/tmpl/fd_dlist.c"

struct fd_accdb_acc {
  struct {
    uint next;
  } map;

  struct {
    uint next;
  } pool;

  ulong  offset;
  ulong  generation;
  ulong  lamports;
  uint   size;
  ushort fork_id;
  uchar  pubkey[ 32UL ];
  uchar  owner[ 32UL ];
};

typedef struct fd_accdb_acc fd_accdb_acc_t;

#define POOL_NAME       acc_pool
#define POOL_T          fd_accdb_acc_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      uint
#define POOL_IMPL_STYLE 1

#include "../../util/tmpl/fd_pool.c"

struct fd_accdb_cache_key {
  uchar pubkey[ 32UL ];
  ulong generation;
};

typedef struct fd_accdb_cache_key fd_accdb_cache_key_t;

struct fd_accdb_cache_line {
  fd_accdb_cache_key_t key;

  uint acc_idx;
  uint cache_idx;

  uchar refcnt;
  uchar persisted;

  struct {
    uint next;
    uint prev;
  };
};

typedef struct fd_accdb_cache_line fd_accdb_cache_line_t;

static inline ulong
fd_xxh3_mul128_fold64( ulong lhs, ulong rhs ) {
  uint128 product = (uint128)lhs * (uint128)rhs;
  return (ulong)product ^ (ulong)( product>>64 );
}

static inline ulong
fd_xxh3_mix16b( ulong i0, ulong i1,
                ulong s0, ulong s1,
                ulong seed ) {
  return fd_xxh3_mul128_fold64( i0 ^ (s0 + seed), i1 ^ (s1 - seed) );
}

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash1( uchar const key[ 32 ],
                       ulong       seed ) {
  ulong k0 = FD_LOAD( ulong, key+ 0 );
  ulong k1 = FD_LOAD( ulong, key+ 8 );
  ulong k2 = FD_LOAD( ulong, key+16 );
  ulong k3 = FD_LOAD( ulong, key+24 );
  ulong acc = 32 * 0x9E3779B185EBCA87ULL;
  acc += fd_xxh3_mix16b( k0, k1, 0xbe4ba423396cfeb8UL, 0x1cad21f72c81017cUL, seed );
  acc += fd_xxh3_mix16b( k2, k3, 0xdb979083e96dd4deUL, 0x1f67b3b7a4a44072UL, seed );
  acc = acc ^ (acc >> 37);
  acc *= 0x165667919E3779F9ULL;
  acc = acc ^ (acc >> 32);
  return acc;
}

/* Custom cache map: chain hash from (pubkey, generation) to a cache_idx
   ulong encoding the cache class (high 3 bits) and pool index (low 61
   bits).  Entries reference the acc pool by index rather than
   duplicating pubkey and generation. */

struct fd_accdb_cache_entry {
  uint  acc_idx;
  ulong cache_idx;
  uint  next;
  uint  prev;
};

typedef struct fd_accdb_cache_entry fd_accdb_cache_entry_t;

#define FD_ACCDB_CACHE_PACK(cls,idx) (((ulong)(cls)<<61)|(idx))
#define FD_ACCDB_CACHE_PACK_CLASS(p) ((p)>>61)
#define FD_ACCDB_CACHE_PACK_IDX(p)   ((p)&((1UL<<61)-1UL))

struct fd_accdb_cache_map {
  ulong chain_cnt;
  ulong entry_max;
  ulong seed;
  uint  free_head;
};

typedef struct fd_accdb_cache_map fd_accdb_cache_map_t;

static inline uint *
fd_accdb_cm_chains( fd_accdb_cache_map_t * map ) {
  return (uint *)( map+1UL );
}

static inline fd_accdb_cache_entry_t *
fd_accdb_cm_entries( fd_accdb_cache_map_t * map ) {
  return (fd_accdb_cache_entry_t *)( fd_accdb_cm_chains( map ) + map->chain_cnt );
}

FD_FN_CONST static inline ulong
cache_map_align( void ) {
  return alignof(fd_accdb_cache_map_t);
}

FD_FN_CONST static inline ulong
cache_map_footprint( ulong entry_max ) {
  if( FD_UNLIKELY( !entry_max ) ) return 0UL;

  ulong chain_cnt = fd_ulong_pow2_up( (entry_max>>1) + (entry_max&1UL) );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_cache_map_t),   sizeof(fd_accdb_cache_map_t)             );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                   chain_cnt*sizeof(uint)                   );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_cache_entry_t), entry_max*sizeof(fd_accdb_cache_entry_t) );
  return FD_LAYOUT_FINI( l, cache_map_align() );
}

static inline void *
cache_map_new( void * mem,
               ulong  entry_max,
               ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, cache_map_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !entry_max ) ) {
    FD_LOG_WARNING(( "entry_max must be > 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( entry_max>=UINT_MAX ) ) {
    FD_LOG_WARNING(( "entry_max must be < UINT_MAX" ));
    return NULL;
  }

  fd_accdb_cache_map_t * map = (fd_accdb_cache_map_t *)mem;
  map->entry_max = entry_max;
  map->seed      = seed;
  map->free_head = 0U;
  map->chain_cnt = fd_ulong_pow2_up( (entry_max>>1) + (entry_max&1UL) );

  uint * chains = fd_accdb_cm_chains( map );
  for( ulong i=0UL; i<map->chain_cnt; i++ ) chains[ i ] = UINT_MAX;

  fd_accdb_cache_entry_t * entries = fd_accdb_cm_entries( map );
  for( ulong i=0UL; i<entry_max; i++ ) {
    if( FD_LIKELY( i+1UL<entry_max ) ) entries[ i ].next = (uint)(i+1UL);
    else                               entries[ i ].next = UINT_MAX;
  }

  return mem;
}

static inline fd_accdb_cache_map_t *
cache_map_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, cache_map_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  return (fd_accdb_cache_map_t *)mem;
}

#define DLIST_NAME       cache_dlist
#define DLIST_ELE_T      fd_accdb_cache_line_t
#define DLIST_IMPL_STYLE 1

#include "../../util/tmpl/fd_dlist.c"

typedef struct { ulong val; } accdb_offset_t;

/* Accounts are written to a tiered partition layout.  Layer 0 is the
   hot write head used by acquire/release (execution).  Layers 1..N-1
   are successively colder compaction tiers: partitions at layer K are
   compacted into layer K+1. */

#define FD_ACCDB_COMPACTION_LAYER_CNT (3UL)

/* Maximum number of concurrent joiners (tiles) that can hold
   rwlock-read on the accdb.  Each joiner claims a slot in the shared
   epoch array during fd_accdb_new.  Must be less than or equal to 256
   so refcnt in cache lines can safely track the number of threads
   referencing each cache line without overflow. */
#define FD_ACCDB_MAX_JOINERS (256UL)

struct fd_accdb_shmem_private {
  fd_rwlock_t lock[1] __attribute__((aligned(64)));

  int cache_lock      __attribute__((aligned(64)));
  int partition_lock  __attribute__((aligned(64)));

  fd_accdb_fork_id_t root_fork_id;

  ulong seed;

  /* generation is a monotonically increasing counter assigned to each
     fork on creation.  When a fork is rooted, its pool slot (fork_id)
     is freed and may be recycled by a new fork, making fork_id in
     on-disk metadata useless for identifying entries from that freed
     fork.  But generation persists in disk metadata and is never
     recycled.

     Any rooted fork is by definition an ancestor of all live forks, so
     entries with generation <= root_fork->generation are
     unconditionally visible without consulting descends_set.  For
     entries with generation > root_fork->generation, the fork_id is
     still valid and descends_set is used to check ancestry. */
  ulong generation;

  ulong cache_class_init[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* cache_class_pool[i] holds the number of unreserved cache slots
     available in size class i for any thread to claim.  Threads
     maintain a local credit array in their join struct; when local
     credit is insufficient for an acquire batch, the deficit is
     atomically subtracted from the pool.  On the rare slow path
     (pool exhausted for some class), the requesting thread returns
     all of its positive local credits to the pool before retrying,
     ensuring hoarded credits become globally visible.  Invariant:
       pool[i] + sum_over_threads(credit[i]) == cache_class_max[i]
     at all times (modulo in-flight reservations). */
  ulong cache_class_pool[ FD_ACCDB_CACHE_CLASS_CNT ] __attribute__((aligned(64)));

  /* Per-layer write heads.  whead[0] is the hot (execution) write
     head, updated with atomic fetch-and-add by acquire/release
     threads.  whead[1..N-1] are compaction write heads, each
     single-writer (compaction tile only). */
  accdb_offset_t whead[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  int            has_partition[ FD_ACCDB_COMPACTION_LAYER_CNT ];

  ulong partition_cnt;
  ulong partition_sz;
  ulong partition_max;

  ulong chain_cnt;
  ulong max_live_slots;
  ulong max_accounts;
  ulong max_account_writes_per_slot;

  ulong partition_pool_off;

  /* compaction_dlist_off[k] is the byte offset (from shmem base) of
     the dlist sentinel for layer k.  Partitions at layer k that
     reach the freed-bytes threshold are enqueued here for compaction
     into layer k+1, or into layer k itself for the deepest layer. */
  ulong compaction_dlist_off[ FD_ACCDB_COMPACTION_LAYER_CNT ];

  /* Epoch-based safe reclamation for compacted partitions.

     epoch is a monotonically increasing counter incremented by the
     compaction tile each time a partition finishes compaction.  The
     completed partition is tagged with the current epoch and pushed
     onto a deferred-free list instead of being released immediately.

     joiner_epochs[i] holds the epoch observed by joiner i at the
     start of its rwlock-read critical section, or ULONG_MAX when
     idle.  The compaction tile scans this array to find the minimum
     observed epoch; any deferred partition tagged with an epoch
     strictly less than that minimum is safe to release, because
     every rwlock-read holder that could have snapshotted an offset
     into that partition has since exited its critical section.

     joiner_cnt is claimed via atomic fetch-and-add in fd_accdb_new
     and never decremented. */
  ulong epoch                                  __attribute__((aligned(64)));
  ulong joiner_epochs[ FD_ACCDB_MAX_JOINERS ]  __attribute__((aligned(64)));
  ulong joiner_cnt                             __attribute__((aligned(64)));
  ulong deferred_free_dlist_off;

  fd_accdb_shmem_metrics_t metrics[1];

  ulong magic; /* ==FD_ACCDB_SHMEM_MAGIC */
};

#endif /* HEADER_fd_src_accdb_fd_accdb_private_h */
