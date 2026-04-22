#ifndef HEADER_fd_src_accdb_fd_accdb_private_h
#define HEADER_fd_src_accdb_fd_accdb_private_h

#include "fd_accdb_shmem.h"
#include "fd_accdb_cache.h"

static inline void
spin_lock_acquire( int * lock ) {
# if FD_HAS_THREADS
  for(;;) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( lock, 0, 1 ) ) ) break;
    FD_SPIN_PAUSE();
  }
# else
  *lock = 1;
# endif
  FD_COMPILER_MFENCE();
}

static inline void
spin_lock_release( int * lock ) {
  FD_COMPILER_MFENCE();
# if FD_HAS_THREADS
  FD_VOLATILE( *lock ) = 0;
# else
  *lock = 0;
# endif
}

#ifndef FD_ACCDB_NO_FORK_ID
struct fd_accdb_fork_id { ushort val; };
typedef struct fd_accdb_fork_id fd_accdb_fork_id_t;
#endif

struct __attribute__((packed)) fd_accdb_disk_meta {
  uchar pubkey[ 32UL ];
  uint  size;
  uchar owner[ 32UL ];
};

typedef struct fd_accdb_disk_meta fd_accdb_disk_meta_t;

struct fd_accdb_txn {
  union {
    struct { uint next; } pool;
    struct { uint next; } fork;
  };

  uint acc_map_idx;
  uint acc_pool_idx;
};

typedef struct fd_accdb_txn fd_accdb_txn_t;

#define POOL_NAME       txn_pool
#define POOL_ELE_T      fd_accdb_txn_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      uint
#define POOL_IDX_WIDTH  32
#define POOL_IMPL_STYLE 0
#define POOL_LAZY       1

#include "../../util/tmpl/fd_pool_para.c"

#define SET_NAME       descends_set
#define SET_IMPL_STYLE 1
#include "../../util/tmpl/fd_set_dynamic.c"

struct fd_accdb_fork_shmem {
  uint generation;

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
#define POOL_ELE_T      fd_accdb_fork_shmem_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      ulong
#define POOL_IMPL_STYLE 0

#include "../../util/tmpl/fd_pool_para.c"

struct fd_accdb_partition {
  ulong marked_compaction;
  ulong write_offset;
  ulong compaction_offset;

  ulong bytes_freed;

  uchar layer; /* compaction tier this partition belongs to */

  /* Epoch at which this partition was enqueued for compaction.  Set by
     fd_accdb_shmem_bytes_freed when the partition crosses the
     freed-bytes threshold.  The compaction tile will not begin reading
     from this partition until all joiners that were in an
     epoch-protected critical section at enqueue time have exited,
     ensuring any in-flight pwritev2 to this partition has completed. */
  ulong compaction_ready_epoch;

  /* Epoch at which this partition was enqueued for deferred freeing.
     Set by compaction when the partition finishes compaction, and
     checked by the reclamation scan to determine when it is safe to
     release the partition back to the pool. */
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

struct fd_accdb_cache_key {
  uchar pubkey[ 32UL ];
  uint generation;
};

typedef struct fd_accdb_cache_key fd_accdb_cache_key_t;

struct fd_accdb_acc {
  fd_accdb_cache_key_t key;

  struct {
    uint next;
  } map;

  union {
    struct {
      uint next;
    } pool;
    uint cache_idx;
  };

  uint   executable_size;

  ulong  lamports;

  /* Pack offset and fork_id together into a single ulong to pack the
     struct into a single 64 byte cache line.  This is a performance win
     of 2-3%. */
  ulong  offset_fork;
};

typedef struct fd_accdb_acc fd_accdb_acc_t;

#define FD_ACCDB_OFF_BITS  48UL
#define FD_ACCDB_OFF_MASK  ((1UL<<FD_ACCDB_OFF_BITS)-1UL)       /* 0x0000_FFFF_FFFF_FFFF */
#define FD_ACCDB_OFF_INVAL FD_ACCDB_OFF_MASK                    /* sentinel: offset bits all-ones */

/* The `size` field in fd_accdb_disk_meta_t and fd_accdb_acc_t packs the
   account's executable flag into bit 31.  The lower 30 bits hold the
   data length in bytes (max ~1 GB, well above FD_RUNTIME_ACC_SZ_MAX
   of 10 MiB).  Bit 30 is used only in the in-memory index as a
   cache_valid flag: when set, cache_idx holds a valid (class, idx)
   pair; when clear, cache_idx must not be dereferenced (it may hold
   a snapshot slot number or garbage).  FD_ACCDB_SIZE_PACK never sets
   bit 30, so the on-disk representation is unchanged and
   compaction's copy_file_range preserves the bit layout without
   rewriting record headers. */

#define FD_ACCDB_SIZE_EXEC_BIT        (1U<<31)
#define FD_ACCDB_SIZE_CACHE_VALID_BIT (1U<<30)
#define FD_ACCDB_SIZE_CACHE_CLAIM_BIT (1U<<29)
#define FD_ACCDB_SIZE_MASK            ((1U<<29)-1U)
#define FD_ACCDB_SIZE_PACK(sz,exec)   ((uint)(sz) | ((exec) ? FD_ACCDB_SIZE_EXEC_BIT : 0U))
#define FD_ACCDB_SIZE_DATA(packed)    ((packed) & FD_ACCDB_SIZE_MASK)
#define FD_ACCDB_SIZE_EXEC(packed)    (!!((packed) & FD_ACCDB_SIZE_EXEC_BIT))
#define FD_ACCDB_SIZE_CACHE_VALID(p)  (!!((p) & FD_ACCDB_SIZE_CACHE_VALID_BIT))
#define FD_ACCDB_SIZE_CACHE_CLAIM(p)  (!!((p) & FD_ACCDB_SIZE_CACHE_CLAIM_BIT))

static inline ulong
fd_accdb_acc_offset( fd_accdb_acc_t const * acc ) {
  return acc->offset_fork & FD_ACCDB_OFF_MASK;
}

static inline ushort
fd_accdb_acc_fork_id( fd_accdb_acc_t const * acc ) {
  return (ushort)( acc->offset_fork >> FD_ACCDB_OFF_BITS );
}

static inline ulong
fd_accdb_acc_pack_offset_fork( ulong  offset,
                               ushort fork_id ) {
  return ( (ulong)fork_id << FD_ACCDB_OFF_BITS ) | ( offset & FD_ACCDB_OFF_MASK );
}

/* fd_accdb_acc_xchg_offset atomically replaces the 48-bit offset
   portion of acc->offset_fork with new_offset while preserving the
   16-bit fork_id, and returns the previous 48-bit offset.  Uses a
   CAS loop so that concurrent compaction CAS and release-overwrite
   exchanges serialize correctly. */

static inline ulong
fd_accdb_acc_xchg_offset( fd_accdb_acc_t * acc,
                           ulong            new_offset ) {
  for(;;) {
    ulong old_packed = FD_VOLATILE_CONST( acc->offset_fork );
    ulong new_packed = ( old_packed & ~FD_ACCDB_OFF_MASK ) | ( new_offset & FD_ACCDB_OFF_MASK );
    if( FD_LIKELY( FD_ATOMIC_CAS( &acc->offset_fork, old_packed, new_packed )==old_packed ) )
      return old_packed & FD_ACCDB_OFF_MASK;
    FD_SPIN_PAUSE();
  }
}

/* Packing helpers for the embedded acc cache index.  3 bits class
   in bits 31-29, 29 bits line index.  INVAL is the sentinel for
   "no cached location known". */

#define FD_ACCDB_ACC_CIDX_INVAL     UINT_MAX
#define FD_ACCDB_ACC_CIDX_PACK(c,i) ((uint)( ((uint)(c)<<29) | ((uint)(i) & 0x1FFFFFFFU) ))
#define FD_ACCDB_ACC_CIDX_CLASS(ci) ((ulong)((uint)(ci) >> 29))
#define FD_ACCDB_ACC_CIDX_IDX(ci)   ((ulong)((uint)(ci) & 0x1FFFFFFFU))

#define POOL_NAME       acc_pool
#define POOL_ELE_T      fd_accdb_acc_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      uint
#define POOL_IDX_WIDTH  32
#define POOL_IMPL_STYLE 0
#define POOL_LAZY       1

#include "../../util/tmpl/fd_pool_para.c"

struct fd_accdb_cache_line {
  fd_accdb_cache_key_t key;

  uint acc_idx;
  uint cache_idx;

  uint  refcnt;
  uchar persisted;
  uchar referenced;

  uint next;

  uchar owner[ 32UL ];
};

typedef struct fd_accdb_cache_line fd_accdb_cache_line_t;

typedef struct __attribute__((aligned(64))) { ulong val; } accdb_offset_t;

/* Partition offsets are packed into accdb_offset_t as:
     bits 63..51: partition pool index
     bits 50..0 : byte offset within the partition */

#define FD_ACCDB_PARTITION_OFF_BITS 51UL

static FD_FN_CONST inline accdb_offset_t
accdb_offset( ulong partition_idx,
              ulong partition_offset ) {
  return (accdb_offset_t){ .val = (partition_idx<<FD_ACCDB_PARTITION_OFF_BITS) | partition_offset };
}

static FD_FN_CONST inline ulong
packed_partition_idx( accdb_offset_t offset ) {
  return offset.val>>FD_ACCDB_PARTITION_OFF_BITS;
}

static FD_FN_CONST inline ulong
packed_partition_offset( accdb_offset_t offset ) {
  return offset.val & ((1UL<<FD_ACCDB_PARTITION_OFF_BITS)-1UL);
}

static FD_FN_CONST inline ulong
packed_partition_file_offset( accdb_offset_t offset,
                              ulong          partition_sz ) {
   return (packed_partition_idx( offset )*partition_sz + packed_partition_offset( offset ));
}

/* Accounts are written to a tiered partition layout.  Layer 0 is the
   hot write head used by acquire/release (execution).  Layers 1..N-1
   are successively colder compaction tiers: partitions at layer K are
   compacted into layer K+1. */

#define FD_ACCDB_COMPACTION_LAYER_CNT (3UL)

/* Maximum number of concurrent joiners (tiles) that can publish an
   epoch in the accdb.  Each joiner claims a slot in the shared epoch
   array during fd_accdb_new.  Must be less than or equal to 256 so
   refcnt in cache lines can safely track the number of threads
   referencing each cache line without overflow.  With a uint refcnt
   field, 256 joiners is well within range. */
#define FD_ACCDB_MAX_JOINERS (256UL)

/* EVICT_SENTINEL: stored in refcnt to indicate a cache line is being
   claimed by an eviction scan.  Any thread seeing this value must treat
   the line as unavailable. */
#define FD_ACCDB_EVICT_SENTINEL UINT_MAX

struct fd_accdb_shmem_private {
  int partition_lock  __attribute__((aligned(64)));

  /* Per-class CLOCK sweep position.  Atomically incremented by
     eviction scans (modulo cache_class_max[c]).  Each element is on
     its own cacheline to avoid false sharing between classes. */
  struct __attribute__((aligned(64))) { ulong val; } clock_hand[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Per-class CAS free list (Treiber stack) for fully-freed cache
     lines.  ver_top packs a 32-bit ABA version counter in bits
     63..32 and a uint pool index in bits 31..0.  UINT_MAX in the
     low 32 bits means empty. */
  struct __attribute__((aligned(64))) { ulong ver_top; } cache_free[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Per-class approximate depth of the CAS free list.  Atomically
     incremented on push, decremented on pop.  Used by the
     background pre-eviction loop to decide when to refill. */
  struct __attribute__((aligned(64))) { ulong val; } cache_free_cnt[ FD_ACCDB_CACHE_CLASS_CNT ];

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
     still valid and descends_set is used to check ancestry.

     KEY INVARIANT: descends_set is ONLY consulted when generation >
     root_generation, which means the fork_id has NOT been rooted yet
     and its pool slot is still live.  This is what makes it safe for
     fork_slot_defer to eagerly clear descends_set bits for retired
     forks: rooted fork bits are dead (bypassed by the generation fast
     path), and purged fork bits were already 0 in all live forks'
     descends_sets (a purged fork is never an ancestor of a live fork).
     */
  uint generation;

  /* Lazy initial-allocation counter per size class.  Atomically
     incremented by acquire_cache_line (with undo on overflow). Each
     element is on its own cacheline to avoid false sharing between
     classes. */
  struct __attribute__((aligned(64))) { ulong val; } cache_class_init[ FD_ACCDB_CACHE_CLASS_CNT ];

  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Byte offsets from shmem base to the per-class cache regions. Each
     region is cache_class_max[c] * fd_accdb_cache_slot_sz[c] bytes,
     with each slot holding an fd_accdb_cache_line_t header followed by
     up to (fd_accdb_cache_slot_sz[c] - META_SZ) bytes of account data.
     */
  ulong cache_region_off[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Background pre-eviction watermarks (computed once in shmem_new).
     cache_free_target[c]: desired free-list depth for class c.
     cache_free_low_water[c]: trigger threshold (target/2). */
  ulong cache_free_target   [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_free_low_water[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* cache_class_used[i].val holds the number of reserved cache
     slots in size class i.  Acquire atomically increments; if the
     result exceeds cache_class_max[i] the reservation overflowed
     and the thread subtracts back and retries.  Release atomically
     decrements.  Each element is on its own cacheline to avoid
     false sharing between classes.  Invariant:
       used[i].val + available[i] == cache_class_max[i]
     at all times. */
  struct __attribute__((aligned(64))) { ulong val; } cache_class_used[ FD_ACCDB_CACHE_CLASS_CNT ];

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

  /* Hard upper bound on concurrent joiners, set at construction.
     Used to determine whether cache_class_used tracking can be
     skipped for a given class (when max[c] >= MIN_RESERVED *
     joiner_cnt, every reservation succeeds trivially). */
  ulong joiner_cnt_max;

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

     joiner_epochs[i] holds the epoch observed by joiner i at the start
     of its epoch-protected critical section, or ULONG_MAX when idle.
     The compaction tile scans this array to find the minimum observed
     epoch; any deferred partition tagged with an epoch strictly less
     than that minimum is safe to release, because every epoch-protected
     operation that could have snapshotted an offset into that partition
     has since exited its critical section.

     joiner_cnt is claimed via atomic fetch-and-add in fd_accdb_new
     and never decremented. */
  ulong epoch __attribute__((aligned(64)));

  /* Each joiner epoch is padded to a full cache line to prevent
     false sharing between joiners writing to adjacent slots. */
  struct __attribute__((aligned(64))) { ulong val; } joiner_epochs[ FD_ACCDB_MAX_JOINERS ];
  ulong joiner_cnt __attribute__((aligned(64)));
  ulong deferred_free_dlist_off;

  fd_accdb_shmem_metrics_t metrics[1];

  /* Command slot for T1 -> T2 offloading of advance_root / purge.
     Padded to its own cache line to avoid false sharing with the
     hot epoch / joiner_epochs fields above. */

#define FD_ACCDB_CMD_IDLE         (0U)
#define FD_ACCDB_CMD_ADVANCE_ROOT (1U)
#define FD_ACCDB_CMD_PURGE        (2U)

  uint   cmd_op       __attribute__((aligned(64))); /* FD_ACCDB_CMD_* */
  ushort cmd_fork_id;                               /* argument       */
  int    cmd_done;                                  /* 0=pending 1=done */

  ulong magic; /* ==FD_ACCDB_SHMEM_MAGIC */
};

#endif /* HEADER_fd_src_accdb_fd_accdb_private_h */
