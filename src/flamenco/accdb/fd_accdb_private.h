#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_private_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_private_h

#include "fd_accdb_base.h"
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

struct fd_accdb_txn {
  union {
    struct { uint next; } pool;
    struct { uint next; } fork;
  };

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

  uchar layer; /* compaction tier this partition belongs to. */

  ulong read_ops;
  ulong bytes_read;
  ulong write_ops;
  ulong bytes_written;

  /* Tickcount (fd_tickcount) of the partition's lifecycle events.  Set
     only at partition creation and again when the partition closes
     (i.e. the layer's write head rotates off it). */
  long created_ticks;
  long filled_ticks;

  /* Compaction lifecycle flags.  queued is set when the partition is
     pushed onto the compaction_dlist and cleared when it is popped.
     compacting_now is set by the compaction tile around the actual
     compaction work for this partition. */
  uchar queued;
  uchar compacting_now;

  /* Per-compaction-pass telemetry accumulators for the
     accdb_compaction_completed event.  Reset when a partition's
     compaction begins (compacting_now set in background_compact) and
     accumulated as records are scanned/relocated. */
  long  compaction_start_wallclock;    /* timestamp when this pass began */
  ulong compaction_accounts_relocated; /* live records moved this pass */
  ulong compaction_bytes_relocated;    /* bytes moved this pass */
  ulong compaction_dead_records;       /* records skipped (no live index entry) this pass */

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

/* Deferred-free buffer tiering.  The buffer must hold txn_max entries
   (worst single advance_root/purge; exhaustion is FD_TEST abort) but
   mainnet appends ~1 rooted slot of unlinks per call.  Locked RAM holds
   DEFER_WINDOW entries (resident + one stage chunk); past resident, T2
   pwrites sealed stage chunks to the scratch file and preads them back
   at drain.  Positions are pure f(cnt). */

#define FD_ACCDB_DEFER_WINDOW_ELE (16UL<<20)  /* 64 MiB locked window  */
#define FD_ACCDB_DEFER_STAGE_ELE  (2UL<<20)   /* 8 MiB spill I/O chunk */

/* Deferred entry tag: pool slot moved between tiers, its bytes live
   on.  Drain skips the byte free, never the CLAIM fence. */
#define FD_ACCDB_DEFER_MIGRATED (1U<<31)

/* T2 background defer ring (index mode): unlinks made outside
   advance_root/purge, sealed in chunks tagged by a T2 epoch bump and
   drained by T2 itself, so pool slots return without a root. */
#define FD_ACCDB_BG_DEFER_MAX   (1UL<<20)
#define FD_ACCDB_BG_DEFER_CHUNK (1UL<<16)
#define FD_ACCDB_BG_DEFER_CHUNKS (FD_ACCDB_BG_DEFER_MAX/FD_ACCDB_BG_DEFER_CHUNK)

/* Hot (demoted / promoted rooted) entries carry this fork id; their
   generation is <= root, so the fork bits are never consulted. */
#define FD_ACCDB_FORK_ID_ROOTED ((ushort)(USHORT_MAX-1U))

#define FD_ACCDB_DEMOTE_AGE   (64U)   /* generations before demotion */
#define FD_ACCDB_DEMOTE_BATCH (64UL)  /* per background call         */
#define FD_ACCDB_HOT_SWEEP    (256UL) /* hot chains per call         */
#define FD_ACCDB_COMPACT_IDX_IO (16UL) /* compaction bucket lookups per call */

/* tier[pool] (T2 only): where T2 last put a slot. */
#define FD_ACCDB_TIER_NONE    (0)
#define FD_ACCDB_TIER_ROOTED  (1)  /* rooted acc_map, in demote FIFO */
#define FD_ACCDB_TIER_HOT     (2)

struct fd_accdb_cache_key {
  uchar pubkey[ 32UL ];
  uint generation;
};

typedef struct fd_accdb_cache_key fd_accdb_cache_key_t;

struct __attribute__((aligned(64))) fd_accdb_accmeta {
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

typedef struct fd_accdb_accmeta fd_accdb_accmeta_t;

FD_STATIC_ASSERT( alignof(fd_accdb_accmeta_t)==64, layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_accmeta_t)==64, layout );

#define FD_ACCDB_OFF_BITS  48UL
#define FD_ACCDB_OFF_MASK  ((1UL<<FD_ACCDB_OFF_BITS)-1UL)       /* 0x0000_FFFF_FFFF_FFFF */
#define FD_ACCDB_OFF_INVAL FD_ACCDB_OFF_MASK                    /* sentinel: offset bits all-ones */

/* The in-memory executable_size field in fd_accdb_accmeta_t packs
   five things into 32 bits:

     bit  31     executable flag                       (FD_ACCDB_SIZE_EXEC_BIT)
     bit  30     cache_valid flag, in-memory only      (FD_ACCDB_SIZE_CACHE_VALID_BIT)
     bit  29     cache_claim flag, in-memory only      (FD_ACCDB_SIZE_CACHE_CLAIM_BIT)
     bit  28     pd_write flag,    in-memory only      (FD_ACCDB_SIZE_PD_WRITE_BIT)
     bits 27..0  data length in bytes                  (FD_ACCDB_SIZE_MASK)

   The data length is therefore 28 bits, max 256 MiB, still well above
   FD_RUNTIME_ACC_SZ_MAX of 10 MiB (enforced by the static assert below).

   The three upper flag bits exist only in the in-memory index, never on
   disk:
     - cache_valid (bit 30): when set, cache_idx holds a valid
       (class, idx) pair; when clear, cache_idx must not be dereferenced
       (it may hold a snapshot slot number or garbage).
     - cache_claim (bit 29): a short-lived eviction/install lock taken
       via CAS while a writer mutates the cache_idx <-> cache-line
       binding, so concurrent readers and the evictor do not race.
     - pd_write (bit 28): set on a committed version whose write changed
       BPF upgradeable-loader deploy status this slot (Deploy/Upgrade/
       Extend/Close).  Meaningful only while the accmeta's key.generation
       equals a live fork's generation (i.e. the version was committed on
       that fork this slot); across snapshot/root boundaries the bit is
       dead by construction because the generation no longer matches any
       live fork.  Carried explicitly by the two commit sites in
       fd_accdb_release and nowhere else.

   The on-disk fd_accdb_disk_meta_t.size is only the raw data length,
   written via FD_ACCDB_SIZE_DATA.  It includes neither the executable
   bit nor the cache/PD flags.  Compaction preserves these record
   headers verbatim with copy_file_range. */

#define FD_ACCDB_SIZE_EXEC_BIT        (1U<<31)
#define FD_ACCDB_SIZE_CACHE_VALID_BIT (1U<<30)
#define FD_ACCDB_SIZE_CACHE_CLAIM_BIT (1U<<29)
#define FD_ACCDB_SIZE_PD_WRITE_BIT    (1U<<28)
#define FD_ACCDB_SIZE_MASK            ((1U<<28)-1U)
#define FD_ACCDB_SIZE_PACK(sz,exec)   ((uint)(sz) | ((exec) ? FD_ACCDB_SIZE_EXEC_BIT : 0U))
#define FD_ACCDB_SIZE_DATA(packed)    ((packed) & FD_ACCDB_SIZE_MASK)
#define FD_ACCDB_SIZE_EXEC(packed)    (!!((packed) & FD_ACCDB_SIZE_EXEC_BIT))
#define FD_ACCDB_SIZE_CACHE_VALID(p)  (!!((p) & FD_ACCDB_SIZE_CACHE_VALID_BIT))
#define FD_ACCDB_SIZE_CACHE_CLAIM(p)  (!!((p) & FD_ACCDB_SIZE_CACHE_CLAIM_BIT))
#define FD_ACCDB_SIZE_PD_WRITE(p)     (!!((p) & FD_ACCDB_SIZE_PD_WRITE_BIT))

FD_STATIC_ASSERT( (10UL<<20) < (1UL<<28), pd_write_bit_collides_with_len );

static inline ulong
fd_accdb_acc_offset( fd_accdb_accmeta_t const * acc ) {
  return acc->offset_fork & FD_ACCDB_OFF_MASK;
}

static inline ushort
fd_accdb_acc_fork_id( fd_accdb_accmeta_t const * acc ) {
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
fd_accdb_acc_xchg_offset( fd_accdb_accmeta_t * acc,
                           ulong               new_offset ) {
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
   "no cached location known".  FD_ACCDB_CACHE_LINE_MAX (defined in
   fd_accdb_cache.h) is the exclusive upper bound on representable
   line indices; per-class slot counts must not exceed it, or cidx
   values would alias. */

#define FD_ACCDB_ACC_CIDX_IDX_MASK  ((uint)(FD_ACCDB_CACHE_LINE_MAX-1UL))
#define FD_ACCDB_ACC_CIDX_INVAL     UINT_MAX
#define FD_ACCDB_ACC_CIDX_PACK(c,i) ((uint)( ((uint)(c)<<FD_ACCDB_CACHE_LINE_BITS) | ((uint)(i) & FD_ACCDB_ACC_CIDX_IDX_MASK) ))
#define FD_ACCDB_ACC_CIDX_CLASS(ci) ((ulong)((uint)(ci) >> FD_ACCDB_CACHE_LINE_BITS))
#define FD_ACCDB_ACC_CIDX_IDX(ci)   ((ulong)((uint)(ci) & FD_ACCDB_ACC_CIDX_IDX_MASK))

#define POOL_NAME       acc_pool
#define POOL_ELE_T      fd_accdb_accmeta_t
#define POOL_NEXT       pool.next
#define POOL_IDX_T      uint
#define POOL_IDX_WIDTH  32
#define POOL_IMPL_STYLE 0
#define POOL_LAZY       1

#include "../../util/tmpl/fd_pool_para.c"

struct fd_accdb_cache_line {
  fd_accdb_cache_key_t key;

  uint acc_idx;
  uint seq; /* incremented each time line is reused */

  uint  refcnt;
  uchar persisted;
  uchar referenced;
  /* Claimed for eviction but still in a reader's hazard list; a later
     sweep takes it once the list is clear. */
  uchar hazard_pending;
  /* Some reader has held this line through its hazard list since the
     line was last taken, so a reclaim has to scan the lists.  Set by
     the reader before it fences and re-checks the account, so a reader
     whose check passed is always seen. */
  uchar hazard_read;

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

static FD_FN_PURE inline ulong
packed_partition_idx( accdb_offset_t const * offset ) {
  return offset->val>>FD_ACCDB_PARTITION_OFF_BITS;
}

static FD_FN_PURE inline ulong
packed_partition_offset( accdb_offset_t const * offset ) {
  return offset->val & ((1UL<<FD_ACCDB_PARTITION_OFF_BITS)-1UL);
}

static FD_FN_PURE inline ulong
packed_partition_file_offset( accdb_offset_t const * offset,
                              ulong                  partition_sz ) {
   return (packed_partition_idx( offset )*partition_sz + packed_partition_offset( offset ));
}

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
  int grow_lock       __attribute__((aligned(64)));

  /* Set non-zero by the snapin tile while a snapshot is being loaded.
     Suppresses compaction enqueue so the compaction tile does not race
     with bulk snapshot writes; fd_accdb_snapshot_load_end performs a
     one-shot sweep to enqueue any partitions that crossed the
     fragmentation threshold during the load. */
  int snapshot_loading;

  /* Set at construction (fd_accdb_shmem_new) when this validator
     supports bundles.  A bundle coalesces up to
     FD_ACCDB_MAX_TXN_PER_ACQUIRE transactions into one acquire, so when
     set, fd_accdb_acquire_inner permits pubkeys_cnt up to
     FD_ACCDB_MAX_ACQUIRE_CNT instead of the single-transaction limit
     FD_ACCDB_MAX_TX_ACCOUNT_LOCKS. */
  int bundle_enabled;

  /* Per-class CLOCK sweep position.  Atomically incremented by
     eviction scans (modulo cache_class_max[c]).  Each element is on
     its own cacheline to avoid false sharing between classes. */
  struct __attribute__((aligned(64))) { ulong val; } clock_hand[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Per-joiner, per-class CAS free lists (Treiber stacks) for
     fully-freed cache lines.  A join pushes to and pops from its own
     lists, one cache line holding its eight class tops that nobody
     else writes unless they have run dry and come to steal.  ver_top
     packs a 32-bit ABA version counter in bits 63..32 and a uint pool
     index in bits 31..0.  UINT_MAX in the low 32 bits means empty. */
  struct __attribute__((aligned(64))) { ulong ver_top[ FD_ACCDB_CACHE_CLASS_CNT ]; } cache_free[ FD_ACCDB_MAX_JOINERS ];

  /* Per-joiner, per-class approximate depth of the free lists.
     Summed over joiners by the background pre-eviction loop to decide
     when to refill. */
  struct __attribute__((aligned(64))) { ulong val[ FD_ACCDB_CACHE_CLASS_CNT ]; } cache_free_cnt[ FD_ACCDB_MAX_JOINERS ];

  /* Per-joiner hazard lists: the packed cidx of every line a join is
     reading without a pin.  A reader stores the cidx, fences, then
     re-checks that the account still names the line; an evictor first
     makes the line unreachable (clears the account's cache_idx), then
     scans every list, and a line found in one stays claimed
     (hazard_pending) until a later sweep finds the lists clear.  A join
     fills from slot 0 and resets cnt when it releases; slots below cnt
     holding FD_ACCDB_ACC_CIDX_INVAL are ones a reader gave up on. */
  struct __attribute__((aligned(64))) { ulong cnt; uint cidx[ 2UL*FD_ACCDB_MAX_ACQUIRE_CNT ]; } cache_hazard[ FD_ACCDB_MAX_JOINERS ];

  /* Per-class hint of which joiners' lists may be non-empty, so a
     steal does not walk every joiner.  Set by a push into an empty
     list whose bit is clear; cleared by a steal that finds the list
     empty, which then looks again and sets it back if a push landed
     meanwhile.  So a set bit may be stale (the list drained without a
     steal noticing; costs the stealer a look) but a list with a line
     on it always has its bit set. */
  struct __attribute__((aligned(64))) { ulong bits[ FD_ACCDB_MAX_JOINERS/64UL ]; } cache_free_have[ FD_ACCDB_CACHE_CLASS_CNT ];

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
     cache_free_low_water[c]: trigger threshold ((target*3)/4). */
  ulong cache_free_target   [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_free_low_water[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Per-layer write heads.  whead[0] is the hot (execution) write
     head, updated with atomic fetch-and-add by acquire/release
     threads.  whead[1..N-1] are compaction write heads, each
     single-writer (compaction tile only). */
  accdb_offset_t whead[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  int            has_partition[ FD_ACCDB_COMPACTION_LAYER_CNT ];

  ulong partition_cnt;
  ulong partition_sz;
  ulong partition_max;         /* acquired high water, for snapshot recovery */
  ulong partition_fallocated;  /* partitions backed by the file, can run ahead */

  ulong chain_cnt;
  ulong max_live_slots;
  ulong max_accounts;
  ulong max_account_writes_per_slot;

  /* Hard upper bound on concurrent joiners, set at construction. */
  ulong joiner_cnt_max;

  /* Per-joiner worst-case cache need, set at construction.  The
     cache is sized so every class holds at least this many lines, so
     a transaction waiting for a full class to drain always gets its
     lines once the others have committed. */
  ulong cache_min_reserved;

  ulong partition_pool_off;

  /* compaction_dlist_off[k] is the byte offset (from shmem base) of
     the dlist sentinel for layer k.  Partitions at layer k that
     reach the freed-bytes threshold are enqueued here for compaction
     into layer k+1, or into layer k itself for the deepest layer. */
  ulong compaction_dlist_off[ FD_ACCDB_COMPACTION_LAYER_CNT ];

  /* Epoch-based grace periods for compaction and resource reclamation.

     Writers advance epoch when enqueueing compaction or retiring resources.
     Compaction and resource reuse wait for the corresponding grace period.

     joiner_epochs[i] holds the epoch observed by joiner i at the start
     of its epoch-protected critical section, or ULONG_MAX when idle.
     A tagged epoch has passed when all published writer and external
     reader epochs are strictly greater than it.

     joiner_cnt is claimed via atomic fetch-and-add in fd_accdb_new
     and never decremented. */
  ulong epoch __attribute__((aligned(64)));

  /* Synchronization with snapshot producer to inhibit compaction
     Holds one of FD_ACCDB_SNAPSHOT_SYNC_* */
  ulong snapshot_sync __attribute__((aligned(64)));

  /* Each joiner epoch is padded to a full cache line to prevent
     false sharing between joiners writing to adjacent slots. */
  struct __attribute__((aligned(64))) { ulong val; } joiner_epochs[ FD_ACCDB_MAX_JOINERS ];
  ulong joiner_cnt __attribute__((aligned(64)));

  /* Number of joins (of either kind) that own free lists in
     cache_free; claimed the same way. */
  ulong free_owner_cnt __attribute__((aligned(64)));
  ulong deferred_free_dlist_off;

  fd_accdb_shmem_metrics_t shmetrics[1];

  /* Command slot for T1 -> T2 offloading of advance_root / purge.
     Padded to its own cache line to avoid false sharing with the
     hot epoch / joiner_epochs fields above. */

#define FD_ACCDB_CMD_IDLE            (0U)
#define FD_ACCDB_CMD_ADVANCE_ROOT    (1U)
#define FD_ACCDB_CMD_PURGE           (2U)
#define FD_ACCDB_CMD_CLEAR_DEFERRED  (3U)
#define FD_ACCDB_CMD_DRAIN_DEFERRED  (4U)

  uint   cmd_op       __attribute__((aligned(64))); /* FD_ACCDB_CMD_* */
  ushort cmd_fork_id;                               /* argument       */

  /* T2-only side buffer for deferred acc unlinks.  Holds the indices of
     accs that have been CAS-unlinked from their map chains in the
     current advance_root or purge call but cannot yet have pool.next
     written: a concurrent cold_load_acc may stomp it via the cache_idx
     union alias.  After wait_for_epoch_drain the list is materialized
     into pool.next links and released via acc_pool_release_chain.

     T2 is the sole writer (advance_root and purge both run on T2 via
     the cmd offload above), so cnt is plain.  Capacity is
     txn_max = max_live_slots * max_account_writes_per_slot, the same
     bound used to size txn_pool.  Stored as a byte offset from shmem
     base. */

  ulong deferred_acc_buf_off;
  ulong deferred_acc_buf_cnt;
  ulong deferred_acc_buf_max;
  ulong deferred_acc_epoch;
  ulong deferred_acc_resident; /* RAM entries before the spill tier  */
  ulong deferred_acc_stage;    /* stage chunk entries, 0 = no spill  */

  /* Disk index (index_ram_entries!=0).  RAM-only mode keeps every
     field below at its RAM-only value and appends no region. */

  ulong index_ram_entries;  /* 0 = RAM-only                        */
  ulong acc_pool_max;       /* acc_pool capacity                   */
  ulong txn_pool_max;       /* txn_pool capacity                   */
  ulong acc_map_off;        /* region offsets for layout mirrors   */
  ulong acc_pool_off;

  ulong idx_bkt_npage;      /* bkt region pages                    */
  ulong idx_bkt_seq_off;
  ulong idx_cf_nb;          /* cuckoo buckets                      */
  ulong idx_cf_off;
  ulong idx_cf_stash_off;
  ulong idx_cf_stash_cnt;
  ulong idx_cf_disabled;
  ulong idx_hot_chain_cnt;  /* pow2                                */
  ulong idx_hot_map_off;
  ulong idx_file_sz;        /* bytes fallocated at boot            */

  ulong idx_bg_defer_off;   /* FD_ACCDB_BG_DEFER_MAX uints         */
  ulong idx_tier_off;       /* acc_pool_max uchars                 */
  ulong idx_hot_ref_off;    /* acc_pool_max uchars, FG sets on hit */
  ulong idx_fifo_off;       /* acc_pool_max ulongs: idx<<32 | gen  */
  ulong fifo_head;          /* T2 only                             */
  ulong fifo_tail;
  ulong hot_cursor;         /* T2 only                             */
  ulong promote_reserve;    /* free slots kept for releases        */
  ulong bg_defer_head;      /* T2 only: total appended             */
  ulong bg_defer_tail;      /* T2 only: total released             */
  ulong bg_defer_sealed;    /* T2 only: entries below are tagged   */
  ulong bg_defer_tag[ FD_ACCDB_BG_DEFER_CHUNKS ];

  ulong idx_cf_seq __attribute__((aligned(64)));

  /* Free accmeta slots not yet reserved by a release (index mode).
     FG CAS-subtracts before publishing its epoch, T2 credits after
     each deferred release. */
  ulong pool_avail __attribute__((aligned(64)));

  acc_pool_shmem_t  acc_pool [1];
  fork_pool_shmem_t fork_pool[1];
  txn_pool_shmem_t  txn_pool [1];

  /* Track accounts modified since full snapshot.

       ------------++++++++.......                       - pruned blocks
       ^           ^      ^      ^                       + active blocks
       full snap   root   head   incremental (future)    . future blocks

     The validator thus needs to track the addresses of all accounts
     that have changed since the last full snapshot.  accdb forks cannot
     be used for this as fork information at the full snapshot slot is
     discarded.

     accdb deltas track this missing information. */

  struct {
    ulong seed;
    ulong chain_off;
    uint  chain_cnt;  /* power of 2 */
    uint  chain_mask; /* chain_cnt-1, contiguous runs of one bits */
    ulong ele_off;
    ulong ele_max;
    ulong head; /* bump alloc head */
  } delta;

  ulong magic; /* ==FD_ACCDB_SHMEM_MAGIC */
};

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_private_h */
