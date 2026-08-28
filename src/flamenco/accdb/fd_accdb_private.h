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

/* ---------------------------------------------------------------------
   Per-fork txn store: sealed chunks with a T2 disk spill tier.

   A txn record is one committed write: just the acc pool index of the
   new version (4 bytes).  The acc_map chain index is not stored: it is
   pure derived data, fd_hash32( acc_pool[ idx ].key.pubkey, seed )&
   (chain_cnt-1), recomputed by the T2 walks (advance_root / purge)
   that consume these records.  The pubkey is stable for the record's
   lifetime: the accmeta slot it references is only released by those
   same T2 walks (via the deferred buffer, after epoch drain) and
   demotion never touches txn-referenced entries (their generation is
   always within FD_ACCDB_DEMOTE_AGE of the root's).

   Records are append-only per fork and consumed only by linear walks
   (advance_root / purge / snapshot recover_delta) once the fork is
   quiescent, so they live in per-fork chains of fixed-size CHUNKS
   instead of a global random-access pool:

     - fork.txn_cursor is a monotonic per-fork entry count; appenders
       FAA it, entry off lives at slot off%CAP of chunk off/CAP.
     - The appender that draws slot 0 of a chunk installs it: acquire
       a node, pop a RAM data slot from the ring, wait for chunk_no-1
       to be published (installs are ordered; ABA-free because the
       cursor never goes backwards), prepend to fork.txn_head.
     - node.fill counts COMPLETED entry writes; a chunk is sealed
       (spillable) only at fill==CAP, so a reservation is never
       confused with a written entry.
     - Walks run newest chunk -> oldest, entries within a chunk
       backwards, preserving the reverse-append order that the
       duplicate-pubkey unlink logic in advance_root depends on.

   The RAM ring holds the mainnet working set (a ~128-slot root-lag
   window of worst-case writes, plus one partial chunk per live fork
   plus reservation headroom).  Under ring pressure (multi-hundred-slot
   no-root stalls, catchup, large incremental loads) sealed chunks of
   the oldest forks are pwritten to the scratch spill file and pread
   back at consume time; full capacity (txn_max entries) is provisioned
   across ring + fallocated disk slots, so the abort-free guarantee is
   bit-for-bit today's.  When the ring already covers full capacity
   (small configs, tests), no tiering is active and exhaustion aborts
   exactly like the old pool.

   DEADLOCK AVOIDANCE: the append in release_inner runs inside the
   joiner-epoch critical section while T2's advance_root/purge begin
   with wait_for_epoch_drain, so an appender must never block on the
   ring while holding an epoch.  release_inner reserves worst-case
   chunk credits (txn_ring_free) BEFORE publishing its epoch, spinning
   outside the epoch when the ring is dry; credits are a conservative
   lower bound on actual free slots (reserve subtracts early, refunds
   settle by actual pops), so a credit-backed pop cannot fail. */

#define FD_ACCDB_TXN_CHUNK_LG_CAP (12)
#define FD_ACCDB_TXN_CHUNK_CAP    (1UL<<FD_ACCDB_TXN_CHUNK_LG_CAP)  /* entries; 16 KiB data */
#define FD_ACCDB_TXN_NODE_DISK    (0x80000000U)                     /* node.loc: spilled    */

struct fd_accdb_txn_node {
  uint pool_next; /* node pool freelist                              */
  uint next;      /* next-older chunk on the fork chain, UINT_MAX end */
  uint chunk_no;  /* position on the fork, == first entry off / CAP  */
  uint loc;       /* RAM ring slot, or disk slot | TXN_NODE_DISK     */
  uint fill;      /* completed entry writes; ==CAP means sealed      */
};

typedef struct fd_accdb_txn_node fd_accdb_txn_node_t;

#define POOL_NAME       txn_node_pool
#define POOL_ELE_T      fd_accdb_txn_node_t
#define POOL_NEXT       pool_next
#define POOL_IDX_T      uint
#define POOL_IDX_WIDTH  32
#define POOL_IMPL_STYLE 0
#define POOL_LAZY       1

#include "../../util/tmpl/fd_pool_para.c"

/* Freelists for chunk data slots (RAM ring and disk file). */

struct fd_accdb_txn_slot {
  uint next;
};

typedef struct fd_accdb_txn_slot fd_accdb_txn_slot_t;

#define POOL_NAME       txn_rslot_pool
#define POOL_ELE_T      fd_accdb_txn_slot_t
#define POOL_NEXT       next
#define POOL_IDX_T      uint
#define POOL_IDX_WIDTH  32
#define POOL_IMPL_STYLE 0
#define POOL_LAZY       1

#include "../../util/tmpl/fd_pool_para.c"

#define POOL_NAME       txn_dslot_pool
#define POOL_ELE_T      fd_accdb_txn_slot_t
#define POOL_NEXT       next
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

  uint  txn_head;   /* newest txn chunk node, UINT_MAX none         */
  ulong txn_cursor; /* monotonic per-fork txn entry count (FAA'd)   */
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

/* ---------------------------------------------------------------------
   Disk-resident index (bucket) tier.

   When index_ram_max is non-zero, the accmeta pool is bounded to
   index_ram_max entries and the full index lives in a flat
   fixed-geometry hash file (the "bucket" file) accessed exclusively
   with explicit pread/pwrite.  RAM holds only the unrooted fork
   overlay, rooted-but-not-yet-demoted versions (acc_map), and a
   bounded read cache of promoted rooted entries (hot_map).  All
   validator memory stays locked in hugetlbfs workspaces; disk
   residency is explicit I/O, never demand paging.

   Bucket file geometry: 4 KiB pages, each a 64 B header plus 63 64 B
   slots.  page(pubkey) = fastrange64( fd_hash32( pubkey, seed^SALT ),
   npage ).  Collision overflow is linear probing to the next page; a
   page that ever overflowed carries a sticky flag so lookups know to
   continue past it (deletes never clear the flag).  Load factor is
   capped at 0.5 so overflow is vanishingly rare (Poisson mean <=31.5
   keys on 63 slots).

   A per-page seqlock word array lives in the workspace.  T2 (and the
   snapin placement pass, disjoint in time) is the sole bucket writer;
   every page write is bracketed odd/even.  Readers pread the page and
   validate against the shmem word.  Correctness relies on buffered
   same-thread pwritev2 (copy_from_user executes on the writing thread,
   TSO-ordered against the seqlock stores).

   A single blocked bloom filter (10 bits/key over max_accounts) is the
   RAM negative oracle: bloom-negative proves a key is not in the
   bucket (inserts happen before the RAM entry is unlinked; deletes
   accumulate as stale positives that only cost a wasted pread). */

#define FD_ACCDB_IDX_PAGE_SZ     (4096UL)
#define FD_ACCDB_IDX_SLOT_CNT    (63UL)
#define FD_ACCDB_IDX_PROBE_MAX   (64UL)
#define FD_ACCDB_IDX_PAGE_STICKY (1U)

/* fork_id stored in promoted (hot_map) entries' offset_fork.  Promoted
   entries are rooted, so the generation<=root_generation fast path
   makes them visible to all forks and the fork bits are never
   consulted; the sentinel just makes them identifiable (compaction's
   bucket re-sync, debugging).  max_live_slots<USHORT_MAX so real fork
   ids never reach this value. */
#define FD_ACCDB_FORK_ID_ROOTED  ((ushort)(USHORT_MAX-1U))

/* hot_map chain head encoding: bit 31 = insert/remove claim bit,
   low 31 bits = acc_pool index or FD_ACCDB_HOT_EMPTY.  Entry links use
   accmeta.map.next with UINT_MAX terminator (an entry is linked in
   exactly one of acc_map/hot_map at a time, so the field is shared).
   Pool indices are < 2^31 (index_ram_max bounded), so "empty" and
   "claimed" cannot collide. */
#define FD_ACCDB_HOT_EMPTY (0x7FFFFFFFU)
#define FD_ACCDB_HOT_CLAIM (0x80000000U)

/* Deferred-free entries tagged MIGRATED are pool slots whose bytes and
   bucket slot live on (demotion / hot eviction): the drain sweep must
   not free their data bytes or decrement accounts_total. */
#define FD_ACCDB_DEFER_MIGRATED (0x80000000U)

struct __attribute__((packed)) fd_accdb_idx_slot {
  uchar pubkey[ 32UL ];
  ulong off_plus1;       /* 0 = empty slot, else data file offset + 1 */
  ulong lamports;        /* always non-zero for a live slot           */
  uint  executable_size; /* data size | EXEC bit; no RAM-only bits    */
  uint  generation;      /* version's original commit generation      */
  ulong slot;            /* snapshot slot at placement; 0 afterwards  */
};

typedef struct fd_accdb_idx_slot fd_accdb_idx_slot_t;

FD_STATIC_ASSERT( sizeof(fd_accdb_idx_slot_t)==64UL, idx_slot_layout );

struct fd_accdb_idx_page {
  uint  flags;           /* FD_ACCDB_IDX_PAGE_STICKY */
  uchar pad[ 60UL ];
  fd_accdb_idx_slot_t slot[ FD_ACCDB_IDX_SLOT_CNT ];
};

typedef struct fd_accdb_idx_page fd_accdb_idx_page_t;

FD_STATIC_ASSERT( sizeof(fd_accdb_idx_page_t)==FD_ACCDB_IDX_PAGE_SZ, idx_page_layout );

/* npage such that load factor max_accounts/(npage*63) <= 0.5 */

static FD_FN_CONST inline ulong
fd_accdb_idx_npage( ulong max_accounts ) {
  return ( 2UL*max_accounts + FD_ACCDB_IDX_SLOT_CNT-1UL )/FD_ACCDB_IDX_SLOT_CNT;
}

static FD_FN_CONST inline ulong
fd_accdb_idx_page_of( ulong hash,
                      ulong npage ) {
  return (ulong)( ( (__uint128_t)hash * (__uint128_t)npage )>>64 );
}

/* Blocked bloom filter: 64 B (8 ulong) blocks, 8 probe bits per key,
   ~10 bits/key budget. */

static FD_FN_CONST inline ulong
fd_accdb_idx_bloom_sz( ulong max_accounts ) {
  return fd_ulong_align_up( max_accounts*10UL/8UL, 64UL );
}

static inline int
fd_accdb_idx_bloom_probe( ulong * bloom,     /* NULL for test-only via const cast at caller */
                          ulong   bloom_sz,
                          ulong   h1,
                          ulong   h2,
                          int     insert ) {
  ulong   nblock = bloom_sz>>6;
  ulong * block  = bloom + 8UL*fd_accdb_idx_page_of( h1, nblock );
  int hit = 1;
  for( ulong j=0UL; j<8UL; j++ ) {
    ulong bit = 1UL<<( ( h2>>(6UL*j) ) & 63UL );
    if( insert ) FD_ATOMIC_FETCH_AND_OR( &block[ j ], bit );
    else         hit &= !!( FD_VOLATILE_CONST( block[ j ] ) & bit );
  }
  return hit;
}

/* Spill/placement constants for full-snapshot bucket construction.
   Spill records (fd_accdb_idx_slot_t) are appended to per-range
   extents of the index file beyond the bucket pages; the placement
   pass then scatters each range into a RAM window and writes the
   range's pages sequentially. */

#define FD_ACCDB_IDX_WINDOW_SZ   (256UL<<20)  /* placement RAM window   */
#define FD_ACCDB_IDX_STAGE_SZ    (64UL<<10)   /* per-range append stage */
#define FD_ACCDB_IDX_CARRY_MAX   (8192UL)     /* cross-range overflow   */

/* Deferred-free buffer tiering.  The buffer must hold txn_max entries
   (worst single advance_root/purge prunes a ~max_live_slots-deep
   competing subtree; exhaustion is FD_TEST abort), but only a small
   window is ever populated on mainnet (~1 rooted slot of unlinks per
   call).  Locked RAM holds the first DEFER_RESIDENT entries plus one
   DEFER_STAGE staging chunk; past the resident window T2 pwrites full
   stage chunks to the scratch spill file (explicit I/O, fallocated to
   full capacity up front) and preads them back at drain.  T2 is the
   sole writer and consumer; the spill cursor is derived entirely from
   deferred_acc_buf_cnt so a direct cnt reset discards spilled data.
   The stage size divides the window so drain preads are sequential
   full chunks. */

#define FD_ACCDB_DEFER_WINDOW_ELE (16UL<<20)  /* 64 MiB locked window  */
#define FD_ACCDB_DEFER_STAGE_ELE  (2UL<<20)   /* 8 MiB spill I/O chunk */

/* Demotion age threshold, in generations (~slots).  A rooted version
   is only written back to the bucket once it has gone this long
   without being superseded, so per-slot rewriters (vote accounts)
   never churn bucket I/O: their versions are superseded before they
   age out. */
#define FD_ACCDB_DEMOTE_AGE      (64U)

struct fd_accdb_idx_range {
  ulong spill_sz;   /* bytes appended to this range's spill extent */
  uint  stage_cnt;  /* records currently in the RAM stage buffer   */
  uint  pad;
};

typedef struct fd_accdb_idx_range fd_accdb_idx_range_t;

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

/* The `size` field in fd_accdb_disk_meta_t (named executable_size in
   fd_accdb_accmeta_t) packs five things into 32 bits:

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

   The on-disk representation (written via SIZE_PACK / SIZE_DATA) carries
   no in-memory flag: persisted bytes are unchanged, and compaction's
   copy_file_range preserves the record headers verbatim without
   rewriting them. */

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
     cache_free_low_water[c]: trigger threshold ((target*3)/4). */
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

  /* Per-joiner worst-case cache reservation, set at construction.
     Used by fd_accdb_reset to replicate the cache_class_used sentinel
     logic from fd_accdb_shmem_new. */
  ulong cache_min_reserved;

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

  /* Synchronization with snapshot producer to inhibit compaction
     Holds one of FD_ACCDB_SNAPSHOT_SYNC_* */
  ulong snapshot_sync __attribute__((aligned(64)));

  /* Each joiner epoch is padded to a full cache line to prevent
     false sharing between joiners writing to adjacent slots. */
  struct __attribute__((aligned(64))) { ulong val; } joiner_epochs[ FD_ACCDB_MAX_JOINERS ];
  ulong joiner_cnt __attribute__((aligned(64)));
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

  /* Deferred buffer RAM window split (see the DEFER tiering comment
     above).  resident+stage entries are backed by the buf region;
     stage==0 means the whole capacity is resident and no spill can
     occur (small txn_max, tests). */
  ulong deferred_acc_resident;
  ulong deferred_acc_stage;

  /* Disk-resident index state.  index_ram_max==0 selects RAM-only mode
     (pool sized max_accounts, none of the structures below exist,
     behavior is bit-for-bit the pre-disk-index database). */

  ulong index_ram_max;   /* accmeta pool bound, 0 = RAM-only        */
  ulong pool_max;        /* actual acc_pool capacity                */
  ulong hot_chain_cnt;   /* pow2 hot_map chain head count           */
  ulong idx_npage;       /* bucket file page count                  */
  ulong idx_bloom_sz;    /* bloom filter bytes (one copy)           */
  ulong idx_spill_base;  /* spill region base offset in index file  */
  ulong idx_spill_extent;/* per-range spill extent bytes            */
  ulong idx_nrange;      /* placement range count                   */

  /* Txn chunk store geometry (see the chunk-store comment above).
     txn_ring_cnt==txn_node_max means the ring covers full capacity
     and tiering (credits, spill) is inactive. */
  ulong txn_node_max;   /* chunk node pool capacity                  */
  ulong txn_ring_cnt;   /* RAM ring data slots                       */
  ulong txn_dslot_cnt;  /* disk data slots in the scratch file       */
  ulong txn_spill_off;  /* chunk region base offset in scratch file  */

  /* Ring credit ledger: conservative count of free RAM ring slots
     (reservations subtract before their epoch, refunds settle by
     actual pops, releases/spills add).  Signed arithmetic on a ulong;
     transiently negative during refund races. */
  struct __attribute__((aligned(64))) { ulong val; } txn_ring_free;

  /* Region offsets from shmem base (also for pre-existing regions so
     joiners need not mirror the layout computation). */
  ulong fork_pool_ele_off;
  ulong descends_off;
  ulong acc_map_off;
  ulong acc_pool_ele_off;
  ulong txn_node_ele_off;
  ulong txn_rslot_ele_off;
  ulong txn_dslot_ele_off;
  ulong txn_chunk_data_off;
  ulong partition_pool_region_off; /* raw region (partition_pool_off
                                      above is the joined pointer)    */
  ulong hot_map_off;      /* hot_chain_cnt uints                     */
  ulong idx_seqlock_off;  /* idx_npage uints                         */
  ulong idx_bloom_off;    /* idx_bloom_sz bytes                      */
  ulong idx_range_off;    /* idx_nrange fd_accdb_idx_range_t         */
  ulong idx_stage_off;    /* idx_nrange * FD_ACCDB_IDX_STAGE_SZ      */
  ulong idx_window_off;   /* FD_ACCDB_IDX_WINDOW_SZ placement window */
  ulong idx_carry_off;    /* FD_ACCDB_IDX_CARRY_MAX slots            */

  /* T2-only demote/evict bookkeeping. */
  ulong demote_chain_cursor; /* acc_map sweep position               */
  ulong hot_evict_cursor;    /* hot_map sweep position               */
  ulong idx_carry_cnt;       /* placement cross-range overflow count */

  /* Live accmeta pool occupancy (FAA at acquire sites, subtracted when
     deferred batches release).  Drives hot_map eviction. */
  struct __attribute__((aligned(64))) { ulong val; } acc_pool_used;

  acc_pool_shmem_t        acc_pool      [1];
  fork_pool_shmem_t       fork_pool     [1];
  txn_node_pool_shmem_t   txn_node_pool [1];
  txn_rslot_pool_shmem_t  txn_rslot_pool[1];
  txn_dslot_pool_shmem_t  txn_dslot_pool[1];

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
