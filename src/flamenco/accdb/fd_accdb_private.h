#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_private_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_private_h

#include "fd_accdb_base.h"
#include "fd_accdb_shmem.h"
#include "fd_accdb_cache.h"
#include "../../util/racesan/fd_racesan_target.h"
#include "../fd_rwlock.h"

/* fd_spinlock_t is a plain mutex for accdb's rare slow paths
   (partition switches, file growth): Reuse fd_rwlock_t instead
   of rolling custom ones.  Uses defines instead of wrapper functions
   to keep thread-safety annotations from fd_rwlock. */

typedef fd_rwlock_t fd_spinlock_t;

#define fd_spinlock_new     fd_rwlock_new
#define fd_spinlock_acquire fd_rwlock_write
#define fd_spinlock_release fd_rwlock_unwrite

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

/* fd_accdb_req_t is the root / purge request word (T1 -> T2) and
   fd_accdb_done_t the matching progress word (T2 -> T1).  Each is
   written by a single thread with one 8-byte store, so a reader always
   sees a consistent set of fields. */

union __attribute__((aligned(8))) fd_accdb_req {
  struct {
    uint               root_gen;   /* generation of the latest requested root */
    ushort             purge_seq;  /* purges requested so far, mod 2^16 */
    fd_accdb_fork_id_t purge_fork; /* latest purged fork */
  };
  ulong u;
};

typedef union fd_accdb_req fd_accdb_req_t;

union __attribute__((aligned(8))) fd_accdb_done {
  struct {
    uint   root_gen;  /* generation of root_fork_id */
    ushort purge_seq; /* purges applied so far, mod 2^16 */
    ushort retiring;  /* 1 while a retired batch awaits release */
  };
  ulong u;
};

typedef union fd_accdb_done fd_accdb_done_t;

FD_STATIC_ASSERT( sizeof(fd_accdb_req_t )==sizeof(ulong), req  );
FD_STATIC_ASSERT( sizeof(fd_accdb_done_t)==sizeof(ulong), done );

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
     fd_accdb_shmem_try_enqueue_compaction.  The compaction tile will not
     begin reading from this partition until all joiners that were in an
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

/* Deferred entry tag: pool slot moved between tiers, its bytes live
   on in the new slot.  The unlinker must not free the record; the
   drain frees no bytes in any case and strips the tag. */
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

/* Demote FIFO tiering (index mode).  Capacity stays acc_pool_max.
   Past FIFO_WINDOW, RAM holds FIFO_SLOTS chunks of FIFO_CHUNK entries;
   T2 pwrites an evicted live chunk to the scratch file tail and preads
   it back when reached.  No I/O while the live span fits SLOTS-1
   chunks (>=3Mi entries; mainnet ~0.3M). */

#define FD_ACCDB_FIFO_CHUNK  (1UL<<19)  /* 4 MiB spill I/O chunk */
#define FD_ACCDB_FIFO_SLOTS  (8UL)
#define FD_ACCDB_FIFO_WINDOW (FD_ACCDB_FIFO_SLOTS*FD_ACCDB_FIFO_CHUNK)

#define FD_ACCDB_DEMOTE_AGE   (64U)   /* generations before demotion */
#define FD_ACCDB_DEMOTE_BATCH (64UL)  /* per background call         */
#define FD_ACCDB_HOT_SWEEP    (256UL) /* hot chains per call         */
#define FD_ACCDB_COMPACT_IDX_IO (16UL) /* compaction bucket lookups per call */

/* Promote rings (index mode).  Residual lane: FG waiters, never
   drops.  Hint lane: prefetch, dropped when full.  Producers reserve
   with a CAS after a fullness check, so no slot is ever owned and left
   unpublished. */
#define FD_ACCDB_RING_RES_CAP  (4096UL)
#define FD_ACCDB_RING_HINT_CAP (65536UL)
#define FD_ACCDB_RING_SERVE    (256UL)  /* hint requests per call  */
#define FD_ACCDB_PROT_MAX      (4096UL)

#define FD_ACCDB_REQ_WARM_PD   (1U)     /* also promote programdata */

struct __attribute__((aligned(64))) fd_accdb_promote_req {
  uchar pubkey[ 32 ];
  ulong seq;      /* ticket+1 once published */
  uint  joiner;   /* residual: epoch slot index */
  uint  flags;
  ushort ovl_fork; /* REQ_UNSPILL: spilled fork to search */
  ushort slot;     /* residual: index into the joiner's answer row */
  uchar pad[ 12 ];
};

typedef struct fd_accdb_promote_req fd_accdb_promote_req_t;

struct fd_accdb_promote_ring {
  ulong tail __attribute__((aligned(64))); /* producers (CAS) */
  ulong head __attribute__((aligned(64))); /* T2 published    */
  ulong done __attribute__((aligned(64))); /* T2: served < done */
  ulong cap;
  ulong ele_off;
};

typedef struct fd_accdb_promote_ring fd_accdb_promote_ring_t;

struct fd_accdb_prot {
  uint  idx;
  uint  joiner;
  ulong ticket;
};

typedef struct fd_accdb_prot fd_accdb_prot_t;

#define FD_ACCDB_HOT_REF_PROT (2)

#define FD_ACCDB_REQ_UNSPILL   (2U)     /* also look in spilled forks */
#define FD_ACCDB_TIER_UNSPILL  (3)      /* acc_map copy of a spilled version */
#define FD_ACCDB_SPILL_SLICE   (256UL)  /* versions per background call */
#define FD_ACCDB_UNSPILL_MAX   (1UL<<15) /* unspill FIFO slots; live copies <= half */
FD_STATIC_ASSERT( FD_ACCDB_UNSPILL_MAX/2UL>FD_ACCDB_PROT_MAX, unspill_victim ); /* an unprotected copy always exists at the cap */

/* idx_fork.frozen: 0 live (releases may target it), 1 parked or
   complete (no release until fd_accdb_fork_thaw), 2 claimed by T2 for
   spill.  Only 1 is spillable; thawing a 2 has T2 restore the fork. */
struct fd_accdb_idx_fork {
  uint  frozen;
  uint  spilled;    /* versions live in ovl + olog        */
  uint  olog_head;  /* chunk, UINT_MAX = none             */
  uint  olog_tail;
  ulong olog_cnt;
};

typedef struct fd_accdb_idx_fork fd_accdb_idx_fork_t;

/* Index tier (T2 only, accmeta executable_size bits 25..24): where T2
   last put a slot. */
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

  /* map.next links the accmeta into exactly one list at a time: its
     acc_map hash chain while linked, the deferred free stack after
     acc_unlink (FD_ACCDB_SIZE_UNLINKED_BIT set first), and the acc_pool
     free list once released (acc_pool's POOL_NEXT).  Chain walkers load
     map.next, then check the unlinked bit (fd_accdb_acc_unlinked), then
     follow map.next. */
  struct {
    uint next;
  } map;

  /* The account's data word: the line its bytes are cached in (cidx,
     meaningful while VALID is set) and its size word es (length, exec,
     pd_write, VALID, unlinked).  Changed only by a single store, CAS,
     swap or OR of the whole word (fd_accdb.c "Data word").  While a
     snapshot loads, cidx holds the record's snapshot slot (VALID
     clear). */
  union {
    struct {
      uint cache_idx;
      uint executable_size;
    };
    ulong data;
  };

  ulong  lamports;

  /* Pack offset and fork_id together into a single ulong to pack the
     struct into a single 64 byte cache line.  This is a performance win
     of 2-3%. */
  ulong  offset_fork;
};

typedef struct fd_accdb_accmeta fd_accdb_accmeta_t;

FD_STATIC_ASSERT( alignof(fd_accdb_accmeta_t)==64, layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_accmeta_t)==64, layout );
FD_STATIC_ASSERT( offsetof(fd_accdb_accmeta_t, data)==offsetof(fd_accdb_accmeta_t, cache_idx), layout );

#define FD_ACCDB_DATA_CIDX(d)  ( (uint)(d) )
#define FD_ACCDB_DATA_ES(d)    ( (uint)( (ulong)(d)>>32 ) )
#define FD_ACCDB_DATA(cidx,es) ( ( (ulong)(uint)(es)<<32 ) | (ulong)(uint)(cidx) )

/* The disk offset (the low 48 bits of offset_fork) is in one of four
   states:

     CLEAN        a record offset, below 2^47 (fd_accdb_shmem_new checks
                  the file fits): the version's bytes are on disk.
     DIRTY(cidx)  line cidx holds the only copy (committed, not
                  written back).  The account is bound to that line.
     UPDATING     a commit that keeps the accmeta is rewriting the
                  version (DIRTY of no line).
     DEAD         unlinked: no record, and none will be published.

   Only a clean version is ever unbound from its line, so an unbound
   version's offset is CLEAN or DEAD. */

#define FD_ACCDB_OFF_BITS      48UL
#define FD_ACCDB_OFF_MASK      ((1UL<<FD_ACCDB_OFF_BITS)-1UL)
#define FD_ACCDB_OFF_DIRTY_BIT (1UL<<47)
#define FD_ACCDB_OFF_DIRTY(ci) ( FD_ACCDB_OFF_DIRTY_BIT | (ulong)(uint)(ci) )
#define FD_ACCDB_OFF_UPDATING  FD_ACCDB_OFF_DIRTY( UINT_MAX )
#define FD_ACCDB_OFF_DEAD      FD_ACCDB_OFF_MASK
#define FD_ACCDB_OFF_CLEAN(o)  ( !( (o) & FD_ACCDB_OFF_DIRTY_BIT ) )

/* The in-memory executable_size field in fd_accdb_accmeta_t packs
   five things into 32 bits:

     bit  31     executable flag                       (FD_ACCDB_SIZE_EXEC_BIT)
     bit  30     cache_valid flag, in-memory only      (FD_ACCDB_SIZE_CACHE_VALID_BIT)
     bit  28     pd_write flag,    in-memory only      (FD_ACCDB_SIZE_PD_WRITE_BIT)
     bit  27     unlinked flag,    in-memory only      (FD_ACCDB_SIZE_UNLINKED_BIT)
     bit  26     spare
     bits 25..24 index tier,       in-memory only      (FD_ACCDB_SIZE_TIER_MASK)
     bits 23..0  data length in bytes                  (FD_ACCDB_SIZE_MASK)

   (bit 29 is spare too: the CACHE_CLAIM lock it held is gone.)

   The data length is therefore 24 bits, max 16 MiB, still above
   FD_RUNTIME_ACC_SZ_MAX of 10 MiB (enforced by the static assert below).

   The tier (index mode, FD_ACCDB_TIER_*) is read and written only by
   T2, with atomic RMWs of the whole data word (fd_accdb_acc_es_or /
   _and) on any accmeta FG can reach, so they compose with the binders'
   and evictors' CAS of the word.  Fresh slot inits store NONE; the
   in-place overwrite preserves it.

   The cache_valid, pd_write, unlinked and tier bits exist only in the
   in-memory index, never on disk:
     - cache_valid (bit 30): when set, cache_idx holds a valid
       (class, idx) pair; when clear, cache_idx must not be dereferenced
       (it may hold a snapshot slot number or garbage).
     - pd_write (bit 28): set on a committed version whose write changed
       BPF upgradeable-loader deploy status this slot (Deploy/Upgrade/
       Extend/Close).  Meaningful only while the accmeta's key.generation
       equals a live fork's generation (i.e. the version was committed on
       that fork this slot); across snapshot/root boundaries the bit is
       dead by construction because the generation no longer matches any
       live fork.  Carried explicitly by the two commit sites in
       fd_accdb_release and nowhere else.
     - unlinked (bit 27): set once, by the accdb tile, after the accmeta
       is spliced out of its hash chain and before map.next is reused to
       link it into the deferred free stack.  A chain walker loads
       map.next, then executable_size; if it sees this bit, the next it
       loaded may already point into the stack, so it restarts from the
       chain head.  Cleared only when the accmeta is reinitialized from
       the pool.

   The on-disk fd_accdb_disk_meta_t.size is only the raw data length,
   written via FD_ACCDB_SIZE_DATA.  It includes neither the executable
   bit nor the cache/PD flags.  Compaction preserves these record
   headers verbatim. */

#define FD_ACCDB_SIZE_EXEC_BIT        (1U<<31)
#define FD_ACCDB_SIZE_CACHE_VALID_BIT (1U<<30)
#define FD_ACCDB_SIZE_PD_WRITE_BIT    (1U<<28)
#define FD_ACCDB_SIZE_UNLINKED_BIT    (1U<<27)
#define FD_ACCDB_SIZE_TIER_SHIFT      (24)
#define FD_ACCDB_SIZE_TIER_MASK       (3U<<FD_ACCDB_SIZE_TIER_SHIFT)
#define FD_ACCDB_SIZE_MASK            ((1U<<24)-1U)
#define FD_ACCDB_SIZE_PACK(sz,exec)   ((uint)(sz) | ((exec) ? FD_ACCDB_SIZE_EXEC_BIT : 0U))
#define FD_ACCDB_SIZE_DATA(packed)    ((packed) & FD_ACCDB_SIZE_MASK)
#define FD_ACCDB_SIZE_EXEC(packed)    (!!((packed) & FD_ACCDB_SIZE_EXEC_BIT))
#define FD_ACCDB_SIZE_CACHE_VALID(p)  (!!((p) & FD_ACCDB_SIZE_CACHE_VALID_BIT))
#define FD_ACCDB_SIZE_PD_WRITE(p)     (!!((p) & FD_ACCDB_SIZE_PD_WRITE_BIT))
#define FD_ACCDB_SIZE_UNLINKED(p)     (!!((p) & FD_ACCDB_SIZE_UNLINKED_BIT))

#define FD_ACCDB_SIZE_TIER(p)         (((p) & FD_ACCDB_SIZE_TIER_MASK)>>FD_ACCDB_SIZE_TIER_SHIFT)

FD_STATIC_ASSERT( (10UL<<20) <= FD_ACCDB_SIZE_MASK, tier_bits_collide_with_len );
FD_STATIC_ASSERT( !( FD_ACCDB_SIZE_TIER_MASK & (FD_ACCDB_SIZE_UNLINKED_BIT|FD_ACCDB_SIZE_PD_WRITE_BIT|FD_ACCDB_SIZE_CACHE_VALID_BIT|FD_ACCDB_SIZE_EXEC_BIT|FD_ACCDB_SIZE_MASK) ), tier_bits_overlap );

/* fd_accdb_acc_unlinked returns 1 if acc was unlinked from its hash
   chain after the caller loaded its map.next (see the unlinked bit
   above).  Callers load map.next first, then call this; on 1 they must
   restart their chain walk from the head.  TSO: loads are not
   reordered, so the compiler fence alone orders the two loads. */

static inline int
fd_accdb_acc_unlinked( fd_accdb_accmeta_t const * acc ) {
  FD_COMPILER_MFENCE();
  return FD_ACCDB_SIZE_UNLINKED( FD_VOLATILE_CONST( acc->executable_size ) );
}
/* fd_accdb_acc_es_or / _and atomically OR / AND bits into acc's size
   word, as one RMW of the whole data word (the word is changed only by
   whole-word stores, CAS and RMWs, see fd_accdb.c "Data word"). */

static inline void
fd_accdb_acc_es_or( fd_accdb_accmeta_t * acc,
                    uint                 bits ) {
  FD_ATOMIC_FETCH_AND_OR( &acc->data, (ulong)bits<<32 );
}

static inline void
fd_accdb_acc_es_and( fd_accdb_accmeta_t * acc,
                     uint                 mask ) {
  FD_ATOMIC_FETCH_AND_AND( &acc->data, ((ulong)mask<<32) | (ulong)UINT_MAX );
}

/* fd_accdb_acc_tier_set sets acc's tier (only T2 writes tier bits, so
   one RMW from the loaded value suffices). */

static inline void
fd_accdb_acc_tier_set( fd_accdb_accmeta_t * acc,
                       uint                 tier ) {
  uint cur = FD_ACCDB_DATA_ES( FD_VOLATILE_CONST( acc->data ) ) & FD_ACCDB_SIZE_TIER_MASK;
  FD_ATOMIC_FETCH_AND_XOR( &acc->data, (ulong)( cur ^ (tier<<FD_ACCDB_SIZE_TIER_SHIFT) )<<32 );
}


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
#define POOL_NEXT       map.next
#define POOL_IDX_T      uint
#define POOL_IDX_WIDTH  32
#define POOL_IMPL_STYLE 0
#define POOL_LAZY       1

#include "../../util/tmpl/fd_pool_para.c"

/* A cache line: this 64 byte header, then the data.  state is one of
   FD_ACCDB_LINE_*:

     FREE     anyone may take it, with one CAS to OWNED.  Free lists are
              only hints (fd_accdb.c "Free lines").
     OWNED    private to one join: staging, a cold load or commit being
              filled, just taken.
     SHARED   holds account acc_idx's bytes, and the account is bound to
              it (or was: an orphan, whose bytes are dead).
     EVICTING one evictor owns it.  Its holders keep reading it; a new
              holder waits until it ends (SHARED again, or unbound).

   A reader holds a line by an entry in its join's hazard list, never
   by a count on the line.  seq is odd while the bytes are unstable
   (from a take until they are filled, and around an in-place commit),
   for readers that copy without holding the line. */

struct fd_accdb_cache_line {
  uint  acc_idx;
  uint  _pad0;
  ulong seq;
  uchar state;
  uchar hot;      /* CLOCK hint: set by hits (only if clear), spent by the sweep */
  uchar _pad1[ 14 ];
  uchar owner[ 32UL ];
};

typedef struct fd_accdb_cache_line fd_accdb_cache_line_t;

FD_STATIC_ASSERT( offsetof(fd_accdb_cache_line_t, owner)==32UL, layout );

#define FD_ACCDB_LINE_FREE    ((uchar)0)
#define FD_ACCDB_LINE_OWNED   ((uchar)1)
#define FD_ACCDB_LINE_SHARED  ((uchar)2)
#define FD_ACCDB_LINE_EVICTING ((uchar)3)

/* fd_accdb_line_read_unheld copies owner (32 bytes) and data_sz bytes
   of data out of line, which the caller found the account bound to
   (data word d, loaded with acquire from *data_word), without holding
   the line (read_one_nocache, backup).  Returns 1 if the copy is good:
   the account is still bound to the line, and seq was even and
   unchanged from before the copy until after that check.  The word is
   checked first: seq never goes back, so an equal seq after it spans
   the copy and the check, and the copy is of the incarnation the word
   names.  The caller's epoch keeps the accmeta from being recycled
   meanwhile. */

static inline int
fd_accdb_line_read_unheld( fd_accdb_cache_line_t const * line,
                           ulong const *                 data_word,
                           ulong                         d,
                           uchar *                       owner,
                           uchar *                       data,
                           ulong                         data_sz ) {
  fd_racesan_hook( "accdb_nocache:pre_seq" );
  ulong s = FD_VOLATILE_CONST( line->seq );  /* after the word: its binder's take is visible */
  if( FD_UNLIKELY( s&1UL ) ) return 0;
  FD_COMPILER_MFENCE();                      /* seq before the copy */

  fd_racesan_hook( "accdb_nocache:pre_copy" );
  fd_memcpy( owner, line->owner, 32UL );
  if( data_sz ) fd_memcpy( data, (uchar const *)( line+1UL ), data_sz );
  fd_racesan_hook( "accdb_nocache:post_copy" );

  FD_COMPILER_MFENCE();                      /* the copy before the rechecks */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( *data_word )!=d ) ) return 0;
  fd_racesan_hook( "accdb_nocache:mid_recheck" );
  FD_COMPILER_MFENCE();                      /* the word before seq */
  return FD_VOLATILE_CONST( line->seq )==s;
}

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
   array during fd_accdb_new.  Every eviction scans each joiner's hazard
   list, so keep it small. */
#define FD_ACCDB_MAX_JOINERS (256UL)

/* Free line hints (fd_accdb.c "Free lines"): per join and class, a
   ring the accdb tile fills with lines it freed. */
#define FD_ACCDB_RING_N (1024UL)

/* Hazard list capacity: an acquire_a plus an acquire_b. */
#define FD_ACCDB_HAZARD_MAX (2UL*FD_ACCDB_MAX_ACQUIRE_CNT)

/* fd_accdb_ring_t is one join's ring of free line hints for one class
   (fd_accdb.c "Free lines").  An empty slot reads INVAL: the accdb tile
   fills slots that read INVAL and the join resets each slot it takes,
   so neither side reads the other's position.  The p line is the accdb
   tile's; the join sets hungry there when it runs out, and the tile
   clears it once it has given lines.  The c line is the join's. */

struct __attribute__((aligned(64))) fd_accdb_ring {
  struct __attribute__((aligned(64))) { ulong prod; ulong hungry; } p;
  struct __attribute__((aligned(64))) { ulong cons;               } c;
  uint e[ FD_ACCDB_RING_N ];
};

typedef struct fd_accdb_ring fd_accdb_ring_t;

struct fd_accdb_shmem_private {
  fd_spinlock_t partition_lock __attribute__((aligned(64)));
  fd_spinlock_t grow_lock      __attribute__((aligned(64)));

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

  /* Per-join, per-class rings of free line hints. */
  fd_accdb_ring_t cache_ring[ FD_ACCDB_MAX_JOINERS ][ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Per-join hazard lists: the cidx of every line join j holds for its
     current acquire bracket, one entry per acquired account (account i
     of an acquire is entry base+i; acquire_b's follow acquire_a's).
     FD_ACCDB_ACC_CIDX_INVAL marks none.  Entries [0,cnt), emptied when
     the bracket closes; 16 entries of padding past the end, so a scan
     can read whole vectors. */
  struct __attribute__((aligned(64))) { ulong cnt; uint cidx[ FD_ACCDB_HAZARD_MAX+16UL ]; } cache_hazard[ FD_ACCDB_MAX_JOINERS ];

  fd_accdb_fork_id_t root_fork_id;

  ulong seed;

  /* generation is a monotonically increasing counter assigned to each
     fork on creation.  When the root advances past a fork, its pool
     slot (fork_id) is retired and may be recycled by a new fork, making
     on-disk fork_id values useless for identifying entries from that
     retired fork.  But generation persists in disk metadata and is never
     recycled.

     Any rooted fork is by definition an ancestor of all live forks, so
     entries with generation <= root_fork->generation are
     unconditionally visible without consulting descends_set.  For
     entries with generation > root_fork->generation, the fork_id is
     still valid and descends_set is used to check ancestry.

     KEY INVARIANT: descends_set is ONLY consulted when generation >
     root_generation, which means the fork_id has NOT been rooted yet
     and its pool slot is still live.  This is what makes it safe for
     fd_accdb_attach_child to clear descends_set bits on slot
     reuse: rooted fork bits are dead (bypassed by the generation fast
     path), and purged fork bits were already 0 in all live forks'
     descends_sets (a purged fork is never an ancestor of a live fork).
     */
  uint generation;

  /* cache_class_init[c].val: lines of class c ever taken.  Lines past
     it have never been used: taken first (one FAA), so CLOCK does not
     evict while the class still has room.  Each element is on its own
     cacheline to avoid false sharing between classes. */
  struct __attribute__((aligned(64))) { ulong val; } cache_class_init[ FD_ACCDB_CACHE_CLASS_CNT ];

  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Byte offsets from shmem base to the per-class cache regions. Each
     region is cache_class_max[c] * fd_accdb_cache_slot_sz[c] bytes,
     with each slot holding an fd_accdb_cache_line_t header followed by
     up to (fd_accdb_cache_slot_sz[c] - META_SZ) bytes of account data.
     */
  ulong cache_region_off[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Background pre-eviction watermarks (computed once in shmem_new).
     cache_free_target[c]: free class-c lines pre-eviction keeps in the
     joins' rings, all joins together.  cache_free_low_water[c]: the
     same, the level below which a ring asks for a refill. */
  ulong cache_free_target   [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_free_low_water[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* cache_class_used[i].val holds the number of reserved cache slots
     in size class i: taken by acquires, and kept as the joins' idle
     reservation credits on release (fd_accdb.c res_*).  The count
     includes those idle credits (join_cred), so used[i].val +
     available[i] == cache_class_max[i] at all times.  ULONG_MAX if the
     class is untracked.  Each element is on its own cacheline to avoid
     false sharing between classes. */
  struct __attribute__((aligned(64))) { ulong val; } cache_class_used[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Per-layer write heads.  whead[0] is the hot (execution) write
     head, updated with atomic fetch-and-add by acquire/release
     threads.  whead[1..N-1] are compaction write heads, each
     single-writer (compaction tile after snapshot loading). */
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

  /* Hard upper bound on concurrent joiners, set at construction.
     Used to determine whether cache_class_used tracking can be
     skipped for a given class (when max[c] >= MIN_RESERVED *
     joiner_cnt, every reservation succeeds trivially). */
  ulong joiner_cnt_max;

  /* Per-joiner worst-case cache reservation, set at construction.
     Used by fd_accdb_shmem_cache_alloc_reset (on new and on reset) to
     pick the untracked classes. */
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
  ulong deferred_free_dlist_off;

  /* join_cred[j].val[c] is join j's idle reservation credits in class
     c (fd_accdb.c res_*).  Only updated atomically: the owner adds and
     CAS-takes, a failing reserver exchanges it to 0. */
  struct __attribute__((aligned(64))) { ulong val[ FD_ACCDB_CACHE_CLASS_CNT ]; } join_cred[ FD_ACCDB_MAX_JOINERS ];

  fd_accdb_shmem_metrics_t shmetrics[1];

  /* Root / purge requests (T1 -> T2).

     T1 (replay or snapin) owns the fork tree: it alone writes fork
     parent / child / sibling links and descends_sets.  advance_root and
     purge update the tree immediately and leave the index work to T2
     (the accdb tile), which never blocks T1.

     req.root_gen is the generation of the latest requested root.  Every
     fork from root_fork_id up to the requested root's parent has a
     single child, and generations increase along that path, so T2
     roots root_fork_id's child_id until root_fork_id has root_gen.
     Attaching the initial root requests it as the root, so there is
     nothing to root.  Generations are never reused (reset keeps
     counting), so done never matches a request it has not applied.

     req.purge_fork is the latest purged (detached) fork.  Each purged
     fork links to the one purged before it through its sibling_id (a
     detached fork has no siblings).  T2 applies the newest
     req.purge_seq-done.purge_seq forks of that chain.  Each unapplied
     purge holds a fork slot, so fewer than 2^16 are ever pending and
     their links are never recycled.

     done is T2's progress, stored last in a pass.  T2 has work when
     done.root_gen or done.purge_seq differ from req.  done.retiring is
     set while T2 holds a batch of retired accounts / fork slots it
     will release to the pools once concurrent readers drain.  When
     done matches req and retiring is clear, T2 does not touch the
     fork, acc or txn pools until the next request. */

  fd_accdb_req_t  req  __attribute__((aligned(64)));
  fd_accdb_done_t done __attribute__((aligned(64)));

  /* T2-only stack of accs unlinked from their map chains by the
     current root / purge pass, linked through map.next (each is marked
     FD_ACCDB_SIZE_UNLINKED_BIT first, see fd_accdb_acc_unlinked).  Its
     links are acc_pool links, so once the pass's epoch drains,
     drain_deferred_frees releases it with one acc_pool_release_chain.
     T2 is the sole writer, so the fields are plain.  head and tail are
     UINT_MAX when empty; tail is the first acc pushed, so the drain needs
     no walk to find it. */

  uint  deferred_acc_head;
  uint  deferred_acc_tail;
  ulong deferred_epoch; /* epoch tag of the retired batch (accs and fork slots) */

  /* T2-only chain (through pool.next) of fork pool slots retired with
     the batch above.  Their IDs may still be referenced by concurrent
     readers (via descends_set_test or a root_fork_id snapshot).
     USHORT_MAX when empty. */
  fd_accdb_fork_id_t deferred_fork_head;
  fd_accdb_fork_id_t deferred_fork_tail;

  /* Disk index (index_ram_entries!=0).  RAM-only mode keeps every
     field below at its RAM-only value and appends no region. */

  ulong index_ram_entries;  /* 0 = RAM-only                        */
  ulong acc_pool_max;       /* acc_pool capacity                   */
  ulong txn_pool_max;       /* txn_pool capacity, 0 in index mode  */
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
  ulong idx_hot_ref_off;    /* acc_pool_max uchars, FG sets on hit */
  ulong idx_fifo_off;       /* acc_pool_max ulongs: idx<<32 | gen  */
  ulong fifo_head;          /* T2 only                             */
  ulong fifo_tail;
  ulong fifo_chunk;         /* 0: ring of acc_pool_max, else FIFO_CHUNK */
  ulong fifo_file_off;      /* scratch file offset of spilled chunks */
  ulong fifo_tag[ FD_ACCDB_FIFO_SLOTS ]; /* chunk id per RAM slot  */
  ulong hot_cursor;         /* T2 only                             */
  ulong promote_reserve;    /* free slots kept for releases        */
  ulong prot_off;           /* FD_ACCDB_PROT_MAX fd_accdb_prot_t   */
  ulong prot_head;          /* T2 only                             */
  ulong prot_tail;
  fd_accdb_promote_ring_t ring_res [1];
  fd_accdb_promote_ring_t ring_hint[1];
  ulong res_ack[ FD_ACCDB_MAX_JOINERS ]; /* joiner: last ticket re-walked */
  ulong res_park[ FD_ACCDB_MAX_JOINERS ]; /* joiner: sleep tile id+1 while parked on a residual wait, 0 = not parked */

  ulong idx_ovl_npage;
  ulong idx_ovl_seq_off;
  ulong idx_olog_byte0;     /* file offset of chunk 0              */
  ulong idx_olog_chunk_cnt;
  ulong idx_olog_next_off;  /* uint per chunk                      */
  uint  olog_free;          /* T2 only, chunk free list head       */
  ulong idx_fork_off;       /* fd_accdb_idx_fork_t per fork        */
  ulong idx_bloom_off;
  ulong idx_bloom_words;    /* per fork                            */
  ulong spill_fork;         /* USHORT_MAX = none in progress       */
  uint  spill_txn;          /* next fork list record to persist    */
  ulong ovl_fork_cnt __attribute__((aligned(64)));
  ulong ovl_epoch;
  ulong thaw_fork;          /* replay: fork to restore, USHORT_MAX = none */
  ulong unspill_off;        /* FD_ACCDB_UNSPILL_MAX ulongs: idx<<32 | gen */
  ulong unspill_head;       /* T2 only                             */
  ulong unspill_tail;
  ulong unspill_cnt;        /* live TIER_UNSPILL copies            */
  ulong unspill_cap;
  ulong ovl_ans_off;        /* uint [MAX_JOINERS][MAX_ACQUIRE_CNT]: T2's
                               newest visible generation per request */

  /* Snapshot staging (index mode).  Stage bytes live in the index file
     at [stage_base, stage_base+stage_head); the region grows by
     fallocate under grow_lock. */
  ulong stage_base;
  ulong stage_head __attribute__((aligned(64)));   /* FAA by writers */
  ulong stage_falloc;                              /* grow_lock      */
  ulong stage_full_end;                            /* full load's records end here */
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

/* fd_accdb_shmem_cache_alloc_reset makes every cache line FREE and
   empty, with no hints, holds or idle reservation credits.
   cache_class_max, cache_region_off, cache_min_reserved and
   joiner_cnt_max must be set.  If a class has enough lines for every
   joiner's worst case at once (cache_min_reserved per joiner), no
   reservation can overflow, and the cache_class_used sentinel
   ULONG_MAX tells acquire to skip the counter. */

static inline void
fd_accdb_shmem_cache_alloc_reset( fd_accdb_shmem_t * shmem ) {
  ulong worst = shmem->cache_min_reserved*shmem->joiner_cnt_max;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    shmem->clock_hand      [ c ].val = 0UL;
    shmem->cache_class_init[ c ].val = 0UL;
    shmem->cache_class_used[ c ].val = fd_ulong_if( shmem->cache_class_max[ c ]>=worst, ULONG_MAX, 0UL );
    uchar * region = (uchar *)shmem + shmem->cache_region_off[ c ];
    for( ulong i=0UL; i<shmem->cache_class_max[ c ]; i++ ) {
      memset( region + i*fd_accdb_cache_slot_sz[ c ], 0, sizeof(fd_accdb_cache_line_t) );  /* FREE, seq 0 */
    }
  }
  for( ulong j=0UL; j<FD_ACCDB_MAX_JOINERS; j++ ) {
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      fd_accdb_ring_t * r = &shmem->cache_ring[ j ][ c ];
      r->p.prod = 0UL; r->p.hungry = 0UL;
      r->c.cons = 0UL;
      memset( r->e, 0xFF, sizeof(r->e) );  /* every slot empty */
      shmem->join_cred [ j ].val[ c ]    = 0UL;
    }
    shmem->cache_hazard[ j ].cnt = 0UL;
  }
}

FD_PROTOTYPES_BEGIN

/* fd_accdb_set_preevict_interval sets the minimum ticks between this
   join's background pre-eviction watermark scans (default ~100000; 0
   scans on every fd_accdb_background call).  For tests: a
   single-threaded test that calls fd_accdb_background once to refill
   the free lists sets 0. */

void
fd_accdb_set_preevict_interval( fd_accdb_t * accdb,
                                long         ticks );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_private_h */
