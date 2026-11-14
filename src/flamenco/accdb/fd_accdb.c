#define _GNU_SOURCE
#include "fd_accdb.h"
#include "fd_accdb_shmem.h"
#include "fd_accdb_private.h"
#include "fd_accdb_idx.h"
#include "../runtime/fd_system_ids.h"
#include "../../util/fd_hash32.h"
#include "../../util/bits/fd_uwide.h"

#if FD_TMPL_USE_HANDHOLDING
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/base58/fd_base58.h"
#endif
#include "../../util/racesan/fd_racesan_target.h"
#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
#endif

#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/sleep/fd_sleep.h"
#include "../runtime/fd_runtime_const.h" /* FD_RUNTIME_ACC_SZ_MAX */

FD_STATIC_ASSERT( sizeof(fd_accdb_cache_line_t)==FD_ACCDB_CACHE_META_SZ, cache_meta_sz );

#define FD_ACCDB_BOUNCE_SZ (16UL<<20)

/* T2 staging: the overflow log's chunk I/O buffer (accdb->stage),
   carved after the compaction bounce buffer. */
#define FD_ACCDB_T2_STAGE_SZ (FD_ACCDB_OLOG_CHUNK*sizeof(fd_accdb_olog_rec_t))
FD_STATIC_ASSERT( FD_ACCDB_BOUNCE_SZ>=FD_RUNTIME_ACC_SZ_MAX+sizeof(fd_accdb_disk_meta_t), bounce_fits_any_record );

/* Minimum ticks (tens of microseconds) between a join's wakeups of the
   accdb tile (cache_free_ring), and the default between its
   background_preevict watermark scans. */
#define FD_ACCDB_BG_RATE_TICKS (100000L)

/* SPIN_UNTIL( cond, hook ) spins until cond holds, and logs a
   rate-limited warning past SPIN_WARN_TICKS (~1s) so a hung wait shows
   up instead of a silent hang.  The clock is read once per 1024
   pauses. */

#define SPIN_WARN_TICKS (3000000000L)

#define SPIN_UNTIL( cond, hook ) do {                                                   \
    if( FD_LIKELY( (cond) ) ) break;                                                    \
    long _warn = fd_tickcount()+SPIN_WARN_TICKS;                                        \
    for( ulong _k=1UL; !(cond); _k++ ) {                                                \
      fd_racesan_hook( hook );                                                          \
      FD_SPIN_PAUSE();                                                                  \
      if( FD_UNLIKELY( !( _k&1023UL ) && fd_tickcount()>_warn ) ) {                     \
        FD_LOG_WARNING(( "accdb: slow wait (%s), still waiting", hook ));               \
        _warn = fd_tickcount()+SPIN_WARN_TICKS;                                         \
      }                                                                                 \
    }                                                                                   \
  } while(0)

#if FD_HAS_RACESAN
/* Test-only telemetry: background_compact publishes the pubkey + dest
   offset of the record it is about to relocation-CAS at the
   accdb_compact:pre_offset_cas hook, so test_accdb_racesan can PROVE the
   parked relocation is the account it set up (avoiding a vacuous test).
   Zero-cost / absent in production (racesan off). */
uchar fd_accdb_dbg_reloc_pubkey[ 32UL ];
ulong fd_accdb_dbg_reloc_dest;
ulong fd_accdb_dbg_reloc_cnt;
ulong fd_accdb_dbg_compact_scanned; /* bytes compaction stepped over */
#endif

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/uio.h>

struct fd_accdb_fork {
  fd_accdb_fork_shmem_t * shmem;
  descends_set_t * descends;
};

typedef struct fd_accdb_fork fd_accdb_fork_t;

#define STASH_MAX  (FD_ACCDB_HAZARD_MAX)  /* every line a bracket can free (staging, commit spares) */
/* RECLAIM_FG is the size of a join's own CLOCK batch: one line for now,
   the rest stashed, sharing one scan and one writeback. */
#define RECLAIM_FG (16UL)

/* RECLAIM_LARGE_SZ: classes with slots this large take one line per
   batch instead (foreground and pre-eviction), so no batch writes back
   more than one large line, and a new holder of a claimed line waits
   for at most that one write. */
#define RECLAIM_LARGE_SZ (128UL<<10)

#define FD_ACCDB_ACQUIRE_STATE_IDLE    (0)
#define FD_ACCDB_ACQUIRE_STATE_PHASE_A (1)
#define FD_ACCDB_ACQUIRE_STATE_OPEN    (2)

struct __attribute__((aligned(FD_ACCDB_ALIGN))) fd_accdb_private {
  int fd;
  int scratch_fd; /* scratch spill file, -1 unless T2 */

  int acquire_state;

  fd_accdb_shmem_t * shmem;

  /* Doorbell for the parked accdb tile, NULL when nobody parks */
  fd_sleep_t * sleep;
  ulong        sleep_tile_id;

  /* Residual wait parking (efficient mode, fd_accdb_park_init).  A
     waiter parks on park_word; T2 rings parked waiters via park_sleep.
     NULL when residual waits spin. */
  fd_sleep_t * park_sleep;
  ulong *      park_word;
  ulong        park_tile_id;
  long         park_spin_ticks;

  fd_accdb_fork_t * fork_pool;
  fork_pool_t fork_shmem_pool[1];

  fd_accdb_accmeta_t * acc_pool;
  acc_pool_t acc_pool_join[1];
  uint * acc_map;

  uchar * cache [ FD_ACCDB_CACHE_CLASS_CNT ];

  fd_accdb_partition_t * partition_pool;
  compaction_dlist_t * compaction_dlist[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  deferred_free_dlist_t * deferred_free_dlist;

  txn_pool_t txn_pool[1];

  /* Pointer into shmem->joiner_epochs[ my_slot ].val for writer
     joiners, or into a private per-tile fseq for read-only joiners.
     Set to the current global epoch on entry to an epoch-protected
     operation, and ULONG_MAX on exit.  Used to determine when
     deferred frees are safe. */
  ulong * my_epoch_slot;

  /* Read-only pointers to external epoch slots (e.g. fseqs owned by
     RO consumer tiles like the rpc tile).  Scanned in addition to
     shmem->joiner_epochs[] by compaction's deferred-free
     reclamation.  Borrowed; the caller of fd_accdb_new owns the
     storage. */
  ulong const * const * external_epoch_slots;
  ulong                 external_epoch_cnt;

  fd_accdb_metrics_t metrics[1];

  ulong prealloc_failed_at;

  /* Compaction bounce buffer. */
  uchar * bounce;
  uchar * stage;  /* T2 staging, FD_ACCDB_T2_STAGE_SZ bytes, NULL unless compaction */
  ulong   carry_off;
  ulong   carry_sz;
  ulong   carry_layer;

  /* This join's index into the per-join shmem arrays (joiner_epochs,
     cache_ring, cache_hazard, join_cred), and the last time it woke the
     accdb tile (cache_free_ring). */
  ulong join_idx;
  long  free_ring_ticks;

  /* Free line hints (fd_accdb.c "Free lines"): this join's rings, and
     a stash of the lines it freed itself, newest last. */
  fd_accdb_ring_t * ring     [ FD_ACCDB_CACHE_CLASS_CNT ];
  uint              stash    [ FD_ACCDB_CACHE_CLASS_CNT ][ STASH_MAX ];
  ulong             stash_cnt[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Entries in this join's hazard list (the bracket so far). */
  ulong hazard_cnt;

  /* Last background_preevict pass (rate-limited to preevict_interval:
     it reads every join's rings), and whether it left a class short,
     so throttled calls keep reporting busy and the tile does not park
     mid-refill. */
  long  preevict_ticks;
  long  preevict_interval;
  int   preevict_pending;

  /* Reservation state (res_*).  res_limit[c] is ULONG_MAX if class c
     is untracked, so the hot path never loads the shared counter just
     to learn that.  cred points at this join's shmem->join_cred line.
     res_held / res_extra are what the open bracket took (res_extra:
     acquire_a's programdata reservation, settled by acquire_b). */
  ulong   res_limit[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong   cred_max [ FD_ACCDB_CACHE_CLASS_CNT ];   /* idle credits kept per class */
  ulong * cred;
  ulong   res_held [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong   res_extra[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Disk index views, zero in RAM-only mode. */
  fd_accdb_idx_region_t bkt[1];
  fd_accdb_idx_region_t ovl[1];
  fd_accdb_cf_t         cf[1];
  uint *                hot_map;
  uchar *               tier;
  uchar *               hot_ref;
  ulong *               fifo;
  ulong                 idx_rng;
  int                   readonly;
  ulong                 residual_ticket; /* ULONG_MAX = none to ack */
  struct { uchar pubkey[ 32 ]; uint fork_gen; uint gen; ulong epoch; } ovl_res[ 32 ]; /* R4: ovl resolved by T2 */
  ulong                 stage_cnt;       /* records in this joiner's share */
  ulong                 pend_watch_cnt;
  uchar                 pend_watch[ FD_ACCDB_PEND_MAX ][ 32 ];
  fd_accdb_stage_rec_t  pend      [ FD_ACCDB_PEND_MAX ];

  /* Track account addresses changed since a full snap.
     Used to determine which accounts should be packed into an incremental
     snapshot (including tombstones for accounts no longer present in
     accdb, but present in the full snapshot). */
  struct {
    uint *             chains;
    fd_accdb_delta_t * pool;
    struct {
      uchar const * pubkey;
      uint          chain;
    } scratch[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  } delta;

  /* Batch metric updates to avoid shared atomics per write. */
  struct {
    ulong bytes;                /* bytes reserved on partition_idx */
    ulong num_ops;              /* reservations behind those bytes */
    ulong partition_idx;        /* set while num_ops>0 */
    ulong disk_used_added;
    ulong disk_used_removed;
    ulong accounts_total_added;
  } write_stats __attribute__((aligned(64)));
};

static inline fd_accdb_cache_line_t *
cache_line( fd_accdb_t * accdb,
            ulong        cls,
            ulong        idx ) {
  return (fd_accdb_cache_line_t *)( accdb->cache[ cls ] + idx * fd_accdb_cache_slot_sz[ cls ] );
}

/* Bump the per-partition read counters for the partition that contains
   file_offset.  Called at preadv2 sites.  Writes are counted at
   allocate time (see fd_accdb_partition_write_bump) so that they reflect
   bytes committed to a partition rather than syscalls — the snapshot
   loader bypasses pwritev2 entirely, but every write still goes through
   reserve_next_write. */
static inline void
fd_accdb_partition_read_bump( fd_accdb_t * accdb,
                              ulong        file_offset,
                              ulong        bytes ) {
  if( FD_UNLIKELY( !bytes ) ) return;
  /* Readonly joiners have no partition_pool join (see
     fd_accdb_join_readonly) and do not contribute to per-partition
     read telemetry today; their disk reads still show up in the
     joiner-local fd_accdb_metrics_t bytes_read/read_ops. */
  if( FD_UNLIKELY( !accdb->partition_pool ) ) return;
  ulong partition_idx = file_offset / accdb->shmem->partition_sz;
  ulong partition_cnt = partition_pool_max( accdb->partition_pool );
  FD_CHECK_CRIT( partition_idx<partition_cnt, "read partition index out of range" );
  fd_accdb_partition_t * p = partition_pool_ele( accdb->partition_pool, partition_idx );
  FD_ATOMIC_FETCH_AND_ADD( &p->bytes_read, bytes );
  FD_ATOMIC_FETCH_AND_ADD( &p->read_ops,   1UL   );
}

/* Bump the per-partition write counters.  bytes is how much landed on
   this partition, over num_ops reservations. */
static inline void
fd_accdb_partition_write_bump( fd_accdb_t * accdb,
                               ulong        partition_idx,
                               ulong        bytes,
                               ulong        num_ops ) {
  if( FD_UNLIKELY( !bytes ) ) return;
  ulong partition_cnt = partition_pool_max( accdb->partition_pool );
  FD_CHECK_CRIT( partition_idx<partition_cnt, "write partition index out of range" );
  fd_accdb_partition_t * p = partition_pool_ele( accdb->partition_pool, partition_idx );
  FD_ATOMIC_FETCH_AND_ADD( &p->bytes_written, bytes   );
  FD_ATOMIC_FETCH_AND_ADD( &p->write_ops,     num_ops );
}

void
fd_accdb_flush_metrics( fd_accdb_t * accdb ) {
  ulong bytes                = accdb->write_stats.bytes;
  ulong num_ops              = accdb->write_stats.num_ops;
  ulong part_idx             = accdb->write_stats.partition_idx;
  ulong disk_used_added      = accdb->write_stats.disk_used_added;
  ulong disk_used_removed    = accdb->write_stats.disk_used_removed;
  ulong accounts_total_added = accdb->write_stats.accounts_total_added;

  memset( &accdb->write_stats, 0, sizeof(accdb->write_stats) );

  if( num_ops ) {
    FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_current_bytes, bytes );
    fd_accdb_partition_write_bump( accdb, part_idx, bytes, num_ops );
  }

  if( disk_used_added      ) FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_used_bytes, disk_used_added      );
  if( disk_used_removed    ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, disk_used_removed    );
  if( accounts_total_added ) FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->accounts_total,  accounts_total_added );
}

static inline int
idx_enabled( fd_accdb_t const * accdb ) {
  return !!accdb->shmem->index_ram_entries;
}

static inline fd_accdb_idx_fork_t *
idx_fork( fd_accdb_t const * accdb,
          ulong              fork_id ) {
  return (fd_accdb_idx_fork_t *)( (uchar *)accdb->shmem + accdb->shmem->idx_fork_off )+fork_id;
}

static inline ulong *
ovl_bloom( fd_accdb_t const * accdb,
           ulong              fork_id ) {
  return (ulong *)( (uchar *)accdb->shmem + accdb->shmem->idx_bloom_off )+fork_id*accdb->shmem->idx_bloom_words;
}

static void idx_spilled_purge( fd_accdb_t * accdb, ushort f );
static inline int ovl_bloom_op( fd_accdb_t const * accdb, ulong fork_id, uchar const pubkey[ 32 ], int insert );
static void idx_spilled_root ( fd_accdb_t * accdb, ushort f );

static inline uint *
olog_next( fd_accdb_t const * accdb ) {
  return (uint *)( (uchar *)accdb->shmem + accdb->shmem->idx_olog_next_off );
}

static void
idx_join( fd_accdb_t * accdb,
          int          idx_fd ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  memset( accdb->bkt, 0, sizeof(accdb->bkt) );
  memset( accdb->ovl, 0, sizeof(accdb->ovl) );
  memset( accdb->ovl_res, 0xFF, sizeof(accdb->ovl_res) );
  memset( accdb->cf,  0, sizeof(accdb->cf)  );
  accdb->hot_map = NULL;
  accdb->tier    = NULL;
  accdb->hot_ref = NULL;
  accdb->fifo    = NULL;
  accdb->idx_rng = shmem->seed;
  if( !shmem->index_ram_entries ) return;
  accdb->tier    = (uchar *)( (uchar *)shmem + shmem->idx_tier_off    );
  accdb->hot_ref = (uchar *)( (uchar *)shmem + shmem->idx_hot_ref_off );
  accdb->fifo    = (ulong *)( (uchar *)shmem + shmem->idx_fifo_off    );
  *accdb->bkt = (fd_accdb_idx_region_t){
    .fd    = idx_fd,
    .page0 = 0UL,
    .npage = shmem->idx_bkt_npage,
    .nhome = shmem->idx_bkt_npage-FD_ACCDB_IDX_PROBE_MAX,
    .seq   = (uint *)( (uchar *)shmem + shmem->idx_bkt_seq_off ),
    .salt  = FD_ACCDB_IDX_SALT_B
  };
  *accdb->ovl = (fd_accdb_idx_region_t){
    .fd         = idx_fd,
    .page0      = shmem->idx_bkt_npage,
    .npage      = shmem->idx_ovl_npage,
    .nhome      = shmem->idx_ovl_npage-FD_ACCDB_IDX_PROBE_MAX,
    .seq        = (uint *)( (uchar *)shmem + shmem->idx_ovl_seq_off ),
    .salt       = FD_ACCDB_IDX_SALT_O,
    .keyed_fork = 1
  };
  *accdb->cf = (fd_accdb_cf_t){
    .cf        = (ulong *)( (uchar *)shmem + shmem->idx_cf_off ),
    .nb        = shmem->idx_cf_nb,
    .seed      = shmem->seed,
    .seq       = &shmem->idx_cf_seq,
    .stash     = (ulong *)( (uchar *)shmem + shmem->idx_cf_stash_off ),
    .stash_cnt = &shmem->idx_cf_stash_cnt,
    .disabled  = &shmem->idx_cf_disabled
  };
  accdb->hot_map = (uint *)( (uchar *)shmem + shmem->idx_hot_map_off );
}

FD_FN_CONST ulong
fd_accdb_align( void ) {
  return FD_ACCDB_ALIGN;
}

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_live_slots,
                    int   compaction ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_ALIGN,           sizeof(fd_accdb_t)                     );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );
  if( compaction ) l = FD_LAYOUT_APPEND( l, FD_ACCDB_ALIGN, FD_ACCDB_BOUNCE_SZ+FD_ACCDB_T2_STAGE_SZ );
  return FD_LAYOUT_FINI( l, FD_ACCDB_ALIGN );
}

void *
fd_accdb_new( void *              ljoin,
              fd_accdb_shmem_t *  shmem,
              int                 fd,
              int                 scratch_fd,
              ulong               external_epoch_cnt,
              ulong const **      external_epoch_slots,
              fd_sleep_t *        sleep,
              ulong               sleep_tile_id,
              int                 compaction,
              int                 idx_fd ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "fd must be a valid file descriptor" ));
    return NULL;
  }

  ulong max_live_slots = shmem->max_live_slots;
  ulong pool_max       = shmem->acc_pool_max;
  ulong partition_cnt  = shmem->partition_cnt;

  ulong chain_cnt = shmem->chain_cnt;
  ulong txn_max   = shmem->txn_pool_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool_ele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t),    pool_max*sizeof(fd_accdb_accmeta_t)                     );
  void * _txn_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_txn_t),        txn_max*sizeof(fd_accdb_txn_t)                          );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),         partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlists[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    _compaction_dlists[ k ] = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                                 );
  }
  void * _deferred_free_dlist = FD_SCRATCH_ALLOC_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                         );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_accdb_t * accdb      = FD_SCRATCH_ALLOC_APPEND( l2, fd_accdb_align(),           sizeof(fd_accdb_t)                     );
  void * _local_fork_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(fd_accdb_fork_t),   max_live_slots*sizeof(fd_accdb_fork_t) );
  uchar * _bounce         = compaction ? FD_SCRATCH_ALLOC_APPEND( l2, FD_ACCDB_ALIGN, FD_ACCDB_BOUNCE_SZ+FD_ACCDB_T2_STAGE_SZ ) : NULL;

  accdb->fd = fd;
  accdb->scratch_fd = scratch_fd;
  accdb->readonly   = 0;
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
  accdb->sleep         = sleep;
  accdb->sleep_tile_id = sleep_tile_id;
  accdb->park_sleep      = NULL;
  accdb->park_word       = NULL;
  accdb->park_tile_id    = ULONG_MAX;
  accdb->park_spin_ticks = 0L;

  accdb->shmem = (fd_accdb_shmem_t *)shmem;
  FD_TEST( acc_pool_join( accdb->acc_pool_join, shmem->acc_pool, _acc_pool_ele, pool_max ) );
  accdb->acc_pool = accdb->acc_pool_join->ele;
  accdb->acc_map = _acc_map;
  FD_TEST( txn_pool_join( accdb->txn_pool, shmem->txn_pool, _txn_pool_ele, txn_max ) );
  idx_join( accdb, idx_fd );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache[ c ] = (uchar *)shmem + shmem->cache_region_off[ c ];
  accdb->partition_pool = partition_pool_join( _partition_pool );
  FD_TEST( accdb->partition_pool );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    accdb->compaction_dlist[ k ] = compaction_dlist_join( _compaction_dlists[ k ] );
    FD_TEST( accdb->compaction_dlist[ k ] );
  }
  accdb->deferred_free_dlist = deferred_free_dlist_join( _deferred_free_dlist );
  FD_TEST( accdb->deferred_free_dlist );

  FD_TEST( fork_pool_join( accdb->fork_shmem_pool, shmem->fork_pool, _fork_pool_ele, max_live_slots ) );
  accdb->fork_pool = _local_fork_pool;
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_accdb_fork_t * fork = &accdb->fork_pool[ i ];
    fork->shmem = fork_pool_ele( accdb->fork_shmem_pool, i );
    fork->descends = descends_set_join( (uchar *)_descends_sets + i*descends_set_footprint( max_live_slots ) );
    FD_TEST( fork->shmem );
    FD_TEST( fork->descends );
  }

  ulong epoch_idx = FD_ATOMIC_FETCH_AND_ADD( &shmem->joiner_cnt, 1UL );
  FD_TEST( epoch_idx<shmem->joiner_cnt_max );
  accdb->my_epoch_slot   = &shmem->joiner_epochs[ epoch_idx ].val;
  accdb->join_idx        = epoch_idx;
  accdb->free_ring_ticks = 0L;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    int tracked = FD_VOLATILE_CONST( shmem->cache_class_used[ c ].val )!=ULONG_MAX;
    accdb->res_limit[ c ] = tracked ? shmem->cache_class_max[ c ] : ULONG_MAX;
    accdb->cred_max [ c ] = tracked ? fd_ulong_min( 64UL, shmem->cache_class_max[ c ]/( 2UL*shmem->joiner_cnt_max ) ) : 0UL;
    accdb->res_held [ c ] = 0UL;
    accdb->res_extra[ c ] = 0UL;
    accdb->ring     [ c ] = &shmem->cache_ring[ epoch_idx ][ c ];
    accdb->stash_cnt[ c ] = 0UL;
  }
  accdb->cred              = shmem->join_cred[ epoch_idx ].val;
  accdb->hazard_cnt        = 0UL;
  accdb->residual_ticket   = ULONG_MAX; /* join_idx also indexes res_ack, stage_dir, place_out, ovl answers */
  accdb->preevict_ticks    = 0L;
  accdb->preevict_interval = FD_ACCDB_BG_RATE_TICKS;
  accdb->preevict_pending  = 0;
  accdb->stage_cnt       = 0UL;
  accdb->pend_watch_cnt  = 0UL;

  accdb->external_epoch_slots = external_epoch_slots;
  accdb->external_epoch_cnt   = external_epoch_cnt;

  accdb->bounce      = _bounce;
  accdb->stage       = _bounce ? _bounce+FD_ACCDB_BOUNCE_SZ : NULL;
  accdb->carry_off   = 0UL;
  accdb->carry_sz    = 0UL;
  accdb->carry_layer = 0UL;

  accdb->delta.chains = (uint *)             ( (uchar *)shmem + shmem->delta.chain_off );
  accdb->delta.pool   = (fd_accdb_delta_t *) ( (uchar *)shmem + shmem->delta.ele_off   );

  accdb->prealloc_failed_at  = ULONG_MAX;

  memset( accdb->metrics,      0, sizeof(fd_accdb_metrics_t) );
  memset( &accdb->write_stats, 0, sizeof(accdb->write_stats) );

  return accdb;
}

static void delta_reset( fd_accdb_t * accdb );

/* wait_idle waits until the accdb tile has applied every published
   root / purge request and released everything they retired.  The
   accdb tile then does not touch the fork, acc or txn pools until the
   next request. */

static void
wait_idle( fd_accdb_t * accdb ) {
  while( fd_accdb_requests_pending( accdb ) ) {
    fd_racesan_hook( "accdb_wait_idle:spin" );
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

/* publish_req publishes a new request word, after the fork tree
   updates it describes. */

static void
publish_req( fd_accdb_t *   accdb,
             fd_accdb_req_t req ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( accdb->shmem->req.u ) = req.u;
  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( accdb->sleep ) ) fd_sleep_ring( accdb->sleep, accdb->sleep_tile_id );
}

void
fd_accdb_reset( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  /* Once idle, the accdb tile holds nothing that refers to the pools
     rebuilt below.  Compaction keeps a carried tail between steps, so
     it must not be running either.  Partitions are only queued for
     compaction once a snapshot load ends, and snapin resets only before
     loading a full snapshot. */
  wait_idle( accdb );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    FD_CHECK_CRIT( compaction_dlist_is_empty( accdb->compaction_dlist[ k ], accdb->partition_pool ),
                   "accdb reset while compaction is queued" );
  }

  /* Reset pools through the joiner's existing pointers.  acc_pool and
     txn_pool use POOL_LAZY=1 so reset is O(1).  fork_pool and
     partition_pool rebuild their free lists in O(max_live_slots) and
     O(partition_cnt), both small. */
  fd_spinlock_acquire( &shmem->grow_lock );
  acc_pool_reset( accdb->acc_pool_join );
  txn_pool_reset( accdb->txn_pool );
  shmem->pool_avail    = shmem->acc_pool_max;
  shmem->bg_defer_head   = 0UL;
  shmem->bg_defer_tail   = 0UL;
  shmem->bg_defer_sealed = 0UL;
  shmem->fifo_head     = 0UL;
  shmem->fifo_tail     = 0UL;
  if( accdb->tier ) {
    /* Index state never survives a reset: the next full placement
       rewrites every bucket page, and the RAM side starts empty. */
    memset( accdb->tier,    0,    shmem->acc_pool_max );
    memset( accdb->hot_ref, 0,    shmem->acc_pool_max );
    memset( accdb->hot_map, 0xFF, shmem->idx_hot_chain_cnt*sizeof(uint) );
    memset( accdb->cf->cf,  0,    shmem->idx_cf_nb*sizeof(ulong) );
    memset( accdb->cf->stash, 0,  FD_ACCDB_CF_STASH_MAX*sizeof(ulong) );
    shmem->idx_cf_stash_cnt = 0UL;
    shmem->idx_cf_disabled  = 0UL;
    shmem->ovl_fork_cnt     = 0UL;
    shmem->ovl_epoch++;
    shmem->spill_fork       = USHORT_MAX;
    uint * nx = olog_next( accdb );
    for( ulong i=0UL; i<shmem->idx_olog_chunk_cnt; i++ ) nx[ i ] = i+1UL<shmem->idx_olog_chunk_cnt ? (uint)(i+1UL) : UINT_MAX;
    shmem->olog_free = shmem->idx_olog_chunk_cnt ? 0U : UINT_MAX;
    for( ulong i=0UL; i<shmem->max_live_slots; i++ ) *idx_fork( accdb, i ) = (fd_accdb_idx_fork_t){ .olog_head = UINT_MAX, .olog_tail = UINT_MAX };
    shmem->prot_head = shmem->prot_tail = 0UL;
    shmem->unspill_head = shmem->unspill_tail = shmem->unspill_cnt = 0UL;
    shmem->thaw_fork = USHORT_MAX;
    FD_VOLATILE( shmem->stage_head ) = 0UL;
    shmem->stage_full_end = 0UL;
  }
  fork_pool_reset( accdb->fork_shmem_pool );
  partition_pool_reset( accdb->partition_pool );

  delta_reset( accdb );

  /* Clear hash chains */
  fd_memset( accdb->acc_map, 0xFF, shmem->chain_cnt*sizeof(uint) );

  /* Empty dlists */
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    compaction_dlist_remove_all( accdb->compaction_dlist[ k ], accdb->partition_pool );
  }
  deferred_free_dlist_remove_all( accdb->deferred_free_dlist, accdb->partition_pool );

  /* Null descends_sets. */
  for( ulong i=0UL; i<shmem->max_live_slots; i++ ) {
    descends_set_null( accdb->fork_pool[ i ].descends );
  }

  /* Reset shmem scalar fields. */
  /* generation keeps counting.  req and done name roots by generation,
     so reusing generations would make a new root look already applied. */
  shmem->root_fork_id   = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fd_spinlock_new( &shmem->partition_lock );
  shmem->partition_max  = 0UL;
  shmem->partition_fallocated = 0UL;
  fd_spinlock_release( &shmem->grow_lock );

  /* Write heads: sentinel values that force partition-switch on first
     write. */
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    shmem->whead[ k ] = accdb_offset( shmem->partition_cnt, shmem->partition_sz );
    shmem->has_partition[ k ] = 0;
  }

  /* Cache state: every line FREE and empty */
  fd_accdb_shmem_cache_alloc_reset( shmem );

  /* Epoch system: reset epoch and all slot values to idle, but
     preserve joiner_cnt and each tile's my_epoch_slot pointer so that
     tiles which joined during init keep their original slot indices. */
  shmem->epoch = 1UL;
  for( ulong i=0UL; i<FD_ACCDB_MAX_JOINERS; i++ ) shmem->joiner_epochs[ i ].val = ULONG_MAX;

  /* Deferred acc stack. */
  shmem->deferred_acc_head    = UINT_MAX;
  shmem->deferred_acc_tail    = UINT_MAX;
  shmem->deferred_epoch       = 0UL;
  shmem->deferred_fork_head   = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  shmem->deferred_fork_tail   = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

  /* Shared metrics: zero gauges that reflect current state (now empty)
     but preserve counters and accounts_capacity. */
  shmem->shmetrics->accounts_total       = 0UL;
  shmem->shmetrics->disk_allocated_bytes = 0UL;
  shmem->shmetrics->disk_current_bytes   = 0UL;
  shmem->shmetrics->disk_used_bytes      = 0UL;
  shmem->shmetrics->in_compaction        = 0;

  shmem->snapshot_loading = 0;

  FD_COMPILER_MFENCE();

  /* Reset local state */
  accdb->acquire_state       = FD_ACCDB_ACQUIRE_STATE_IDLE;
  memset( &accdb->write_stats, 0, sizeof(accdb->write_stats) );
}

void
fd_accdb_snapshot_load_begin( fd_accdb_t * accdb ) {
  FD_CHECK_CRIT( fd_accdb_snapshot_sync_state( &accdb->shmem->snapshot_sync )==FD_ACCDB_SNAPSHOT_SYNC_IDLE,
                 "snapshot load started while snapshot production active" );
  FD_VOLATILE( accdb->shmem->snapshot_loading ) = 1;
}

static inline void
change_partition( fd_accdb_t *           accdb,
                  accdb_offset_t const * offset_before,
                  accdb_offset_t *       out_offset,
                  int *                  has_partition,
                  uchar                  layer );

void
fd_accdb_snapshot_load_end( fd_accdb_t * accdb ) {
  fd_accdb_flush_metrics( accdb );

  /* Once the snapshot is done loading, the cold partition we were
     writing into is left open as the layer 2 head, and we switch the
     layer 0 head to a new hot partition. */
  ulong const cold = FD_ACCDB_COMPACTION_LAYER_CNT-1UL;
  if( FD_LIKELY( accdb->shmem->has_partition[ 0 ] ) ) {
    if( FD_LIKELY( !accdb->shmem->has_partition[ cold ] ) ) {
      accdb_offset_t snap_head = accdb->shmem->whead[ 0 ];
      int            no_head   = 0;
      change_partition( accdb, &snap_head, &accdb->shmem->whead[ 0 ], &no_head, 0 );
      fd_spinlock_acquire( &accdb->shmem->partition_lock );
      accdb->shmem->whead[ cold ]         = snap_head;
      accdb->shmem->has_partition[ cold ] = 1;
      fd_spinlock_release( &accdb->shmem->partition_lock );
    } else {
      change_partition( accdb, &accdb->shmem->whead[ 0 ], &accdb->shmem->whead[ 0 ], &accdb->shmem->has_partition[ 0 ], 0 );
    }
  }

  fd_spinlock_acquire( &accdb->shmem->partition_lock );
  if( FD_LIKELY( accdb->shmem->has_partition[ 0 ] ) ) {
    ulong new_idx = packed_partition_idx( &accdb->shmem->whead[ 0 ] );
    fd_accdb_partition_t * newp = partition_pool_ele( accdb->partition_pool, new_idx );
    FD_VOLATILE( newp->layer ) = 0;
  }

  FD_VOLATILE( accdb->shmem->snapshot_loading ) = 0;

  /* Sweep all partitions written during the load — any that crossed
     the fragmentation threshold while enqueue was suppressed are
     re-checked now and pushed onto the compaction queue. */
  ulong partition_max = accdb->shmem->partition_max;
  for( ulong p=0UL; p<partition_max; p++ ) {
    fd_accdb_shmem_try_enqueue_compaction( accdb->shmem, p );
  }

  fd_spinlock_release( &accdb->shmem->partition_lock );
}

static inline uint
delta_chain( fd_accdb_shmem_t const * accdb,
             uchar const              pubkey[ 32 ] ) {
  uint hash = (uint)fd_hash32( pubkey, accdb->delta.seed );
  return hash & accdb->delta.chain_mask;
}

static int
delta_insert( fd_accdb_t * accdb,
              uchar const  pubkey[ 32 ] ) {
  /* FIXME consider batch inserting */
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_UNLIKELY( shmem->delta.head >= shmem->delta.ele_max ) ) return 0;

  uint *             chains = accdb->delta.chains;
  uint *             chain  = &chains[ delta_chain( shmem, pubkey ) ];
  fd_accdb_delta_t * pool   = accdb->delta.pool;

  uint head = *chain;
  for( uint cur=head; cur!=UINT_MAX; cur=pool[ cur ].next ) {
    if( FD_UNLIKELY( !memcmp( pool[ cur ].pubkey, pubkey, 32UL ) ) ) return 1;
  }

  ulong idx = shmem->delta.head++;
  fd_accdb_delta_t * delta = &pool[ idx ];
  delta->next = head;
  memcpy( delta->pubkey, pubkey, 32UL );
  *chain = (uint)idx;
  return 1;
}

int
fd_accdb_snapshot_recover_delta( fd_accdb_t *       accdb,
                                 fd_accdb_fork_id_t fork_id ) {
  if( FD_UNLIKELY( fork_id.val>=fork_pool_ele_max( accdb->fork_shmem_pool ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_snapshot_recover_delta: invalid fork id %u (capacity %lu)",
                  (uint)fork_id.val, fork_pool_ele_max( accdb->fork_shmem_pool ) ));
  }

  uint txn_idx = accdb->fork_pool[ fork_id.val ].shmem->txn_head;
  while( txn_idx!=UINT_MAX ) {
    fd_accdb_txn_t const * txn = txn_pool_ele( accdb->txn_pool, (ulong)txn_idx );
    fd_accdb_accmeta_t const * acc = &accdb->acc_pool[ txn->acc_pool_idx ];
    if( FD_UNLIKELY( !delta_insert( accdb, acc->key.pubkey ) ) ) return -1;
    txn_idx = txn->fork.next;
  }
  return 0;
}

void
fd_accdb_for_each_modified( fd_accdb_t *           accdb,
                            fd_accdb_fork_id_t     fork_id,
                            fd_accdb_modified_fn_t fn,
                            void *                 ctx ) {
  if( FD_UNLIKELY( fork_id.val>=fork_pool_ele_max( accdb->fork_shmem_pool ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_for_each_modified: invalid fork id %u (capacity %lu)",
                  (uint)fork_id.val, fork_pool_ele_max( accdb->fork_shmem_pool ) ));
  }

  uint txn_idx = accdb->fork_pool[ fork_id.val ].shmem->txn_head;
  while( txn_idx!=UINT_MAX ) {
    fd_accdb_txn_t const * txn = txn_pool_ele( accdb->txn_pool, (ulong)txn_idx );
    fn( ctx, accdb->acc_pool[ txn->acc_pool_idx ].key.pubkey );
    txn_idx = txn->fork.next;
  }
}

void
fd_accdb_snapshot_save_whead( fd_accdb_t *                   accdb,
                              fd_accdb_snapshot_recovery_t * out ) {
  /* Flush metrics to update disk_current_bytes. */
  fd_accdb_flush_metrics( accdb );

  out->whead_val          = FD_VOLATILE_CONST( accdb->shmem->whead[ 0 ].val );
  out->has_partition      = FD_VOLATILE_CONST( accdb->shmem->has_partition[ 0 ] );
  out->partition_max      = FD_VOLATILE_CONST( accdb->shmem->partition_max );
  out->disk_current_bytes = FD_VOLATILE_CONST( accdb->shmem->shmetrics->disk_current_bytes );

  if( out->has_partition ) {
    accdb_offset_t whead = { .val = out->whead_val };
    ulong idx = packed_partition_idx( &whead );
    fd_accdb_partition_t * part = partition_pool_ele( accdb->partition_pool, idx );
    out->savepoint_bytes_freed = FD_VOLATILE_CONST( part->bytes_freed );
  } else {
    out->savepoint_bytes_freed = 0UL;
  }
}

void
fd_accdb_snapshot_revert_whead( fd_accdb_t *                         accdb,
                                fd_accdb_snapshot_recovery_t const * recover ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  /* Partitions are about to be released, so flush metrics first. */
  fd_accdb_flush_metrics( accdb );

  /* The incremental fork purge must be applied, and its accounts
     released, before its partitions are. */
  wait_idle( accdb );

  ulong cur_partition_max = shmem->partition_max;

  /* Materialize the active partition's write_offset from the whead
     before releasing.  Closed partitions have write_offset set by
     change_partition, but the last active partition still has
     write_offset == 0 from its initialization.  The real byte offset
     is encoded in whead[0]. */
  if( shmem->has_partition[ 0 ] && cur_partition_max>recover->partition_max ) {
    ulong active_idx = packed_partition_idx( &shmem->whead[ 0 ] );
    if( active_idx>=recover->partition_max && active_idx<cur_partition_max ) {
      fd_accdb_partition_t * active = partition_pool_ele( accdb->partition_pool, active_idx );
      active->write_offset = packed_partition_offset( &shmem->whead[ 0 ] );
    }
  }

  /* Release partitions that have been previously allocated.  Must hold
     partition_lock because partition_pool_ele_release mutates the
     pool free list.  Before releasing, unlink any partition that sits
     on a compaction dlist (queued flag).

     Release in descending index order so that the LIFO free list
     re-acquires them in ascending order (P, P+1, P+2, ...).  This
     preserves the ascending partition index order expected when the
     released suffix is allocated again. */
  fd_spinlock_acquire( &shmem->partition_lock );
  for( ulong p=cur_partition_max; p>recover->partition_max; p-- ) {
    fd_accdb_partition_t * part = partition_pool_ele( accdb->partition_pool, p-1UL );
    if( FD_UNLIKELY( part->queued ) ) {
      compaction_dlist_ele_remove( accdb->compaction_dlist[ part->layer ], part, accdb->partition_pool );
    }
    FD_VOLATILE( part->write_offset ) = 0UL;
    partition_pool_ele_release( accdb->partition_pool, part );
  }

  shmem->whead[ 0 ].val     = recover->whead_val;
  shmem->has_partition[ 0 ] = recover->has_partition;
  shmem->partition_max      = recover->partition_max;

  /* disk_used_bytes is NOT saved/restored here.  It is implicitly
     reverted by purge_inner -> acc_unlink, which decrements
     disk_used_bytes for each unlinked entry.  The caller must
     complete the purge before calling revert_whead. */

  shmem->shmetrics->disk_current_bytes = recover->disk_current_bytes;

  if( recover->has_partition ) {
    accdb_offset_t sp_off = (accdb_offset_t){ .val = recover->whead_val };
    ulong sp_idx = packed_partition_idx( &sp_off );
    fd_accdb_partition_t * sp = partition_pool_ele( accdb->partition_pool, sp_idx );
    sp->bytes_freed   = recover->savepoint_bytes_freed;
    sp->write_offset  = 0UL;
  }

  fd_spinlock_release( &shmem->partition_lock );
}

fd_accdb_t *
fd_accdb_join( void * shaccdb ) {
  if( FD_UNLIKELY( !shaccdb ) ) {
    FD_LOG_WARNING(( "NULL shaccdb" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shaccdb, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shaccdb" ));
    return NULL;
  }

  return (fd_accdb_t*)shaccdb;
}

fd_accdb_t *
fd_accdb_join_readonly( void *             ljoin,
                        fd_accdb_shmem_t * shmem,
                        ulong *            my_epoch_slot_rw,
                        int                fd_ro,
                        int                idx_fd_ro ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !my_epoch_slot_rw ) ) {
    FD_LOG_WARNING(( "NULL my_epoch_slot_rw" ));
    return NULL;
  }

  ulong max_live_slots = shmem->max_live_slots;
  ulong pool_max       = shmem->acc_pool_max;
  ulong partition_cnt  = shmem->partition_cnt;

  ulong chain_cnt = shmem->chain_cnt;
  ulong txn_max   = shmem->txn_pool_max;

  /* Recompute the same shmem scratch layout that fd_accdb_shmem_new
     used.  All FD_SCRATCH_ALLOC_APPEND calls here only compute pointer
     offsets — they do not write to shmem. */
  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool_ele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t),    pool_max*sizeof(fd_accdb_accmeta_t)                     );
                             FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_txn_t),        txn_max*sizeof(fd_accdb_txn_t)                          );
                             FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),         partition_pool_footprint( partition_cnt )               );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
                             FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(),       compaction_dlist_footprint()                            );
  }
                             FD_SCRATCH_ALLOC_APPEND( l, deferred_free_dlist_align(),    deferred_free_dlist_footprint()                         );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_accdb_t * accdb      = FD_SCRATCH_ALLOC_APPEND( l2, fd_accdb_align(),         sizeof(fd_accdb_t)                     );
  void * _local_fork_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );

  accdb->fd    = fd_ro;
  accdb->scratch_fd = -1;
  accdb->readonly   = 1;
  accdb->residual_ticket = ULONG_MAX;
  accdb->park_sleep      = NULL;
  accdb->park_word       = NULL;
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
  accdb->shmem = shmem;
  FD_TEST( acc_pool_join( accdb->acc_pool_join, shmem->acc_pool, _acc_pool_ele, pool_max ) );
  idx_join( accdb, idx_fd_ro );
  accdb->acc_pool = accdb->acc_pool_join->ele;
  accdb->acc_map  = _acc_map;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache[ c ] = (uchar *)shmem + shmem->cache_region_off[ c ];

  /* Writer-only structures: leave NULL so any accidental writer-path
     call from a readonly joiner crashes loudly rather than corrupting
     state. */
  accdb->partition_pool      = NULL;
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) accdb->compaction_dlist[ k ] = NULL;
  accdb->deferred_free_dlist = NULL;
  accdb->delta.chains        = NULL;
  accdb->delta.pool          = NULL;

  FD_TEST( fork_pool_join( accdb->fork_shmem_pool, shmem->fork_pool, _fork_pool_ele, max_live_slots ) );
  accdb->fork_pool = _local_fork_pool;
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_accdb_fork_t * fork = &accdb->fork_pool[ i ];
    fork->shmem    = fork_pool_ele( accdb->fork_shmem_pool, i );
    fork->descends = descends_set_join( (uchar *)_descends_sets + i*descends_set_footprint( max_live_slots ) );
    FD_TEST( fork->shmem );
    FD_TEST( fork->descends );
  }

  /* my_epoch_slot_rw points at memory owned by this joiner (e.g. a
     private per-tile fseq) that the joiner can write to.  The
     accdb tile sees it via its external_epoch_slots[] array (mapped
     read-only) and includes it in its compaction epoch scan.
     Storing through this pointer is the only side effect a readonly
     joiner has on shared state. */
  accdb->my_epoch_slot = my_epoch_slot_rw;

  /* Readonly joiners do not own external slots themselves; only the
     compaction tile / writer joiners do. */
  accdb->external_epoch_slots = NULL;
  accdb->external_epoch_cnt   = 0UL;
  accdb->bounce               = NULL;
  accdb->stage                = NULL;

  accdb->prealloc_failed_at  = ULONG_MAX;

  memset( accdb->metrics,      0, sizeof(fd_accdb_metrics_t) );
  memset( &accdb->write_stats, 0, sizeof(accdb->write_stats) );

  return accdb;
}

fd_accdb_fork_id_t
fd_accdb_attach_child( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t parent_fork_id ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  if( FD_UNLIKELY( shmem->generation==UINT_MAX ) ) FD_LOG_ERR(( "accdb ran out of generation sequence numbers, restart required" ));

  /* The pool can be exhausted by forks that are purged or rooted past
     but not yet released.  The accdb tile releases them once concurrent
     readers drain. */
  fd_accdb_fork_shmem_t * acquired = fork_pool_acquire( accdb->fork_shmem_pool );
  if( FD_UNLIKELY( !acquired ) ) {
    wait_idle( accdb );
    acquired = fork_pool_acquire( accdb->fork_shmem_pool );
    FD_CHECK_CRIT( acquired, "accdb fork pool exhausted" );
  }
  ulong idx = fork_pool_idx( accdb->fork_shmem_pool, acquired );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ idx ];
  fd_accdb_fork_id_t fork_id = { .val = (ushort)idx };

  /* The slot's previous fork may still have its bit set in the
     descends_set of a fork that descended from it.  That bit was
     harmless while the slot was retired (a rooted fork's accounts are
     visible by generation, a purged fork had no live descendants), but
     it would make the new fork look like an ancestor.  Clear it before
     the new fork can write any account. */
  for( ulong i=0UL; i<shmem->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, idx );

  fork->shmem->child_id   = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->generation = shmem->generation++;
  fork->shmem->txn_head   = UINT_MAX;
  if( FD_UNLIKELY( accdb->tier ) ) idx_fork( accdb, idx )->frozen = 0U;

  if( FD_UNLIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    /* Published as both the applied and the requested root, so the
       accdb tile has nothing to root.  The request keeps purge_seq
       (the accdb tile is idle, so every purge is applied). */
    FD_CHECK_CRIT( shmem->root_fork_id.val==USHORT_MAX, "accdb root fork already exists" );
    fork->shmem->parent_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    descends_set_null( fork->descends );
    FD_VOLATILE( shmem->root_fork_id ) = fork_id;
    fd_accdb_req_t req = shmem->req;
    req.root_gen = fork->shmem->generation;
    publish_req( accdb, req );
  } else {
    /* Forks below the requested root have a single child that the
       accdb tile may be rooting.  Every other live fork descends from
       the requested root and so is newer. */
    fd_accdb_fork_t * parent = &accdb->fork_pool[ parent_fork_id.val ];
    FD_CHECK_CRIT( shmem->root_fork_id.val!=USHORT_MAX, "attach_child before the root fork exists" );
    FD_CHECK_CRIT( parent->shmem->generation>=shmem->req.root_gen, "attach_child parent is an ancestor of the root" );
    fork->shmem->parent_id  = parent_fork_id;
    fork->shmem->sibling_id = parent->shmem->child_id;
    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );
    parent->shmem->child_id = fork_id;
  }

  FD_TEST( !descends_set_test( fork->descends, fork_id.val ) );

  return fork_id;
}

static int
grow_locked( fd_accdb_t * accdb,
             ulong        partition_idx,
             uchar        layer,
             ulong        prior_partition_idx,
             int          preallocated ) {
  for( ulong p=accdb->shmem->partition_fallocated; p<=partition_idx; p++ ) {
    FD_LOG_INFO(( "growing accounts database from %lu GiB to %lu GiB", p*accdb->shmem->partition_sz/(1UL<<30UL), (p+1UL)*accdb->shmem->partition_sz/(1UL<<30UL) ));

    long fallocate_nanos = -fd_log_wallclock();
    int  result          = fallocate( accdb->fd, 0, (long)(p*accdb->shmem->partition_sz), (long)accdb->shmem->partition_sz );
    fallocate_nanos     += fd_log_wallclock();
    if( FD_UNLIKELY( -1==result ) ) {
      if( FD_LIKELY( preallocated ) ) return errno;
      if( FD_LIKELY( errno==ENOSPC ) ) FD_LOG_ERR(( "fallocate() failed (%d-%s). The accounts database filled "
                                                    "the disk it is on, trying to grow from %lu GiB to %lu GiB. Please "
                                                    "free up disk space and restart the validator.",
                                                    errno, fd_io_strerror( errno ), p*accdb->shmem->partition_sz/(1UL<<30UL), (p+1UL)*accdb->shmem->partition_sz/(1UL<<30UL) ));
      else FD_LOG_ERR(( "fallocate() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    FD_VOLATILE( accdb->shmem->partition_fallocated ) = p+1UL;
    accdb->shmem->shmetrics->disk_allocated_bytes = (p+1UL)*accdb->shmem->partition_sz;

    fd_event_accdb_partition_added_t ev = {
      .partition_idx        = p,
      .prior_partition_idx  = p==partition_idx ? prior_partition_idx : ULONG_MAX,
      .layer                = layer,
      .old_partition_max    = p,
      .new_partition_max    = p+1UL,
      .partition_sz         = accdb->shmem->partition_sz,
      .disk_allocated_bytes = (p+1UL)*accdb->shmem->partition_sz,
      .duration_fallocate_nanos = (ulong)fd_long_max( fallocate_nanos, 0L ),
      .preallocated         = preallocated,
    };
    fd_event_report_accdb_partition_added( &ev );
  }
  return 0;
}

static inline void
change_partition( fd_accdb_t *           accdb,
                  accdb_offset_t const * offset_before,
                  accdb_offset_t *       out_offset,
                  int *                  has_partition,
                  uchar                  layer ) {
  /* New data will not fit in the current partition, so we need to
     move to the next one.  */
  fd_spinlock_acquire( &accdb->shmem->partition_lock );
  ulong partition_idx_before = packed_partition_idx( offset_before );
  ulong partition_offset_before = packed_partition_offset( offset_before );
  if( FD_LIKELY( *has_partition ) ) {
    fd_accdb_partition_t * before = partition_pool_ele( accdb->partition_pool, partition_idx_before );
    before->write_offset = partition_offset_before;
  }

  /* Single rdtsc per partition lifecycle event: stamp the closing
     partition's filled time and the new partition's created time off
     the same sample. */
  long now_ticks = (long)fd_tickcount();

  ulong free_size = accdb->shmem->partition_sz - partition_offset_before;
  if( FD_LIKELY( *has_partition ) ) {
    fd_accdb_partition_t * old = partition_pool_ele( accdb->partition_pool, partition_idx_before );
    FD_ATOMIC_FETCH_AND_ADD( &old->bytes_freed, free_size );
    FD_VOLATILE( old->filled_ticks ) = now_ticks;
    /* The tail slack is now committed dead — count it as current
       (written-through) so fragmentation reflects it. */
    FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_current_bytes, free_size );
  }

  if( FD_UNLIKELY( !partition_pool_free( accdb->partition_pool ) ) ) FD_LOG_ERR(( "accounts database file is at capacity" ));
  fd_accdb_partition_t * partition = partition_pool_ele_acquire( accdb->partition_pool );
  partition->bytes_freed       = 0UL;
  partition->marked_compaction = 0;
  partition->layer             = layer;
  partition->read_ops          = 0UL;
  partition->bytes_read        = 0UL;
  partition->write_ops         = 0UL;
  partition->bytes_written     = 0UL;
  partition->write_offset      = 0UL;
  partition->compaction_offset = 0UL;
  partition->created_ticks     = now_ticks;
  partition->filled_ticks      = 0L;
  partition->queued            = 0;
  partition->compacting_now    = 0;

  ulong new_partition_idx = partition_pool_idx( accdb->partition_pool, partition );
  int had_partition = *has_partition;

  /* Snapshot-load tiering: accounts loaded from a snapshot never get
     a second write, so compaction-driven promotion never fires and
     they would otherwise live in Hot forever.  When snapshot_loading
     is set, tag the new partition as Cold up front.
     fd_accdb_snapshot_load_end transfers the last snapshot partition
     to the Cold write head if that head is not already set. */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( accdb->shmem->snapshot_loading ) && layer==0 ) ) {
    FD_VOLATILE( partition->layer ) = FD_ACCDB_COMPACTION_LAYER_CNT-1UL;
  }

  if( FD_UNLIKELY( new_partition_idx>=accdb->shmem->partition_max ) ) FD_VOLATILE( accdb->shmem->partition_max ) = new_partition_idx+1UL;
  fd_spinlock_release( &accdb->shmem->partition_lock );

  /* Back the partition before publishing the head, so no writer
     reserves into it while fallocate is running.  Layer-0 writers spin
     on the head until then. */
  if( FD_UNLIKELY( new_partition_idx>=FD_VOLATILE_CONST( accdb->shmem->partition_fallocated ) ) ) {
    fd_spinlock_acquire( &accdb->shmem->grow_lock );
    grow_locked( accdb, new_partition_idx, layer, had_partition ? partition_idx_before : ULONG_MAX, 0 );
    fd_spinlock_release( &accdb->shmem->grow_lock );
  }

  fd_spinlock_acquire( &accdb->shmem->partition_lock );
  *out_offset   = accdb_offset( new_partition_idx, 0UL );
  FD_COMPILER_MFENCE();
  *has_partition = 1;
  if( FD_LIKELY( had_partition && partition_idx_before!=new_partition_idx ) ) {
    fd_accdb_shmem_try_enqueue_compaction( accdb->shmem, partition_idx_before );
  }
  fd_spinlock_release( &accdb->shmem->partition_lock );
}

/* Reserve sz bytes in the layer-0 write head and set
   out_partition_idx to where they landed.  Bumps no counters. */

static inline ulong
reserve_next_write( fd_accdb_t * accdb,
                    ulong        sz,
                    ulong *      out_partition_idx ) {
  for(;;) {
    accdb_offset_t offset = { .val = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->whead[ 0 ].val, sz ) };
    if( FD_LIKELY( packed_partition_offset( &offset )+sz<=accdb->shmem->partition_sz ) ) {
      *out_partition_idx = packed_partition_idx( &offset );
      return packed_partition_file_offset( &offset, accdb->shmem->partition_sz );
    }

    if( FD_UNLIKELY( packed_partition_offset( &offset )>accdb->shmem->partition_sz ) ) {
      /* This can happen if another thread also raced to allocate the
         next write and won.  Wait for the partition switch to finish
         before retrying, so we do not keep doing fetch-and-adds that
         advance the offset further past the boundary.

         A switch is detected by the head moving to a different
         partition index OR its offset dropping back to a valid position
         (a switch resets the offset to 0).  We must not key the wait
         solely on the index changing: the initial write head is a
         sentinel whose packed index can coincide with a real pool
         index. */
      ulong stale_partition = packed_partition_idx( &offset );
      for(;;) {
        accdb_offset_t cur = { .val = FD_VOLATILE_CONST( accdb->shmem->whead[ 0 ].val ) };
        if( packed_partition_idx( &cur )!=stale_partition ) break;
        if( packed_partition_offset( &cur )<=accdb->shmem->partition_sz ) break;
        fd_racesan_hook( "accdb_reserve:switch_wait" );
        FD_SPIN_PAUSE();
      }
      continue;
    }

    change_partition( accdb, &offset, &accdb->shmem->whead[ 0 ], &accdb->shmem->has_partition[ 0 ], 0 );
  }
}

/* Reserve sz bytes.  Layer-0 write metrics are deferred until
   explicitly flushed. */

static inline ulong
allocate_next_write( fd_accdb_t * accdb,
                     ulong        sz ) {
  ulong partition_idx;
  ulong file_offset = reserve_next_write( accdb, sz, &partition_idx );

  /* Very rarely the reservation crosses into a new partition.  Since
     stats are aggregated per-partition, any accumulated stats are
     flushed and reset to accommodate the new partition. */
  if( FD_LIKELY( accdb->write_stats.num_ops ) &&
      FD_UNLIKELY( accdb->write_stats.partition_idx!=partition_idx ) ) {
    fd_accdb_flush_metrics( accdb );
  }

  accdb->write_stats.partition_idx  = partition_idx;
  accdb->write_stats.bytes         += sz;
  accdb->write_stats.num_ops++;
  return file_offset;
}

/* write_iov writes iov[0,n) (sz bytes in all) at file offset off,
   retrying partial writes.  n<=IOV_MAX. */

static void
write_iov( fd_accdb_t *   accdb,
           ulong          off,
           struct iovec * iov,
           ulong          n,
           ulong          sz ) {
  ulong i0 = 0UL;
  for( ulong done=0UL; done<sz; ) {
    long r = pwritev2( accdb->fd, iov+i0, (int)( n-i0 ), (long)( off+done ), 0 );
    if( FD_UNLIKELY( -1==r && ( errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==r ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !r ) ) FD_LOG_ERR(( "accounts database is corrupt, pwritev2() returned 0 at offset %lu", off+done ));
    done += (ulong)r;
    accdb->metrics->bytes_written += (ulong)r;
    accdb->metrics->write_ops++;
    for( ulong u=(ulong)r; u; ) {
      if( u>=iov[ i0 ].iov_len ) { u -= iov[ i0 ].iov_len; iov[ i0 ].iov_len = 0UL; i0++; }
      else { iov[ i0 ].iov_base = (uchar *)iov[ i0 ].iov_base + u; iov[ i0 ].iov_len -= u; u = 0UL; }
    }
  }
}

/* read_full reads sz bytes at file offset off into buf.  preadv2, not
   pread: tile seccomp policies allow only preadv2 on the accounts fd. */

static void
read_full( fd_accdb_t * accdb,
           ulong        off,
           void *       buf,
           ulong        sz ) {
  for( ulong done=0UL; done<sz; ) {
    struct iovec iov = { .iov_base = (uchar *)buf+done, .iov_len = sz-done };
    long r = preadv2( accdb->fd, &iov, 1, (long)( off+done ), 0 );
    if( FD_UNLIKELY( -1==r && ( errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==r ) ) FD_LOG_ERR(( "preadv2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !r ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents", off+done, sz ));
    fd_accdb_partition_read_bump( accdb, off+done, (ulong)r );
    done += (ulong)r;
    accdb->metrics->bytes_read += (ulong)r;
    accdb->metrics->read_ops++;
  }
}

/* Data word and disk offset.  A version is bound to a line while its
   data word is VALID and names it.  The offset is DIRTY(line) while that
   line holds the only copy.  Only clean versions are unbound, so a cold
   load always finds its record on disk. */

static inline ulong
rec_sz( uint es ) {
  return sizeof(fd_accdb_disk_meta_t)+(ulong)FD_ACCDB_SIZE_DATA( es );
}

/* off_swap sets the offset to `to` and frees the record it replaced,
   if any (es: its size word). */

static void
off_swap( fd_accdb_t *         accdb,
          fd_accdb_accmeta_t * meta,
          ulong                to,
          uint                 es ) {
  ulong old = fd_accdb_acc_xchg_offset( meta, to );
  if( FD_LIKELY( !FD_ACCDB_OFF_CLEAN( old ) ) ) return;
  fd_accdb_shmem_bytes_freed( accdb->shmem, old, rec_sz( es ) );
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, rec_sz( es ) );
}

/* off_publish swaps DIRTY(cidx) for the written-back record off.  If a
   commit or unlink got there first, the record is freed instead. */

static void
off_publish( fd_accdb_t *         accdb,
             fd_accdb_accmeta_t * meta,
             uint                 cidx,
             ulong                off,
             ulong                sz ) {
  ushort f    = fd_accdb_acc_fork_id( meta );
  ulong  dirty = fd_accdb_acc_pack_offset_fork( FD_ACCDB_OFF_DIRTY( cidx ), f );
  if( FD_LIKELY( FD_ATOMIC_CAS( &meta->offset_fork, dirty, fd_accdb_acc_pack_offset_fork( off, f ) )==dirty ) ) return;
  fd_accdb_shmem_bytes_freed( accdb->shmem, off, sz );
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, sz );
}

/* Cache lines.  An acquire holds a line by an entry in its join's
   hazard list.

   Hold vs evict (Dekker): the holder stores its entry, fences, then
   waits out EVICTING and checks the binding.  The evictor claims
   (SHARED -> EVICTING), fences, then scans every list.  Either the scan
   sees the entry (the line goes back) or the holder sees the unbind.

   In-place commit vs evict (Dekker): the committer swaps the offset to
   UPDATING then loads the state; the evictor claims then loads the
   offset.  Whoever loses backs off. */

static inline fd_accdb_cache_line_t *
line_at( fd_accdb_t * accdb,
         uint         cidx ) {
  return cache_line( accdb, FD_ACCDB_ACC_CIDX_CLASS( cidx ), FD_ACCDB_ACC_CIDX_IDX( cidx ) );
}

/* line_seq_open / close bracket a rewrite of a line's bytes for unheld
   readers: seq is odd in between.  open always moves to a new odd value,
   even if the last open was never closed. */

static inline void
line_seq_open( fd_accdb_cache_line_t * line ) {
  FD_VOLATILE( line->seq ) = ( line->seq+1UL )|1UL;
  FD_COMPILER_MFENCE();  /* the odd seq before any byte we write */
}

static inline void
line_seq_close( fd_accdb_cache_line_t * line ) {
  FD_COMPILER_MFENCE();  /* the bytes before the even seq */
  FD_VOLATILE( line->seq ) = line->seq+1UL;
}

/* line_grab takes a FREE line, OWNED by us, if nobody grabs it first. */

static inline int
line_grab( fd_accdb_cache_line_t * line ) {
  if( FD_UNLIKELY( FD_VOLATILE_CONST( line->state )!=FD_ACCDB_LINE_FREE ) ) return 0;
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &line->state, FD_ACCDB_LINE_FREE, FD_ACCDB_LINE_OWNED )!=FD_ACCDB_LINE_FREE ) ) return 0;
  line_seq_open( line );
  return 1;
}

/* line_publish makes a line we own SHARED, with one more CLOCK lap. */

static inline void
line_publish( fd_accdb_cache_line_t * line ) {
  FD_VOLATILE( line->hot ) = 1;
  FD_COMPILER_MFENCE();  /* its bytes and fields before the state */
  FD_VOLATILE( line->state ) = FD_ACCDB_LINE_SHARED;
}

/* hazard_list_has returns whether join j holds line cidx.  The AVX-512
   path reads whole vectors (the list is padded). */

static inline int
hazard_list_has( fd_accdb_shmem_t const * shmem,
                 ulong                    j,
                 uint                     cidx ) {
  ulong        cnt = fd_ulong_min( FD_VOLATILE_CONST( shmem->cache_hazard[ j ].cnt ), FD_ACCDB_HAZARD_MAX );
  uint const * arr = shmem->cache_hazard[ j ].cidx;
  FD_COMPILER_MFENCE();  /* cnt before the entries */
#if FD_HAS_AVX512
  wwu_t want = wwu_bcast( cidx );
  for( ulong k=0UL; k<cnt; k+=16UL ) {
    uint hit = (uint)wwu_eq( wwu_ldu( arr+k ), want );
    if( FD_UNLIKELY( hit ) ) {
      /* a hit past cnt is padding: either way the scan ends */
      return !!( hit & (uint)fd_ulong_mask_lsb( (int)fd_ulong_min( cnt-k, 16UL ) ) );
    }
  }
#else
  for( ulong k=0UL; k<cnt; k++ ) if( FD_UNLIKELY( FD_VOLATILE_CONST( arr[ k ] )==cidx ) ) return 1;
#endif
  return 0;
}

/* line_scan sets held[k] if any join holds line cidx[k].  A batch is
   checked in one pass over every list, against a hash table. */

#define RECLAIM_MAX (64UL)

static void
line_scan( fd_accdb_t * accdb,
           uint const * cidx,
           uchar *      held,
           ulong        cnt ) {
  enum { tab_lg = 7, tab_sz = 1<<tab_lg };       /* 2*RECLAIM_MAX slots: load <= 1/2 */
  FD_STATIC_ASSERT( tab_sz==2UL*RECLAIM_MAX, reclaim_tab );
  ulong const mul = 0x9E3779B97F4A7C15UL;       /* Fibonacci hashing: top tab_lg bits of cidx*mul */

  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong joiner_cnt = fd_ulong_min( FD_VOLATILE_CONST( shmem->joiner_cnt ), FD_ACCDB_MAX_JOINERS );
  FD_HW_MFENCE();  /* StoreLoad: our claims before the entries (holders' Dekker) */
  fd_racesan_hook( "accdb_hazard:pre_scan" );

  /* One line: a linear scan of each list */
  if( cnt==1UL ) {
    held[ 0 ] = 0;
    for( ulong j=0UL; j<joiner_cnt && !held[ 0 ]; j++ ) held[ 0 ] = (uchar)hazard_list_has( shmem, j, cidx[ 0 ] );
    return;
  }

  /* Hash the batch */
  uint  tab[ tab_sz ];   /* cidx+1, 0 empty */
  uchar pos[ tab_sz ];
  memset( tab, 0, sizeof(tab) );
  for( ulong k=0UL; k<cnt; k++ ) {
    held[ k ] = 0;
    ulong h = ( (ulong)cidx[ k ]*mul )>>( 64-tab_lg );
    while( tab[ h ] ) h = ( h+1UL )&( (ulong)tab_sz-1UL );
    tab[ h ] = cidx[ k ]+1U;
    pos[ h ] = (uchar)k;
  }

  /* Look up every entry of every list */
  for( ulong j=0UL; j<joiner_cnt; j++ ) {
    ulong        n   = fd_ulong_min( FD_VOLATILE_CONST( shmem->cache_hazard[ j ].cnt ), FD_ACCDB_HAZARD_MAX );
    uint const * arr = shmem->cache_hazard[ j ].cidx;
    FD_COMPILER_MFENCE();  /* cnt before the entries */
    for( ulong e=0UL; e<n; e++ ) {
      uint c = FD_VOLATILE_CONST( arr[ e ] );
      if( c==FD_ACCDB_ACC_CIDX_INVAL ) continue;
      for( ulong h=( (ulong)c*mul )>>( 64-tab_lg ); tab[ h ]; h=( h+1UL )&( (ulong)tab_sz-1UL ) ) {
        if( FD_UNLIKELY( tab[ h ]==c+1U ) ) { held[ pos[ h ] ] = 1; break; }
      }
    }
  }
}

/* line_writeback writes back the lines with dirty[k] set, one pwritev2
   per partition-sized chunk, and publishes their offsets. */

static void
line_writeback( fd_accdb_t *             accdb,
                uint const *             cidx,
                fd_accdb_cache_line_t ** line,
                uchar const *            dirty,
                ulong                    cnt ) {
  fd_accdb_disk_meta_t hdr[ RECLAIM_MAX ];
  struct iovec         iov[ 2UL*RECLAIM_MAX ];
  ulong                rsz[ RECLAIM_MAX ];
  uint                 who[ RECLAIM_MAX ];
  ulong n  = 0UL;
  ulong sz = 0UL;
  for( ulong k=0UL; k<=cnt; k++ ) {
    /* Skip clean lines */
    ulong esz = 0UL;
    if( k<cnt ) {
      if( !dirty[ k ] ) continue;
      esz = rec_sz( FD_ACCDB_DATA_ES( FD_VOLATILE_CONST( accdb->acc_pool[ line[ k ]->acc_idx ].data ) ) );
    }

    /* Flush the chunk at the end, or when it would overflow a partition */
    if( n && ( k==cnt || sz+esz>accdb->shmem->partition_sz ) ) {
      ulong off = allocate_next_write( accdb, sz );
      write_iov( accdb, off, iov, 2UL*n, sz );
      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_used_bytes, sz );
      fd_racesan_hook( "accdb_writeback:post_write" );
      FD_COMPILER_MFENCE();  /* the records before their offsets */
      for( ulong x=0UL; x<n; x++ ) {
        off_publish( accdb, &accdb->acc_pool[ line[ who[ x ] ]->acc_idx ], cidx[ who[ x ] ], off, rsz[ x ] );
        off += rsz[ x ];
      }
      n = 0UL; sz = 0UL;
    }
    if( k==cnt ) break;

    /* Queue the record: header, then the line's bytes */
    fd_accdb_accmeta_t const * m = &accdb->acc_pool[ line[ k ]->acc_idx ];
    fd_memcpy( hdr[ n ].pubkey, m->key.pubkey, 32UL );
    hdr[ n ].size       = (uint)( esz-sizeof(fd_accdb_disk_meta_t) );
    hdr[ n ].generation = m->key.generation;
    fd_memcpy( hdr[ n ].owner, line[ k ]->owner, 32UL );
    iov[ 2UL*n     ] = (struct iovec){ .iov_base = &hdr[ n ],     .iov_len = sizeof(fd_accdb_disk_meta_t) };
    iov[ 2UL*n+1UL ] = (struct iovec){ .iov_base = line[ k ]+1UL, .iov_len = hdr[ n ].size };
    rsz[ n ] = esz;
    who[ n ] = (uint)k;
    n++;
    sz += esz;
  }
}

/* line_reclaim is CLOCK, used by both the foreground and pre-eviction.
   It visits up to `visit` lines of class c and takes up to `want` (OWNED
   by us, empty) into out[].  Returns how many. */

static ulong
line_reclaim( fd_accdb_t * accdb,
              ulong        c,
              ulong        visit,
              ulong        want,
              uint *       out,
              int          pre ) {   /* the accdb tile: count as pre-evicted */
  fd_accdb_shmem_t *      shmem = accdb->shmem;
  ulong                   max_c = shmem->cache_class_max[ c ];
  uint                    cidx [ RECLAIM_MAX ];
  fd_accdb_cache_line_t * line [ RECLAIM_MAX ];
  uchar                   flag [ RECLAIM_MAX ];
  ulong                   cnt   = 0UL;
  ulong                   taken = 0UL;
  want = fd_ulong_min( want, RECLAIM_MAX );

  /* Take never-used lines first */
  ulong * init = &shmem->cache_class_init[ c ].val;
  while( taken<want && FD_VOLATILE_CONST( *init )<max_c ) {
    ulong idx = FD_ATOMIC_FETCH_AND_ADD( init, 1UL );
    if( FD_UNLIKELY( idx>=max_c ) ) { FD_ATOMIC_FETCH_AND_SUB( init, 1UL ); break; }
    if( line_grab( cache_line( accdb, c, idx ) ) ) out[ taken++ ] = FD_ACCDB_ACC_CIDX_PACK( (uint)c, (uint)idx );  /* (a CLOCK may have got it first) */
  }

  /* Claim: FREE lines are taken as is, SHARED ones once their hint is spent */
  for( ulong v=0UL; v<visit && taken+cnt<want; v++ ) {
    ulong                   idx = FD_ATOMIC_FETCH_AND_ADD( &shmem->clock_hand[ c ].val, 1UL ) % max_c;
    fd_accdb_cache_line_t * l   = cache_line( accdb, c, idx );
    uchar                   st  = FD_VOLATILE_CONST( l->state );
    if( st==FD_ACCDB_LINE_FREE ) {
      if( line_grab( l ) ) out[ taken++ ] = FD_ACCDB_ACC_CIDX_PACK( (uint)c, (uint)idx );
      continue;
    }
    if( st!=FD_ACCDB_LINE_SHARED ) continue;
    if( FD_VOLATILE_CONST( l->hot ) ) { FD_VOLATILE( l->hot ) = 0; continue; }  /* second chance */
    if( FD_ATOMIC_CAS( &l->state, FD_ACCDB_LINE_SHARED, FD_ACCDB_LINE_EVICTING )!=FD_ACCDB_LINE_SHARED ) continue;
    fd_racesan_hook( "accdb_reclaim:post_claim" );
    cidx[ cnt ] = FD_ACCDB_ACC_CIDX_PACK( (uint)c, (uint)idx );
    line[ cnt ] = l;
    cnt++;
  }
  if( !cnt ) return taken;

  /* Scan: held lines go back, still bound */
  line_scan( accdb, cidx, flag, cnt );
  FD_COMPILER_MFENCE();  /* ended holds' uses before our reuse */
  ulong n = 0UL;
  for( ulong k=0UL; k<cnt; k++ ) {
    if( FD_UNLIKELY( flag[ k ] ) ) { line_publish( line[ k ] ); continue; }
    cidx[ n ] = cidx[ k ];
    line[ n ] = line[ k ];
    n++;
  }
  if( !n ) return taken;

  /* Write back dirty lines.  UPDATING: an in-place commit got there
     first, so give the line back. */
  ulong dirty = 0UL;
  for( ulong k=0UL; k<n; k++ ) {
    ulong off = fd_accdb_acc_offset( &accdb->acc_pool[ line[ k ]->acc_idx ] );
    flag[ k ] = off==FD_ACCDB_OFF_DIRTY( cidx[ k ] );
    dirty += flag[ k ];
    if( FD_UNLIKELY( off==FD_ACCDB_OFF_UPDATING ) ) { line_publish( line[ k ] ); line[ k ] = NULL; }
  }
  if( dirty ) {
    line_writeback( accdb, cidx, line, flag, n );
    if( pre ) {
      accdb->metrics->accounts_preevicted                += dirty;
      accdb->metrics->accounts_preevicted_per_class[ c ] += dirty;
    } else {
      accdb->metrics->accounts_evicted                += dirty;
      accdb->metrics->accounts_evicted_per_class[ c ] += dirty;
    }
  }

  /* Unbind (an orphan has nothing to unbind) and take.  The word can
     change under us (the unlinked mark), so retry until it no longer
     names the line: a line is never reused while a word still binds it. */
  for( ulong k=0UL; k<n; k++ ) {
    if( FD_UNLIKELY( !line[ k ] ) ) continue;
    fd_accdb_accmeta_t * m = &accdb->acc_pool[ line[ k ]->acc_idx ];
    for(;;) {
      ulong d = FD_VOLATILE_CONST( m->data );
      if( !( FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( d ) ) && FD_ACCDB_DATA_CIDX( d )==cidx[ k ] ) ) break;
      fd_racesan_hook( "accdb_reclaim:pre_unbind" );
      if( FD_LIKELY( FD_ATOMIC_CAS( &m->data, d, FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, FD_ACCDB_DATA_ES( d ) & ~FD_ACCDB_SIZE_CACHE_VALID_BIT ) )==d ) ) break;
    }
    line_seq_open( line[ k ] );
    FD_VOLATILE( line[ k ]->state ) = FD_ACCDB_LINE_OWNED;  /* a waiting holder reloads the word: unbound */
    out[ taken++ ] = cidx[ k ];
  }
  return taken;
}

/* Free lines.  Anyone may take a FREE line, so the free lists are only
   hints: a join's stash of lines it freed itself, and its ring per
   class, which pre-eviction fills.  A join with an empty ring sets the
   ring's hungry flag. */

static inline void
line_free( fd_accdb_t * accdb,
           uint         cidx ) {
  fd_accdb_cache_line_t * line = line_at( accdb, cidx );
  FD_COMPILER_MFENCE();  /* our use of the line before it is free */
  FD_VOLATILE( line->state ) = FD_ACCDB_LINE_FREE;
  ulong c = FD_ACCDB_ACC_CIDX_CLASS( cidx );
  if( FD_LIKELY( accdb->stash_cnt[ c ]<STASH_MAX ) ) accdb->stash[ c ][ accdb->stash_cnt[ c ]++ ] = cidx;
}

/* cache_free_ring wakes the accdb tile (rate-limited). */

static inline void
cache_free_ring( fd_accdb_t * accdb ) {
  if( FD_LIKELY( !accdb->sleep ) ) return;
  long now = fd_tickcount();
  if( FD_LIKELY( now-accdb->free_ring_ticks<FD_ACCDB_BG_RATE_TICKS ) ) return;
  accdb->free_ring_ticks = now;
  fd_sleep_ring( accdb->sleep, accdb->sleep_tile_id );
}

/* line_alloc_try takes a line of class c from the stash, the ring, or a
   CLOCK batch.  Returns INVAL if the batch found nothing. */

static uint
line_alloc_try( fd_accdb_t * accdb,
                ulong        c ) {
  /* Our own frees, newest first */
  while( accdb->stash_cnt[ c ] ) {
    uint cidx = accdb->stash[ c ][ --accdb->stash_cnt[ c ] ];
    if( FD_LIKELY( line_grab( line_at( accdb, cidx ) ) ) ) return cidx;
  }

  /* Hints from pre-eviction */
  fd_accdb_ring_t * r   = accdb->ring[ c ];
  uint              got = FD_ACCDB_ACC_CIDX_INVAL;
  for(;;) {
    uint * slot = &r->e[ r->c.cons%FD_ACCDB_RING_N ];
    uint   cidx = FD_VOLATILE_CONST( *slot );
    if( cidx==FD_ACCDB_ACC_CIDX_INVAL ) break;   /* empty */
    FD_VOLATILE( *slot ) = FD_ACCDB_ACC_CIDX_INVAL;
    FD_VOLATILE( r->c.cons ) = r->c.cons+1UL;  /* pre-eviction reads it to count our hints */
    if( FD_LIKELY( line_grab( line_at( accdb, cidx ) ) ) ) { got = cidx; break; }
  }
  if( FD_LIKELY( got!=FD_ACCDB_ACC_CIDX_INVAL ) ) return got;

  /* Ran out: ask pre-eviction for more, unless already asked */
  if( !FD_VOLATILE_CONST( r->p.hungry ) ) {
    FD_VOLATILE( r->p.hungry ) = 1UL;
    cache_free_ring( accdb );
  }

  /* Our own CLOCK batch: keep one, stash the rest */
  uint  batch[ RECLAIM_MAX ];
  ulong want = fd_accdb_cache_slot_sz[ c ]<RECLAIM_LARGE_SZ ? RECLAIM_FG : 1UL;
  ulong n    = line_reclaim( accdb, c, RECLAIM_MAX, want, batch, 0 );
  if( FD_UNLIKELY( !n ) ) return FD_ACCDB_ACC_CIDX_INVAL;
  for( ulong k=1UL; k<n; k++ ) line_free( accdb, batch[ k ] );
  return batch[ 0 ];
}

/* line_alloc takes a line of class c, retrying until one frees up (the
   caller's reservation guarantees one will). */

static uint
line_alloc( fd_accdb_t * accdb,
            ulong        c ) {
  for(;;) {
    uint cidx = line_alloc_try( accdb, c );
    if( FD_LIKELY( cidx!=FD_ACCDB_ACC_CIDX_INVAL ) ) return cidx;
    fd_racesan_hook( "accdb_alloc:retry" );
    FD_SPIN_PAUSE();
  }
}

/* Reservations.  Release keeps up to cred_max of a join's reserved
   lines as idle credits (all joins together hold at most half a class),
   and acquire spends those before the shared counter.  A failed
   reservation steals every join's idle credits back. */

static inline int
res_tracked( fd_accdb_t const * accdb,
             ulong              c ) {
  return accdb->res_limit[ c ]!=ULONG_MAX;
}

static inline int
res_take( fd_accdb_t * accdb,
          ulong        c,
          ulong        n ) {
  /* Try local credits */
  ulong * cred = &accdb->cred[ c ];
  for( ulong v=FD_VOLATILE_CONST( *cred ); v>=n; ) {
    ulong seen = FD_ATOMIC_CAS( cred, v, v-n );
    if( FD_LIKELY( seen==v ) ) return 1;
    v = seen;
  }

  /* Try shared credits */
  ulong * used = &accdb->shmem->cache_class_used[ c ].val;
  if( FD_LIKELY( FD_ATOMIC_ADD_AND_FETCH( used, n )<=accdb->res_limit[ c ] ) ) return 1;
  FD_ATOMIC_FETCH_AND_SUB( used, n );
  return 0;
}

static inline void
res_give( fd_accdb_t * accdb,
          ulong        c,
          ulong        n ) {
  if( FD_UNLIKELY( !n ) ) return;
  ulong * cred = &accdb->cred[ c ];
  ulong   max  = accdb->cred_max[ c ];
  if( FD_LIKELY( FD_ATOMIC_ADD_AND_FETCH( cred, n )<=max ) ) return;

  /* Over the cap: give the surplus back to the shared counter */
  for( ulong v=FD_VOLATILE_CONST( *cred ); v>max; ) {
    ulong seen = FD_ATOMIC_CAS( cred, v, max );
    if( FD_LIKELY( seen==v ) ) { FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ c ].val, v-max ); return; }
    v = seen;
  }
}

static void
res_steal( fd_accdb_t * accdb,
           ulong        c ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong joiner_cnt = fd_ulong_min( FD_VOLATILE_CONST( shmem->joiner_cnt ), FD_ACCDB_MAX_JOINERS );
  for( ulong j=0UL; j<joiner_cnt; j++ ) {
    ulong * cred = &shmem->join_cred[ j ].val[ c ];
    if( FD_LIKELY( !FD_VOLATILE_CONST( *cred ) ) ) continue;
    ulong s = FD_ATOMIC_XCHG( cred, 0UL );
    if( s ) FD_ATOMIC_FETCH_AND_SUB( &shmem->cache_class_used[ c ].val, s );
  }
}

/* min_joiner_epoch returns the smallest published epoch over every
   joiner and external epoch slot. */

static ulong
min_joiner_epoch( fd_accdb_t const * accdb ) {
  ulong min_epoch = ULONG_MAX;
  ulong joiner_cnt = FD_VOLATILE_CONST( accdb->shmem->joiner_cnt );
  for( ulong t=0UL; t<joiner_cnt; t++ ) {
    ulong e = FD_VOLATILE_CONST( accdb->shmem->joiner_epochs[ t ].val );
    if( FD_LIKELY( e<min_epoch ) ) min_epoch = e;
  }
  for( ulong t=0UL; t<accdb->external_epoch_cnt; t++ ) {
    ulong e = FD_VOLATILE_CONST( *accdb->external_epoch_slots[ t ] );
    if( FD_LIKELY( e<min_epoch ) ) min_epoch = e;
  }
  return min_epoch;
}

/* epoch_drained returns 1 if every joiner's published epoch exceeds
   tag, meaning all readers that were active at epoch=tag have since
   exited their critical sections. */

static int
epoch_drained( fd_accdb_t * accdb,
               ulong        tag ) {
  return tag<min_joiner_epoch( accdb );
}

/* drain_deferred_frees releases the accs and fork slots retired by the
   last request pass, once its epoch has drained (checked by the
   caller).  Must run before the next batch is created. */

static void
drain_deferred_frees( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_UNLIKELY( shmem->deferred_fork_head.val!=USHORT_MAX ) ) {
    fork_pool_release_chain( accdb->fork_shmem_pool,
                             fork_pool_ele( accdb->fork_shmem_pool, shmem->deferred_fork_head.val ),
                             fork_pool_ele( accdb->fork_shmem_pool, shmem->deferred_fork_tail.val ) );
    shmem->deferred_fork_head = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    shmem->deferred_fork_tail = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  }

  uint head_idx = shmem->deferred_acc_head;
  if( FD_LIKELY( head_idx==UINT_MAX ) ) return;

  /* Every reader that could still be standing on one of these accs at
     unlink time has exited its epoch section.  The stack is already
     linked through map.next, the acc_pool link, so it goes back to the
     pool as one chain, head to tail.  acc_unlink set each offset DEAD,
     so a late writeback frees its own record (off_publish) and nothing
     is left to sweep.  In index mode pool_avail counts the released
     accs, so the chain is walked for its length. */
  uint tail_idx = shmem->deferred_acc_tail;
  FD_TEST( (ulong)head_idx<acc_pool_ele_max( accdb->acc_pool_join ) );
  FD_TEST( (ulong)tail_idx<acc_pool_ele_max( accdb->acc_pool_join ) );
  if( idx_enabled( accdb ) ) {
    fd_accdb_accmeta_t * acc_pool     = accdb->acc_pool;
    ulong                acc_pool_cap = acc_pool_ele_max( accdb->acc_pool_join );
    ulong                n            = 0UL;
    for( uint idx=head_idx; idx!=UINT_MAX; idx=acc_pool[ idx ].map.next ) {
      FD_TEST( (ulong)idx<acc_pool_cap );
      n++;
    }
    acc_pool_release_chain( accdb->acc_pool_join, &acc_pool[ head_idx ], &acc_pool[ tail_idx ] );
    FD_ATOMIC_FETCH_AND_ADD( &shmem->pool_avail, n );
  } else {
    acc_pool_release_chain( accdb->acc_pool_join, &accdb->acc_pool[ head_idx ], &accdb->acc_pool[ tail_idx ] );
  }
  shmem->deferred_acc_head = UINT_MAX;
  shmem->deferred_acc_tail = UINT_MAX;
}

/* bg_defer_append (T2, index mode): records a background unlink.
   Returns 0 if the ring is full; the caller stops unlinking.  The ring
   holds indices, so an entry's map.next is left alone until its chunk
   drains (no walker can be standing on it by then): no unlinked mark
   is needed. */

static inline int
bg_defer_append( fd_accdb_t * accdb,
                 uint         v ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong head = shmem->bg_defer_head;
  if( FD_UNLIKELY( head-shmem->bg_defer_tail>=FD_ACCDB_BG_DEFER_MAX-FD_ACCDB_BG_DEFER_CHUNK ) ) return 0;
  uint * ring = (uint *)( (uchar *)shmem + shmem->idx_bg_defer_off );
  ring[ head & (FD_ACCDB_BG_DEFER_MAX-1UL) ] = v;
  shmem->bg_defer_head = head+1UL;
  return 1;
}

static inline int
bg_defer_room( fd_accdb_t const * accdb,
               ulong              n ) {
  fd_accdb_shmem_t const * shmem = accdb->shmem;
  return shmem->bg_defer_head-shmem->bg_defer_tail+n<FD_ACCDB_BG_DEFER_MAX-FD_ACCDB_BG_DEFER_CHUNK;
}

/* bg_defer_seal tags every unsealed entry with a fresh epoch, padding
   the open chunk so chunks stay aligned.  bg_defer_drain releases
   sealed chunks whose tag every joiner has passed.  Both T2 only.
   Entries may carry FD_ACCDB_DEFER_MIGRATED; the drain frees no bytes
   either way (the unlinker settled the record), so it only strips it. */

static void
bg_defer_seal( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong head = shmem->bg_defer_head;
  if( head==shmem->bg_defer_sealed ) return;
  uint * ring = (uint *)( (uchar *)shmem + shmem->idx_bg_defer_off );
  while( head & (FD_ACCDB_BG_DEFER_CHUNK-1UL) ) ring[ (head++) & (FD_ACCDB_BG_DEFER_MAX-1UL) ] = UINT_MAX;
  /* every chunk filled since the last seal, not just the open one */
  ulong tag = FD_ATOMIC_FETCH_AND_ADD( &shmem->epoch, 1UL );
  for( ulong c=shmem->bg_defer_sealed/FD_ACCDB_BG_DEFER_CHUNK; c<head/FD_ACCDB_BG_DEFER_CHUNK; c++ ) shmem->bg_defer_tag[ c % FD_ACCDB_BG_DEFER_CHUNKS ] = tag;
  shmem->bg_defer_head   = head;
  shmem->bg_defer_sealed = head;
}

static ulong
bg_defer_drain( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong released = 0UL;
  uint * ring    = (uint *)( (uchar *)shmem + shmem->idx_bg_defer_off );
  ulong  min_ep  = ULONG_MAX;
  ulong  cap     = acc_pool_ele_max( accdb->acc_pool_join );
  while( shmem->bg_defer_sealed-shmem->bg_defer_tail>=FD_ACCDB_BG_DEFER_CHUNK ) {
    ulong tail = shmem->bg_defer_tail;
    ulong tag  = shmem->bg_defer_tag[ (tail/FD_ACCDB_BG_DEFER_CHUNK) % FD_ACCDB_BG_DEFER_CHUNKS ];
    if( min_ep==ULONG_MAX ) min_ep = min_joiner_epoch( accdb );
    if( tag>=min_ep ) break;
    uint head_idx = UINT_MAX, prev = UINT_MAX;
    ulong n = 0UL;
    for( ulong i=0UL; i<FD_ACCDB_BG_DEFER_CHUNK; i++ ) {
      uint raw = ring[ (tail+i) & (FD_ACCDB_BG_DEFER_MAX-1UL) ];
      if( raw==UINT_MAX ) continue;
      uint v = raw & ~FD_ACCDB_DEFER_MIGRATED;
      FD_TEST( (ulong)v<cap );
      if( prev!=UINT_MAX ) accdb->acc_pool[ prev ].map.next = acc_pool_private_cidx( (ulong)v );
      else                 head_idx = v;
      prev = v;
      n++;
    }
    if( n ) {
      acc_pool_release_chain( accdb->acc_pool_join, &accdb->acc_pool[ head_idx ], &accdb->acc_pool[ prev ] );
      FD_ATOMIC_FETCH_AND_ADD( &shmem->pool_avail, n );
    }
    shmem->bg_defer_tail = tail+FD_ACCDB_BG_DEFER_CHUNK;
    released += n;
  }
  return released;
}

/* deferred_acc_append pushes an acc that acc_unlink spliced out of its
   chain onto the deferred stack, for release once its epoch drains.
   T2 is the sole writer.

   The stack is linked through map.next.  A concurrent chain walker may
   still be standing on the acc and about to follow map.next, so the
   acc is marked unlinked first: walkers load map.next, then the size
   word, and restart from the chain head on seeing the mark
   (fd_accdb_acc_unlinked).  TSO keeps the two stores in order, so a
   walker that read the stack link also sees the mark.  A walker that
   read the old link (before the mark) follows the acc's chain successor,
   which is either still linked or itself marked.

   The mark is an atomic OR of the whole data word: every change to the
   word is a 64-bit store, CAS or RMW (see "Data word").  A racing
   evictor's or cold load's CAS then fails and retries with the mark.

   The stack links are acc_pool links (map.next is the pool's POOL_NEXT),
   so drain_deferred_frees releases the stack as is.  The first acc
   pushed onto an empty stack stays its bottom, so it is the tail.

   acc_idx may carry FD_ACCDB_DEFER_MIGRATED (a tier move whose bytes
   live on in the new slot).  The drain frees no bytes either way, so
   the tag is stripped. */

static inline void
deferred_acc_append( fd_accdb_t * accdb,
                     uint         acc_idx ) {
  fd_accdb_shmem_t *   shmem   = accdb->shmem;
  acc_idx &= ~FD_ACCDB_DEFER_MIGRATED;
  fd_accdb_accmeta_t * accmeta = &accdb->acc_pool[ acc_idx ];
  FD_ATOMIC_FETCH_AND_OR( &accmeta->data, FD_ACCDB_DATA( 0U, FD_ACCDB_SIZE_UNLINKED_BIT ) );
  fd_racesan_hook( "accdb_defer:post_mark" );
  FD_COMPILER_MFENCE();  /* the mark before the stack link */
  FD_VOLATILE( accmeta->map.next ) = shmem->deferred_acc_head;
  if( shmem->deferred_acc_head==UINT_MAX ) shmem->deferred_acc_tail = acc_idx;
  shmem->deferred_acc_head = acc_idx;
}

/* acc_unlink removes a version from its chain and sets its offset DEAD.
   Its line, if any, ages out clean.  Only the accdb tile removes, and
   inserts touch only the head: CAS the head, or else store into the
   predecessor. */

static void acc_chain_splice( fd_accdb_t * accdb, uint map_idx, uint acc_idx );
static void acc_record_dead( fd_accdb_t * accdb, fd_accdb_accmeta_t * meta );

static inline void
acc_unlink( fd_accdb_t * accdb,
            uint         map_idx,
            uint         acc_idx ) {
  acc_chain_splice( accdb, map_idx, acc_idx );
  acc_record_dead( accdb, &accdb->acc_pool[ acc_idx ] );
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->accounts_total, 1UL );
  accdb->metrics->accounts_deleted++;
}

/* acc_chain_splice removes acc_idx from acc_map chain map_idx.  T2
   only.  The node keeps map.next for concurrent walkers until the
   caller defers it. */

static void
acc_chain_splice( fd_accdb_t * accdb,
                  uint         map_idx,
                  uint         acc_idx ) {
  fd_accdb_accmeta_t * meta = &accdb->acc_pool[ acc_idx ];
  uint                 next = FD_VOLATILE_CONST( meta->map.next );
  uint *               head = &accdb->acc_map[ map_idx ];
  if( FD_UNLIKELY( FD_VOLATILE_CONST( *head )!=acc_idx || FD_ATOMIC_CAS( head, acc_idx, next )!=acc_idx ) ) {
    uint prev = FD_VOLATILE_CONST( *head );
    for( uint cur; (cur=FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next ))!=acc_idx; ) prev = cur;
    FD_VOLATILE( accdb->acc_pool[ prev ].map.next ) = next;
  }
  fd_racesan_hook( "accdb_acc_unlink:post_splice" );
}

/* acc_record_dead sets meta's offset DEAD, freeing the record it had
   (a late writeback frees its own, off_publish).  Its line, if any,
   ages out clean. */

static void
acc_record_dead( fd_accdb_t *         accdb,
                 fd_accdb_accmeta_t * meta ) {
  off_swap( accdb, meta, FD_ACCDB_OFF_DEAD, FD_ACCDB_DATA_ES( FD_VOLATILE_CONST( meta->data ) ) );
}

/* acc_migrated_settle: T2 moved meta out of the RAM tiers (MIGRATED),
   its bytes living on in the bucket or the overflow log.  A live
   version is clean there already (the mover wrote it back first), so
   its record stays.  A tombstone's record is referenced by no other
   tier: set it DEAD, freeing a written-back record and stopping a
   pending writeback (off_publish frees it instead).  Either way a line
   still bound to meta ages out clean and becomes an orphan once the
   slot recycles. */

static void
acc_migrated_settle( fd_accdb_t *         accdb,
                     fd_accdb_accmeta_t * meta ) {
  if( FD_LIKELY( meta->lamports ) ) return;
  acc_record_dead( accdb, meta );
}

/* fork_slot_defer chains a retired fork pool slot onto the deferred
   fork chain.  The slot is released only after concurrent readers that
   could still hold its fork ID (via root_fork_id or descends_set) have
   exited.  Stale descends_set bits naming the slot are cleared by
   fd_accdb_attach_child when the slot is reused. */

static inline void
fork_slot_defer( fd_accdb_t *       accdb,
                 fd_accdb_fork_id_t fork_id ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( shmem->deferred_fork_tail.val!=USHORT_MAX ) fork_pool_ele( accdb->fork_shmem_pool, shmem->deferred_fork_tail.val )->pool.next = fork_pool_private_cidx( (ulong)fork_id.val );
  else                                            shmem->deferred_fork_head = fork_id;
  shmem->deferred_fork_tail = fork_id;
}

/* chain_prewalk prefetches the hash chain walks of up to CHAIN_PREWALK_W
   txn records from txn in lock-step, over the span the caller will walk.
   Read only.  Fills txns[] and map_idxs[] and returns the count. */

#define CHAIN_PREWALK_W (16UL)

static ulong
chain_prewalk( fd_accdb_t *      accdb,
               uint              txn,
               int               purge,
               fd_accdb_txn_t ** txns,
               uint *            map_idxs ) {
  uint acc_idx[ CHAIN_PREWALK_W ];
  uint cur    [ CHAIN_PREWALK_W ];

  ulong cnt = 0UL;
  for( ; cnt<CHAIN_PREWALK_W && txn!=UINT_MAX; cnt++ ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, (ulong)txn );
    txns   [ cnt ] = txne;
    acc_idx[ cnt ] = txne->acc_pool_idx;
    __builtin_prefetch( &accdb->acc_pool[ txne->acc_pool_idx ], 0, 3 );
    txn = txne->fork.next;
  }
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_accdb_accmeta_t const * acc = &accdb->acc_pool[ acc_idx[ i ] ];
    map_idxs[ i ] = (uint)(fd_hash32( acc->key.pubkey, accdb->shmem->seed ) & (accdb->shmem->chain_cnt-1UL));
    if( purge ) __builtin_prefetch( &accdb->acc_map[ map_idxs[ i ] ], 1, 3 );
  }
  for( ulong i=0UL; i<cnt; i++ ) {  /* a purge walks from the head to its version; a root, from its version on */
    if( purge ) cur[ i ] = FD_VOLATILE_CONST( accdb->acc_map[ map_idxs[ i ] ] );
    else        cur[ i ] = FD_VOLATILE_CONST( accdb->acc_pool[ acc_idx[ i ] ].map.next );
  }

  for(;;) {
    ulong live = 0UL;
    for( ulong i=0UL; i<cnt; i++ ) {
      if( cur[ i ]==UINT_MAX || ( purge && cur[ i ]==acc_idx[ i ] ) ) continue;
      cur[ i ] = FD_VOLATILE_CONST( accdb->acc_pool[ cur[ i ] ].map.next );
      live++;
    }
    if( !live ) break;
  }
  return cnt;
}

static void
purge_inner( fd_accdb_t *       accdb,
             fd_accdb_fork_id_t fork_id ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  fd_accdb_fork_id_t child = fork->shmem->child_id;
  while( child.val!=USHORT_MAX ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ child.val ].shmem->sibling_id;
    purge_inner( accdb, child );
    child = next;
  }

  if( FD_UNLIKELY( accdb->tier ) ) idx_spilled_purge( accdb, fork_id.val );

  uint txn = fork->shmem->txn_head;
  if( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txn_head = txn_pool_ele( accdb->txn_pool, (ulong)txn );
    fd_accdb_txn_t * txn_tail = NULL;
    while( txn!=UINT_MAX ) {
      fd_accdb_txn_t * txns    [ CHAIN_PREWALK_W ];
      uint             map_idxs[ CHAIN_PREWALK_W ];
      ulong cnt = chain_prewalk( accdb, txn, 1, txns, map_idxs );
      for( ulong w=0UL; w<cnt; w++ ) {
        fd_accdb_txn_t * txne = txns[ w ];

        uint acc_idx     = txne->acc_pool_idx;
        uint acc_map_idx = map_idxs[ w ];

        fd_racesan_hook( "accdb_purge:pre_unlink" );
        acc_unlink( accdb, acc_map_idx, acc_idx );
        deferred_acc_append( accdb, acc_idx );

        txn_tail = txne;
        txn = txne->fork.next;
      }
    }
    txn_pool_release_chain( accdb->txn_pool, txn_head, txn_tail );
  }

  fork_slot_defer( accdb, fork_id );
}

/* root_level roots fork_id, the only child of the current root,
   on the accdb tile.  Siblings were already detached and purged by
   fd_accdb_advance_root. */

/* (definition of idx_root_tomb follows the bucket helpers) */

/* fifo_push (T2, advance_root): a newly rooted live version. */

static inline void
fifo_push( fd_accdb_t * accdb,
           uint         idx,
           uint         gen ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong max = shmem->acc_pool_max;
  if( FD_UNLIKELY( shmem->fifo_head-shmem->fifo_tail>=max ) ) {
    /* Full: drop superseded entries, order kept.  Each pool slot has at
       most one live entry and idx is not live yet, so room remains. */
    ulong w = shmem->fifo_tail;
    for( ulong r=shmem->fifo_tail; r<shmem->fifo_head; r++ ) {
      ulong e = accdb->fifo[ r % max ];
      if( accdb->tier[ e>>32 ]==FD_ACCDB_TIER_ROOTED && accdb->acc_pool[ e>>32 ].key.generation==(uint)e ) accdb->fifo[ (w++) % max ] = e;
    }
    shmem->fifo_head = w;
    FD_TEST( shmem->fifo_head-shmem->fifo_tail<max );
  }
  accdb->fifo[ shmem->fifo_head % max ] = ((ulong)idx<<32) | gen;
  shmem->fifo_head++;
  accdb->tier[ idx ] = FD_ACCDB_TIER_ROOTED;
}

/* idx_root_tomb (T2): a rooted tombstone for pubkey kills its bucket
   slot (generation-guarded, idempotent) and hot copy while the
   tombstone still shadows them in acc_map. */

static void
idx_root_tomb( fd_accdb_t * accdb,
               uchar const  pubkey[ 32 ],
               uint         gen );

static void
root_level( fd_accdb_t *       accdb,
            fd_accdb_fork_id_t fork_id ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val==accdb->shmem->root_fork_id.val );
  FD_TEST( fork->shmem->sibling_id.val==USHORT_MAX );

  fd_accdb_fork_t * parent_fork = &accdb->fork_pool[ fork->shmem->parent_id.val ];

  if( FD_UNLIKELY( accdb->tier ) ) idx_spilled_root( accdb, fork_id.val );

  /* And for any accounts which were updated in the newly rooted slot,
     we will now never need to access any older version, so we can
     discard any slots earlier than the one we are rooting. */
  uint txn = fork->shmem->txn_head;
  if( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txn_head = txn_pool_ele( accdb->txn_pool, (ulong)txn );
    fd_accdb_txn_t * txn_tail = NULL;
    while( txn!=UINT_MAX ) {
      fd_accdb_txn_t * txns    [ CHAIN_PREWALK_W ];
      uint             map_idxs[ CHAIN_PREWALK_W ];
      ulong cnt = chain_prewalk( accdb, txn, 0, txns, map_idxs );
      for( ulong w=0UL; w<cnt; w++ ) {
        fd_accdb_txn_t * txne = txns[ w ];

        fd_accdb_accmeta_t const * new_acc = &accdb->acc_pool[ txne->acc_pool_idx ];
        uint acc_map_idx = map_idxs[ w ];

        delta_insert( accdb, new_acc->key.pubkey );

        /* Unlink every older version this fork could see: they are all
           behind new_acc (everything ahead of it was prepended by a
           non-ancestor fork). */
        FD_TEST( new_acc->key.generation==fork->shmem->generation && fd_accdb_acc_fork_id( new_acc )==fork_id.val );
#if FD_TMPL_USE_HANDHOLDING
        uint chk = FD_VOLATILE_CONST( accdb->acc_map[ acc_map_idx ] );
        while( chk!=UINT_MAX && chk!=txne->acc_pool_idx ) {
          fd_accdb_accmeta_t const * ahead = &accdb->acc_pool[ chk ];
          FD_TEST( !( (ahead->key.generation<=parent_fork->shmem->generation || descends_set_test( fork->descends, fd_accdb_acc_fork_id(ahead) ) ) && !memcmp( new_acc->key.pubkey, ahead->key.pubkey, 32UL ) ) );
          chk = FD_VOLATILE_CONST( ahead->map.next );
        }
        FD_TEST( chk==txne->acc_pool_idx );
#endif
        uint acc = FD_VOLATILE_CONST( new_acc->map.next );
        while( acc!=UINT_MAX ) {
          fd_accdb_accmeta_t const * cur_acc = &accdb->acc_pool[ acc ];
          uint next = FD_VOLATILE_CONST( cur_acc->map.next );
          if( FD_LIKELY( (cur_acc->key.generation<=parent_fork->shmem->generation || descends_set_test( fork->descends, fd_accdb_acc_fork_id(cur_acc) ) ) && !memcmp( new_acc->key.pubkey, cur_acc->key.pubkey, 32UL ) ) ) {
            fd_racesan_hook( "accdb_advance:pre_unlink" );
            acc_unlink( accdb, acc_map_idx, acc );
            deferred_acc_append( accdb, acc );
            if( accdb->tier ) accdb->tier[ acc ] = FD_ACCDB_TIER_NONE;
          }
          acc = next;
        }

        /* If the newly rooted version is a tombstone (lamports==0, e.g.
           account was closed), drop it from the index too: no fork can
           reach it anymore, and keeping it around just wastes a hash
           slot and the disk bytes it occupies. */
        if( FD_UNLIKELY( new_acc->lamports==0UL ) ) {
          if( accdb->fifo ) idx_root_tomb( accdb, new_acc->key.pubkey, new_acc->key.generation );
          acc_unlink( accdb, acc_map_idx, txne->acc_pool_idx );
          deferred_acc_append( accdb, txne->acc_pool_idx );
        } else if( accdb->fifo ) {
          fifo_push( accdb, txne->acc_pool_idx, new_acc->key.generation );
        }

        txn_tail = txne;
        txn = txne->fork.next;
      }
    }
    txn_pool_release_chain( accdb->txn_pool, txn_head, txn_tail );
  }

  uint parent_txn = parent_fork->shmem->txn_head;
  if( parent_txn!=UINT_MAX ) {
    fd_accdb_txn_t * parent_head = txn_pool_ele( accdb->txn_pool, (ulong)parent_txn );
    fd_accdb_txn_t * parent_tail = NULL;
    while( parent_txn!=UINT_MAX ) {
      fd_accdb_txn_t * t = txn_pool_ele( accdb->txn_pool, (ulong)parent_txn );
      parent_tail = t;
      parent_txn = t->fork.next;
    }
    txn_pool_release_chain( accdb->txn_pool, parent_head, parent_tail );
  }

  fork->shmem->txn_head = UINT_MAX;

  /* Retire the old root.  Its accounts stay visible through the
     generation <= root_generation fast path.  A reader that loaded the
     old root_fork_id may still read its slot, so the slot is released
     only after the epoch bump that ends the pass drains. */
  fork_slot_defer( accdb, fork->shmem->parent_id );

  fd_racesan_hook( "accdb_advance:pre_publish_root" );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( accdb->shmem->root_fork_id ) = fork_id;
  FD_COMPILER_MFENCE();
  fd_racesan_hook( "accdb_advance:post_publish_root" );
}

/* requests_unapplied returns 1 if a root or purge request has not been
   applied yet (unlike fd_accdb_requests_pending, a retired batch
   waiting on readers does not count).  T2 bounded work yields to it. */

static inline int
requests_unapplied( fd_accdb_t const * accdb ) {
  fd_accdb_req_t  req  = { .u = FD_VOLATILE_CONST( accdb->shmem->req.u  ) };
  fd_accdb_done_t done = { .u = FD_VOLATILE_CONST( accdb->shmem->done.u ) };
  return done.root_gen!=req.root_gen || done.purge_seq!=req.purge_seq;
}

int
fd_accdb_requests_pending( fd_accdb_t const * accdb ) {
  fd_accdb_req_t  req  = { .u = FD_VOLATILE_CONST( accdb->shmem->req.u  ) };
  fd_accdb_done_t done = { .u = FD_VOLATILE_CONST( accdb->shmem->done.u ) };
  return done.root_gen!=req.root_gen || done.purge_seq!=req.purge_seq || done.retiring;
}

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  FD_CHECK_CRIT( fd_accdb_snapshot_sync_state( &shmem->snapshot_sync )!=FD_ACCDB_SNAPSHOT_SYNC_RUNNING,
                 "fd_accdb_advance_root called during snapshot production" );

  /* The caller roots sequentially: fork_id is a child of the last
     requested root. */
  fd_accdb_req_t    req  = shmem->req;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  fd_accdb_fork_id_t parent_id = fork->shmem->parent_id;
  FD_CHECK_CRIT( parent_id.val!=USHORT_MAX && accdb->fork_pool[ parent_id.val ].shmem->generation==req.root_gen, "advance_root target is not a child of the root" );

  /* Detach the competing siblings for purging.  The parent is left with
     fork_id as its only child, which is how the accdb tile finds the
     next level to root.  The purges and the root are published in one
     request, and the accdb tile applies a request's purges first. */
  fd_accdb_fork_shmem_t * parent = accdb->fork_pool[ parent_id.val ].shmem;
  fd_accdb_fork_id_t child = parent->child_id;
  while( child.val!=USHORT_MAX ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ child.val ].shmem->sibling_id;
    if( child.val!=fork_id.val ) {
      accdb->fork_pool[ child.val ].shmem->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
      accdb->fork_pool[ child.val ].shmem->sibling_id = req.purge_fork;
      req.purge_fork = child;
      req.purge_seq++;
    }
    child = next;
  }
  fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  parent->child_id        = fork_id;

  req.root_gen = fork->shmem->generation;
  publish_req( accdb, req );
}

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  /* Live forks that do not descend from the requested root are the
     root and its ancestors, which are older.  A fork newer than the
     root has a parent (unless it was already purged). */
  fd_accdb_req_t          req  = shmem->req;
  fd_accdb_fork_shmem_t * fork = accdb->fork_pool[ fork_id.val ].shmem;
  FD_CHECK_CRIT( shmem->root_fork_id.val!=USHORT_MAX, "purge before the root fork exists" );
  FD_CHECK_CRIT( fork->generation>req.root_gen, "purge target is the root or its ancestor" );
  fd_accdb_fork_id_t parent_id = fork->parent_id;
  FD_CHECK_CRIT( parent_id.val!=USHORT_MAX, "purge target was already purged" );

  fd_accdb_fork_shmem_t * parent = accdb->fork_pool[ parent_id.val ].shmem;
  fd_accdb_fork_id_t      next   = fork->sibling_id;
  if( parent->child_id.val==fork_id.val ) {
    parent->child_id = next;
  } else {
    fd_accdb_fork_shmem_t * prev = accdb->fork_pool[ parent->child_id.val ].shmem;
    while( prev->sibling_id.val!=fork_id.val ) prev = accdb->fork_pool[ prev->sibling_id.val ].shmem;
    prev->sibling_id = next;
  }

  fork->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->sibling_id = req.purge_fork;
  req.purge_fork   = fork_id;
  req.purge_seq++;
  publish_req( accdb, req );
}

/* background_release releases the retired batch once every reader
   that could still reference it has exited.  Does not wait.  Returns
   1 if no batch is held afterwards. */

static int
background_release( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  fd_accdb_done_t    done  = shmem->done;
  if( FD_LIKELY( !done.retiring ) ) return 1;
  if( FD_UNLIKELY( !epoch_drained( accdb, shmem->deferred_epoch ) ) ) return 0;
  drain_deferred_frees( accdb );
  fd_racesan_hook( "accdb_release:pre_done" );
  done.retiring = 0U;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->done.u ) = done.u;
  FD_COMPILER_MFENCE();
  return 1;
}

/* background_requests applies the root and purge requests published
   since the last pass, then retires everything they unlinked as one
   batch.  Returns 1 if it did any work.

   A request's purges are applied before its root, and fd_accdb_advance_root
   requests a level's sibling purges together with the level, so no
   losing sibling is visible through the generation fast path. */

static int
background_requests( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  /* One batch is held at a time.  Until it is released, requests wait
     and the tile keeps doing other work. */
  if( FD_UNLIKELY( !background_release( accdb ) ) ) return 0;

  fd_accdb_req_t  req  = { .u = FD_VOLATILE_CONST( shmem->req.u ) };
  fd_accdb_done_t done = shmem->done;
  if( FD_LIKELY( done.root_gen==req.root_gen && done.purge_seq==req.purge_seq ) ) return 0;
  FD_COMPILER_MFENCE();

  /* The newest purge_cnt forks of the chain are the ones not yet
     applied.  Each still holds its slot, so the links are intact. */
  ulong              purge_cnt = (ushort)( req.purge_seq-done.purge_seq );
  fd_accdb_fork_id_t purge     = req.purge_fork;
  for( ulong i=0UL; i<purge_cnt; i++ ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ purge.val ].shmem->sibling_id;
    purge_inner( accdb, purge );
    purge = next;
  }
  done.purge_seq = req.purge_seq;

  for(;;) {
    fd_accdb_fork_shmem_t const * root = accdb->fork_pool[ shmem->root_fork_id.val ].shmem;
    done.root_gen = root->generation;
    if( done.root_gen==req.root_gen ) break;
    FD_TEST( done.root_gen<req.root_gen );
    root_level( accdb, root->child_id );
  }

  /* One grace period for everything unlinked or retired in this pass. */
  if( FD_LIKELY( shmem->deferred_acc_head!=UINT_MAX || shmem->deferred_fork_head.val!=USHORT_MAX ) ) {
    shmem->deferred_epoch = FD_ATOMIC_FETCH_AND_ADD( &shmem->epoch, 1UL );
    done.retiring         = 1U;
  }

  fd_racesan_hook( "accdb_requests:pre_done" );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->done.u ) = done.u;
  FD_COMPILER_MFENCE();
  return 1;
}

ulong
fd_accdb_snapshot_reserve_write( fd_accdb_t * accdb,
                                 ulong        sz,
                                 ulong        dead_tail_sz ) {
  FD_TEST( sz && sz<=accdb->shmem->partition_sz && dead_tail_sz<=sz );
  ulong off = allocate_next_write( accdb, sz );
  if( dead_tail_sz ) fd_accdb_shmem_bytes_freed( accdb->shmem, off+sz-dead_tail_sz, dead_tail_sz );
  return off;
}

/* Compaction write allocation.  Single-threaded: only the compaction
   tile calls these, so the compaction write heads do not need atomic
   fetch-and-add.  dest_layer is the target layer (1..N-1). */

static inline ulong
allocate_next_compaction_write( fd_accdb_t * accdb,
                                ulong        sz,
                                ulong        dest_layer ) {
  accdb_offset_t offset = accdb->shmem->whead[ dest_layer ];
  if( FD_UNLIKELY( !accdb->shmem->has_partition[ dest_layer ] ||
                    packed_partition_offset( &offset )+sz>accdb->shmem->partition_sz ) ) {
    change_partition( accdb, &offset, &accdb->shmem->whead[ dest_layer ], &accdb->shmem->has_partition[ dest_layer ], (uchar)dest_layer );
    offset = accdb->shmem->whead[ dest_layer ];
  }
  accdb->shmem->whead[ dest_layer ].val += sz;
  FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_current_bytes, sz );
  ulong file_offset = packed_partition_file_offset( &offset, accdb->shmem->partition_sz );
  fd_accdb_partition_write_bump( accdb, packed_partition_idx( &offset ), sz, 1UL );
  return file_offset;
}

/* background_compact relocates batches of records from src_layer
   into the next colder tier (or the same tier for the deepest layer)
   and reclaims retired partitions.  Sets *charge_busy if work is done.

   src_layer must be in 0..FD_ACCDB_COMPACTION_LAYER_CNT-1. */

static void
background_compact( fd_accdb_t * accdb,
                    ulong        src_layer,
                    int *        charge_busy ) {
  FD_TEST( accdb->bounce );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: epoch store must be globally visible
                     before any subsequent loads so the deferred
                     reclamation scan does not miss us. */

  /* Reclaim any deferred-free partitions whose epoch has been observed
     by all joiners (i.e. no epoch-publishing joiner could still be
     referencing data in them).  Scan writer slots [0, joiner_cnt)
     plus each external (read-only) joiner's private epoch fseq. */
  ulong min_epoch = ULONG_MAX;
  ulong joiner_cnt = FD_VOLATILE_CONST( accdb->shmem->joiner_cnt );
  for( ulong t=0UL; t<joiner_cnt; t++ ) {
    ulong e = FD_VOLATILE_CONST( accdb->shmem->joiner_epochs[ t ].val );
    if( FD_LIKELY( e<min_epoch ) ) min_epoch = e;
  }
  for( ulong t=0UL; t<accdb->external_epoch_cnt; t++ ) {
    ulong e = FD_VOLATILE_CONST( *accdb->external_epoch_slots[ t ] );
    if( FD_LIKELY( e<min_epoch ) ) min_epoch = e;
  }
  for(;;) {
    if( FD_LIKELY( deferred_free_dlist_is_empty( accdb->deferred_free_dlist, accdb->partition_pool ) ) ) break;
    fd_accdb_partition_t * p = deferred_free_dlist_ele_peek_head( accdb->deferred_free_dlist, accdb->partition_pool );
    if( FD_LIKELY( p->epoch_tag>=min_epoch ) ) break;

    fd_racesan_hook( "accdb_reclaim:pre_free_partition" );

    fd_spinlock_acquire( &accdb->shmem->partition_lock );
    deferred_free_dlist_ele_pop_head( accdb->deferred_free_dlist, accdb->partition_pool );
    FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_current_bytes, accdb->shmem->partition_sz );
    FD_VOLATILE( p->write_offset ) = 0UL;
    partition_pool_ele_release( accdb->partition_pool, p );
    fd_spinlock_release( &accdb->shmem->partition_lock );
  }

  if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist[ src_layer ], accdb->partition_pool ) ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    return;
  }
  fd_accdb_partition_t * compact = compaction_dlist_ele_peek_head( accdb->compaction_dlist[ src_layer ], accdb->partition_pool );
  if( FD_UNLIKELY( !compact ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    return;
  }

  /* Wait until all epoch-publishing joiners that were active when this
     partition was enqueued for compaction have exited, ensuring any
     in-flight pwritev2 to this partition has completed before we start
     reading from it. */
  if( FD_UNLIKELY( compact->compaction_ready_epoch>=min_epoch ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    return;
  }

  *charge_busy = 1;

  if( FD_UNLIKELY( !compact->compacting_now ) ) {
    compact->compaction_start_wallclock    = fd_log_wallclock();
    compact->compaction_accounts_relocated = 0UL;
    compact->compaction_bytes_relocated    = 0UL;
    compact->compaction_dead_records       = 0UL;
  }
  FD_VOLATILE( compact->queued )         = 0;
  FD_VOLATILE( compact->compacting_now ) = 1;

  ulong compact_base = partition_pool_idx( accdb->partition_pool, compact )*accdb->shmem->partition_sz;
  ulong dest_layer   = fd_ulong_min( src_layer+1UL, FD_ACCDB_COMPACTION_LAYER_CNT-1UL );

  ulong want  = fd_ulong_min( FD_ACCDB_BOUNCE_SZ, compact->write_offset-compact->compaction_offset );
  ulong carry = fd_ulong_if( accdb->carry_off==compact_base+compact->compaction_offset, fd_ulong_min( accdb->carry_sz, want ), 0UL );
  accdb->carry_sz = 0UL;
  ulong bytes_read = carry;
  while( bytes_read<want ) {
    long result = pread( accdb->fd, accdb->bounce+bytes_read, want-bytes_read, (long)(compact_base+compact->compaction_offset+bytes_read) );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pread() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                   compact_base+compact->compaction_offset+bytes_read, want ));
    fd_accdb_partition_read_bump( accdb, compact_base+compact->compaction_offset+bytes_read, (ulong)result );
    bytes_read += (ulong)result;
  }

  ulong span = 0UL;
  for(;;) {
    if( FD_UNLIKELY( span+sizeof(fd_accdb_disk_meta_t)>bytes_read ) ) break;
    ulong record_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)((fd_accdb_disk_meta_t const *)(accdb->bounce+span))->size;
    if( FD_UNLIKELY( span+record_sz>bytes_read ) ) break;
    span += record_sz;
  }
  if( FD_UNLIKELY( !span ) ) FD_LOG_ERR(( "accounts database is corrupt, record at offset %lu larger than %lu bytes",
                                          compact_base+compact->compaction_offset, FD_ACCDB_BOUNCE_SZ ));

  fd_accdb_accmeta_t * live_accmeta[ IOV_MAX ];
  uchar                live_kind   [ IOV_MAX ]; /* 0 acc_map, 1 hot, 2 bucket only, 3 ovl only */
  ushort               live_fork   [ IOV_MAX ];
  ulong                live_packed [ IOV_MAX ];
  ulong                live_src    [ IOV_MAX ];
  ulong                live_sz     [ IOV_MAX ];
  ulong                live_dst    [ IOV_MAX ];
  struct iovec         iov         [ IOV_MAX ];

  ulong live_cnt = 0UL;
  ulong live_bytes = 0UL;
  ulong idx_io = 0UL;
  for( ulong off=0UL; off<span; ) {
    fd_accdb_disk_meta_t const * meta = (fd_accdb_disk_meta_t const *)(accdb->bounce+off);

    fd_accdb_accmeta_t * accmeta = NULL;
    ulong source_packed = 0UL;
    uint * chain = &accdb->acc_map[ fd_hash32( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ];
    uint acc_idx = FD_VOLATILE_CONST( *chain );
    while( acc_idx!=UINT_MAX ) {
      fd_accdb_accmeta_t * candidate = &accdb->acc_pool[ acc_idx ];
      uint next_idx = FD_VOLATILE_CONST( candidate->map.next );
      ulong candidate_packed = FD_VOLATILE_CONST( candidate->offset_fork );
      if( FD_LIKELY( (candidate_packed & FD_ACCDB_OFF_MASK)==compact_base+compact->compaction_offset+off ) ) {
        accmeta       = candidate;
        source_packed = candidate_packed;
        break;
      }
      if( FD_UNLIKELY( fd_accdb_acc_unlinked( candidate ) ) ) { acc_idx = FD_VOLATILE_CONST( *chain ); continue; }
      acc_idx = next_idx;
    }

    ulong record_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)meta->size;
    uchar kind      = 0;
    ushort fork     = USHORT_MAX;
    if( FD_UNLIKELY( !accmeta && idx_enabled( accdb ) ) ) {
      /* Live iff some tier names this exact offset (§5.6). */
      ulong rec_off = compact_base+compact->compaction_offset+off;
      int   hot_key = 0;
      uint  h = accdb->hot_map[ fd_hash32( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ];
      while( h!=UINT_MAX ) {
        fd_accdb_accmeta_t * hm = &accdb->acc_pool[ h ];
        if( !memcmp( hm->key.pubkey, meta->pubkey, 32UL ) ) {
          hot_key = 1; /* the bucket slot mirrors it (I8) */
          if( (hm->offset_fork & FD_ACCDB_OFF_MASK)==rec_off ) {
            accmeta       = hm;
            source_packed = hm->offset_fork;
            kind          = 1;
          }
          break;
        }
        h = hm->map.next;
      }
      /* Bounded preads per call and never ahead of a cmd, checked only
         before a record's first lookup so every record completes. */
      int spilled_any = FD_VOLATILE_CONST( accdb->shmem->ovl_fork_cnt ) || accdb->shmem->spill_fork!=USHORT_MAX;
      int need_io     = !accmeta && ( spilled_any || ( !hot_key && fd_accdb_cf_probe( accdb->cf, meta->pubkey ) ) );
      if( need_io && idx_io && ( idx_io>=FD_ACCDB_COMPACT_IDX_IO || requests_unapplied( accdb ) ) ) {
        span = off;
        break;
      }
      if( !accmeta && !hot_key && fd_accdb_cf_probe( accdb->cf, meta->pubkey ) ) {
        idx_io++;
        fd_accdb_idx_slot_t slot;
        if( fd_accdb_idx_lookup( accdb->bkt, accdb->shmem->seed, meta->pubkey, 0, &slot ) && slot.off_plus1==rec_off+1UL ) {
          kind          = 2;
          source_packed = rec_off;
        }
      }
      if( FD_UNLIKELY( !accmeta && kind!=2 && spilled_any ) ) {
        /* a spilled version lives only in its ovl slot */
        for( ulong f=0UL; f<accdb->shmem->max_live_slots && kind!=3; f++ ) {
          if( !idx_fork( accdb, f )->spilled && f!=accdb->shmem->spill_fork ) continue;
          if( !ovl_bloom_op( accdb, f, meta->pubkey, 0 ) ) continue;
          idx_io++;
          fd_accdb_idx_slot_t slot;
          if( fd_accdb_idx_lookup( accdb->ovl, accdb->shmem->seed, meta->pubkey, (ushort)f, &slot ) && slot.off_plus1==rec_off+1UL ) {
            kind          = 3;
            fork          = (ushort)f;
            source_packed = rec_off;
          }
        }
      }
    }
    if( FD_UNLIKELY( !accmeta && kind!=2 ) ) compact->compaction_dead_records++; /* index entry gone, extent is garbage */
    else {
      live_kind   [ live_cnt ] = kind;
      live_fork   [ live_cnt ] = fork;
      live_accmeta[ live_cnt ] = accmeta;
      live_packed [ live_cnt ] = source_packed;
      live_src    [ live_cnt ] = off;
      live_sz     [ live_cnt ] = record_sz;
      live_cnt++;
      live_bytes += record_sz;
    }
    off += record_sz;

    if( FD_UNLIKELY( live_cnt==IOV_MAX ) ) {
      span = off;
      break;
    }
  }

  if( FD_LIKELY( live_cnt ) ) {
    ulong dest_base = allocate_next_compaction_write( accdb, live_bytes, dest_layer );
    ulong dst = dest_base;
    for( ulong i=0UL; i<live_cnt; i++ ) { live_dst[ i ] = dst; dst += live_sz[ i ]; }

    for( ulong i=0UL; i<live_cnt; i++ ) iov[ i ] = (struct iovec){ .iov_base = accdb->bounce+live_src[ i ], .iov_len = live_sz[ i ] };
    ulong written = 0UL; ulong iov_idx = 0UL;
    while( written<live_bytes ) {
      long result = pwritev2( accdb->fd, iov+iov_idx, (int)(live_cnt-iov_idx), (long)(dest_base+written), 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, pwritev2() returned 0 at offset %lu", dest_base+written ));
      written += (ulong)result;
      accdb->metrics->copy_ops++;
      ulong adv = (ulong)result;
      while( adv && iov_idx<live_cnt ) {
        if( adv>=iov[ iov_idx ].iov_len ) {
          adv -= iov[ iov_idx ].iov_len;
          iov_idx++;
        }
        else {
          iov[ iov_idx ].iov_base = (uchar *)iov[ iov_idx ].iov_base+adv;
          iov[ iov_idx ].iov_len -= adv;
          adv = 0UL;
        }
      }
    }

    accdb->shmem->shmetrics->accounts_relocated       += live_cnt;
    accdb->shmem->shmetrics->accounts_relocated_bytes += live_bytes;
    compact->compaction_accounts_relocated            += live_cnt;
    compact->compaction_bytes_relocated               += live_bytes;

    /* Data is written before the offsets are published, so a
       concurrent acquire never preadv2s an unwritten location. */
    FD_COMPILER_MFENCE();

    for( ulong i=0UL; i<live_cnt; i++ ) {
      /* CAS the offset from the exact source record we copied to the
         new destination.  If a concurrent release overwrote the offset
         (to DIRTY/UPDATING for a new commit, or DEAD for an unlink),
         or later published a newer on-disk location, the CAS fails and
         the relocated copy is dead on arrival: account it as freed so
         compaction reclaims it.  The full packed offset_fork is CASed
         so the fork_id is preserved. */
      ulong new_packed = ( live_packed[ i ] & ~FD_ACCDB_OFF_MASK ) | ( live_dst[ i ] & FD_ACCDB_OFF_MASK );
#if FD_HAS_RACESAN
      fd_memcpy( fd_accdb_dbg_reloc_pubkey, ((fd_accdb_disk_meta_t const *)( accdb->bounce+live_src[ i ] ))->pubkey, 32UL );
      fd_accdb_dbg_reloc_dest = live_dst[ i ];
      fd_accdb_dbg_reloc_cnt++;
#endif
      fd_racesan_hook( "accdb_compact:pre_offset_cas" );
      fd_accdb_disk_meta_t const * rmeta = (fd_accdb_disk_meta_t const *)( accdb->bounce+live_src[ i ] );
      if( FD_UNLIKELY( live_kind[ i ]>=2 ) ) {
        fd_accdb_idx_region_t const * r = live_kind[ i ]==2 ? accdb->bkt : accdb->ovl;
        ushort                        f = live_kind[ i ]==2 ? (ushort)0 : live_fork[ i ];
        if( FD_UNLIKELY( !fd_accdb_idx_resync( r, accdb->shmem->seed, rmeta->pubkey, f, live_packed[ i ]+1UL, live_dst[ i ]+1UL ) ) )
          fd_accdb_shmem_bytes_freed( accdb->shmem, live_dst[ i ], live_sz[ i ] );
      } else if( FD_UNLIKELY( FD_ATOMIC_CAS( &live_accmeta[ i ]->offset_fork, live_packed[ i ], new_packed )!=live_packed[ i ] ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, live_dst[ i ], live_sz[ i ] );
      } else if( live_kind[ i ]==0 && accdb->tier && ( accdb->tier[ live_accmeta[ i ]-accdb->acc_pool ]==FD_ACCDB_TIER_UNSPILL ||
                                                       ( accdb->shmem->spill_fork!=USHORT_MAX && fd_accdb_acc_fork_id( live_accmeta[ i ] )==accdb->shmem->spill_fork ) ) ) {
        /* unspilled copy, or a version logged by an unfinished spill */
        fd_accdb_idx_resync( accdb->ovl, accdb->shmem->seed, rmeta->pubkey, fd_accdb_acc_fork_id( live_accmeta[ i ] ),
                             (live_packed[ i ]&FD_ACCDB_OFF_MASK)+1UL, live_dst[ i ]+1UL );
      } else if( live_kind[ i ]==1 ) {
        /* hot copies always mirror the bucket slot (I8) */
        fd_accdb_idx_resync( accdb->bkt, accdb->shmem->seed, rmeta->pubkey, 0, (live_packed[ i ]&FD_ACCDB_OFF_MASK)+1UL, live_dst[ i ]+1UL );
      }
    }
  }

  fd_racesan_hook( "accdb_compact:post_relocate" );

  compact->compaction_offset += span;
#if FD_HAS_RACESAN
  fd_accdb_dbg_compact_scanned += span;
#endif

  if( FD_LIKELY( span<bytes_read ) ) {
    memmove( accdb->bounce, accdb->bounce+span, bytes_read-span );
    accdb->carry_off   = compact_base+compact->compaction_offset;
    accdb->carry_sz    = bytes_read-span;
    accdb->carry_layer = src_layer;
  }

  if( FD_UNLIKELY( compact->compaction_offset>=compact->write_offset ) ) {
    FD_LOG_INFO(( "compaction of partition %lu completed", partition_pool_idx( accdb->partition_pool, compact ) ));
    accdb->carry_sz = 0UL; /* nothing is carried past a finished partition */

    fd_event_accdb_compaction_completed_t ev = {
      .partition_idx      = partition_pool_idx( accdb->partition_pool, compact ),
      .src_layer          = (uchar)src_layer,
      .dest_layer         = (uchar)fd_ulong_min( src_layer+1UL, FD_ACCDB_COMPACTION_LAYER_CNT-1UL ),
      .bytes_scanned      = compact->write_offset,
      .bytes_freed        = compact->bytes_freed,
      .accounts_relocated = compact->compaction_accounts_relocated,
      .bytes_relocated    = compact->compaction_bytes_relocated,
      .dead_records       = compact->compaction_dead_records,
      .start_time         = (ulong)compact->compaction_start_wallclock,
      .end_time           = (ulong)fd_log_wallclock(),
    };
    fd_event_report_accdb_compaction_completed( &ev );

    /* Ensure the new acc->offset_fork stores above are visible to other
       cores before the source partition is moved to the deferred-free
       list.  On x86 (TSO) hardware store ordering already guarantees
       this, but the compiler fence prevents the compiler from sinking
       the offset store past the inlined pool/dlist mutations below. */
    FD_COMPILER_MFENCE();

    /* Bump the global epoch and tag this partition so the reclamation
       scan knows when all epoch-publishing joiners that could reference
       data in this partition have exited. */
    ulong tag = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->epoch, 1UL );
    compact->epoch_tag = tag;

    /* partition_lock serializes these dlist/pool mutations with
       concurrent push_tail in fd_accdb_shmem_bytes_freed and
       partition_pool_ele_acquire in change_partition.  Neither fd_dlist
       nor fd_pool are thread-safe, so all mutations must be under the
       same lock. */
    fd_spinlock_acquire( &accdb->shmem->partition_lock );

    accdb->shmem->shmetrics->partitions_freed++;
    compaction_dlist_ele_pop_head( accdb->compaction_dlist[ src_layer ], accdb->partition_pool );
    FD_VOLATILE( compact->compacting_now ) = 0;
    FD_VOLATILE( compact->queued )         = 0;
    deferred_free_dlist_ele_push_tail( accdb->deferred_free_dlist, compact, accdb->partition_pool );

    accdb->shmem->shmetrics->compactions_completed++;
    if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist[ src_layer ], accdb->partition_pool ) ) ) {
      accdb->shmem->shmetrics->in_compaction = 0;
    } else {
      fd_accdb_partition_t * next = compaction_dlist_ele_peek_head( accdb->compaction_dlist[ src_layer ], accdb->partition_pool );
      FD_LOG_INFO(( "compaction of layer %lu partition %lu started", src_layer, partition_pool_idx( accdb->partition_pool, next ) ));
    }

    fd_spinlock_release( &accdb->shmem->partition_lock );
  }

  accdb->metrics->bytes_read += bytes_read-carry;
  accdb->metrics->bytes_written += live_bytes;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

#define RESERVATION_TYPE_SIMPLE            (0)
#define RESERVATION_TYPE_MAYBE_PROGRAMDATA (1)
#define RESERVATION_TYPE_ALREADY_RESERVED  (2)

static inline int
ovl_bloom_op( fd_accdb_t const * accdb,
              ulong              fork_id,
              uchar const        pubkey[ 32 ],
              int                insert ) {
  ulong * b = ovl_bloom( accdb, fork_id );
  ulong   m = accdb->shmem->idx_bloom_words*64UL-1UL;
  ulong   h = fd_hash32( pubkey, accdb->shmem->seed^0x626c6f6f6d5f6f76UL );
  int hit = 1;
  for( ulong k=0UL; k<4UL; k++ ) {
    ulong bit = ( h>>(16UL*k) ) & m;
    if( insert ) b[ bit>>6 ] |= 1UL<<(bit&63UL);
    else         hit &= !!( FD_VOLATILE_CONST( b[ bit>>6 ] ) & (1UL<<(bit&63UL)) );
  }
  return hit;
}

/* ovl_candidate (any joiner, epoch held): could pubkey have a version
   newer than gen_floor in a spilled fork visible from fork? */

static int
ovl_candidate( fd_accdb_t const *      accdb,
               fd_accdb_fork_t const * fork,
               ushort                  fork_id,
               uchar const             pubkey[ 32 ],
               uint                    gen_floor ) {
  ulong max = accdb->shmem->max_live_slots;
  for( ulong f=0UL; f<max; f++ ) {
    if( f!=fork_id && !descends_set_test( fork->descends, f ) ) continue;
    if( !FD_VOLATILE_CONST( idx_fork( accdb, f )->spilled ) ) continue;
    if( accdb->fork_pool[ f ].shmem->generation<=gen_floor ) continue;
    if( ovl_bloom_op( accdb, f, pubkey, 0 ) ) return 1;
  }
  return 0;
}

/* ovl_search (index fd holders): newest version of pubkey above
   gen_floor in any spilled fork visible from fork.  Every bloom hit is
   looked up, so a false positive never hides an older fork.  Returns
   its fork id and slot, or USHORT_MAX. */

static ushort
ovl_search( fd_accdb_t const *      accdb,
            fd_accdb_fork_t const * fork,
            ushort                  fork_id,
            uchar const             pubkey[ 32 ],
            uint                    gen_floor,
            fd_accdb_idx_slot_t *   out ) {
  ushort best = USHORT_MAX; uint best_gen = gen_floor;
  ulong max = accdb->shmem->max_live_slots;
  for( ulong f=0UL; f<max; f++ ) {
    if( f!=fork_id && !descends_set_test( fork->descends, f ) ) continue;
    if( !FD_VOLATILE_CONST( idx_fork( accdb, f )->spilled ) ) continue;
    if( accdb->fork_pool[ f ].shmem->generation<=best_gen ) continue;
    if( !ovl_bloom_op( accdb, f, pubkey, 0 ) ) continue;
    fd_accdb_idx_slot_t s;
    if( !fd_accdb_idx_lookup( accdb->ovl, accdb->shmem->seed, pubkey, (ushort)f, &s ) ) continue;
    best = (ushort)f; best_gen = s.generation; *out = s;
  }
  return best;
}

/* ovl_res: T2 searched every spilled fork visible from the reader fork
   (identified by its generation) for pubkey and unspilled the newest
   hit, of generation gen.  Valid while ovl_epoch is unchanged and the
   walk still finds a version at least that new (an evicted unspilled
   copy fails this).  Exact keys; a slot eviction only costs a wait. */

static inline ulong
ovl_res_slot( uchar const pubkey[ 32 ],
              uint        fork_gen ) {
  return ( FD_LOAD( ulong, pubkey+8 ) ^ (ulong)fork_gen ) & 31UL;
}

static inline int
ovl_res_test( fd_accdb_t const * accdb,
              uchar const        pubkey[ 32 ],
              uint               fork_gen,
              uint               floor ) {
  ulong i = ovl_res_slot( pubkey, fork_gen );
  return accdb->ovl_res[ i ].epoch==FD_VOLATILE_CONST( accdb->shmem->ovl_epoch ) &&
         accdb->ovl_res[ i ].fork_gen==fork_gen && floor>=accdb->ovl_res[ i ].gen &&
         !memcmp( accdb->ovl_res[ i ].pubkey, pubkey, 32UL );
}

static inline void
ovl_res_insert( fd_accdb_t * accdb,
                uchar const  pubkey[ 32 ],
                uint         fork_gen,
                uint         gen,
                ulong        epoch ) {
  ulong i = ovl_res_slot( pubkey, fork_gen );
  memcpy( accdb->ovl_res[ i ].pubkey, pubkey, 32UL );
  accdb->ovl_res[ i ].fork_gen = fork_gen;
  accdb->ovl_res[ i ].gen      = gen;
  accdb->ovl_res[ i ].epoch    = epoch;
}

/* idx_resolve returns the pool index of the first fork-visible version
   of pubkey on fork, or UINT_MAX.  Every read API resolves through
   here.  Caller holds an epoch.  See fd_accdb_acquire_inner STEP 1 for
   the walk's safety under concurrent prepend. */

static inline uint
idx_resolve( fd_accdb_t *            accdb,
             fd_accdb_fork_t const * fork,
             ushort                  fork_id,
             uint                    root_generation,
             uchar const *           pubkey,
             ulong                   map_idx,
             int                     hook,
             int                     skip_ovl,
             int *                   known,
             ushort *                ovl_f ) {
  *ovl_f = USHORT_MAX;
  uint acc = FD_VOLATILE_CONST( accdb->acc_map[ map_idx ] );
  while( acc!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate_acc = &accdb->acc_pool[ acc ];
    uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

    if( hook ) { fd_racesan_hook( "accdb_acquire:post_next" ); }

    if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation &&
                      fd_accdb_acc_fork_id(candidate_acc)!=fork_id &&
                      !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) ||
                      memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) {
      /* Before following next: if the node was unlinked since we
         loaded it, next may be a deferred stack link, so restart */
      if( FD_UNLIKELY( fd_accdb_acc_unlinked( candidate_acc ) ) ) {
        if( hook ) { fd_racesan_hook( "accdb_acquire:restart" ); }
        acc = FD_VOLATILE_CONST( accdb->acc_map[ map_idx ] );
        continue;
      }
      acc = next_acc;
      continue;
    }
    break;
  }
  if( FD_UNLIKELY( accdb->hot_map && !skip_ovl && FD_VOLATILE_CONST( accdb->shmem->ovl_fork_cnt ) ) ) {
    /* A spilled visible fork newer than the acc_map match wins (R5).
       *ovl_f is the reader fork: the search covers every spilled one. */
    uint floor = acc==UINT_MAX ? 0U : accdb->acc_pool[ acc ].key.generation;
    if( !ovl_res_test( accdb, pubkey, fork->shmem->generation, floor ) && ovl_candidate( accdb, fork, fork_id, pubkey, floor ) ) {
      *ovl_f = fork_id;
      *known = 0;
      return UINT_MAX;
    }
  }
  if( FD_UNLIKELY( acc==UINT_MAX && accdb->hot_map ) ) {
    /* Hot (rooted) tier: older than anything in acc_map for the key. */
    acc = FD_VOLATILE_CONST( accdb->hot_map[ map_idx ] );
    while( acc!=UINT_MAX ) {
      fd_accdb_accmeta_t const * h = &accdb->acc_pool[ acc ];
      uint next = FD_VOLATILE_CONST( h->map.next );
      if( FD_LIKELY( !memcmp( pubkey, h->key.pubkey, 32UL ) ) ) break;
      /* A hot entry unlinked inside a cmd goes on the deferred stack,
         which reuses map.next: restart, as on acc_map */
      if( FD_UNLIKELY( fd_accdb_acc_unlinked( h ) ) ) { acc = FD_VOLATILE_CONST( accdb->hot_map[ map_idx ] ); continue; }
      acc = next;
    }
    if( acc!=UINT_MAX && !accdb->readonly && !FD_VOLATILE_CONST( accdb->hot_ref[ acc ] ) ) FD_VOLATILE( accdb->hot_ref[ acc ] ) = 1;
    if( acc!=UINT_MAX && !FD_VOLATILE_CONST( accdb->acc_pool[ acc ].lamports ) ) { /* NEG */
      *known = 1;
      return UINT_MAX;
    }
  }
  *known = acc!=UINT_MAX;
  return acc;
}

static void idx_residual_wait( fd_accdb_t * accdb, ulong cnt, uchar const * const * keys, ushort const * ovl_forks );

/* idx_maybe_bucket: RAM tiers missed; might the key be bucket-only? */

static inline int
idx_maybe_bucket( fd_accdb_t const * accdb,
                  uchar const *      pubkey ) {
  return accdb->hot_map && fd_accdb_cf_probe( accdb->cf, pubkey );
}

static inline void
idx_residual_ack( fd_accdb_t * accdb ) {
  if( FD_LIKELY( accdb->residual_ticket==ULONG_MAX ) ) return;
  FD_VOLATILE( accdb->shmem->res_ack[ accdb->join_idx ] ) = accdb->residual_ticket+1UL;
  accdb->residual_ticket = ULONG_MAX;
}

static void
fd_accdb_acquire_inner( fd_accdb_t *          accdb,
                        fd_accdb_fork_id_t    fork_id,
                        int                   reservation_type,
                        ulong                 reserved_cnt,
                        ulong                 pubkeys_cnt,
                        uchar const * const * pubkeys,
                        int const *           writable,
                        fd_acc_t *            out_accs ) {
  (void)reserved_cnt;  /* acquire_a remembered what it took for us */
  accdb->metrics->acquire_calls++;

  ulong max_acquire_cnt = accdb->shmem->bundle_enabled ? FD_ACCDB_MAX_ACQUIRE_CNT : FD_ACCDB_MAX_TX_ACCOUNT_LOCKS;
  FD_TEST( pubkeys_cnt<=max_acquire_cnt );

  FD_TEST( FD_VOLATILE_CONST( *accdb->my_epoch_slot )==ULONG_MAX );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: our epoch before any load the reclaim scan protects */

  // PHASE 1.
  //   Find each account's visible version.  The chain head and accmeta
  //   are both likely misses, so prefetch them for the whole batch.

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_racesan_hook( "accdb_acquire:post_root_gen" );

  uchar const * miss_keys[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  ushort        miss_ovl [ FD_ACCDB_MAX_ACQUIRE_CNT ];
  ulong         miss_idx [ FD_ACCDB_MAX_ACQUIRE_CNT ];
  uchar         ovl_done [ FD_ACCDB_MAX_ACQUIRE_CNT ];
  ulong miss_cnt;
  ulong ovl_done_epoch = ULONG_MAX;
  memset( ovl_done, 0, pubkeys_cnt );

step1:
  miss_cnt = 0UL;

  /* Prefetch chain heads, then accmetas */
  uint acc     [ FD_ACCDB_MAX_ACQUIRE_CNT ];  /* the version found (UINT_MAX: none) */
  uint map_idx [ FD_ACCDB_MAX_ACQUIRE_CNT ];
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    map_idx[ i ] = (uint)( fd_hash32( pubkeys[ i ], accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) );
    __builtin_prefetch( &accdb->acc_map[ map_idx[ i ] ], 0, 3 );
  }
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    acc[ i ] = FD_VOLATILE_CONST( accdb->acc_map[ map_idx[ i ] ] );
    if( FD_LIKELY( acc[ i ]!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ acc[ i ] ], 0, 3 );
  }

  /* Walk each chain to the version this fork sees */
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    int    known;
    ushort ovl_f;
    /* keys T2 resolved this call skip ovl while no spill intervened */
    int skip_ovl = ovl_done[ i ] && ovl_done_epoch==FD_VOLATILE_CONST( accdb->shmem->ovl_epoch );
    uint a = idx_resolve( accdb, fork, fork_id.val, root_generation, pubkeys[ i ], map_idx[ i ], 1, skip_ovl, &known, &ovl_f );
    if( FD_UNLIKELY( ovl_f!=USHORT_MAX || ( !known && idx_maybe_bucket( accdb, pubkeys[ i ] ) ) ) ) {
      miss_ovl [ miss_cnt   ] = ovl_f;
      miss_idx [ miss_cnt   ] = i;
      miss_keys[ miss_cnt++ ] = pubkeys[ i ];
      continue;
    }
#if FD_TMPL_USE_HANDHOLDING
    if( FD_UNLIKELY( a!=UINT_MAX ) ) FD_TEST( accdb->acc_pool[ a ].key.generation<=FD_VOLATILE_CONST( accdb->shmem->generation ) );
#endif
    /* A read-only tombstone is not found (it is never loaded) */
    if( FD_UNLIKELY( a!=UINT_MAX && !writable[ i ] && !accdb->acc_pool[ a ].lamports ) ) a = UINT_MAX;
    acc[ i ] = a;

    ulong cls = a!=UINT_MAX ? fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accdb->acc_pool[ a ].executable_size ) ) : 0UL;
    if( FD_LIKELY( writable[ i ] ) ) accdb->metrics->writable_accounts_acquired_per_class[ cls ]++;
    else                             accdb->metrics->accounts_acquired_per_class[ cls ]++;
  }

  /* Residual miss (index mode): STEP 1 holds nothing, so leave the
     epoch, have T2 promote every missing key, and walk again. */
  if( FD_UNLIKELY( miss_cnt ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    ulong ovl_epoch = FD_VOLATILE_CONST( accdb->shmem->ovl_epoch );
    idx_residual_wait( accdb, miss_cnt, miss_keys, miss_ovl );
    if( ovl_epoch!=ovl_done_epoch ) memset( ovl_done, 0, pubkeys_cnt );
    ovl_done_epoch = ovl_epoch;
    for( ulong m=0UL; m<miss_cnt; m++ ) ovl_done[ miss_idx[ m ] ] |= (uchar)( miss_ovl[ m ]!=USHORT_MAX );
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
    FD_HW_MFENCE();
    root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
    goto step1;
  }
  idx_residual_ack( accdb );

  // PHASE 2.
  //   Reserve a line per found account and a staging line per writer.
  //   acquire_a also reserves one per account in every class for
  //   programdata; acquire_b keeps what it needs and gives back the rest.

  /* Count what each class needs */
  ulong need[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_LIKELY( acc[ i ]!=UINT_MAX ) ) need[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accdb->acc_pool[ acc[ i ] ].executable_size ) ) ]++;
    need[ FD_ACCDB_CACHE_CLASS_CNT-1UL ] += (ulong)!!writable[ i ];
  }
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) need[ c ] = fd_ulong_if( res_tracked( accdb, c ), need[ c ], 0UL );

  /* acquire_b: settle acquire_a's reservation.  Else take it all,
     stealing idle credits and retrying on failure. */
  if( FD_UNLIKELY( reservation_type==RESERVATION_TYPE_ALREADY_RESERVED ) ) {
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      FD_TEST( need[ c ]<=accdb->res_extra[ c ] );
      res_give( accdb, c, accdb->res_extra[ c ]-need[ c ] );
      accdb->res_held [ c ] += need[ c ];
      accdb->res_extra[ c ]  = 0UL;
    }
  } else {
    ulong extra = reservation_type==RESERVATION_TYPE_MAYBE_PROGRAMDATA ? pubkeys_cnt : 0UL;
    ulong take[ FD_ACCDB_CACHE_CLASS_CNT ];
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) take[ c ] = need[ c ] + fd_ulong_if( res_tracked( accdb, c ), extra, 0UL );
    for(;;) {
      ulong failed = ULONG_MAX;
      for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
        if( FD_UNLIKELY( take[ c ] && !res_take( accdb, c, take[ c ] ) ) ) { failed = c; break; }
      }
      if( FD_LIKELY( failed==ULONG_MAX ) ) break;
      accdb->metrics->acquire_failed++;
      for( ulong c=0UL; c<failed; c++ ) res_give( accdb, c, take[ c ] );
      res_steal( accdb, failed );
      fd_racesan_hook( "accdb_acquire:reservation_retry" );
      FD_SPIN_PAUSE();
    }
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      accdb->res_held [ c ] += need[ c ];
      accdb->res_extra[ c ]  = take[ c ]-need[ c ];
    }
  }

  // PHASE 3.
  //   Writers take a staging line.  This may evict, so do it before
  //   holding anything.

  uint staging[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( writable[ i ] ) ) staging[ i ] = line_alloc( accdb, FD_ACCDB_CACHE_CLASS_CNT-1UL );
  }

  // PHASE 4.
  //   Hold a line per found account (hazard entry base+i), in rounds:
  //   point each entry at the account's line, fence once, then verify.
  //   Unbound accounts are bound to a line of ours for a cold load.

  /* Publish empty entries */
  uint * hz   = accdb->shmem->cache_hazard[ accdb->join_idx ].cidx;
  ulong  base = accdb->hazard_cnt;
  FD_TEST( base+pubkeys_cnt<=FD_ACCDB_HAZARD_MAX );
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) hz[ base+i ] = FD_ACCDB_ACC_CIDX_INVAL;
  accdb->hazard_cnt = base+pubkeys_cnt;
  FD_COMPILER_MFENCE();  /* the empty entries before cnt */
  FD_VOLATILE( accdb->shmem->cache_hazard[ accdb->join_idx ].cnt ) = accdb->hazard_cnt;

  /* Resolve entries until every found account is held */
  uint  todo[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  uint  cold[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  ulong todo_cnt = 0UL;
  ulong cold_cnt = 0UL;
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    todo[ todo_cnt ] = (uint)i;
    todo_cnt += acc[ i ]!=UINT_MAX;
  }
  while( todo_cnt ) {
    ulong left = 0UL;
    for( ulong t=0UL; t<todo_cnt; t++ ) {
      ulong                i = todo[ t ];
      fd_accdb_accmeta_t * m = &accdb->acc_pool[ acc[ i ] ];
      uint                 h = hz[ base+i ];
      if( h!=FD_ACCDB_ACC_CIDX_INVAL ) {
        /* Wait out an evictor: it ends the line SHARED or unbound */
        fd_accdb_cache_line_t * l = line_at( accdb, h );
        SPIN_UNTIL( FD_VOLATILE_CONST( l->state )!=FD_ACCDB_LINE_EVICTING, "accdb_acquire:claim_wait" );
        FD_COMPILER_MFENCE();  /* the state before the word */
      }
      ulong                d = FD_VOLATILE_CONST( m->data );
      uint                 es = FD_ACCDB_DATA_ES( d );
      fd_racesan_hook( "accdb_acquire:pre_hold" );

      /* Bound: held if our fenced entry names its line, else retry */
      if( FD_ACCDB_SIZE_CACHE_VALID( es ) ) {
        if( h==FD_ACCDB_DATA_CIDX( d ) ) {   /* held: last round's entry, and the fence since */
          fd_accdb_cache_line_t * l = line_at( accdb, h );
          if( FD_UNLIKELY( !FD_VOLATILE_CONST( l->hot ) ) ) FD_VOLATILE( l->hot ) = 1;  /* hint only if clear: hot lines stay read-shared */
          fd_racesan_hook( "accdb_acquire:held" );
          continue;
        }
        FD_VOLATILE( hz[ base+i ] ) = FD_ACCDB_DATA_CIDX( d ); /* changed: try verify new line after fence */
        __builtin_prefetch( line_at( accdb, FD_ACCDB_DATA_CIDX( d ) ), 0, 3 );
        todo[ left++ ] = (uint)i;
        continue;
      }

      /* Unbound: bind it to a line of ours, or retry if someone beat us */
      FD_VOLATILE( hz[ base+i ] ) = FD_ACCDB_ACC_CIDX_INVAL;  /* no stale hold while we allocate */
      uint L = line_alloc( accdb, fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( es ) ) );
      fd_racesan_hook( "accdb_acquire:pre_publish" );
      if( FD_LIKELY( FD_ATOMIC_CAS( &m->data, d, FD_ACCDB_DATA( L, es | FD_ACCDB_SIZE_CACHE_VALID_BIT ) )==d ) ) {
        hz[ base+i ] = L;   /* OWNED until phase 5 publishes it: no claim can see it */
        cold[ cold_cnt++ ] = (uint)i;
        continue;
      }
      fd_racesan_hook( "accdb_acquire:lost_publish" );
      line_free( accdb, L );
      todo[ left++ ] = (uint)i;
    }
    todo_cnt = left;
    if( todo_cnt ) FD_HW_MFENCE();  /* StoreLoad: this round's entries before the checks (evictors' Dekker) */
  }

  // PHASE 5.
  //   Read cold accounts from disk.

  for( ulong k=0UL; k<cold_cnt; k++ ) {
    ulong                   i = cold[ k ];
    fd_accdb_accmeta_t *    m = &accdb->acc_pool[ acc[ i ] ];
    fd_accdb_cache_line_t * l = line_at( accdb, hz[ base+i ] );
    ulong                   n = FD_ACCDB_SIZE_DATA( m->executable_size );
    accdb->metrics->accounts_not_found_per_class[ fd_accdb_cache_class( n ) ]++;
    if( FD_LIKELY( m->lamports ) ) {   /* a tombstone has no payload */
      ulong off = fd_accdb_acc_offset( m );
#if FD_TMPL_USE_HANDHOLDING
      FD_TEST( FD_ACCDB_OFF_CLEAN( off ) );
#endif
      fd_racesan_hook( "accdb_acquire:pre_read" );
      read_full( accdb, off+offsetof( fd_accdb_disk_meta_t, owner ), l->owner, 32UL+n );
    }
    l->acc_idx = acc[ i ];
    line_seq_close( l );
    line_publish( l );
  }

  // PHASE 6.
  //   Fill the outputs from each held line.

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    /* Private fields */
    fd_acc_t * out = &out_accs[ i ];
    fd_racesan_hook( "accdb_acquire:pre_out" );
    fd_memcpy( out->pubkey, pubkeys[ i ], 32UL );
    out->commit    = 0;
    out->pd_write  = 0;
    out->_writable = writable[ i ];
    out->_acc      = acc[ i ];
    out->_cidx     = FD_ACCDB_ACC_CIDX_INVAL;
    out->_staging  = writable[ i ] ? staging[ i ] : FD_ACCDB_ACC_CIDX_INVAL;
    out->_overwrite = 0;
    if( FD_UNLIKELY( writable[ i ] ) ) {
      out->_fork_id     = fork_id.val;
      out->_generation  = fork->shmem->generation;
      out->_acc_map_idx = map_idx[ i ];
    }

    /* Not found: empty */
    if( FD_UNLIKELY( acc[ i ]==UINT_MAX ) ) {
      out->data       = writable[ i ] ? (uchar *)( line_at( accdb, staging[ i ] )+1UL ) : NULL;
      out->data_len   = 0UL;
      out->lamports   = 0UL;
      out->executable = 0;
      memset( out->owner, 0, 32UL );
      out->prior_lamports   = 0UL;
      out->prior_data_len   = 0UL;
      out->prior_executable = 0;
      memset( out->prior_owner, 0, 32UL );
      out->prior_data = NULL;
      continue;
    }

    /* Wait for another join's cold load of our line */
    fd_accdb_accmeta_t const * m = &accdb->acc_pool[ acc[ i ] ];
    uint                       c = hz[ base+i ];
    fd_accdb_cache_line_t *    l = line_at( accdb, c );
    if( FD_UNLIKELY( FD_VOLATILE_CONST( l->state )==FD_ACCDB_LINE_OWNED ) ) {
      accdb->metrics->accounts_waited++;
      SPIN_UNTIL( FD_VOLATILE_CONST( l->state )!=FD_ACCDB_LINE_OWNED, "accdb_acquire:load_wait" );
    }
    FD_COMPILER_MFENCE();  /* the state before the bytes */
#if FD_TMPL_USE_HANDHOLDING
    FD_TEST( l->acc_idx==acc[ i ] );
    FD_TEST( FD_ACCDB_ACC_CIDX_CLASS( c )==fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( m->executable_size ) ) );
#endif

    /* Account fields.  Tombstone reset: agave's account loader returns
       AccountSharedData::default() (System owner, empty data, exec=0)
       for any account with lamports==0.
       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L199-L228 */
    uint es        = m->executable_size;
    int  tombstone = !m->lamports;
    out->_cidx      = c;
    out->_overwrite = writable[ i ] && fork->shmem->generation==m->key.generation;
    out->lamports   = m->lamports;
    out->data_len   = tombstone ? 0UL : FD_ACCDB_SIZE_DATA( es );
    out->executable = tombstone ? 0   : FD_ACCDB_SIZE_EXEC( es );
    if( FD_UNLIKELY( tombstone ) ) memset   ( out->owner, 0,        32UL );
    else                           fd_memcpy( out->owner, l->owner, 32UL );
    fd_memcpy( out->prior_owner, out->owner, 32UL );
    out->prior_lamports   = out->lamports;
    out->prior_data_len   = out->data_len;
    out->prior_executable = out->executable;
    out->prior_data       = (uchar *)( l+1UL );
    FD_TEST( out->data_len<=(10UL<<20) );

    /* Data: readers use the line, writers a copy in their staging line */
    if( FD_LIKELY( !writable[ i ] ) ) {
      out->data = (uchar *)( l+1UL );
    } else {
      out->data = (uchar *)( line_at( accdb, staging[ i ] )+1UL );
      fd_memcpy( out->data, l+1UL, out->data_len );
      accdb->metrics->bytes_copied += out->data_len;
    }
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

void
fd_accdb_acquire( fd_accdb_t *          accdb,
                  fd_accdb_fork_id_t    fork_id,
                  ulong                 pubkeys_cnt,
                  uchar const * const * pubkeys,
                  int *                 writable,
                  fd_acc_t *            out_accs ) {
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_IDLE );
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_OPEN;
  fd_accdb_acquire_inner( accdb, fork_id, RESERVATION_TYPE_SIMPLE, 0UL, pubkeys_cnt, pubkeys, writable, out_accs );
}

void
fd_accdb_acquire_a( fd_accdb_t *             accdb,
                       fd_accdb_fork_id_t    fork_id,
                       ulong                 pubkeys_cnt,
                       uchar const * const * pubkeys,
                       int *                 writable,
                       fd_acc_t *            out_accs ) {
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_IDLE );
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_PHASE_A;
  fd_accdb_acquire_inner( accdb, fork_id, RESERVATION_TYPE_MAYBE_PROGRAMDATA, 0UL, pubkeys_cnt, pubkeys, writable, out_accs );
}

void
fd_accdb_acquire_b( fd_accdb_t *          accdb,
                    fd_accdb_fork_id_t    fork_id,
                    ulong                 reserved_cnt,
                    ulong                 pubkeys_cnt,
                    uchar const * const * pubkeys,
                    fd_acc_t *            out_accs ) {
  static int const readonly[ FD_ACCDB_MAX_ACQUIRE_CNT ] = {0};
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_PHASE_A );
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_OPEN;
  fd_accdb_acquire_inner( accdb, fork_id, RESERVATION_TYPE_ALREADY_RESERVED, reserved_cnt, pubkeys_cnt, pubkeys, readonly, out_accs );
}

/* commit_dst picks a commit's line: a line of class c, retried until
   CLOCK has swept the class twice (one lap spends the hints, the next
   tries every unheld line).  Commits are not reserved, so if every line
   is held it returns INVAL and the commit goes to disk (commit_disk).
   An account is only ever bound to a line of its own class, which is
   what acquire reserves. */

static inline uint
commit_dst( fd_accdb_t * accdb,
            ulong        c,
            uint         staging ) {
  if( c==FD_ACCDB_CACHE_CLASS_CNT-1UL ) return staging;
  uint d = line_alloc_try( accdb, c );
  if( FD_LIKELY( d!=FD_ACCDB_ACC_CIDX_INVAL ) ) return d;

  /* Retry until the shared hand has gone two more laps */
  ulong * hand = &accdb->shmem->clock_hand[ c ].val;
  ulong   end  = FD_VOLATILE_CONST( *hand ) + 2UL*accdb->shmem->cache_class_max[ c ];
  while( (long)( FD_VOLATILE_CONST( *hand )-end )<0L ) {
    fd_racesan_hook( "accdb_commit:dst_retry" );
    FD_SPIN_PAUSE();
    d = line_alloc_try( accdb, c );
    if( FD_LIKELY( d!=FD_ACCDB_ACC_CIDX_INVAL ) ) return d;
  }
  return FD_ACCDB_ACC_CIDX_INVAL;
}

/* commit_disk writes a committed account straight from its staging
   line to a new disk record and returns the record's offset.  For when
   commit_dst finds no line: the account is then published unbound. */

static __attribute__((noinline,cold)) ulong
commit_disk( fd_accdb_t *                  accdb,
             fd_acc_t const *              a,
             uint                          generation,
             fd_accdb_cache_line_t const * staging ) {
  fd_accdb_disk_meta_t hdr;
  fd_memcpy( hdr.pubkey, a->pubkey, 32UL );
  hdr.size       = (uint)a->data_len;
  hdr.generation = generation;
  fd_memcpy( hdr.owner, a->owner, 32UL );
  struct iovec iov[ 2 ] = {
    { .iov_base = &hdr,                    .iov_len = sizeof(fd_accdb_disk_meta_t) },
    { .iov_base = (void *)( staging+1UL ), .iov_len = a->data_len                  },
  };
  ulong sz  = sizeof(fd_accdb_disk_meta_t)+a->data_len;
  ulong off = allocate_next_write( accdb, sz );
  write_iov( accdb, off, iov, 2UL, sz );
  FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_used_bytes, sz );
  fd_racesan_hook( "accdb_commit:post_disk" );
  return off;
}

/* release_inner commits or discards one group of acquired accounts. */

static void
release_inner( fd_accdb_t * accdb,
               ulong        accs_cnt,
               fd_acc_t *   accs ) {
  /* Index mode: reserve one pool slot per new version before taking
     the epoch, so T2 never waits on us while we wait on it. */
  if( FD_UNLIKELY( idx_enabled( accdb ) ) ) {
    FD_TEST( FD_VOLATILE_CONST( *accdb->my_epoch_slot )==ULONG_MAX );
    ulong need = 0UL;
    for( ulong i=0UL; i<accs_cnt; i++ ) need += (ulong)( accs[ i ]._writable && accs[ i ].commit && !accs[ i ]._overwrite );
    while( need ) {
      ulong avail = FD_VOLATILE_CONST( accdb->shmem->pool_avail );
      if( FD_LIKELY( avail>=need && FD_ATOMIC_CAS( &accdb->shmem->pool_avail, avail, avail-need )==avail ) ) break;
      accdb->metrics->acquire_pool_waits++;
      if( FD_LIKELY( accdb->sleep ) ) fd_sleep_ring( accdb->sleep, accdb->sleep_tile_id );
      FD_SPIN_PAUSE();
    }
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: our epoch before we touch accmetas */

  for( ulong i=0UL; i<accs_cnt; i++ ) {
    fd_acc_t * a = &accs[ i ];
#if FD_TMPL_USE_HANDHOLDING
    if( FD_UNLIKELY( a->commit ) ) FD_TEST( a->_writable );
#endif
    /* Discard: free the staging line */
    if( FD_LIKELY( !a->_writable ) ) continue;
    uint s = a->_staging;
    if( FD_LIKELY( !a->commit ) ) { line_free( accdb, s ); continue; }

    ulong c  = fd_accdb_cache_class( a->data_len );
    uint  es = FD_ACCDB_SIZE_PACK( (uint)a->data_len, a->executable )
             | FD_ACCDB_SIZE_CACHE_VALID_BIT
             | ( a->pd_write ? FD_ACCDB_SIZE_PD_WRITE_BIT : 0U );
    fd_racesan_hook( "accdb_commit:pre" );

    if( FD_LIKELY( a->_overwrite ) ) {
      /* Overwrite our fork's version.  Retire its record first (UPDATING
         is our side of the in-place Dekker). */
      fd_accdb_accmeta_t * m   = &accdb->acc_pool[ a->_acc ];
      uint                 old = FD_ACCDB_DATA_ES( m->data );
      es |= old & FD_ACCDB_SIZE_PD_WRITE_BIT;  /* sticky within the slot */
      off_swap( accdb, m, FD_ACCDB_OFF_UPDATING, old );
      m->lamports = a->lamports;
      accdb->metrics->accounts_committed_overwrite_per_class[ c ]++;

      /* Rewrite the line in place if no evictor has it, else move.  The
         largest class always moves: its staging line is adopted as is
         (commit_dst), which saves copying up to 10 MiB. */
      uint                    og = a->_cidx;
      fd_accdb_cache_line_t * L  = line_at( accdb, og );
      uint                    D;
      if( c!=FD_ACCDB_CACHE_CLASS_CNT-1UL && FD_ACCDB_ACC_CIDX_CLASS( og )==c && FD_VOLATILE_CONST( L->state )==FD_ACCDB_LINE_SHARED ) {
        D = og;
        line_seq_open( L );
        fd_memcpy( L->owner, a->owner, 32UL );
        fd_memcpy( L+1UL, line_at( accdb, s )+1UL, a->data_len );
        line_seq_close( L );
        line_free( accdb, s );
      } else {
        D = commit_dst( accdb, c, s );
        if( FD_UNLIKELY( D==FD_ACCDB_ACC_CIDX_INVAL ) ) {
          /* No line: commit to disk, then unbind (og is now an orphan) */
          ulong off = commit_disk( accdb, a, m->key.generation, line_at( accdb, s ) );
          line_free( accdb, s );
          FD_COMPILER_MFENCE();  /* the record before its offset */
          fd_accdb_acc_xchg_offset( m, off );
          FD_COMPILER_MFENCE();  /* a real offset before unbound: a cold load reads the record */
          FD_VOLATILE( m->data ) = FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, es & ~FD_ACCDB_SIZE_CACHE_VALID_BIT );
          continue;
        }
        fd_accdb_cache_line_t * Ld = line_at( accdb, D );
        fd_memcpy( Ld->owner, a->owner, 32UL );
        if( D!=s ) { fd_memcpy( Ld+1UL, line_at( accdb, s )+1UL, a->data_len ); line_free( accdb, s ); }
        Ld->acc_idx = a->_acc;
        line_seq_close( Ld );
      }
      accdb->metrics->bytes_copied += a->data_len;

      /* Point the word at D, then mark it dirty */
      FD_COMPILER_MFENCE();  /* D's bytes before the word: readers that see it read them */
      FD_VOLATILE( m->data ) = FD_ACCDB_DATA( D, es );   /* og, if moved, is now an orphan */
      fd_racesan_hook( "accdb_commit:pre_dirty" );
      FD_COMPILER_MFENCE();  /* the word before DIRTY (DIRTY(D) => the word names D) */
      fd_accdb_acc_xchg_offset( m, FD_ACCDB_OFF_DIRTY( D ) );
      if( D!=og ) line_publish( line_at( accdb, D ) );
      continue;
    }

    /* New version: fill its line, or write it to disk if there is none */
    accdb->metrics->accounts_committed_new_per_class[ c ]++;
    uint                    D   = commit_dst( accdb, c, s );
    ulong                   off = FD_ACCDB_OFF_DIRTY( D );
    fd_accdb_cache_line_t * Ld  = NULL;
    if( FD_UNLIKELY( D==FD_ACCDB_ACC_CIDX_INVAL ) ) {
      off = commit_disk( accdb, a, a->_generation, line_at( accdb, s ) );
      line_free( accdb, s );
      es &= ~FD_ACCDB_SIZE_CACHE_VALID_BIT;
    } else {
      Ld = line_at( accdb, D );
      fd_memcpy( Ld->owner, a->owner, 32UL );
      if( D!=s ) { fd_memcpy( Ld+1UL, line_at( accdb, s )+1UL, a->data_len ); line_free( accdb, s ); }
      accdb->metrics->bytes_copied += a->data_len;
    }

    /* Fill a new accmeta (unreachable until the head CAS) */
    fd_accdb_accmeta_t * m = acc_pool_acquire( accdb->acc_pool_join );
    if( FD_UNLIKELY( !m ) ) FD_LOG_ERR(( "accounts database ran out of space, increase [accounts.max_accounts], current value is %lu", acc_pool_ele_max( accdb->acc_pool_join ) ));
    uint acc_idx = (uint)acc_pool_idx( accdb->acc_pool_join, m );
    fd_memcpy( m->key.pubkey, a->pubkey, 32UL );
    m->key.generation = a->_generation;
    m->lamports       = a->lamports;
    m->offset_fork    = fd_accdb_acc_pack_offset_fork( off, a->_fork_id );
    FD_VOLATILE( m->data ) = FD_ACCDB_DATA( D, es );  /* an orphan's evictor may still read the recycled word */
    if( FD_LIKELY( Ld ) ) {
      Ld->acc_idx = acc_idx;
      line_seq_close( Ld );
      line_publish( Ld );
    }

    /* Prepend it to its chain and to the fork's txn list */
    for(;;) {
      uint head = FD_VOLATILE_CONST( accdb->acc_map[ a->_acc_map_idx ] );
      m->map.next = head;
      FD_COMPILER_MFENCE();  /* the accmeta's fields before the head */
      fd_racesan_hook( "accdb_release:pre_chain_cas" );
      if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->acc_map[ a->_acc_map_idx ], head, acc_idx )==head ) ) break;
    }

    fd_accdb_txn_t * txn = txn_pool_acquire( accdb->txn_pool );
    FD_TEST( txn ); /* sized so it always succeeds */
    txn->acc_pool_idx = acc_idx;
    uint txn_idx = (uint)txn_pool_idx( accdb->txn_pool, txn );
    for(;;) {
      uint head = FD_VOLATILE_CONST( accdb->fork_pool[ a->_fork_id ].shmem->txn_head );
      txn->fork.next = head;
      if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->fork_pool[ a->_fork_id ].shmem->txn_head, head, txn_idx )==head ) ) break;
    }
    FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->accounts_total, 1UL );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

/* release_end drops every hold and reservation of the bracket. */

static void
release_end( fd_accdb_t * accdb ) {
  fd_racesan_hook( "accdb_release:pre_drop" );
  FD_COMPILER_MFENCE();  /* our uses of the held lines before the drop */
  FD_VOLATILE( accdb->shmem->cache_hazard[ accdb->join_idx ].cnt ) = 0UL;
  accdb->hazard_cnt = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    res_give( accdb, c, accdb->res_held[ c ]+accdb->res_extra[ c ] );
    accdb->res_held [ c ] = 0UL;
    accdb->res_extra[ c ] = 0UL;
  }
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
}

void
fd_accdb_release( fd_accdb_t * accdb,
                  ulong        accs_cnt,
                  fd_acc_t *   accs ) {
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_OPEN );
  release_inner( accdb, accs_cnt, accs );
  release_end( accdb );
}

void
fd_accdb_release_ab( fd_accdb_t * accdb,
                     ulong        accs_cnt,
                     fd_acc_t *   accs,
                     ulong        execs_cnt,
                     fd_acc_t *   execs ) {
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_OPEN );
  release_inner( accdb, accs_cnt, accs );
  if( FD_LIKELY( execs_cnt ) ) release_inner( accdb, execs_cnt, execs );
  release_end( accdb );
}

fd_acc_t
fd_accdb_read_one( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey ) {
  fd_acc_t acc;
  fd_accdb_acquire( accdb, fork_id, 1UL, &pubkey, (int[]){0}, &acc );
  return acc;
}

void
fd_accdb_unread_one( fd_accdb_t * accdb,
                     fd_acc_t *   acc ) {
  fd_accdb_release( accdb, 1UL, acc );
}

fd_acc_t
fd_accdb_write_one( fd_accdb_t *       accdb,
                    fd_accdb_fork_id_t fork_id,
                    uchar const *      pubkey ) {
  fd_acc_t acc;
  fd_accdb_acquire( accdb, fork_id, 1UL, &pubkey, (int[]){1}, &acc );
  return acc;
}

void
fd_accdb_unwrite_one( fd_accdb_t * accdb,
                      fd_acc_t *   acc ) {
  fd_accdb_release( accdb, 1UL, acc );
}

int
fd_accdb_read_one_nocache( fd_accdb_t *       accdb,
                           fd_accdb_fork_id_t fork_id,
                           uchar const *      pubkey,
                           ulong *            out_lamports,
                           int *              out_executable,
                           uchar *            out_owner,
                           uchar *            out_data,
                           ulong *            out_data_len ) {
  /* The epoch keeps the accmeta and its record alive */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();

  /* Find the visible version, as acquire does. */
  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  int    known;
  ushort ovl_f;
  uint acc_idx = idx_resolve( accdb, fork, fork_id.val, root_generation, pubkey, hash, 0, 0, &known, &ovl_f );
  fd_accdb_idx_slot_t ovl_slot;
  int                 ovl_hit = 0;
  if( FD_UNLIKELY( ovl_f!=USHORT_MAX && accdb->bkt->fd>=0 ) ) {
    /* search every spilled fork, else the older tiers answer */
    acc_idx = idx_resolve( accdb, fork, fork_id.val, root_generation, pubkey, hash, 0, 1, &known, &ovl_f );
    uint floor = acc_idx==UINT_MAX ? 0U : accdb->acc_pool[ acc_idx ].key.generation;
    ovl_hit = ovl_search( accdb, fork, fork_id.val, pubkey, floor, &ovl_slot )!=USHORT_MAX;
    ovl_f   = USHORT_MAX;
    if( ovl_hit ) { acc_idx = UINT_MAX; known = 1; }
  }
  fd_accdb_accmeta_t const * accmeta = acc_idx==UINT_MAX ? NULL : &accdb->acc_pool[ acc_idx ];

  fd_accdb_accmeta_t bkt_meta[1];
  /* Incremental under check: its watched winners shadow the bucket. */
  if( FD_UNLIKELY( accdb->pend_watch_cnt ) ) {
    for( ulong i=0UL; i<accdb->pend_watch_cnt; i++ ) {
      if( !accdb->pend[ i ].off_plus1 || memcmp( accdb->pend[ i ].pubkey, pubkey, 32UL ) ) continue;
      memset( bkt_meta, 0, sizeof(bkt_meta) );
      memcpy( bkt_meta->key.pubkey, pubkey, 32UL );
      bkt_meta->lamports        = accdb->pend[ i ].lamports;
      bkt_meta->executable_size = accdb->pend[ i ].exec_size;
      bkt_meta->cache_idx       = FD_ACCDB_ACC_CIDX_INVAL;
      bkt_meta->offset_fork     = fd_accdb_acc_pack_offset_fork( accdb->pend[ i ].off_plus1-1UL, FD_ACCDB_FORK_ID_ROOTED );
      accmeta = bkt_meta;
      known   = 1;
    }
  }
  /* Bucket-only or spilled (index mode, joiners with an index fd):
     read the slot, then the record. */
  if( FD_UNLIKELY( !accmeta && ( ovl_hit || ( !known && idx_maybe_bucket( accdb, pubkey ) ) ) && accdb->bkt->fd>=0 ) ) {
    fd_accdb_idx_slot_t slot;
    int hit = ovl_hit ? ( slot = ovl_slot, 1 ) : fd_accdb_idx_lookup( accdb->bkt, accdb->shmem->seed, pubkey, 0, &slot );
    if( hit && slot.lamports ) {
      memset( bkt_meta, 0, sizeof(bkt_meta) );
      memcpy( bkt_meta->key.pubkey, pubkey, 32UL );
      bkt_meta->key.generation  = slot.generation;
      bkt_meta->lamports        = slot.lamports;
      bkt_meta->data            = FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, slot.exec_size & ~FD_ACCDB_SIZE_CACHE_VALID_BIT );
      bkt_meta->offset_fork     = fd_accdb_acc_pack_offset_fork( slot.off_plus1-1UL, FD_ACCDB_FORK_ID_ROOTED );
      accmeta = bkt_meta;
    }
  }

  if( FD_UNLIKELY( !accmeta ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    if( FD_UNLIKELY( !accdb->readonly && ( ovl_f!=USHORT_MAX || ( !known && accdb->bkt->fd<0 && idx_maybe_bucket( accdb, pubkey ) ) ) ) ) {
      idx_residual_wait( accdb, 1UL, &pubkey, &ovl_f );
      int r = fd_accdb_read_one_nocache( accdb, fork_id, pubkey, out_lamports, out_executable, out_owner, out_data, out_data_len );
      idx_residual_ack( accdb );
      return r;
    }
    accdb->metrics->accounts_acquired_per_class[ 0 ]++;
    *out_lamports = 0UL;
    return FD_ACCDB_READ_ONE_NOCACHE_MISS;
  }

  int result = FD_ACCDB_READ_ONE_NOCACHE_MISS;
  *out_lamports = 0UL;

  accdb->metrics->accounts_acquired_per_class[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( FD_VOLATILE_CONST( accmeta->executable_size ) ) ) ]++;

  /* Copy from the line without holding it, else read the disk.  A
     dirty version has no record yet, so retry until it is clean.  The
     fields are stable while another fork can see the version, but an
     overwrite on its own fork changes them, so each try reloads them:
     the lengths are those of the word the copy is checked against. */
  ulong lamports;
  uint  es;
  ulong data_len;
  for(;;) {
    lamports = FD_VOLATILE_CONST( accmeta->lamports );
    if( FD_UNLIKELY( !lamports ) ) goto done;
    ulong d = FD_VOLATILE_CONST( accmeta->data );
    es       = FD_ACCDB_DATA_ES( d );
    data_len = FD_ACCDB_SIZE_DATA( es );
    ulong read_len = out_data ? data_len : 0UL;
    FD_COMPILER_MFENCE();  /* the word before the line */
    if( FD_LIKELY( FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( d ) ) &&
                   fd_accdb_line_read_unheld( line_at( accdb, FD_ACCDB_DATA_CIDX( d ) ), &accmeta->data, d, out_owner, out_data, read_len ) ) ) {
      result = FD_ACCDB_READ_ONE_NOCACHE_CACHE;
      accdb->metrics->bytes_copied += read_len;
      break;
    }
    ulong off = fd_accdb_acc_offset( accmeta );
    if( FD_UNLIKELY( off==FD_ACCDB_OFF_DEAD ) ) goto done;   /* unlinked under us */
    if( FD_UNLIKELY( !FD_ACCDB_OFF_CLEAN( off ) ) ) {
      fd_racesan_hook( "accdb_nocache:dirty_wait" );
      FD_SPIN_PAUSE();
      continue;
    }
    /* A commit retires the offset before it changes the word, so with
       the word unchanged, the clean offset is the record d sizes */
    if( FD_UNLIKELY( FD_VOLATILE_CONST( accmeta->data )!=d ) ) continue;
    accdb->metrics->accounts_not_found_per_class[ fd_accdb_cache_class( data_len ) ]++;
    fd_racesan_hook( "accdb_nocache:pre_preadv2" );
    ulong start = off+offsetof( fd_accdb_disk_meta_t, owner );
    read_full( accdb, start, out_owner, 32UL );
    if( read_len ) read_full( accdb, start+32UL, out_data, read_len );
    result = FD_ACCDB_READ_ONE_NOCACHE_DISK;
    break;
  }
  *out_lamports   = lamports;
  *out_executable = FD_ACCDB_SIZE_EXEC( es );
  *out_data_len   = data_len;

done:
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  return result;
}

/* idx_meta resolves (lamports, executable_size) of pubkey on fork
   through every tier.  Returns 0 if absent. */

static int
idx_meta( fd_accdb_t *       accdb,
          fd_accdb_fork_id_t fork_id,
          uchar const *      pubkey,
          ulong *            out_lamports,
          uint *             out_es ) {
  ulong hash = fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  for(;;) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
    FD_HW_MFENCE();
    uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
    fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
    int    known;
    ushort ovl_f;
    uint acc   = idx_resolve( accdb, fork, fork_id.val, root_generation, pubkey, hash, 0, 0, &known, &ovl_f );
    int  found = 0;
    fd_accdb_idx_slot_t slot;
    if( FD_UNLIKELY( ovl_f!=USHORT_MAX && accdb->bkt->fd>=0 ) ) {
      acc = idx_resolve( accdb, fork, fork_id.val, root_generation, pubkey, hash, 0, 1, &known, &ovl_f );
      uint floor = acc==UINT_MAX ? 0U : accdb->acc_pool[ acc ].key.generation;
      ovl_f = USHORT_MAX;
      if( ovl_search( accdb, fork, fork_id.val, pubkey, floor, &slot )!=USHORT_MAX ) {
        *out_lamports = slot.lamports;
        *out_es       = slot.exec_size;
        found = 1;
        known = 1;
        acc   = UINT_MAX;
      }
    }
    if( found ) {
    } else if( acc!=UINT_MAX ) {
      *out_lamports = FD_VOLATILE_CONST( accdb->acc_pool[ acc ].lamports );
      *out_es       = FD_VOLATILE_CONST( accdb->acc_pool[ acc ].executable_size );
      found = 1;
    } else if( !known && idx_maybe_bucket( accdb, pubkey ) && accdb->bkt->fd>=0 ) {
      fd_accdb_idx_slot_t slot;
      if( fd_accdb_idx_lookup( accdb->bkt, accdb->shmem->seed, pubkey, 0, &slot ) ) {
        *out_lamports = slot.lamports;
        *out_es       = slot.exec_size;
        found = 1;
      }
      known = 1;
    }
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    if( found || ( ovl_f==USHORT_MAX && ( known || !idx_maybe_bucket( accdb, pubkey ) ) ) || accdb->readonly ) {
      idx_residual_ack( accdb );
      return found;
    }
    idx_residual_wait( accdb, 1UL, &pubkey, &ovl_f );
  }
}

int
fd_accdb_read_one_meta( fd_accdb_t *       accdb,
                        fd_accdb_fork_id_t fork_id,
                        uchar const *      pubkey,
                        uchar *            out_owner,
                        ulong *            out_data_len ) {
  ulong lamports;
  int   executable;
  return fd_accdb_read_one_nocache( accdb, fork_id, pubkey, &lamports, &executable,
                                   out_owner, NULL, out_data_len );
}

int
fd_accdb_exists( fd_accdb_t *       accdb,
                 fd_accdb_fork_id_t fork_id,
                 uchar const *      pubkey ) {
  ulong lamports; uint es;
  return idx_meta( accdb, fork_id, pubkey, &lamports, &es ) && lamports;
}

int
fd_accdb_probe_pd_this_fork( fd_accdb_t *       accdb,
                             fd_accdb_fork_id_t fork_id,
                             uchar const *      pubkey,
                             int *              out_pd_write,
                             ulong *            out_data_len,
                             ulong *            out_lamports ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();

  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  int    known;
  ushort ovl_f;
  uint acc = idx_resolve( accdb, fork, fork_id.val, root_generation, pubkey, hash, 0, 0, &known, &ovl_f );

  int   pd        = 0;
  int   gen_match = 0;
  ulong len       = 0UL;
  ulong lamports  = 0UL;
  if( FD_LIKELY( acc!=UINT_MAX ) ) {
    fd_accdb_accmeta_t const * m = &accdb->acc_pool[ acc ];
    uint es   = FD_VOLATILE_CONST( m->executable_size );
    gen_match = ( m->key.generation==fork->shmem->generation );
    pd        = gen_match && FD_ACCDB_SIZE_PD_WRITE( es );
    len       = FD_ACCDB_SIZE_DATA( es );
    lamports  = FD_VOLATILE_CONST( m->lamports );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;

  *out_pd_write = pd;
  if( gen_match ) {
    *out_data_len = len;
    *out_lamports = lamports;
  }
  return gen_match;
}

ulong
fd_accdb_lamports( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey ) {
  ulong lamports; uint es;
  return idx_meta( accdb, fork_id, pubkey, &lamports, &es ) ? lamports : 0UL;
}

ulong
fd_accdb_data_len( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey ) {
  ulong lamports; uint es;
  if( !idx_meta( accdb, fork_id, pubkey, &lamports, &es ) || !lamports ) return 0UL;
  return FD_ACCDB_SIZE_DATA( es );
}

/* background_preevict (the accdb tile) refills a class's free lines up
   to its target, as hints in the joins' rings.  It runs when the class
   drops below low water or a join ran out, and visits at most
   PREEVICT_TICK_BUDGET lines and reads about PREEVICT_SCAN_BUDGET
   hazard entries per class per call.  force (tests) sweeps
   every class eight times. */

#define PREEVICT_TICK_BUDGET (1024UL)

/* PREEVICT_SCAN_BUDGET bounds the hazard entries one pass reads per
   class: each CLOCK batch scans every join's list, so long lists (big
   bundles) get fewer batches per pass. */
#define PREEVICT_SCAN_BUDGET (4096UL)

static void
background_preevict( fd_accdb_t * accdb,
                     int *        charge_busy,
                     int          force ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_LIKELY( !force ) ) {
    long now = fd_tickcount();
    if( FD_LIKELY( now-accdb->preevict_ticks<accdb->preevict_interval ) ) {
      *charge_busy |= accdb->preevict_pending;
      return;
    }
    accdb->preevict_ticks   = now;
    accdb->preevict_pending = 0;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: victims' accmetas are read until their records publish */

  ulong joiner_cnt = fd_ulong_min( FD_VOLATILE_CONST( shmem->joiner_cnt ), FD_ACCDB_MAX_JOINERS );

  /* Batches per class this pass: a scan costs about every list's length */
  ulong hz_len = joiner_cnt;
  for( ulong j=0UL; j<joiner_cnt; j++ ) hz_len += fd_ulong_min( FD_VOLATILE_CONST( shmem->cache_hazard[ j ].cnt ), FD_ACCDB_HAZARD_MAX );
  ulong scan_max = fd_ulong_max( 1UL, PREEVICT_SCAN_BUDGET/hz_len );

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong max_c = shmem->cache_class_max[ c ];

    /* Tests: free everything */
    if( FD_UNLIKELY( force ) ) {
      for( ulong budget=8UL*max_c; budget; ) {
        uint  got[ RECLAIM_MAX ];
        ulong visit = fd_ulong_min( budget, 2UL*RECLAIM_MAX );
        ulong n     = line_reclaim( accdb, c, visit, RECLAIM_MAX, got, 1 );
        budget -= visit;
        for( ulong k=0UL; k<n; k++ ) line_free( accdb, got[ k ] );
      }
      continue;
    }

    /* Count free lines and demand */
    ulong have  [ FD_ACCDB_MAX_JOINERS ];   /* untaken hints (never less than this) */
    uchar active[ FD_ACCDB_MAX_JOINERS ];   /* the join allocates in class c */
    ulong free_c = max_c - fd_ulong_min( FD_VOLATILE_CONST( shmem->cache_class_init[ c ].val ), max_c );
    ulong hungry = 0UL;
    for( ulong j=0UL; j<joiner_cnt; j++ ) {
      fd_accdb_ring_t * r = &shmem->cache_ring[ j ][ c ];
      have  [ j ] = fd_ulong_min( r->p.prod - FD_VOLATILE_CONST( r->c.cons ), FD_ACCDB_RING_N );
      active[ j ] = (uchar)( FD_VOLATILE_CONST( r->c.cons ) || FD_VOLATILE_CONST( r->p.hungry ) );
      free_c += have[ j ];
      hungry += !!FD_VOLATILE_CONST( r->p.hungry );
    }

    /* Decide how many to free, capped by the rings' room */
    if( FD_LIKELY( free_c>=shmem->cache_free_low_water[ c ] && !hungry ) ) continue;
    *charge_busy = 1;
    ulong want   = fd_ulong_sat_sub( shmem->cache_free_target[ c ], free_c ) + hungry*RECLAIM_MAX;
    ulong room   = 0UL;   /* a line freed past the rings' room would be invisible to the next count */
    for( ulong j=0UL; j<joiner_cnt; j++ ) room += active[ j ] ? FD_ACCDB_RING_N-have[ j ] : 0UL;
    want = fd_ulong_min( want, room );

    /* Reclaim in batches, handing each line to the neediest ring */
    ulong budget    = PREEVICT_TICK_BUDGET;
    ulong scans     = scan_max;
    ulong batch     = fd_accdb_cache_slot_sz[ c ]<RECLAIM_LARGE_SZ ? RECLAIM_MAX : 1UL;
    int   taken_any = 0;
    while( want && budget && scans-- ) {
      uint  got[ RECLAIM_MAX ];
      ulong visit = fd_ulong_min( budget, 2UL*RECLAIM_MAX );
      ulong n     = line_reclaim( accdb, c, visit, fd_ulong_min( want, batch ), got, 1 );
      budget -= visit;
      want   -= n;
      taken_any |= !!n;
      for( ulong k=0UL; k<n; k++ ) {
        ulong best = ULONG_MAX;
        for( ulong j=0UL; j<joiner_cnt; j++ ) {
          if( active[ j ] && have[ j ]<FD_ACCDB_RING_N && ( best==ULONG_MAX || have[ j ]<have[ best ] ) ) best = j;
        }
        fd_accdb_cache_line_t * l = line_at( accdb, got[ k ] );
        FD_COMPILER_MFENCE();  /* the take before the line is free */
        FD_VOLATILE( l->state ) = FD_ACCDB_LINE_FREE;
        if( FD_UNLIKELY( best==ULONG_MAX ) ) continue;  /* unhinted: CLOCK takes it */
        fd_accdb_ring_t * r = &shmem->cache_ring[ best ][ c ];
        FD_COMPILER_MFENCE();  /* free before its slot */
        FD_VOLATILE( r->e[ r->p.prod%FD_ACCDB_RING_N ] ) = got[ k ];
        r->p.prod++;
        have[ best ]++;
      }
    }

    /* Answer the hungry joins that got lines.  Stay busy if the budget
       ran out, or one is still hungry. */
    if( FD_UNLIKELY( want && taken_any ) ) accdb->preevict_pending = 1;
    for( ulong j=0UL; j<joiner_cnt; j++ ) {
      fd_accdb_ring_t * r = &shmem->cache_ring[ j ][ c ];
      if( FD_LIKELY( !FD_VOLATILE_CONST( r->p.hungry ) ) ) continue;
      if( have[ j ] ) FD_VOLATILE( r->p.hungry ) = 0UL;
      else            accdb->preevict_pending = 1;
    }
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

/* ---- Snapshot staging and placement (§9, §15 R17/R21/R23) ----------- */

/* Each writer joiner stages into its own share of the window (no
   sharing), flushing whole chunks to the index file at an FAA offset.
   share = window / joiner_cnt_max, rounded to chunks. */

static inline fd_accdb_stage_rec_t *
stage_buf( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong share = fd_ulong_align_dn( FD_ACCDB_PLACE_WINDOW/shmem->joiner_cnt_max, 64UL );
  return (fd_accdb_stage_rec_t *)( (uchar *)shmem + shmem->window_off + accdb->join_idx*share );
}

static inline ulong
stage_buf_max( fd_accdb_t const * accdb ) {
  ulong share = FD_ACCDB_PLACE_WINDOW/accdb->shmem->joiner_cnt_max;
  return fd_ulong_min( FD_ACCDB_STAGE_CHUNK_REC, share/64UL );
}

static void
stage_grow( fd_accdb_t * accdb,
            ulong        end ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_LIKELY( end<=FD_VOLATILE_CONST( shmem->stage_falloc ) ) ) return;
  fd_spinlock_acquire( &shmem->grow_lock );
  if( end>shmem->stage_falloc ) {
    ulong to = fd_ulong_align_up( end, 1UL<<30 );
    if( FD_UNLIKELY( -1==fallocate( accdb->bkt->fd, 0, (long)(shmem->stage_base+shmem->stage_falloc), (long)(to-shmem->stage_falloc) ) ) )
      FD_LOG_ERR(( "fallocate() of the snapshot index stage failed (%d-%s); free disk space", errno, fd_io_strerror( errno ) ));
    FD_VOLATILE( shmem->stage_falloc ) = to;
  }
  fd_spinlock_release( &shmem->grow_lock );
}

/* fd_accdb_snapshot_stage_flush writes this joiner's staged records.
   Every snapin writer calls it before acking FINI. */

void
fd_accdb_snapshot_stage_flush( fd_accdb_t * accdb ) {
  if( FD_LIKELY( !idx_enabled( accdb ) || !accdb->stage_cnt ) ) return;
  ulong sz  = accdb->stage_cnt*sizeof(fd_accdb_stage_rec_t);
  ulong off = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->stage_head, sz );
  stage_grow( accdb, off+sz );
  fd_accdb_idx_io( accdb->bkt->fd, 1, stage_buf( accdb ), sz, accdb->shmem->stage_base+off );
  accdb->stage_cnt = 0UL;
}

static void
stage_append( fd_accdb_t *  accdb,
              uchar const * pubkey,
              ulong         off,
              ulong         lamports,
              uint          exec_size,
              ulong         slot,
              uint          flags ) {
  fd_accdb_stage_rec_t * r = &stage_buf( accdb )[ accdb->stage_cnt++ ];
  memcpy( r->pubkey, pubkey, 32UL );
  r->off_plus1 = off+1UL;
  r->lamports  = lamports;
  r->exec_size = exec_size;
  r->slot      = (uint)slot;
  r->flags     = flags;
  r->pad       = 0U;
  if( FD_UNLIKELY( accdb->stage_cnt==stage_buf_max( accdb ) ) ) fd_accdb_snapshot_stage_flush( accdb );
}

/* Placement scratch, lead only (writers are done). */

struct place_ctx {
  fd_accdb_t *                  accdb;
  fd_accdb_place_tomb_fn_t      tomb_fn;
  void *                        tomb_ctx;
  fd_accdb_snapshot_placement_t out[1];
  int                           incr;
  int                           apply;   /* incr phase B */
  ulong                         recs_end;
};

typedef struct place_ctx place_ctx_t;

static inline void
place_free_rec( place_ctx_t *                 pc,
                fd_accdb_stage_rec_t const *  r ) {
  ulong sz = sizeof(fd_accdb_disk_meta_t)+FD_ACCDB_SIZE_DATA( r->exec_size );
  fd_accdb_shmem_bytes_freed( pc->accdb->shmem, r->off_plus1-1UL, sz );
  pc->out->disk_freed += sz;
}

static inline void
place_dup( place_ctx_t * pc,
           ulong         lamports ) {
  fd_uwide_inc( &pc->out->dup_lamports_hi, &pc->out->dup_lamports, pc->out->dup_lamports_hi, pc->out->dup_lamports, lamports );
  pc->out->duplicates++;
}


/* pend_note (incr phase A): winners for the caller's watched keys are
   readable through read_one_nocache before phase B (sysvar checks). */

static void
pend_note( fd_accdb_t *                 accdb,
           fd_accdb_stage_rec_t const * w ) {
  for( ulong i=0UL; i<accdb->pend_watch_cnt; i++ ) {
    if( memcmp( accdb->pend_watch[ i ], w->pubkey, 32UL ) ) continue;
    accdb->pend[ i ] = *w;
    return;
  }
}

/* Placement marks on page slots (cleared before any page write):
   flags MINE = placed by this load, DELEG / ANY_DELEG = the winner /
   some loser was a snooped delegation, CROSS = replaced a bucket slot;
   aux = winner's snapshot slot. */
#define PLACE_MINE      (1U)
#define PLACE_DELEG     (2U)
#define PLACE_ANY_DELEG (4U)
#define PLACE_CROSS     (8U)

/* place_rec (streaming, any order): r against the window pages
   [p0,p1).  Newest slot wins, equal slots = corrupt (as upstream
   write_batch, which also compares against the current winner only).
   Returns -1 on a corrupt snapshot. */

static int
place_rec( place_ctx_t *                pc,
           ulong                        p0,
           ulong                        p1,
           fd_accdb_stage_rec_t const * r,
           fd_accdb_idx_page_t *        pages ) {
  fd_accdb_idx_region_t * bkt = pc->accdb->bkt;
  int   count = !pc->incr || !pc->apply;  /* capitalization inputs */
  int   tomb  = !pc->incr ||  pc->apply;  /* byte frees, once      */
  uchar deleg = ( r->flags & FD_ACCDB_STAGE_DELEG ) ? (uchar)PLACE_DELEG : (uchar)0;
  ulong home  = fd_accdb_idx_home( bkt, r->pubkey, 0, pc->accdb->shmem->seed );
  fd_accdb_idx_slot_t * found = NULL;
  for( ulong pg=home; pg<p1 && !found; pg++ ) {
    fd_accdb_idx_page_t * P = &pages[ pg-p0 ];
    found = fd_accdb_idx_page_find( bkt, P, r->pubkey, 0 );
    if( !found && !(P->flags & FD_ACCDB_IDX_OVERFLOWED) ) break;
  }
  if( found && ( found->flags & PLACE_MINE ) ) {
    if( FD_UNLIKELY( found->aux==r->slot ) ) return -1;
    fd_accdb_stage_rec_t loser = *r;
    if( found->aux<r->slot ) { /* r wins */
      memcpy( loser.pubkey, found->pubkey, 32UL );
      loser.off_plus1 = found->off_plus1; loser.lamports = found->lamports; loser.exec_size = found->exec_size;
      if( found->flags & PLACE_DELEG ) found->flags |= PLACE_ANY_DELEG;
      found->off_plus1 = r->off_plus1; found->lamports = r->lamports; found->exec_size = r->exec_size; found->aux = r->slot;
      found->flags = (uchar)( ( found->flags & ~PLACE_DELEG ) | deleg );
    } else if( deleg ) {
      found->flags |= PLACE_ANY_DELEG;
    }
    if( tomb  ) place_free_rec( pc, &loser );
    if( count ) place_dup( pc, loser.lamports );
    return 0;
  }
  if( found ) { /* incremental replacing a full version (REPLACED_CROSS) */
    if( count ) place_dup( pc, found->lamports );
    if( pc->apply ) {
      ulong sz = sizeof(fd_accdb_disk_meta_t)+FD_ACCDB_SIZE_DATA( found->exec_size );
      fd_accdb_shmem_bytes_freed( pc->accdb->shmem, found->off_plus1-1UL, sz );
      pc->out->disk_freed += sz;
    }
    found->off_plus1 = r->off_plus1; found->lamports = r->lamports; found->exec_size = r->exec_size; found->generation = 0U;
    found->aux = r->slot; found->flags = (uchar)( PLACE_MINE | PLACE_CROSS | deleg );
    return 0;
  }
  ulong pg = home;
  while( pages[ pg-p0 ].cnt==FD_ACCDB_IDX_SLOT_CNT ) {
    pages[ pg-p0 ].flags |= FD_ACCDB_IDX_OVERFLOWED;
    if( FD_UNLIKELY( ++pg>=p1 ) ) FD_LOG_ERR(( "snapshot placement range overflow" ));
  }
  fd_accdb_idx_page_t * P = &pages[ pg-p0 ];
  for( ulong i=0UL; i<FD_ACCDB_IDX_SLOT_CNT; i++ ) {
    fd_accdb_idx_slot_t * d = &P->slot[ i ];
    if( d->off_plus1 ) continue;
    memset( d, 0, sizeof(*d) );
    memcpy( d->pubkey, r->pubkey, 32UL );
    d->off_plus1 = r->off_plus1; d->lamports = r->lamports; d->exec_size = r->exec_size;
    d->aux = r->slot; d->flags = (uchar)( PLACE_MINE | deleg );
    P->cnt++;
    return 0;
  }
  FD_LOG_CRIT(( "page cnt out of sync" ));
}

/* place_settle: every slot this range placed gets its final effect
   (stake tombstones, zero-lamport removal, counts, filter, delta,
   pending sysvars), then marks are cleared and the range is written
   (except in the incremental check, which leaves the bucket as is). */

static void
place_settle( place_ctx_t *         pc,
              ulong                 p0,
              ulong                 p1,
              fd_accdb_idx_page_t * pages ) {
  fd_accdb_t * accdb = pc->accdb;
  int tomb = !pc->incr || pc->apply;
  for( ulong pg=p0; pg<p1; pg++ ) {
    fd_accdb_idx_page_t * P = &pages[ pg-p0 ];
    for( ulong i=0UL; i<FD_ACCDB_IDX_SLOT_CNT; i++ ) {
      fd_accdb_idx_slot_t * d = &P->slot[ i ];
      if( !d->off_plus1 || !( d->flags & PLACE_MINE ) ) continue;
      int cross = !!( d->flags & PLACE_CROSS );
      if( tomb && pc->tomb_fn && !( d->flags & PLACE_DELEG ) && ( cross || ( d->flags & PLACE_ANY_DELEG ) ) )
        pc->tomb_fn( pc->tomb_ctx, d->pubkey, d->aux, cross );
      fd_accdb_stage_rec_t w = { .off_plus1 = d->off_plus1, .lamports = d->lamports, .exec_size = d->exec_size, .slot = d->aux };
      memcpy( w.pubkey, d->pubkey, 32UL );
      if( pc->incr && !pc->apply ) pend_note( accdb, &w );
      if( pc->incr &&  pc->apply ) delta_insert( accdb, d->pubkey );
      if( !d->lamports ) {
        if( tomb ) place_free_rec( pc, &w );
        if( cross && pc->apply ) { fd_accdb_cf_delete( accdb->cf, d->pubkey ); pc->out->removed++; }
        memset( d, 0, sizeof(*d) ); P->cnt--;
        continue;
      }
      if( !cross ) {
        pc->out->loaded++;
        if( tomb ) fd_accdb_cf_insert( accdb->cf, d->pubkey, &accdb->idx_rng );
      }
      d->flags = 0; d->aux = 0U;
    }
  }
  if( tomb ) fd_accdb_idx_io( accdb->bkt->fd, 1, pages, (p1-p0)*FD_ACCDB_IDX_PAGE_SZ, (accdb->bkt->page0+p0)*FD_ACCDB_IDX_PAGE_SZ );
}

/* place_all: scatters the stage [s0,s1) by range into run files after
   the stage, then streams each range's run against its pages.  All
   scratch is the window (locked shmem): counters at its end, pages
   then a read buffer in pass 2, so a range of any density fits. */

static int
place_all( place_ctx_t * pc,
           ulong         s0,
           ulong         s1 ) {
  fd_accdb_t *       accdb = pc->accdb;
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong npage  = accdb->bkt->npage;
  ulong R      = ( npage + FD_ACCDB_PLACE_RANGE_PG-1UL )/FD_ACCDB_PLACE_RANGE_PG;
  ulong nrec   = ( s1-s0 )/sizeof(fd_accdb_stage_rec_t);
  uchar * win  = (uchar *)shmem + shmem->window_off;
  ulong meta_sz = fd_ulong_align_up( 3UL*R*sizeof(ulong), FD_ACCDB_IDX_PAGE_SZ );
  FD_TEST( R<=FD_ACCDB_PLACE_RANGE_MAX );
  ulong * cnt  = (ulong *)( win+FD_ACCDB_PLACE_WINDOW-meta_sz );
  ulong * pos  = cnt+R;
  ulong * fill = pos+R;

  /* pass 1: counts per range, then a prefix layout of the run area */
  memset( cnt, 0, 3UL*R*sizeof(ulong) );
  ulong rd_max = FD_ACCDB_PLACE_WINDOW/2UL/sizeof(fd_accdb_stage_rec_t);
  fd_accdb_stage_rec_t * rd = (fd_accdb_stage_rec_t *)win;
  for( ulong i=0UL; i<nrec; i+=rd_max ) {
    ulong n = fd_ulong_min( rd_max, nrec-i );
    fd_accdb_idx_io( accdb->bkt->fd, 0, rd, n*sizeof(*rd), shmem->stage_base+s0+i*sizeof(*rd) );
    for( ulong k=0UL; k<n; k++ ) if( rd[ k ].off_plus1 ) cnt[ fd_accdb_idx_home( accdb->bkt, rd[ k ].pubkey, 0, shmem->seed )/FD_ACCDB_PLACE_RANGE_PG ]++;
  }
  ulong runs = fd_ulong_align_up( s1, 64UL ), acc = 0UL;
  for( ulong r=0UL; r<R; r++ ) { pos[ r ] = acc; acc += cnt[ r ]; }
  stage_grow( accdb, runs+acc*sizeof(fd_accdb_stage_rec_t) );
  /* scatter with per-range write buffers of B records */
  ulong B = fd_ulong_max( 1UL, ( ( FD_ACCDB_PLACE_WINDOW/2UL-meta_sz )/sizeof(fd_accdb_stage_rec_t) )/R );
  B = fd_ulong_min( B, 4096UL );
  fd_accdb_stage_rec_t * wb = (fd_accdb_stage_rec_t *)( win+FD_ACCDB_PLACE_WINDOW/2UL );
  for( ulong i=0UL; i<nrec; i+=rd_max ) {
    ulong n = fd_ulong_min( rd_max, nrec-i );
    fd_accdb_idx_io( accdb->bkt->fd, 0, rd, n*sizeof(*rd), shmem->stage_base+s0+i*sizeof(*rd) );
    for( ulong k=0UL; k<n; k++ ) {
      if( !rd[ k ].off_plus1 ) continue;
      ulong r = fd_accdb_idx_home( accdb->bkt, rd[ k ].pubkey, 0, shmem->seed )/FD_ACCDB_PLACE_RANGE_PG;
      wb[ r*B+fill[ r ] ] = rd[ k ];
      if( ++fill[ r ]==B ) {
        fd_accdb_idx_io( accdb->bkt->fd, 1, &wb[ r*B ], B*sizeof(*wb), shmem->stage_base+runs+pos[ r ]*sizeof(*wb) );
        pos[ r ] += B; fill[ r ] = 0UL;
      }
    }
  }
  for( ulong r=0UL; r<R; r++ ) if( fill[ r ] ) {
    fd_accdb_idx_io( accdb->bkt->fd, 1, &wb[ r*B ], fill[ r ]*sizeof(*wb), shmem->stage_base+runs+pos[ r ]*sizeof(*wb) );
    pos[ r ] += fill[ r ];
  }
  /* pass 2: ranges in order; a range's trailing PROBE_MAX pages
     overlap the next range, which picks them up from disk. */
  fd_accdb_idx_page_t *  pages = (fd_accdb_idx_page_t *)win;
  fd_accdb_stage_rec_t * buf   = (fd_accdb_stage_rec_t *)( win+FD_ACCDB_PLACE_PG_MAX*FD_ACCDB_IDX_PAGE_SZ );
  ulong                  buf_n = ( FD_ACCDB_PLACE_WINDOW-meta_sz-FD_ACCDB_PLACE_PG_MAX*FD_ACCDB_IDX_PAGE_SZ )/sizeof(fd_accdb_stage_rec_t);
  ulong base = 0UL;
  for( ulong r=0UL; r<R; r++ ) {
    ulong p0 = r*FD_ACCDB_PLACE_RANGE_PG;
    ulong p1 = fd_ulong_min( npage, p0+FD_ACCDB_PLACE_PG_MAX );
    ulong pg_bytes = (p1-p0)*FD_ACCDB_IDX_PAGE_SZ;
    if( !cnt[ r ] && pc->incr ) continue;
    if( pc->incr ) {
      fd_accdb_idx_io( accdb->bkt->fd, 0, pages, pg_bytes, (accdb->bkt->page0+p0)*FD_ACCDB_IDX_PAGE_SZ );
    } else {
      ulong carry = r ? fd_ulong_min( FD_ACCDB_IDX_PROBE_MAX, p1-p0 ) : 0UL;
      if( carry ) fd_accdb_idx_io( accdb->bkt->fd, 0, pages, carry*FD_ACCDB_IDX_PAGE_SZ, (accdb->bkt->page0+p0)*FD_ACCDB_IDX_PAGE_SZ );
      memset( pages+carry, 0, pg_bytes-carry*FD_ACCDB_IDX_PAGE_SZ );
    }
    for( ulong i=0UL; i<cnt[ r ]; i+=buf_n ) {
      ulong n = fd_ulong_min( buf_n, cnt[ r ]-i );
      fd_accdb_idx_io( accdb->bkt->fd, 0, buf, n*sizeof(*buf), shmem->stage_base+runs+(base+i)*sizeof(*buf) );
      for( ulong k=0UL; k<n; k++ ) if( FD_UNLIKELY( place_rec( pc, p0, p1, &buf[ k ], pages ) ) ) return -1;
    }
    place_settle( pc, p0, p1, pages );
    base += cnt[ r ];
  }
  return 0;
}

int
fd_accdb_snapshot_place( fd_accdb_t *                    accdb,
                         int                             phase,
                         fd_accdb_place_tomb_fn_t        tomb_fn,
                         void *                          tomb_ctx,
                         fd_accdb_snapshot_placement_t * out ) {
  memset( out, 0, sizeof(*out) );
  if( FD_LIKELY( !idx_enabled( accdb ) ) ) return 0;
  fd_accdb_shmem_t * shmem = accdb->shmem;
  place_ctx_t pc[1] = {{ .accdb = accdb, .tomb_fn = tomb_fn, .tomb_ctx = tomb_ctx }};
  ulong s0 = phase==FD_ACCDB_PLACE_FULL ? 0UL : shmem->stage_full_end;
  ulong s1 = FD_VOLATILE_CONST( shmem->stage_head );
  pc->incr  = phase!=FD_ACCDB_PLACE_FULL;
  pc->apply = phase==FD_ACCDB_PLACE_INCR_APPLY;
  if( phase==FD_ACCDB_PLACE_INCR_CHECK ) memset( accdb->pend, 0, sizeof(accdb->pend) );
  int err = place_all( pc, s0, s1 );
  *out = *pc->out;
  if( err ) return -1;
  if( phase==FD_ACCDB_PLACE_FULL ) {
    shmem->shmetrics->accounts_total = out->loaded;
    shmem->stage_full_end = s1;
  } else if( phase==FD_ACCDB_PLACE_INCR_APPLY ) {
    shmem->shmetrics->accounts_total += out->loaded;
    shmem->shmetrics->accounts_total -= out->removed;
  }
  if( phase!=FD_ACCDB_PLACE_INCR_CHECK ) {
    /* stage consumed: punch it */
    if( shmem->stage_falloc ) fallocate( accdb->bkt->fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, (long)shmem->stage_base, (long)shmem->stage_falloc );
    shmem->stage_falloc = 0UL; /* punched: the next stage fallocates again */
    FD_VOLATILE( shmem->stage_head ) = 0UL;
    shmem->stage_full_end = 0UL;
    memset( accdb->pend, 0, sizeof(accdb->pend) );
  }
  FD_ATOMIC_FETCH_AND_SUB( &shmem->shmetrics->disk_used_bytes, out->disk_freed );
  return 0;
}

void
fd_accdb_snapshot_stage_drop( fd_accdb_t * accdb ) {
  accdb->stage_cnt = 0UL;
}

void
fd_accdb_snapshot_stage_discard( fd_accdb_t * accdb ) {
  if( FD_LIKELY( !idx_enabled( accdb ) ) ) return;
  fd_accdb_shmem_t * shmem = accdb->shmem;
  accdb->stage_cnt = 0UL;
  FD_VOLATILE( shmem->stage_head ) = shmem->stage_full_end;
  memset( accdb->pend, 0, sizeof(accdb->pend) );
}

void
fd_accdb_snapshot_pending_watch( fd_accdb_t *          accdb,
                                 ulong                 cnt,
                                 uchar const * const * pubkeys ) {
  FD_TEST( cnt<=FD_ACCDB_PEND_MAX );
  accdb->pend_watch_cnt = cnt;
  for( ulong i=0UL; i<cnt; i++ ) memcpy( accdb->pend_watch[ i ], pubkeys[ i ], 32UL );
  memset( accdb->pend, 0, sizeof(accdb->pend) );
}

int
fd_accdb_index_mode( fd_accdb_t const * accdb ) {
  return idx_enabled( accdb );
}

int
fd_accdb_snapshot_write_batch( fd_accdb_t *        accdb,
                               fd_accdb_fork_id_t  fork_id,
                               ulong               cnt,
                               uchar const * const pubkeys[],
                               ulong  const        slots[],
                               ulong  const        lamports[],
                               ulong  const        data_lens[],
                               int    const        executables[],
                               ulong  const        file_offsets[],
                               ulong *             accounts_ignored,
                               ulong *             accounts_replaced,
                               ulong *             accounts_loaded,
                               ulong *             out_replaced_lamports,
                               ulong *             out_ignored_lamports,
                               uchar *             results,
                               uint const *        stage_flags ) {
#define CHAIN_LOCKED (UINT_MAX-1U)

  FD_TEST( cnt>0UL && cnt<=8UL );

  int incremental = fork_id.val!=USHORT_MAX;

  fd_accdb_fork_t * fork     = NULL;
  uint              fork_gen = 0U;
  if( FD_UNLIKELY( incremental ) ) {
    fork     = &accdb->fork_pool[ fork_id.val ];
    fork_gen = fork->shmem->generation;
  }

  ulong seed      = accdb->shmem->seed;
  ulong chain_msk = accdb->shmem->chain_cnt - 1UL;
  if( FD_UNLIKELY( !incremental && accdb->shmem->root_fork_id.val==USHORT_MAX ) ) {
    FD_LOG_ERR(( "snapshot_write_batch called without a root fork attached" ));
  }
  uint  gen       = incremental ? 0U : accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;

  ulong ignored           = 0UL;
  ulong replaced          = 0UL;
  ulong loaded            = 0UL;
  ulong cross_replaced    = 0UL; /* cross-fork overrides (subset of replaced) */
  ulong replaced_lamports = 0UL;
  ulong ignored_lamports  = 0UL;
  int   result            = 0;

  /* Snapshot slots are stored in the 32-bit cache_idx scratch field
     during loading.  Reject anything that would truncate. */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( slots[ i ]>UINT_MAX ) ) FD_LOG_ERR(( "snapshot slot %lu exceeds 2^32-1, accdb format must be widened", slots[ i ] ));
  }

  /* Phase 1: compute hashes and prefetch chain heads. */

  ulong hashes[ 8 ];
  for( ulong i=0UL; i<cnt; i++ ) {
    hashes[ i ] = fd_hash32( pubkeys[ i ], seed ) & chain_msk;
    __builtin_prefetch( &accdb->acc_map[ hashes[ i ] ], 1, 1 );
  }

  /* Phase 1b: reject same-slot duplicate pubkeys. */

  for( ulong i=1UL; i<cnt; i++ ) {
    for( ulong j=0UL; j<i; j++ ) {
      if( FD_UNLIKELY( hashes[ j ]==hashes[ i ] && slots[ j ]==slots[ i ] &&
                       !memcmp( pubkeys[ j ], pubkeys[ i ], 32UL ) ) ) {
        FD_LOG_WARNING(( "corrupt snapshot: duplicate pubkey within a single batch (entries %lu and %lu, slots %lu and %lu)", j, i, slots[ j ], slots[ i ] ));
        return -1;
      }
    }
  }

  /* Index mode: stage, never touch acc_map or the pool (§9.1). */
  if( FD_UNLIKELY( idx_enabled( accdb ) ) ) {
    for( ulong i=0UL; i<cnt; i++ ) {
      stage_append( accdb, pubkeys[ i ], file_offsets[ i ], lamports[ i ],
                    FD_ACCDB_SIZE_PACK( (uint)data_lens[ i ], executables[ i ] ), slots[ i ],
                    stage_flags ? stage_flags[ i ] : 0U );
      results[ i ] = FD_ACCDB_SNAPSHOT_WRITE_LOADED;
      accdb->write_stats.disk_used_added += sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];
    }
    *accounts_ignored      = 0UL;
    *accounts_replaced     = 0UL;
    *accounts_loaded       = 0UL;
    *out_replaced_lamports = 0UL;
    *out_ignored_lamports  = 0UL;
    return 0;
  }

  fd_accdb_accmeta_t * acquired[ 8 ];
  if( FD_UNLIKELY( !acc_pool_acquire_batch( accdb->acc_pool_join, cnt, acquired ) ) ) {
    FD_LOG_ERR(( "accounts database ran out of space during snapshot loading, increase [accounts.max_accounts], current value is %lu", acc_pool_ele_max( accdb->acc_pool_join ) ));
  }
  if( FD_UNLIKELY( idx_enabled( accdb ) ) ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->pool_avail, cnt );

  /* Phase 2: walk and commit under the account chain lock. */

  ulong used_bytes_added   = 0UL;
  ulong used_bytes_removed = 0UL;
  ulong acquired_used      = 0UL;

  for( ulong i=0UL; i<cnt; i++ ) {
    ulong entry_sz = sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];
    int   skip     = 0;

    uint chain_head;
    for(;;) {
      chain_head = FD_VOLATILE_CONST( accdb->acc_map[ hashes[ i ] ] );
      if( FD_UNLIKELY( chain_head==CHAIN_LOCKED ) ) {
        FD_SPIN_PAUSE();
        continue;
      }
      if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->acc_map[ hashes[ i ] ], chain_head, CHAIN_LOCKED )==chain_head ) ) {
        break;
      }
      FD_SPIN_PAUSE();
    }

    fd_accdb_accmeta_t * existing       = NULL;
    fd_accdb_accmeta_t * cross_existing = NULL; /* cross-fork dup (incremental only) */
    uint next_acc = chain_head;
    while( next_acc!=UINT_MAX ) {
      fd_accdb_accmeta_t * candidate = &accdb->acc_pool[ next_acc ];
      uint                 cand_next = FD_VOLATILE_CONST( candidate->map.next );

      if( FD_LIKELY( cand_next!=UINT_MAX ) ) {
        __builtin_prefetch( &accdb->acc_pool[ cand_next ], 0, 1 );
      }

      if( FD_UNLIKELY( !memcmp( pubkeys[ i ], candidate->key.pubkey, 32UL ) ) ) {
        if( FD_LIKELY( (ulong)candidate->cache_idx>slots[ i ] ) ) {
          skip = 1;
        } else if( FD_UNLIKELY( (ulong)candidate->cache_idx==slots[ i ] ) ) {
          FD_LOG_WARNING(( "corrupt snapshot: duplicate account at slot %lu", slots[ i ] ));
          FD_COMPILER_MFENCE();
          FD_VOLATILE( accdb->acc_map[ hashes[ i ] ] ) = chain_head;
          result = -1;
          goto fini;
        } else if( FD_UNLIKELY( incremental ) && candidate->key.generation!=fork_gen ) {
          cross_existing = candidate;
        } else {
          existing = candidate;
        }
        break;
      }
      if( FD_UNLIKELY( fd_accdb_acc_unlinked( candidate ) ) ) { next_acc = chain_head; continue; }
      next_acc = cand_next;
    }

    if( FD_UNLIKELY( skip ) ) {
      results[ i ] = FD_ACCDB_SNAPSHOT_WRITE_IGNORED;
      FD_COMPILER_MFENCE();
      FD_VOLATILE( accdb->acc_map[ hashes[ i ] ] ) = chain_head;
      fd_accdb_shmem_bytes_freed( accdb->shmem, file_offsets[ i ], entry_sz );
      ignored_lamports  += lamports[ i ];
      ignored++;
      continue;
    }

    fd_accdb_accmeta_t * accmeta;
    uint new_head = chain_head;

    fd_accdb_accmeta_t const * prev = existing ? existing : cross_existing;
    if( !prev || !prev->lamports ) results[ i ] = FD_ACCDB_SNAPSHOT_WRITE_LOADED;
    else if( cross_existing )      results[ i ] = FD_ACCDB_SNAPSHOT_WRITE_REPLACED_CROSS;
    else                           results[ i ] = FD_ACCDB_SNAPSHOT_WRITE_REPLACED;

    if( FD_UNLIKELY( existing ) ) {
      accmeta = existing;
      ulong old_sz = sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( accmeta->executable_size );
      fd_accdb_shmem_bytes_freed( accdb->shmem, fd_accdb_acc_offset( accmeta ), old_sz );
      used_bytes_removed += old_sz;
      replaced_lamports += accmeta->lamports;
      replaced++;
    } else {
      accmeta = acquired[ acquired_used++ ];

      uint acc_idx = (uint)acc_pool_idx( accdb->acc_pool_join, accmeta );

      fd_memcpy( accmeta->key.pubkey, pubkeys[ i ], 32UL );
      accmeta->key.generation = incremental ? fork_gen : gen;
      accmeta->map.next = chain_head;
      new_head = acc_idx;

      if( FD_UNLIKELY( incremental ) ) {
        fd_accdb_txn_t * txn = txn_pool_acquire( accdb->txn_pool );
        if( FD_UNLIKELY( !txn ) ) FD_LOG_ERR(( "txn pool exhausted during incremental snapshot loading" ));
        txn->acc_pool_idx = acc_idx;
        uint txn_idx      = (uint)txn_pool_idx( accdb->txn_pool, txn );
        for(;;) {
          uint old_head  = FD_VOLATILE_CONST( fork->shmem->txn_head );
          txn->fork.next = old_head;
          if( FD_LIKELY( FD_ATOMIC_CAS( &fork->shmem->txn_head, old_head, txn_idx )==old_head ) ) break;
          FD_SPIN_PAUSE();
        }
      }

      if( FD_UNLIKELY( cross_existing ) ) {
        replaced_lamports += cross_existing->lamports;
        replaced++;
        cross_replaced++;
      } else {
        loaded++;
      }
    }

    accmeta->cache_idx       = (uint)slots[ i ];
    accmeta->lamports        = lamports[ i ];
    accmeta->executable_size = FD_ACCDB_SIZE_PACK( (uint)data_lens[ i ], executables[ i ] );
    ulong file_off           = file_offsets[ i ];
    accmeta->offset_fork     = incremental ? fd_accdb_acc_pack_offset_fork( file_off, fork_id.val ) : file_off;

    FD_COMPILER_MFENCE();
    FD_VOLATILE( accdb->acc_map[ hashes[ i ] ] ) = new_head;

    used_bytes_added += entry_sz;
  }

fini:
  for( ulong i=acquired_used; i<cnt; i++ ) {
    acc_pool_release( accdb->acc_pool_join, acquired[ i ] );
  }
  if( FD_UNLIKELY( idx_enabled( accdb ) ) ) FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->pool_avail, cnt-acquired_used );

  accdb->write_stats.disk_used_added      += used_bytes_added;
  accdb->write_stats.disk_used_removed    += used_bytes_removed;
  accdb->write_stats.accounts_total_added += loaded + cross_replaced;

  *accounts_ignored      = ignored;
  *accounts_replaced     = replaced;
  *accounts_loaded       = loaded;
  *out_replaced_lamports = replaced_lamports;
  *out_ignored_lamports  = ignored_lamports;

  return result;

#undef CHAIN_LOCKED
}

static void
delta_reset( fd_accdb_t * accdb ) {
  if( !accdb->shmem->delta.head ) return; /* clean */
  uint * chains    = accdb->delta.chains;
  ulong  chain_cnt = accdb->shmem->delta.chain_cnt;
  for( ulong i=0UL; i<chain_cnt; i++ ) chains[ i ] = UINT_MAX;
  accdb->shmem->delta.head = 0UL;
}

static int
delta_is_valid( fd_accdb_shmem_t const * accdb ) {
  return accdb->delta.head < accdb->delta.ele_max;
}

/* ---- Index mode T2 tiers (§5.3, §5.4, §7.2, §15 R10) ---------------- */

static inline ulong
idx_chain_of( fd_accdb_t const * accdb,
              uchar const        pubkey[ 32 ] ) {
  return fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
}

static inline ulong
idx_pool_free( fd_accdb_t const * accdb ) {
  return FD_VOLATILE_CONST( accdb->shmem->pool_avail );
}

/* idx_pool_take (T2): one fresh slot, accounted against pool_avail.
   NULL if T2 must not dip into the release reserve. */

static fd_accdb_accmeta_t *
idx_pool_take( fd_accdb_t * accdb,
               ulong        keep ) {
  for(;;) {
    ulong avail = FD_VOLATILE_CONST( accdb->shmem->pool_avail );
    if( FD_UNLIKELY( avail<=keep ) ) return NULL;
    if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->pool_avail, avail, avail-1UL )==avail ) ) break;
  }
  fd_accdb_accmeta_t * m = acc_pool_acquire( accdb->acc_pool_join );
  FD_TEST( m );
  return m;
}

/* hot_find returns (idx, prev) of P's hot entry or UINT_MAX. */

static uint
hot_find( fd_accdb_t * accdb,
          ulong        chain,
          uchar const  pubkey[ 32 ],
          uint *       out_prev ) {
  uint prev = UINT_MAX;
  uint cur  = accdb->hot_map[ chain ];
  while( cur!=UINT_MAX ) {
    if( !memcmp( accdb->acc_pool[ cur ].key.pubkey, pubkey, 32UL ) ) { *out_prev = prev; return cur; }
    prev = cur;
    cur  = accdb->acc_pool[ cur ].map.next;
  }
  return UINT_MAX;
}

/* hot_unlink (T2): splice out, tear down its line, defer the slot.
   The node keeps map.next for lock-free walkers. */

static void
hot_unlink( fd_accdb_t * accdb,
            ulong        chain,
            uint         prev,
            uint         idx,
            int          in_cmd ) {
  fd_accdb_accmeta_t * h = &accdb->acc_pool[ idx ];
  if( prev==UINT_MAX ) FD_VOLATILE( accdb->hot_map[ chain ] )        = h->map.next;
  else                 FD_VOLATILE( accdb->acc_pool[ prev ].map.next ) = h->map.next;
  /* Its line, if any, ages out clean (its offset stays CLEAN: the
     record is the bucket's) and is an orphan once the slot recycles. */
  accdb->tier[ idx ] = FD_ACCDB_TIER_NONE;
  if( in_cmd ) deferred_acc_append( accdb, idx | FD_ACCDB_DEFER_MIGRATED ); /* cmd epoch tags it */
  else         FD_TEST( bg_defer_append( accdb, idx | FD_ACCDB_DEFER_MIGRATED ) );
}

static void
hot_purge( fd_accdb_t * accdb,
           uchar const  pubkey[ 32 ],
           int          in_cmd ) {
  ulong chain = idx_chain_of( accdb, pubkey );
  uint  prev;
  uint  idx = hot_find( accdb, chain, pubkey, &prev );
  if( idx!=UINT_MAX ) hot_unlink( accdb, chain, prev, idx, in_cmd );
}

/* hot_insert (T2): replaces P's hot entry with h (initialized). */

static void
hot_insert( fd_accdb_t * accdb,
            uint         idx ) {
  fd_accdb_accmeta_t * h = &accdb->acc_pool[ idx ];
  ulong chain = idx_chain_of( accdb, h->key.pubkey );
  hot_purge( accdb, h->key.pubkey, 0 );
  h->map.next = accdb->hot_map[ chain ];
  accdb->tier   [ idx ] = FD_ACCDB_TIER_HOT;
  accdb->hot_ref[ idx ] = 0;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( accdb->hot_map[ chain ] ) = idx;
}

/* bkt_commit (T2): rooted version -> bucket with supersede accounting,
   cuckoo insert before any RAM unlink. */

static void
bkt_commit( fd_accdb_t *               accdb,
            fd_accdb_accmeta_t const * a,
            ulong                      off ) {
  fd_accdb_idx_slot_t rec = {0}, old;
  memcpy( rec.pubkey, a->key.pubkey, 32UL );
  rec.off_plus1  = off+1UL;
  rec.lamports   = a->lamports;
  rec.exec_size  = a->executable_size & (FD_ACCDB_SIZE_EXEC_BIT|FD_ACCDB_SIZE_MASK);
  rec.generation = a->key.generation;
  if( fd_accdb_idx_upsert( accdb->bkt, accdb->shmem->seed, &rec, &old ) ) {
    if( old.off_plus1!=rec.off_plus1 ) {
      ulong sz = sizeof(fd_accdb_disk_meta_t)+FD_ACCDB_SIZE_DATA( old.exec_size );
      fd_accdb_shmem_bytes_freed( accdb->shmem, old.off_plus1-1UL, sz );
      FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, sz );
      FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->accounts_total, 1UL );
    }
  } else {
    fd_accdb_cf_insert( accdb->cf, a->key.pubkey, &accdb->idx_rng );
  }
}

static void
idx_root_tomb( fd_accdb_t * accdb,
               uchar const  pubkey[ 32 ],
               uint         gen ) {
  if( fd_accdb_cf_probe( accdb->cf, pubkey ) ) {
    fd_accdb_idx_slot_t old;
    if( fd_accdb_idx_delete( accdb->bkt, accdb->shmem->seed, pubkey, 0, gen, &old ) ) {
      ulong sz = sizeof(fd_accdb_disk_meta_t)+FD_ACCDB_SIZE_DATA( old.exec_size );
      fd_accdb_shmem_bytes_freed( accdb->shmem, old.off_plus1-1UL, sz );
      FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, sz );
      FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->accounts_total, 1UL );
      fd_accdb_cf_delete( accdb->cf, pubkey );
    }
  }
  hot_purge( accdb, pubkey, 1 );
}

/* idx_writeback (T2): writes back a committed version that is still
   dirty, leaving it bound to its line.  It claims the line as an
   evictor does (SHARED -> EVICTING), so no other evictor or in-place
   commit races it (the commit / evict Dekker), writes the record and
   publishes its offset (off_publish), then gives the line back SHARED.
   Holders keep reading the line meanwhile; nothing is unbound, so no
   hazard scan is needed.  Returns 0 if it must be retried. */

static int
idx_writeback( fd_accdb_t *         accdb,
               fd_accdb_accmeta_t * a ) {
  ulong d = FD_VOLATILE_CONST( a->data );
  if( FD_UNLIKELY( !FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( d ) ) ) ) return 0;
  uint                    cidx = FD_ACCDB_DATA_CIDX( d );
  fd_accdb_cache_line_t * l    = line_at( accdb, cidx );
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &l->state, FD_ACCDB_LINE_SHARED, FD_ACCDB_LINE_EVICTING )!=FD_ACCDB_LINE_SHARED ) ) return 0;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();
  uint  a_idx = (uint)( a-accdb->acc_pool );
  uchar dirty = FD_VOLATILE_CONST( l->acc_idx )==a_idx &&
                FD_VOLATILE_CONST( a->data )==d &&
                fd_accdb_acc_offset( a )==FD_ACCDB_OFF_DIRTY( cidx );
  if( FD_LIKELY( dirty ) ) {
    fd_accdb_cache_line_t * line[ 1 ] = { l };
    line_writeback( accdb, &cidx, line, &dirty, 1UL );
  }
  line_publish( l );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  return dirty;
}

/* demote_one (T2): rooted acc_map version A (its chain predecessor
   prev) -> bucket, plus a hot copy H that takes over A's line if the
   line is free to rebind.  Returns 0 if A must be retried later. */

static int
demote_one( fd_accdb_t * accdb,
            uint         a_idx,
            ulong        chain,
            uint         prev ) {
  fd_accdb_accmeta_t * a = &accdb->acc_pool[ a_idx ];
  ulong off = fd_accdb_acc_offset( a );
  if( !FD_ACCDB_OFF_CLEAN( off ) ) {
    if( !idx_writeback( accdb, a ) ) return 0;
    off = fd_accdb_acc_offset( a );
    if( FD_UNLIKELY( !FD_ACCDB_OFF_CLEAN( off ) ) ) return 0;
  }
  if( FD_UNLIKELY( !bg_defer_room( accdb, 2UL ) ) ) return 0;
  fd_accdb_accmeta_t * h = idx_pool_take( accdb, accdb->shmem->promote_reserve );

  bkt_commit( accdb, a, off );

  if( FD_LIKELY( h ) ) {
    uint h_idx = (uint)acc_pool_idx( accdb->acc_pool_join, h );
    memcpy( h->key.pubkey, a->key.pubkey, 32UL );
    h->key.generation  = a->key.generation;
    h->lamports        = a->lamports;
    uint es_h          = FD_ACCDB_DATA_ES( FD_VOLATILE_CONST( a->data ) ) & (FD_ACCDB_SIZE_EXEC_BIT|FD_ACCDB_SIZE_MASK);
    h->offset_fork     = fd_accdb_acc_pack_offset_fork( off, FD_ACCDB_FORK_ID_ROOTED );
    h->data            = FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, es_h );

    /* Line transfer: claim A's line as an evictor would (never waits),
       bind H to it, then unbind A.  Holders that found A keep reading
       the same bytes; new ones see A unbound and load it cold.  Unheld
       readers see A's word change and retry. */
    ulong d = FD_VOLATILE_CONST( a->data );
    if( FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( d ) ) ) {
      uint                    cidx = FD_ACCDB_DATA_CIDX( d );
      fd_accdb_cache_line_t * l    = line_at( accdb, cidx );
      if( FD_ATOMIC_CAS( &l->state, FD_ACCDB_LINE_SHARED, FD_ACCDB_LINE_EVICTING )==FD_ACCDB_LINE_SHARED ) {
        if( FD_VOLATILE_CONST( l->acc_idx )==a_idx && FD_VOLATILE_CONST( a->data )==d ) {
          FD_VOLATILE( h->data ) = FD_ACCDB_DATA( cidx, es_h | FD_ACCDB_SIZE_CACHE_VALID_BIT );
          FD_COMPILER_MFENCE();
          FD_VOLATILE( l->acc_idx ) = h_idx;
          FD_COMPILER_MFENCE();
          FD_TEST( FD_ATOMIC_CAS( &a->data, d, FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, FD_ACCDB_DATA_ES( d ) & ~FD_ACCDB_SIZE_CACHE_VALID_BIT ) )==d );
        }
        line_publish( l );
      }
    }
    hot_insert( accdb, h_idx );
  } else {
    hot_purge( accdb, a->key.pubkey, 0 );
  }

  (void)prev;
  acc_chain_splice( accdb, (uint)chain, a_idx );
  /* A's offset stays CLEAN (the record is the bucket's now); a line
     still bound to it ages out clean. */
  accdb->tier[ a_idx ] = FD_ACCDB_TIER_NONE;
  FD_TEST( bg_defer_append( accdb, a_idx | FD_ACCDB_DEFER_MIGRATED ) );
  accdb->metrics->accounts_demoted++;
  return 1;
}

/* background_demote (T2): pops aged rooted versions (or any rooted
   version under pool pressure).  A version that cannot be persisted
   yet is pushed back to the FIFO tail, never dropped. */

static ulong
background_demote( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_UNLIKELY( shmem->root_fork_id.val==USHORT_MAX ) ) return 0UL; /* no root before snapshot load */
  ulong max  = shmem->acc_pool_max;
  uint  root = accdb->fork_pool[ shmem->root_fork_id.val ].shmem->generation;
  int   pressure = idx_pool_free( accdb )<2UL*shmem->promote_reserve;
  ulong done = 0UL;
  ulong n    = fd_ulong_min( FD_ACCDB_DEMOTE_BATCH, shmem->fifo_head-shmem->fifo_tail );
  for( ulong k=0UL; k<n; k++ ) {
    ulong e   = accdb->fifo[ shmem->fifo_tail % max ];
    uint  idx = (uint)(e>>32);
    uint  gen = (uint)e;
    if( !pressure && root-gen<FD_ACCDB_DEMOTE_AGE ) break;
    shmem->fifo_tail++;
    fd_accdb_accmeta_t * a = &accdb->acc_pool[ idx ];
    if( accdb->tier[ idx ]!=FD_ACCDB_TIER_ROOTED || a->key.generation!=gen ) continue; /* superseded and unlinked */

    ulong chain = idx_chain_of( accdb, a->key.pubkey );
    uint prev = UINT_MAX, cur = FD_VOLATILE_CONST( accdb->acc_map[ chain ] );
    while( cur!=UINT_MAX && cur!=idx ) { prev = cur; cur = FD_VOLATILE_CONST( accdb->acc_pool[ cur ].map.next ); }
    FD_TEST( cur==idx );
    if( FD_UNLIKELY( !demote_one( accdb, idx, chain, prev ) ) ) {
      accdb->fifo[ shmem->fifo_head % max ] = e;
      shmem->fifo_head++;
      continue;
    }
    done++;
  }
  return done;
}

/* background_hot_evict (T2): CLOCK over hot chains while the pool is
   below 2x reserve.  Lineless entries first, then unreferenced. */

static ulong
background_hot_evict( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_LIKELY( idx_pool_free( accdb )>=2UL*shmem->promote_reserve ) ) return 0UL;
  ulong evicted = 0UL;
  ulong chains  = shmem->idx_hot_chain_cnt;
  for( ulong k=0UL; k<FD_ACCDB_HOT_SWEEP && bg_defer_room( accdb, 1UL ); k++ ) {
    ulong chain = (shmem->hot_cursor++) & (chains-1UL);
    uint prev = UINT_MAX, cur = accdb->hot_map[ chain ];
    while( cur!=UINT_MAX && bg_defer_room( accdb, 1UL ) ) {
      uint next = accdb->acc_pool[ cur ].map.next;
      int lineless = !FD_ACCDB_SIZE_CACHE_VALID( FD_VOLATILE_CONST( accdb->acc_pool[ cur ].executable_size ) );
      if( accdb->hot_ref[ cur ]==FD_ACCDB_HOT_REF_PROT ) {
        prev = cur;
      } else if( lineless || !accdb->hot_ref[ cur ] ) {
        hot_unlink( accdb, chain, prev, cur, 0 );
        evicted++;
      } else {
        accdb->hot_ref[ cur ] = 0;
        prev = cur;
      }
      cur = next;
    }
  }
  return evicted;
}

/* ---- Overflow tier for unrooted versions (§8, §15 R4-R9) ------------ */

static inline ulong
olog_rec_off( fd_accdb_t const * accdb,
              uint               chunk,
              ulong              i ) {
  return accdb->shmem->idx_olog_byte0 + ( (ulong)chunk*FD_ACCDB_OLOG_CHUNK + i )*sizeof(fd_accdb_olog_rec_t);
}

static void
olog_append( fd_accdb_t *          accdb,
             fd_accdb_idx_fork_t * f,
             uchar const           pubkey[ 32 ] ) {
  ulong i = f->olog_cnt % FD_ACCDB_OLOG_CHUNK;
  if( !i ) {
    uint c = accdb->shmem->olog_free;
    FD_TEST( c!=UINT_MAX ); /* sized txn_max/chunk + one per fork */
    accdb->shmem->olog_free = olog_next( accdb )[ c ];
    olog_next( accdb )[ c ] = UINT_MAX;
    if( f->olog_tail==UINT_MAX ) f->olog_head = c;
    else                         olog_next( accdb )[ f->olog_tail ] = c;
    f->olog_tail = c;
  }
  fd_accdb_olog_rec_t rec = {0};
  memcpy( rec.pubkey, pubkey, 32UL );
  rec.ram_idx = UINT_MAX;
  fd_accdb_idx_io( accdb->bkt->fd, 1, &rec, sizeof(rec), olog_rec_off( accdb, f->olog_tail, i ) );
  f->olog_cnt++;
}

/* fd_accdb_fork_freeze / fd_accdb_fork_thaw: replay parks a fork no
   release can target (complete, or nothing in flight) and unparks it
   before the next release.  T2 claims parked forks (1->2) to spill. */

void
fd_accdb_fork_freeze( fd_accdb_t *       accdb,
                      fd_accdb_fork_id_t fork_id ) {
  if( FD_LIKELY( !idx_enabled( accdb ) ) ) return;
  FD_ATOMIC_CAS( &idx_fork( accdb, fork_id.val )->frozen, 0U, 1U );
}

void
fd_accdb_fork_thaw( fd_accdb_t *       accdb,
                    fd_accdb_fork_id_t fork_id ) {
  if( FD_LIKELY( !idx_enabled( accdb ) ) ) return;
  fd_accdb_idx_fork_t * xf = idx_fork( accdb, fork_id.val );
  uint cur = FD_VOLATILE_CONST( xf->frozen );
  if( FD_LIKELY( !cur || ( cur==1U && FD_ATOMIC_CAS( &xf->frozen, 1U, 0U )==1U ) ) ) return;
  /* claimed: T2 discards or restores the spill, then clears thaw_fork */
  FD_VOLATILE( accdb->shmem->thaw_fork ) = fork_id.val;
  if( FD_LIKELY( accdb->sleep ) ) fd_sleep_ring( accdb->sleep, accdb->sleep_tile_id );
  while( FD_VOLATILE_CONST( accdb->shmem->thaw_fork )!=USHORT_MAX ) FD_SPIN_PAUSE();
}

/* ---- T2: spill one frozen fork (sliced, §15 R9/R10/R20) ------------- */

static ushort
spill_pick( fd_accdb_t * accdb ) {
  ulong max = accdb->shmem->max_live_slots;
  ushort best = USHORT_MAX; ulong best_n = 0UL;
  for( ulong f=0UL; f<max; f++ ) {
    fd_accdb_idx_fork_t * xf = idx_fork( accdb, f );
    if( FD_VOLATILE_CONST( xf->frozen )!=1U || xf->spilled || f==accdb->shmem->root_fork_id.val ) continue;
    if( accdb->fork_pool[ f ].shmem->txn_head==UINT_MAX ) continue;
    ulong n = 0UL;
    for( uint t=accdb->fork_pool[ f ].shmem->txn_head; t!=UINT_MAX && n<=best_n; t=txn_pool_ele( accdb->txn_pool, t )->fork.next ) n++;
    if( n>best_n ) { best = (ushort)f; best_n = n; }
  }
  return best;
}

/* background_spill: persists and logs up to SPILL_SLICE versions of the
   fork being spilled; when all are persisted, publishes spilled and
   unlinks them.  Returns work done. */

static ulong
background_spill( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( shmem->spill_fork==USHORT_MAX ) {
    if( idx_pool_free( accdb )>=shmem->promote_reserve ) return 0UL;
    ushort f = spill_pick( accdb );
    if( f==USHORT_MAX ) return 0UL;
    if( FD_ATOMIC_CAS( &idx_fork( accdb, f )->frozen, 1U, 2U )!=1U ) return 1UL; /* thawed meanwhile */
    shmem->spill_fork = f;
    shmem->spill_txn  = accdb->fork_pool[ f ].shmem->txn_head;
    memset( ovl_bloom( accdb, f ), 0, shmem->idx_bloom_words*sizeof(ulong) );
  }
  ushort                f  = (ushort)shmem->spill_fork;
  fd_accdb_idx_fork_t * xf = idx_fork( accdb, f );
  fd_accdb_fork_t *     fk = &accdb->fork_pool[ f ];
  ulong work = 0UL;
  while( shmem->spill_txn!=UINT_MAX && work<FD_ACCDB_SPILL_SLICE ) {
    fd_accdb_txn_t *     t = txn_pool_ele( accdb->txn_pool, shmem->spill_txn );
    fd_accdb_accmeta_t * a = &accdb->acc_pool[ t->acc_pool_idx ];
    if( !FD_ACCDB_OFF_CLEAN( fd_accdb_acc_offset( a ) ) && a->lamports && !idx_writeback( accdb, a ) ) return work+1UL; /* retry */
    fd_accdb_idx_slot_t rec = {0}, old;
    memcpy( rec.pubkey, a->key.pubkey, 32UL );
    rec.off_plus1  = a->lamports ? fd_accdb_acc_offset( a )+1UL : 1UL;
    rec.lamports   = a->lamports;
    rec.exec_size  = a->executable_size & (FD_ACCDB_SIZE_EXEC_BIT|FD_ACCDB_SIZE_MASK);
    rec.generation = a->key.generation;
    rec.fork_id    = f;
    rec.pd_write   = (uchar)FD_ACCDB_SIZE_PD_WRITE( a->executable_size );
    FD_TEST( !fd_accdb_idx_upsert( accdb->ovl, shmem->seed, &rec, &old ) );
    olog_append( accdb, xf, a->key.pubkey );
    ovl_bloom_op( accdb, f, a->key.pubkey, 1 );
    shmem->spill_txn = t->fork.next;
    work++;
  }
  if( shmem->spill_txn!=UINT_MAX ) return work;
  if( !bg_defer_room( accdb, xf->olog_cnt ) ) return work;

  /* Publish before any unlink: a reader either still finds the RAM
     version or sees spilled and checks ovl. */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( xf->spilled ) = 1U;
  FD_ATOMIC_FETCH_AND_ADD( &shmem->ovl_fork_cnt, 1UL );
  FD_ATOMIC_FETCH_AND_ADD( &shmem->ovl_epoch, 1UL );
  FD_COMPILER_MFENCE();

  uint txn = fk->shmem->txn_head;
  fd_accdb_txn_t * th = txn==UINT_MAX ? NULL : txn_pool_ele( accdb->txn_pool, txn );
  fd_accdb_txn_t * tt = NULL;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * t = txn_pool_ele( accdb->txn_pool, txn );
    uint idx = t->acc_pool_idx;
    fd_accdb_accmeta_t * a = &accdb->acc_pool[ idx ];
    ulong chain = idx_chain_of( accdb, a->key.pubkey );
    acc_chain_splice( accdb, (uint)chain, idx );
    acc_migrated_settle( accdb, a );
    FD_TEST( bg_defer_append( accdb, idx | FD_ACCDB_DEFER_MIGRATED ) );
    tt  = t;
    txn = t->fork.next;
  }
  if( th ) txn_pool_release_chain( accdb->txn_pool, th, tt );
  fk->shmem->txn_head = UINT_MAX;
  shmem->spill_fork = USHORT_MAX;
  accdb->metrics->forks_spilled++;
  return work+1UL;
}

/* olog_walk calls fn on each logged record of fork f, then frees the
   log.  T2 only. */

typedef void (* olog_fn_t)( fd_accdb_t * accdb, ushort f, fd_accdb_olog_rec_t const * rec );

static void
olog_walk( fd_accdb_t * accdb,
           ushort       f,
           olog_fn_t    fn ) {
  fd_accdb_idx_fork_t * xf = idx_fork( accdb, f );
  fd_accdb_olog_rec_t * buf = (fd_accdb_olog_rec_t *)accdb->stage; /* T2 only */
  ulong left = xf->olog_cnt;
  uint  c    = xf->olog_head;
  while( c!=UINT_MAX ) {
    ulong n = fd_ulong_min( left, FD_ACCDB_OLOG_CHUNK );
    fd_accdb_idx_io( accdb->bkt->fd, 0, buf, n*sizeof(fd_accdb_olog_rec_t), olog_rec_off( accdb, c, 0UL ) );
    for( ulong i=0UL; i<n; i++ ) fn( accdb, f, &buf[ i ] );
    left -= n;
    uint nx = olog_next( accdb )[ c ];
    olog_next( accdb )[ c ] = accdb->shmem->olog_free;
    accdb->shmem->olog_free = c;
    c = nx;
  }
  *xf = (fd_accdb_idx_fork_t){ .olog_head = UINT_MAX, .olog_tail = UINT_MAX };
}

/* unspilled RAM copy (if any) leaves acc_map first, without freeing
   bytes (the ovl action below owns them). */

/* unspill_live: idx still holds the copy of (pubkey, f); at most one
   copy per version exists and eviction clears its tier. */

static inline int
unspill_live( fd_accdb_t const * accdb,
              uint               idx,
              ushort             f,
              uchar const        pubkey[ 32 ] ) {
  fd_accdb_accmeta_t const * a = &accdb->acc_pool[ idx ];
  return accdb->tier[ idx ]==FD_ACCDB_TIER_UNSPILL && fd_accdb_acc_fork_id( a )==f && !memcmp( a->key.pubkey, pubkey, 32UL );
}

static void
olog_drop_ram( fd_accdb_t *                accdb,
               ushort                      f,
               fd_accdb_olog_rec_t const * rec ) {
  if( rec->ram_idx==UINT_MAX || !unspill_live( accdb, rec->ram_idx, f, rec->pubkey ) ) return;
  uint idx = rec->ram_idx;
  accdb->shmem->unspill_cnt--;
  fd_accdb_accmeta_t * a = &accdb->acc_pool[ idx ];
  ulong chain = idx_chain_of( accdb, a->key.pubkey );
  acc_chain_splice( accdb, (uint)chain, idx );
  acc_migrated_settle( accdb, a );
  accdb->tier[ idx ] = FD_ACCDB_TIER_NONE;
  deferred_acc_append( accdb, idx | FD_ACCDB_DEFER_MIGRATED );
}

/* Spill aborted before publish: RAM still owns the versions, so only
   the ovl slots go. */

static void
olog_discard_one( fd_accdb_t *                accdb,
                  ushort                      f,
                  fd_accdb_olog_rec_t const * rec ) {
  fd_accdb_idx_slot_t old;
  fd_accdb_idx_delete( accdb->ovl, accdb->shmem->seed, rec->pubkey, f, UINT_MAX, &old );
}

static void
olog_purge_one( fd_accdb_t *                accdb,
                ushort                      f,
                fd_accdb_olog_rec_t const * rec ) {
  olog_drop_ram( accdb, f, rec );
  fd_accdb_idx_slot_t old;
  if( !fd_accdb_idx_delete( accdb->ovl, accdb->shmem->seed, rec->pubkey, f, UINT_MAX, &old ) ) return;
  ulong lamports = old.lamports, exec_size = old.exec_size, off = old.off_plus1-1UL;
  if( lamports ) {
    ulong sz = sizeof(fd_accdb_disk_meta_t)+FD_ACCDB_SIZE_DATA( exec_size );
    fd_accdb_shmem_bytes_freed( accdb->shmem, off, sz );
    FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, sz );
  }
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->accounts_total, 1UL );
}

/* Rooting a spilled fork: older acc_map versions of the key are now
   superseded (upstream cleanup), then the version goes straight to the
   bucket with the same hot fix-up as demotion (I8). */

/* Order keeps the version reachable at every step: older acc_map
   versions go first (readers then reach V through its RAM copy or
   ovl), the bucket and hot tiers next, the RAM copy and ovl slot
   last. */

static void
olog_root_one( fd_accdb_t *                accdb,
               ushort                      f,
               fd_accdb_olog_rec_t const * rec ) {
  fd_accdb_idx_slot_t s, old;
  delta_insert( accdb, rec->pubkey ); /* the fork's txn list went with the spill */
  if( !fd_accdb_idx_lookup( accdb->ovl, accdb->shmem->seed, rec->pubkey, f, &s ) ) { olog_drop_ram( accdb, f, rec ); return; }
  ulong chain = idx_chain_of( accdb, rec->pubkey );
  uint cur = FD_VOLATILE_CONST( accdb->acc_map[ chain ] );
  while( cur!=UINT_MAX ) {
    fd_accdb_accmeta_t * c = &accdb->acc_pool[ cur ];
    uint nx = FD_VOLATILE_CONST( c->map.next );  /* before the defer reuses it (T2 is the only unlinker) */
    if( !memcmp( c->key.pubkey, rec->pubkey, 32UL ) && c->key.generation<s.generation ) {
      acc_unlink( accdb, (uint)chain, cur );
      deferred_acc_append( accdb, cur );
      accdb->tier[ cur ] = FD_ACCDB_TIER_NONE;
    }
    cur = nx;
  }
  if( !s.lamports ) {
    idx_root_tomb( accdb, rec->pubkey, s.generation );
    FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->accounts_total, 1UL );
  } else {
    fd_accdb_accmeta_t tmp = {0};
    memcpy( tmp.key.pubkey, rec->pubkey, 32UL );
    tmp.key.generation  = s.generation;
    tmp.lamports        = s.lamports;
    tmp.executable_size = s.exec_size;
    bkt_commit( accdb, &tmp, s.off_plus1-1UL );
    hot_purge( accdb, rec->pubkey, 1 );
  }
  olog_drop_ram( accdb, f, rec );
  fd_accdb_idx_delete( accdb->ovl, accdb->shmem->seed, rec->pubkey, f, UINT_MAX, &old );
}

static void
ovl_fork_done( fd_accdb_t * accdb,
               ushort       f FD_FN_UNUSED ) {
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->ovl_fork_cnt, 1UL );
  FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->ovl_epoch, 1UL );
}

/* idx_spilled_purge / idx_spilled_root (T2, inside a request pass). */

static void
idx_spilled_purge( fd_accdb_t * accdb,
                   ushort       f ) {
  fd_accdb_idx_fork_t * xf = idx_fork( accdb, f );
  int was = (int)xf->spilled;
  if( accdb->shmem->spill_fork==f ) { accdb->shmem->spill_fork = USHORT_MAX; olog_walk( accdb, f, olog_discard_one ); return; }
  if( was ) { olog_walk( accdb, f, olog_purge_one ); ovl_fork_done( accdb, f ); }
  else *xf = (fd_accdb_idx_fork_t){ .olog_head = UINT_MAX, .olog_tail = UINT_MAX };
}

static void
idx_spilled_root( fd_accdb_t * accdb,
                  ushort       f ) {
  fd_accdb_idx_fork_t * xf = idx_fork( accdb, f );
  if( accdb->shmem->spill_fork==f ) { /* logged, not published: RAM intact */
    accdb->shmem->spill_fork = USHORT_MAX;
    olog_walk( accdb, f, olog_discard_one );
    return;
  }
  int was = (int)xf->spilled;
  if( was ) { olog_walk( accdb, f, olog_root_one ); ovl_fork_done( accdb, f ); }
  else *xf = (fd_accdb_idx_fork_t){ .olog_head = UINT_MAX, .olog_tail = UINT_MAX };
}

/* acc_map_insert_ordered (T2): publishes initialized node idx before
   the first same-key node with a lower generation (§15 R6).  T2 is the
   only interior mutator; releases only prepend. */

static void
acc_map_insert_ordered( fd_accdb_t * accdb,
                        ulong        chain,
                        uint         idx ) {
  fd_accdb_accmeta_t * a = &accdb->acc_pool[ idx ];
  uint prev = UINT_MAX, cur = FD_VOLATILE_CONST( accdb->acc_map[ chain ] );
  while( cur!=UINT_MAX ) {
    fd_accdb_accmeta_t const * c = &accdb->acc_pool[ cur ];
    if( !memcmp( c->key.pubkey, a->key.pubkey, 32UL ) && c->key.generation<a->key.generation ) break;
    prev = cur; cur = c->map.next;
  }
  if( prev==UINT_MAX ) {
    for(;;) {
      uint head = FD_VOLATILE_CONST( accdb->acc_map[ chain ] );
      if( head!=cur ) { /* a release prepended: re-find from the new head */
        prev = head;
        while( accdb->acc_pool[ prev ].map.next!=cur ) prev = accdb->acc_pool[ prev ].map.next;
        a->map.next = cur;
        FD_COMPILER_MFENCE();
        FD_VOLATILE( accdb->acc_pool[ prev ].map.next ) = idx;
        return;
      }
      a->map.next = cur;
      FD_COMPILER_MFENCE();
      if( FD_ATOMIC_CAS( &accdb->acc_map[ chain ], cur, idx )==cur ) return;
    }
  }
  a->map.next = cur;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( accdb->acc_pool[ prev ].map.next ) = idx;
}

/* unspill_evict_one (T2): drops the oldest live unspilled copy not
   protected for a residual waiter (the ovl slot still holds the
   version, so a later reader unspills again).  0 if none qualifies. */

static int
unspill_evict_one( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong * fifo = (ulong *)( (uchar *)shmem + shmem->unspill_off );
  ulong   n    = shmem->unspill_head-shmem->unspill_tail;
  for( ulong k=0UL; k<n; k++ ) {
    ulong e   = fifo[ (shmem->unspill_tail++) % FD_ACCDB_UNSPILL_MAX ];
    uint  idx = (uint)(e>>32);
    if( accdb->tier[ idx ]!=FD_ACCDB_TIER_UNSPILL || accdb->acc_pool[ idx ].key.generation!=(uint)e ) continue; /* stale */
    if( accdb->hot_ref[ idx ]==FD_ACCDB_HOT_REF_PROT ) { fifo[ (shmem->unspill_head++) % FD_ACCDB_UNSPILL_MAX ] = e; continue; }
    fd_accdb_accmeta_t * a = &accdb->acc_pool[ idx ];
    ulong chain = idx_chain_of( accdb, a->key.pubkey );
    acc_chain_splice( accdb, (uint)chain, idx );
    acc_migrated_settle( accdb, a );
    accdb->tier[ idx ] = FD_ACCDB_TIER_NONE;
    shmem->unspill_cnt--;
    FD_TEST( bg_defer_append( accdb, idx | FD_ACCDB_DEFER_MIGRATED ) );
    accdb->metrics->unspill_evicted++;
    return 1;
  }
  return 0;
}

/* idx_unspill (T2): re-materializes the version of pubkey in spilled
   fork f into acc_map, in generation order (§15 R6), and records the
   RAM copy in f's log (R8).  Returns 1 if found, 0 if absent, -1 if
   resources are short (retry). */

static int
idx_unspill( fd_accdb_t * accdb,
             ushort       f,
             uchar const  pubkey[ 32 ],
             uint *       out_idx ) {
  fd_accdb_idx_slot_t s;
  if( !fd_accdb_idx_lookup( accdb->ovl, accdb->shmem->seed, pubkey, f, &s ) ) return 0;
  ulong chain = idx_chain_of( accdb, pubkey );
  for( uint cur=FD_VOLATILE_CONST( accdb->acc_map[ chain ] ); cur!=UINT_MAX; cur=accdb->acc_pool[ cur ].map.next ) {
    fd_accdb_accmeta_t const * c = &accdb->acc_pool[ cur ];
    if( !memcmp( c->key.pubkey, pubkey, 32UL ) && c->key.generation==s.generation && fd_accdb_acc_fork_id( c )==f ) {
      if( accdb->tier[ cur ]==FD_ACCDB_TIER_UNSPILL ) *out_idx = cur;
      return 1;
    }
  }
  if( !bg_defer_room( accdb, 2UL ) ) return -1;
  if( accdb->shmem->unspill_cnt>=accdb->shmem->unspill_cap && !unspill_evict_one( accdb ) ) return -1;
  fd_accdb_accmeta_t * a = idx_pool_take( accdb, accdb->shmem->promote_reserve/2UL );
  if( FD_UNLIKELY( !a ) ) { unspill_evict_one( accdb ); return -1; } /* slot returns at the next drain */
  uint idx = (uint)acc_pool_idx( accdb->acc_pool_join, a );
  memcpy( a->key.pubkey, pubkey, 32UL );
  a->key.generation  = s.generation;
  a->lamports        = s.lamports;
  a->offset_fork     = fd_accdb_acc_pack_offset_fork( s.lamports ? s.off_plus1-1UL : FD_ACCDB_OFF_DEAD, f ); /* a tombstone has no record */
  a->data            = FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, s.exec_size | ( s.pd_write ? FD_ACCDB_SIZE_PD_WRITE_BIT : 0U ) );

  acc_map_insert_ordered( accdb, chain, idx );
  accdb->tier[ idx ] = FD_ACCDB_TIER_UNSPILL;
  accdb->hot_ref[ idx ] = 0;
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong * fifo = (ulong *)( (uchar *)shmem + shmem->unspill_off );
  if( FD_UNLIKELY( shmem->unspill_head-shmem->unspill_tail>=FD_ACCDB_UNSPILL_MAX ) ) {
    /* drop stale and duplicate entries (mark bit 7 of hot_ref, which
       FG never touches for acc_map nodes), order kept; distinct live
       copies <= cap < MAX leaves room */
    ulong w = shmem->unspill_tail;
    for( ulong r=shmem->unspill_tail; r<shmem->unspill_head; r++ ) {
      ulong e = fifo[ r % FD_ACCDB_UNSPILL_MAX ];
      uint  i = (uint)(e>>32);
      if( accdb->tier[ i ]!=FD_ACCDB_TIER_UNSPILL || accdb->acc_pool[ i ].key.generation!=(uint)e || (accdb->hot_ref[ i ] & 0x80) ) continue;
      accdb->hot_ref[ i ] |= 0x80;
      fifo[ (w++) % FD_ACCDB_UNSPILL_MAX ] = e;
    }
    for( ulong r=shmem->unspill_tail; r<w; r++ ) accdb->hot_ref[ fifo[ r % FD_ACCDB_UNSPILL_MAX ]>>32 ] &= 0x7F;
    shmem->unspill_head = w;
  }
  fifo[ (shmem->unspill_head++) % FD_ACCDB_UNSPILL_MAX ] = ((ulong)idx<<32) | s.generation;
  shmem->unspill_cnt++;

  /* record ram_idx on the log entry */
  fd_accdb_idx_fork_t * xf = idx_fork( accdb, f );
  fd_accdb_olog_rec_t * buf = (fd_accdb_olog_rec_t *)accdb->stage; /* T2 only */
  ulong left = xf->olog_cnt;
  for( uint c=xf->olog_head; c!=UINT_MAX; c=olog_next( accdb )[ c ] ) {
    ulong n = fd_ulong_min( left, FD_ACCDB_OLOG_CHUNK );
    fd_accdb_idx_io( accdb->bkt->fd, 0, buf, n*sizeof(fd_accdb_olog_rec_t), olog_rec_off( accdb, c, 0UL ) );
    for( ulong i=0UL; i<n; i++ ) {
      if( memcmp( buf[ i ].pubkey, pubkey, 32UL ) ) continue;
      buf[ i ].ram_idx = idx;
      fd_accdb_idx_io( accdb->bkt->fd, 1, &buf[ i ], sizeof(fd_accdb_olog_rec_t), olog_rec_off( accdb, c, i ) );
      accdb->metrics->unspilled++;
      *out_idx = idx;
      return 1;
    }
    left -= n;
  }
  FD_LOG_CRIT(( "ovl version without a log record" ));
}

FD_STATIC_ASSERT( FD_ACCDB_OLOG_CHUNK*sizeof(fd_accdb_olog_rec_t)<=FD_ACCDB_T2_STAGE_SZ, olog_buf );

/* idx_ovl_serve (T2): a reader on fork_id missed with a possible ovl
   version.  Unspills the newest visible spilled version if it is newer
   than the reader's acc_map match.  Returns as idx_unspill. */

static int
idx_ovl_serve( fd_accdb_t * accdb,
               ushort       fork_id,
               uchar const  pubkey[ 32 ],
               uint *       out_idx,
               uint *       out_gen ) {
  fd_accdb_fork_t const * fork = &accdb->fork_pool[ fork_id ];
  uint root_gen = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  uint floor    = 0U;
  for( uint cur=accdb->acc_map[ idx_chain_of( accdb, pubkey ) ]; cur!=UINT_MAX; cur=accdb->acc_pool[ cur ].map.next ) {
    fd_accdb_accmeta_t const * c = &accdb->acc_pool[ cur ];
    if( memcmp( c->key.pubkey, pubkey, 32UL ) ) continue;
    if( c->key.generation>root_gen && fd_accdb_acc_fork_id( c )!=fork_id && !descends_set_test( fork->descends, fd_accdb_acc_fork_id( c ) ) ) continue;
    floor = c->key.generation;
    if( accdb->tier[ cur ]==FD_ACCDB_TIER_UNSPILL ) *out_idx = cur;
    break;
  }
  fd_accdb_idx_slot_t s;
  ushort f = ovl_search( accdb, fork, fork_id, pubkey, floor, &s );
  *out_gen = f==USHORT_MAX ? floor : s.generation;
  return f==USHORT_MAX ? 0 : idx_unspill( accdb, f, pubkey, out_idx );
}

/* ---- Promote rings (§6.2, §6.3, §15 R3/R12/R14/R16) ----------------- */

/* ring_push: reserve with a CAS after the fullness check, publish seq.
   Returns the ticket, or ULONG_MAX if the ring is full and !wait. */

static ulong
ring_push( fd_accdb_t *  accdb,
           fd_accdb_promote_ring_t * ring,
           uchar const   pubkey[ 32 ],
           uint          flags,
           ushort        ovl_fork,
           ushort        slot,
           int           wait ) {
  fd_accdb_promote_req_t * ele = (fd_accdb_promote_req_t *)( (uchar *)accdb->shmem + ring->ele_off );
  ulong t;
  for(;;) {
    t = FD_VOLATILE_CONST( ring->tail );
    if( FD_UNLIKELY( t-FD_VOLATILE_CONST( ring->head )>=ring->cap ) ) {
      if( !wait ) return ULONG_MAX;
      if( FD_LIKELY( accdb->sleep ) ) fd_sleep_ring( accdb->sleep, accdb->sleep_tile_id );
      FD_SPIN_PAUSE();
      continue;
    }
    if( FD_LIKELY( FD_ATOMIC_CAS( &ring->tail, t, t+1UL )==t ) ) break;
  }
  fd_accdb_promote_req_t * r = &ele[ t & (ring->cap-1UL) ];
  memcpy( r->pubkey, pubkey, 32UL );
  r->flags    = flags;
  r->ovl_fork = ovl_fork;
  r->slot     = slot;
  r->joiner   = (uint)accdb->join_idx;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( r->seq ) = t+1UL;
  return t;
}

/* fd_accdb_prefetch: hint-lane pushes for keys that may live only in
   the bucket.  Never waits. */

void
fd_accdb_prefetch( fd_accdb_t *          accdb,
                   fd_accdb_fork_id_t    fork_id,
                   ulong                 cnt,
                   uchar const * const * pubkeys,
                   int                   warm ) {
  if( FD_LIKELY( !idx_enabled( accdb ) || accdb->readonly ) ) return;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();
  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong hash = fd_hash32( pubkeys[ i ], accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
    int    known;
    ushort ovl_f;
    idx_resolve( accdb, fork, fork_id.val, root_generation, pubkeys[ i ], hash, 0, 0, &known, &ovl_f );
    if( known || ovl_f!=USHORT_MAX ) continue;
    if( !fd_accdb_cf_probe( accdb->cf, pubkeys[ i ] ) ) continue;
    if( ring_push( accdb, accdb->shmem->ring_hint, pubkeys[ i ], warm ? FD_ACCDB_REQ_WARM_PD : 0U, USHORT_MAX, 0, 0 )==ULONG_MAX ) accdb->metrics->prefetch_dropped++;
    else                                                                                                           accdb->metrics->prefetch_pushed++;
  }
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  if( FD_LIKELY( accdb->sleep ) ) fd_sleep_ring( accdb->sleep, accdb->sleep_tile_id );
}

/* idx_residual_park (FG, outside any epoch, efficient mode): sleeps
   on this tile's sleep word so the accdb tile can run when it shares
   our CPU.  ring_serve rings our doorbell once done moves and the
   mwaitx tile turns that into a FUTEX_WAKE.  res_park and done form a
   Dekker pair (store, fence, load on both sides), so either we see
   done or T2 sees res_park and rings.  word is 0 before res_park is
   visible, so mwaitx never drops that ring as for a running tile.  The
   timeout bounds anything else (no mwaitx, a stray doorbell). */

#define FD_ACCDB_RES_PARK_NS (1000000L) /* 1 ms: lost-wake bound only */

static void
idx_residual_park( fd_accdb_t *            accdb,
                   fd_accdb_promote_ring_t const * ring,
                   ulong                   last ) {
  ulong * word = accdb->park_word;
  ulong * park = &accdb->shmem->res_park[ accdb->join_idx ];
  FD_VOLATILE( *word ) = 0UL;
  FD_VOLATILE( *park ) = accdb->park_tile_id+1UL;
  FD_HW_MFENCE();
  if( FD_LIKELY( FD_VOLATILE_CONST( ring->done )<=last ) ) {
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    long ns = ts.tv_nsec+FD_ACCDB_RES_PARK_NS;
    ts.tv_sec  += ns/1000000000L;
    ts.tv_nsec  = ns%1000000000L;
    for(;;) {
      /* val 0: the futex seccomp rule of every stem tile */
      long r = syscall( SYS_futex, (uint *)word, FUTEX_WAIT_BITSET, 0U, &ts, NULL, FUTEX_BITSET_MATCH_ANY );
      if( FD_LIKELY( !r || errno==ETIMEDOUT || errno==EAGAIN ) ) break;
      if( FD_UNLIKELY( errno!=EINTR ) ) FD_LOG_ERR(( "futex(FUTEX_WAIT_BITSET) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    accdb->metrics->residual_parks++;
  }
  FD_VOLATILE( *park ) = 0UL;
  FD_VOLATILE( *word ) = 1UL;
}

/* idx_residual_wait (FG, outside any epoch): pushes every key and
   waits once for T2 to serve the last ticket, then acks it so T2 drops
   protection of what it promoted. */

static void
idx_residual_wait( fd_accdb_t *          accdb,
                   ulong                 cnt,
                   uchar const * const * keys,
                   ushort const *        ovl_forks ) {
  FD_TEST( FD_VOLATILE_CONST( *accdb->my_epoch_slot )==ULONG_MAX );
  fd_accdb_promote_ring_t * ring = accdb->shmem->ring_res;
  ulong last  = 0UL;
  ulong epoch = FD_VOLATILE_CONST( accdb->shmem->ovl_epoch );
  for( ulong i=0UL; i<cnt; i++ ) {
    ushort f = ovl_forks ? ovl_forks[ i ] : USHORT_MAX;
    last = ring_push( accdb, ring, keys[ i ], FD_ACCDB_REQ_WARM_PD | (f!=USHORT_MAX ? FD_ACCDB_REQ_UNSPILL : 0U), f, (ushort)i, 1 );
  }
  long t0 = fd_tickcount();
  if( FD_LIKELY( accdb->sleep ) ) fd_sleep_ring( accdb->sleep, accdb->sleep_tile_id );
  long spin_end = t0+accdb->park_spin_ticks;
  while( FD_VOLATILE_CONST( ring->done )<=last ) {
    fd_racesan_hook( "accdb_residual:wait" );
    if( FD_UNLIKELY( accdb->park_word && fd_tickcount()>spin_end ) ) idx_residual_park( accdb, ring, last );
    else                                                             FD_SPIN_PAUSE();
  }
  accdb->metrics->residual_waits++;
  accdb->metrics->residual_wait_ticks += (ulong)( fd_tickcount()-t0 );
  accdb->residual_ticket = last;
  /* T2 searched every visible spilled fork and unspilled the newest
     hit, so acc_map now answers for these keys until the next spill
     or spilled-fork root/purge (R4). */
  uint const * ans = (uint const *)( (uchar const *)accdb->shmem + accdb->shmem->ovl_ans_off )+accdb->join_idx*FD_ACCDB_MAX_ACQUIRE_CNT;
  for( ulong i=0UL; ovl_forks && i<cnt; i++ ) {
    if( ovl_forks[ i ]!=USHORT_MAX ) ovl_res_insert( accdb, keys[ i ], accdb->fork_pool[ ovl_forks[ i ] ].shmem->generation, FD_VOLATILE_CONST( ans[ i ] ), epoch );
  }
}

/* T2 side ---------------------------------------------------------- */

static int
idx_warm_line( fd_accdb_t *         accdb,
               fd_accdb_accmeta_t * h,
               uchar *              owner_out,
               uchar *              head_out );

/* idx_promote (T2): makes pubkey resolvable from RAM: a hot entry
   built from its bucket slot, or a NEG entry if absent.  Returns the
   hot idx (UINT_MAX if the pool is short). */

static uint
idx_promote( fd_accdb_t * accdb,
             uchar const  pubkey[ 32 ],
             uint         flags,
             int          residual ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong chain = idx_chain_of( accdb, pubkey );
  uint  prev;
  uint  idx = hot_find( accdb, chain, pubkey, &prev );
  if( idx==UINT_MAX ) {
    /* a rooted acc_map version (visible to every fork) makes it moot */
    uint root_gen = accdb->fork_pool[ shmem->root_fork_id.val ].shmem->generation;
    uint a = FD_VOLATILE_CONST( accdb->acc_map[ chain ] );
    while( a!=UINT_MAX && ( memcmp( accdb->acc_pool[ a ].key.pubkey, pubkey, 32UL ) || accdb->acc_pool[ a ].key.generation>root_gen ) ) a = accdb->acc_pool[ a ].map.next;
    if( a!=UINT_MAX ) return UINT_MAX;
    if( !bg_defer_room( accdb, 1UL ) ) return UINT_MAX;
    fd_accdb_accmeta_t * h = idx_pool_take( accdb, residual ? shmem->promote_reserve/2UL : shmem->promote_reserve );
    if( FD_UNLIKELY( !h ) ) return UINT_MAX;
    fd_accdb_idx_slot_t slot;
    int hit = fd_accdb_cf_probe( accdb->cf, pubkey ) && fd_accdb_idx_lookup( accdb->bkt, shmem->seed, pubkey, 0, &slot );
    memcpy( h->key.pubkey, pubkey, 32UL );
    if( hit ) {
      h->key.generation  = slot.generation;
      h->lamports        = slot.lamports;
      h->data            = FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, slot.exec_size & ~FD_ACCDB_SIZE_CACHE_VALID_BIT );
      h->offset_fork     = fd_accdb_acc_pack_offset_fork( slot.off_plus1-1UL, FD_ACCDB_FORK_ID_ROOTED );
    } else {
      /* NEG: resolves as a tombstone, so every reader treats it absent */
      h->key.generation  = 0U;
      h->lamports        = 0UL;
      h->data            = FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, 0U );
      h->offset_fork     = fd_accdb_acc_pack_offset_fork( FD_ACCDB_OFF_DEAD, FD_ACCDB_FORK_ID_ROOTED );
      accdb->metrics->neg_hot++;
    }
    idx = (uint)acc_pool_idx( accdb->acc_pool_join, h );
    hot_insert( accdb, idx );
    accdb->metrics->promoted++;
  }
  fd_accdb_accmeta_t * h = &accdb->acc_pool[ idx ];
  if( h->lamports && (flags & FD_ACCDB_REQ_WARM_PD) ) {
    uchar owner[ 32 ], head[ 36 ];
    if( idx_warm_line( accdb, h, owner, head ) && !memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.uc, 32UL ) &&
        FD_ACCDB_SIZE_DATA( h->executable_size )>=36UL ) {
      /* Program state: programdata address at data[4..36) */
      if( FD_LOAD( uint, head )==2U ) idx_promote( accdb, head+4, 0U, residual );
    }
  }
  return idx;
}

/* idx_warm_line (T2): try-only cold load of h's data into a free or
   never-used line (never CLOCK, never waits on a line).  Returns 1 with
   owner and data[0,36) (zero past the data) if h is bound to a line
   afterwards.  A bound h is read without holding its line
   (fd_accdb_line_read_unheld); an unbound one is loaded into a line we
   take OWNED, bound with one CAS of h's data word (as an acquire's cold
   load does) and published SHARED.  Losing that CAS (an FG cold load
   got there first) frees the line. */

static int
idx_warm_line( fd_accdb_t *         accdb,
               fd_accdb_accmeta_t * h,
               uchar *              owner_out,
               uchar *              head_out ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  memset( head_out, 0, 36UL );
  ulong d       = FD_VOLATILE_CONST( h->data );
  uint  es      = FD_ACCDB_DATA_ES( d );
  ulong head_sz = fd_ulong_min( 36UL, FD_ACCDB_SIZE_DATA( es ) );
  int   ok      = 0;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( shmem->epoch );
  FD_HW_MFENCE();

  if( FD_ACCDB_SIZE_CACHE_VALID( es ) ) {
    uchar data[ 36 ];
    ok = fd_accdb_line_read_unheld( line_at( accdb, FD_ACCDB_DATA_CIDX( d ) ), &h->data, d, owner_out, data, head_sz );
    if( ok ) memcpy( head_out, data, head_sz );
    goto done;
  }

  ulong cls   = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( es ) );
  ulong max_c = shmem->cache_class_max[ cls ];

  /* try-only: a never-used line, else our stash or ring, never CLOCK */
  uint L = FD_ACCDB_ACC_CIDX_INVAL;
  if( FD_VOLATILE_CONST( shmem->cache_class_init[ cls ].val )<max_c ) {
    ulong idx = FD_ATOMIC_FETCH_AND_ADD( &shmem->cache_class_init[ cls ].val, 1UL );
    if( FD_LIKELY( idx<max_c ) ) { if( line_grab( cache_line( accdb, cls, idx ) ) ) L = FD_ACCDB_ACC_CIDX_PACK( (uint)cls, (uint)idx ); }
    else                         FD_ATOMIC_FETCH_AND_SUB( &shmem->cache_class_init[ cls ].val, 1UL );
  }
  while( L==FD_ACCDB_ACC_CIDX_INVAL && accdb->stash_cnt[ cls ] ) {
    uint cidx = accdb->stash[ cls ][ --accdb->stash_cnt[ cls ] ];
    if( line_grab( line_at( accdb, cidx ) ) ) L = cidx;
  }
  if( L==FD_ACCDB_ACC_CIDX_INVAL ) goto done;

  fd_accdb_cache_line_t * l   = line_at( accdb, L );
  ulong                   off = fd_accdb_acc_offset( h );
  ulong                   sz  = FD_ACCDB_SIZE_DATA( es );
  if( FD_UNLIKELY( !FD_ACCDB_OFF_CLEAN( off ) || off==FD_ACCDB_OFF_DEAD ) ) { line_free( accdb, L ); goto done; }
  fd_accdb_idx_io( accdb->fd, 0, l->owner, 32UL, off+offsetof( fd_accdb_disk_meta_t, owner ) );
  if( sz ) fd_accdb_idx_io( accdb->fd, 0, l+1UL, sz, off+sizeof(fd_accdb_disk_meta_t) );
  accdb->metrics->read_ops++;
  accdb->metrics->bytes_read += 32UL+sz;
  l->acc_idx = (uint)acc_pool_idx( accdb->acc_pool_join, h );
  line_seq_close( l );

  /* Bind: the word must still be the unbound one we loaded */
  FD_COMPILER_MFENCE();  /* the bytes before the binding */
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &h->data, d, FD_ACCDB_DATA( L, es | FD_ACCDB_SIZE_CACHE_VALID_BIT ) )!=d ) ) {
    line_free( accdb, L );
    goto done;
  }
  memcpy( owner_out, l->owner, 32UL );
  memcpy( head_out, l+1UL, head_sz );
  line_publish( l );
  /* Bound and SHARED: foreground readers can already hold the line,
     and nothing below touches it. */
  fd_racesan_hook( "accdb_warm:pre_unpin" );
  accdb->metrics->warmed++;
  ok = 1;

done:
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  return ok;
}

/* ring_serve (T2): serves up to max requests; returns count. */

static ulong
ring_serve( fd_accdb_t *      accdb,
            fd_accdb_promote_ring_t * ring,
            ulong             max,
            int               residual ) {
  fd_accdb_promote_req_t * ele = (fd_accdb_promote_req_t *)( (uchar *)accdb->shmem + ring->ele_off );
  ulong n = 0UL;
  while( n<max ) {
    ulong h = ring->head;
    fd_accdb_promote_req_t * r = &ele[ h & (ring->cap-1UL) ];
    if( FD_VOLATILE_CONST( r->seq )!=h+1UL ) break;
    FD_COMPILER_MFENCE();
    uchar key[ 32 ]; memcpy( key, r->pubkey, 32UL );
    uint   flags  = r->flags;
    uint   joiner = r->joiner;
    ushort of     = r->ovl_fork;
    ushort slot   = r->slot;
    FD_COMPILER_MFENCE();
    if( FD_UNLIKELY( flags & FD_ACCDB_REQ_UNSPILL ) ) {
      uint uidx = UINT_MAX, ugen = 0U;
      int ok = idx_ovl_serve( accdb, of, key, &uidx, &ugen );
      if( FD_UNLIKELY( ok<0 ) ) break; /* pool or defer ring short: drains free both, retry next call */
      FD_VOLATILE( ((uint *)( (uchar *)accdb->shmem + accdb->shmem->ovl_ans_off ))[ joiner*FD_ACCDB_MAX_ACQUIRE_CNT+slot ] ) = ugen;
      if( uidx!=UINT_MAX && accdb->shmem->prot_head-accdb->shmem->prot_tail<FD_ACCDB_PROT_MAX ) {
        fd_accdb_prot_t * prot = (fd_accdb_prot_t *)( (uchar *)accdb->shmem + accdb->shmem->prot_off );
        prot[ accdb->shmem->prot_head % FD_ACCDB_PROT_MAX ] = (fd_accdb_prot_t){ .idx=uidx, .joiner=joiner, .ticket=h };
        accdb->shmem->prot_head++;
        accdb->hot_ref[ uidx ] = FD_ACCDB_HOT_REF_PROT;
      }
      FD_VOLATILE( ring->head ) = h+1UL;
      FD_COMPILER_MFENCE();
      FD_VOLATILE( ring->done ) = h+1UL;
      n++;
      continue;
    }
    FD_VOLATILE( ring->head ) = h+1UL;
    uint idx = idx_promote( accdb, key, flags, residual );
    if( residual && idx!=UINT_MAX && accdb->shmem->prot_head-accdb->shmem->prot_tail<FD_ACCDB_PROT_MAX ) {
      fd_accdb_prot_t * prot = (fd_accdb_prot_t *)( (uchar *)accdb->shmem + accdb->shmem->prot_off );
      prot[ accdb->shmem->prot_head % FD_ACCDB_PROT_MAX ] = (fd_accdb_prot_t){ .idx=idx, .joiner=joiner, .ticket=h };
      accdb->shmem->prot_head++;
      accdb->hot_ref[ idx ] = FD_ACCDB_HOT_REF_PROT;
    }
    FD_COMPILER_MFENCE();
    FD_VOLATILE( ring->done ) = h+1UL;
    n++;
    if( !residual && requests_unapplied( accdb ) ) break;
  }
  if( FD_UNLIKELY( residual && n && accdb->park_sleep ) ) {
    /* Ring parked waiters (Dekker with idx_residual_park).  One not
       yet served just re-parks. */
    FD_HW_MFENCE();
    ulong cnt = fd_ulong_min( FD_VOLATILE_CONST( accdb->shmem->joiner_cnt ), FD_ACCDB_MAX_JOINERS );
    for( ulong j=0UL; j<cnt; j++ ) {
      ulong t = FD_VOLATILE_CONST( accdb->shmem->res_park[ j ] );
      if( FD_UNLIKELY( t ) ) fd_sleep_ring( accdb->park_sleep, t-1UL );
    }
  }
  return n;
}

/* prot_release (T2): unprotect entries whose waiter re-walked. */

static void
prot_release( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  fd_accdb_prot_t * prot = (fd_accdb_prot_t *)( (uchar *)shmem + shmem->prot_off );
  while( shmem->prot_tail<shmem->prot_head ) {
    fd_accdb_prot_t * p = &prot[ shmem->prot_tail % FD_ACCDB_PROT_MAX ];
    if( FD_VOLATILE_CONST( shmem->res_ack[ p->joiner ] )<=p->ticket ) break;
    uchar t = accdb->tier[ p->idx ];
    if( ( t==FD_ACCDB_TIER_HOT || t==FD_ACCDB_TIER_UNSPILL ) && accdb->hot_ref[ p->idx ]==FD_ACCDB_HOT_REF_PROT ) accdb->hot_ref[ p->idx ] = t==FD_ACCDB_TIER_HOT;
    shmem->prot_tail++;
  }
}

void
fd_accdb_park_init( fd_accdb_t * accdb,
                    fd_sleep_t * sleep,
                    ulong        tile_id ) {
  accdb->park_sleep = sleep;
  if( FD_UNLIKELY( !sleep || tile_id==ULONG_MAX ) ) return; /* T2, or no waiter role */
  FD_TEST( tile_id<FD_SLEEP_TILE_MAX );
  accdb->park_tile_id    = tile_id;
  accdb->park_word       = &sleep->tile[ tile_id ].word;
  accdb->park_spin_ticks = (long)( (double)FD_SLEEP_PARK_MIN_NS*sleep->tick_per_ns );
}

int
fd_accdb_idx_busy( fd_accdb_t const * accdb ) {
  fd_accdb_shmem_t const * shmem = accdb->shmem;
  if( FD_LIKELY( !shmem->index_ram_entries ) ) return 0;
  return FD_VOLATILE_CONST( shmem->ring_res->tail )!=FD_VOLATILE_CONST( shmem->ring_res->head ) ||
         FD_VOLATILE_CONST( shmem->ring_hint->tail )!=FD_VOLATILE_CONST( shmem->ring_hint->head ) ||
         FD_VOLATILE_CONST( shmem->pool_avail )<2UL*shmem->promote_reserve;
}

/* idx_write_tomb (T2): a tombstone that lost its line (spill) gets a
   72 B record, so an overwrite on a thawed fork never waits on an
   offset nobody will publish (acquire STEP 11). */

static void
idx_write_tomb( fd_accdb_t *         accdb,
                fd_accdb_accmeta_t * a ) {
  fd_accdb_disk_meta_t meta = {0};
  memcpy( meta.pubkey, a->key.pubkey, 32UL );
  meta.generation = a->key.generation;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();
  ulong off = allocate_next_write( accdb, sizeof(meta) );
  for( ulong put=0UL; put<sizeof(meta); ) {
    struct iovec v = { .iov_base = (uchar *)&meta+put, .iov_len = sizeof(meta)-put };
    long r = pwritev2( accdb->fd, &v, 1, (long)(off+put), 0 );
    if( FD_UNLIKELY( -1==r && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( r<=0 ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    put += (ulong)r;
  }
  accdb->metrics->write_ops++;
  accdb->metrics->bytes_written += sizeof(meta);
  FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_used_bytes, sizeof(meta) );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( a->offset_fork ) = fd_accdb_acc_pack_offset_fork( off, fd_accdb_acc_fork_id( a ) );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

/* background_thaw (T2): replay unparks a fork T2 claimed.  A spill in
   progress is discarded.  A spilled fork's versions return to acc_map
   with txn records (reusing live unspilled copies), one olog chunk per
   call; a record is done once its ovl slot is gone, so a slice cut
   short by the pool resumes where it stopped.  Returns work done. */

static ulong
background_thaw( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  ulong tf = FD_VOLATILE_CONST( shmem->thaw_fork );
  if( FD_LIKELY( tf==USHORT_MAX ) ) return 0UL;
  ushort                f  = (ushort)tf;
  fd_accdb_idx_fork_t * xf = idx_fork( accdb, f );
  fd_accdb_fork_t *     fk = &accdb->fork_pool[ f ];
  ulong work = 1UL;
  if( shmem->spill_fork==f ) {
    shmem->spill_fork = USHORT_MAX;
    olog_walk( accdb, f, olog_discard_one ); /* resets frozen */
  } else if( xf->spilled ) {
    fd_accdb_olog_rec_t * buf = (fd_accdb_olog_rec_t *)accdb->stage; /* T2 only */
    if( xf->olog_head!=UINT_MAX ) {
      uint  c = xf->olog_head;
      ulong n = fd_ulong_min( xf->olog_cnt, FD_ACCDB_OLOG_CHUNK );
      fd_accdb_idx_io( accdb->bkt->fd, 0, buf, n*sizeof(fd_accdb_olog_rec_t), olog_rec_off( accdb, c, 0UL ) );
      for( ulong i=0UL; i<n; i++ ) {
        fd_accdb_olog_rec_t const * rec = &buf[ i ];
        fd_accdb_idx_slot_t s, old;
        if( !fd_accdb_idx_lookup( accdb->ovl, shmem->seed, rec->pubkey, f, &s ) ) continue; /* restored */
        uint idx;
        if( rec->ram_idx!=UINT_MAX && unspill_live( accdb, rec->ram_idx, f, rec->pubkey ) ) {
          idx = rec->ram_idx;
          shmem->unspill_cnt--;
        } else {
          fd_accdb_accmeta_t * a = idx_pool_take( accdb, 0UL );
          if( FD_UNLIKELY( !a ) ) return work; /* spill and eviction free more */
          idx = (uint)acc_pool_idx( accdb->acc_pool_join, a );
          memcpy( a->key.pubkey, rec->pubkey, 32UL );
          a->key.generation  = s.generation;
          a->lamports        = s.lamports;
          a->offset_fork     = fd_accdb_acc_pack_offset_fork( s.lamports ? s.off_plus1-1UL : FD_ACCDB_OFF_DEAD, f ); /* a tombstone has no record */
          a->data            = FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, s.exec_size | ( s.pd_write ? FD_ACCDB_SIZE_PD_WRITE_BIT : 0U ) );
          acc_map_insert_ordered( accdb, idx_chain_of( accdb, rec->pubkey ), idx );
        }
        accdb->tier   [ idx ] = FD_ACCDB_TIER_NONE;
        accdb->hot_ref[ idx ] = 0;
        fd_accdb_accmeta_t * a = &accdb->acc_pool[ idx ];
        if( !a->lamports && fd_accdb_acc_offset( a )==FD_ACCDB_OFF_DEAD ) idx_write_tomb( accdb, a );
        fd_accdb_txn_t * t = txn_pool_acquire( accdb->txn_pool );
        FD_TEST( t ); /* records <= RAM versions <= pool */
        t->acc_pool_idx = idx;
        t->fork.next    = fk->shmem->txn_head;
        FD_VOLATILE( fk->shmem->txn_head ) = (uint)txn_pool_idx( accdb->txn_pool, t );
        fd_accdb_idx_delete( accdb->ovl, shmem->seed, rec->pubkey, f, UINT_MAX, &old ); /* bytes now owned by idx */
        work++;
      }
      xf->olog_head = olog_next( accdb )[ c ];
      olog_next( accdb )[ c ] = shmem->olog_free;
      shmem->olog_free = c;
      xf->olog_cnt -= n;
      if( xf->olog_head!=UINT_MAX ) return work;
    }
    FD_COMPILER_MFENCE();
    *xf = (fd_accdb_idx_fork_t){ .olog_head = UINT_MAX, .olog_tail = UINT_MAX };
    ovl_fork_done( accdb, f );
  } else {
    FD_VOLATILE( xf->frozen ) = 0U;
  }
  accdb->metrics->forks_thawed++;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->thaw_fork ) = USHORT_MAX;
  return work;
}

/* background_idx: index-mode T2 maintenance, one bounded slice per
   call.  Bucket writes stop while a snapshot is being produced. */

static void
background_idx( fd_accdb_t * accdb,
                int *        charge_busy ) {
  int producing = fd_accdb_snapshot_sync_state( &accdb->shmem->snapshot_sync )!=FD_ACCDB_SNAPSHOT_SYNC_IDLE;
  prot_release( accdb );
  ulong work = background_thaw( accdb );
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_UNLIKELY( idx_pool_free( accdb )<2UL*shmem->promote_reserve && shmem->done.retiring ) ) {
    /* under pressure, return the last request pass's batch without
       waiting for the next pass, once no joiner can still see it */
    if( background_release( accdb ) ) work++;
  }
  work += background_hot_evict( accdb );
  work += background_spill( accdb );
  if( !producing ) work += background_demote( accdb );
  bg_defer_seal( accdb );
  work += bg_defer_drain( accdb );
  if( work ) *charge_busy = 1;
}

void
fd_accdb_background( fd_accdb_t * accdb,
                     int *        charge_busy ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  ulong * snap_sync_p = &shmem->snapshot_sync;
  ulong   snap_sync   = fd_accdb_snapshot_sync_state( snap_sync_p );

  /* The batch a pass retires is usually free to release right away
     (no reader mid-epoch).  A held batch keeps the tile busy, so it
     does not park with it.  A call that applies requests does nothing
     else, as before: single-threaded joins without a compaction buffer
     call it once after a purge. */
  int requests = background_requests( accdb );
  if( FD_UNLIKELY( !background_release( accdb ) ) ) *charge_busy = 1;
  if( FD_UNLIKELY( requests ) ) {
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( idx_enabled( accdb ) && !FD_VOLATILE_CONST( shmem->snapshot_loading ) ) ) {
    ulong n = ring_serve( accdb, shmem->ring_res, FD_ACCDB_RING_RES_CAP, 1 );
    n      += ring_serve( accdb, shmem->ring_hint, FD_ACCDB_RING_SERVE, 0 );
    if( n ) *charge_busy = 1;
  }

  if( FD_UNLIKELY( snap_sync!=FD_ACCDB_SNAPSHOT_SYNC_IDLE ) ) {
    switch( snap_sync ) {
    case FD_ACCDB_SNAPSHOT_SYNC_RUNNING:
      /* while producing a snapshot, don't do compaction work */
      background_preevict( accdb, charge_busy, 0 );
      return;
    case FD_ACCDB_SNAPSHOT_SYNC_DONE:
      fd_accdb_snapshot_sync_advance( snap_sync_p, FD_ACCDB_SNAPSHOT_SYNC_IDLE );
      break;
    case FD_ACCDB_SNAPSHOT_SYNC_START_FULL:
      FD_CHECK_CRIT( !FD_VOLATILE_CONST( shmem->snapshot_loading ),
                     "snapshot production requested during snapshot load" );
      delta_reset( accdb );
      fd_accdb_snapshot_sync_advance( snap_sync_p, FD_ACCDB_SNAPSHOT_SYNC_RUNNING );
      *charge_busy = 1;
      return;
    case FD_ACCDB_SNAPSHOT_SYNC_START_INCR:
      FD_CHECK_CRIT( !FD_VOLATILE_CONST( shmem->snapshot_loading ),
                     "snapshot production requested during snapshot load" );
      if( delta_is_valid( accdb->shmem ) ) {
        fd_accdb_snapshot_sync_advance( snap_sync_p, FD_ACCDB_SNAPSHOT_SYNC_RUNNING );
      } else {
        /* cannot produce incrementals because delta ran out of space,
           therefore don't know which accounts changed */
        fd_accdb_snapshot_sync_advance( snap_sync_p, FD_ACCDB_SNAPSHOT_SYNC_FAIL );
      }
      *charge_busy = 1;
      return;
    case FD_ACCDB_SNAPSHOT_SYNC_FAIL:
      /* wait for client to acknowledge */
      break;
    default:
      FD_LOG_CRIT(( "corrupt snapshot_sync state %lu", snap_sync ));
    }
  }

  background_preevict( accdb, charge_busy, 0 );

  if( FD_UNLIKELY( idx_enabled( accdb ) ) ) background_idx( accdb, charge_busy );

  /* Keep one partition allocated ahead so a write head rotating into a
     new partition never waits on fallocate. */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( shmem->partition_max )>=FD_VOLATILE_CONST( shmem->partition_fallocated ) &&
                   FD_VOLATILE_CONST( shmem->partition_fallocated )!=accdb->prealloc_failed_at ) ) {
    fd_spinlock_acquire( &shmem->grow_lock );
    ulong fallocated = shmem->partition_fallocated;
    int   grow       = fallocated<shmem->partition_cnt && FD_VOLATILE_CONST( shmem->partition_max )>=fallocated;
    int   err        = grow ? grow_locked( accdb, fallocated, 0, ULONG_MAX, 1 ) : 0;
    fd_spinlock_release( &shmem->grow_lock );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fallocate() failed (%d-%s) preallocating the accounts database beyond %lu GiB. "
                       "The validator will exit soon when the disk fills.",
                       err, fd_io_strerror( err ), fallocated*shmem->partition_sz/(1UL<<30UL) ));
      accdb->prealloc_failed_at = fallocated;
    } else if( FD_LIKELY( grow ) ) {
      *charge_busy = 1;
      return;
    }
  }

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    if( FD_UNLIKELY( accdb->carry_sz && k!=accdb->carry_layer ) ) continue; /* would overwrite the carried tail */
    background_compact( accdb, k, charge_busy );
  }
}

fd_accdb_shmem_metrics_t const *
fd_accdb_shmetrics( fd_accdb_t * accdb ) {
  return accdb->shmem->shmetrics;
}

fd_accdb_metrics_t const *
fd_accdb_metrics( fd_accdb_t * accdb ) {
  return accdb->metrics;
}

void
fd_accdb_cache_class_occupancy( fd_accdb_t * accdb,
                                ulong *      used,
                                ulong *      max,
                                ulong *      reserved ) {
  fd_accdb_shmem_t * shmem      = accdb->shmem;
  ulong              joiner_cnt = fd_ulong_min( FD_VOLATILE_CONST( shmem->joiner_cnt ), FD_ACCDB_MAX_JOINERS );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    /* Approximate, O(joins): lines ever taken, less the free hints in
       every join's ring and in our stash (FREE lines in other joins'
       stashes still count as used) */
    ulong cap  = shmem->cache_class_max[ c ];
    ulong live = fd_ulong_min( FD_VOLATILE_CONST( shmem->cache_class_init[ c ].val ), cap );
    live = fd_ulong_sat_sub( live, accdb->stash_cnt[ c ] );
    for( ulong j=0UL; j<joiner_cnt; j++ ) {
      fd_accdb_ring_t const * r = &shmem->cache_ring[ j ][ c ];
      live = fd_ulong_sat_sub( live, fd_ulong_min( FD_VOLATILE_CONST( r->p.prod )-FD_VOLATILE_CONST( r->c.cons ), FD_ACCDB_RING_N ) );
    }
    max [ c ] = cap;
    used[ c ] = live;
    ulong res = FD_VOLATILE_CONST( shmem->cache_class_used[ c ].val );
    if( res!=ULONG_MAX ) { /* in-flight reservations only, not idle credits */
      ulong idle = 0UL;
      for( ulong j=0UL; j<joiner_cnt; j++ ) idle += FD_VOLATILE_CONST( shmem->join_cred[ j ].val[ c ] );
      res = res>idle ? res-idle : 0UL;
    }
    reserved[ c ] = res;
  }
}

void
fd_accdb_set_preevict_interval( fd_accdb_t * accdb,
                                long         ticks ) {
  accdb->preevict_interval = ticks;
}

void
fd_accdb_cache_class_thresholds( fd_accdb_t * accdb,
                                 ulong *      free_target,
                                 ulong *      free_low_water ) {
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    free_target   [ c ] = accdb->shmem->cache_free_target   [ c ];
    free_low_water[ c ] = accdb->shmem->cache_free_low_water[ c ];
  }
}

#if FD_HAS_RACESAN

/* Force pre-eviction (ignore the rings' hunger and the budget) so a
   deterministic single-threaded test can exercise the writeback path
   without manufacturing real cache pressure.  Sweeps several times:
   CLOCK needs two visits to evict a recently-touched line (spend the
   hint, then evict). */
void
fd_accdb_debug_force_preevict( fd_accdb_t * accdb ) {
  for( ulong iter=0UL; iter<8UL; iter++ ) {
    int charge_busy = 0;
    background_preevict( accdb, &charge_busy, 1 );
  }
}

/* fd_accdb_debug_find_line finds the line the visible version of
   pubkey (the newest generation holding it) is bound to.  Returns 1
   and fills out_class/out_idx if it is cached. */

int
fd_accdb_debug_find_line( fd_accdb_t *  accdb,
                          uchar const * pubkey,
                          ulong *       out_class,
                          ulong *       out_idx ) {
  int  found    = 0;
  uint best_gen = 0U;
  ulong hash = fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  /* acc_map, then (index mode) the hot tier */
  for( int t=0; t<2; t++ ) {
    uint const * map = t ? accdb->hot_map : accdb->acc_map;
    if( !map ) break;
    for( uint a=FD_VOLATILE_CONST( map[ hash ] ); a!=UINT_MAX; a=FD_VOLATILE_CONST( accdb->acc_pool[ a ].map.next ) ) {
      fd_accdb_accmeta_t const * m = &accdb->acc_pool[ a ];
      ulong d = FD_VOLATILE_CONST( m->data );
      if( memcmp( m->key.pubkey, pubkey, 32UL ) || !FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( d ) ) ) continue;
      if( found && m->key.generation<best_gen ) continue;
      best_gen   = m->key.generation;
      *out_class = FD_ACCDB_ACC_CIDX_CLASS( FD_ACCDB_DATA_CIDX( d ) );
      *out_idx   = FD_ACCDB_ACC_CIDX_IDX  ( FD_ACCDB_DATA_CIDX( d ) );
      found      = 1;
    }
  }
  return found;
}

/* Address of one cache line.  struct fd_accdb_private is local to this
   translation unit, so a test cannot reach accdb->cache[] itself. */

void *
fd_accdb_debug_line_addr( fd_accdb_t * accdb,
                          ulong        size_class,
                          ulong        line_idx ) {
  return cache_line( accdb, size_class, line_idx );
}

fd_accdb_accmeta_t *
fd_accdb_debug_accmeta( fd_accdb_t * accdb,
                        uint         acc_idx ) {
  FD_TEST( (ulong)acc_idx<acc_pool_ele_max( accdb->acc_pool_join ) );
  return &accdb->acc_pool[ acc_idx ];
}

/* fd_accdb_debug_evict_line evicts one line now, as CLOCK does without
   the second chance: claim it, scan, write it back if dirty, unbind.
   Returns 1 if the line was evicted (it is FREE again), 0 if it was
   not SHARED or is held. */

int
fd_accdb_debug_evict_line( fd_accdb_t * accdb,
                           ulong        size_class,
                           ulong        line_idx ) {
  fd_accdb_cache_line_t * line = cache_line( accdb, size_class, line_idx );
  if( FD_VOLATILE_CONST( line->state )!=FD_ACCDB_LINE_SHARED ) return 0;
  FD_VOLATILE( line->hot ) = 0;
  ulong max_c = accdb->shmem->cache_class_max[ size_class ];
  ulong hand  = FD_VOLATILE_CONST( accdb->shmem->clock_hand[ size_class ].val );
  FD_VOLATILE( accdb->shmem->clock_hand[ size_class ].val ) = hand + ( line_idx+max_c-hand%max_c )%max_c;  /* aim the hand */
  uint got;
  if( !line_reclaim( accdb, size_class, 1UL, 1UL, &got, 0 ) ) return 0;
  line_free( accdb, got );
  return 1;
}

#endif
