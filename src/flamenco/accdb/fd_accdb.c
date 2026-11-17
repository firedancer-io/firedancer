#define _GNU_SOURCE
#include "fd_accdb.h"
#include "fd_accdb_shmem.h"
#include "fd_accdb_private.h"
#include "../../util/fd_hash32.h"

#if FD_TMPL_USE_HANDHOLDING
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/base58/fd_base58.h"
#endif
#include "../../util/racesan/fd_racesan_target.h"
#include "../../util/simd/fd_avx512.h"

#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/sleep/fd_sleep.h"
#include "../runtime/fd_runtime_const.h" /* FD_RUNTIME_ACC_SZ_MAX */

FD_STATIC_ASSERT( sizeof(fd_accdb_cache_line_t)==FD_ACCDB_CACHE_META_SZ, cache_meta_sz );

#define FD_ACCDB_BOUNCE_SZ (16UL<<20)
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

/* RECLAIM_FG_LARGE_SZ: classes with slots this large take one line at a
   time instead, so an exec tile never writes back more than one large
   line on its own path. */
#define RECLAIM_FG_LARGE_SZ (128UL<<10)

#define FD_ACCDB_ACQUIRE_STATE_IDLE    (0)
#define FD_ACCDB_ACQUIRE_STATE_PHASE_A (1)
#define FD_ACCDB_ACQUIRE_STATE_OPEN    (2)

struct __attribute__((aligned(FD_ACCDB_ALIGN))) fd_accdb_private {
  int fd;

  int acquire_state;

  fd_accdb_shmem_t * shmem;

  /* Doorbell for the parked accdb tile, NULL when nobody parks */
  fd_sleep_t * sleep;
  ulong        sleep_tile_id;

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

  /* Side buffer of acc pool indices that have been unlinked from their
     hash chains but cannot be released back to acc_pool yet, because
     concurrent readers (acquire / compact) may still be traversing the
     removed nodes via map.next.  The batch is released once all
     joiner_epochs exceed shmem->deferred_epoch.  Backed by
     shmem->deferred_acc_buf_off; cnt and epoch live in shmem too. */
  uint * deferred_acc_buf;

  fd_accdb_metrics_t metrics[1];

  ulong prealloc_failed_at;

  /* Compaction bounce buffer. */
  uchar * bounce;
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

  /* Track account addresses changed since a full snap.
     Used to determine which accounts should be packed into a full
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
  if( compaction ) l = FD_LAYOUT_APPEND( l, FD_ACCDB_ALIGN, FD_ACCDB_BOUNCE_SZ );
  return FD_LAYOUT_FINI( l, FD_ACCDB_ALIGN );
}

void *
fd_accdb_new( void *              ljoin,
              fd_accdb_shmem_t *  shmem,
              int                 fd,
              ulong               external_epoch_cnt,
              ulong const **      external_epoch_slots,
              fd_sleep_t *        sleep,
              ulong               sleep_tile_id,
              int                 compaction ) {
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
  ulong max_accounts = shmem->max_accounts;
  ulong max_account_writes_per_slot = shmem->max_account_writes_per_slot;
  ulong partition_cnt = shmem->partition_cnt;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );
  ulong txn_max = max_live_slots * max_account_writes_per_slot;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool_ele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t),        max_accounts*sizeof(fd_accdb_accmeta_t)             );
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
  uchar * _bounce         = compaction ? FD_SCRATCH_ALLOC_APPEND( l2, FD_ACCDB_ALIGN, FD_ACCDB_BOUNCE_SZ ) : NULL;

  accdb->fd = fd;
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
  accdb->sleep         = sleep;
  accdb->sleep_tile_id = sleep_tile_id;

  accdb->shmem = (fd_accdb_shmem_t *)shmem;
  FD_TEST( acc_pool_join( accdb->acc_pool_join, shmem->acc_pool, _acc_pool_ele, max_accounts ) );
  accdb->acc_pool = accdb->acc_pool_join->ele;
  accdb->acc_map = _acc_map;
  FD_TEST( txn_pool_join( accdb->txn_pool, shmem->txn_pool, _txn_pool_ele, txn_max ) );
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
  accdb->preevict_ticks    = 0L;
  accdb->preevict_interval = FD_ACCDB_BG_RATE_TICKS;
  accdb->preevict_pending  = 0;

  accdb->external_epoch_slots = external_epoch_slots;
  accdb->external_epoch_cnt   = external_epoch_cnt;

  accdb->bounce      = _bounce;
  accdb->carry_off   = 0UL;
  accdb->carry_sz    = 0UL;
  accdb->carry_layer = 0UL;

  accdb->deferred_acc_buf = (uint *)( (uchar *)shmem + shmem->deferred_acc_buf_off );

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

  /* Deferred acc buffer. */
  shmem->deferred_acc_buf_cnt = 0UL;
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
                        int                fd_ro ) {
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

  ulong max_live_slots               = shmem->max_live_slots;
  ulong max_accounts                 = shmem->max_accounts;
  ulong max_account_writes_per_slot  = shmem->max_account_writes_per_slot;
  ulong partition_cnt                = shmem->partition_cnt;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );
  ulong txn_max   = max_live_slots * max_account_writes_per_slot;

  /* Recompute the same shmem scratch layout that fd_accdb_shmem_new
     used.  All FD_SCRATCH_ALLOC_APPEND calls here only compute pointer
     offsets — they do not write to shmem. */
  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool_ele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t),    max_accounts*sizeof(fd_accdb_accmeta_t)                 );
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
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
  accdb->shmem = shmem;
  FD_TEST( acc_pool_join( accdb->acc_pool_join, shmem->acc_pool, _acc_pool_ele, max_accounts ) );
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

  accdb->deferred_acc_buf    = NULL;
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
     is set, tag the new partition as Cold up front.  We do not set
     has_partition[Cold] / whead[Cold] — those are owned by the
     compaction tile and represent the live Cold write head, which is
     independent of snapshot-loaded partitions that happen to be
     labeled Cold. */
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
    if( !pre ) {
      accdb->metrics->accounts_evicted                += dirty;
      accdb->metrics->accounts_evicted_per_class[ c ] += dirty;
    }
  }

  /* Unbind (an orphan has nothing to unbind) and take */
  for( ulong k=0UL; k<n; k++ ) {
    if( FD_UNLIKELY( !line[ k ] ) ) continue;
    fd_accdb_accmeta_t * m = &accdb->acc_pool[ line[ k ]->acc_idx ];
    ulong                d = FD_VOLATILE_CONST( m->data );
    if( FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( d ) ) && FD_ACCDB_DATA_CIDX( d )==cidx[ k ] ) {
      FD_ATOMIC_CAS( &m->data, d, FD_ACCDB_DATA( FD_ACCDB_ACC_CIDX_INVAL, FD_ACCDB_DATA_ES( d ) & ~FD_ACCDB_SIZE_CACHE_VALID_BIT ) );
    }
    line_seq_open( line[ k ] );
    FD_VOLATILE( line[ k ]->state ) = FD_ACCDB_LINE_OWNED;  /* a waiting holder reloads the word: unbound */
    out[ taken++ ] = cidx[ k ];
    if( pre ) {
      accdb->metrics->accounts_preevicted++;
      accdb->metrics->accounts_preevicted_per_class[ c ]++;
    }
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
  ulong want = fd_accdb_cache_slot_sz[ c ]<RECLAIM_FG_LARGE_SZ ? RECLAIM_FG : 1UL;
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

/* epoch_drained returns 1 if every joiner's published epoch exceeds
   tag, meaning all readers that were active at epoch=tag have since
   exited their critical sections. */

static int
epoch_drained( fd_accdb_t * accdb,
               ulong        tag ) {
  ulong joiner_cnt = FD_VOLATILE_CONST( accdb->shmem->joiner_cnt );
  for( ulong t=0UL; t<joiner_cnt; t++ ) {
    if( FD_VOLATILE_CONST( accdb->shmem->joiner_epochs[ t ].val )<=tag ) return 0;
  }
  for( ulong t=0UL; t<accdb->external_epoch_cnt; t++ ) {
    if( FD_VOLATILE_CONST( *accdb->external_epoch_slots[ t ] )<=tag ) return 0;
  }
  return 1;
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

  ulong n = shmem->deferred_acc_buf_cnt;
  if( FD_LIKELY( !n ) ) return;
  uint *               buf      = accdb->deferred_acc_buf;
  fd_accdb_accmeta_t * acc_pool = accdb->acc_pool;
  for( ulong i=0UL; i+1UL<n; i++ ) acc_pool[ buf[ i ] ].map.next = acc_pool_private_cidx( (ulong)buf[ i+1UL ] );
  acc_pool_release_chain( accdb->acc_pool_join, &acc_pool[ buf[ 0UL ] ], &acc_pool[ buf[ n-1UL ] ] );
  shmem->deferred_acc_buf_cnt = 0UL;
}

/* deferred_acc_append records an unlinked acc for release once its
   epoch drains.  T2 is the sole writer. */

static inline void
deferred_acc_append( fd_accdb_t * accdb,
                     uint         acc_idx ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  FD_TEST( shmem->deferred_acc_buf_cnt<shmem->deferred_acc_buf_max );
  accdb->deferred_acc_buf[ shmem->deferred_acc_buf_cnt++ ] = acc_idx;
}

/* acc_unlink removes a version from its chain and sets its offset DEAD.
   Its line, if any, ages out clean.  Only the accdb tile removes, and
   inserts touch only the head: CAS the head, or else store into the
   predecessor. */

static inline void
acc_unlink( fd_accdb_t * accdb,
            uint         map_idx,
            uint         acc_idx ) {
  /* Splice it out of the chain */
  fd_accdb_accmeta_t * meta = &accdb->acc_pool[ acc_idx ];
  uint                 next = FD_VOLATILE_CONST( meta->map.next );
  uint *               head = &accdb->acc_map[ map_idx ];
  if( FD_UNLIKELY( FD_VOLATILE_CONST( *head )!=acc_idx || FD_ATOMIC_CAS( head, acc_idx, next )!=acc_idx ) ) {
    uint prev = FD_VOLATILE_CONST( *head );
    for( uint cur; (cur=FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next ))!=acc_idx; ) prev = cur;
    FD_VOLATILE( accdb->acc_pool[ prev ].map.next ) = next;
  }
  fd_racesan_hook( "accdb_acc_unlink:post_splice" );

  /* Free its record */
  off_swap( accdb, meta, FD_ACCDB_OFF_DEAD, FD_ACCDB_DATA_ES( FD_VOLATILE_CONST( meta->data ) ) );
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->accounts_total, 1UL );
  accdb->metrics->accounts_deleted++;
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

static void
root_level( fd_accdb_t *       accdb,
            fd_accdb_fork_id_t fork_id ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val==accdb->shmem->root_fork_id.val );
  FD_TEST( fork->shmem->sibling_id.val==USHORT_MAX );

  fd_accdb_fork_t * parent_fork = &accdb->fork_pool[ fork->shmem->parent_id.val ];

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
          }
          acc = next;
        }

        /* If the newly rooted version is a tombstone (lamports==0, e.g.
           account was closed), drop it from the index too: no fork can
           reach it anymore, and keeping it around just wastes a hash
           slot and the disk bytes it occupies. */
        if( FD_UNLIKELY( new_acc->lamports==0UL ) ) {
          acc_unlink( accdb, acc_map_idx, txne->acc_pool_idx );
          deferred_acc_append( accdb, txne->acc_pool_idx );
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

  /* A level unlinks at most two accounts per txn (the replaced rooted
     version and a rooted tombstone).  A level that could overflow the
     deferred buffer is left for the next pass, which starts with an
     empty buffer, so passes always progress. */
  for(;;) {
    fd_accdb_fork_shmem_t const * root = accdb->fork_pool[ shmem->root_fork_id.val ].shmem;
    done.root_gen = root->generation;
    if( done.root_gen==req.root_gen ) break;
    FD_TEST( done.root_gen<req.root_gen );
    fd_accdb_fork_id_t level = root->child_id;
    if( shmem->deferred_acc_buf_cnt ) {
      ulong unlink_max = 0UL;
      for( uint txn=accdb->fork_pool[ level.val ].shmem->txn_head; txn!=UINT_MAX; txn=txn_pool_ele( accdb->txn_pool, (ulong)txn )->fork.next ) unlink_max += 2UL;
      if( FD_UNLIKELY( shmem->deferred_acc_buf_cnt+unlink_max>shmem->deferred_acc_buf_max ) ) break;
    }
    root_level( accdb, level );
  }

  /* One grace period for everything unlinked or retired in this pass. */
  if( FD_LIKELY( shmem->deferred_acc_buf_cnt || shmem->deferred_fork_head.val!=USHORT_MAX ) ) {
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
  ulong                live_packed [ IOV_MAX ];
  ulong                live_src    [ IOV_MAX ];
  ulong                live_sz     [ IOV_MAX ];
  ulong                live_dst    [ IOV_MAX ];
  struct iovec         iov         [ IOV_MAX ];

  ulong live_cnt = 0UL;
  ulong live_bytes = 0UL;
  for( ulong off=0UL; off<span; ) {
    fd_accdb_disk_meta_t const * meta = (fd_accdb_disk_meta_t const *)(accdb->bounce+off);

    fd_accdb_accmeta_t * accmeta = NULL;
    ulong source_packed = 0UL;
    uint acc_idx = FD_VOLATILE_CONST( accdb->acc_map[ fd_hash32( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ] );
    while( acc_idx!=UINT_MAX ) {
      fd_accdb_accmeta_t * candidate = &accdb->acc_pool[ acc_idx ];
      uint next_idx = FD_VOLATILE_CONST( candidate->map.next );
      ulong candidate_packed = FD_VOLATILE_CONST( candidate->offset_fork );
      if( FD_LIKELY( (candidate_packed & FD_ACCDB_OFF_MASK)==compact_base+compact->compaction_offset+off ) ) {
        accmeta       = candidate;
        source_packed = candidate_packed;
        break;
      }
      acc_idx = next_idx;
    }

    ulong record_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)meta->size;
    if( FD_UNLIKELY( !accmeta ) ) compact->compaction_dead_records++; /* index entry gone, extent is garbage */
    else {
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
      fd_memcpy( fd_accdb_dbg_reloc_pubkey, live_accmeta[ i ]->key.pubkey, 32UL );
      fd_accdb_dbg_reloc_dest = live_dst[ i ];
      fd_accdb_dbg_reloc_cnt++;
#endif
      fd_racesan_hook( "accdb_compact:pre_offset_cas" );
      if( FD_UNLIKELY( FD_ATOMIC_CAS( &live_accmeta[ i ]->offset_fork, live_packed[ i ], new_packed )!=live_packed[ i ] ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, live_dst[ i ], live_sz[ i ] );
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
    uint a = acc[ i ];
    while( a!=UINT_MAX ) {
      fd_accdb_accmeta_t const * m = &accdb->acc_pool[ a ];
      uint next = FD_VOLATILE_CONST( m->map.next );
      fd_racesan_hook( "accdb_acquire:post_next" );
      if( FD_LIKELY( !memcmp( pubkeys[ i ], m->key.pubkey, 32UL ) &&
                     ( m->key.generation<=root_generation ||
                       fd_accdb_acc_fork_id( m )==fork_id.val ||
                       descends_set_test( fork->descends, fd_accdb_acc_fork_id( m ) ) ) ) ) break;
      a = next;
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

      /* Rewrite the line in place if no evictor has it, else move */
      uint                    og = a->_cidx;
      fd_accdb_cache_line_t * L  = line_at( accdb, og );
      uint                    D;
      if( FD_ACCDB_ACC_CIDX_CLASS( og )==c && FD_VOLATILE_CONST( L->state )==FD_ACCDB_LINE_SHARED ) {
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
  uint acc_idx = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  fd_accdb_accmeta_t const * accmeta = NULL;
  while( acc_idx!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate = &accdb->acc_pool[ acc_idx ];
    uint next_idx = FD_VOLATILE_CONST( candidate->map.next );
    if( FD_LIKELY( !memcmp( pubkey, candidate->key.pubkey, 32UL ) &&
                   ( candidate->key.generation<=root_generation ||
                     fd_accdb_acc_fork_id( candidate )==fork_id.val ||
                     descends_set_test( fork->descends, fd_accdb_acc_fork_id( candidate ) ) ) ) ) {
      accmeta = candidate;
      break;
    }
    acc_idx = next_idx;
  }

  int result = FD_ACCDB_READ_ONE_NOCACHE_MISS;
  *out_lamports = 0UL;
  if( FD_UNLIKELY( !accmeta ) ) {
    accdb->metrics->accounts_acquired_per_class[ 0 ]++;
    goto done;
  }

  /* Fixed fields: stable while another fork can see the version */
  ulong lamports  = accmeta->lamports;
  uint  es        = FD_ACCDB_DATA_ES( FD_VOLATILE_CONST( accmeta->data ) );
  ulong data_len  = FD_ACCDB_SIZE_DATA( es );
  ulong read_len  = out_data ? data_len : 0UL;
  accdb->metrics->accounts_acquired_per_class[ fd_accdb_cache_class( data_len ) ]++;
  if( FD_UNLIKELY( !lamports ) ) goto done;

  /* Copy from the line without holding it, else read the disk.  A
     dirty version has no record yet, so retry until it is clean. */
  for(;;) {
    ulong d = FD_VOLATILE_CONST( accmeta->data );
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
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();

  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  uint acc = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  while( acc!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate_acc = &accdb->acc_pool[ acc ];
    uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

    if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation && fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val && !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) || memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) {
      acc = next_acc;
      continue;
    }

    break;
  }

  int result;
  if( FD_UNLIKELY( acc==UINT_MAX ) ) result = 0;
  else                               result = !!FD_VOLATILE_CONST( accdb->acc_pool[ acc ].lamports );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  return result;
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
  uint acc = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  while( acc!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate_acc = &accdb->acc_pool[ acc ];
    uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

    if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation && fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val && !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) || memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) {
      acc = next_acc;
      continue;
    }

    break;
  }

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
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();

  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  uint acc = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  while( acc!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate_acc = &accdb->acc_pool[ acc ];
    uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

    if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation && fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val && !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) || memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) {
      acc = next_acc;
      continue;
    }

    break;
  }

  ulong result;
  if( FD_UNLIKELY( acc==UINT_MAX ) ) result = 0UL;
  else                               result = FD_VOLATILE_CONST( accdb->acc_pool[ acc ].lamports );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  return result;
}

ulong
fd_accdb_data_len( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();

  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_hash32( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  uint acc = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  while( acc!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate_acc = &accdb->acc_pool[ acc ];
    uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

    if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation && fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val && !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) || memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) {
      acc = next_acc;
      continue;
    }

    break;
  }

  ulong result;
  if( FD_UNLIKELY( acc==UINT_MAX || !FD_VOLATILE_CONST( accdb->acc_pool[ acc ].lamports ) ) ) result = 0UL;
  else result = FD_ACCDB_SIZE_DATA( FD_VOLATILE_CONST( accdb->acc_pool[ acc ].executable_size ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  return result;
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
    int   taken_any = 0;
    while( want && budget && scans-- ) {
      uint  got[ RECLAIM_MAX ];
      ulong visit = fd_ulong_min( budget, 2UL*RECLAIM_MAX );
      ulong n     = line_reclaim( accdb, c, visit, fd_ulong_min( want, RECLAIM_MAX ), got, 1 );
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
                               uchar *             results ) {
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

  fd_accdb_accmeta_t * acquired[ 8 ];
  if( FD_UNLIKELY( !acc_pool_acquire_batch( accdb->acc_pool_join, cnt, acquired ) ) ) {
    FD_LOG_ERR(( "accounts database ran out of space during snapshot loading, increase [accounts.max_accounts], current value is %lu", acc_pool_ele_max( accdb->acc_pool_join ) ));
  }

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

      if( FD_LIKELY( candidate->map.next!=UINT_MAX ) ) {
        __builtin_prefetch( &accdb->acc_pool[ candidate->map.next ], 0, 1 );
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
      next_acc = candidate->map.next;
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
  for( uint a=FD_VOLATILE_CONST( accdb->acc_map[ hash ] ); a!=UINT_MAX; a=FD_VOLATILE_CONST( accdb->acc_pool[ a ].map.next ) ) {
    fd_accdb_accmeta_t const * m = &accdb->acc_pool[ a ];
    ulong d = FD_VOLATILE_CONST( m->data );
    if( memcmp( m->key.pubkey, pubkey, 32UL ) || !FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( d ) ) ) continue;
    if( found && m->key.generation<best_gen ) continue;
    best_gen   = m->key.generation;
    *out_class = FD_ACCDB_ACC_CIDX_CLASS( FD_ACCDB_DATA_CIDX( d ) );
    *out_idx   = FD_ACCDB_ACC_CIDX_IDX  ( FD_ACCDB_DATA_CIDX( d ) );
    found      = 1;
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

uint *
fd_accdb_debug_acc_pool_next( fd_accdb_t * accdb,
                              uint         acc_idx ) {
  FD_TEST( (ulong)acc_idx<acc_pool_ele_max( accdb->acc_pool_join ) );
  return &accdb->acc_pool[ acc_idx ].map.next;
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
