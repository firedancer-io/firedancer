#define _GNU_SOURCE
#include "fd_accdb.h"
#include "fd_accdb_shmem.h"
#define FD_ACCDB_NO_FORK_ID
#include "fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID

#if FD_TMPL_USE_HANDHOLDING
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/base58/fd_base58.h"
#endif
#include "../../util/racesan/fd_racesan_target.h"

#include "../../disco/events/generated/fd_event_gen.h"

FD_STATIC_ASSERT( sizeof(fd_accdb_cache_line_t)==FD_ACCDB_CACHE_META_SZ, cache_meta_sz );

#if FD_HAS_RACESAN
/* Test-only telemetry: background_compact publishes the pubkey + dest
   offset of the record it is about to relocation-CAS at the
   accdb_compact:pre_offset_cas hook, so test_accdb_racesan can PROVE the
   parked relocation is the account it set up (avoiding a vacuous test).
   Zero-cost / absent in production (racesan off). */
uchar fd_accdb_dbg_reloc_pubkey[ 32UL ];
ulong fd_accdb_dbg_reloc_dest;
ulong fd_accdb_dbg_reloc_cnt;
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

#define FD_ACCDB_ACQUIRE_STATE_IDLE    (0)
#define FD_ACCDB_ACQUIRE_STATE_PHASE_A (1)
#define FD_ACCDB_ACQUIRE_STATE_OPEN    (2)

struct __attribute__((aligned(FD_ACCDB_ALIGN))) fd_accdb_private {
  int fd;

  int acquire_state;

  fd_accdb_shmem_t * shmem;

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

  /* Side buffer of acc pool indices that have been CAS-unlinked from
     their hash chains but cannot be released back to acc_pool yet,
     because concurrent readers (acquire / compact) may still be
     traversing the removed nodes via map.next.  The batch is released
     once all joiner_epochs exceed shmem->deferred_acc_epoch.  Indices
     are written here (not into pool.next) until after the epoch drain
     because pool.next is union-aliased to cache_idx, which a concurrent
     cold_load_acc may still write through a captured pointer.  Backed
     by shmem->deferred_acc_buf_off; cnt and epoch live in shmem too. */
  uint * deferred_acc_buf;

  /* Chain of fork pool slots whose IDs are still potentially
     referenced by concurrent readers (via descends_set_test or
     root_fork_id snapshot).  The chain is released back to fork_pool
     once all joiner_epochs exceed deferred_fork_epoch.  NULL head
     means no deferred forks. */
  fd_accdb_fork_shmem_t * deferred_fork_head;
  fd_accdb_fork_shmem_t * deferred_fork_tail;
  ulong                   deferred_fork_epoch;

  fd_accdb_metrics_t metrics[1];

  /* Set by fd_accdb_snapshot_load_begin/end.  When non-zero, layer-0
     partition handoffs (in change_partition) re-tier the partitions
     that fell out of the snapshot-load working set: P-2 to Warm and
     P-3 to Cold.  This backfills tiering for snapshot-loaded data
     that never gets a second write (and therefore would otherwise
     never be promoted by compaction). */
  int snapshot_loading;
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
   allocate_next_write. */
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
  fd_accdb_partition_t * p = partition_pool_ele( accdb->partition_pool, partition_idx );
  if( FD_UNLIKELY( !p ) ) return;
  FD_ATOMIC_FETCH_AND_ADD( &p->bytes_read, bytes );
  FD_ATOMIC_FETCH_AND_ADD( &p->read_ops,   1UL   );
}

/* Bump the per-partition write counters at allocate time.  bytes is the
   reserved size, which equals the bytes that will land on this
   partition.  Called from allocate_next_write and
   allocate_next_compaction_write. */
static inline void
fd_accdb_partition_write_bump( fd_accdb_t * accdb,
                               ulong        file_offset,
                               ulong        bytes ) {
  if( FD_UNLIKELY( !bytes ) ) return;
  ulong partition_idx = file_offset / accdb->shmem->partition_sz;
  fd_accdb_partition_t * p = partition_pool_ele( accdb->partition_pool, partition_idx );
  if( FD_UNLIKELY( !p ) ) return;
  FD_ATOMIC_FETCH_AND_ADD( &p->bytes_written, bytes );
  FD_ATOMIC_FETCH_AND_ADD( &p->write_ops,     1UL   );
}

static inline ulong
cache_line_idx( fd_accdb_t *                  accdb,
                ulong                         cls,
                fd_accdb_cache_line_t const * line ) {
  return (ulong)( (uchar const *)line - accdb->cache[ cls ] ) / fd_accdb_cache_slot_sz[ cls ];
}

#if FD_TMPL_USE_HANDHOLDING
static inline int
fd_accdb_ptr_in_region( fd_accdb_t const * accdb,
                        ulong              cls,
                        void const *       ptr ) {
  if( FD_UNLIKELY( cls>=FD_ACCDB_CACHE_CLASS_CNT ) ) return 0;

  uchar const * base = accdb->cache[ cls ];
  if( FD_UNLIKELY( !base ) ) return 0;

  ulong slot_sz   = fd_accdb_cache_slot_sz[ cls ];
  ulong region_sz = accdb->shmem->cache_class_max[ cls ] * slot_sz;
  uchar const * p = (uchar const *)ptr;

  if( FD_UNLIKELY( p<base || p>=base+region_sz ) ) return 0;
  return ( (ulong)( p - base ) % slot_sz )==FD_ACCDB_CACHE_META_SZ;
}
#endif

FD_FN_CONST ulong
fd_accdb_align( void ) {
  return FD_ACCDB_ALIGN;
}

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_live_slots ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_ALIGN,           sizeof(fd_accdb_t)                     );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );
  return FD_LAYOUT_FINI( l, FD_ACCDB_ALIGN );
}

void *
fd_accdb_new( void *              ljoin,
              fd_accdb_shmem_t *  shmem,
              int                 fd,
              ulong               external_epoch_cnt,
              ulong const **      external_epoch_slots ) {
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
  fd_accdb_t * accdb      = FD_SCRATCH_ALLOC_APPEND( l2, fd_accdb_align(),         sizeof(fd_accdb_t)                     );
  void * _local_fork_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );

  accdb->fd = fd;
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
  accdb->snapshot_loading = 0;

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
  accdb->my_epoch_slot = &shmem->joiner_epochs[ epoch_idx ].val;

  accdb->external_epoch_slots = external_epoch_slots;
  accdb->external_epoch_cnt   = external_epoch_cnt;

  accdb->deferred_acc_buf = (uint *)( (uchar *)shmem + shmem->deferred_acc_buf_off );

  accdb->deferred_fork_head  = NULL;
  accdb->deferred_fork_tail  = NULL;
  accdb->deferred_fork_epoch = 0UL;

  memset( accdb->metrics, 0, sizeof(fd_accdb_metrics_t) );

  return accdb;
}

static inline void wait_cmd( fd_accdb_t * accdb );
static inline void submit_cmd( fd_accdb_t * accdb, uint op, ushort fork_id );

void
fd_accdb_reset( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  /* Wait for any pending background command (advance_root / purge) on
     T2 to finish before clobbering shared state. */
  wait_cmd( accdb );

  /* Reset pools through the joiner's existing pointers.  acc_pool and
     txn_pool use POOL_LAZY=1 so reset is O(1).  fork_pool and
     partition_pool rebuild their free lists in O(max_live_slots) and
     O(partition_cnt), both small. */
  acc_pool_reset( accdb->acc_pool_join );
  txn_pool_reset( accdb->txn_pool );
  fork_pool_reset( accdb->fork_shmem_pool );
  partition_pool_reset( accdb->partition_pool );

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
  shmem->root_fork_id   = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  shmem->generation     = 0U;
  shmem->partition_lock = 0;
  shmem->partition_max  = 0UL;

  /* Write heads: sentinel values that force partition-switch on first
     write. */
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    shmem->whead[ k ] = accdb_offset( shmem->partition_cnt, shmem->partition_sz );
    shmem->has_partition[ k ] = 0;
  }

  /* Cache state */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    shmem->clock_hand[ c ].val       = 0UL;
    shmem->cache_free[ c ].ver_top   = (ulong)UINT_MAX;
    shmem->cache_free_cnt[ c ].val   = 0UL;
    shmem->cache_class_init[ c ].val = 0UL;
    if( shmem->cache_class_max[ c ]>=shmem->cache_min_reserved*shmem->joiner_cnt_max )
      shmem->cache_class_used[ c ].val = ULONG_MAX;
    else
      shmem->cache_class_used[ c ].val = 0UL;
  }

  /* Reset every cache slot's metadata to empty sentinels. */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong slot_sz = fd_accdb_cache_slot_sz[ c ];
    for( ulong i=0UL; i<shmem->cache_class_max[ c ]; i++ ) {
      fd_accdb_cache_line_t * line = (fd_accdb_cache_line_t *)( accdb->cache[ c ] + i*slot_sz );
      line->key.generation = UINT_MAX;
      line->acc_idx        = UINT_MAX;
      line->refcnt         = 0U;
      line->referenced     = 0;
      line->persisted      = 1;
    }
  }

  /* Epoch system: reset epoch and all slot values to idle, but
     preserve joiner_cnt and each tile's my_epoch_slot pointer so that
     tiles which joined during init keep their original slot indices. */
  shmem->epoch = 1UL;
  for( ulong i=0UL; i<FD_ACCDB_MAX_JOINERS; i++ ) shmem->joiner_epochs[ i ].val = ULONG_MAX;

  /* Deferred acc buffer. */
  shmem->deferred_acc_buf_cnt = 0UL;
  shmem->deferred_acc_epoch   = 0UL;

  /* Shared metrics: zero gauges that reflect current state (now empty)
     but preserve counters and accounts_capacity. */
  shmem->shmetrics->accounts_total       = 0UL;
  shmem->shmetrics->disk_allocated_bytes = 0UL;
  shmem->shmetrics->disk_current_bytes   = 0UL;
  shmem->shmetrics->disk_used_bytes      = 0UL;
  shmem->shmetrics->in_compaction        = 0;

  /* Command slot */
  shmem->cmd_op      = FD_ACCDB_CMD_IDLE;
  shmem->cmd_fork_id = USHORT_MAX;

  shmem->snapshot_loading = 0;

  FD_COMPILER_MFENCE();

  /* Tell the accdb tile to clear its stale deferred fork chain.
     Its deferred_fork_head/tail now reference recycled pool elements;
     it must discard them before processing any future advance_root or
     purge command.  The command is asynchronous; the next advance_root
     or purge call will wait for it to complete via wait_cmd. */
  submit_cmd( accdb, FD_ACCDB_CMD_CLEAR_DEFERRED, 0 );

  /* Reset local state */
  accdb->deferred_fork_head  = NULL;
  accdb->deferred_fork_tail  = NULL;
  accdb->deferred_fork_epoch = 0UL;
  accdb->snapshot_loading    = 0;
  accdb->acquire_state       = FD_ACCDB_ACQUIRE_STATE_IDLE;
}

void
fd_accdb_snapshot_load_begin( fd_accdb_t * accdb ) {
  accdb->snapshot_loading = 1;
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
  spin_lock_acquire( &accdb->shmem->partition_lock );

  /* Force the next layer-0 write onto a fresh Hot partition so we do
     not keep appending live execution writes to the tail of a partition
     that was tagged Cold during snapshot load.  Must run while
     snapshot_loading is still set so the partition we just closed
     (the snapshot-tagged Cold one) is not enqueued for compaction by
     change_partition's tail-credit try_enqueue.  change_partition will
     retag the newly-allocated partition as Cold (because the flag is
     still set), so we fix it back to Hot below. */
  if( FD_LIKELY( accdb->shmem->has_partition[ 0 ] ) ) {
    change_partition( accdb, &accdb->shmem->whead[ 0 ], &accdb->shmem->whead[ 0 ], &accdb->shmem->has_partition[ 0 ], 0 );
    ulong new_idx = packed_partition_idx( &accdb->shmem->whead[ 0 ] );
    fd_accdb_partition_t * newp = partition_pool_ele( accdb->partition_pool, new_idx );
    FD_VOLATILE( newp->layer ) = 0;
  }

  accdb->snapshot_loading = 0;
  FD_VOLATILE( accdb->shmem->snapshot_loading ) = 0;

  /* Sweep all partitions written during the load — any that crossed
     the fragmentation threshold while enqueue was suppressed are
     re-checked now and pushed onto the compaction queue. */
  ulong partition_max = accdb->shmem->partition_max;
  for( ulong p=0UL; p<partition_max; p++ ) {
    fd_accdb_shmem_try_enqueue_compaction( accdb->shmem, p );
  }

  spin_lock_release( &accdb->shmem->partition_lock );
}

void
fd_accdb_snapshot_save_whead( fd_accdb_t *                   accdb,
                              fd_accdb_snapshot_recovery_t * out ) {
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

  /* Wait for any pending background command (purge) on T2 to finish
     before releasing partitions. */
  wait_cmd( accdb );

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
     keeps allocate_next_write in sync with snapwr, which advances
     its flat file offset sequentially. */
  spin_lock_acquire( &shmem->partition_lock );
  for( ulong p=cur_partition_max; p>recover->partition_max; p-- ) {
    fd_accdb_partition_t * part = partition_pool_ele( accdb->partition_pool, p-1UL );
    if( FD_UNLIKELY( part->queued ) ) {
      compaction_dlist_ele_remove( accdb->compaction_dlist[ part->layer ], part, accdb->partition_pool );
    }
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
  shmem->shmetrics->disk_allocated_bytes = recover->partition_max * shmem->partition_sz;

  if( recover->has_partition ) {
    accdb_offset_t sp_off = (accdb_offset_t){ .val = recover->whead_val };
    ulong sp_idx = packed_partition_idx( &sp_off );
    fd_accdb_partition_t * sp = partition_pool_ele( accdb->partition_pool, sp_idx );
    sp->bytes_freed   = recover->savepoint_bytes_freed;
    sp->write_offset  = 0UL;
  }

  spin_lock_release( &shmem->partition_lock );
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

  accdb->deferred_acc_buf    = NULL;
  accdb->deferred_fork_head  = NULL;
  accdb->deferred_fork_tail  = NULL;
  accdb->deferred_fork_epoch = 0UL;

  memset( accdb->metrics, 0, sizeof(fd_accdb_metrics_t) );

  return accdb;
}

/* T1 -> T2 cmd channel.  Two states on cmd_op:

     IDLE     - no cmd in flight
     non-IDLE - cmd pending; T2 will process it then flip back to IDLE

   T1 submits by writing fork_id then cmd_op (non-IDLE).  T2 processes
   by reading fork_id then writing cmd_op = IDLE.  T1 waits for IDLE
   before submitting again, so T2 never sees a half-written cmd and
   never re-processes the same cmd. */

static inline void
wait_cmd( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  while( FD_VOLATILE_CONST( shmem->cmd_op )!=FD_ACCDB_CMD_IDLE ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
}

static inline void
submit_cmd( fd_accdb_t * accdb,
            uint         op,
            ushort       fork_id ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  FD_VOLATILE( shmem->cmd_fork_id ) = fork_id;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->cmd_op ) = op;
}

fd_accdb_fork_id_t
fd_accdb_attach_child( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t parent_fork_id ) {
  /* fork_pool_acquire is not NULL-checked: replay gates attaches on
     fd_banks_can_start_bank, and wait_cmd ensures the prior
     advance_root has fully run on T2, so
     live + deferred forks <= max_live_slots. */
  wait_cmd( accdb );

  fd_accdb_fork_shmem_t * acquired = fork_pool_acquire( accdb->fork_shmem_pool );
  if( FD_UNLIKELY( !acquired ) ) {
    submit_cmd( accdb, FD_ACCDB_CMD_DRAIN_DEFERRED, USHORT_MAX );
    wait_cmd( accdb );
    acquired = fork_pool_acquire( accdb->fork_shmem_pool );
    FD_CHECK_CRIT( acquired, "accdb fork pool exhausted after deferred drain" );
  }
  ulong idx = fork_pool_idx( accdb->fork_shmem_pool, acquired );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ idx ];
  fd_accdb_fork_id_t fork_id = { .val = (ushort)idx };

  fork->shmem->child_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    fork->shmem->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

    descends_set_null( fork->descends );
    accdb->shmem->root_fork_id = fork_id;
  } else {
    fd_accdb_fork_t * parent = &accdb->fork_pool[ parent_fork_id.val ];
    fork->shmem->parent_id  = parent_fork_id;

    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );

    /* Atomically prepend to parent's child list.  T2 (background_purge)
       may concurrently unlink a different child from the same list, so
       we must CAS here. */
    FD_COMPILER_MFENCE();
    for(;;) {
      ushort old_head = FD_VOLATILE_CONST( parent->shmem->child_id.val );
      fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = old_head };
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &parent->shmem->child_id.val, old_head, fork_id.val )==old_head ) ) break;
      FD_SPIN_PAUSE();
    }
  }

  fork->shmem->generation = accdb->shmem->generation++;
  fork->shmem->txn_head = UINT_MAX;

  FD_TEST( !descends_set_test( fork->descends, fork_id.val ) );

  return fork_id;
}

/* evict_clear_acc_cache_ref atomically tears down acc->cache_idx and
   acc->executable_size.CACHE_VALID for an acc that is being evicted
   from cache line (size_class, line_idx).  The caller must already
   hold an exclusive claim on the line (line->refcnt ==
   FD_ACCDB_EVICT_SENTINEL) so that no concurrent thread can pin the
   line.

   The naive sequence (clear cache_idx, clear VALID) lets a reader in
   cold_load_acc see VALID=1 and read a stale INVAL cache_idx, which
   decodes to an OOB cache_line pointer.  The reverse sequence (clear
   VALID, clear cache_idx) lets a concurrent cold_load_acc observe
   VALID=0/CLAIM=0 and start publishing a *new* cache_idx + VALID=1
   between our two stores; our later cache_idx=INVAL would then
   stomp on the cold-loader's published idx.

   We close both races by acquiring CACHE_CLAIM_BIT before mutating
   acc->cache_idx.  cold_load_acc spins while CLAIM is held, so it
   cannot enter the publish path concurrently.  If CLAIM is already
   held, a cold-loader is already mid-publish; in that case
   acc->cache_idx is being repointed away from our line, and we must
   not touch it.  After mutation we release CLAIM.

   Verifies acc->cache_idx still encodes (size_class, line_idx) before
   clobbering, in case the acc was concurrently re-published into a
   different line (e.g. by a previous cold_load_acc completing before
   we arrived). */

static inline void
evict_clear_acc_cache_ref( fd_accdb_accmeta_t * accmeta,
                           ulong                size_class,
                           ulong                line_idx ) {
  uint expected_cidx = FD_ACCDB_ACC_CIDX_PACK( (uint)size_class, (uint)line_idx );

  /* CAS-acquire CLAIM.  If a cold-loader already holds CLAIM, they
     own the publish path; bail without touching accmeta fields (their
     republish is repointing accmeta->cache_idx away from our line). */
  for(;;) {
    uint cur = FD_VOLATILE_CONST( accmeta->executable_size );
    if( FD_UNLIKELY( cur & FD_ACCDB_SIZE_CACHE_CLAIM_BIT ) ) return;
    uint nxt = cur | FD_ACCDB_SIZE_CACHE_CLAIM_BIT;
    if( FD_LIKELY( FD_ATOMIC_CAS( &accmeta->executable_size, cur, nxt )==cur ) ) break;
    fd_racesan_hook( "accdb_evict_clear:claim_wait" );
    FD_SPIN_PAUSE();
  }

  fd_racesan_hook( "accdb_evict_clear:post_claim" );

  /* CLAIM held.  If accmeta->cache_idx still points at our line, clear
     VALID and INVAL the cache_idx.  Otherwise the accmeta was already
     re-published into a different line; leave it alone. */
  if( FD_LIKELY( FD_VOLATILE_CONST( accmeta->cache_idx )==expected_cidx ) ) {
    FD_ATOMIC_FETCH_AND_AND( &accmeta->executable_size, ~FD_ACCDB_SIZE_CACHE_VALID_BIT );
    FD_VOLATILE( accmeta->cache_idx ) = FD_ACCDB_ACC_CIDX_INVAL;
  }

  /* Release CLAIM. */
  FD_ATOMIC_FETCH_AND_AND( &accmeta->executable_size, ~FD_ACCDB_SIZE_CACHE_CLAIM_BIT );
}

/* cache_free_push pushes a fully-freed cache line onto the per-class
   CAS free list (Treiber stack).  The caller must have already
   invalidated the line (key.generation==UINT_MAX) and set persisted=1
   before pushing. */

static inline void
cache_free_push( fd_accdb_t * accdb,
                 ulong        size_class,
                 fd_accdb_cache_line_t * line ) {
  ulong line_idx = cache_line_idx( accdb, size_class, line );
  for(;;) {
    ulong old_vt  = FD_VOLATILE_CONST( accdb->shmem->cache_free[ size_class ].ver_top );
    uint  old_top = (uint)( old_vt & (ulong)UINT_MAX );
    uint  old_ver = (uint)( old_vt >> 32 );
    line->next = old_top;
    FD_COMPILER_MFENCE();
    ulong new_vt = ((ulong)(uint)( old_ver+1U ) << 32) | (ulong)(uint)line_idx;
    if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->cache_free[ size_class ].ver_top, old_vt, new_vt )==old_vt ) ) {
      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->cache_free_cnt[ size_class ].val, 1UL );
      return;
    }
    FD_SPIN_PAUSE();
  }
}

/* cache_free_pop pops a line from the per-class CAS free list.  Returns
   NULL if the list is empty. */

static inline fd_accdb_cache_line_t *
cache_free_pop( fd_accdb_t * accdb,
                ulong        size_class ) {
  for(;;) {
    ulong old_vt  = FD_VOLATILE_CONST( accdb->shmem->cache_free[ size_class ].ver_top );
    uint  old_top = (uint)( old_vt & (ulong)UINT_MAX );
    if( FD_UNLIKELY( old_top==UINT_MAX ) ) return NULL;
    uint  old_ver = (uint)( old_vt >> 32 );
    fd_accdb_cache_line_t * top = cache_line( accdb, size_class, (ulong)old_top );
    uint next = FD_VOLATILE_CONST( top->next );
    ulong new_vt = ((ulong)(uint)( old_ver+1U ) << 32) | (ulong)next;
    if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->cache_free[ size_class ].ver_top, old_vt, new_vt )==old_vt ) ) {
      FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_free_cnt[ size_class ].val, 1UL );
      return top;
    }
    FD_SPIN_PAUSE();
  }
}

/* cache_try_pin attempts a lock-free pin of a cache-hit line.  Returns
   the line if successfully pinned, or NULL if the line is being evicted
   or was recycled (ABA). */

static inline fd_accdb_cache_line_t *
cache_try_pin( fd_accdb_cache_line_t * line,
               uchar const             pubkey[ 32 ],
               uint                    generation ) {
  for(;;) {
    uint old_rc = FD_VOLATILE_CONST( line->refcnt );
    if( FD_UNLIKELY( old_rc==FD_ACCDB_EVICT_SENTINEL ) ) return NULL;
    /* No saturation guard needed: refcnt is a uint and at most
       FD_ACCDB_MAX_JOINERS (256) threads can pin concurrently,
       so old_rc+1 can never reach FD_ACCDB_EVICT_SENTINEL
       (UINT_MAX) or wrap. */
    if( FD_LIKELY( FD_ATOMIC_CAS( &line->refcnt, old_rc, old_rc+1U )==old_rc ) ) {
      /* Pinned.  ABA check: verify the key hasn't changed under us. */
      fd_racesan_hook( "accdb_try_pin:post_cas" );
      FD_COMPILER_MFENCE();
      if( FD_UNLIKELY( line->key.generation!=generation ||
                       memcmp( line->key.pubkey, pubkey, 32UL ) ) ) {
        FD_ATOMIC_FETCH_AND_SUB( &line->refcnt, 1U );
        return NULL;
      }
      line->referenced = 1;
      fd_racesan_hook( "cache_try_pin:pinned" );
      return line;
    }
    FD_SPIN_PAUSE();
  }
}

/* wait_for_epoch_drain spins until every joiner's published epoch
   exceeds tag, meaning all readers that were active at epoch=tag have
   since exited their critical sections. */

static void
wait_for_epoch_drain( fd_accdb_t * accdb,
                      ulong        tag ) {
  for(;;) {
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
    if( FD_LIKELY( tag<min_epoch ) ) break;
    fd_racesan_hook( "accdb_epoch_drain:wait" );
    FD_SPIN_PAUSE();
  }
}

/* drain_deferred_frees releases back to their respective pools any acc
   batch and/or fork slots that were unlinked in a prior advance_root /
   purge call.  The resources cannot be released immediately because
   concurrent readers may still reference them. We wait until every
   joiner's published epoch exceeds the tag stamped when each resource
   was unlinked.

   Must be called before creating new deferred batches (there is at most
   one of each outstanding at a time). */

static void
drain_deferred_frees( fd_accdb_t * accdb ) {
  if( FD_UNLIKELY( accdb->deferred_fork_head ) ) {
    wait_for_epoch_drain( accdb, accdb->deferred_fork_epoch );
    fork_pool_release_chain( accdb->fork_shmem_pool, accdb->deferred_fork_head, accdb->deferred_fork_tail );
    accdb->deferred_fork_head = NULL;
    accdb->deferred_fork_tail = NULL;
  }

  ulong n = accdb->shmem->deferred_acc_buf_cnt;
  if( FD_LIKELY( !n ) ) return;
  wait_for_epoch_drain( accdb, accdb->shmem->deferred_acc_epoch );

  /* All readers that could have been holding a captured pointer to any
     of these accs at unlink time have now exited their epoch sections.
     It is safe to materialize pool.next links and hand the chain to
     acc_pool_release_chain. */
  uint *               buf      = accdb->deferred_acc_buf;
  fd_accdb_accmeta_t * acc_pool = accdb->acc_pool;

  /* Late-publish sweep: a concurrent acquire evictor may have published
     a new offset into one of these accmetas after acc_unlink's
     xchg-to-INVAL but before exiting its epoch.  Now that the epoch has
     drained, any such publish is complete and visible.  Free the
     orphaned disk bytes here, before the accmeta is released to the
     pool and its fields recycled. */
  ulong acc_pool_cap = acc_pool_ele_max( accdb->acc_pool_join );
  for( ulong i=0UL; i<n; i++ ) {
    FD_TEST( (ulong)buf[ i ]<acc_pool_cap );
    fd_accdb_accmeta_t * accmeta = &acc_pool[ buf[ i ] ];
    ulong off = fd_accdb_acc_offset( accmeta );
    if( FD_UNLIKELY( off!=FD_ACCDB_OFF_INVAL ) ) {
      ulong entry_sz = (ulong)FD_ACCDB_SIZE_DATA(accmeta->executable_size)+sizeof(fd_accdb_disk_meta_t);
      fd_accdb_shmem_bytes_freed( accdb->shmem, off, entry_sz );
      FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
    }
  }

  for( ulong i=0UL; i+1UL<n; i++ ) {
    acc_pool[ buf[ i ] ].pool.next = acc_pool_private_cidx( (ulong)buf[ i+1UL ] );
  }
  fd_accdb_accmeta_t * head = &acc_pool[ buf[ 0UL ] ];
  fd_accdb_accmeta_t * tail = &acc_pool[ buf[ n-1UL ] ];
  acc_pool_release_chain( accdb->acc_pool_join, head, tail );
  accdb->shmem->deferred_acc_buf_cnt = 0UL;
}

/* deferred_acc_append records an unlinked acc index in the side buffer
   for later release after wait_for_epoch_drain.  T2 is the sole writer.
   The chain link from acc->pool.next is NOT laid down here: pool.next
   is union-aliased to cache_idx, and a concurrent cold_load_acc may
   still publish through a captured pointer until the epoch drains.
   Materialization of the chain happens in drain_deferred_frees. */

static inline void
deferred_acc_append( fd_accdb_t * accdb,
                     uint         acc_idx ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  FD_TEST( shmem->deferred_acc_buf_cnt<shmem->deferred_acc_buf_max );
  accdb->deferred_acc_buf[ shmem->deferred_acc_buf_cnt++ ] = acc_idx;
}

/* acc_unlink unlinks an account from its hash map chain, frees any
   associated disk bytes, and invalidates a stale cache reference.  Does
   NOT release the acc pool slot — the caller is responsible for that
   (or for batching releases).

   prev is the previous element in the map chain (UINT_MAX if acc_idx is
   the head).

   CONCURRENCY: The chain link being removed is swapped out with a CAS
   so that a concurrent fd_accdb_release prepending to the same chain
   cannot lose its update.  If a head-removal CAS fails (a new node was
   prepended since we loaded the head), we re-walk from the new head to
   find the target as an interior node.  Interior CAS cannot fail from
   inserts (inserts only touch the head) and only one remover exists at
   a time (advance_root / purge are serialized). */

static inline void
acc_unlink( fd_accdb_t * accdb,
            uint         map_idx,
            uint         prev,
            uint         acc_idx ) {
  fd_accdb_accmeta_t * accmeta = &accdb->acc_pool[ acc_idx ];

  /* Atomically capture and clear the offset.  Two races to defuse:

     (1) A concurrent fd_accdb_acquire_inner that is CLOCK-evicting the
         cache line currently holding this acc's data may have already
         xchg'd the offset to INVAL in step 5-6 and freed the old disk
         bytes.  Without atomicity we would re-read the old offset and
         free those same bytes a second time.  The xchg here serializes:
         whoever wins sees the real offset and frees; the loser sees
         INVAL and skips.

     (2) That same evictor may also be mid-flight to publish a NEW
         offset in step 9 (after step 5-6's free but before step 9's
         store).  That late publish lands on an accmeta that is about
         to be chain-unlinked and deferred-released.  drain_deferred_
         frees sweeps the deferred buffer after epoch drain to catch
         the late publish and free the orphaned bytes. */
  ulong entry_sz = (ulong)FD_ACCDB_SIZE_DATA(accmeta->executable_size)+sizeof(fd_accdb_disk_meta_t);
  ulong old_offset = fd_accdb_acc_xchg_offset( accmeta, FD_ACCDB_OFF_INVAL );
  if( FD_LIKELY( old_offset!=FD_ACCDB_OFF_INVAL ) ) {
    fd_accdb_shmem_bytes_freed( accdb->shmem, old_offset, entry_sz );
    FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
  }
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->accounts_total, 1UL );
  accdb->metrics->accounts_deleted++;

  if( FD_LIKELY( prev==UINT_MAX ) ) {
    /* Head removal — CAS may fail if a concurrent insert prepended a
       new node.  On failure the target is now interior. */
    for(;;) {
      uint old_head = FD_VOLATILE_CONST( accdb->acc_map[ map_idx ] );
      if( FD_LIKELY( old_head==acc_idx ) ) {
        if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->acc_map[ map_idx ], acc_idx, accmeta->map.next )==acc_idx ) ) break;
        FD_SPIN_PAUSE();
        continue;
      }
      /* Head changed — walk from new head to find prev for interior
         removal.  The target must still be in the chain because only
         this thread removes elements. */
      prev = old_head;
      while( FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next )!=acc_idx ) prev = FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next );
      FD_ATOMIC_CAS( &accdb->acc_pool[ prev ].map.next, acc_idx, accmeta->map.next );
      break;
    }
  } else {
    FD_ATOMIC_CAS( &accdb->acc_pool[ prev ].map.next, acc_idx, accmeta->map.next );
  }

  fd_racesan_hook( "accdb_acc_unlink:post_splice" );

  /* If the freed acc still has a cached location, invalidate it and
     try to reclaim the cache line so the eviction path does not try
     to write back stale data from a recycled pool slot.  Lock-free:
     CAS the refcnt 0 -> EVICT_SENTINEL to claim it exclusively, then
     push to the CAS free list.  If the line is pinned (refcnt>0),
     skip, the pinner's release will handle it.

     Acquire CACHE_CLAIM_BIT before touching acc->cache_idx /
     CACHE_VALID — see evict_clear_acc_cache_ref for the protocol.
     Without CLAIM, a concurrent cold_load_acc can publish a fresh
     (cache_idx, VALID=1) pair into this acc between our two stores,
     and our subsequent cache_idx=INVAL stomps onto the freelist
     pool.next field (the union sibling of cache_idx), corrupting the
     pool.  Unlike evict_clear_acc_cache_ref, we cannot bail when CLAIM
     is held: this acc is being permanently unlinked, so we must
     spin-wait for the cold-loader to release CLAIM and then invalidate
     whatever cache_idx is current. */
  uint cur_es;
  for(;;) {
    cur_es = FD_VOLATILE_CONST( accmeta->executable_size );
    if( FD_UNLIKELY( cur_es & FD_ACCDB_SIZE_CACHE_CLAIM_BIT ) ) { FD_SPIN_PAUSE(); continue; }
    uint nxt_es = cur_es | FD_ACCDB_SIZE_CACHE_CLAIM_BIT;
    if( FD_LIKELY( FD_ATOMIC_CAS( &accmeta->executable_size, cur_es, nxt_es )==cur_es ) ) break;
    FD_SPIN_PAUSE();
  }

  uint cidx = FD_ACCDB_ACC_CIDX_INVAL;
  int  had_valid = FD_ACCDB_SIZE_CACHE_VALID( cur_es );
  if( FD_UNLIKELY( had_valid ) ) {
    cidx = FD_VOLATILE_CONST( accmeta->cache_idx );
    /* Clear VALID before INVAL'ing cache_idx — matches the order in
       evict_clear_acc_cache_ref so cold_load_acc's "VALID=1 +
       cidx=INVAL" spin path resolves on the next iteration when it
       observes VALID=0. */
    FD_ATOMIC_FETCH_AND_AND( &accmeta->executable_size, ~FD_ACCDB_SIZE_CACHE_VALID_BIT );
    FD_VOLATILE( accmeta->cache_idx ) = FD_ACCDB_ACC_CIDX_INVAL;
  }

  /* Release CLAIM. */
  FD_ATOMIC_FETCH_AND_AND( &accmeta->executable_size, ~FD_ACCDB_SIZE_CACHE_CLAIM_BIT );

  if( FD_UNLIKELY( had_valid ) ) {
    fd_accdb_cache_line_t * stale = cache_line( accdb, FD_ACCDB_ACC_CIDX_CLASS( cidx ), FD_ACCDB_ACC_CIDX_IDX( cidx ) );
    fd_racesan_hook( "acc_unlink:pre_reclaim_cas" );
    uint old_rc = FD_ATOMIC_CAS( &stale->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL );
    fd_racesan_hook( "acc_unlink:post_reclaim_cas" );
    if( FD_LIKELY( !old_rc ) ) {
      /* Claimed.  Validate key (ABA, slot could have been recycled
         between our read of cache_idx and the CAS). */
      if( FD_LIKELY( stale->key.generation==accmeta->key.generation &&
                     !memcmp( stale->key.pubkey, accmeta->key.pubkey, 32UL ) ) ) {
        ulong sc = FD_ACCDB_ACC_CIDX_CLASS( cidx );
        stale->key.generation = UINT_MAX;
        stale->persisted = 1;
        stale->acc_idx   = UINT_MAX;
        stale->refcnt    = 0;
        cache_free_push( accdb, sc, stale );
      } else {
        /* Wrong line (ABA).  Release claim. */
        FD_VOLATILE( stale->refcnt ) = 0;
      }
    }
    else if( FD_LIKELY( old_rc!=FD_ACCDB_EVICT_SENTINEL ) ) {
      /* The CAS lost to a non-sentinel refcnt, but that does not prove
         `stale` is still our line.  Between capturing cidx and here we
         released the claim, so we could have evicted `stale` and
         recycled it to an unrelated account. */
      fd_accdb_cache_line_t * mine = cache_try_pin( stale, accmeta->key.pubkey, accmeta->key.generation );
      if( FD_LIKELY( mine ) ) {
        /* Genuinely our line, still pinned by a reader.  The accmeta
           slot is about to be deferred-released and recycled; if a
           later writeback of this dirty line fires, it would pair the
           recycled accmeta's pubkey with the old owner/data.  Set
           persisted so the writeback gate never fires. */
        FD_VOLATILE( mine->persisted ) = 1;

        /* Only the tombstone self-unlink may be pinned here old-version
           and purge unlinks are never pinned, because a reader on a
           live fork resolves to the newest version, not the one these
           unlink. */
        FD_TEST( accmeta->lamports==0UL );

        FD_ATOMIC_FETCH_AND_SUB( &mine->refcnt, 1U );
      }
      /* Else was recycled to a foreign account.  Nothing to neutralize,
         leave the line alone. */
    } else {
      /* A foreground evictor already claimed this line.  It holds its
         epoch acquire and writeback, so drain_deferred_frees cannot
         recycle the slot before it finishes. Its writeback names the
         old account correctly, no poison. */
    }
  }
}

/* fork_slot_defer removes fork_id from every descends_set and chains
   the fork pool slot onto the deferred fork chain for later release.
   The slot must not be released immediately because concurrent readers
   may still reference the fork ID via descends_set or stale chain
   walks.

   The eager descends_set_remove here is safe despite being a
   non-atomic RMW that races with concurrent descends_set_test in
   fd_accdb_acquire, for two reasons:

   (a) Rooted parent forks: after advance_root publishes the new
       root_fork_id, any acquire loads root_generation >=
       parent->generation.  Every account from the old parent has
       generation <= parent->generation, so the
       "generation > root_generation" gate in the chain walk is
       never satisfied and the parent's bit is never tested.

   (b) Purged / pruned sibling forks: a purged fork is by
       definition not an ancestor of any live fork, so its bit
       was never set in any live fork's descends_set.  Clearing
       it is a literal no-op.

   Fork-id ABA after slot reuse is also safe: the fork pool slot
   is not released until drain_deferred_frees, which waits until
   all epoch-protected readers have exited.  On x86 (TSO), the
   synchronization chain (T2: bit clear -> epoch FAA; reader:
   epoch load -> epoch_slot store -> mfence -> bit read) guarantees
   that any reader entering a new epoch section after the drain
   will observe the cleared bit before the slot is recycled by
   attach_child. */

static inline void
fork_slot_defer( fd_accdb_t *              accdb,
                 fd_accdb_fork_id_t         fork_id,
                 fd_accdb_fork_shmem_t **   fork_head,
                 fd_accdb_fork_shmem_t **   fork_tail ) {
  for( ulong i=0UL; i<accdb->shmem->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, fork_id.val );
  fd_accdb_fork_shmem_t * shmem = fork_pool_ele( accdb->fork_shmem_pool, (ulong)fork_id.val );
  if( *fork_tail ) (*fork_tail)->pool.next = fork_pool_private_cidx( (ulong)fork_id.val );
  else             *fork_head = shmem;
  *fork_tail = shmem;
}

static void
purge_inner( fd_accdb_t *              accdb,
             fd_accdb_fork_id_t         fork_id,
             fd_accdb_fork_shmem_t **   fork_head,
             fd_accdb_fork_shmem_t **   fork_tail ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  fd_accdb_fork_id_t child = fork->shmem->child_id;
  while( child.val!=USHORT_MAX ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ child.val ].shmem->sibling_id;
    purge_inner( accdb, child, fork_head, fork_tail );
    child = next;
  }

  uint txn = fork->shmem->txn_head;
  if( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txn_head = txn_pool_ele( accdb->txn_pool, (ulong)txn );
    fd_accdb_txn_t * txn_tail = NULL;
    while( txn!=UINT_MAX ) {
      fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, (ulong)txn );

      uint acc_idx = txne->acc_pool_idx;

      uint prev = UINT_MAX;
      uint cur = FD_VOLATILE_CONST( accdb->acc_map[ txne->acc_map_idx ] );
      while( cur!=acc_idx ) {
        prev = cur;
        cur = FD_VOLATILE_CONST( accdb->acc_pool[ cur ].map.next );
      }

      fd_racesan_hook( "accdb_purge:pre_unlink" );
      acc_unlink( accdb, txne->acc_map_idx, prev, acc_idx );
      deferred_acc_append( accdb, acc_idx );

      txn_tail = txne;
      txn = txne->fork.next;
    }
    txn_pool_release_chain( accdb->txn_pool, txn_head, txn_tail );
  }

  fork_slot_defer( accdb, fork_id, fork_head, fork_tail );
}

static inline void
remove_children( fd_accdb_t *              accdb,
                 fd_accdb_fork_t *          fork,
                 fd_accdb_fork_t *          except,
                 fd_accdb_fork_shmem_t **   fork_head,
                 fd_accdb_fork_shmem_t **   fork_tail ) {
  fd_accdb_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    fd_accdb_fork_t * sibling = &accdb->fork_pool[ sibling_idx.val ];
    fd_accdb_fork_id_t cur_idx = sibling_idx;

    sibling_idx = sibling->shmem->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    purge_inner( accdb, cur_idx, fork_head, fork_tail );
  }
}

static void
background_advance_root( fd_accdb_t *       accdb,
                         fd_accdb_fork_id_t fork_id ) {
  drain_deferred_frees( accdb );

  /* The caller guarantees that rooting is sequential: each call
     advances the root by exactly one slot (the immediate child of the
     current root).  Skipping levels is not supported. */
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val==accdb->shmem->root_fork_id.val );
  FD_TEST( fork->shmem->parent_id.val!=USHORT_MAX );

  fd_accdb_fork_t * parent_fork = &accdb->fork_pool[ fork->shmem->parent_id.val ];

  /* Accumulate freed fork pool slots across remove_children and the
     old-version cleanup below into a chain that will be deferred-
     released after the epoch bump.  Freed acc pool slots are recorded
     in the shmem side buffer via deferred_acc_append (they cannot be
     chained via pool.next yet — see comment on the side buffer). */
  fd_accdb_fork_shmem_t * fork_head = NULL;
  fd_accdb_fork_shmem_t * fork_tail = NULL;

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( accdb, parent_fork, fork, &fork_head, &fork_tail );

  /* And for any accounts which were updated in the newly rooted slot,
     we will now never need to access any older version, so we can
     discard any slots earlier than the one we are rooting. */
  uint txn = fork->shmem->txn_head;
  if( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txn_head = txn_pool_ele( accdb->txn_pool, (ulong)txn );
    fd_accdb_txn_t * txn_tail = NULL;
    while( txn!=UINT_MAX ) {
      fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, (ulong)txn );

      fd_accdb_accmeta_t const * new_acc = &accdb->acc_pool[ txne->acc_pool_idx ];

      uint prev          = UINT_MAX;
      uint new_acc_prev  = UINT_MAX; /* prev of new_acc on the chain when we encounter it (UINT_MAX if head or never seen) */
      int  new_acc_seen  = 0;
      uint acc = FD_VOLATILE_CONST( accdb->acc_map[ txne->acc_map_idx ] );
      FD_TEST( acc!=UINT_MAX );
      while( acc!=UINT_MAX ) {
        fd_accdb_accmeta_t const * cur_acc = &accdb->acc_pool[ acc ];
        uint cur_next = FD_VOLATILE_CONST( cur_acc->map.next );

        if( FD_LIKELY( acc==txne->acc_pool_idx ) ) {
          new_acc_prev = prev;
          new_acc_seen = 1;
          prev = acc;
          acc = cur_next;
          continue;
        }

        if( FD_LIKELY( (cur_acc->key.generation<=parent_fork->shmem->generation || descends_set_test( fork->descends, fd_accdb_acc_fork_id(cur_acc) ) ) && !memcmp( new_acc->key.pubkey, cur_acc->key.pubkey, 32UL ) ) ) {
          uint next = cur_next;
          fd_racesan_hook( "accdb_advance:pre_unlink" );
          acc_unlink( accdb, txne->acc_map_idx, prev, acc );
          deferred_acc_append( accdb, acc );
          acc = next;
        } else {
          prev = acc;
          acc = cur_next;
        }
      }

      /* If the newly rooted version is a tombstone (lamports==0, e.g.
         account was closed), drop it from the index too: no fork can
         reach it anymore, and keeping it around just wastes a hash
         slot and the disk bytes it occupies.

         If a later txn on this same fork wrote the same pubkey, that
         txn's inner walk above would have already unlinked this txn's
         new_acc as an "older version" - in that case new_acc_seen=0
         and we skip, since the freelist cleanup is already done. */
      if( FD_UNLIKELY( new_acc_seen && new_acc->lamports==0UL ) ) {
        uint new_acc_idx = (uint)txne->acc_pool_idx;
        acc_unlink( accdb, txne->acc_map_idx, new_acc_prev, new_acc_idx );
        deferred_acc_append( accdb, new_acc_idx );
      }

      txn_tail = txne;
      txn = txne->fork.next;
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

  /* Remove the parent from all descends_sets and chain it for deferred
     release, so that when the slot is eventually recycled to a new
     fork, no concurrent reader can mistake the new fork for the old
     ancestor.  Entries from the freed parent are still visible via the
     generation <= root_generation fast path in reads. */
  fd_accdb_fork_id_t old_parent_id = fork->shmem->parent_id;
  fork_slot_defer( accdb, old_parent_id, &fork_head, &fork_tail );

  fork->shmem->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->txn_head   = UINT_MAX;
  descends_set_null( fork->descends );

  /* Publish the new root_fork_id BEFORE bumping the epoch and deferring
     the parent slot.  On x86-64 (TSO) a concurrent reader that still
     loads the old root_fork_id is guaranteed to see the parent shmem in
     its original (not-yet-recycled) state because the slot has not been
     released yet.  A reader that loads the new root_fork_id uses the
     new fork. */
  fd_racesan_hook( "accdb_advance:pre_publish_root" );
  accdb->shmem->root_fork_id = fork_id;
  FD_COMPILER_MFENCE();
  fd_racesan_hook( "accdb_advance:post_publish_root" );

  /* Bump epoch and defer both the acc batch and parent fork slot. They
     will be released at the next drain_deferred_frees call once all
     concurrent readers have exited.  The acc batch lives in the shmem
     side buffer; only its epoch tag needs setting here. */
  ulong tag = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->epoch, 1UL );
  if( FD_LIKELY( accdb->shmem->deferred_acc_buf_cnt ) ) {
    accdb->shmem->deferred_acc_epoch = tag;
  }
  if( FD_LIKELY( fork_head ) ) {
    accdb->deferred_fork_head  = fork_head;
    accdb->deferred_fork_tail  = fork_tail;
    accdb->deferred_fork_epoch = tag;
  }
}

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id ) {
  wait_cmd( accdb );
  submit_cmd( accdb, FD_ACCDB_CMD_ADVANCE_ROOT, fork_id.val );
}

/* background_purge does the heavy lifting of purge on T2: unlink the
   fork from the parent's child list, drain deferred frees, recursively
   purge the fork subtree, and defer-release the freed acc pool
   elements.  The sibling-list unlink is done here (not on T1) because
   advance_root / remove_children also mutate sibling lists on T2, and
   T2 is single-threaded so plain stores are safe. */

static void
background_purge( fd_accdb_t *       accdb,
                  fd_accdb_fork_id_t fork_id ) {
  /* Unlink fork_id from its parent's child list.  This runs on T2
     which is the sole mutator of sibling lists (advance_root and
     remove_children also run on T2), so plain stores are safe. */
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  fd_accdb_fork_id_t parent_id = fork->shmem->parent_id;
  if( FD_LIKELY( parent_id.val!=USHORT_MAX ) ) {
    fd_accdb_fork_t * parent = &accdb->fork_pool[ parent_id.val ];
    if( FD_UNLIKELY( parent->shmem->child_id.val==fork_id.val ) ) {
      parent->shmem->child_id = fork->shmem->sibling_id;
    } else {
      fd_accdb_fork_id_t prev_id = parent->shmem->child_id;
      while( prev_id.val!=USHORT_MAX ) {
        fd_accdb_fork_t * prev = &accdb->fork_pool[ prev_id.val ];
        if( prev->shmem->sibling_id.val==fork_id.val ) {
          prev->shmem->sibling_id = fork->shmem->sibling_id;
          break;
        }
        prev_id = prev->shmem->sibling_id;
      }
    }
  }

  drain_deferred_frees( accdb );

  fd_accdb_fork_shmem_t * fork_head = NULL;
  fd_accdb_fork_shmem_t * fork_tail = NULL;
  purge_inner( accdb, fork_id, &fork_head, &fork_tail );

  ulong tag = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->epoch, 1UL );
  if( FD_LIKELY( accdb->shmem->deferred_acc_buf_cnt ) ) {
    accdb->shmem->deferred_acc_epoch = tag;
  }
  if( FD_LIKELY( fork_head ) ) {
    accdb->deferred_fork_head  = fork_head;
    accdb->deferred_fork_tail  = fork_tail;
    accdb->deferred_fork_epoch = tag;
  }
}

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id ) {
  FD_TEST( fork_id.val!=accdb->shmem->root_fork_id.val );

  wait_cmd( accdb );
  submit_cmd( accdb, FD_ACCDB_CMD_PURGE, fork_id.val );
}

static inline fd_accdb_cache_line_t *
acquire_cache_line( fd_accdb_t * accdb,
                    ulong        size_class,
                    uint *       out_evicted_acc_idx ) {
  /* Priority 1: CAS free list — already invalidated,
     persisted==1, generation==UINT_MAX.  Cheapest path. */
  fd_accdb_cache_line_t * result = cache_free_pop( accdb, size_class );
  if( FD_LIKELY( result ) ) {
    while( FD_UNLIKELY( FD_ATOMIC_CAS( &result->refcnt, 0U, 1U )!=0U ) ) {
      fd_racesan_hook( "accdb_freepop:refcnt_wait" );
      FD_SPIN_PAUSE();
    }
    result->referenced = 0;
    *out_evicted_acc_idx = UINT_MAX;
    return result;
  }

  /* Priority 2: Lazy initial allocation — atomic FAA with undo on
     overflow.  Safe for concurrent callers. */
  ulong old_init = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->cache_class_init[ size_class ].val, 1UL );
  if( FD_LIKELY( old_init<accdb->shmem->cache_class_max[ size_class ] ) ) {
    result = cache_line( accdb, size_class, old_init );
    result->refcnt         = 1;
    result->persisted      = 1;
    result->referenced     = 0;
    result->acc_idx        = UINT_MAX;
    result->key.generation = UINT_MAX;
    *out_evicted_acc_idx   = UINT_MAX;
    return result;
  }
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_init[ size_class ].val, 1UL );

  /* Priority 3: CLOCK sweep ... scan forward giving second chances. */
  for(;;) {
    ulong hand = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->clock_hand[ size_class ].val, 1UL ) % accdb->shmem->cache_class_max[ size_class ];
    fd_accdb_cache_line_t * line = cache_line( accdb, size_class, hand );

    if( FD_UNLIKELY( line->key.generation==UINT_MAX && line->acc_idx==UINT_MAX ) ) continue;

    uint rc = FD_VOLATILE_CONST( line->refcnt );
    if( FD_UNLIKELY( rc!=0U ) ) continue; /* Pinned or being evicted */

    if( FD_UNLIKELY( line->referenced ) ) {
      line->referenced = 0;
      continue; /* Second chance */
    }

    if( FD_UNLIKELY( FD_ATOMIC_CAS( &line->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL )!=0U ) ) continue;

    /* The line is now claimed for eviction (refcnt==EVICT_SENTINEL).  A
       concurrent acc_unlink that targets this same line's accmeta will
       observe the sentinel here and take its do-nothing branch — see the
       test_accdb_racesan SENTINEL case. */
    fd_racesan_hook( "clock_evict:post_sentinel" );

    if( FD_LIKELY( line->acc_idx!=UINT_MAX ) ) {
      evict_clear_acc_cache_ref( &accdb->acc_pool[ line->acc_idx ], size_class, hand );
    }
    *out_evicted_acc_idx    = line->persisted ? UINT_MAX : line->acc_idx;
    line->key.generation    = UINT_MAX;
    line->refcnt            = 1;
    line->referenced        = 0;
    return line;
  }

  FD_TEST( 0 );
  return NULL;
}

static inline void
change_partition( fd_accdb_t *           accdb,
                  accdb_offset_t const * offset_before,
                  accdb_offset_t *       out_offset,
                  int *                  has_partition,
                  uchar                  layer ) {
  /* New data will not fit in the current partition, so we need to
     move to the next one.  */
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
  *out_offset   = accdb_offset( new_partition_idx, 0UL );
  *has_partition = 1;

  /* Now that the write head has been rotated away from the old
     partition, check if it should be enqueued for compaction.  We call
     try_enqueue directly because the caller already holds
     partition_lock (calling fd_accdb_shmem_bytes_freed here would
     deadlock on the non-reentrant lock).  Skip when
     has_partition was 0, because the sentinel partition_idx is
     not a valid pool element. */
  if( FD_LIKELY( had_partition && partition_idx_before!=new_partition_idx ) ) {
    fd_accdb_shmem_try_enqueue_compaction( accdb->shmem, partition_idx_before );
  }

  /* Snapshot-load tiering: accounts loaded from a snapshot never get
     a second write, so compaction-driven promotion never fires and
     they would otherwise live in Hot forever.  When snapshot_loading
     is set, tag the new partition as Cold up front.  We do not set
     has_partition[Cold] / whead[Cold] — those are owned by the
     compaction tile and represent the live Cold write head, which is
     independent of snapshot-loaded partitions that happen to be
     labeled Cold. */
  if( FD_UNLIKELY( accdb->snapshot_loading && layer==0 ) ) {
    FD_VOLATILE( partition->layer ) = FD_ACCDB_COMPACTION_LAYER_CNT-1UL;
  }

  if( FD_UNLIKELY( new_partition_idx>=accdb->shmem->partition_max ) ) {
    FD_LOG_INFO(( "growing accounts database from %lu GiB to %lu GiB", accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<30UL), (new_partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<30UL) ));

    int result = fallocate( accdb->fd, 0, (long)(new_partition_idx*accdb->shmem->partition_sz), (long)accdb->shmem->partition_sz );
    if( FD_UNLIKELY( -1==result ) ) {
      if( FD_LIKELY( errno==ENOSPC ) ) FD_LOG_ERR(( "fallocate() failed (%d-%s). The accounts database filled "
                                                    "the disk it is on, trying to grow from %lu GiB to %lu GiB. Please "
                                                    "free up disk space and restart the validator.",
                                                    errno, fd_io_strerror( errno ), accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<30UL), (new_partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<30UL) ));
      else FD_LOG_ERR(( "fallocate() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    /* CAS loop: the compaction tile may also be growing the file
       concurrently, so neither path may clobber the other. */
    for(;;) {
      ulong cur = accdb->shmem->partition_max;
      if( FD_LIKELY( new_partition_idx+1UL<=cur ) ) break;
      if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->partition_max, cur, new_partition_idx+1UL )==cur ) ) {
        fd_event_accdb_partition_added_t ev = {
          .partition_idx        = new_partition_idx,
          .prior_partition_idx  = had_partition ? partition_idx_before : ULONG_MAX,
          .layer                = layer,
          .old_partition_max    = cur,
          .new_partition_max    = new_partition_idx+1UL,
          .partition_sz         = accdb->shmem->partition_sz,
          .disk_allocated_bytes = (new_partition_idx+1UL)*accdb->shmem->partition_sz,
        };
        fd_event_report_accdb_partition_added( &ev );
        break;
      }
    }
    accdb->shmem->shmetrics->disk_allocated_bytes = accdb->shmem->partition_max*accdb->shmem->partition_sz;
  }
}

static inline ulong
allocate_next_write( fd_accdb_t * accdb,
                     ulong        sz ) {
  for(;;) {
    accdb_offset_t offset = { .val = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->whead[ 0 ].val, sz ) };
    if( FD_LIKELY( packed_partition_offset( &offset )+sz<=accdb->shmem->partition_sz ) ) {
      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_current_bytes, sz );
      ulong file_offset = packed_partition_file_offset( &offset, accdb->shmem->partition_sz );
      fd_accdb_partition_write_bump( accdb, file_offset, sz );
      return file_offset;
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
        FD_SPIN_PAUSE();
      }
      continue;
    }

    spin_lock_acquire( &accdb->shmem->partition_lock );
    change_partition( accdb, &offset, &accdb->shmem->whead[ 0 ], &accdb->shmem->has_partition[ 0 ], 0 );
    spin_lock_release( &accdb->shmem->partition_lock );
  }
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
    spin_lock_acquire( &accdb->shmem->partition_lock );
    change_partition( accdb, &offset, &accdb->shmem->whead[ dest_layer ], &accdb->shmem->has_partition[ dest_layer ], (uchar)dest_layer );
    spin_lock_release( &accdb->shmem->partition_lock );
    offset = accdb->shmem->whead[ dest_layer ];
  }
  accdb->shmem->whead[ dest_layer ].val += sz;
  FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_current_bytes, sz );
  ulong file_offset = packed_partition_file_offset( &offset, accdb->shmem->partition_sz );
  fd_accdb_partition_write_bump( accdb, file_offset, sz );
  return file_offset;
}

/* fd_accdb_compact relocates one record from the oldest partition
   queued for compaction at src_layer into the write head for the
   next colder tier, or the same tier for the deepest layer.  It is
   designed to be called repeatedly from a dedicated compaction tile.
   If there is work to do, *charge_busy is set to 1; otherwise 0 is
   left unchanged and the call returns immediately.

   src_layer must be in 0..FD_ACCDB_COMPACTION_LAYER_CNT-1. */

static void
background_compact( fd_accdb_t * accdb,
                    ulong        src_layer,
                    int *        charge_busy ) {
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

    spin_lock_acquire( &accdb->shmem->partition_lock );
    deferred_free_dlist_ele_pop_head( accdb->deferred_free_dlist, accdb->partition_pool );
    FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_current_bytes, accdb->shmem->partition_sz );
    partition_pool_ele_release( accdb->partition_pool, p );
    spin_lock_release( &accdb->shmem->partition_lock );
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

  fd_accdb_disk_meta_t meta[1];

  ulong compact_base = partition_pool_idx( accdb->partition_pool, compact )*accdb->shmem->partition_sz;

  /* Read the on-disk metadata header at the current compaction
     cursor within the partition being compacted. */
  ulong bytes_read = 0UL;
  while( FD_UNLIKELY( bytes_read<sizeof(fd_accdb_disk_meta_t) ) ) {
    long result = pread( accdb->fd, ((uchar *)meta)+bytes_read, sizeof(fd_accdb_disk_meta_t)-bytes_read, (long)(compact_base+compact->compaction_offset+bytes_read) );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pread() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                   compact_base+compact->compaction_offset+bytes_read, sizeof(fd_accdb_disk_meta_t) ));
    fd_accdb_partition_read_bump( accdb, compact_base+compact->compaction_offset, (ulong)result );
    bytes_read += (ulong)result;
  }

  /* Walk the hash chain to find a live index entry whose on-disk
     offset matches the record we are compacting. */
  fd_accdb_accmeta_t * accmeta = NULL;
  ulong source_packed = 0UL;
  uint acc_idx = FD_VOLATILE_CONST( accdb->acc_map[ fd_accdb_hash( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ] );
  while( acc_idx!=UINT_MAX ) {
    fd_accdb_accmeta_t * candidate = &accdb->acc_pool[ acc_idx ];
    uint next_idx = FD_VOLATILE_CONST( candidate->map.next );
    ulong candidate_packed = FD_VOLATILE_CONST( candidate->offset_fork );
    if( FD_LIKELY( (candidate_packed & FD_ACCDB_OFF_MASK)==compact_base+compact->compaction_offset ) ) {
      accmeta       = candidate;
      source_packed = candidate_packed;
      break;
    }
    acc_idx = next_idx;
  }

  ulong record_sz  = sizeof(fd_accdb_disk_meta_t) + (ulong)meta->size;
  ulong bytes_copied = 0UL;
  if( FD_UNLIKELY( !accmeta ) ) {
    /* Dead record — the index entry was already removed, so this
       on-disk extent is garbage.  Nothing to relocate. */
    compact->compaction_dead_records++;
  } else {
    ulong dest_layer  = fd_ulong_min( src_layer+1UL, FD_ACCDB_COMPACTION_LAYER_CNT-1UL );
    ulong dest_offset = allocate_next_compaction_write( accdb, record_sz, dest_layer );

    while( FD_UNLIKELY( bytes_copied<record_sz ) ) {
      long in_off  = (long)(compact_base + compact->compaction_offset + bytes_copied);
      long out_off = (long)(dest_offset + bytes_copied);

      long result = copy_file_range( accdb->fd, &in_off, accdb->fd, &out_off, record_sz-bytes_copied, 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "copy_file_range() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                      compact_base+compact->compaction_offset+bytes_copied, record_sz ));
      fd_accdb_partition_read_bump( accdb, compact_base+compact->compaction_offset+bytes_copied, (ulong)result );
      bytes_copied += (ulong)result;
      accdb->metrics->copy_ops++;
    }

    accdb->shmem->shmetrics->accounts_relocated++;
    accdb->shmem->shmetrics->accounts_relocated_bytes += bytes_copied;
    compact->compaction_accounts_relocated++;
    compact->compaction_bytes_relocated += bytes_copied;

    /* Ensure the data is on disk before publishing the new offset,
       so concurrent acquire threads do not preadv2 from a location
       that hasn't been written yet. */
    FD_COMPILER_MFENCE();

     /* CAS the offset from the exact source record we copied to the new
       destination.  If a concurrent release overwrote the offset to
       FD_ACCDB_OFF_INVAL (dirty sentinel for a new commit), or later
       published a newer on-disk location, the CAS fails and we treat
       the relocated copy as stale.  We CAS the full packed
       offset_fork so the fork_id is preserved and so we only publish
       the relocation if the copied source record is still current. */
     ulong new_packed = ( source_packed & ~FD_ACCDB_OFF_MASK ) | ( dest_offset & FD_ACCDB_OFF_MASK );

#if FD_HAS_RACESAN
     fd_memcpy( fd_accdb_dbg_reloc_pubkey, accmeta->key.pubkey, 32UL );
     fd_accdb_dbg_reloc_dest = dest_offset;
     fd_accdb_dbg_reloc_cnt++;
#endif

     fd_racesan_hook( "accdb_compact:pre_offset_cas" );
     if( FD_UNLIKELY( FD_ATOMIC_CAS( &accmeta->offset_fork, source_packed, new_packed )!=source_packed ) ) {
      /* Record was superseded by a concurrent overwrite commit.
         The disk space we just wrote is dead on arrival — account
         it as freed so compaction can reclaim it later. */
      fd_accdb_shmem_bytes_freed( accdb->shmem, dest_offset, record_sz );
      bytes_copied = 0UL;
    }
  }

  fd_racesan_hook( "accdb_compact:post_relocate" );

  compact->compaction_offset += record_sz;

  if( FD_UNLIKELY( compact->compaction_offset>=compact->write_offset ) ) {
    FD_LOG_INFO(( "compaction of partition %lu completed", partition_pool_idx( accdb->partition_pool, compact ) ));

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
    spin_lock_acquire( &accdb->shmem->partition_lock );

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

    spin_lock_release( &accdb->shmem->partition_lock );
  }

  accdb->metrics->bytes_read += bytes_read + bytes_copied;
  accdb->metrics->bytes_written += bytes_copied;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

/* cold_load_acc resolves the cache slot for `acc` when STEP 1's
   cache_try_pin failed.  It uses bit 29 of executable_size as a
   single-claimer lock so that two concurrent acquirers cannot each
   install their own cache slot for the same acc (which would orphan
   one slot with a dangling line->acc_idx and eventually corrupt
   acc->cache_valid via CLOCK).

   Protocol per acc:
     - If cache_valid is set, retry cache_try_pin (another thread
       finished the cold-load while we were here).  On success, mark
       exists_in_cache so STEP 4 will not write back the slot.
     - If claim is set, spin (another thread is mid-cold-load).
     - Otherwise CAS-set the claim bit.  Winner allocates a cache
       line, populates the placeholder (acc_idx=UINT_MAX), publishes
       cache_idx, then atomically (CAS-loop) sets cache_valid and
       clears claim.

   The eviction sites that clear cache_valid must use FETCH_AND with
   ~CACHE_VALID_BIT (preserving the claim bit) to interact correctly
   with this protocol. */

static fd_accdb_cache_line_t *
cold_load_acc( fd_accdb_t *     accdb,
               fd_accdb_accmeta_t * accmeta,
               uchar const *    pubkey,
               int *            out_exists_in_cache,
               uint *           out_evicted_acc_idx ) {
  for(;;) {
    uint old_es  = FD_VOLATILE_CONST( accmeta->executable_size );
    int  valid   = FD_ACCDB_SIZE_CACHE_VALID( old_es );
    int  claimed = FD_ACCDB_SIZE_CACHE_CLAIM( old_es );

    if( FD_UNLIKELY( valid ) ) {
      /* old_es snapshot saw VALID=1 but a concurrent
         evict_clear_acc_cache_ref may have cleared VALID and stored
         cache_idx=INVAL between our snapshot and this load.  Decoding
         INVAL would yield a wild cache_line pointer; retry the loop
         instead (next iteration will see VALID=0). */
      uint cidx = FD_VOLATILE_CONST( accmeta->cache_idx );
      if( FD_UNLIKELY( cidx==FD_ACCDB_ACC_CIDX_INVAL ) ) { FD_SPIN_PAUSE(); continue; }
      fd_accdb_cache_line_t * hit = cache_line( accdb, FD_ACCDB_ACC_CIDX_CLASS( cidx ), FD_ACCDB_ACC_CIDX_IDX( cidx ) );
      fd_racesan_hook( "accdb_cold_load:pre_try_pin" );
      fd_accdb_cache_line_t * pinned = cache_try_pin( hit, pubkey, accmeta->key.generation );
      if( FD_LIKELY( pinned ) ) {
        *out_exists_in_cache  = 1;
        *out_evicted_acc_idx  = UINT_MAX;
        return pinned;
      }
      FD_SPIN_PAUSE();
      continue;
    }

    if( FD_UNLIKELY( claimed ) ) {
      fd_racesan_hook( "accdb_cold_load:claim_wait" );
      FD_SPIN_PAUSE();
      continue;
    }

    if( FD_UNLIKELY( FD_ATOMIC_CAS( &accmeta->executable_size, old_es, old_es | FD_ACCDB_SIZE_CACHE_CLAIM_BIT )!=old_es ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    /* We hold the claim.  Allocate a cache line and publish. */
    ulong size_class = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( old_es ) );
    fd_accdb_cache_line_t * line = acquire_cache_line( accdb, size_class, out_evicted_acc_idx );
    fd_memcpy( line->key.pubkey, accmeta->key.pubkey, 32UL );
    line->key.generation = accmeta->key.generation;
    /* Leave acc_idx at UINT_MAX (the "loading" sentinel) until step 12
       publishes it after the preadv2 fence.  Concurrent threads that
       pin via cache_idx will spin on this in step 13. */
    line->acc_idx = UINT_MAX;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( accmeta->cache_idx ) = FD_ACCDB_ACC_CIDX_PACK( (uint)size_class, (uint)cache_line_idx( accdb, size_class, line ) );
    FD_COMPILER_MFENCE();

    fd_racesan_hook( "accdb_cold_load:pre_valid" );

    /* Atomically set CACHE_VALID_BIT and clear CACHE_CLAIM_BIT.
       Eviction may have flipped CACHE_VALID_BIT on us between our
       claim and now (it preserves CLAIM but can clear VALID); the
       CAS loop tolerates that.  The data length and exec bits stay
       unchanged. */
    for(;;) {
      uint cur = FD_VOLATILE_CONST( accmeta->executable_size );
      uint nxt = (cur & ~FD_ACCDB_SIZE_CACHE_CLAIM_BIT) | FD_ACCDB_SIZE_CACHE_VALID_BIT;
      if( FD_LIKELY( FD_ATOMIC_CAS( &accmeta->executable_size, cur, nxt )==cur ) ) break;
      FD_SPIN_PAUSE();
    }

    *out_exists_in_cache = 0;
    return line;
  }
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
                        int *                 writable,
                        fd_acc_t *            out_accs ) {
  accdb->metrics->acquire_calls++;

  ulong max_acquire_cnt = accdb->shmem->bundle_enabled ? FD_ACCDB_MAX_ACQUIRE_CNT : FD_ACCDB_MAX_TX_ACCOUNT_LOCKS;
  FD_TEST( pubkeys_cnt<=max_acquire_cnt );

  FD_TEST( FD_VOLATILE_CONST( *accdb->my_epoch_slot )==ULONG_MAX );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: epoch store must be globally visible
                     before any subsequent loads so the deferred
                     reclamation scan does not miss us */

  // STEP 1.
  //   Locate each account in the fork and index structure, to determine
  //   if it already exists, its size and other metadata, and which
  //   specific slot (generation) it was last written in.

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;

  fd_racesan_hook( "accdb_acquire:post_root_gen" );

  fd_accdb_accmeta_t * accmetas[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  ulong acc_map_idxs[ FD_ACCDB_MAX_ACQUIRE_CNT ];

  /* Walk the hash chain for each pubkey and take the first visible
     match.  Correctness relies on newer entries always being prepended
     to the chain head, which is guaranteed because replay processes
     writes in slot order and release always inserts at the head.

     CONCURRENCY: This chain walk runs epoch-protected.  A concurrent
     fd_accdb_release may prepend a new node to the same chain while
     we walk it.  This is safe on x86-64 (TSO): the releasing thread
     stores all acc fields (pubkey, generation, map.next, ...) before
     publishing the new head via a CAS on acc_map[idx], and TSO
     guarantees a reading core that observes the new head also observes
     all prior stores to the node.  A reader that does not yet see the
     new head simply sees an older (still valid) version of the chain.
     On weakly-ordered architectures an explicit acquire fence would be
     needed before the chain walk and a release fence in
     fd_accdb_release before the head-pointer store.  Multiple
     concurrent releases serialize on the CAS of the chain head. */
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    acc_map_idxs[ i ] = fd_accdb_hash( pubkeys[ i ], accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
    uint acc = FD_VOLATILE_CONST( accdb->acc_map[ acc_map_idxs[ i ] ] );
    while( acc!=UINT_MAX ) {
      fd_accdb_accmeta_t const * candidate_acc = &accdb->acc_pool[ acc ];
      uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

      fd_racesan_hook( "accdb_acquire:post_next" );

      if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation &&
                        fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val &&
                        !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) ||
                        memcmp( pubkeys[ i ], candidate_acc->key.pubkey, 32UL ) ) {
        acc = next_acc;
        continue;
      }

      break;
    }
    if( FD_UNLIKELY( acc==UINT_MAX ) )                                       accmetas[ i ] = NULL;
    else                                                                     accmetas[ i ] = &accdb->acc_pool[ acc ];

#if FD_TMPL_USE_HANDHOLDING
    if( FD_UNLIKELY( accmetas[ i ] ) ) {
      fd_accdb_accmeta_t const * sel = accmetas[ i ];
      FD_TEST( !memcmp( sel->key.pubkey, pubkeys[ i ], 32UL ) );
      FD_TEST( sel->key.generation<=root_generation ||
               fd_accdb_acc_fork_id( sel )==fork_id.val ||
               descends_set_test( fork->descends, fd_accdb_acc_fork_id( sel ) ) );
      FD_TEST( sel->key.generation<=FD_VOLATILE_CONST( accdb->shmem->generation ) );
    }
#endif

    if( FD_UNLIKELY( accmetas[ i ] && !writable[ i ] && !accmetas[ i ]->lamports ) ) accmetas[ i ] = NULL;

    /* Attribute this acquired account to a size class for per-class
       rate metrics.  Use the account's current size class when known;
       otherwise (new account) bucket as class 0. */
    ulong acq_class = 0UL;
    if( FD_LIKELY( accmetas[ i ] ) ) acq_class = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) );
    if( FD_LIKELY( writable[ i ] ) ) accdb->metrics->writable_accounts_acquired_per_class[ acq_class ]++;
    else                             accdb->metrics->accounts_acquired_per_class[ acq_class ]++;
  }

  // STEP 2.
  //   The two-phase programdata acquire (acquire_a then acquire_b)
  //   works as follows: acquire_a (RESERVATION_TYPE_MAYBE_PROGRAMDATA)
  //   over-reserves one slot in every live size class per candidate
  //   account (reserved_cnt total per class), because it does not yet
  //   know which accounts have programdata or what size class it lands
  //   in.  acquire_b then resolves the actual programdata pubkeys and
  //   re-enters here with RESERVATION_TYPE_ALREADY_RESERVED to refund
  //   the surplus.  Keep one reservation per found programdata account
  //   in its own size class (consumed later by release) and give the
  //   rest back.
  if( FD_UNLIKELY( reservation_type==RESERVATION_TYPE_ALREADY_RESERVED ) ) {
    ulong refund[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
      if( FD_LIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) refund[ j ] = reserved_cnt;
    }
    for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
      if( FD_LIKELY( accmetas[ i ] ) ) {
        ulong cls = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) );
        if( FD_LIKELY( accdb->shmem->cache_class_used[ cls ].val!=ULONG_MAX ) ) {
          FD_TEST( refund[ cls ]>0UL );
          refund[ cls ]--;
        }
      }
    }
    for( ulong k=0UL; k<FD_ACCDB_CACHE_CLASS_CNT; k++ ) {
      if( FD_UNLIKELY( refund[ k ] ) ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ k ].val, refund[ k ] );
    }
  }

  // STEP 3.
  //   We are potentially going to need to read the account data off of
  //   disk into the cache, if the account(s) are not in the cache so
  //   reserve the necessary cache space.  This is done with an "atomic
  //   subtract" spin loop on the cache class counters, which is
  //   actually faster than doing a real CAS on a packed ulong.
  //
  //   For reads, we only need space to copy the account data into a
  //   single right-sized cache line, but for writes ... we need to
  //   reserve one of every size class.  The reason is we are going to
  //   need a 10MiB staging buffer for the executor to write to (it may
  //   grow the account, so needs the max size class).  Even if the
  //   account is already in the 10MiB cache class, we need another one
  //   because a transaction can fail half way, so we need scratch space
  //   to be able to unwind.
  //
  //   So we acquire one of each size class.  Then when the transaction
  //   finishes, if it succeeded, we will copy the data back to the
  //   whichever size-class is now right-sized post execution.
  if( FD_LIKELY( reservation_type==RESERVATION_TYPE_SIMPLE || reservation_type==RESERVATION_TYPE_MAYBE_PROGRAMDATA ) ) {
    ulong requested_buckets[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
    for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
      if( FD_LIKELY( accmetas[ i ] || writable[ i ] ) ) {
        if( FD_LIKELY( accmetas[ i ] ) ) {
          if( FD_UNLIKELY( accdb->shmem->cache_class_used[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) ) ].val!=ULONG_MAX ) ) {
            requested_buckets[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) ) ]++;
          }
        }
        if( FD_UNLIKELY( writable[ i ] ) ) {
          for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
            if( FD_UNLIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) {
              requested_buckets[ j ]++;
            }
          }
        }
      }

      if( FD_LIKELY( reservation_type==RESERVATION_TYPE_MAYBE_PROGRAMDATA ) ) {
        /* Any account could also have an implied reference to a
          programdata account, which we don't know yet ... so we need to
          reserve worst case space if they all went to the same size
          class.  This reservation runs unconditionally per pubkey (not
          gated on accmetas/writable) so that acquire_b can refund based on
          pubkeys_cnt without needing to re-derive the live-account set. */
        for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
          if( FD_UNLIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) {
            requested_buckets[ j ]++;
          }
        }
      }
    }

    /* TODO: This over-reserves cache slots for writable accounts that
       already exist.  For each such account we reserve one line in the
       account's size class (for the read into cache) AND one line in
       every size class (for the write destination buffers). But if the
       account is already resident in cache (which is the common case
       for hot accounts), the read-into-cache line is unnecessary — we
       will get a cache hit in step 4 and never use it.  The fix is to
       probe acc->cache_idx here and skip the per-account size class
       reservation per-account size class reservation when a hit is
       found. This would reduce peak reservation by up to one line per
       writable account per acquire batch, lowering contention on the
       cache class counters and allowing smaller cache provisioning. */

    /* Reserve cache slots by atomically incrementing the shared used
       counters.  If any class exceeds its max, the reservation
       overflowed — subtract back partial grabs and retry. */
    for(;;) {
      int acquire_failed = 0;
      ulong grabbed[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
      for( ulong i=0UL; i<FD_ACCDB_CACHE_CLASS_CNT; i++ ) {
        if( FD_LIKELY( !requested_buckets[ i ] ) ) continue;
        ulong new_used = FD_ATOMIC_ADD_AND_FETCH( &accdb->shmem->cache_class_used[ i ].val, requested_buckets[ i ] );
        if( FD_UNLIKELY( new_used>accdb->shmem->cache_class_max[ i ] ) ) {
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ i ].val, requested_buckets[ i ] );
          acquire_failed = 1;
        } else {
          grabbed[ i ] = requested_buckets[ i ];
        }
        if( FD_UNLIKELY( acquire_failed ) ) {
          accdb->metrics->acquire_failed++;
          for( ulong j=0UL; j<i; j++ ) {
            if( grabbed[ j ] ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ j ].val, grabbed[ j ] );
          }
          FD_SPIN_PAUSE();
          break;
        }
      }
      if( FD_LIKELY( !acquire_failed ) ) break;
    }
  }

  // STEP 4.
  //   For any accounts that are not in cache, we now need to actually
  //   retrieve the cache pointers from our structures.  Space has been
  //   reserved already, so this step is guaranteed to succeed, and is
  //   just pulling the cache lines out of the free lists and marking
  //   them as in-use.
  //
  //   This step is fully lock-free.  Cache hits are pinned with an
  //   atomic CAS on refcnt (cache_try_pin).  Eviction uses the CLOCK
  //   algorithm.  The CAS free list provides immediate recycling of
  //   fully-freed lines.

  int exists_in_cache[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  fd_accdb_cache_line_t * original_cache_line[ FD_ACCDB_MAX_ACQUIRE_CNT ];
  fd_accdb_cache_line_t * destination_cache_lines[ FD_ACCDB_MAX_ACQUIRE_CNT ][ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Saved acc_pool indices of evicted dirty cache lines.  These are
     captured before clearing acc_idx to UINT_MAX on the line struct, so
     that the sentinel protocol (step 14) works correctly while the
     evicted account metadata is still available for writeback in steps
     4 and 6. */
  uint evicted_dest_acc[ FD_ACCDB_MAX_ACQUIRE_CNT ][ FD_ACCDB_CACHE_CLASS_CNT ];
  uint evicted_orig_acc[ FD_ACCDB_MAX_ACQUIRE_CNT ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] && !writable[ i ] ) ) continue;

    original_cache_line[ i ] = NULL;
    if( FD_LIKELY( accmetas[ i ] ) ) {
      if( FD_LIKELY( FD_ACCDB_SIZE_CACHE_VALID( FD_VOLATILE_CONST( accmetas[ i ]->executable_size ) ) ) ) {
        /* Concurrent evict_clear_acc_cache_ref clears VALID then stores
           cache_idx=INVAL.  We may have observed VALID=1 just before the
           writer cleared it, so cidx can read as INVAL here; decoding it
           would yield a wild cache_line pointer.  Skip on INVAL.  Any
           other stale cidx is harmless: cache_try_pin's ABA generation
           check rejects a recycled line. */
        uint cidx = FD_VOLATILE_CONST( accmetas[ i ]->cache_idx );
        if( FD_LIKELY( cidx!=FD_ACCDB_ACC_CIDX_INVAL ) ) {
          fd_accdb_cache_line_t * hit = cache_line( accdb, FD_ACCDB_ACC_CIDX_CLASS( cidx ), FD_ACCDB_ACC_CIDX_IDX( cidx ) );
          fd_racesan_hook( "accdb_acquire:pre_try_pin" );
          original_cache_line[ i ] = cache_try_pin( hit, pubkeys[ i ], accmetas[ i ]->key.generation );
#if FD_TMPL_USE_HANDHOLDING
          if( FD_LIKELY( original_cache_line[ i ] ) ) {
            FD_TEST( original_cache_line[ i ]->key.generation==accmetas[ i ]->key.generation &&
                     !memcmp( original_cache_line[ i ]->key.pubkey, pubkeys[ i ], 32UL ) );
            uint rc = FD_VOLATILE_CONST( original_cache_line[ i ]->refcnt );
            FD_TEST( rc>0U && rc!=FD_ACCDB_EVICT_SENTINEL );
          }
#endif
        }
      }
    }
    exists_in_cache[ i ] = original_cache_line[ i ]!=NULL;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) destination_cache_lines[ i ][ j ] = acquire_cache_line( accdb, j, &evicted_dest_acc[ i ][ j ] );
      if( FD_UNLIKELY( accmetas[ i ] && !original_cache_line[ i ] ) ) {
        original_cache_line[ i ] = cold_load_acc( accdb, accmetas[ i ], pubkeys[ i ], &exists_in_cache[ i ], &evicted_orig_acc[ i ] );
      }
    } else {
      if( FD_UNLIKELY( !original_cache_line[ i ] ) ) {
        original_cache_line[ i ] = cold_load_acc( accdb, accmetas[ i ], pubkeys[ i ], &exists_in_cache[ i ], &evicted_orig_acc[ i ] );
      }
    }
  }

  // STEP 5.
  //   For any cache lines we have retrieved, which we might potentially
  //   be about to trash (by writing stuff in there), we need to write
  //   them back to disk first if they are dirty.  This is the proces of
  //   "persisting" (a/k/a evicting) whatever was previously in the
  //   cache line we are about to use.
  //
  //   This step does not actually persist the data to disk, it just
  //   constructs a series of iovecs (write instructions) which will be
  //   used later to do the actual write.  The reason is that we want to
  //   batch all the writes together into a single writev call, to
  //   minimize overhead, and also keep the actual writes at the end of
  //   the function and independent of the specific control flow, so
  //   that they could be offloaded to another thread of made
  //   asynchronous (e.g. with io_uring) in the future without needing
  //   to change the rest of the logic.

  int write_ops_cnt = 0;
  int write_meta_cnt = 0;
  ulong total_write_sz = 0UL;
  fd_accdb_disk_meta_t write_metas[ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*FD_ACCDB_MAX_ACQUIRE_CNT ];
  struct iovec write_ops[ 2UL*(FD_ACCDB_CACHE_CLASS_CNT+1UL)*FD_ACCDB_MAX_ACQUIRE_CNT ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] && !writable[ i ] ) ) continue;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        if( FD_LIKELY( evicted_dest_acc[ i ][ j ]==UINT_MAX ) ) continue;
        accdb->metrics->accounts_evicted++;
        accdb->metrics->accounts_evicted_per_class[ j ]++;

        fd_accdb_accmeta_t const * evicted = &accdb->acc_pool[ evicted_dest_acc[ i ][ j ] ];
        fd_racesan_hook( "writeback:pre_synth" );
        total_write_sz += sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( evicted->executable_size );
        FD_TEST( write_meta_cnt<(int)(sizeof(write_metas)/sizeof(write_metas[0])) );
        fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->key.pubkey, 32UL );
        write_metas[ write_meta_cnt ].size = FD_ACCDB_SIZE_DATA( evicted->executable_size );
        fd_memcpy( write_metas[ write_meta_cnt ].owner, destination_cache_lines[ i ][ j ]->owner, 32UL );
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
        write_meta_cnt++;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = destination_cache_lines[ i ][ j ]+1UL, .iov_len = FD_ACCDB_SIZE_DATA( evicted->executable_size ) };
      }
      if( FD_UNLIKELY( accmetas[ i ] && !exists_in_cache[ i ] && evicted_orig_acc[ i ]!=UINT_MAX ) ) {
        fd_accdb_accmeta_t const * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
        accdb->metrics->accounts_evicted++;
        accdb->metrics->accounts_evicted_per_class[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( evicted->executable_size ) ) ]++;

        total_write_sz += sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( evicted->executable_size );
        FD_TEST( write_meta_cnt<(int)(sizeof(write_metas)/sizeof(write_metas[0])) );
        fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->key.pubkey, 32UL );
        write_metas[ write_meta_cnt ].size = FD_ACCDB_SIZE_DATA( evicted->executable_size );
        fd_memcpy( write_metas[ write_meta_cnt ].owner, original_cache_line[ i ]->owner, 32UL );
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
        write_meta_cnt++;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = original_cache_line[ i ]+1UL, .iov_len = FD_ACCDB_SIZE_DATA( evicted->executable_size ) };
      }
    } else {
      if( FD_LIKELY( exists_in_cache[ i ] || evicted_orig_acc[ i ]==UINT_MAX ) ) continue;
      fd_accdb_accmeta_t const * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
      accdb->metrics->accounts_evicted++;
      accdb->metrics->accounts_evicted_per_class[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( evicted->executable_size ) ) ]++;
      total_write_sz += sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( evicted->executable_size );
      FD_TEST( write_meta_cnt<(int)(sizeof(write_metas)/sizeof(write_metas[0])) );
      fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->key.pubkey, 32UL );
      write_metas[ write_meta_cnt ].size = FD_ACCDB_SIZE_DATA( evicted->executable_size );
      fd_memcpy( write_metas[ write_meta_cnt ].owner, original_cache_line[ i ]->owner, 32UL );
      write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
      write_meta_cnt++;
      write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = original_cache_line[ i ]+1UL, .iov_len = FD_ACCDB_SIZE_DATA( evicted->executable_size ) };
    }
  }

  // STEP 6-7.
  //   Compute the file offset for the writes we are about to do and
  //   build the pending offset table.  The common case is a single
  //   atomic fetch-add on the write head, reserving a contiguous
  //   region.  If the total eviction batch is too large to fit in one
  //   partition (extremely unlikely — requires many dirty 10MiB
  //   evictions), fall back to per-entry allocation so that each
  //   individual write fits in a single partition.
  //
  //   The actual stores to evicted->offset_fork and line->persisted
  //   are deferred until after pwritev2 completes (Step 9-10), so
  //   a concurrent acquire spinning on offset==FD_ACCDB_OFF_INVAL
  //   does not proceed to preadv2 from a location that hasn't been
  //   written.
  int                     pending_cnt = 0;
  fd_accdb_accmeta_t *    pending_accs [ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*FD_ACCDB_MAX_ACQUIRE_CNT ];
  ulong                   pending_offs [ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*FD_ACCDB_MAX_ACQUIRE_CNT ];
  fd_accdb_cache_line_t * pending_lines[ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*FD_ACCDB_MAX_ACQUIRE_CNT ];

  ulong file_offset;
  int   batch_contiguous;
  if( FD_LIKELY( total_write_sz && total_write_sz<=accdb->shmem->partition_sz ) ) {
    file_offset      = allocate_next_write( accdb, total_write_sz );
    batch_contiguous = 1;
  } else {
    file_offset      = 0UL;
    batch_contiguous = 0;
  }

  ulong cumulative_offset = 0UL;
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] && !writable[ i ] ) ) continue;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        if( FD_LIKELY( evicted_dest_acc[ i ][ j ]==UINT_MAX ) ) continue;

        fd_accdb_accmeta_t * evicted = &accdb->acc_pool[ evicted_dest_acc[ i ][ j ] ];
        ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( evicted->executable_size );
        /* xchg-to-INVAL atomically captures the old offset and prevents
           a concurrent acc_unlink from also reading and freeing it (the
           xchg there will see INVAL and skip).  Step 10 republishes the
           new offset; the spinner at line ~2082 tolerates the transient
           INVAL.  Same pattern as the overwrite path at line ~2388. */
        ulong old_off = fd_accdb_acc_xchg_offset( evicted, FD_ACCDB_OFF_INVAL );
        if( FD_LIKELY( old_off!=FD_ACCDB_OFF_INVAL ) ) {
          fd_accdb_shmem_bytes_freed( accdb->shmem, old_off, entry_sz );
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
        }
        FD_TEST( pending_cnt<(int)(sizeof(pending_accs)/sizeof(pending_accs[0])) );
        pending_accs [ pending_cnt ] = evicted;
        if( FD_LIKELY( batch_contiguous ) ) pending_offs[ pending_cnt ] = file_offset + cumulative_offset;
        else                                pending_offs[ pending_cnt ] = allocate_next_write( accdb, entry_sz );
        pending_lines[ pending_cnt ] = destination_cache_lines[ i ][ j ];
        pending_cnt++;
        cumulative_offset += entry_sz;
        FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
      }
      if( FD_UNLIKELY( accmetas[ i ] && !exists_in_cache[ i ] && evicted_orig_acc[ i ]!=UINT_MAX ) ) {
        fd_accdb_accmeta_t * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
        ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( evicted->executable_size );
        ulong old_off = fd_accdb_acc_xchg_offset( evicted, FD_ACCDB_OFF_INVAL );
        if( FD_LIKELY( old_off!=FD_ACCDB_OFF_INVAL ) ) {
          fd_accdb_shmem_bytes_freed( accdb->shmem, old_off, entry_sz );
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
        }
        FD_TEST( pending_cnt<(int)(sizeof(pending_accs)/sizeof(pending_accs[0])) );
        pending_accs [ pending_cnt ] = evicted;
        if( FD_LIKELY( batch_contiguous ) ) pending_offs[ pending_cnt ] = file_offset + cumulative_offset;
        else                                pending_offs[ pending_cnt ] = allocate_next_write( accdb, entry_sz );
        pending_lines[ pending_cnt ] = original_cache_line[ i ];
        pending_cnt++;
        cumulative_offset += entry_sz;
        FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
      }
    } else {
      if( FD_LIKELY( exists_in_cache[ i ] || evicted_orig_acc[ i ]==UINT_MAX ) ) continue;

      fd_accdb_accmeta_t * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
      ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( evicted->executable_size );
      ulong old_off = fd_accdb_acc_xchg_offset( evicted, FD_ACCDB_OFF_INVAL );
      if( FD_LIKELY( old_off!=FD_ACCDB_OFF_INVAL ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, old_off, entry_sz );
        FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
      }
      FD_TEST( pending_cnt<(int)(sizeof(pending_accs)/sizeof(pending_accs[0])) );
      pending_accs [ pending_cnt ] = evicted;
      if( FD_LIKELY( batch_contiguous ) ) pending_offs[ pending_cnt ] = file_offset + cumulative_offset;
      else                                pending_offs[ pending_cnt ] = allocate_next_write( accdb, entry_sz );
      pending_lines[ pending_cnt ] = original_cache_line[ i ];
      pending_cnt++;
      cumulative_offset += entry_sz;
      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->disk_used_bytes, entry_sz );
    }
  }

  // STEP 8.
  //   Fill the output entries with cache pointers and metadata based on
  //   the accounts we have located and the cache lines we have
  //   reserved.

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] && !writable[ i ] ) ) {
      out_accs[ i ].data = NULL;
      out_accs[ i ].data_len = 0UL;
      out_accs[ i ].lamports = 0UL;
      out_accs[ i ].executable = 0;
      memset( out_accs[ i ].owner, 0, 32UL );
      fd_memcpy( out_accs[ i ].pubkey, pubkeys[ i ], 32UL );
      out_accs[ i ].prior_lamports = 0UL;
      out_accs[ i ].prior_data_len = 0UL;
      out_accs[ i ].prior_executable = 0;
      memset( out_accs[ i ].prior_owner, 0, 32UL );
      out_accs[ i ].prior_data = NULL;
      out_accs[ i ].commit = 0;
      out_accs[ i ].pd_write = 0;
      out_accs[ i ]._writable = 0;
      out_accs[ i ]._original_size_class = ULONG_MAX;
      out_accs[ i ]._original_cache_idx = ULONG_MAX;
      continue;
    }

    if( FD_LIKELY( !writable[ i ] ) ) out_accs[ i ].data = (uchar *)(original_cache_line[ i ]+1UL);
    else                              out_accs[ i ].data = (uchar *)(destination_cache_lines[ i ][ 7UL ]+1UL);
    /* Tombstone reset: agave's account loader returns AccountSharedData::default()
       (System owner, empty data, exec=0) for any account with lamports==0.
       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L199-L228 */
    fd_racesan_hook( "accdb_acquire:pre_step7_meta" );
    int tombstone = accmetas[ i ] && accmetas[ i ]->lamports==0UL;
    out_accs[ i ].data_len = ( accmetas[ i ] && !tombstone ) ? FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) : 0UL;
    out_accs[ i ].executable = ( accmetas[ i ] && !tombstone ) ? FD_ACCDB_SIZE_EXEC( accmetas[ i ]->executable_size ) : 0;
    fd_racesan_hook( "accdb_acquire:mid_step7_meta" );
    out_accs[ i ].lamports = accmetas[ i ] ? accmetas[ i ]->lamports : 0UL;
    if( FD_UNLIKELY( !accmetas[ i ] ) ) memset( out_accs[ i ].owner, 0, 32UL );
    /* For accmetas[i] != NULL, the owner is copied from the cache line
       below in step 15, after step 12 has populated it from disk for
       cold loads. */

    out_accs[ i ].prior_lamports   = out_accs[ i ].lamports;
    out_accs[ i ].prior_data_len   = out_accs[ i ].data_len;
    out_accs[ i ].prior_executable = out_accs[ i ].executable;
    out_accs[ i ].prior_data       = (uchar *)(original_cache_line[ i ] ? (original_cache_line[ i ]+1UL) : NULL);

    out_accs[ i ].commit = 0;
    out_accs[ i ].pd_write = 0;
    out_accs[ i ]._writable = writable[ i ];
    if( FD_UNLIKELY( writable[ i ] && accmetas[ i ] ) ) out_accs[ i ]._overwrite = accdb->fork_pool[ fork_id.val ].shmem->generation==accmetas[ i ]->key.generation;
    else                                            out_accs[ i ]._overwrite = 0;

    FD_TEST( out_accs[ i ].data_len<=(10UL<<20) );
    FD_TEST( !out_accs[ i ]._overwrite || accdb->fork_pool[ fork_id.val ].shmem->generation==accmetas[ i ]->key.generation );

#if FD_TMPL_USE_HANDHOLDING
    if( FD_UNLIKELY( !writable[ i ] && accmetas[ i ] && !tombstone ) ) {
      ulong cls = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) );
      FD_TEST( fd_accdb_ptr_in_region( accdb, cls, out_accs[ i ].data ) );
    }
#endif

    if( FD_UNLIKELY( writable[ i ] ) ) {
      out_accs[ i ]._fork_id = fork_id.val;
      out_accs[ i ]._generation = fork->shmem->generation;
      out_accs[ i ]._acc_map_idx = acc_map_idxs[ i ];
    }
    fd_memcpy( out_accs[ i ].pubkey, pubkeys[ i ], 32UL );

    if( FD_UNLIKELY( !accmetas[ i ] ) ) {
      out_accs[ i ]._original_size_class = ULONG_MAX;
      out_accs[ i ]._original_cache_idx = ULONG_MAX;
    } else {
      out_accs[ i ]._original_size_class = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) );
      out_accs[ i ]._original_cache_idx = cache_line_idx( accdb, out_accs[ i ]._original_size_class, original_cache_line[ i ] );
    }

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        out_accs[ i ]._write.destination_cache_idx[ j ] = cache_line_idx( accdb, j, destination_cache_lines[ i ][ j ] );
      }
    }
  }

  // STEP 9.
  //   Write the dirty eviction data to disk and publish the new offsets
  //   BEFORE constructing read iovecs.  This is critical: step 4 may
  //   have evicted a dirty cache line belonging to another account in
  //   the same batch whose acc->offset is still FD_ACCDB_OFF_INVAL.
  //   The read-iovec loop below spin-waits on
  //   offset!=FD_ACCDB_OFF_INVAL, so publishing evicted offsets first
  //   prevents an intra-batch deadlock where the thread waits on an
  //   offset that only it can resolve.
  if( FD_LIKELY( batch_contiguous ) ) {
    /* Fast path: all evictions fit in one contiguous region.  Use the
       pre-built iovec array for a single batched pwritev2 call. */
    ulong bytes_written = 0UL;
    struct iovec * write_ptr = write_ops;
    while( FD_LIKELY( bytes_written<total_write_sz ) ) {
      long result = pwritev2( accdb->fd, write_ptr, fd_int_min( write_ops_cnt, IOV_MAX ), (long)(file_offset+bytes_written), 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, pwritev2() returned 0 at offset %lu with %lu bytes remaining",
                                                     file_offset+bytes_written, total_write_sz-bytes_written ));
      bytes_written += (ulong)result;
      accdb->metrics->bytes_written += (ulong)result;
      accdb->metrics->write_ops++;

      while( write_ops_cnt && (ulong)result>=(ulong)write_ptr[ 0 ].iov_len ) {
        result -= (long)write_ptr[ 0 ].iov_len;
        write_ptr++;
        write_ops_cnt--;
      }
      if( FD_LIKELY( write_ops_cnt ) ) {
        write_ptr[ 0 ].iov_base = (uchar *)write_ptr[ 0 ].iov_base + result;
        write_ptr[ 0 ].iov_len -= (ulong)result;
      }
    }
  } else {
    /* Slow path: total eviction batch exceeds a single partition.
       Write each entry individually using its own allocated offset.
       This path is only taken in extreme edge cases (many concurrent
       dirty 10 MiB evictions). */
    struct iovec * wp = write_ops;
    for( int k=0; k<pending_cnt; k++ ) {
      ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( pending_accs[ k ]->executable_size );
      ulong entry_off = pending_offs[ k ];
      struct iovec entry_iovs[2] = { wp[0], wp[1] };
      wp += 2;

      ulong written = 0UL;
      while( FD_LIKELY( written<entry_sz ) ) {
        long result = pwritev2( accdb->fd, entry_iovs, 2, (long)(entry_off+written), 0 );
        if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
        else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
        else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, pwritev2() returned 0 at offset %lu with %lu bytes remaining", entry_off+written, entry_sz-written ));
        written += (ulong)result;
        accdb->metrics->bytes_written += (ulong)result;
        accdb->metrics->write_ops++;

        for( int v=0; v<2; v++ ) {
          if( (ulong)result>=(ulong)entry_iovs[ v ].iov_len ) {
            result -= (long)entry_iovs[ v ].iov_len;
            entry_iovs[ v ].iov_len = 0UL;
          } else {
            entry_iovs[ v ].iov_base = (uchar *)entry_iovs[ v ].iov_base + result;
            entry_iovs[ v ].iov_len -= (ulong)result;
            break;
          }
        }
      }
    }
  }

  // STEP 10.
  //   Now that the data is on disk, publish the evicted account offsets
  //   so concurrent acquire threads spinning on
  //   offset==FD_ACCDB_OFF_INVAL can proceed.  The fence ensures
  //   pwritev2 data is globally visible before the offset stores.
  FD_COMPILER_MFENCE();
  for( int k=0; k<pending_cnt; k++ ) {
    pending_accs[ k ]->offset_fork = fd_accdb_acc_pack_offset_fork( pending_offs[ k ], fd_accdb_acc_fork_id(pending_accs[ k ]) );
    pending_lines[ k ]->persisted = 1;
  }

  // STEP 11.
  //   Now construct iovecs for any reads we need to do of accounts into
  //   the cache.  For reading accounts, we read them directly into the
  //   sole cache line we took (and maybe just evicted).  For writing
  //   accounts, we read them into the right sized cache line, and later
  //   it will be copied to the staging buffer.  This is to prevent
  //   repeatedly reading the same account off disk into cache, if it is
  //   being written cold multiple times and every write fails.

  ulong read_ops_cnt = 0UL;
  ulong read_offsets[ FD_ACCDB_CACHE_CLASS_CNT*FD_ACCDB_MAX_ACQUIRE_CNT ];
  uchar * read_bases[ FD_ACCDB_CACHE_CLASS_CNT*FD_ACCDB_MAX_ACQUIRE_CNT ];
  ulong read_sizes[ FD_ACCDB_CACHE_CLASS_CNT*FD_ACCDB_MAX_ACQUIRE_CNT ];
  struct iovec read_ops[ FD_ACCDB_CACHE_CLASS_CNT*FD_ACCDB_MAX_ACQUIRE_CNT ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] || exists_in_cache[ i ] ) ) continue;

    accdb->metrics->accounts_not_found_per_class[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) ) ]++;

    /* Tombstones (lamports==0) have no on-disk payload to read, and
       background_advance_root may unlink the acc and never assign it a
       disk offset, so the offset_fork spin below would hang forever.
       Step 15's tombstone reset zeros the owner for these accounts. */
    if( FD_UNLIKELY( !accmetas[ i ]->lamports ) ) continue;

    /* We are guaranteed that if an account is in the cache, the bytes
       are available (all cache operations are atomic via refcnt CAS),
       but we are not guaranteed that if something is _not_ in the cache
       that it has been written back to disk yet.  In paticular, if we
       are trying to read an account that another thread is in the
       process of evicting, we know they removed it from the cache, but
       we don't know exactly when they will have written it back fully
       to disk, so we may need to wait for that here.

       Compaction may concurrently relocate this record, but
       epoch-based safe reclamation guarantees the source partition
       is not freed until all epoch-protected operations that could
       have snapshotted the old offset have exited.  So the data at the
       snapshotted offset remains stable for the duration of our
       read and no post-read validation is needed. */
    ulong off_packed = FD_VOLATILE_CONST( accmetas[ i ]->offset_fork );
    while( FD_UNLIKELY( (off_packed & FD_ACCDB_OFF_MASK)==FD_ACCDB_OFF_INVAL ) ) {
      FD_SPIN_PAUSE();
      off_packed = FD_VOLATILE_CONST( accmetas[ i ]->offset_fork );
    }
    fd_racesan_hook( "accdb_coldload:pre_iovec" );

    read_offsets[ read_ops_cnt ] = fd_accdb_acc_offset(accmetas[ i ]) + offsetof(fd_accdb_disk_meta_t, owner);
    read_bases[ read_ops_cnt ]   = original_cache_line[ i ]->owner;
    read_sizes[ read_ops_cnt ]   = 32UL + FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size );
    read_ops[ read_ops_cnt++ ]   = (struct iovec){ .iov_base = original_cache_line[ i ]->owner, .iov_len = 32UL + FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size ) };
  }

  // STEP 12.
  //   Almost done... now do the actual reads of accounts into cache,
  //   using the iovecs we constructed.  This is basically the same loop
  //   as the writes, but with preadv2 instead of pwritev2, and that the
  //   reads are not necessarily all contiguous, but occur at random
  //   offsets.
  //
  //   CONCURRENCY: The compaction tile may concurrently relocate a
  //   record we are about to read (both are epoch-protected).  Epoch-
  //   based safe reclamation guarantees the source partition is not
  //   freed until all epoch-protected operations that could have
  //   snapshotted the old offset have exited, so the data at the
  //   remains stable for the duration of this read — no post-read
  //   validation or retry is needed.
  for( ulong i=0UL; i<read_ops_cnt; i++ ) {
    ulong bytes_read = 0UL;
    while( FD_LIKELY( bytes_read<read_sizes[ i ] ) ) {
      long result = preadv2( accdb->fd, &read_ops[ i ], 1, (long)(read_offsets[ i ]+bytes_read), 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "preadv2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                     read_offsets[ i ]+bytes_read, read_sizes[ i ] ));
      fd_accdb_partition_read_bump( accdb, read_offsets[ i ]+bytes_read, (ulong)result );
      bytes_read += (ulong)result;
      accdb->metrics->bytes_read += (ulong)result;
      accdb->metrics->read_ops++;

      read_ops[ i ].iov_base = read_bases[ i ] + bytes_read;
      read_ops[ i ].iov_len  = read_sizes[ i ] - bytes_read;
    }
  }

  // STEP 13.
  //   Publish the real acc index for any cache lines we just loaded
  //   from disk, so concurrent threads spinning on acc_idx==UINT_MAX
  //   can proceed.  The fence ensures all preadv2 data is visible
  //   before the sentinel is cleared.
  FD_COMPILER_MFENCE();
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] || exists_in_cache[ i ] ) ) continue;
    FD_VOLATILE( original_cache_line[ i ]->acc_idx ) = (uint)( accmetas[ i ] - accdb->acc_pool );
    FD_TEST( FD_VOLATILE_CONST( original_cache_line[ i ]->acc_idx )==(uint)( accmetas[ i ] - accdb->acc_pool ) );
  }

  // STEP 14.
  //   Spin-wait for any cache lines found via acc->cache_idx that are
  //   still being loaded by another thread's preadv2.  The loading
  //   thread sets acc_idx to UINT_MAX before publishing cache_idx
  //   and publishes the real acc index after its read completes.
  //   This step is placed as late as possible to give the loading
  //   thread maximum time to finish before we need to spin.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] && !writable[ i ] ) ) continue;

    if( FD_UNLIKELY( !original_cache_line[ i ] ) ) continue;
    if( FD_LIKELY( FD_VOLATILE_CONST( original_cache_line[ i ]->acc_idx )!=UINT_MAX ) ) goto step13_check;
    accdb->metrics->accounts_waited++;
    while( FD_UNLIKELY( FD_VOLATILE_CONST( original_cache_line[ i ]->acc_idx )==UINT_MAX ) ) {
      fd_racesan_hook( "accdb_acquire:step14_load_wait" );
      FD_SPIN_PAUSE();
    }
  step13_check:;
#if FD_TMPL_USE_HANDHOLDING
    FD_TEST( original_cache_line[ i ]->key.generation==accmetas[ i ]->key.generation &&
             !memcmp( original_cache_line[ i ]->key.pubkey, pubkeys[ i ], 32UL ) );
#endif
  }

  // STEP 15.
  //   Now that all reads from disk into original_cache_line have
  //   completed (and any concurrent loaders have published their
  //   acc_idx in step 14), copy the owner into the output entries.
  //   This must happen here rather than in step 8 because the cache
  //   line owner is only valid post-read for cold loads.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] ) ) continue;
    fd_racesan_hook( "accdb_acquire:pre_step14_owner" );
    /* Tombstone reset: see STEP 7 comment. */
    if( FD_UNLIKELY( accmetas[ i ]->lamports==0UL ) ) {
      memset( out_accs[ i ].owner,       0, 32UL );
      memset( out_accs[ i ].prior_owner, 0, 32UL );
    } else {
      fd_memcpy( out_accs[ i ].owner,       original_cache_line[ i ]->owner, 32UL );
      fd_memcpy( out_accs[ i ].prior_owner, original_cache_line[ i ]->owner, 32UL );
    }
  }

  // STEP 16.
  //   Finally, copy any accounts we are writing into the staging
  //   buffers, so they occupy a 10MiB cache line for the execution
  //   system.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accmetas[ i ] || !writable[ i ] ) ) continue;

    ulong copy_sz = (ulong)FD_ACCDB_SIZE_DATA( accmetas[ i ]->executable_size );
    fd_memcpy( destination_cache_lines[ i ][ 7UL ]+1UL, original_cache_line[ i ]+1UL, copy_sz );
    accdb->metrics->bytes_copied += copy_sz;
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
                    int *                 writable,
                    fd_acc_t *            out_accs ) {
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_PHASE_A );
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_OPEN;
  fd_accdb_acquire_inner( accdb, fork_id, RESERVATION_TYPE_ALREADY_RESERVED, reserved_cnt, pubkeys_cnt, pubkeys, writable, out_accs );
}

/* release_inner drains one group of acquired accs but does NOT change the
   handle's acquire_state.  The public fd_accdb_release / fd_accdb_release_ab
   wrappers below own the state transition (a single-phase release closes
   the bracket; release_ab drains both phase groups then closes). */
static void
release_inner( fd_accdb_t * accdb,
               ulong        accs_cnt,
               fd_acc_t *   accs ) {
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_OPEN );

  {
    ulong prev = FD_VOLATILE_CONST( *accdb->my_epoch_slot );
    FD_TEST( prev==ULONG_MAX || prev<=FD_VOLATILE_CONST( accdb->shmem->epoch ) );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: epoch store must be globally visible
                     before any subsequent loads so the deferred
                     reclamation scan does not miss us. */

  // STEP 1.
  //   For each cache line which was written to in the 10MiB staging
  //   buffer, we may need to copy to the data out to a right sized
  //   cache line.  Figuring out the target cache line is non-obvious,
  //   but follows the more complete logic below this, we just pull the
  //   memcpy out so they are not done inside the cache lock.

  for( ulong i=0UL; i<accs_cnt; i++ ) {
    if( FD_UNLIKELY( accs[ i ]._original_size_class==ULONG_MAX && !accs[ i ]._writable ) ) continue;

#if FD_TMPL_USE_HANDHOLDING
    if( FD_LIKELY( accs[ i ]._original_size_class!=ULONG_MAX ) ) {
      FD_TEST( accs[ i ]._original_cache_idx<accdb->shmem->cache_class_max[ accs[ i ]._original_size_class ] );
    }
    if( FD_UNLIKELY( accs[ i ].commit ) ) FD_TEST( accs[ i ]._writable );
#endif

    if( FD_LIKELY( !accs[ i ]._writable || !accs[ i ].commit ) ) continue;
#if FD_TMPL_USE_HANDHOLDING
    if( FD_UNLIKELY( accs[ i ]._overwrite ) ) {
      FD_TEST( accs[ i ]._writable );
      FD_TEST( accs[ i ]._original_cache_idx!=ULONG_MAX );
      FD_TEST( accs[ i ]._original_size_class!=ULONG_MAX );
    }
#endif

    ulong original_size_class = accs[ i ]._original_size_class;
    ulong new_size_class = fd_accdb_cache_class( accs[ i ].data_len );
    if( FD_UNLIKELY( new_size_class==7UL ) ) continue;

    fd_accdb_cache_line_t * target_cache_line;
    if( FD_LIKELY( original_size_class==new_size_class && accs[ i ]._overwrite ) ) target_cache_line = cache_line( accdb, original_size_class, accs[ i ]._original_cache_idx );
    else                                                                              target_cache_line = cache_line( accdb, new_size_class, accs[ i ]._write.destination_cache_idx[ new_size_class ] );

    fd_accdb_cache_line_t * staging_line = cache_line( accdb, 7UL, accs[ i ]._write.destination_cache_idx[ 7UL ] );

    fd_racesan_hook( "accdb_commit:pre_owner_write" );

#if FD_TMPL_USE_HANDHOLDING
    if( FD_UNLIKELY( original_size_class==new_size_class && accs[ i ]._overwrite ) ) {
      uint rc = FD_VOLATILE_CONST( target_cache_line->refcnt );
      FD_TEST( target_cache_line->key.generation==accs[ i ]._generation &&
               !memcmp( target_cache_line->key.pubkey, accs[ i ].pubkey, 32UL ) &&
               rc>0U &&
              rc!=FD_ACCDB_EVICT_SENTINEL );
    }
#endif

    fd_memcpy( target_cache_line->owner, accs[ i ].owner, 32UL );
    fd_memcpy( target_cache_line+1UL, staging_line+1UL, accs[ i ].data_len );
    accdb->metrics->bytes_copied += accs[ i ].data_len;
  }

  // STEP 2.
  //   Now update the metadata structures and free lists to reflect the
  //   fact that we are done with these cache lines.  This is fully
  //   atomic with CLOCK.

  for( ulong i=0UL; i<accs_cnt; i++ ) {
    if( FD_UNLIKELY( accs[ i ]._original_size_class==ULONG_MAX && !accs[ i ]._writable ) ) continue;

    ulong original_size_class = accs[ i ]._original_size_class;
    fd_accdb_cache_line_t * original_cache_line = accs[ i ]._original_cache_idx==ULONG_MAX ? NULL : cache_line( accdb, original_size_class, accs[ i ]._original_cache_idx );
    /* For overwrite commits, defer the refcnt decrement on
       original_cache_line until after invalidation completes.  If
       we dropped refcnt to 0 here, a concurrent CLOCK sweep could
       CAS(refcnt, 0, EVICT_SENTINEL) and steal the line before we
       get to invalidate it, causing data corruption.
       Non-overwrite and non-commit paths unpin
       immediately because they never invalidate the original line. */
    if( FD_LIKELY( original_cache_line ) ) {
#if FD_TMPL_USE_HANDHOLDING
      FD_TEST( original_cache_line->refcnt>0U );
#endif
      if( FD_LIKELY( !accs[ i ]._writable || !accs[ i ].commit || !accs[ i ]._overwrite ) ) {
        FD_ATOMIC_FETCH_AND_SUB( &original_cache_line->refcnt, 1U );
      }
    }

    if( FD_LIKELY( !accs[ i ]._writable ) ) {
      /* For readonly accounts, mark as recently used so the CLOCK
         algorithm gives it a second chance before eviction. */
#if FD_TMPL_USE_HANDHOLDING
      FD_TEST( original_cache_line );
#endif
      original_cache_line->referenced = 1;
      continue;
    }

    fd_accdb_cache_line_t * destination_cache_lines[ FD_ACCDB_CACHE_CLASS_CNT ];
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) destination_cache_lines[ j ] = cache_line( accdb, j, accs[ i ]._write.destination_cache_idx[ j ] );
    int destination_committed[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};

    if( FD_LIKELY( !accs[ i ].commit ) ) {
      /* If it's writable but it didn't commit, all of the destination
         cache lines (including the staging buffer which is trashed) are
         unused and can be pushed to the CAS free list for immediate
         reuse.  Whatever buffer it was accessing also gets marked as
         recently used. */
      if( FD_LIKELY( original_cache_line ) ) original_cache_line->referenced = 1;
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        /* acquire_cache_line via CLOCK leaves line->acc_idx pointing
           at the prior owner.  cache_free_push consumers (CLOCK,
           background_preevict) skip lines only when acc_idx==UINT_MAX
           AND gen==UINT_MAX; if we leave the stale acc_idx, a future
           CLOCK pick would call line 849/853 against the wrong acc
           and corrupt its cache_idx/valid. */
        destination_cache_lines[ j ]->acc_idx        = UINT_MAX;
        destination_cache_lines[ j ]->key.generation = UINT_MAX;
        destination_cache_lines[ j ]->persisted = 1;
        while( FD_UNLIKELY( FD_ATOMIC_CAS( &destination_cache_lines[ j ]->refcnt, 1U, 0U )!=1U ) ) {
          fd_racesan_hook( "accdb_release:dest_refcnt_wait" );
          FD_SPIN_PAUSE();
        }
        cache_free_push( accdb, j, destination_cache_lines[ j ] );
      }
      continue;
    }

    ulong new_size_class = fd_accdb_cache_class( accs[ i ].data_len );
    uint original_acc_idx = original_cache_line ? original_cache_line->acc_idx : UINT_MAX;
    fd_accdb_cache_line_t * committed_line;

    /* For overwrites, invalidate the on-disk offset BEFORE removing
       the cache acc.  This ensures a concurrent acquire that misses
       the cache will see offset==FD_ACCDB_OFF_INVAL and spin-wait,
       rather than reading stale on-disk bytes from the old location.
       The CAS-loop exchange also serializes with a concurrent
       compaction CAS (old_offset -> dest_offset). */
    ulong old_offset = FD_ACCDB_OFF_INVAL;
    if( FD_LIKELY( accs[ i ]._overwrite ) ) {
      fd_accdb_accmeta_t * ow_accmeta = &accdb->acc_pool[ original_acc_idx ];
      fd_racesan_hook( "accdb_overwrite:pre_xchg_offset" );
      old_offset = fd_accdb_acc_xchg_offset( ow_accmeta, FD_ACCDB_OFF_INVAL );
      if( FD_LIKELY( old_offset!=FD_ACCDB_OFF_INVAL ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, old_offset, (ulong)FD_ACCDB_SIZE_DATA(ow_accmeta->executable_size)+sizeof(fd_accdb_disk_meta_t) );
        FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->shmetrics->disk_used_bytes, (ulong)FD_ACCDB_SIZE_DATA(ow_accmeta->executable_size)+sizeof(fd_accdb_disk_meta_t) );
      }
    }

    if( FD_UNLIKELY( new_size_class==7UL ) ) {
      /* The account belongs in the largest size class, and we already
         have it resident in a 10MiB buffer anyway, so no need to copy
         back.  If we are "overwriting" (same generation as the account
         came from), then the original can be discarded (pushed to
         the CAS free list) and removed from the cache. */
      destination_cache_lines[ 7UL ]->persisted = 0;
      destination_committed[ 7UL ] = 1;
      if( FD_LIKELY( accs[ i ]._overwrite ) ) {
        /* Atomically clear acc.VALID and acc.cache_idx BEFORE freeing
           the line, so a reader cannot observe acc.VALID=1 with
           acc.cache_idx pointing at a line that has been recycled to
           another acc.  evict_clear_acc_cache_ref uses the CLAIM
           protocol to serialize with cold_load_acc. */
        evict_clear_acc_cache_ref( &accdb->acc_pool[ original_acc_idx ], original_size_class, accs[ i ]._original_cache_idx );

        /* Drop our pin, then try to claim the line exclusively for
           freeing.  A concurrent reader that pinned the line via
           cache_try_pin BEFORE evict_clear_acc_cache_ref completed
           may still hold a reference here (its ABA check on
           line->key.generation is not synchronized with our writes
           to that field).  CAS(refcnt, 0, EVICT_SENTINEL) succeeds
           only when no such reader is outstanding; on failure we
           must NOT free the line — leave acc_idx/key.generation
           intact so CLOCK can reclaim it once the reader unpins.
           At that point CLOCK's call to evict_clear_acc_cache_ref
           is a no-op (acc.cache_idx no longer matches expected_cidx)
           and the line is safely repurposed. */
        FD_ATOMIC_FETCH_AND_SUB( &original_cache_line->refcnt, 1U );
        if( FD_LIKELY( FD_ATOMIC_CAS( &original_cache_line->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL )==0U ) ) {
          original_cache_line->persisted = 1;
          original_cache_line->acc_idx   = UINT_MAX;
          original_cache_line->key.generation = UINT_MAX;
          original_cache_line->refcnt    = 0;
          cache_free_push( accdb, original_size_class, original_cache_line );
        }
      }
      committed_line = destination_cache_lines[ 7UL ];
    } else {
      /* The account started in some arbitrary size class, transited
         through a 10MiB staging buffer, and is now being written back
         to some arbitrary (non-10MiB) size class, so we need to copy it
         there.  The staging buffer is discarded.  If we are going to
         a different size class, and we are "overwriting" (same
         generation), then the original can also be discarded, but if
         we are staying in the same size class, we can reuse the cache
         line in place. */
      fd_accdb_cache_line_t * target_cache_line;
      if( FD_LIKELY( original_size_class==new_size_class ) ) {
        if( FD_LIKELY( accs[ i ]._overwrite ) ) {
          /* a reader holding a stale acc->cache_idx from this line's
             previous life may hold a transient cache_try_pin pin, so
             our own pin only bounds refcnt from below. */
          uint ow_rc = FD_VOLATILE_CONST( original_cache_line->refcnt );
          FD_TEST( ow_rc>0U && ow_rc!=FD_ACCDB_EVICT_SENTINEL );
          original_cache_line->key.generation = UINT_MAX;
          /* Keep refcnt>=1 through the reuse window so CLOCK cannot
             steal the line between invalidation and re-publish. The
             pin is released in the destination cleanup loop after
             acc->cache_idx has been republished. */
          original_cache_line->acc_idx = UINT_MAX;
          target_cache_line = original_cache_line;
        } else {
          target_cache_line = destination_cache_lines[ new_size_class ];
          destination_committed[ new_size_class ] = 1;
        }
      } else {
        if( FD_LIKELY( accs[ i ]._overwrite ) ) {
          /* Atomically clear acc.VALID and acc.cache_idx BEFORE freeing
             the line, so a reader cannot observe acc.VALID=1 with
             acc.cache_idx pointing at a line that has been recycled to
             another acc.  evict_clear_acc_cache_ref uses the CLAIM
             protocol to serialize with cold_load_acc.  See the
             size_class==7 path above for the refcnt CAS rationale. */
          evict_clear_acc_cache_ref( &accdb->acc_pool[ original_acc_idx ], original_size_class, accs[ i ]._original_cache_idx );
          FD_ATOMIC_FETCH_AND_SUB( &original_cache_line->refcnt, 1U );
          if( FD_LIKELY( FD_ATOMIC_CAS( &original_cache_line->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL )==0U ) ) {
            original_cache_line->persisted = 1;
            original_cache_line->acc_idx   = UINT_MAX;
            original_cache_line->key.generation = UINT_MAX;
            original_cache_line->refcnt    = 0;
            cache_free_push( accdb, original_size_class, original_cache_line );
          }
        }

        destination_committed[ new_size_class ] = 1;
        target_cache_line = destination_cache_lines[ new_size_class ];
      }

      target_cache_line->persisted = 0;
      /* If target is the original cache line (overwrite, same size
         class), mark as referenced directly since the cleanup loop
         only handles destination lines. */
      if( FD_LIKELY( !destination_committed[ new_size_class ] ) ) target_cache_line->referenced = 1;
      committed_line = target_cache_line;
    }

    /* For non-overwrite commits, the original cache line (if any) still
       holds valid ancestor data but is no longer pinned.  Mark it as
       recently used so the CLOCK algorithm retains it. */
    if( FD_UNLIKELY( !accs[ i ]._overwrite && original_cache_line ) ) {
      original_cache_line->referenced = 1;
    }

    /* Handle every destination cache line: committed ones keep
       refcnt>=1 until acc->cache_idx is published (the deferred
       unpin happens after the publish below), uncommitted ones are
       fully freed to the CAS free list. */
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
      if( destination_committed[ j ] ) {
        destination_cache_lines[ j ]->referenced = 1;
      } else {
        /* See note above (no-commit path): clear stale acc_idx/gen
           before pushing, otherwise CLOCK can pick this line and
           stomp the prior owner's cache_idx/valid.  CAS on refcnt for
           the same stray-pin reason as the no-commit path. */
        destination_cache_lines[ j ]->acc_idx        = UINT_MAX;
        destination_cache_lines[ j ]->key.generation = UINT_MAX;
        destination_cache_lines[ j ]->persisted = 1;
        while( FD_UNLIKELY( FD_ATOMIC_CAS( &destination_cache_lines[ j ]->refcnt, 1U, 0U )!=1U ) ) {
          fd_racesan_hook( "accdb_release:dest_refcnt_wait" );
          FD_SPIN_PAUSE();
        }
        cache_free_push( accdb, j, destination_cache_lines[ j ] );
      }
    }

    /* Update the accounts index for this committed write.  For an
       overwrite (same fork+generation), update the existing acc
       acc in place.  Otherwise allocate a new acc, prepend it
       to the hash chain, and record the write in a txn linked to
       the fork so advance_root can clean up old versions. */
    if( FD_LIKELY( accs[ i ]._overwrite ) ) {
      accdb->metrics->accounts_committed_overwrite_per_class[ new_size_class ]++;
      committed_line->acc_idx = original_acc_idx;

      fd_accdb_accmeta_t * accmeta = &accdb->acc_pool[ original_acc_idx ];
      /* The offset was already atomically swapped to FD_ACCDB_OFF_INVAL
         and bytes freed above, so just update the metadata and
         re-publish the cache location.  CAS-loop preserves CLAIM bit
         (a concurrent evict_clear_acc_cache_ref or acc_unlink may
         hold it) and clears VALID; a plain store would clobber CLAIM
         and break those protocols. */
      uint pd = accs[ i ].pd_write ? FD_ACCDB_SIZE_PD_WRITE_BIT : 0U;
      for(;;) {
        uint cur = FD_VOLATILE_CONST( accmeta->executable_size );
        uint nxt = (cur & (FD_ACCDB_SIZE_CACHE_CLAIM_BIT|FD_ACCDB_SIZE_PD_WRITE_BIT))
                 | FD_ACCDB_SIZE_PACK( (uint)accs[ i ].data_len, accs[ i ].executable )
                 | pd;
        if( FD_LIKELY( FD_ATOMIC_CAS( &accmeta->executable_size, cur, nxt )==cur ) ) break;
        FD_SPIN_PAUSE();
      }
      accmeta->lamports = accs[ i ].lamports;
      fd_racesan_hook( "accdb_overwrite:mid_inplace" );

      fd_memcpy( committed_line->owner, accs[ i ].owner, 32UL );
      fd_memcpy( committed_line->key.pubkey, accmeta->key.pubkey, 32UL );
      committed_line->key.generation = accmeta->key.generation;
      committed_line->acc_idx = original_acc_idx;
      FD_VOLATILE( accmeta->cache_idx ) = FD_ACCDB_ACC_CIDX_PACK( (uint)new_size_class, (uint)cache_line_idx( accdb, new_size_class, committed_line ) );
      /* Atomic OR so a concurrent evict_clear_acc_cache_ref's CLAIM
         clear (FETCH_AND_AND with ~CLAIM) cannot be lost by an RMW
         race with a plain |= store. */
      FD_ATOMIC_FETCH_AND_OR( &accmeta->executable_size, FD_ACCDB_SIZE_CACHE_VALID_BIT );

      /* Now that acc->cache_idx is published, unpin so CLOCK can
         eventually evict it.  For same-size overwrites, committed_line
         IS the reused original_cache_line.  For cross-size overwrites,
         committed_line is a destination line whose refcnt decrement was
         deferred from the cleanup loop. */
      FD_ATOMIC_FETCH_AND_SUB( &committed_line->refcnt, 1U );
      committed_line->referenced = 1;
    } else {
      accdb->metrics->accounts_committed_new_per_class[ new_size_class ]++;
      fd_accdb_accmeta_t * accmeta = acc_pool_acquire( accdb->acc_pool_join );
      FD_TEST( accmeta );
      ulong acc_idx = acc_pool_idx( accdb->acc_pool_join, accmeta );
      fd_memcpy( accmeta->key.pubkey, accs[ i ].pubkey, 32UL );
      accmeta->lamports        = accs[ i ].lamports;
      accmeta->executable_size = FD_ACCDB_SIZE_PACK( (uint)accs[ i ].data_len, accs[ i ].executable )
                               | (accs[ i ].pd_write ? FD_ACCDB_SIZE_PD_WRITE_BIT : 0U);
      accmeta->key.generation  = accs[ i ]._generation;
      accmeta->offset_fork     = fd_accdb_acc_pack_offset_fork( FD_ACCDB_OFF_INVAL, accs[ i ]._fork_id );

      /* Publish in the cache BEFORE the acc_map head so that a
         concurrent acquire that finds this acc in the hash chain will
         also find a cache hit, rather than inserting a conflicting
         placeholder cache acc. */
      committed_line->acc_idx = (uint)acc_idx;
      fd_memcpy( committed_line->owner, accs[ i ].owner, 32UL );
      fd_memcpy( committed_line->key.pubkey, accmeta->key.pubkey, 32UL );
      committed_line->key.generation = accmeta->key.generation;
      FD_VOLATILE( accmeta->cache_idx ) = FD_ACCDB_ACC_CIDX_PACK( (uint)new_size_class, (uint)cache_line_idx( accdb, new_size_class, committed_line ) );
      /* Atomic OR so a concurrent evict_clear_acc_cache_ref's CLAIM
         clear (FETCH_AND_AND with ~CLAIM) cannot be lost by an RMW
         race with a plain |= store. */
      FD_ATOMIC_FETCH_AND_OR( &accmeta->executable_size, FD_ACCDB_SIZE_CACHE_VALID_BIT );

      /* Now that acc->cache_idx is published, unpin it so
         CLOCK can eventually evict it. */
      FD_ATOMIC_FETCH_AND_SUB( &committed_line->refcnt, 1U );
      committed_line->referenced = 1;

      /* CAS loop to prepend to the hash chain.  Succeeds on the first
         try in most cases, but a concurrent acc_unlink CAS removing
         the old head can change acc_map[idx] between our load and
         CAS.  Multiple concurrent releases may also race on the head
         pointer — the CAS retry handles this. */
      for(;;) {
        uint old_head = FD_VOLATILE_CONST( accdb->acc_map[ accs[ i ]._acc_map_idx ] );
        accmeta->map.next = old_head;
        FD_COMPILER_MFENCE();
        fd_racesan_hook( "accdb_release:pre_chain_cas" );
        if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->acc_map[ accs[ i ]._acc_map_idx ], old_head, (uint)acc_idx )==old_head ) ) break;
        FD_SPIN_PAUSE();
      }

      /* CONCURRENCY: The cache acc is published before the acc_map
         head so that a concurrent fd_accdb_acquire reader that
         observes the new head also finds a cache hit, preventing
         duplicate cache insertion.

         (1) The CAS on acc_map[idx] serializes head-pointer mutations
             from concurrent releases onto the same chain without any
             external lock.

         (2) The FD_COMPILER_MFENCE above ensures stores to the acc node
             fields (pubkey, lamports, size, generation, fork_id,
             offset, map.next) are ordered before the CAS that publishes
             the new head.  On x86-64 (TSO), hardware also guarantees
             this, but the compiler fence is needed to prevent the
             compiler from reordering the stores.  A reader that
             observes the new head is guaranteed to see a fully
             initialized node.  A reader that has not yet seen the new
             head simply traverses the previous (still valid) chain.

         (3) A concurrent acc_unlink (advance_root / purge) may CAS the
             head away between our load and CAS here.  The CAS retry
             loop handles this. */

      fd_accdb_txn_t * txn = txn_pool_acquire( accdb->txn_pool );
      FD_TEST( txn ); /* Sized so it always succeeds */
      txn->acc_map_idx  = (uint)accs[ i ]._acc_map_idx;
      txn->acc_pool_idx = (uint)acc_idx;
      uint txn_idx = (uint)txn_pool_idx( accdb->txn_pool, txn );
      for(;;) {
        uint old_head = FD_VOLATILE_CONST( accdb->fork_pool[ accs[ i ]._fork_id ].shmem->txn_head );
        txn->fork.next = old_head;
        if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->fork_pool[ accs[ i ]._fork_id ].shmem->txn_head, old_head, txn_idx )==old_head ) ) break;
        FD_SPIN_PAUSE();
      }

      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->shmetrics->accounts_total, 1UL );
    }
  }

  // STEP 3.
  //   Finally, we release the cache class reservations we took at the
  //   beginning when we acquired these cache lines.  Credits return
  //   directly to the shared pool so other threads can use them
  //   immediately.

  ulong refund[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
  for( ulong i=0UL; i<accs_cnt; i++ ) {
    if( FD_LIKELY( accs[ i ]._original_size_class!=ULONG_MAX ) ) {
      if( FD_UNLIKELY( accdb->shmem->cache_class_used[ accs[ i ]._original_size_class ].val!=ULONG_MAX ) ) {
        refund[ accs[ i ]._original_size_class ]++;
      }
    }
    if( FD_UNLIKELY( accs[ i ]._writable ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        if( FD_UNLIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) {
          refund[ j ]++;
        }
      }
    }
  }
  for( ulong k=0UL; k<FD_ACCDB_CACHE_CLASS_CNT; k++ ) {
    if( FD_UNLIKELY( refund[ k ] ) ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ k ].val, refund[ k ] );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

void
fd_accdb_release( fd_accdb_t * accdb,
                  ulong        accs_cnt,
                  fd_acc_t *   accs ) {
  FD_TEST( accdb->acquire_state==FD_ACCDB_ACQUIRE_STATE_OPEN );
  release_inner( accdb, accs_cnt, accs );
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
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
  accdb->acquire_state = FD_ACCDB_ACQUIRE_STATE_IDLE;
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

void
fd_accdb_read_one_nocache( fd_accdb_t *       accdb,
                           fd_accdb_fork_id_t fork_id,
                           uchar const *      pubkey,
                           ulong *            out_lamports,
                           int *              out_executable,
                           uchar *            out_owner,
                           uchar *            out_data,
                           ulong *            out_data_len ) {
  /* Publish epoch — protects against compaction freeing the partition
     under us during the preadv2 path.  This is the only write the
     readonly joiner makes into accdb shmem (and the pointer it stores
     through is mapped through a separately-mmap'd writable page that
     aliases shmem->joiner_epochs[idx]). */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();

  /// STEP 1.
  ///   Walk the hash chain at acc_map[hash(pubkey)] using the same
  //    visibility test as fd_accdb_acquire_inner.  See that function
  //    for the detailed safety argument under concurrent prepend.
  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  uint acc_idx = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  fd_accdb_accmeta_t const * accmeta = NULL;
  while( acc_idx!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate = &accdb->acc_pool[ acc_idx ];
    uint next_idx = FD_VOLATILE_CONST( candidate->map.next );
    if( FD_UNLIKELY( (candidate->key.generation>root_generation &&
                      fd_accdb_acc_fork_id(candidate)!=fork_id.val &&
                      !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate) )) ) ||
                     memcmp( pubkey, candidate->key.pubkey, 32UL ) ) {
      acc_idx = next_idx;
      continue;
    }
    accmeta = candidate;
    break;
  }

  if( FD_UNLIKELY( !accmeta ) ) {
    accdb->metrics->accounts_acquired_per_class[ 0 ]++;
    *out_lamports = 0UL;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    return;
  }

  /// STEP 2.
  ///   Snapshot acc fields.  The acc element's metadata is effectively
  ///   immutable from the perspective of cross-fork readers (see the
  ///   comment block in fd_accdb.h about cross-fork reads). */
  uint  snap_es       = FD_VOLATILE_CONST( accmeta->executable_size );
  uint  snap_gen      = accmeta->key.generation;
  ulong snap_lamports = accmeta->lamports;
  uint  snap_cidx     = FD_VOLATILE_CONST( accmeta->cache_idx );
  ulong data_len      = (ulong)FD_ACCDB_SIZE_DATA( snap_es );
  int   executable    = FD_ACCDB_SIZE_EXEC( snap_es );

  accdb->metrics->accounts_acquired_per_class[ fd_accdb_cache_class( data_len ) ]++;

  if( FD_UNLIKELY( !snap_lamports ) ) {
    *out_lamports = 0UL;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    return;
  }

  /// STEP 3.
  ///    Cache hit fast path with try-read-test (ABA) loop.  Same
  ///    primitives as cache_try_pin: re-check key.generation + pubkey
  ///    before and after the bulk copy, and bail to the disk path if the
  ///    line was claimed for eviction (refcnt ==
  ///    FD_ACCDB_EVICT_SENTINEL).  No CAS on refcnt, we never pin the
  ///    line.
  if( FD_LIKELY( FD_ACCDB_SIZE_CACHE_VALID( snap_es ) && snap_cidx!=FD_ACCDB_ACC_CIDX_INVAL ) ) {
    ulong cls = FD_ACCDB_ACC_CIDX_CLASS( snap_cidx );
    ulong idx = FD_ACCDB_ACC_CIDX_IDX  ( snap_cidx );
    fd_accdb_cache_line_t * line = cache_line( accdb, cls, idx );

    for(;;) {
      uint gen0 = FD_VOLATILE_CONST( line->key.generation );
      uint rc0  = FD_VOLATILE_CONST( line->refcnt );
      uint ai0  = FD_VOLATILE_CONST( line->acc_idx );
      if( FD_UNLIKELY( rc0==FD_ACCDB_EVICT_SENTINEL ) ) goto miss;
      if( FD_UNLIKELY( gen0!=snap_gen ) ) goto miss;
      if( FD_UNLIKELY( memcmp( line->key.pubkey, pubkey, 32UL ) ) ) goto miss;
      /* acc_idx==UINT_MAX is the "loading" sentinel set by cold_load_acc
         before the preadv2 fills the line.  CACHE_VALID can be observed
         set while the bytes are still stale, so fall to the disk path
         (which spins on offset_fork and reads from the file) rather
         than copying garbage. */
      if( FD_UNLIKELY( ai0==UINT_MAX ) ) goto miss;

      FD_COMPILER_MFENCE();
      memcpy( out_owner, line->owner, 32UL );
      memcpy( out_data,  (uchar const *)(line+1UL), data_len );
      FD_COMPILER_MFENCE();

      uint gen1 = FD_VOLATILE_CONST( line->key.generation );
      uint rc1  = FD_VOLATILE_CONST( line->refcnt );
      uint ai1  = FD_VOLATILE_CONST( line->acc_idx );
      if( FD_UNLIKELY( rc1==FD_ACCDB_EVICT_SENTINEL ) ) goto miss;
      if( FD_UNLIKELY( gen1!=snap_gen ) ) goto miss;
      if( FD_UNLIKELY( memcmp( line->key.pubkey, pubkey, 32UL ) ) ) goto miss;
      if( FD_UNLIKELY( ai1==UINT_MAX ) ) goto miss;

      *out_lamports   = snap_lamports;
      *out_executable = executable;
      *out_data_len   = data_len;
      accdb->metrics->bytes_copied += data_len;
      FD_COMPILER_MFENCE();
      FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
      return;
    }
  }

miss:;
  accdb->metrics->accounts_not_found_per_class[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( snap_es ) ) ]++;

  /// STEP 4.
  ///   Disk path.  Spin until the writer publishes a real offset
  ///   (matches STEP 10 of fd_accdb_acquire_inner).  Compaction may
  ///   concurrently relocate the record, but our published epoch
  ///   prevents the source partition from being freed until we exit
  ///   our critical section, so the bytes at the snapshotted offset
  ///   remain stable for the duration of the read.
  fd_racesan_hook( "accdb_nocache:pre_offset" );
  ulong off_packed = FD_VOLATILE_CONST( accmeta->offset_fork );
  if( FD_UNLIKELY( (off_packed & FD_ACCDB_OFF_MASK)==FD_ACCDB_OFF_INVAL ) ) {
    accdb->metrics->accounts_waited++;
    while( FD_UNLIKELY( ((off_packed=FD_VOLATILE_CONST( accmeta->offset_fork )) & FD_ACCDB_OFF_MASK)==FD_ACCDB_OFF_INVAL ) ) FD_SPIN_PAUSE();
  }
  ulong off = off_packed & FD_ACCDB_OFF_MASK;
  fd_racesan_hook( "accdb_nocache:pre_preadv2" );

  struct iovec iovs[ 2 ] = {
    { .iov_base = out_owner, .iov_len = 32UL     },
    { .iov_base = out_data,  .iov_len = data_len },
  };
  ulong total = 32UL+data_len;
  ulong start = off+offsetof( fd_accdb_disk_meta_t, owner );
  ulong got   = 0UL;
  int   nio   = data_len ? 2 : 1;
  while( FD_LIKELY( got<total ) ) {
    long result = preadv2( accdb->fd, iovs, nio, (long)(start+got), 0 );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "preadv2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents", start+got, total ));
    fd_accdb_partition_read_bump( accdb, start+got, (ulong)result );
    got += (ulong)result;
    accdb->metrics->bytes_read += (ulong)result;
    accdb->metrics->read_ops++;

    long r = result;
    for( int v=0; v<nio; v++ ) {
      if( (ulong)r>=iovs[ v ].iov_len ) {
        r -= (long)iovs[ v ].iov_len;
        iovs[ v ].iov_len = 0UL;
      } else {
        iovs[ v ].iov_base = (uchar *)iovs[ v ].iov_base + r;
        iovs[ v ].iov_len -= (ulong)r;
        break;
      }
    }
  }

  *out_lamports   = snap_lamports;
  *out_executable = executable;
  *out_data_len   = data_len;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
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
  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
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
                             ulong *            out_data_len ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE();

  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
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
  if( FD_LIKELY( acc!=UINT_MAX ) ) {
    fd_accdb_accmeta_t const * m = &accdb->acc_pool[ acc ];
    uint es   = FD_VOLATILE_CONST( m->executable_size );
    gen_match = ( m->key.generation==fork->shmem->generation );
    pd        = gen_match && FD_ACCDB_SIZE_PD_WRITE( es );
    len       = FD_ACCDB_SIZE_DATA( es );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;

  *out_pd_write = pd;
  if( gen_match ) *out_data_len = len;
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
  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
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

/* cache_bg_evict pre-evicts cache lines in the background to keep the
   per-class CAS free lists populated ahead of demand.  For each class
  whose immediately available capacity has dropped below low_water,
  a bounded CLOCK sweep claims lines, writes dirty ones to disk, and
  pushes them onto the free list until available capacity reaches
  target.  Immediately available capacity includes both the CAS free
  list and the never-initialized tail of the class, since foreground
  allocators can consume either path without evicting resident data.

  Budget: at most 256 CLOCK ticks per class per invocation to keep the
  background loop responsive.  The function is called every tick of
  fd_accdb_background, so large refills happen across several ticks
  rather than blocking.  The low_water / target thresholds are static
  per-class watermarks computed at initialization; pre-eviction only
  converts resident lines into free-list entries and does not consume
  cache-slot reservations.

  force: when non-zero, ignore the watermark and sweep every line in
  every class.  Always 0 in normal operation; used only by
  test_accdb_racesan to deterministically exercise the writeback path
  without manufacturing real cache pressure. */

static void
background_preevict( fd_accdb_t * accdb,
                     int *        charge_busy,
                     int          force ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong target = shmem->cache_free_target[ c ];
    ulong max_c  = shmem->cache_class_max[ c ];
    ulong init   = fd_ulong_min( FD_VOLATILE_CONST( shmem->cache_class_init[ c ].val ), max_c );
    ulong freec  = FD_VOLATILE_CONST( shmem->cache_free_cnt[ c ].val );
    ulong live   = init>freec ? init-freec : 0UL;
    ulong avail  = max_c-live;
    if( FD_LIKELY( !force && avail>=shmem->cache_free_low_water[ c ] ) ) continue;

    *charge_busy = 1;

    ulong budget  = force ? init : 256UL;
    ulong evicted = 0UL;
    if( FD_UNLIKELY( force ) ) target = max_c; /* sweep everything */

    for( ulong tick=0UL; tick<budget && avail+evicted<target; tick++ ) {
      /* Only sweep the lazily initialized prefix.  cache_class_init
         may transiently exceed max_c during the acquire_cache_line
         overflow/undo path, so clamp it before using it as the wrap
         bound. */
      init = fd_ulong_min( FD_VOLATILE_CONST( shmem->cache_class_init[ c ].val ), max_c );
      if( FD_UNLIKELY( !init ) ) break;

      ulong hand = FD_ATOMIC_FETCH_AND_ADD( &shmem->clock_hand[ c ].val, 1UL ) % init;

      fd_accdb_cache_line_t * line = cache_line( accdb, c, hand );

      if( FD_UNLIKELY( line->key.generation==UINT_MAX && line->acc_idx==UINT_MAX ) ) continue;

      uint rc = FD_VOLATILE_CONST( line->refcnt );
      if( FD_UNLIKELY( rc ) ) continue;

      if( FD_UNLIKELY( line->referenced ) ) {
        line->referenced = 0;
        continue;
      }

      if( FD_UNLIKELY( FD_ATOMIC_CAS( &line->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL )!=0U ) ) continue;

      uint acc_idx = line->acc_idx;
#if FD_TMPL_USE_HANDHOLDING
      uint line_gen FD_FN_UNUSED = line->key.generation;
#endif
      if( FD_LIKELY( acc_idx!=UINT_MAX ) ) {
        evict_clear_acc_cache_ref( &accdb->acc_pool[ acc_idx ], c, hand );
      }
      line->key.generation = UINT_MAX;
      if( FD_UNLIKELY( !line->persisted && acc_idx!=UINT_MAX ) ) {
        fd_accdb_accmeta_t * accmeta = &accdb->acc_pool[ acc_idx ];
        fd_racesan_hook( "preevict:pre_synth" );
#if FD_TMPL_USE_HANDHOLDING
        FD_TEST( line_gen==accmeta->key.generation &&
                 !memcmp( line->key.pubkey, accmeta->key.pubkey, 32UL ) );
#endif
        ulong entry_sz = sizeof(fd_accdb_disk_meta_t)+(ulong)FD_ACCDB_SIZE_DATA( accmeta->executable_size );

        /* Atomically swap the old offset to FD_ACCDB_OFF_INVAL so that
           a concurrent compaction CAS (old_offset -> dest_offset)
           cannot succeed between our read and our later store of
           the new file_off.  Without the exchange, compaction could
           relocate the record, then our plain store would overwrite
           the relocated offset, leaving the compaction destination
           as unreachable dead space whose bytes are never freed. */
        ulong old_offset = fd_accdb_acc_xchg_offset( accmeta, FD_ACCDB_OFF_INVAL );
        if( FD_LIKELY( old_offset!=FD_ACCDB_OFF_INVAL ) ) {
          fd_accdb_shmem_bytes_freed( shmem, old_offset, entry_sz );
          FD_ATOMIC_FETCH_AND_SUB( &shmem->shmetrics->disk_used_bytes, entry_sz );
        }

        fd_accdb_disk_meta_t meta;
        fd_memcpy( meta.pubkey, accmeta->key.pubkey, 32UL );
        meta.size = FD_ACCDB_SIZE_DATA( accmeta->executable_size );
        fd_memcpy( meta.owner, line->owner, 32UL );

        struct iovec iovs[ 2UL ] = {
          { .iov_base = &meta,              .iov_len = sizeof(fd_accdb_disk_meta_t) },
          { .iov_base = (void *)(line+1UL), .iov_len = FD_ACCDB_SIZE_DATA( accmeta->executable_size ) }
        };

        ulong file_off = allocate_next_write( accdb, entry_sz );
        ulong written = 0UL;
        while( written<entry_sz ) {
          long result = pwritev2( accdb->fd, iovs, 2, (long)(file_off+written), 0 );
          if( FD_UNLIKELY( result==-1 && errno==EINTR ) ) continue;
          else if( FD_UNLIKELY( result<=0 ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
          written += (ulong)result;
          accdb->metrics->bytes_written += (ulong)result;
          accdb->metrics->write_ops++;

          for( int v=0; v<2; v++ ) {
            if( (ulong)result>=iovs[ v ].iov_len ) {
              result -= (long)iovs[ v ].iov_len;
              iovs[ v ].iov_len = 0UL;
            } else {
              iovs[ v ].iov_base = (uchar *)iovs[ v ].iov_base + result;
              iovs[ v ].iov_len -= (ulong)result;
              break;
            }
          }
        }

        FD_COMPILER_MFENCE();
        accmeta->offset_fork = fd_accdb_acc_pack_offset_fork( file_off, fd_accdb_acc_fork_id(accmeta) );
        FD_ATOMIC_FETCH_AND_ADD( &shmem->shmetrics->disk_used_bytes, entry_sz );

        accdb->metrics->accounts_preevicted++;
        accdb->metrics->accounts_preevicted_per_class[ c ]++;
      }

      line->persisted      = 1;
      line->acc_idx        = UINT_MAX;
      line->key.generation = UINT_MAX;
      line->refcnt         = 0;
      cache_free_push( accdb, c, line );
      evicted++;
    }
  }
}

int
fd_accdb_snapshot_write_one( fd_accdb_t *       accdb,
                             fd_accdb_fork_id_t fork_id,
                             uchar const *      pubkey,
                             ulong              slot,
                             ulong              lamports,
                             ulong              data_len,
                             int                executable,
                             ulong *            out_replaced_lamports ) {
  /* Snapshot slots are stored in the 32-bit cache_idx scratch field
     during loading.  Reject anything that would truncate. */
  if( FD_UNLIKELY( slot>UINT_MAX ) ) FD_LOG_ERR(( "snapshot slot %lu exceeds 2^32-1, accdb format must be widened", slot ));

  int incremental = fork_id.val!=USHORT_MAX;

  fd_accdb_fork_t * fork     = NULL;
  uint              fork_gen = 0U;
  if( FD_UNLIKELY( incremental ) ) {
    fork     = &accdb->fork_pool[ fork_id.val ];
    fork_gen = fork->shmem->generation;
  }

  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);

  *out_replaced_lamports = 0UL;

  fd_accdb_accmeta_t * accmeta = NULL;
  int cross_fork = 0; /* incremental only: existing entry from different fork */

  ulong next_acc = accdb->acc_map[ hash ];
  while( next_acc!=UINT_MAX ) {
    fd_accdb_accmeta_t * candidate_acc = &accdb->acc_pool[ next_acc ];
    if( FD_UNLIKELY( !memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) ) {
      if( FD_LIKELY( (ulong)candidate_acc->cache_idx>slot ) ) {
        /* Still advance the write head so snapwr and snapin stay in
           sync — snapwr unconditionally writes every account to disk.
           Mark the space as immediately freed since it is dead on
           arrival. */
        ulong dead_sz  = sizeof(fd_accdb_disk_meta_t)+data_len;
        ulong dead_off = allocate_next_write( accdb, dead_sz );
        fd_accdb_shmem_bytes_freed( accdb->shmem, dead_off, dead_sz );
        return -1;
      }
      if( FD_UNLIKELY( incremental ) && candidate_acc->key.generation!=fork_gen ) {
        /* Cross-snapshot override: don't replace in-place; insert a
           new entry alongside the old one so purge can revert. */
        cross_fork = 1;
        *out_replaced_lamports = candidate_acc->lamports;
      } else {
        /* Same-fork duplicate (or full-snapshot mode): replace in-place */
        accmeta = candidate_acc;
      }
      break;
    }
    next_acc = candidate_acc->map.next;
  }

  int replace = !!accmeta;

  if( FD_UNLIKELY( !accmeta ) ) {
    accmeta = acc_pool_acquire( accdb->acc_pool_join );
    if( FD_UNLIKELY( !accmeta ) ) FD_LOG_ERR(( "accounts database ran out of space during snapshot loading, increase [accounts.max_accounts], current value is %lu", acc_pool_ele_max( accdb->acc_pool_join ) ));

    uint acc_idx = (uint)acc_pool_idx( accdb->acc_pool_join, accmeta );

    fd_memcpy( accmeta->key.pubkey, pubkey, 32UL );
    if( FD_UNLIKELY( !incremental && accdb->shmem->root_fork_id.val==USHORT_MAX ) ) {
      FD_LOG_ERR(( "snapshot_write_one called without a root fork attached" ));
    }
    accmeta->key.generation = incremental ? fork_gen : accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
    accmeta->map.next = accdb->acc_map[ hash ];
    accdb->acc_map[ hash ] = acc_idx;

    /* In incremental mode, record this insert in the fork's txn list
       so purge can find and unlink it on failure. */
    if( FD_UNLIKELY( incremental ) ) {
      fd_accdb_txn_t * txn = txn_pool_acquire( accdb->txn_pool );
      if( FD_UNLIKELY( !txn ) ) FD_LOG_ERR(( "txn pool exhausted during incremental snapshot loading" ));
      txn->acc_map_idx  = (uint)hash;
      txn->acc_pool_idx = acc_idx;
      uint txn_idx      = (uint)txn_pool_idx( accdb->txn_pool, txn );
      txn->fork.next          = fork->shmem->txn_head;
      fork->shmem->txn_head   = txn_idx;
    }
  }

  if( FD_UNLIKELY( replace ) ) {
    /* The old version's disk space is now dead. */
    ulong old_sz = sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( accmeta->executable_size );
    fd_accdb_shmem_bytes_freed( accdb->shmem, fd_accdb_acc_offset( accmeta ), old_sz );
    accdb->shmem->shmetrics->disk_used_bytes -= old_sz;
    *out_replaced_lamports = accmeta->lamports;
  }

  accmeta->cache_idx = (uint)slot;
  accmeta->lamports = lamports;
  accmeta->executable_size = FD_ACCDB_SIZE_PACK( (uint)data_len, executable );
  ulong entry_sz = sizeof(fd_accdb_disk_meta_t)+data_len;
  ulong file_off = allocate_next_write( accdb, entry_sz );
  accmeta->offset_fork = incremental ? fd_accdb_acc_pack_offset_fork( file_off, fork_id.val ) : file_off;
  accdb->shmem->shmetrics->disk_used_bytes += entry_sz;
  if( !replace ) accdb->shmem->shmetrics->accounts_total++;

  return ( replace || cross_fork ) ? 2 : 1;
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
                               ulong *             accounts_ignored,
                               ulong *             accounts_replaced,
                               ulong *             accounts_loaded,
                               ulong *             out_replaced_lamports,
                               ulong *             out_ignored_lamports ) {
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

  ulong ignored          = 0UL;
  ulong replaced         = 0UL;
  ulong loaded           = 0UL;
  ulong cross_replaced   = 0UL; /* cross-fork overrides (subset of replaced) */
  ulong replaced_lamports = 0UL;
  ulong ignored_lamports  = 0UL;

  /* Snapshot slots are stored in the 32-bit cache_idx scratch field
     during loading.  Reject anything that would truncate. */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( slots[ i ]>UINT_MAX ) ) FD_LOG_ERR(( "snapshot slot %lu exceeds 2^32-1, accdb format must be widened", slots[ i ] ));
  }

  /* Phase 1: compute hashes and prefetch chain heads. */

  ulong                hashes[ 8 ];
  fd_accdb_accmeta_t * existing[ 8 ];       /* same-fork dup or full-snapshot replace */
  fd_accdb_accmeta_t * cross_existing[ 8 ]; /* cross-fork dup (incremental only) */
  int                  skip[ 8 ];

  for( ulong i=0UL; i<cnt; i++ ) {
    hashes[ i ]          = fd_accdb_hash( pubkeys[ i ], seed ) & chain_msk;
    existing[ i ]        = NULL;
    cross_existing[ i ]  = NULL;
    skip[ i ]            = 0;

    /* Prefetch the chain head and first pool element on the chain */
    __builtin_prefetch( &accdb->acc_map[ hashes[ i ] ], 1, 1 );
  }

  /* Phase 2: walk chains looking for duplicates.  By now the chain
     heads prefetched above should be warm in L1/L2.  If the existing
     entry has a higher slot, mark skip.  Otherwise, save the existing
     entry pointer for in-place update (matching write_one semantics).
     In incremental mode, cross-fork entries are saved separately so
     they can be left in place while a new entry is inserted. */

  for( ulong i=0UL; i<cnt; i++ ) {
    ulong next_acc = accdb->acc_map[ hashes[ i ] ];

    if( FD_LIKELY( next_acc!=UINT_MAX ) ) {
      __builtin_prefetch( &accdb->acc_pool[ next_acc ], 0, 1 );
    }

    while( next_acc!=UINT_MAX ) {
      fd_accdb_accmeta_t * candidate = &accdb->acc_pool[ next_acc ];

      if( FD_LIKELY( candidate->map.next!=UINT_MAX ) ) {
        __builtin_prefetch( &accdb->acc_pool[ candidate->map.next ], 0, 1 );
      }

      if( FD_UNLIKELY( !memcmp( pubkeys[ i ], candidate->key.pubkey, 32UL ) ) ) {
        if( FD_LIKELY( (ulong)candidate->cache_idx>slots[ i ] ) ) {
          skip[ i ] = 1;
        } else if( FD_UNLIKELY( incremental ) && candidate->key.generation!=fork_gen ) {
          cross_existing[ i ] = candidate;
        } else {
          existing[ i ] = candidate;
        }
        break;
      }
      next_acc = candidate->map.next;
    }
  }

  /* Phase 2b: reject intra-batch duplicate pubkeys.  Snapin always
     populates a batch from a single AppendVec, so every slot in the
     batch is identical and a duplicate pubkey means the same account
     appears twice at the same slot — i.e. a corrupt snapshot per the
     Agave spec.  We have no principled way to pick a winner; return
     -1 so the caller can flag the snapshot malformed.  Batches are
     bounded (<=8) so the O(n^2) scan is trivial. */

  for( ulong i=1UL; i<cnt; i++ ) {
    for( ulong j=0UL; j<i; j++ ) {
      if( hashes[ j ]!=hashes[ i ] ) continue;
      if( FD_UNLIKELY( !memcmp( pubkeys[ j ], pubkeys[ i ], 32UL ) ) ) {
        FD_LOG_WARNING(( "corrupt snapshot: duplicate pubkey within a single batch (entries %lu and %lu, slots %lu and %lu)", j, i, slots[ j ], slots[ i ] ));
        return -1;
      }
    }
  }

  /* Phase 3: commit.  For each account either update the existing
     entry in-place (replace), allocate and insert at the chain head
     (new), or skip entirely (ignore).  This matches the
     insert/replace/ignore semantics of write_one. */

  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( skip[ i ] ) ) {
      /* Still advance the write head so snapwr and snapin stay in
         sync — snapwr unconditionally writes every account to disk.
         Mark the space as immediately freed since it is dead on
         arrival. */
      ulong dead_sz  = sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];
      ulong dead_off = allocate_next_write( accdb, dead_sz );
      fd_accdb_shmem_bytes_freed( accdb->shmem, dead_off, dead_sz );
      ignored_lamports += lamports[ i ];
      ignored++;
      continue;
    }

    fd_accdb_accmeta_t * accmeta;

    if( FD_UNLIKELY( existing[ i ] ) ) {
      accmeta = existing[ i ];
      /* The old version's disk space is now dead. */
      ulong old_sz = sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( accmeta->executable_size );
      fd_accdb_shmem_bytes_freed( accdb->shmem, fd_accdb_acc_offset( accmeta ), old_sz );
      accdb->shmem->shmetrics->disk_used_bytes -= old_sz;
      replaced_lamports += accmeta->lamports;
      replaced++;
    } else {
      accmeta = acc_pool_acquire( accdb->acc_pool_join );
      if( FD_UNLIKELY( !accmeta ) ) FD_LOG_ERR(( "accounts database ran out of space during snapshot loading" ));

      uint acc_idx = (uint)acc_pool_idx( accdb->acc_pool_join, accmeta );

      fd_memcpy( accmeta->key.pubkey, pubkeys[ i ], 32UL );
      accmeta->key.generation = incremental ? fork_gen : gen;
      accmeta->map.next = accdb->acc_map[ hashes[ i ] ];
      accdb->acc_map[ hashes[ i ] ] = acc_idx;

      if( FD_UNLIKELY( incremental ) ) {
        fd_accdb_txn_t * txn = txn_pool_acquire( accdb->txn_pool );
        if( FD_UNLIKELY( !txn ) ) FD_LOG_ERR(( "txn pool exhausted during incremental snapshot loading" ));
        txn->acc_map_idx  = (uint)hashes[ i ];
        txn->acc_pool_idx = acc_idx;
        uint txn_idx      = (uint)txn_pool_idx( accdb->txn_pool, txn );
        txn->fork.next          = fork->shmem->txn_head;
        fork->shmem->txn_head   = txn_idx;
      }

      if( cross_existing[ i ] ) {
        replaced_lamports += cross_existing[ i ]->lamports;
        replaced++;
        cross_replaced++;
      } else {
        loaded++;
      }
    }

    accmeta->cache_idx       = (uint)slots[ i ];
    accmeta->lamports        = lamports[ i ];
    accmeta->executable_size = FD_ACCDB_SIZE_PACK( (uint)data_lens[ i ], executables[ i ] );
    ulong entry_sz       = sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];
    ulong file_off       = allocate_next_write( accdb, entry_sz );
    accmeta->offset_fork = incremental ? fd_accdb_acc_pack_offset_fork( file_off, fork_id.val ) : file_off;
    accdb->shmem->shmetrics->disk_used_bytes += entry_sz;
  }

  /* accounts_total tracks acc_pool entries: increment for every new
     allocation (both genuinely new accounts and cross-fork overrides
     that insert a second pool entry).  The output counter
     *accounts_loaded excludes cross-fork overrides to match
     snapshot_write_one semantics (cross-fork returns 2 = replaced). */
  accdb->shmem->shmetrics->accounts_total += loaded + cross_replaced;

  *accounts_ignored      = ignored;
  *accounts_replaced     = replaced;
  *accounts_loaded       = loaded;
  *out_replaced_lamports = replaced_lamports;
  *out_ignored_lamports  = ignored_lamports;

  return 0;
}

void
fd_accdb_background( fd_accdb_t * accdb,
                     int *        charge_busy ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  uint op = FD_VOLATILE_CONST( shmem->cmd_op );
  if( FD_UNLIKELY( op!=FD_ACCDB_CMD_IDLE ) ) {
    fd_accdb_fork_id_t fork_id = { .val = FD_VOLATILE_CONST( shmem->cmd_fork_id ) };

    switch( op ) {
      case FD_ACCDB_CMD_ADVANCE_ROOT:
        background_advance_root( accdb, fork_id );
        break;
      case FD_ACCDB_CMD_PURGE:
        background_purge( accdb, fork_id );
        break;
      case FD_ACCDB_CMD_DRAIN_DEFERRED:
        drain_deferred_frees( accdb );
        break;
      case FD_ACCDB_CMD_CLEAR_DEFERRED: {
        /* Posted by fd_accdb_reset after it clobbers shared pools.
           T2's deferred fork chain now points at recycled elements;
           discard the stale pointers.  Epoch slots are preserved
           across reset so no re-join is needed. */
        accdb->deferred_fork_head  = NULL;
        accdb->deferred_fork_tail  = NULL;
        accdb->deferred_fork_epoch = 0UL;
        break;
      }
      default:
        FD_LOG_ERR(( "unexpected accdb cmd_op %u", op ));
    }

    FD_COMPILER_MFENCE();
    FD_VOLATILE( shmem->cmd_op ) = FD_ACCDB_CMD_IDLE;
    *charge_busy = 1;
    return;
  }

  background_preevict( accdb, charge_busy, 0 );

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
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
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong cap   = accdb->shmem->cache_class_max[ c ];
    ulong init  = FD_VOLATILE_CONST( accdb->shmem->cache_class_init[ c ].val );
    ulong freec = FD_VOLATILE_CONST( accdb->shmem->cache_free_cnt  [ c ].val );
    ulong live  = init>freec ? init-freec : 0UL;
    if( live>cap ) live = cap;
    max     [ c ] = cap;
    used    [ c ] = live;
    reserved[ c ] = FD_VOLATILE_CONST( accdb->shmem->cache_class_used[ c ].val );
  }
}

void
fd_accdb_cache_class_thresholds( fd_accdb_t * accdb,
                                 ulong *      target_used,
                                 ulong *      low_water_used ) {
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong max_c    = accdb->shmem->cache_class_max     [ c ];
    ulong free_tgt = accdb->shmem->cache_free_target   [ c ];
    ulong free_lwm = accdb->shmem->cache_free_low_water[ c ];
    target_used   [ c ] = max_c>free_tgt ? max_c-free_tgt : 0UL;
    low_water_used[ c ] = max_c>free_lwm ? max_c-free_lwm : 0UL;
  }
}

#if FD_HAS_RACESAN

/* Force pre-eviction (ignore the watermark) so a deterministic
   single-threaded test can exercise the writeback path without
   manufacturing real cache pressure.  Sweeps several times: CLOCK needs
   two visits to evict a recently-touched line (clear the "referenced"
   bit, then evict), and the clock hand position carries across calls, so
   one or two sweeps is not enough to guarantee every eligible line is
   flushed back. */
void
fd_accdb_debug_force_preevict( fd_accdb_t * accdb ) {
  for( ulong iter=0UL; iter<8UL; iter++ ) {
    int charge_busy = 0;
    background_preevict( accdb, &charge_busy, 1 );
  }
}

/* Locate the resident cache line currently holding `pubkey` (most recent
   generation if multiple).  Returns 1 and fills out_class/out_idx on a
   hit, 0 if no resident line matches.  Test-only helper so the test can
   target a specific line without seeing the opaque fd_accdb struct. */

int
fd_accdb_debug_find_line( fd_accdb_t *  accdb,
                          uchar const * pubkey,
                          ulong *       out_class,
                          ulong *       out_idx ) {
  int   found      = 0;
  uint  best_gen   = 0U;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong init  = FD_VOLATILE_CONST( accdb->shmem->cache_class_init[ c ].val );
    ulong max_c = accdb->shmem->cache_class_max[ c ];
    if( init>max_c ) init = max_c;
    for( ulong idx=0UL; idx<init; idx++ ) {
      fd_accdb_cache_line_t * line = cache_line( accdb, c, idx );
      if( line->key.generation==UINT_MAX ) continue;
      if( memcmp( line->key.pubkey, pubkey, 32UL ) ) continue;
      if( !found || line->key.generation>=best_gen ) {
        best_gen   = line->key.generation;
        *out_class = c;
        *out_idx   = idx;
        found      = 1;
      }
    }
  }
  return found;
}

/* Deterministically evict a single specified cache line via the
   foreground evictor's claim sequence (CAS refcnt 0->EVICT_SENTINEL),
   then write the dirty line back exactly as fd_accdb_acquire_inner's
   STEP-4 / background_ preevict do (pubkey from accmeta, owner+data
   from the line).  Mirrors acquire_cache_line's CLOCK-claim path
   (fd_accdb.c) so a racesan test can reproduce, without a 640+-slot
   cache-pressure rig, the interleaving where acc_unlink observes
   EVICT_SENTINEL on the line it is unlinking.

   The fd_racesan_hook("clock_evict:post_sentinel") fires right after
   the sentinel is installed (matching the production foreground path),
   so the test can suspend this fiber holding the sentinel while another
   fiber drives acc_unlink to its reclaim CAS.  Returns the captured
   evicted acc_idx (UINT_MAX if the line was clean / unbound). */

uint
fd_accdb_debug_clock_evict_line( fd_accdb_t * accdb,
                                 ulong        size_class,
                                 ulong        line_idx ) {
  fd_accdb_shmem_t *      shmem = accdb->shmem;
  fd_accdb_cache_line_t * line  = cache_line( accdb, size_class, line_idx );

  /* Claim for eviction, same as acquire_cache_line's CLOCK path. */
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &line->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL )!=0U ) ) return UINT_MAX;

  fd_racesan_hook( "clock_evict:post_sentinel" );

  uint acc_idx = line->acc_idx;
  if( FD_LIKELY( acc_idx!=UINT_MAX ) ) {
    evict_clear_acc_cache_ref( &accdb->acc_pool[ acc_idx ], size_class, line_idx );
  }
  uint evicted_acc_idx = line->persisted ? UINT_MAX : acc_idx;
  line->key.generation = UINT_MAX;

  /* Write back the dirty line, exactly like the production writeback
     sites: this is the synthesis that would emit a pubkey=NEW/owner=OLD
     poison record if the accmeta slot had been recycled out from under
     us.  In the SENTINEL-vs-acc_unlink race this proves no poison: the
     epoch the evictor holds blocks drain_deferred_frees, so the slot is
     never recycled while we are here. */
  if( FD_UNLIKELY( !line->persisted && acc_idx!=UINT_MAX ) ) {
    fd_accdb_accmeta_t * accmeta = &accdb->acc_pool[ acc_idx ];
    ulong entry_sz = sizeof(fd_accdb_disk_meta_t)+(ulong)FD_ACCDB_SIZE_DATA( accmeta->executable_size );

    ulong old_offset = fd_accdb_acc_xchg_offset( accmeta, FD_ACCDB_OFF_INVAL );
    if( FD_LIKELY( old_offset!=FD_ACCDB_OFF_INVAL ) ) {
      fd_accdb_shmem_bytes_freed( shmem, old_offset, entry_sz );
      FD_ATOMIC_FETCH_AND_SUB( &shmem->shmetrics->disk_used_bytes, entry_sz );
    }

    fd_accdb_disk_meta_t meta;
    fd_memcpy( meta.pubkey, accmeta->key.pubkey, 32UL );
    meta.size = FD_ACCDB_SIZE_DATA( accmeta->executable_size );
    fd_memcpy( meta.owner, line->owner, 32UL );

    struct iovec iovs[ 2UL ] = {
      { .iov_base = &meta,              .iov_len = sizeof(fd_accdb_disk_meta_t) },
      { .iov_base = (void *)(line+1UL), .iov_len = FD_ACCDB_SIZE_DATA( accmeta->executable_size ) }
    };
    ulong file_off = allocate_next_write( accdb, entry_sz );
    ulong written  = 0UL;
    while( written<entry_sz ) {
      long result = pwritev2( accdb->fd, iovs, 2, (long)(file_off+written), 0 );
      if( FD_UNLIKELY( result==-1 && errno==EINTR ) ) continue;
      else if( FD_UNLIKELY( result<=0 ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      written += (ulong)result;
      for( int v=0; v<2; v++ ) {
        if( (ulong)result>=iovs[ v ].iov_len ) { result -= (long)iovs[ v ].iov_len; iovs[ v ].iov_len = 0UL; }
        else { iovs[ v ].iov_base = (uchar *)iovs[ v ].iov_base + result; iovs[ v ].iov_len -= (ulong)result; break; }
      }
    }
    FD_COMPILER_MFENCE();
    accmeta->offset_fork = fd_accdb_acc_pack_offset_fork( file_off, fd_accdb_acc_fork_id(accmeta) );
    FD_ATOMIC_FETCH_AND_ADD( &shmem->shmetrics->disk_used_bytes, entry_sz );
  }

  line->persisted      = 1;
  line->acc_idx        = UINT_MAX;
  line->key.generation = UINT_MAX;
  line->refcnt         = 0;
  cache_free_push( accdb, size_class, line );
  return evicted_acc_idx;
}

#endif
