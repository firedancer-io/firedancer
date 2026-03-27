#include "fd_accdb_shmem.h"
#include "fd_accdb_private.h"

#include "../../util/log/fd_log.h"

#define POOL_NAME       partition_pool
#define POOL_T          fd_accdb_partition_t
#define POOL_NEXT       pool_next
#define POOL_IDX_T      ulong
#define POOL_IMPL_STYLE 2

#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME       compaction_dlist
#define DLIST_ELE_T      fd_accdb_partition_t
#define DLIST_PREV       dlist_prev
#define DLIST_NEXT       dlist_next
#define DLIST_IMPL_STYLE 2

#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME       deferred_free_dlist
#define DLIST_ELE_T      fd_accdb_partition_t
#define DLIST_PREV       dlist_prev
#define DLIST_NEXT       dlist_next
#define DLIST_IMPL_STYLE 2

#include "../../util/tmpl/fd_dlist.c"

FD_FN_CONST ulong
fd_accdb_shmem_align( void ) {
  return FD_ACCDB_SHMEM_ALIGN;
}

fd_accdb_shmem_t *
fd_accdb_shmem_join( void * shtc ) {
  if( FD_UNLIKELY( !shtc ) ) {
    FD_LOG_WARNING(( "NULL shtc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtc, fd_accdb_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtc" ));
    return NULL;
  }

  fd_accdb_shmem_t * accdb = (fd_accdb_shmem_t *)shtc;

  if( FD_UNLIKELY( accdb->magic!=FD_ACCDB_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return accdb;
}

FD_FN_CONST ulong
fd_accdb_shmem_footprint( ulong max_accounts,
                          ulong max_live_slots,
                          ulong max_account_writes_per_slot,
                          ulong partition_cnt,
                          ulong cache_footprint,
                          ulong joiner_cnt ) {
  if( FD_UNLIKELY( !max_accounts    ) ) return 0UL;
  if( FD_UNLIKELY( !max_live_slots  ) ) return 0UL;
  if( FD_UNLIKELY( !max_account_writes_per_slot) ) return 0UL;
  if( FD_UNLIKELY( !partition_cnt   ) ) return 0UL;
  if( FD_UNLIKELY( partition_cnt>=(1UL<<13) ) ) return 0UL;
  if( FD_UNLIKELY( !joiner_cnt || joiner_cnt>FD_ACCDB_MAX_JOINERS ) ) return 0UL;

  if( FD_UNLIKELY( max_accounts>=UINT_MAX ) ) return 0UL;

  if( FD_UNLIKELY( max_live_slots>=USHORT_MAX ) ) return 0UL;

  ulong txn_max = max_live_slots * max_account_writes_per_slot;
  if( FD_UNLIKELY( txn_max/max_account_writes_per_slot!=max_live_slots ) ) return 0UL;
  if( FD_UNLIKELY( txn_max>=UINT_MAX                        ) ) return 0UL;

  ulong descends_fp = descends_set_footprint( max_live_slots );
  if( FD_UNLIKELY( !descends_fp                          ) ) return 0UL;
  if( FD_UNLIKELY( max_live_slots>ULONG_MAX/descends_fp  ) ) return 0UL;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );

  if( FD_UNLIKELY( chain_cnt>ULONG_MAX/sizeof(uint) ) ) return 0UL;

  if( FD_UNLIKELY( !cache_footprint ) ) return 0UL;
  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];
  if( FD_UNLIKELY( !fd_accdb_cache_class_cnt( cache_footprint, cache_class_max ) ) ) return 0UL;

  ulong total_cache_slots = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) total_cache_slots += cache_class_max[c];

  ulong cache_map_ele_max = fd_ulong_pow2_up( total_cache_slots * 2UL );
  ulong cache_map_lock    = cache_map_lock_cnt_est( cache_map_ele_max );
  ulong cache_map_probe   = cache_map_probe_max_est( cache_map_ele_max );

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint()                                   );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)      );
  l = FD_LAYOUT_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, cache_map_align(),        cache_map_footprint( cache_map_ele_max, cache_map_lock, cache_map_probe ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_cache_ele_t), cache_map_ele_max*sizeof(fd_accdb_cache_ele_t)     );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  l = FD_LAYOUT_APPEND( l, acc_pool_align(),         acc_pool_footprint()                                    );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_acc_t),  max_accounts*sizeof(fd_accdb_acc_t)                     );
  l = FD_LAYOUT_APPEND( l, txn_pool_align(),         txn_pool_footprint()                                    );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_txn_t),  txn_max*sizeof(fd_accdb_txn_t)                          );
  l = FD_LAYOUT_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    l = FD_LAYOUT_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                          );
  }
  l = FD_LAYOUT_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                      );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    l = FD_LAYOUT_APPEND( l, FD_ACCDB_CACHE_META_SZ, cache_class_max[c]*fd_accdb_cache_slot_sz[c]            );
  }
  return FD_LAYOUT_FINI( l, FD_ACCDB_SHMEM_ALIGN );
}

void *
fd_accdb_shmem_new( void * shmem,
                    ulong  max_accounts,
                    ulong  max_live_slots,
                    ulong  max_account_writes_per_slot,
                    ulong  partition_cnt,
                    ulong  partition_sz,
                    ulong  cache_footprint,
                    ulong  seed,
                    ulong  joiner_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_accdb_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_accounts ) ) {
    FD_LOG_WARNING(( "max_accounts must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_live_slots ) ) {
    FD_LOG_WARNING(( "max_live_slots must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_account_writes_per_slot ) ) {
    FD_LOG_WARNING(( "max_account_writes_per_slot must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !joiner_cnt || joiner_cnt>FD_ACCDB_MAX_JOINERS ) ) {
    FD_LOG_WARNING(( "joiner_cnt must be in [1, %lu]", FD_ACCDB_MAX_JOINERS ));
    return NULL;
  }

  if( FD_UNLIKELY( max_live_slots>=USHORT_MAX ) ) {
    FD_LOG_WARNING(( "max_live_slots must be less than %u", (uint)USHORT_MAX ));
    return NULL;
  }

  if( FD_UNLIKELY( !partition_cnt ) ) {
    FD_LOG_WARNING(( "partition_cnt must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( partition_cnt>=(1UL<<13) ) ) {
    FD_LOG_WARNING(( "partition_cnt must be less than %lu", 1UL<<13 ));
    return NULL;
  }

  if( FD_UNLIKELY( !partition_sz ) ) {
    FD_LOG_WARNING(( "partition_sz must be non-zero" ));
    return NULL;
  }

  /* Partition offsets are packed into the low 51 bits of accdb_offset_t
     (see FD_ACCDB_PARTITION_OFF_BITS in fd_accdb.c).  partition_sz must
     be small enough that speculative fetch-and-adds from up to
     FD_ACCDB_MAX_JOINERS concurrent threads in allocate_next_write
     can never carry the offset field into the partition_idx bits.
     Worst case: all joiners each do one FETCH_AND_ADD of partition_sz
     before the partition switch completes, starting from an offset of
     at most partition_sz-1. */
  if( FD_UNLIKELY( partition_sz>(1UL<<51)/(FD_ACCDB_MAX_JOINERS+1UL) ) ) {
    FD_LOG_WARNING(( "partition_sz must be at most %lu", (1UL<<51)/(FD_ACCDB_MAX_JOINERS+1UL) ));
    return NULL;
  }

  /* The maximum file offset is (partition_cnt-1)*partition_sz +
     partition_sz - 1, which must fit in a signed long (off_t) because
     pwritev2, preadv2, and fallocate all take signed offsets. */
  if( FD_UNLIKELY( partition_cnt>=(ulong)LONG_MAX/partition_sz ) ) {
    FD_LOG_WARNING(( "partition_cnt*partition_sz must be at most LONG_MAX" ));
    return NULL;
  }

  /* partition_sz must be large enough to hold at least one worst-case
     account write (disk metadata header + largest cache class payload).
     Without this, allocate_next_write can never fit the entry in a
     single partition. */
  ulong min_partition_sz = sizeof(fd_accdb_disk_meta_t) + fd_accdb_cache_slot_sz[ FD_ACCDB_CACHE_CLASS_CNT-1UL ] - FD_ACCDB_CACHE_META_SZ;
  if( FD_UNLIKELY( partition_sz<min_partition_sz ) ) {
    FD_LOG_WARNING(( "partition_sz must be at least %lu to fit worst-case account write", min_partition_sz ));
    return NULL;
  }

  if( FD_UNLIKELY( max_accounts>=UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_accounts must be less than UINT_MAX" ));
    return NULL;
  }

  ulong txn_max = max_live_slots * max_account_writes_per_slot;
  if( FD_UNLIKELY( txn_max/max_account_writes_per_slot!=max_live_slots ) ) {
    FD_LOG_WARNING(( "max_live_slots*max_account_writes_per_slot overflows" ));
    return NULL;
  }
  if( FD_UNLIKELY( txn_max>=UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_live_slots*max_account_writes_per_slot must be less than UINT_MAX" ));
    return NULL;
  }

  ulong descends_fp = descends_set_footprint( max_live_slots );
  if( FD_UNLIKELY( !descends_fp || max_live_slots>ULONG_MAX/descends_fp ) ) {
    FD_LOG_WARNING(( "max_live_slots*descends_set_footprint overflows" ));
    return NULL;
  }

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );

  if( FD_UNLIKELY( chain_cnt>ULONG_MAX/sizeof(uint) ) ) {
    FD_LOG_WARNING(( "chain_cnt*sizeof(uint) overflows" ));
    return NULL;
  }
  
  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];
  if( FD_UNLIKELY( !fd_accdb_cache_class_cnt( cache_footprint, cache_class_max ) ) ) {
    FD_LOG_WARNING(( "invalid cache_footprint" ));
    return NULL;
  }

  ulong total_cache_slots = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) total_cache_slots += cache_class_max[c];

  ulong cache_map_ele_max = fd_ulong_pow2_up( total_cache_slots * 2UL );
  ulong cache_map_lock    = cache_map_lock_cnt_est( cache_map_ele_max );
  ulong cache_map_probe   = cache_map_probe_max_est( cache_map_ele_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_accdb_shmem_t * accdb = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool_shmem  = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),              fork_pool_footprint()                             );
  void * _fork_pool_ele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)      );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _cache_shmap      = FD_SCRATCH_ALLOC_APPEND( l, cache_map_align(),        cache_map_footprint( cache_map_ele_max, cache_map_lock, cache_map_probe ) );
  void * _cache_shele      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_cache_ele_t), cache_map_ele_max*sizeof(fd_accdb_cache_ele_t) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  void * _acc_pool_shmem   = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),         acc_pool_footprint()                                    );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_acc_t),  max_accounts*sizeof(fd_accdb_acc_t)                     );
  void * _txn_pool_shmem   = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),         txn_pool_footprint()                                    );
  void * _txn_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_txn_t),  txn_max*sizeof(fd_accdb_txn_t)                          );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlists[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    _compaction_dlists[ k ] = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                           );
  }
  void * _deferred_free_dlist = FD_SCRATCH_ALLOC_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                   );
  void * _cache_regions[ FD_ACCDB_CACHE_CLASS_CNT ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    _cache_regions[ c ] = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_CACHE_META_SZ, cache_class_max[c]*fd_accdb_cache_slot_sz[c]                 );
  }

  for( ulong i=0UL; i<chain_cnt; i++ ) ((uint *)_acc_map)[ i ] = UINT_MAX;

  FD_TEST( acc_pool_new( _acc_pool_shmem ) );
  acc_pool_t _acc_pool_join[1];
  FD_TEST( acc_pool_join( _acc_pool_join, _acc_pool_shmem, _acc_pool_ele, max_accounts ) );
  acc_pool_reset( _acc_pool_join, 0UL );
  acc_pool_leave( _acc_pool_join );

  FD_TEST( fork_pool_new( _fork_pool_shmem ) );
  fork_pool_t _fork_pool_join[1];
  FD_TEST( fork_pool_join( _fork_pool_join, _fork_pool_shmem, _fork_pool_ele, max_live_slots ) );
  fork_pool_reset( _fork_pool_join, 0UL );
  fork_pool_leave( _fork_pool_join );

  ulong descends_set_fp = descends_set_footprint( max_live_slots );
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    descends_set_t * descends_set = descends_set_join( descends_set_new( (uchar *)_descends_sets + i*descends_set_fp, max_live_slots ) );
    FD_TEST( descends_set );
  }

  FD_TEST( txn_pool_new( _txn_pool_shmem ) );
  txn_pool_t _txn_pool_join[1];
  FD_TEST( txn_pool_join( _txn_pool_join, _txn_pool_shmem, _txn_pool_ele, txn_max ) );
  txn_pool_reset( _txn_pool_join, 0UL );
  txn_pool_leave( _txn_pool_join );

  fd_accdb_partition_t * partition_pool = partition_pool_join( partition_pool_new( _partition_pool, partition_cnt ) );
  FD_TEST( partition_pool );

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    compaction_dlist_t * dlist = compaction_dlist_join( compaction_dlist_new( _compaction_dlists[ k ] ) );
    FD_TEST( dlist );
  }

  deferred_free_dlist_t * deferred_free = deferred_free_dlist_join( deferred_free_dlist_new( _deferred_free_dlist ) );
  FD_TEST( deferred_free );

  fd_accdb_cache_ele_t * cache_eles = (fd_accdb_cache_ele_t *)_cache_shele;
  for( ulong i=0UL; i<cache_map_ele_max; i++ ) cache_eles[ i ].acc_idx = UINT_MAX;

  FD_TEST( cache_map_new( _cache_shmap, cache_map_ele_max, cache_map_lock, cache_map_probe, seed ) );

  accdb->seed = seed;
  accdb->root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  accdb->generation = 0UL;

  accdb->partition_lock = 0;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->clock_hand[ c ].val = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_free[ c ].ver_top = (ulong)UINT_MAX;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_free_cnt[ c ].val = 0UL;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong max_c    = cache_class_max[ c ];
    ulong floor_c  = fd_ulong_min( FD_ACCDB_CACHE_MIN_RESERVED, max_c );
    ulong headroom = ( max_c>floor_c ) ? ( max_c - floor_c ) : 0UL;
    ulong cap      = fd_ulong_min( 8192UL, (64UL<<20) / fd_accdb_cache_slot_sz[ c ] );
    ulong target   = fd_ulong_min( headroom/20UL, cap );
    accdb->cache_free_target   [ c ] = target;
    accdb->cache_free_low_water[ c ] = target / 2UL;
  }

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    /* Sentinel: partition_offset == partition_sz forces the first
       allocate_next_write to fall into the partition-switch slow path,
       which acquires a real partition from the pool.  The partition_idx
       is set to partition_cnt (an invalid pool index) so concurrent
       losers spinning on partition_idx can detect the switch even if
       the pool hands back index 0. */
    accdb->whead[ k ]         = accdb_offset( partition_cnt, partition_sz );
    accdb->has_partition[ k ] = 0;
  }

  accdb->chain_cnt        = chain_cnt;
  accdb->max_live_slots   = max_live_slots;
  accdb->max_accounts     = max_accounts;
  accdb->max_account_writes_per_slot = max_account_writes_per_slot;
  accdb->joiner_cnt_max   = joiner_cnt;
  accdb->partition_cnt    = partition_cnt;
  accdb->partition_sz     = partition_sz;
  accdb->partition_max    = 0UL;

  accdb->partition_pool_off = (ulong)_partition_pool - (ulong)shmem;
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    accdb->compaction_dlist_off[ k ] = (ulong)_compaction_dlists[ k ] - (ulong)shmem;
  }
  accdb->deferred_free_dlist_off = (ulong)_deferred_free_dlist - (ulong)shmem;

  accdb->epoch      = 1UL;
  accdb->joiner_cnt = 0UL;
  for( ulong i=0UL; i<FD_ACCDB_MAX_JOINERS; i++ ) accdb->joiner_epochs[ i ].val = ULONG_MAX;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_class_init[ c ].val = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_class_max[ c ] = cache_class_max[ c ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_region_off[ c ] = (ulong)_cache_regions[ c ] - (ulong)shmem;

  /* If a class has enough slots for every joiner's worst case
     simultaneously (FD_ACCDB_CACHE_MIN_RESERVED per joiner), no
     reservation can ever overflow.  Sentinel ULONG_MAX tells
     acquire/release to skip the atomic counters entirely. */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    if( cache_class_max[ c ]>=FD_ACCDB_CACHE_MIN_RESERVED*joiner_cnt ) accdb->cache_class_used[ c ].val = ULONG_MAX;
    else                                                               accdb->cache_class_used[ c ].val = 0UL;
  }

  memset( accdb->metrics, 0, sizeof( fd_accdb_shmem_metrics_t ) );
  accdb->metrics->accounts_capacity = max_accounts;

  accdb->cmd_op      = FD_ACCDB_CMD_IDLE;
  accdb->cmd_fork_id = USHORT_MAX;
  accdb->cmd_done    = 0;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( accdb->magic ) = FD_ACCDB_SHMEM_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)accdb;
}

void
fd_accdb_shmem_try_enqueue_compaction( fd_accdb_shmem_t * accdb,
                                       ulong              partition_idx ) {
  /* Caller must hold partition_lock. */

  fd_accdb_partition_t * partition_pool = (fd_accdb_partition_t *)( (uchar *)accdb + accdb->partition_pool_off );
  fd_accdb_partition_t * partition = partition_pool_ele( partition_pool, partition_idx );

  if( FD_UNLIKELY( partition->bytes_freed<(accdb->partition_sz*3UL/10UL) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;

  /* Do not enqueue any currently active write-head partition.  Its
     write_offset is not yet finalized, so compaction cannot determine
     the valid data range.  The partition_lock serializes this check
     with change_partition, so it is not racy. */
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    if( FD_UNLIKELY( accdb->has_partition[ k ] && packed_partition_idx( accdb->whead[ k ] )==partition_idx ) ) return;
  }

  uchar layer = partition->layer;
  compaction_dlist_t * compaction_dlist = (compaction_dlist_t *)( (uchar *)accdb + accdb->compaction_dlist_off[ layer ] );

  partition->marked_compaction = 1;
  partition->compaction_offset = 0UL;
  partition->compaction_ready_epoch = FD_ATOMIC_FETCH_AND_ADD( &accdb->epoch, 1UL );
  if( FD_LIKELY( compaction_dlist_is_empty( compaction_dlist, partition_pool ) ) ) {
    FD_LOG_NOTICE(( "compaction of layer %u partition %lu started", (uint)layer, partition_pool_idx( partition_pool, partition ) ));
  }
  compaction_dlist_ele_push_tail( compaction_dlist, partition, partition_pool );
  accdb->metrics->in_compaction = 1;
  accdb->metrics->compactions_requested++;
}

void
fd_accdb_shmem_bytes_freed( fd_accdb_shmem_t * accdb,
                            ulong              offset,
                            ulong              sz ) {
  fd_accdb_partition_t * partition_pool = (fd_accdb_partition_t *)( (uchar *)accdb + accdb->partition_pool_off );

  ulong partition_idx = offset/accdb->partition_sz;
  fd_accdb_partition_t * partition = partition_pool_ele( partition_pool, partition_idx );
  FD_ATOMIC_FETCH_AND_ADD( &partition->bytes_freed, sz );

  /* Fast-path exit: skip the lock if clearly below threshold or
     already enqueued. */
  if( FD_LIKELY( partition->bytes_freed<(accdb->partition_sz*3UL/10UL) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;

  spin_lock_acquire( &accdb->partition_lock );
  fd_accdb_shmem_try_enqueue_compaction( accdb, partition_idx );
  spin_lock_release( &accdb->partition_lock );
}
