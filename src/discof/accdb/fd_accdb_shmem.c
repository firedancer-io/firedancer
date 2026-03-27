#include "fd_accdb_shmem.h"
#include "fd_accdb_private.h"

#include "../../util/log/fd_log.h"

FD_FN_CONST ulong
fd_accdb_shmem_footprint( ulong max_accounts,
                          ulong max_live_slots,
                          ulong max_account_writes_per_slot,
                          ulong partition_cnt,
                          ulong cache_footprint ) {
  if( FD_UNLIKELY( !max_accounts    ) ) return 0UL;
  if( FD_UNLIKELY( !max_live_slots  ) ) return 0UL;
  if( FD_UNLIKELY( !max_account_writes_per_slot) ) return 0UL;
  if( FD_UNLIKELY( !partition_cnt   ) ) return 0UL;

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

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  l = FD_LAYOUT_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, cache_map_align(),        cache_map_footprint( total_cache_slots )                );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  l = FD_LAYOUT_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  l = FD_LAYOUT_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  l = FD_LAYOUT_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    l = FD_LAYOUT_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                          );
  }
  l = FD_LAYOUT_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                      );
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
                    ulong  seed ) {
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

  if( FD_UNLIKELY( max_live_slots>=USHORT_MAX ) ) {
    FD_LOG_WARNING(( "max_live_slots must be less than %u", (uint)USHORT_MAX ));
    return NULL;
  }

  if( FD_UNLIKELY( !partition_cnt ) ) {
    FD_LOG_WARNING(( "partition_cnt must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !partition_sz ) ) {
    FD_LOG_WARNING(( "partition_sz must be non-zero" ));
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

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_accdb_shmem_t * accdb = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool        = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _cache_map        = FD_SCRATCH_ALLOC_APPEND( l, cache_map_align(),        cache_map_footprint( total_cache_slots )                );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  void * _acc_pool         = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  void * _txn_pool         = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlists[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    _compaction_dlists[ k ] = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                           );
  }
  void * _deferred_free_dlist = FD_SCRATCH_ALLOC_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                   );

  for( ulong i=0UL; i<chain_cnt; i++ ) ((uint *)_acc_map)[ i ] = UINT_MAX;

  fd_accdb_acc_t * acc_pool = acc_pool_join( acc_pool_new( _acc_pool, max_accounts ) );
  FD_TEST( acc_pool );

  fd_accdb_fork_shmem_t * fork_pool = fork_pool_join( fork_pool_new( _fork_pool, max_live_slots ) );
  FD_TEST( fork_pool );

  ulong descends_set_fp = descends_set_footprint( max_live_slots );
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    descends_set_t * descends_set = descends_set_join( descends_set_new( (uchar *)_descends_sets + i*descends_set_fp, max_live_slots ) );
    FD_TEST( descends_set );
  }

  fd_accdb_txn_t * txn_pool = txn_pool_join( txn_pool_new( _txn_pool, txn_max ) );
  FD_TEST( txn_pool );

  fd_accdb_partition_t * partition_pool = partition_pool_join( partition_pool_new( _partition_pool, partition_cnt ) );
  FD_TEST( partition_pool );

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    compaction_dlist_t * dlist = compaction_dlist_join( compaction_dlist_new( _compaction_dlists[ k ] ) );
    FD_TEST( dlist );
  }

  deferred_free_dlist_t * deferred_free = deferred_free_dlist_join( deferred_free_dlist_new( _deferred_free_dlist ) );
  FD_TEST( deferred_free );

  fd_accdb_cache_map_t * cache_map = cache_map_join( cache_map_new( _cache_map, total_cache_slots, seed ) );
  FD_TEST( cache_map );

  accdb->seed = seed;
  accdb->root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  accdb->generation = 0UL;

  fd_rwlock_new( accdb->lock );
  accdb->cache_lock     = 0;
  accdb->partition_lock = 0;

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    accdb->whead[ k ]         = (accdb_offset_t){ .val = 0UL };
    accdb->has_partition[ k ] = 0;
  }

  accdb->chain_cnt        = chain_cnt;
  accdb->max_live_slots   = max_live_slots;
  accdb->max_accounts     = max_accounts;
  accdb->max_account_writes_per_slot = max_account_writes_per_slot;
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
  for( ulong i=0UL; i<FD_ACCDB_MAX_JOINERS; i++ ) accdb->joiner_epochs[ i ] = ULONG_MAX;

  memset( accdb->cache_class_init, 0, sizeof( accdb->cache_class_init ) );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_class_max[ c ] = cache_class_max[ c ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_class_pool[ c ] = cache_class_max[ c ];

  memset( accdb->metrics, 0, sizeof( fd_accdb_shmem_metrics_t ) );
  accdb->metrics->accounts_capacity = max_accounts;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( accdb->magic ) = FD_ACCDB_SHMEM_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)accdb;
}

void
fd_accdb_shmem_bytes_freed( fd_accdb_shmem_t * accdb,
                            ulong              offset,
                            ulong              sz ) {
  fd_accdb_partition_t * partition_pool = (fd_accdb_partition_t *)( (uchar *)accdb + accdb->partition_pool_off );

  fd_accdb_partition_t * partition = partition_pool_ele( partition_pool, offset/accdb->partition_sz );
  ulong bytes_freed = FD_ATOMIC_ADD_AND_FETCH( &partition->bytes_freed, sz );

  if( FD_UNLIKELY( bytes_freed<(accdb->partition_sz*3UL/10UL) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;

  uchar layer = partition->layer;

  /* Do not enqueue any currently active write-head partition.  These
     reads are racy (no lock) but safe: the worst case is a partition
     gets enqueued one call early or late, and marked_compaction above
     prevents double-enqueue. */
  ulong freed_partition_idx = offset/accdb->partition_sz;
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    if( FD_UNLIKELY( accdb->has_partition[ k ] && packed_partition_idx( accdb->whead[ k ] )==freed_partition_idx ) ) return;
  }

  compaction_dlist_t * compaction_dlist = (compaction_dlist_t *)( (uchar *)accdb + accdb->compaction_dlist_off[ layer ] );

  spin_lock_acquire( &accdb->partition_lock );

  if( FD_UNLIKELY( partition->marked_compaction ) ) {
    spin_lock_release( &accdb->partition_lock );
    return;
  }

  partition->marked_compaction = 1;
  partition->compaction_offset = 0UL;
  if( FD_LIKELY( compaction_dlist_is_empty( compaction_dlist, partition_pool ) ) ) {
    FD_LOG_NOTICE(( "compaction of layer %u partition %lu started", (uint)layer, partition_pool_idx( partition_pool, partition ) ));
  }
  compaction_dlist_ele_push_tail( compaction_dlist, partition, partition_pool );
  accdb->metrics->in_compaction = 1;
  accdb->metrics->compactions_requested++;

  spin_lock_release( &accdb->partition_lock );
}
