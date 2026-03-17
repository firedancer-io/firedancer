#include "fd_accdb_shmem.h"
#include "fd_accdb_private.h"

#include "../../util/log/fd_log.h"

FD_FN_CONST static inline int
determine_map_size( ulong cache_footprint ) {
  (void)cache_footprint;
  FD_LOG_ERR(( "determine_map_size not implemented" ));
  return -1;
}

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
  int cache_map_lg_slot_count = determine_map_size( cache_footprint );

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  l = FD_LAYOUT_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, cache_map_align(),        cache_map_footprint( cache_map_lg_slot_count )          );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  l = FD_LAYOUT_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  l = FD_LAYOUT_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  l = FD_LAYOUT_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  l = FD_LAYOUT_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                            );
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
  
  int cache_map_lg_slot_count = determine_map_size( cache_footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_accdb_shmem_t * accdb = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool        = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _cache_map        = FD_SCRATCH_ALLOC_APPEND( l, cache_map_align(),        cache_map_footprint( cache_map_lg_slot_count )          );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  void * _acc_pool         = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  void * _txn_pool         = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlist = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                            );

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

  compaction_dlist_t * compaction_dlist = compaction_dlist_join( compaction_dlist_new( _compaction_dlist ) );
  FD_TEST( compaction_dlist );

  cache_entry_t * cache_map = cache_map_join( cache_map_new( _cache_map, cache_map_lg_slot_count, seed ) );
  FD_TEST( cache_map );

  accdb->seed = seed;
  accdb->root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  accdb->generation = 0UL;

  accdb->cache_map_lg_slot_count = determine_map_size( cache_footprint );
  accdb->chain_cnt        = chain_cnt;
  accdb->max_live_slots   = max_live_slots;
  accdb->max_accounts     = max_accounts;
  accdb->max_account_writes_per_slot = max_account_writes_per_slot;
  accdb->partition_cnt    = partition_cnt;
  accdb->partition_sz     = partition_sz;
  accdb->partition_idx    = ULONG_MAX;
  accdb->partition_max    = 0UL;
  accdb->partition_offset = 0UL;

  accdb->partition_pool_off = (ulong)_partition_pool - (ulong)shmem;
  accdb->compaction_dlist_off = (ulong)_compaction_dlist - (ulong)shmem;

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
  compaction_dlist_t * compaction_dlist = (compaction_dlist_t *)( (uchar *)accdb + accdb->compaction_dlist_off );

  fd_accdb_partition_t * partition = partition_pool_ele( partition_pool, offset/accdb->partition_sz );
  partition->bytes_freed += sz;

  if( FD_UNLIKELY( accdb->partition_idx==(offset/accdb->partition_sz) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;
  if( FD_UNLIKELY( partition->bytes_freed<(accdb->partition_sz*3UL/10UL) ) ) return;

  partition->marked_compaction = 1;
  partition->compaction_offset = 0UL;
  if( FD_LIKELY( compaction_dlist_is_empty( compaction_dlist, partition_pool ) ) ) {
    FD_LOG_NOTICE(( "compaction of partition %lu started", partition_pool_idx( partition_pool, partition ) ));
  }
  compaction_dlist_ele_push_tail( compaction_dlist, partition, partition_pool );
  accdb->metrics->in_compaction = 1;
  accdb->metrics->compactions_requested++;
}

