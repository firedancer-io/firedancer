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

/* fd_accdb_shmem_layout computes the shared-memory layout.  Offsets
   are relative to the shmem base.  Returns the total footprint, or 0
   if the parameters are invalid.  The disk-index regions (hot_map,
   seqlocks, bloom, spill state) have size zero in RAM-only mode
   (index_ram_max==0) and are appended after the RAM-only layout, so
   RAM-only images are bit-compatible with the historical layout. */

struct fd_accdb_shmem_layout {
  ulong pool_max;
  ulong chain_cnt;
  ulong txn_max;
  ulong delta_chain_cnt;
  ulong hot_chain_cnt;
  ulong npage;
  ulong bloom_sz;
  ulong nrange;
  ulong spill_base;
  ulong spill_extent;
  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  ulong fork_pool_ele_off;
  ulong descends_off;
  ulong acc_map_off;
  ulong acc_pool_ele_off;
  ulong txn_pool_ele_off;
  ulong partition_pool_off;
  ulong compaction_dlist_off[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  ulong deferred_free_dlist_off;
  ulong deferred_acc_buf_off;
  ulong cache_region_off[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong delta_chain_off;
  ulong delta_ele_off;
  ulong hot_map_off;
  ulong idx_seqlock_off;
  ulong idx_bloom_off;
  ulong idx_range_off;
  ulong idx_stage_off;
  ulong idx_window_off;
  ulong idx_carry_off;
};

typedef struct fd_accdb_shmem_layout fd_accdb_shmem_layout_t;

static ulong
fd_accdb_shmem_layout( fd_accdb_shmem_layout_t * out,
                       ulong max_accounts,
                       ulong index_ram_max,
                       ulong max_live_slots,
                       ulong max_account_writes_per_slot,
                       ulong partition_cnt,
                       ulong cache_footprint,
                       ulong cache_min_reserved,
                       ulong joiner_cnt,
                       ulong max_incremental_accounts ) {
  if( FD_UNLIKELY( !max_accounts    ) ) return 0UL;
  if( FD_UNLIKELY( !max_live_slots  ) ) return 0UL;
  if( FD_UNLIKELY( !max_account_writes_per_slot) ) return 0UL;
  if( FD_UNLIKELY( !partition_cnt   ) ) return 0UL;
  if( FD_UNLIKELY( !cache_min_reserved ) ) return 0UL;
  /* Partition indices are packed into 13 bits of accdb_offset_t
     (bits 63..51), so partition_cnt==8192 uses indices 0..8191, the
     full 13-bit range.  The initial write-head sentinel encodes its
     invalidity in the offset bits (partition_offset==partition_sz),
     not the index, so it remains distinguishable even when no spare
     index value is left. */
  if( FD_UNLIKELY( partition_cnt>(1UL<<13) ) ) return 0UL;
  if( FD_UNLIKELY( !joiner_cnt || joiner_cnt>FD_ACCDB_MAX_JOINERS ) ) return 0UL;

  if( FD_UNLIKELY( max_accounts>=UINT_MAX ) ) return 0UL;

  if( FD_UNLIKELY( max_live_slots>=USHORT_MAX ) ) return 0UL;

  /* Disk-index mode bounds: pool indices must fit the 31-bit hot_map
     head encoding, and a pool larger than the account cap is
     equivalent to RAM-only. */
  if( FD_UNLIKELY( index_ram_max>=(1UL<<31)      ) ) return 0UL;
  if( FD_UNLIKELY( index_ram_max> max_accounts   ) ) return 0UL;

  ulong pool_max = index_ram_max ? index_ram_max : max_accounts;

  ulong txn_max = max_live_slots * max_account_writes_per_slot;
  if( FD_UNLIKELY( txn_max/max_account_writes_per_slot!=max_live_slots ) ) return 0UL;
  if( FD_UNLIKELY( txn_max>=UINT_MAX                        ) ) return 0UL;

  ulong descends_fp = descends_set_footprint( max_live_slots );
  if( FD_UNLIKELY( !descends_fp                          ) ) return 0UL;
  if( FD_UNLIKELY( max_live_slots>ULONG_MAX/descends_fp  ) ) return 0UL;

  ulong chain_cnt = fd_ulong_pow2_up( (pool_max>>1) + (pool_max&1UL) );

  if( FD_UNLIKELY( chain_cnt>ULONG_MAX/sizeof(uint) ) ) return 0UL;

  if( FD_UNLIKELY( !cache_footprint ) ) return 0UL;
  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];
  if( FD_UNLIKELY( !fd_accdb_cache_class_cnt( cache_footprint, cache_min_reserved, cache_class_max ) ) ) return 0UL;

  if( FD_UNLIKELY( max_incremental_accounts>UINT_MAX ) ) return 0UL;
  ulong delta_chain_cnt = fd_ulong_pow2_up( (max_incremental_accounts>>1) + (max_incremental_accounts&1UL) );

  ulong hot_chain_cnt = 0UL;
  ulong npage         = 0UL;
  ulong bloom_sz      = 0UL;
  ulong nrange        = 0UL;
  ulong spill_base    = 0UL;
  ulong spill_extent  = 0UL;
  if( index_ram_max ) {
    hot_chain_cnt = chain_cnt;
    npage         = fd_accdb_idx_npage( max_accounts );
    bloom_sz      = fd_accdb_idx_bloom_sz( max_accounts );
    nrange        = ( npage*FD_ACCDB_IDX_PAGE_SZ + FD_ACCDB_IDX_WINDOW_SZ-1UL )/FD_ACCDB_IDX_WINDOW_SZ;
    spill_base    = fd_ulong_align_up( npage*FD_ACCDB_IDX_PAGE_SZ, 1UL<<20 );
    /* 1.5x hash-uniformity slack over the expected per-range record
       volume; overflow past the extent is a hard error (indicates a
       snapshot far above max_accounts). */
    spill_extent  = fd_ulong_align_up( ( max_accounts*sizeof(fd_accdb_idx_slot_t)*3UL/2UL )/nrange, 1UL<<20 );
    if( FD_UNLIKELY( spill_base+nrange*spill_extent>(ulong)LONG_MAX ) ) return 0UL;
  }

  fd_accdb_shmem_layout_t lo[1];
  memset( lo, 0, sizeof(lo) );
  lo->pool_max        = pool_max;
  lo->chain_cnt       = chain_cnt;
  lo->txn_max         = txn_max;
  lo->delta_chain_cnt = delta_chain_cnt;
  lo->hot_chain_cnt   = hot_chain_cnt;
  lo->npage           = npage;
  lo->bloom_sz        = bloom_sz;
  lo->nrange          = nrange;
  lo->spill_base      = spill_base;
  lo->spill_extent    = spill_extent;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) lo->cache_class_max[ c ] = cache_class_max[ c ];

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  lo->fork_pool_ele_off = fd_ulong_align_up( l, alignof(fd_accdb_fork_shmem_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)      );
  lo->descends_off = fd_ulong_align_up( l, descends_set_align() );
  l = FD_LAYOUT_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  lo->acc_map_off = fd_ulong_align_up( l, alignof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  lo->acc_pool_ele_off = fd_ulong_align_up( l, alignof(fd_accdb_accmeta_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_accmeta_t), pool_max*sizeof(fd_accdb_accmeta_t)                  );
  lo->txn_pool_ele_off = fd_ulong_align_up( l, alignof(fd_accdb_txn_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_txn_t),  txn_max*sizeof(fd_accdb_txn_t)                          );
  lo->partition_pool_off = fd_ulong_align_up( l, partition_pool_align() );
  l = FD_LAYOUT_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    lo->compaction_dlist_off[ k ] = fd_ulong_align_up( l, compaction_dlist_align() );
    l = FD_LAYOUT_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                          );
  }
  lo->deferred_free_dlist_off = fd_ulong_align_up( l, deferred_free_dlist_align() );
  l = FD_LAYOUT_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                      );
  lo->deferred_acc_buf_off = fd_ulong_align_up( l, alignof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            txn_max*sizeof(uint)                                    );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    lo->cache_region_off[ c ] = fd_ulong_align_up( l, FD_ACCDB_CACHE_META_SZ );
    l = FD_LAYOUT_APPEND( l, FD_ACCDB_CACHE_META_SZ, cache_class_max[c]*fd_accdb_cache_slot_sz[c]            );
  }
  lo->delta_chain_off = fd_ulong_align_up( l, alignof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            delta_chain_cnt*sizeof(uint)                            );
  lo->delta_ele_off = fd_ulong_align_up( l, alignof(fd_accdb_delta_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_delta_t),max_incremental_accounts*sizeof(fd_accdb_delta_t)       );
  lo->hot_map_off = fd_ulong_align_up( l, 64UL );
  l = FD_LAYOUT_APPEND( l, 64UL,                     hot_chain_cnt*sizeof(uint)                              );
  lo->idx_seqlock_off = fd_ulong_align_up( l, 64UL );
  l = FD_LAYOUT_APPEND( l, 64UL,                     npage*sizeof(uint)                                      );
  lo->idx_bloom_off = fd_ulong_align_up( l, 64UL );
  l = FD_LAYOUT_APPEND( l, 64UL,                     bloom_sz                                                );
  lo->idx_range_off = fd_ulong_align_up( l, 64UL );
  l = FD_LAYOUT_APPEND( l, 64UL,                     nrange*sizeof(fd_accdb_idx_range_t)                     );
  lo->idx_stage_off = fd_ulong_align_up( l, 64UL );
  l = FD_LAYOUT_APPEND( l, 64UL,                     nrange*( index_ram_max ? FD_ACCDB_IDX_STAGE_SZ : 0UL )  );
  lo->idx_window_off = fd_ulong_align_up( l, FD_ACCDB_IDX_PAGE_SZ );
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_IDX_PAGE_SZ,     index_ram_max ? FD_ACCDB_IDX_WINDOW_SZ : 0UL            );
  lo->idx_carry_off = fd_ulong_align_up( l, 64UL );
  l = FD_LAYOUT_APPEND( l, 64UL,                     index_ram_max ? FD_ACCDB_IDX_CARRY_MAX*sizeof(fd_accdb_idx_slot_t) : 0UL );
  ulong footprint = FD_LAYOUT_FINI( l, FD_ACCDB_SHMEM_ALIGN );
  if( out ) *out = *lo;
  return footprint;
}

ulong
fd_accdb_idx_bucket_sz( ulong max_accounts,
                        ulong index_ram_max ) {
  if( !index_ram_max ) return 0UL;
  return fd_accdb_idx_npage( max_accounts )*FD_ACCDB_IDX_PAGE_SZ;
}

ulong
fd_accdb_idx_file_sz( ulong max_accounts,
                      ulong index_ram_max ) {
  if( !index_ram_max ) return 0UL;
  ulong npage      = fd_accdb_idx_npage( max_accounts );
  ulong nrange     = ( npage*FD_ACCDB_IDX_PAGE_SZ + FD_ACCDB_IDX_WINDOW_SZ-1UL )/FD_ACCDB_IDX_WINDOW_SZ;
  ulong spill_base = fd_ulong_align_up( npage*FD_ACCDB_IDX_PAGE_SZ, 1UL<<20 );
  ulong extent     = fd_ulong_align_up( ( max_accounts*sizeof(fd_accdb_idx_slot_t)*3UL/2UL )/nrange, 1UL<<20 );
  return spill_base + nrange*extent;
}

ulong
fd_accdb_shmem_footprint( ulong max_accounts,
                          ulong index_ram_max,
                          ulong max_live_slots,
                          ulong max_account_writes_per_slot,
                          ulong partition_cnt,
                          ulong cache_footprint,
                          ulong cache_min_reserved,
                          ulong joiner_cnt,
                          ulong max_incremental_accounts ) {
  return fd_accdb_shmem_layout( NULL, max_accounts, index_ram_max, max_live_slots, max_account_writes_per_slot,
                                partition_cnt, cache_footprint, cache_min_reserved, joiner_cnt, max_incremental_accounts );
}

void *
fd_accdb_shmem_new( void * shmem,
                    ulong  max_accounts,
                    ulong  index_ram_max,
                    ulong  max_live_slots,
                    ulong  max_account_writes_per_slot,
                    ulong  partition_cnt,
                    ulong  partition_sz,
                    ulong  cache_footprint,
                    ulong  cache_min_reserved,
                    int    bundle_enabled,
                    ulong  seed,
                    ulong  joiner_cnt,
                    ulong  max_incremental_accounts ) {
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

  if( FD_UNLIKELY( partition_cnt>(1UL<<13) ) ) {
    FD_LOG_WARNING(( "partition_cnt must be at most %lu", 1UL<<13 ));
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

  /* The total addressable file space (partition_cnt * partition_sz)
     must not exceed 2^FD_ACCDB_OFF_BITS.  File offsets are stored in
     the 48-bit offset portion of acc->offset_fork, and the all-ones
     value FD_ACCDB_OFF_INVAL is reserved as a dirty sentinel.  The
     allocator guarantees record start offsets are always at least
     sizeof(fd_accdb_disk_meta_t) below a partition boundary, so a
     total of exactly 2^48 is safe (no valid offset reaches the
     sentinel), but exceeding it is not. */
  if( FD_UNLIKELY( partition_cnt>((1UL<<FD_ACCDB_OFF_BITS)/partition_sz) ) ) {
    FD_LOG_WARNING(( "partition_cnt*partition_sz must be at most %lu", 1UL<<FD_ACCDB_OFF_BITS ));
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

  if( FD_UNLIKELY( !cache_min_reserved ) ) {
    FD_LOG_WARNING(( "cache_min_reserved must be non-zero" ));
    return NULL;
  }

  fd_accdb_shmem_layout_t lo[1];
  if( FD_UNLIKELY( !fd_accdb_shmem_layout( lo, max_accounts, index_ram_max, max_live_slots, max_account_writes_per_slot,
                                           partition_cnt, cache_footprint, cache_min_reserved, joiner_cnt, max_incremental_accounts ) ) ) {
    FD_LOG_WARNING(( "invalid accdb shmem parameters" ));
    return NULL;
  }
  ulong pool_max        = lo->pool_max;
  ulong chain_cnt       = lo->chain_cnt;
  ulong txn_max         = lo->txn_max;
  ulong delta_chain_cnt = lo->delta_chain_cnt;
  ulong * cache_class_max = lo->cache_class_max;
  /* cidx packs only FD_ACCDB_CACHE_LINE_BITS bits of line index, so
     cache_class_max[c]>FD_ACCDB_CACHE_LINE_MAX would let line indices
     alias.  fd_accdb_cache_class_cnt clamps this; assert here so any
     future regression in the allocator is caught at shmem-new time
     rather than as silent cache corruption at runtime. */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) FD_TEST( cache_class_max[ c ]<=FD_ACCDB_CACHE_LINE_MAX );

  fd_accdb_shmem_t * accdb = (fd_accdb_shmem_t *)shmem;
  uchar * base = (uchar *)shmem;
  void * _fork_pool_ele       = base + lo->fork_pool_ele_off;
  void * _descends_sets       = base + lo->descends_off;
  void * _acc_map             = base + lo->acc_map_off;
  void * _acc_pool_ele        = base + lo->acc_pool_ele_off;
  void * _txn_pool_ele        = base + lo->txn_pool_ele_off;
  void * _partition_pool      = base + lo->partition_pool_off;
  void * _compaction_dlists[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    _compaction_dlists[ k ]   = base + lo->compaction_dlist_off[ k ];
  }
  void * _deferred_free_dlist = base + lo->deferred_free_dlist_off;
  void * _cache_regions[ FD_ACCDB_CACHE_CLASS_CNT ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    _cache_regions[ c ]       = base + lo->cache_region_off[ c ];
  }
  void * _delta_map           = base + lo->delta_chain_off;

  fd_memset( _acc_map, 0xFF, chain_cnt*sizeof(uint) );

  FD_TEST( acc_pool_new( accdb->acc_pool ) );
  acc_pool_t _acc_pool_join[1];
  FD_TEST( acc_pool_join( _acc_pool_join, accdb->acc_pool, _acc_pool_ele, pool_max ) );
  acc_pool_reset( _acc_pool_join );
  acc_pool_leave( _acc_pool_join );

  FD_TEST( fork_pool_new( accdb->fork_pool ) );
  fork_pool_t _fork_pool_join[1];
  FD_TEST( fork_pool_join( _fork_pool_join, accdb->fork_pool, _fork_pool_ele, max_live_slots ) );
  fork_pool_reset( _fork_pool_join );
  fork_pool_leave( _fork_pool_join );

  ulong descends_set_fp = descends_set_footprint( max_live_slots );
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    descends_set_t * descends_set = descends_set_join( descends_set_new( (uchar *)_descends_sets + i*descends_set_fp, max_live_slots ) );
    FD_TEST( descends_set );
  }

  FD_TEST( txn_pool_new( accdb->txn_pool ) );
  txn_pool_t _txn_pool_join[1];
  FD_TEST( txn_pool_join( _txn_pool_join, accdb->txn_pool, _txn_pool_ele, txn_max ) );
  txn_pool_reset( _txn_pool_join );
  txn_pool_leave( _txn_pool_join );

  fd_accdb_partition_t * partition_pool = partition_pool_join( partition_pool_new( _partition_pool, partition_cnt ) );
  FD_TEST( partition_pool );
  for( ulong i=0UL; i<partition_cnt; i++ ) {
    partition_pool_ele( partition_pool, i )->write_offset = 0UL;
  }

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    compaction_dlist_t * dlist = compaction_dlist_join( compaction_dlist_new( _compaction_dlists[ k ] ) );
    FD_TEST( dlist );
  }

  deferred_free_dlist_t * deferred_free = deferred_free_dlist_join( deferred_free_dlist_new( _deferred_free_dlist ) );
  FD_TEST( deferred_free );

  fd_memset( _delta_map, 0xFF, delta_chain_cnt*sizeof(uint) );

  accdb->seed = seed;
  accdb->root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  accdb->generation = 0U;

  accdb->partition_lock   = 0;
  accdb->snapshot_loading = 0;
  accdb->bundle_enabled   = bundle_enabled;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->clock_hand[ c ].val = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_free[ c ].ver_top = (ulong)UINT_MAX;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_free_cnt[ c ].val = 0UL;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong max_c       = cache_class_max[ c ];
    ulong floor_c     = fd_ulong_min( cache_min_reserved, max_c );
    ulong headroom    = ( max_c>floor_c ) ? ( max_c - floor_c ) : 0UL;
    ulong cap         = fd_ulong_min( 8192UL, (64UL<<20) / fd_accdb_cache_slot_sz[ c ] );
    ulong burst_floor = fd_ulong_min( 512UL, headroom/2UL );
    ulong target      = fd_ulong_min( cap, fd_ulong_max( headroom/10UL, burst_floor ) );
    accdb->cache_free_target   [ c ] = target;
    accdb->cache_free_low_water[ c ] = (target * 3UL) / 4UL;
  }

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    /* Sentinel: partition_offset == partition_sz forces the first
       allocate_next_write to fall into the partition-switch slow path,
       which acquires a real partition from the pool.

       The invalidity lives in the offset bits, not the index bits.  The
       index here (partition_cnt) is only nominally invalid: at the
       maximum partition_cnt==8192 it does not fit in the 13-bit index
       field and wraps to 0, a perfectly valid pool index. */
    accdb->whead[ k ]         = accdb_offset( partition_cnt, partition_sz );
    accdb->has_partition[ k ] = 0;
  }

  accdb->chain_cnt        = chain_cnt;
  accdb->max_live_slots   = max_live_slots;
  accdb->max_accounts     = max_accounts;
  accdb->max_account_writes_per_slot = max_account_writes_per_slot;
  accdb->joiner_cnt_max   = joiner_cnt;
  accdb->cache_min_reserved = cache_min_reserved;
  accdb->partition_cnt    = partition_cnt;
  accdb->partition_sz     = partition_sz;
  accdb->partition_max    = 0UL;

  accdb->partition_pool_off = (ulong)partition_pool - (ulong)shmem;
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    accdb->compaction_dlist_off[ k ] = (ulong)_compaction_dlists[ k ] - (ulong)shmem;
  }
  accdb->deferred_free_dlist_off = (ulong)_deferred_free_dlist - (ulong)shmem;

  accdb->deferred_acc_buf_off = lo->deferred_acc_buf_off;
  accdb->deferred_acc_buf_cnt = 0UL;
  accdb->deferred_acc_buf_max = txn_max;
  accdb->deferred_acc_epoch   = 0UL;

  /* Disk-resident index state and region offsets. */
  accdb->index_ram_max    = index_ram_max;
  accdb->pool_max         = pool_max;
  accdb->hot_chain_cnt    = lo->hot_chain_cnt;
  accdb->idx_npage        = lo->npage;
  accdb->idx_bloom_sz     = lo->bloom_sz;
  accdb->idx_spill_base   = lo->spill_base;
  accdb->idx_spill_extent = lo->spill_extent;
  accdb->idx_nrange       = lo->nrange;
  accdb->fork_pool_ele_off = lo->fork_pool_ele_off;
  accdb->descends_off      = lo->descends_off;
  accdb->acc_map_off       = lo->acc_map_off;
  accdb->acc_pool_ele_off  = lo->acc_pool_ele_off;
  accdb->txn_pool_ele_off  = lo->txn_pool_ele_off;
  accdb->partition_pool_region_off = lo->partition_pool_off;
  accdb->hot_map_off       = lo->hot_map_off;
  accdb->idx_seqlock_off   = lo->idx_seqlock_off;
  accdb->idx_bloom_off     = lo->idx_bloom_off;
  accdb->idx_range_off     = lo->idx_range_off;
  accdb->idx_stage_off     = lo->idx_stage_off;
  accdb->idx_window_off    = lo->idx_window_off;
  accdb->idx_carry_off     = lo->idx_carry_off;
  accdb->demote_chain_cursor = 0UL;
  accdb->hot_evict_cursor    = 0UL;
  accdb->idx_carry_cnt       = 0UL;
  accdb->acc_pool_used.val   = 0UL;
  if( index_ram_max ) {
    uint * hot_map = (uint *)( base + lo->hot_map_off );
    for( ulong i=0UL; i<lo->hot_chain_cnt; i++ ) hot_map[ i ] = FD_ACCDB_HOT_EMPTY;
    fd_memset( base + lo->idx_seqlock_off, 0, lo->npage*sizeof(uint) );
    fd_memset( base + lo->idx_bloom_off,   0, lo->bloom_sz );
    fd_memset( base + lo->idx_range_off,   0, lo->nrange*sizeof(fd_accdb_idx_range_t) );
  }

  accdb->epoch          = 1UL;
  accdb->snapshot_sync  = FD_ACCDB_SNAPSHOT_SYNC_IDLE;
  accdb->joiner_cnt     = 0UL;
  for( ulong i=0UL; i<FD_ACCDB_MAX_JOINERS; i++ ) accdb->joiner_epochs[ i ].val = ULONG_MAX;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_class_init[ c ].val = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_class_max[ c ] = cache_class_max[ c ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_region_off[ c ] = (ulong)_cache_regions[ c ] - (ulong)shmem;

  /* Pre-initialize every cache slot's metadata to the "empty" sentinel
     (gen=UINT_MAX, acc_idx=UINT_MAX, refcnt=0).  Without this, the
     lazy-init path in acquire_cache_line bumps cache_class_init before
     writing the sentinels into the freshly-claimed line; a concurrent
     background_preevict reading the bumped init counter could then sweep
     a slot whose memory still reads as zero, see (gen=0, acc_idx=0)
     instead of the skip predicate, CAS refcnt 0->EVICT_SENTINEL, and
     "evict" a line the lazy-init owner is about to publish. */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong slot_sz = fd_accdb_cache_slot_sz[ c ];
    for( ulong i=0UL; i<cache_class_max[ c ]; i++ ) {
      fd_accdb_cache_line_t * line = (fd_accdb_cache_line_t *)( (uchar *)_cache_regions[ c ] + i*slot_sz );
      line->key.generation = UINT_MAX;
      line->acc_idx        = UINT_MAX;
      line->refcnt         = 0U;
      line->referenced     = 0;
      line->persisted      = 1;
    }
  }

  /* If a class has enough slots for every joiner's worst case
     simultaneously (cache_min_reserved per joiner), no reservation can
     ever overflow.  Sentinel ULONG_MAX tells acquire/release to skip
     the atomic counters entirely. */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    if( cache_class_max[ c ]>=cache_min_reserved*joiner_cnt ) accdb->cache_class_used[ c ].val = ULONG_MAX;
    else                                                      accdb->cache_class_used[ c ].val = 0UL;
  }

  accdb->delta.seed       = seed+1UL;
  accdb->delta.chain_off  = lo->delta_chain_off;
  accdb->delta.chain_cnt  = (uint)delta_chain_cnt;
  accdb->delta.chain_mask = (uint)delta_chain_cnt - 1U;
  accdb->delta.ele_off    = lo->delta_ele_off;
  accdb->delta.ele_max    = max_incremental_accounts;
  accdb->delta.head       = 0UL;

  memset( accdb->shmetrics, 0, sizeof( fd_accdb_shmem_metrics_t ) );
  accdb->shmetrics->accounts_capacity = max_accounts;

  accdb->cmd_op      = FD_ACCDB_CMD_IDLE;
  accdb->cmd_fork_id = USHORT_MAX;

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

  if( FD_UNLIKELY( partition->bytes_freed<(accdb->partition_sz*FD_ACCDB_COMPACTION_THRESHOLD_PCT/100UL) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;

  /* While a snapshot load is in flight, defer all compaction so the
     compaction tile cannot race with the bulk loader.  Anything that
     crosses the threshold here will be re-checked by
     fd_accdb_snapshot_load_end's sweep when loading completes. */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( accdb->snapshot_loading ) ) ) return;

  /* Do not enqueue any currently active write-head partition.  Its
     write_offset is not yet finalized, so compaction cannot determine
     the valid data range.  The partition_lock serializes this check
     with change_partition, so it is not racy. */
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    if( FD_UNLIKELY( accdb->has_partition[ k ] && packed_partition_idx( &accdb->whead[ k ] )==partition_idx ) ) return;
  }

  uchar layer = partition->layer;
  compaction_dlist_t * compaction_dlist = (compaction_dlist_t *)( (uchar *)accdb + accdb->compaction_dlist_off[ layer ] );

  partition->marked_compaction = 1;
  partition->compaction_offset = 0UL;
  partition->compaction_ready_epoch = FD_ATOMIC_FETCH_AND_ADD( &accdb->epoch, 1UL );
  partition->queued = 1;
  if( FD_LIKELY( compaction_dlist_is_empty( compaction_dlist, partition_pool ) ) ) {
    FD_LOG_INFO(( "compaction of layer %u partition %lu started", (uint)layer, partition_pool_idx( partition_pool, partition ) ));
  }
  compaction_dlist_ele_push_tail( compaction_dlist, partition, partition_pool );
  accdb->shmetrics->in_compaction = 1;
  accdb->shmetrics->compactions_requested++;
}

void
fd_accdb_shmem_bytes_freed( fd_accdb_shmem_t * accdb,
                            ulong              offset,
                            ulong              sz ) {
  fd_accdb_partition_t * partition_pool = (fd_accdb_partition_t *)( (uchar *)accdb + accdb->partition_pool_off );

  ulong partition_idx = offset/accdb->partition_sz;
  fd_accdb_partition_t * partition = partition_pool_ele( partition_pool, partition_idx );
  /* Launder the pointer: GCC derives partition from (accdb + off) and so
     believes __builtin_object_size( &partition->bytes_freed )==0, which
     trips a spurious -Wstringop-overflow on the atomic add below. */
  FD_COMPILER_FORGET( partition );
  FD_ATOMIC_FETCH_AND_ADD( &partition->bytes_freed, sz );

  /* Fast-path exit: skip the lock if clearly below threshold or
     already enqueued. */
  if( FD_LIKELY( partition->bytes_freed<(accdb->partition_sz*FD_ACCDB_COMPACTION_THRESHOLD_PCT/100UL) ) ) return;
  if( FD_UNLIKELY( partition->marked_compaction ) ) return;

  spin_lock_acquire( &accdb->partition_lock );
  fd_accdb_shmem_try_enqueue_compaction( accdb, partition_idx );
  spin_lock_release( &accdb->partition_lock );
}

ulong
fd_accdb_shmem_partition_max( fd_accdb_shmem_t const * accdb ) {
  return accdb->partition_max;
}

ulong
fd_accdb_shmem_partition_sz( fd_accdb_shmem_t const * accdb ) {
  return accdb->partition_sz;
}

void
fd_accdb_shmem_partition_info( fd_accdb_shmem_t const *          accdb,
                               ulong                             partition_idx,
                               fd_accdb_shmem_partition_info_t * out ) {
  fd_accdb_partition_t const * partition_pool = (fd_accdb_partition_t const *)( (uchar const *)accdb + accdb->partition_pool_off );
  fd_accdb_partition_t const * p              = partition_pool_ele_const( partition_pool, partition_idx );

  out->file_offset       = partition_idx * accdb->partition_sz;
  out->is_write_head     = 0;
  /* If this partition is currently the active write head for any
     layer, partition->write_offset is stale (it's only updated at
     handoff in change_partition).  The live tip lives in whead[layer].
     Surface the live value so the GUI shows real-time fill, not the
     "0 until rolled" snapshot.  The tip is a reservation that can
     briefly overrun the partition, so clamp rather than show >100%. */
  ulong head_off = ULONG_MAX;
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    if( !FD_VOLATILE_CONST( accdb->has_partition[ k ] ) ) continue;
    accdb_offset_t whead = { .val = FD_VOLATILE_CONST( accdb->whead[ k ].val ) };
    if( packed_partition_idx( &whead )==partition_idx ) {
      head_off           = packed_partition_offset( &whead );
      out->is_write_head = 1;
      break;
    }
  }
  if( FD_UNLIKELY( out->is_write_head ) ) {
    out->write_offset_raw = head_off;
    out->write_offset     = fd_ulong_min( head_off, accdb->partition_sz );
  } else {
    out->write_offset_raw = FD_VOLATILE_CONST( p->write_offset );
    out->write_offset     = out->write_offset_raw;
  }
  out->bytes_freed       = FD_VOLATILE_CONST( p->bytes_freed );
  out->compaction_offset = FD_VOLATILE_CONST( p->compaction_offset );
  out->read_ops          = FD_VOLATILE_CONST( p->read_ops );
  out->bytes_read        = FD_VOLATILE_CONST( p->bytes_read );
  out->write_ops         = FD_VOLATILE_CONST( p->write_ops );
  out->bytes_written     = FD_VOLATILE_CONST( p->bytes_written );
  out->created_ticks     = (long)FD_VOLATILE_CONST( p->created_ticks );
  out->filled_ticks      = (long)FD_VOLATILE_CONST( p->filled_ticks );
  out->layer             = p->layer;
  uchar compacting       = FD_VOLATILE_CONST( p->compacting_now );
  uchar queued           = FD_VOLATILE_CONST( p->queued );
  out->compaction_state  = compacting ? 2 : ( queued ? 1 : 0 );
}

FD_STATIC_ASSERT( sizeof(((fd_accdb_shmem_writer_barrier_t *)0)->bits)*8UL==FD_ACCDB_MAX_JOINERS, barrier_width );

void
fd_accdb_shmem_writer_barrier_capture( fd_accdb_shmem_t const *          accdb,
                                       fd_accdb_shmem_writer_barrier_t * barrier ) {
  memset( barrier->bits, 0, sizeof(barrier->bits) );
  ulong joiner_cnt = FD_VOLATILE_CONST( accdb->joiner_cnt );
  for( ulong t=0UL; t<joiner_cnt; t++ ) {
    if( FD_VOLATILE_CONST( accdb->joiner_epochs[ t ].val )==ULONG_MAX ) continue;
    barrier->bits[ t/64UL ] |= 1UL<<(t%64UL);
  }
}

ulong
fd_accdb_shmem_writer_barrier_poll( fd_accdb_shmem_t const *          accdb,
                                    fd_accdb_shmem_writer_barrier_t * barrier ) {
  ulong remain = 0UL;
  for( ulong w=0UL; w<sizeof(barrier->bits)/sizeof(ulong); w++ ) {
    ulong bits = barrier->bits[ w ];
    while( bits ) {
      ulong b = (ulong)fd_ulong_find_lsb( bits );
      bits &= bits-1UL;
      if( FD_VOLATILE_CONST( accdb->joiner_epochs[ w*64UL+b ].val )==ULONG_MAX ) {
        barrier->bits[ w ] &= ~(1UL<<b);
      }
    }
    remain |= barrier->bits[ w ];
  }
  return remain;
}

ulong const *
fd_accdb_shmem_snapshot_sync( fd_accdb_shmem_t const * accdb ) {
  return &accdb->snapshot_sync;
}
