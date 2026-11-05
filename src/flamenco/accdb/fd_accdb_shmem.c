#define _GNU_SOURCE
#include "fd_accdb_shmem.h"
#include "fd_accdb_private.h"
#include "fd_accdb_idx.h"

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

/* acc_map chains.  Index mode: acc_map holds only unrooted, young
   rooted and unspill versions (rooted hot copies live on hot_map, which
   keeps pool-sized chains), so size by the in-flight floor.  Chained:
   any pow2 count is correct, entries stay pool-bound. */

static inline ulong
acc_chain_cnt( ulong pool_max,
               ulong index_ram_entries,
               ulong max_account_writes_per_slot ) {
  ulong n = index_ram_entries ? fd_ulong_min( pool_max, fd_accdb_idx_ram_min( max_account_writes_per_slot, 0UL ) ) : pool_max;
  return fd_ulong_pow2_up( (n>>1) + (n&1UL) );
}

static inline ulong
fifo_ele( ulong max_accounts,
          ulong index_ram_entries ) {
  if( !index_ram_entries || index_ram_entries>=max_accounts ) return 0UL;
  return fd_ulong_min( index_ram_entries, FD_ACCDB_FIFO_WINDOW );
}

ulong
fd_accdb_scratch_sz( ulong max_live_slots,
                     ulong max_account_writes_per_slot,
                     ulong max_accounts,
                     ulong index_ram_entries ) {
  ulong sz = fd_ulong_align_up( max_live_slots*max_account_writes_per_slot*sizeof(uint), 4096UL );
  if( fifo_ele( max_accounts, index_ram_entries )<index_ram_entries )
    sz += ( index_ram_entries/FD_ACCDB_FIFO_CHUNK+2UL )*FD_ACCDB_FIFO_CHUNK*sizeof(ulong);
  return sz;
}

ulong
fd_accdb_idx_file_sz( ulong max_accounts,
                      ulong index_ram_entries,
                      ulong max_live_slots,
                      ulong max_account_writes_per_slot ) {
  if( !index_ram_entries || index_ram_entries>=max_accounts ) return 0UL;
  ulong txn_max = max_live_slots*max_account_writes_per_slot;
  return ( fd_accdb_idx_npage( max_accounts )+fd_accdb_idx_npage( txn_max ) )*FD_ACCDB_IDX_PAGE_SZ
       + fd_accdb_olog_chunk_cnt( txn_max, max_live_slots )*FD_ACCDB_OLOG_CHUNK*sizeof(fd_accdb_olog_rec_t);
}

ulong
fd_accdb_shmem_footprint( ulong max_accounts,
                          ulong max_live_slots,
                          ulong max_account_writes_per_slot,
                          ulong partition_cnt,
                          ulong cache_footprint,
                          ulong cache_min_reserved,
                          ulong joiner_cnt,
                          ulong max_incremental_accounts,
                          ulong index_ram_entries ) {
  if( FD_UNLIKELY( !max_accounts    ) ) return 0UL;
  if( FD_UNLIKELY( index_ram_entries>=max_accounts ) ) index_ram_entries = 0UL;
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

  ulong txn_max = max_live_slots * max_account_writes_per_slot;
  if( FD_UNLIKELY( txn_max/max_account_writes_per_slot!=max_live_slots ) ) return 0UL;
  if( FD_UNLIKELY( txn_max>=UINT_MAX                        ) ) return 0UL;

  int   defer_spill    = txn_max>FD_ACCDB_DEFER_WINDOW_ELE;
  ulong defer_resident = defer_spill ? FD_ACCDB_DEFER_WINDOW_ELE-FD_ACCDB_DEFER_STAGE_ELE : txn_max;
  ulong defer_stage    = defer_spill ? FD_ACCDB_DEFER_STAGE_ELE : 0UL;

  ulong descends_fp = descends_set_footprint( max_live_slots );
  if( FD_UNLIKELY( !descends_fp                          ) ) return 0UL;
  if( FD_UNLIKELY( max_live_slots>ULONG_MAX/descends_fp  ) ) return 0UL;

  ulong pool_max  = index_ram_entries ? index_ram_entries : max_accounts;
  ulong chain_cnt = fd_ulong_pow2_up( (pool_max>>1) + (pool_max&1UL) );
  ulong acc_chain = acc_chain_cnt( pool_max, index_ram_entries, max_account_writes_per_slot );

  if( FD_UNLIKELY( chain_cnt>ULONG_MAX/sizeof(uint) ) ) return 0UL;

  if( FD_UNLIKELY( !cache_footprint ) ) return 0UL;
  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];
  if( FD_UNLIKELY( !fd_accdb_cache_class_cnt( cache_footprint, cache_min_reserved, cache_class_max ) ) ) return 0UL;

  if( FD_UNLIKELY( max_incremental_accounts>UINT_MAX ) ) return 0UL;
  ulong delta_chain_cnt = fd_ulong_pow2_up( (max_incremental_accounts>>1) + (max_incremental_accounts&1UL) );

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)      );
  l = FD_LAYOUT_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            acc_chain*sizeof(uint)                                  );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_accmeta_t), pool_max*sizeof(fd_accdb_accmeta_t)                  );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_txn_t),  index_ram_entries ? pool_max*sizeof(uint) : txn_max*sizeof(fd_accdb_txn_t) );
  l = FD_LAYOUT_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    l = FD_LAYOUT_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                          );
  }
  l = FD_LAYOUT_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                      );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            (defer_resident+defer_stage)*sizeof(uint)               );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_cache_line_t), cache_class_max[c]*fd_accdb_cache_slot_sz[c]   );
  }
  l = FD_LAYOUT_APPEND( l, alignof(uint),            delta_chain_cnt*sizeof(uint)                            );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_delta_t),max_incremental_accounts*sizeof(fd_accdb_delta_t)       );
  if( index_ram_entries ) {
    ulong bkt_npage = fd_accdb_idx_npage( max_accounts );
    l = FD_LAYOUT_APPEND( l, 64UL,                     fd_accdb_idx_seq_cnt( bkt_npage )*sizeof(uint)          );
    l = FD_LAYOUT_APPEND( l, 64UL,                     fd_accdb_cf_nb( max_accounts )*sizeof(ulong)            );
    l = FD_LAYOUT_APPEND( l, 64UL,                     FD_ACCDB_CF_STASH_MAX*sizeof(ulong)                     );
    l = FD_LAYOUT_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
    l = FD_LAYOUT_APPEND( l, alignof(uint),            FD_ACCDB_BG_DEFER_MAX*sizeof(uint)                      );
    l = FD_LAYOUT_APPEND( l, alignof(ulong),           fifo_ele( max_accounts, index_ram_entries )*sizeof(ulong) );
    l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_req_t),  (FD_ACCDB_RING_RES_CAP+FD_ACCDB_RING_HINT_CAP)*sizeof(fd_accdb_req_t) );
    l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_prot_t), FD_ACCDB_PROT_MAX*sizeof(fd_accdb_prot_t)               );
    l = FD_LAYOUT_APPEND( l, alignof(ulong),           FD_ACCDB_UNSPILL_MAX*sizeof(ulong)                      );
    l = FD_LAYOUT_APPEND( l, alignof(uint),            FD_ACCDB_MAX_JOINERS*FD_ACCDB_MAX_ACQUIRE_CNT*sizeof(uint) );
    l = FD_LAYOUT_APPEND( l, 64UL,                     fd_accdb_idx_seq_cnt( fd_accdb_idx_npage( txn_max ) )*sizeof(uint) );
    l = FD_LAYOUT_APPEND( l, alignof(uint),            fd_accdb_olog_chunk_cnt( txn_max, max_live_slots )*sizeof(uint) );
    l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_idx_fork_t), max_live_slots*sizeof(fd_accdb_idx_fork_t)          );
    l = FD_LAYOUT_APPEND( l, 64UL,                     max_live_slots*fd_accdb_ovl_bloom_words( max_live_slots )*sizeof(ulong) );
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
                    ulong  cache_min_reserved,
                    int    bundle_enabled,
                    ulong  seed,
                    ulong  joiner_cnt,
                    ulong  max_incremental_accounts,
                    ulong  index_ram_entries ) {
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

  if( FD_UNLIKELY( index_ram_entries>=max_accounts ) ) index_ram_entries = 0UL;
  ulong pool_max  = index_ram_entries ? index_ram_entries : max_accounts;
  ulong chain_cnt = fd_ulong_pow2_up( (pool_max>>1) + (pool_max&1UL) );
  ulong acc_chain = acc_chain_cnt( pool_max, index_ram_entries, max_account_writes_per_slot );

  if( FD_UNLIKELY( chain_cnt>ULONG_MAX/sizeof(uint) ) ) {
    FD_LOG_WARNING(( "chain_cnt*sizeof(uint) overflows" ));
    return NULL;
  }

  if( FD_UNLIKELY( !cache_min_reserved ) ) {
    FD_LOG_WARNING(( "cache_min_reserved must be non-zero" ));
    return NULL;
  }

  ulong cache_class_max[ FD_ACCDB_CACHE_CLASS_CNT ];
  if( FD_UNLIKELY( !fd_accdb_cache_class_cnt( cache_footprint, cache_min_reserved, cache_class_max ) ) ) {
    FD_LOG_WARNING(( "invalid cache_footprint" ));
    return NULL;
  }
  /* cidx packs only FD_ACCDB_CACHE_LINE_BITS bits of line index, so
     cache_class_max[c]>FD_ACCDB_CACHE_LINE_MAX would let line indices
     alias.  fd_accdb_cache_class_cnt clamps this; assert here so any
     future regression in the allocator is caught at shmem-new time
     rather than as silent cache corruption at runtime. */
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) FD_TEST( cache_class_max[ c ]<=FD_ACCDB_CACHE_LINE_MAX );

  if( FD_UNLIKELY( max_incremental_accounts>UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_incremental_accounts must be at most %u", UINT_MAX ));
    return NULL;
  }

  ulong delta_chain_cnt = fd_ulong_pow2_up( (max_incremental_accounts>>1) + (max_incremental_accounts&1UL) );
  if( FD_UNLIKELY( delta_chain_cnt>UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_incremental_accounts must be at most %u", UINT_MAX ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_accdb_shmem_t * accdb = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool_ele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)      );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            acc_chain*sizeof(uint)                                  );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t), pool_max*sizeof(fd_accdb_accmeta_t)                         );
  ulong  txn_pool_max      = index_ram_entries ? 0UL : txn_max; /* index mode: uint fork_next[ pool_max ] instead */
  void * _txn_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_txn_t),  index_ram_entries ? pool_max*sizeof(uint) : txn_max*sizeof(fd_accdb_txn_t) );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlists[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    _compaction_dlists[ k ] = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                           );
  }
  void * _deferred_free_dlist = FD_SCRATCH_ALLOC_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                   );
  int    defer_spill          = txn_max>FD_ACCDB_DEFER_WINDOW_ELE;
  ulong  defer_resident       = defer_spill ? FD_ACCDB_DEFER_WINDOW_ELE-FD_ACCDB_DEFER_STAGE_ELE : txn_max;
  ulong  defer_stage          = defer_spill ? FD_ACCDB_DEFER_STAGE_ELE : 0UL;
  void * _deferred_acc_buf    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            (defer_resident+defer_stage)*sizeof(uint)            );
  void * _cache_regions[ FD_ACCDB_CACHE_CLASS_CNT ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    _cache_regions[ c ] = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_cache_line_t), cache_class_max[c]*fd_accdb_cache_slot_sz[c]        );
  }
  void * _delta_map  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),             delta_chain_cnt*sizeof(uint)                      );
  void * _delta_pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_delta_t), max_incremental_accounts*sizeof(fd_accdb_delta_t) );
  ulong  bkt_npage   = index_ram_entries ? fd_accdb_idx_npage( max_accounts ) : 0UL;
  ulong  cf_nb       = index_ram_entries ? fd_accdb_cf_nb( max_accounts )     : 0UL;
  ulong  hot_cnt     = index_ram_entries ? chain_cnt                          : 0UL;
  void * _bkt_seq    = FD_SCRATCH_ALLOC_APPEND( l, 64UL,          fd_accdb_idx_seq_cnt( bkt_npage )*sizeof(uint)*!!index_ram_entries );
  void * _cf         = FD_SCRATCH_ALLOC_APPEND( l, 64UL,          cf_nb*sizeof(ulong)                               );
  void * _cf_stash   = FD_SCRATCH_ALLOC_APPEND( l, 64UL,          FD_ACCDB_CF_STASH_MAX*sizeof(ulong)*!!index_ram_entries );
  void * _hot_map    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), hot_cnt*sizeof(uint)                              );
  void * _bg_defer   = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), FD_ACCDB_BG_DEFER_MAX*sizeof(uint)*!!index_ram_entries );
  void * _fifo       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), fifo_ele( max_accounts, index_ram_entries )*sizeof(ulong) );
  void * _ring       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_req_t),  (FD_ACCDB_RING_RES_CAP+FD_ACCDB_RING_HINT_CAP)*sizeof(fd_accdb_req_t)*!!index_ram_entries );
  void * _prot       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_prot_t), FD_ACCDB_PROT_MAX*sizeof(fd_accdb_prot_t)*!!index_ram_entries );
  void * _unspill    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), FD_ACCDB_UNSPILL_MAX*sizeof(ulong)*!!index_ram_entries );
  void * _ovl_ans    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),  FD_ACCDB_MAX_JOINERS*FD_ACCDB_MAX_ACQUIRE_CNT*sizeof(uint)*!!index_ram_entries );
  ulong  ovl_npage   = index_ram_entries ? fd_accdb_idx_npage( txn_max ) : 0UL;
  ulong  olog_cnt    = index_ram_entries ? fd_accdb_olog_chunk_cnt( txn_max, max_live_slots ) : 0UL;
  ulong  bloom_words = index_ram_entries ? fd_accdb_ovl_bloom_words( max_live_slots ) : 0UL;
  void * _ovl_seq    = FD_SCRATCH_ALLOC_APPEND( l, 64UL,          fd_accdb_idx_seq_cnt( ovl_npage )*sizeof(uint)*!!index_ram_entries );
  void * _olog_next  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), olog_cnt*sizeof(uint) );
  void * _idx_fork   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_idx_fork_t), max_live_slots*sizeof(fd_accdb_idx_fork_t)*!!index_ram_entries );
  void * _bloom      = FD_SCRATCH_ALLOC_APPEND( l, 64UL,          max_live_slots*bloom_words*sizeof(ulong) );
  if( index_ram_entries ) {
    memset( _ring,    0, (FD_ACCDB_RING_RES_CAP+FD_ACCDB_RING_HINT_CAP)*sizeof(fd_accdb_req_t) );
  }
  if( index_ram_entries ) {
    memset( _bkt_seq,  0,    fd_accdb_idx_seq_cnt( bkt_npage )*sizeof(uint) );
    memset( _cf,       0,    cf_nb*sizeof(ulong) );
    memset( _cf_stash, 0,    FD_ACCDB_CF_STASH_MAX*sizeof(ulong) );
    memset( _hot_map,  0xFF, hot_cnt*sizeof(uint) );
  }

  fd_memset( _acc_map, 0xFF, acc_chain*sizeof(uint) );

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
  FD_TEST( txn_pool_join( _txn_pool_join, accdb->txn_pool, _txn_pool_ele, txn_pool_max ) );
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
  accdb->grow_lock        = 0;
  accdb->snapshot_loading = 0;
  accdb->bundle_enabled   = bundle_enabled;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->clock_hand[ c ].val = 0UL;
  for( ulong j=0UL; j<FD_ACCDB_MAX_JOINERS; j++ ) {
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_free[ j ].ver_top[ c ] = (ulong)UINT_MAX;
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache_free_cnt[ j ].val[ c ] = 0UL;
  }
  memset( accdb->cache_free_have, 0, sizeof(accdb->cache_free_have) );
  for( ulong j=0UL; j<FD_ACCDB_MAX_JOINERS; j++ ) accdb->cache_hazard[ j ].cnt = 0UL;

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

  accdb->chain_cnt        = acc_chain;
  accdb->max_live_slots   = max_live_slots;
  accdb->max_accounts     = max_accounts;

  accdb->index_ram_entries = index_ram_entries;
  accdb->acc_pool_max      = pool_max;
  accdb->txn_pool_max      = txn_pool_max;
  accdb->acc_map_off       = (ulong)_acc_map      - (ulong)shmem;
  accdb->acc_pool_off      = (ulong)_acc_pool_ele - (ulong)shmem;
  accdb->idx_bkt_npage     = bkt_npage;
  accdb->idx_bkt_seq_off   = (ulong)_bkt_seq  - (ulong)shmem;
  accdb->idx_cf_nb         = cf_nb;
  accdb->idx_cf_off        = (ulong)_cf       - (ulong)shmem;
  accdb->idx_cf_stash_off  = (ulong)_cf_stash - (ulong)shmem;
  accdb->idx_cf_stash_cnt  = 0UL;
  accdb->idx_cf_disabled   = 0UL;
  accdb->idx_cf_seq        = 0UL;
  accdb->idx_hot_chain_cnt = hot_cnt;
  accdb->idx_hot_map_off   = (ulong)_hot_map  - (ulong)shmem;
  accdb->idx_file_sz       = fd_accdb_idx_file_sz( max_accounts, index_ram_entries, max_live_slots, max_account_writes_per_slot );
  accdb->idx_bg_defer_off  = (ulong)_bg_defer - (ulong)shmem;
  accdb->bg_defer_head     = 0UL;
  accdb->bg_defer_tail     = 0UL;
  accdb->bg_defer_sealed   = 0UL;
  accdb->pool_avail        = pool_max;
  accdb->idx_fifo_off      = (ulong)_fifo - (ulong)shmem;
  accdb->fifo_head         = 0UL;
  accdb->fifo_tail         = 0UL;
  accdb->fifo_chunk        = fifo_ele( max_accounts, index_ram_entries )<index_ram_entries ? FD_ACCDB_FIFO_CHUNK : 0UL;
  accdb->fifo_file_off     = fd_ulong_align_up( txn_max*sizeof(uint), 4096UL );
  for( ulong i=0UL; i<FD_ACCDB_FIFO_SLOTS; i++ ) accdb->fifo_tag[ i ] = ULONG_MAX;
  accdb->hot_cursor        = 0UL;
  /* Headroom T2 promotes leave for releases. */
  ulong reserve = fd_ulong_max( 1UL<<20, 5UL*max_account_writes_per_slot );
  if( index_ram_entries ) reserve = fd_ulong_min( reserve, pool_max/4UL ); /* tiny test pools */
  accdb->promote_reserve   = reserve;
  accdb->prot_off          = (ulong)_prot - (ulong)shmem;
  accdb->prot_head         = 0UL;
  accdb->prot_tail         = 0UL;
  memset( accdb->ring_res,  0, sizeof(fd_accdb_ring_t) );
  memset( accdb->ring_hint, 0, sizeof(fd_accdb_ring_t) );
  accdb->ring_res ->cap     = FD_ACCDB_RING_RES_CAP;
  accdb->ring_res ->ele_off = (ulong)_ring - (ulong)shmem;
  accdb->ring_hint->cap     = FD_ACCDB_RING_HINT_CAP;
  accdb->ring_hint->ele_off = (ulong)_ring + FD_ACCDB_RING_RES_CAP*sizeof(fd_accdb_req_t) - (ulong)shmem;
  memset( accdb->res_ack, 0, sizeof(accdb->res_ack) );
  accdb->idx_ovl_npage      = ovl_npage;
  accdb->idx_ovl_seq_off    = (ulong)_ovl_seq   - (ulong)shmem;
  accdb->idx_olog_byte0     = ( bkt_npage+ovl_npage )*FD_ACCDB_IDX_PAGE_SZ;
  accdb->idx_olog_chunk_cnt = olog_cnt;
  accdb->idx_olog_next_off  = (ulong)_olog_next - (ulong)shmem;
  accdb->idx_fork_off       = (ulong)_idx_fork  - (ulong)shmem;
  accdb->idx_bloom_off      = (ulong)_bloom     - (ulong)shmem;
  accdb->idx_bloom_words    = bloom_words;
  accdb->spill_fork         = USHORT_MAX;
  accdb->spill_txn          = UINT_MAX;
  accdb->ovl_fork_cnt       = 0UL;
  accdb->ovl_epoch          = 0UL;
  accdb->thaw_fork          = USHORT_MAX;
  accdb->unspill_off        = (ulong)_unspill - (ulong)shmem;
  accdb->unspill_head       = 0UL;
  accdb->unspill_tail       = 0UL;
  accdb->unspill_cnt        = 0UL;
  accdb->unspill_cap        = pool_max>=(FD_ACCDB_UNSPILL_MAX<<4) ? FD_ACCDB_UNSPILL_MAX/2UL : fd_ulong_max( 4UL, pool_max/16UL ); /* tiny test pools */
  accdb->ovl_ans_off        = (ulong)_ovl_ans - (ulong)shmem;
  accdb->olog_free          = olog_cnt ? 0U : UINT_MAX;
  accdb->stage_base         = accdb->idx_olog_byte0 + olog_cnt*FD_ACCDB_OLOG_CHUNK*sizeof(fd_accdb_olog_rec_t);
  accdb->stage_head         = 0UL;
  accdb->stage_falloc       = 0UL;
  memset( accdb->stage_dir, 0, sizeof(accdb->stage_dir) );
  if( index_ram_entries ) {
    memset( _ovl_seq, 0, fd_accdb_idx_seq_cnt( ovl_npage )*sizeof(uint) );
    uint * nx = (uint *)_olog_next;
    for( ulong i=0UL; i<olog_cnt; i++ ) nx[ i ] = i+1UL<olog_cnt ? (uint)(i+1UL) : UINT_MAX;
    fd_accdb_idx_fork_t * f = (fd_accdb_idx_fork_t *)_idx_fork;
    for( ulong i=0UL; i<max_live_slots; i++ ) f[ i ] = (fd_accdb_idx_fork_t){ .olog_head = UINT_MAX, .olog_tail = UINT_MAX };
    memset( _bloom, 0, max_live_slots*bloom_words*sizeof(ulong) );
  }
  accdb->max_account_writes_per_slot = max_account_writes_per_slot;
  accdb->joiner_cnt_max   = joiner_cnt;
  accdb->cache_min_reserved = cache_min_reserved;
  accdb->partition_cnt    = partition_cnt;
  accdb->partition_sz     = partition_sz;
  accdb->partition_max    = 0UL;
  accdb->partition_fallocated = 0UL;

  accdb->partition_pool_off = (ulong)partition_pool - (ulong)shmem;
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    accdb->compaction_dlist_off[ k ] = (ulong)_compaction_dlists[ k ] - (ulong)shmem;
  }
  accdb->deferred_free_dlist_off = (ulong)_deferred_free_dlist - (ulong)shmem;

  accdb->deferred_acc_buf_off = (ulong)_deferred_acc_buf - (ulong)shmem;
  accdb->deferred_acc_buf_cnt = 0UL;
  accdb->deferred_acc_buf_max = txn_max;
  accdb->deferred_acc_epoch   = 0UL;
  accdb->deferred_acc_resident = defer_resident;
  accdb->deferred_acc_stage    = defer_stage;

  accdb->epoch          = 1UL;
  accdb->snapshot_sync  = FD_ACCDB_SNAPSHOT_SYNC_IDLE;
  accdb->joiner_cnt     = 0UL;
  accdb->free_owner_cnt = 0UL;
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
      line->generation     = UINT_MAX;
      line->acc_idx        = UINT_MAX;
      line->refcnt         = 0U;
      line->referenced     = 0;
      line->hazard_pending = 0;
      line->hazard_read    = 0;
      line->persisted      = 1;
      line->loading        = 0;
      line->seq            = 0U;
    }
  }

  accdb->delta.seed       = seed+1UL;
  accdb->delta.chain_off  = (ulong)_delta_map - (ulong)shmem;
  accdb->delta.chain_cnt  = (uint)delta_chain_cnt;
  accdb->delta.chain_mask = (uint)delta_chain_cnt - 1U;
  accdb->delta.ele_off    = (ulong)_delta_pool - (ulong)shmem;
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
