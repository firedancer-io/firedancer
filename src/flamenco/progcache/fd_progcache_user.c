#include "fd_prog_load.h"
#include "fd_progcache_user.h"
#include "fd_progcache_rec.h"
#include "../accdb/fd_accdb_sync.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../../util/racesan/fd_racesan_target.h"

FD_TL fd_progcache_metrics_t fd_progcache_metrics_default;

fd_progcache_t *
fd_progcache_join( fd_progcache_t *       ljoin,
                   fd_progcache_shmem_t * shmem,
                   uchar *                scratch,
                   ulong                  scratch_sz ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_LIKELY( scratch_sz ) ) {
    if( FD_UNLIKELY( !scratch ) ) {
      FD_LOG_WARNING(( "NULL scratch" ));
      return NULL;
    }
    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, FD_PROGCACHE_SCRATCH_ALIGN ) ) ) {
      FD_LOG_WARNING(( "misaligned scratch" ));
      return NULL;
    }
  }
  memset( ljoin, 0, sizeof(fd_progcache_t) );
  if( FD_UNLIKELY( !fd_progcache_shmem_join( ljoin, shmem ) ) ) return NULL;
  /* FIXME initialize lineage */

  ljoin->metrics    = &fd_progcache_metrics_default;
  ljoin->scratch    = scratch;
  ljoin->scratch_sz = scratch_sz;

  return ljoin;
}

void *
fd_progcache_leave( fd_progcache_t *        cache,
                    fd_progcache_shmem_t ** opt_shmem ) {
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL cache" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_progcache_shmem_leave( cache, opt_shmem ) ) ) return NULL;
  cache->scratch    = NULL;
  cache->scratch_sz = 0UL;
  return cache;
}

static void
fd_progcache_clock_evict( fd_progcache_t * cache ) {

}

/* fd_progcache_load_fork pivots the progcache object to the selected
   fork (identified by tip XID).

   Populates cache->fork, which is a array-backed list of XIDs sorted
   newest to oldest.  Cache lookups only respect records with an XID
   present in that list.

   For any given xid, the epoch_slot0 is assumed to stay constant. */

static void
fd_progcache_load_fork_slow( fd_progcache_t *          cache,
                             fd_funk_txn_xid_t const * xid,
                             ulong                     epoch_slot0 ) {
  FD_TEST( xid->ul[0]>=epoch_slot0 );

  fd_accdb_lineage_t *        lineage = cache->lineage;
  fd_progcache_join_t const * ljoin   = cache->join;
  fd_rwlock_read( ljoin->txn.lock );

  uint next_idx = (uint)fd_prog_txnm_idx_query_const( ljoin->txn.map, xid, UINT_MAX, ljoin->txn.pool );
  if( FD_UNLIKELY( next_idx==UINT_MAX ) ) FD_LOG_ERR(( "XID %lu:%lu not found", xid->ul[0], xid->ul[1] ));

  lineage->fork_depth = 0UL;

  ulong txn_max = fd_prog_txnp_max( ljoin->txn.pool );
  ulong i;
  for( i=0UL; i<FD_PROGCACHE_DEPTH_MAX; i++ ) {
    fd_progcache_txn_t * txn = &ljoin->txn.pool[ next_idx ];
    lineage->fork[ i ] = txn->xid;
    next_idx           = txn->parent_idx;
    if( FD_UNLIKELY( next_idx==UINT_MAX ) ) break;
    FD_CRIT( next_idx<=txn_max, "invalid next_idx" );
    if( FD_UNLIKELY( ljoin->txn.pool[ next_idx ].xid.ul[0]<epoch_slot0 ) ) break;
  }

  /* Only include published/rooted records if they include at least one
     cache entry from the current epoch. */
  if( ljoin->shmem->txn.last_publish->ul[0] >= epoch_slot0 &&
      lineage->fork_depth < FD_PROGCACHE_DEPTH_MAX ) {
    fd_funk_txn_xid_set_root( &lineage->fork[ lineage->fork_depth++ ] );
  }

  fd_rwlock_unread( ljoin->txn.lock );
}

static inline void
fd_progcache_load_fork( fd_progcache_t *          cache,
                        fd_funk_txn_xid_t const * xid,
                        ulong                     epoch_slot0 ) {
  /* Skip if already on the correct fork */
  fd_accdb_lineage_t * lineage = cache->lineage;
  if( FD_LIKELY( (!!lineage->fork_depth) & (!!fd_funk_txn_xid_eq( &lineage->fork[ 0 ], xid ) ) ) ) return;
  cache->metrics->fork_switch_cnt++;
  fd_progcache_load_fork_slow( cache, xid, epoch_slot0 ); /* switch fork */
}

/* fd_progcache_query searches for a program cache entry on the current
   fork.  Stops short of an epoch boundary. */

static int
fd_progcache_search_chain( fd_progcache_t const *    cache,
                           ulong                     chain_idx,
                           fd_funk_rec_key_t const * key,
                           ulong                     epoch_slot0,
                           fd_progcache_rec_t **     out_rec ) {
  *out_rec = NULL;

  fd_progcache_join_t const *                ljoin     = cache->join;
  fd_accdb_lineage_t const *                 lineage   = cache->lineage;
  fd_prog_recm_shmem_t *                     shmap     = ljoin->rec.map->map;
  fd_prog_recm_shmem_private_chain_t const * chain_tbl = fd_prog_recm_shmem_private_chain_const( shmap, 0UL );
  fd_prog_recm_shmem_private_chain_t const * chain     = chain_tbl + chain_idx;
  fd_progcache_rec_t *                       rec_tbl   = ljoin->rec.pool->ele;
  ulong                                      rec_max   = fd_prog_recp_ele_max( ljoin->rec.pool );
  ulong                                      ver_cnt   = FD_VOLATILE_CONST( chain->ver_cnt );
  ulong                                      root_slot = FD_VOLATILE_CONST( ljoin->shmem->txn.last_publish->ul[0] );

  /* Start a speculative transaction for the chain containing revisions
     of the program cache key we are looking for. */
  ulong cnt = fd_funk_rec_map_private_vcnt_cnt( ver_cnt );
  if( FD_UNLIKELY( fd_funk_rec_map_private_vcnt_ver( ver_cnt )&1 ) ) {
    return FD_MAP_ERR_AGAIN; /* chain is locked */
  }
  FD_COMPILER_MFENCE();
  uint ele_idx = chain->head_cidx;

  /* Walk the map chain, remember the best entry */
  fd_progcache_rec_t * best      = NULL;
  long                 best_slot = -1L;
  for( ulong i=0UL; i<cnt; i++, ele_idx=rec_tbl[ ele_idx ].map_next ) {
    fd_progcache_rec_t * rec = &rec_tbl[ ele_idx ];

    /* Skip over unrelated records (hash collision) */
    if( FD_UNLIKELY( !fd_funk_rec_key_eq( rec->pair.key, key ) ) ) continue;

    /* Skip over records from an older epoch (FIXME could bail early
       here if the chain is ordered) */
    ulong found_slot = rec->pair.xid->ul[0];
    if( found_slot==ULONG_MAX ) found_slot = root_slot;

    if( FD_UNLIKELY( found_slot<epoch_slot0 ) ) continue;

    /* Skip over records that are older than what we already have */
    if( FD_UNLIKELY( (long)found_slot<best_slot ) ) continue;

    /* Confirm that record is part of the current fork */
    if( FD_UNLIKELY( !fd_accdb_lineage_has_xid( lineage, rec->pair.xid ) ) ) continue;

    best      = rec;
    best_slot = (long)found_slot;
    if( FD_UNLIKELY( rec->map_next==ele_idx ) ) {
      FD_LOG_CRIT(( "fd_progcache_search_chain detected cycle" ));
    }
    if( rec->map_next > rec_max ) {
      if( FD_UNLIKELY( !fd_funk_rec_map_private_idx_is_null( rec->map_next ) ) ) {
        FD_LOG_CRIT(( "fd_progcache_search_chain detected memory corruption: rec->map_next %u is out of bounds (rec_max %lu)",
                      rec->map_next, rec_max ));
      }
    }
  }

  /* Retry if we were overrun */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( chain->ver_cnt )!=ver_cnt ) ) {
    return FD_MAP_ERR_AGAIN;
  }

  *out_rec = best;
  return FD_MAP_SUCCESS;
}

static fd_progcache_rec_t *
fd_progcache_query( fd_progcache_t *          cache,
                    fd_funk_txn_xid_t const * xid,
                    fd_funk_rec_key_t const * key,
                    ulong                     epoch_slot0 ) {
  /* Hash key to chain */
  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_copy( pair->xid, xid );
  fd_funk_rec_key_copy( pair->key, key );
  fd_prog_recm_t const * rec_map = cache->join->rec.map;
  ulong hash      = fd_funk_rec_map_key_hash( pair, rec_map->map->seed );
  ulong chain_idx = (hash & (rec_map->map->chain_cnt-1UL) );

  /* Traverse chain for candidate */
  fd_progcache_rec_t * rec = NULL;
  for(;;) {
    int err = fd_progcache_search_chain( cache, chain_idx, key, epoch_slot0, &rec );
    if( FD_LIKELY( err==FD_MAP_SUCCESS ) ) break;
    FD_SPIN_PAUSE();
    fd_racesan_hook( "fd_progcache_query_wait" );
    /* FIXME backoff */
  }

  return rec;
}

fd_progcache_rec_t const *
fd_progcache_peek( fd_progcache_t *          cache,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr,
                   ulong                     epoch_slot0 ) {
  fd_progcache_join_t * ljoin = cache->join;

  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_progcache_load_fork( cache, xid, epoch_slot0 );
  fd_funk_rec_key_t key[1]; memcpy( key->uc, prog_addr, 32UL );
  fd_progcache_rec_t const * rec = fd_progcache_query( cache, xid, key, epoch_slot0 );
  if( FD_UNLIKELY( !rec ) ) return NULL;

  fd_progcache_rec_t const * entry = fd_funk_val_const( rec, ljoin->wksp );
  if( entry->slot < epoch_slot0 ) entry = NULL;

  cache->metrics->hit_cnt += !!entry;

  return entry;
}

static void
fd_progcache_rec_push_tail( fd_progcache_rec_t * rec_pool,
                            fd_progcache_rec_t * rec,
                            uint *               rec_head_idx,
                            uint *               rec_tail_idx ) {
  uint rec_idx = (uint)( rec - rec_pool );
  for(;;) {

    /* Doubly linked list append.  Robust in the event of concurrent
       publishes.  Iteration during publish not supported.  Sequence:
       - Identify tail element
       - Set new element's prev and next pointers
       - Set tail element's next pointer
       - Set tail pointer */

    uint rec_prev_idx = FD_VOLATILE_CONST( *rec_tail_idx );
    rec->prev_idx = rec_prev_idx;
    rec->next_idx = FD_FUNK_REC_IDX_NULL;
    FD_COMPILER_MFENCE();

    uint * next_idx_p;
    if( fd_funk_rec_idx_is_null( rec_prev_idx ) ) {
      next_idx_p = rec_head_idx;
    } else {
      next_idx_p = &rec_pool[ rec_prev_idx ].next_idx;
    }

    fd_racesan_hook( "fd_progcache_rec_push_tail_start" );
    if( FD_UNLIKELY( !__sync_bool_compare_and_swap( next_idx_p, FD_FUNK_REC_IDX_NULL, rec_idx ) ) ) {
      /* Another thread beat us to the punch */
      FD_SPIN_PAUSE();
      continue;
    }

    if( FD_UNLIKELY( !__sync_bool_compare_and_swap( rec_tail_idx, rec_prev_idx, rec_idx ) ) ) {
      /* This CAS is guaranteed to succeed if the previous CAS passed. */
      FD_LOG_CRIT(( "Irrecoverable data race encountered while appending to txn rec list (invariant violation?): cas(%p,%u,%u)",
                    (void *)rec_tail_idx, rec_prev_idx, rec_idx ));
    }

    break;
  }
}

__attribute__((warn_unused_result))
static int
fd_progcache_push( fd_progcache_join_t * cache,
                   fd_progcache_txn_t *  txn,
                   fd_progcache_rec_t *  rec,
                   void const *          prog_addr ) {
  /* Phase 1: Determine record's xid-key pair */

  rec->prev_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;
  memcpy( rec->pair.key, prog_addr, 32UL );
  fd_rwlock_read( &rec->lock );
  rec->clock = 1;
  if( FD_UNLIKELY( txn ) ) {
    fd_funk_txn_xid_copy( rec->pair.xid, &txn->xid );
  } else {
    fd_funk_txn_xid_set_root( rec->pair.xid );
  }

  /* Phase 2: Lock rec_map chain, entering critical section */

  struct {
    fd_prog_recm_txn_t txn[1];
    fd_prog_recm_txn_private_info_t info[1];
  } _map_txn;
  fd_prog_recm_txn_t * map_txn = fd_prog_recm_txn_init( _map_txn.txn, cache->rec.map, 1UL );
  fd_prog_recm_txn_add( map_txn, &rec->pair, 1 );
  int txn_err = fd_prog_recm_txn_try( map_txn, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( txn_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to insert progcache record: cannot lock funk rec map chain: %i-%s", txn_err, fd_map_strerror( txn_err ) ));
  }

  /* Phase 3: Check if record exists */

  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_txn_query( cache->rec.map, &rec->pair, NULL, query, 0 );
  if( FD_UNLIKELY( query_err==FD_MAP_SUCCESS ) ) {
    fd_prog_recm_txn_test( map_txn );
    fd_prog_recm_txn_fini( map_txn );
    return 0;
  } else if( FD_UNLIKELY( query_err!=FD_MAP_ERR_KEY ) ) {
    FD_LOG_CRIT(( "fd_prog_recm_txn_query failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
  }

  /* Phase 4: Insert new record */

  int insert_err = fd_prog_recm_txn_insert( cache->rec.map, rec );
  if( FD_UNLIKELY( insert_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_prog_recm_txn_insert failed: %i-%s", insert_err, fd_map_strerror( insert_err ) ));
  }

  /* Phase 5: Insert rec into rec_map */

  if( txn ) {
    fd_progcache_rec_push_tail( cache->rec.pool->ele,
                                rec,
                                &txn->rec_head_idx,
                                &txn->rec_tail_idx );
  }

  /* Phase 6: Finish rec_map transaction */

  int test_err = fd_prog_recm_txn_test( map_txn );
  if( FD_UNLIKELY( test_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_txn_test failed: %i-%s", test_err, fd_map_strerror( test_err ) ));
  fd_prog_recm_txn_fini( map_txn );
  return 1;
}

/* fd_progcache_lock_best_txn picks a fork graph node close to
   target_slot and write locks it for program cache entry insertion.

   The cache entry should be placed as far up the fork graph as
   possible (so it can be shared across more downstream forks), but not
   too early (or it would cause non-determinism). */

static fd_progcache_txn_t *
fd_progcache_lock_best_txn( fd_progcache_t * cache,
                            ulong            target_slot ) {
  fd_progcache_join_t * ljoin   = cache->join;
  fd_accdb_lineage_t *  lineage = cache->lineage;

  fd_funk_txn_xid_t last_publish[1];
  fd_funk_txn_xid_ld_atomic( last_publish, ljoin->shmem->txn.last_publish );
  if( target_slot <= last_publish->ul[0] &&
      !fd_funk_txn_xid_eq_root( last_publish ) ) {
    return NULL; /* publishing record immediately */
  }

  /* Scan fork graph for oldest node >= the target slot. */
  ulong target_xid_idx = ULONG_MAX;
  ulong fork_depth     = lineage->fork_depth;
  for( ulong xid_idx=0UL; xid_idx<fork_depth && lineage->fork[ xid_idx ].ul[0]>=target_slot; xid_idx++ ) {
    target_xid_idx = xid_idx;
  }
  if( FD_UNLIKELY( target_xid_idx==ULONG_MAX ) ) FD_LOG_CRIT(( "no target xid idx found for slot %lu", target_slot ));

  /* Backtrack up to newer fork graph nodes (>= access slot)
     Very old slots could have been rooted at this point */
  fd_rwlock_read( ljoin->txn.lock );
  fd_funk_txn_xid_t const * xid = &lineage->fork[ target_xid_idx ];
  fd_progcache_txn_t * txn = fd_prog_txnm_ele_query( ljoin->txn.map, xid, NULL, ljoin->txn.pool );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "XID %lu:%lu is missing", xid->ul[0], xid->ul[1] ));
  }
  fd_rwlock_read( &txn->lock );
  fd_rwlock_unread( ljoin->txn.lock );
  return txn;
}

/* account_xid_lower_bound tries to find the oldest XID at which the
   given record is exactly present.  sample_xid is an arbitrary XID at
   which the given record is present.  May return a newer XID, if the
   oldest XID cannot be determined exactly. */

static fd_funk_txn_xid_t
account_xid_lower_bound( fd_accdb_user_t *         accdb,
                         fd_accdb_ro_t const *     record,
                         fd_funk_txn_xid_t const * sample_xid ) {
  switch( record->ref->accdb_type ) {
  case FD_ACCDB_TYPE_V1: { /* possibly rooted */
    fd_funk_rec_t * rec = (fd_funk_rec_t *)record->ref->user_data;
    fd_funk_txn_xid_t res;
    fd_funk_txn_xid_ld_atomic( &res, rec->pair.xid );
    if( FD_UNLIKELY( fd_funk_txn_xid_eq_root( &res ) ) ) {
      fd_funk_txn_xid_ld_atomic( &res, fd_funk_last_publish( fd_accdb_user_v1_funk( accdb ) ) );
    }
    return res;
  }
  case FD_ACCDB_TYPE_V2: { /* rooted */
    fd_funk_txn_xid_t res;
    fd_funk_txn_xid_ld_atomic( &res, fd_funk_last_publish( fd_accdb_user_v1_funk( accdb ) ) );
    return res;
  }
  default: /* unknown */
    return *sample_xid;
  }
}

static fd_progcache_rec_t const *
fd_progcache_insert( fd_progcache_t *           cache,
                     fd_accdb_user_t *          accdb,
                     fd_funk_txn_xid_t const *  load_xid,
                     void const *               prog_addr,
                     fd_prog_load_env_t const * env,
                     long                       slot_min ) {
  fd_progcache_join_t * ljoin = cache->join;

  /* XID overview:

     - load_xid:   tip of fork currently being executed
     - modify_xid: xid in which program was last modified / deployed
     - txn->xid:   xid in which program cache entry is inserted

     slot(load_xid) > slot(entry_xid) >= slot(txn->xid) */

  /* Acquire reference to ELF binary data */

  fd_accdb_ro_t progdata[1];
  ulong         elf_offset;
  if( FD_UNLIKELY( !fd_prog_load_elf( accdb, load_xid, progdata, prog_addr, &elf_offset ) ) ) {
    return NULL;
  }

  uchar const * bin    = (uchar const *)fd_accdb_ref_data_const( progdata ) + elf_offset;
  ulong         bin_sz = /*           */fd_accdb_ref_data_sz   ( progdata ) - elf_offset;

  /* Derive the slot in which the account was modified in */

  fd_funk_txn_xid_t modify_xid = account_xid_lower_bound( accdb, progdata, load_xid );
  ulong target_slot = modify_xid.ul[0];

  /* Prevent cache entry from crossing epoch boundary */

  target_slot = fd_ulong_max( target_slot, env->epoch_slot0 );

  /* Prevent cache entry from shadowing invalidation */

  target_slot = (ulong)fd_long_max( (long)target_slot, slot_min );

  fd_progcache_rec_t * rec = NULL;
  for(;;) {
    rec = fd_prog_recp_acquire( ljoin->rec.pool, NULL, 1, NULL );
    if( FD_UNLIKELY( !rec ) ) {
      fd_progcache_clock_evict( cache );
    }
  }
  /* FIXME initialize */
  fd_rwlock_write( &rec->lock );

  /* Pick and lock a txn in which cache entry is created at */

  fd_progcache_txn_t * txn = fd_progcache_lock_best_txn( cache, target_slot );

  /* Publish cache entry to index */

  int push_ok = fd_progcache_push( ljoin, txn, rec, prog_addr );
  fd_rwlock_unread( &txn->lock );
  if( FD_UNLIKELY( !fd_progcache_push( ljoin, txn, rec, prog_addr ) ) ) {
    fd_rwlock_unwrite( &rec->lock );
    /* Destroy record */
    return NULL;
  }

  /* Load program */

  fd_features_t const * features  = env->features;
  ulong         const   load_slot = env->slot;
  fd_prog_versions_t versions = fd_prog_versions( features, load_slot );
  fd_sbpf_loader_config_t config = {
    .sbpf_min_version = versions.min_sbpf_version,
    .sbpf_max_version = versions.max_sbpf_version,
  };
  fd_sbpf_elf_info_t elf_info[1];

  if( FD_LIKELY( fd_sbpf_elf_peek( elf_info, bin, bin_sz, &config )==FD_SBPF_ELF_SUCCESS ) ) {

    // ulong       rec_align     = fd_progcache_rec_align();
    // ulong       rec_footprint = fd_progcache_rec_footprint( elf_info );

    // for(;;) {
    //   void * rec_mem = fd_funk_val_truncate( rec, funk->alloc, funk->wksp, rec_align, rec_footprint, NULL );
    //   if( FD_UNLIKELY( !rec_mem ) ) {
    //     fd_progcache_clock_evict( cache );
    //     continue;
    //   }
    //   break;
    // }

    // rec = fd_progcache_rec_new( rec_mem, elf_info, &config, load_slot, features, bin, bin_sz, cache->scratch, cache->scratch_sz );
    // if( !rec ) {
    //   fd_funk_val_flush( funk_rec, funk->alloc, funk->wksp );
    // }

  }

  fd_accdb_close_ro( accdb, progdata );
  /* invalidates bin pointer */

  /* Convert to tombstone if load failed */

  if( !rec ) {  /* load fail */
    // void * rec_mem = fd_funk_val_truncate( funk_rec, funk->alloc, funk->wksp, fd_progcache_rec_align(), fd_progcache_rec_footprint( NULL ), NULL );
    // if( FD_UNLIKELY( !rec_mem ) ) {
    //   FD_LOG_ERR(( "Program cache is out of memory: fd_alloc_malloc failed (requested align=%lu sz=%lu)",
    //                fd_progcache_rec_align(), fd_progcache_rec_footprint( NULL ) ));
    // }
    // rec = fd_progcache_rec_new_nx( rec_mem, load_slot );
  }

  cache->metrics->fill_cnt++;
  cache->metrics->fill_tot_sz += rec->rodata_sz;

  return rec;
}

fd_progcache_rec_t const *
fd_progcache_pull( fd_progcache_t *           cache,
                   fd_accdb_user_t *          accdb,
                   fd_funk_txn_xid_t const *  xid,
                   void const *               prog_addr,
                   fd_prog_load_env_t const * env ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_progcache_load_fork( cache, xid, env->epoch_slot0 );

  fd_progcache_rec_t const * found_rec = fd_progcache_peek( cache, xid, prog_addr, env->epoch_slot0 );
  long slot_min = -1L;
  if( !found_rec ) goto miss;

  /* Cache invalidation, update next slot */
  if( found_rec->invalidate ) {
    slot_min = (long)found_rec->slot+1L;
    if( FD_UNLIKELY( xid->ul[0] < (ulong)slot_min ) ) {
      FD_LOG_CRIT(( "Program cache entry %016lx%016lx%016lx%016lx invalidated at slot %lu but loaded at slot %lu",
                    fd_ulong_bswap( FD_LOAD( ulong, (uchar const *)prog_addr    ) ),
                    fd_ulong_bswap( FD_LOAD( ulong, (uchar const *)prog_addr+ 8 ) ),
                    fd_ulong_bswap( FD_LOAD( ulong, (uchar const *)prog_addr+16 ) ),
                    fd_ulong_bswap( FD_LOAD( ulong, (uchar const *)prog_addr+24 ) ),
                    found_rec->slot,
                    xid->ul[0] ));
    }
    goto miss;
  }

  /* Passed all checks */
  cache->metrics->hit_cnt++;
  cache->metrics->hit_tot_sz += found_rec->rodata_sz;
  return found_rec;

miss:
  cache->metrics->miss_cnt++;
  return fd_progcache_insert( cache, accdb, xid, prog_addr, env, slot_min );
}

fd_progcache_rec_t const *
fd_progcache_invalidate( fd_progcache_t *          cache,
                         fd_funk_txn_xid_t const * xid,
                         void const *              prog_addr,
                         ulong                     slot ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_progcache_join_t * ljoin = cache->join;

  fd_progcache_rec_t * rec = NULL;
  for(;;) {
    rec = fd_prog_recp_acquire( ljoin->rec.pool, NULL, 1, NULL );
    if( FD_UNLIKELY( !rec ) ) {
      fd_progcache_clock_evict( cache );
    }
  }
  fd_progcache_rec_new_nx( rec, slot );

  fd_rwlock_read( &ljoin->shmem->txn.rwlock );
  fd_progcache_txn_t * txn = (fd_progcache_txn_t * )fd_prog_txnm_ele_query_const( ljoin->txn.map, xid, NULL, ljoin->txn.pool );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_invalidate(xid=%lu:%lu) failed: database transaction not found", xid->ul[0], xid->ul[1] ));
  }

  fd_rwlock_write( &txn->lock );
  fd_rwlock_unread( &ljoin->shmem->txn.rwlock );
  int push_ok = fd_progcache_push( cache->join, txn, rec, prog_addr );
  if( FD_UNLIKELY( !push_ok ) ) FD_LOG_CRIT(( "fd_progcache_push failed (invalidate while pull?)" ));
  fd_rwlock_unwrite( &txn->lock );

  cache->metrics->invalidate_cnt++;
  return rec;
}
