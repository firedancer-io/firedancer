#include "fd_prog_load.h"
#include "fd_progcache_user.h"
#include "fd_progcache.h"
#include "fd_progcache_rec.h"
#include "../accdb/fd_accdb_sync.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../../util/racesan/fd_racesan_target.h"

FD_TL fd_progcache_metrics_t fd_progcache_metrics_default;

fd_progcache_t *
fd_progcache_join( fd_progcache_t *       cache,
                   fd_progcache_shmem_t * shmem,
                   uchar *                scratch,
                   ulong                  scratch_sz ) {
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL cache" ));
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
  memset( cache, 0, sizeof(fd_progcache_t) );
  if( FD_UNLIKELY( !fd_progcache_shmem_join( cache->join, shmem ) ) ) return NULL;

  cache->metrics    = &fd_progcache_metrics_default;
  cache->scratch    = scratch;
  cache->scratch_sz = scratch_sz;

  return cache;
}

void *
fd_progcache_leave( fd_progcache_t *        cache,
                    fd_progcache_shmem_t ** opt_shmem ) {
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL cache" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_progcache_shmem_leave( cache->join, opt_shmem ) ) ) return NULL;
  cache->scratch    = NULL;
  cache->scratch_sz = 0UL;
  return cache;
}

/* fd_progcache_chain_evict evicts records from the index (hash map) and
   frees program cache memory.  Non-rooted progcache_rec objects are not
   freed immediately (kept as exists=0, deferred to publish/cancel for
   cleanup.) */

static void
fd_progcache_chain_evict( fd_progcache_t * cache,
                          uint             chain_idx ) {
  fd_progcache_join_t * ljoin = cache->join;
  fd_prog_recm_shmem_private_chain_t * chain = fd_prog_recm_shmem_private_chain( ljoin->rec.map->map, chain_idx );

  /* Lock chain */
  struct {
    fd_prog_recm_txn_t txn[1];
    fd_prog_recm_txn_private_info_t info[1];
  } _map_txn;
  fd_prog_recm_txn_t * map_txn = fd_prog_recm_txn_init( _map_txn.txn, ljoin->rec.map, 1UL );
  _map_txn.info->chain = chain;
  map_txn->lock_cnt = 1UL;
  int txn_err = fd_prog_recm_txn_try( map_txn, FD_MAP_FLAG_BLOCKING );
  FD_TEST( txn_err==FD_MAP_SUCCESS );
  ulong cnt = fd_prog_recm_private_vcnt_cnt( _map_txn.info->ver_cnt );
  if( FD_UNLIKELY( !cnt ) ) goto exit;
  if( FD_UNLIKELY( chain->head_cidx==UINT_MAX ) ) {
    FD_LOG_CRIT(( "corrupt progcache: chain[%u] cnt=%lu head_cidx=UINT_MAX", chain_idx, cnt ));
  }

  /* Peek key of first record */
  fd_progcache_rec_t * rec0 = ljoin->rec.pool->ele;
  fd_funk_rec_key_t    key  = *rec0[ chain->head_cidx ].pair.key;

  /* Iterate chain and lock all records matching key */
  ulong lock_cnt = 0UL;
  for( uint node = chain->head_cidx; node!=UINT_MAX; node = rec0[ node ].map_next ) {
    fd_progcache_rec_t * rec = &ljoin->rec.pool->ele[ node ];
    if( FD_UNLIKELY( !fd_funk_rec_key_eq( rec->pair.key, &key ) ) ) break;
    if( FD_UNLIKELY( !fd_rwlock_trywrite( &rec->lock ) ) ) {
      /* CAS failed, unlock records we just locked */
      for( uint node1 = chain->head_cidx; node1!=node; node1 = rec0[ node1 ].map_next ) {
        fd_rwlock_unwrite( &ljoin->rec.pool->ele[ node1 ].lock );
      }
      lock_cnt = 0UL;
      break; /* give up */
    }
    lock_cnt++;
  }

  /* All records locked, now free underlying memory */
  uint * next = &chain->head_cidx;
  for( uint node = chain->head_cidx; node!=UINT_MAX && lock_cnt; ) {
    fd_progcache_rec_t * rec = &ljoin->rec.pool->ele[ node ];
    *next = rec->map_next;
    node  = rec->map_next;
    rec->map_next = UINT_MAX;
    int is_root = fd_funk_txn_xid_eq_root( rec->pair.xid );
    ulong rodata_sz = rec->rodata_sz;
    ulong data_max  = rec->data_max;

    fd_progcache_val_free( rec, ljoin );
    rec->exists     = 0;
    rec->executable = 0;
    rec->invalidate = 0;
    fd_rwlock_unwrite( &rec->lock );

    if( is_root ) fd_prog_recp_release( ljoin->rec.pool, rec, 1 );
    else          {} /* record free deferred to txn cleanup */

    lock_cnt--;
    FD_CRIT( cnt>0, "invariant violation" );
    cnt--;
    cache->metrics->evict_cnt++;
    cache->metrics->evict_tot_sz   += rodata_sz;
    cache->metrics->evict_freed_sz += data_max;
  }

  chain->ver_cnt = fd_prog_recm_private_vcnt( fd_prog_recm_private_vcnt_ver( chain->ver_cnt ), cnt );

  /* Unlock chain */
exit:
  fd_prog_recm_txn_test( map_txn ); /* increments ver, keeps above cnt */
  fd_prog_recm_txn_fini( map_txn );
}

static void
fd_progcache_clock_evict( fd_progcache_t * cache ) {
  fd_progcache_join_t * ljoin = cache->join;
  fd_rwlock_write( &ljoin->shmem->clock.lock );

  /* Evict until a hardcoded threshold worth of data is freed */

  uint  head        = ljoin->shmem->clock.head;
  uint  chain_max   = (uint)fd_prog_recm_chain_cnt( ljoin->rec.map );
  ulong free_target = cache->metrics->evict_freed_sz + (16UL<<20);  /* 16 MiB */
  for(;;) {
    fd_prog_recm_shmem_private_chain_t * chain = fd_prog_recm_shmem_private_chain( ljoin->rec.map->map, head );
    uint  clock_pre = atomic_load_explicit( &chain->clock,                   memory_order_relaxed );
    ulong ver_cnt   = atomic_load_explicit( (atomic_ulong *)&chain->ver_cnt, memory_order_relaxed );
    ulong cnt       = fd_prog_recm_private_vcnt_cnt( ver_cnt );
    if( FD_LIKELY( clock_pre ) ) {
      atomic_store_explicit( &chain->clock, 0, memory_order_relaxed );
    } else if( cnt ) {
      fd_progcache_chain_evict( cache, head );
      if( cache->metrics->evict_freed_sz >= free_target ) break;
    }
    head++;
    if( head==chain_max ) head = 0;
  }
  ljoin->shmem->clock.head = head;

  fd_rwlock_unwrite( &ljoin->shmem->clock.lock );
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
  fd_accdb_lineage_t *        lineage = cache->lineage;
  fd_progcache_join_t const * ljoin   = cache->join;
  fd_rwlock_read( &ljoin->shmem->txn.rwlock );

  fd_funk_txn_xid_t next_xid = *xid;
  if( FD_UNLIKELY( next_xid.ul[0]<epoch_slot0 ) ) {
    FD_LOG_CRIT(( "fd_progcache_load_fork: attempted to load xid=%lu:%lu, which predates first slot of bank's epoch (epoch_slot0=%lu)",
                  next_xid.ul[0], next_xid.ul[1], epoch_slot0 ));
  }

  lineage->fork_depth = 0UL;

  ulong i;
  for( i=0UL;; i++ ) {
    if( FD_UNLIKELY( i>=FD_PROGCACHE_DEPTH_MAX ) ) {
      FD_LOG_CRIT(( "fd_progcache_load_fork: fork depth exceeded max of %lu", (ulong)FD_PROGCACHE_DEPTH_MAX ));
    }
    uint next_idx = (uint)fd_prog_txnm_idx_query_const( ljoin->txn.map, &next_xid, UINT_MAX, ljoin->txn.pool );
    if( FD_UNLIKELY( next_idx==UINT_MAX ) ) break;
    fd_progcache_txn_t * candidate = &ljoin->txn.pool[ next_idx ];

    uint parent_idx = candidate->parent_idx;
    FD_TEST( parent_idx!=next_idx );
    lineage->fork[ i ] = next_xid;
    if( parent_idx==UINT_MAX || next_xid.ul[0]<epoch_slot0 ) {
      /* Reached root or fork graph node is from previous epoch */
      i++;
      break;
    }
    next_xid = ljoin->txn.pool[ parent_idx ].xid;
  }

  lineage->fork_depth = i;

  fd_rwlock_unread( &ljoin->shmem->txn.rwlock );
}

static inline void
fd_progcache_load_fork( fd_progcache_t *          cache,
                        fd_funk_txn_xid_t const * xid,
                        ulong                     epoch_slot0 ) {
  /* Skip if already on the correct fork */
  fd_accdb_lineage_t * lineage = cache->lineage;
  if( FD_LIKELY( (!!lineage->fork_depth) & (!!fd_funk_txn_xid_eq( &lineage->fork[ 0 ], xid ) ) ) ) return;
  fd_progcache_load_fork_slow( cache, xid, epoch_slot0 ); /* switch fork */
}

/* fd_progcache_query searches for a program cache entry on the current
   fork.  Stops short of an epoch boundary. */

static int
fd_progcache_search_chain( fd_progcache_t const *    cache,
                           ulong                     chain_idx,
                           fd_funk_rec_key_t const * key,
                           ulong                     epoch_slot0,
                           fd_progcache_rec_t **     out_rec ) { /* read locked */
  *out_rec = NULL;

  fd_progcache_join_t const *                ljoin     = cache->join;
  fd_accdb_lineage_t const *                 lineage   = cache->lineage;
  fd_prog_recm_shmem_t *                     shmap     = ljoin->rec.map->map;
  fd_prog_recm_shmem_private_chain_t const * chain_tbl = fd_prog_recm_shmem_private_chain_const( shmap, 0UL );
  fd_prog_recm_shmem_private_chain_t const * chain     = chain_tbl + chain_idx;
  fd_progcache_rec_t *                       rec_tbl   = ljoin->rec.pool->ele;
  ulong                                      rec_max   = fd_prog_recp_ele_max( ljoin->rec.pool );
  ulong                                      ver_cnt   = FD_VOLATILE_CONST( chain->ver_cnt );

  /* Start a speculative transaction for the chain containing revisions
     of the program cache key we are looking for. */
  ulong cnt = fd_prog_recm_private_vcnt_cnt( ver_cnt );
  if( FD_UNLIKELY( fd_prog_recm_private_vcnt_ver( ver_cnt )&1 ) ) {
    return FD_MAP_ERR_AGAIN; /* chain is locked */
  }
  FD_COMPILER_MFENCE();
  uint ele_idx = chain->head_cidx;

  /* Walk the map chain, remember the best entry */
  fd_progcache_rec_t * best      = NULL;
  long                 best_slot = -1L;
  for( ulong i=0UL; i<cnt; i++, ele_idx=FD_VOLATILE_CONST( rec_tbl[ ele_idx ].map_next ) ) {
    if( FD_UNLIKELY( (ulong)ele_idx >= rec_max ) ) return FD_MAP_ERR_AGAIN;
    fd_progcache_rec_t * rec = &rec_tbl[ ele_idx ];

    /* Skip over unrelated records (hash collision) */
    if( FD_UNLIKELY( !fd_funk_rec_key_eq( rec->pair.key, key ) ) ) continue;

    /* Skip over records from an older epoch (FIXME could bail early
       here if the chain is ordered) */
    ulong found_slot = rec->pair.xid->ul[0];
    if( found_slot==ULONG_MAX ) found_slot = FD_VOLATILE_CONST( ljoin->shmem->txn.last_publish->ul[0] );

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
  if( best && FD_UNLIKELY( !fd_rwlock_tryread( &best->lock ) ) ) {
    return FD_MAP_ERR_AGAIN;
  }

  /* Retry if we were overrun */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( chain->ver_cnt )!=ver_cnt ) ) {
    if( best ) fd_rwlock_unread( &best->lock );
    return FD_MAP_ERR_AGAIN;
  }

  *out_rec = best;
  return FD_MAP_SUCCESS;
}

static fd_progcache_rec_t * /* read locked */
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

fd_progcache_rec_t * /* read locked */
fd_progcache_peek( fd_progcache_t *          cache,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr,
                   ulong                     epoch_slot0 ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_progcache_load_fork( cache, xid, epoch_slot0 );
  fd_funk_rec_key_t key[1]; memcpy( key->uc, prog_addr, 32UL );
  fd_progcache_rec_t * rec = fd_progcache_query( cache, xid, key, epoch_slot0 );
  if( FD_UNLIKELY( !rec ) ) return NULL;
  if( rec->slot < epoch_slot0 ) {
    fd_rwlock_unread( &rec->lock );
    rec = NULL;
  }
  cache->metrics->hit_cnt += !!rec;
  return rec;
}

static void
fd_progcache_rec_push_tail( fd_progcache_rec_t * rec_pool,
                            fd_progcache_rec_t * rec,
                            uint *               rec_head_idx, /* write locked (txn) */
                            uint *               rec_tail_idx ) {
  uint rec_idx     = (uint)( rec - rec_pool );
  uint rec_prev_idx = *rec_tail_idx;

  rec->prev_idx = rec_prev_idx;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;

  if( fd_funk_rec_idx_is_null( rec_prev_idx ) ) {
    *rec_head_idx = rec_idx;
  } else {
    rec_pool[ rec_prev_idx ].next_idx = rec_idx;
  }
  *rec_tail_idx = rec_idx;
}

__attribute__((warn_unused_result))
static int
fd_progcache_push( fd_progcache_join_t * cache,
                   fd_progcache_txn_t *  txn, /* read locked */
                   fd_progcache_rec_t *  rec,
                   void const *          prog_addr,
                   ulong                 target_slot ) {

  /* Determine record's xid-key pair */

  rec->prev_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;
  memcpy( rec->pair.key, prog_addr, 32UL );
  if( FD_UNLIKELY( txn ) ) {
    fd_funk_txn_xid_copy( rec->pair.xid, &txn->xid );
  } else {
    fd_funk_txn_xid_set_root( rec->pair.xid );
  }

  /* Lock rec_map chain, entering critical section */

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

  /* Mark chain as recently accessed */

  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_txn_query( cache->rec.map, &rec->pair, NULL, query, 0 );
  fd_prog_recm_clock_touch( cache, query->memo );

  /* Check if record exists */

  if( FD_UNLIKELY( query_err==FD_MAP_SUCCESS ) ) {
    /* Always replace existing rooted records */
    fd_progcache_rec_t * prev_rec = query->ele;
    if( fd_funk_txn_xid_eq_root( rec->pair.xid ) && prev_rec->slot < target_slot ) {
      fd_rwlock_write( &prev_rec->lock );
      fd_prog_recm_txn_remove( cache->rec.map, &rec->pair, NULL, query, FD_MAP_FLAG_USE_HINT );
      fd_progcache_val_free( prev_rec, cache );
      fd_rwlock_unwrite( &prev_rec->lock );
      fd_prog_recp_release( cache->rec.pool, prev_rec, 1 );
    } else {
      fd_prog_recm_txn_test( map_txn );
      fd_prog_recm_txn_fini( map_txn );
      return 0;
    }
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
  fd_funk_txn_xid_t const * xid = &lineage->fork[ target_xid_idx ];
  if( FD_UNLIKELY( fd_funk_txn_xid_eq_root( xid ) ) ) target_xid_idx--;
  if( FD_UNLIKELY( target_xid_idx==ULONG_MAX ) ) FD_LOG_CRIT(( "no target xid idx found for slot %lu", target_slot ));
  xid = &lineage->fork[ target_xid_idx ];

  fd_rwlock_read( &ljoin->shmem->txn.rwlock );
  fd_progcache_txn_t * txn = fd_prog_txnm_ele_query( ljoin->txn.map, xid, NULL, ljoin->txn.pool );
  if( FD_UNLIKELY( !txn ) ) {
    /* Did replay tile root this slot in the mean time? */
    fd_funk_txn_xid_ld_atomic( last_publish, ljoin->shmem->txn.last_publish );
    if( FD_LIKELY( target_slot <= last_publish->ul[0] &&
                   !fd_funk_txn_xid_eq_root( last_publish ) ) ) {
      fd_rwlock_unread( &ljoin->shmem->txn.rwlock );
      return NULL; /* published in the meantime */
    }
    FD_LOG_CRIT(( "XID %lu:%lu is missing", xid->ul[0], xid->ul[1] ));
  }
  fd_rwlock_write( &txn->lock );
  fd_rwlock_unread( &ljoin->shmem->txn.rwlock );
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

/* fd_progcache_spill_open loads a program into the cache spill buffer.
   The spill area is an "emergency" area for temporary program loads in
   case the record pool/heap are too contended. */

static fd_progcache_rec_t * /* read locked */
fd_progcache_spill_open( fd_progcache_t *                cache,
                         fd_sbpf_elf_info_t const *      elf_info,
                         fd_sbpf_loader_config_t const * config,
                         ulong const                     load_slot,
                         fd_features_t const *           features,
                         uchar const *                   bin,
                         ulong                           bin_sz ) {
  fd_progcache_join_t *  join  = cache->join;
  fd_progcache_shmem_t * shmem = join->shmem;
  if( !cache->spill_active ) fd_rwlock_write( &shmem->spill.lock );
  else                       FD_TEST( FD_VOLATILE_CONST( shmem->spill.lock.value )==FD_RWLOCK_WRITE_LOCK );

  /* Allocate record */

  if( FD_UNLIKELY( shmem->spill.rec_used >= FD_MAX_INSTRUCTION_STACK_DEPTH ) ) {
    FD_LOG_CRIT(( "spill buffer overflow: rec_used=%u rec_max=%lu", shmem->spill.rec_used, FD_MAX_INSTRUCTION_STACK_DEPTH ));
  }
  cache->spill_active++;
  uint rec_idx = shmem->spill.rec_used++;
  shmem->spill.spad_off[ rec_idx ] = shmem->spill.spad_used;
  fd_progcache_rec_t * rec = &shmem->spill.rec[ rec_idx ];
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->lock.value = 1; /* read lock; no concurrency, don't need CAS */
  rec->exists     = 1;
  rec->slot       = load_slot;

  /* Load program */

  if( elf_info ) {
    ulong off0 = fd_ulong_align_up( shmem->spill.spad_used, fd_progcache_val_align() );
    ulong off1 = off0 + fd_progcache_val_footprint( elf_info );
    if( FD_UNLIKELY( off1 > FD_PROGCACHE_SPAD_MAX ) ) {
      FD_LOG_CRIT(( "spill buffer overflow: spad_used=%u val_sz=%lu spad_max=%lu", shmem->spill.spad_used, off1-off0, FD_PROGCACHE_SPAD_MAX ));
    }
    rec->data_gaddr = fd_wksp_gaddr_fast( join->wksp, shmem->spill.spad + off0 );
    rec->data_max   = (uint)( off1 - off0 );

    long dt = -fd_tickcount();
    if( FD_LIKELY( fd_progcache_rec_load( rec, cache->join->wksp, elf_info, config, load_slot, features, bin, bin_sz, cache->scratch, cache->scratch_sz ) ) ) {
      /* Valid program, allocate data */
      shmem->spill.spad_used = (uint)off1;
    } else {
      fd_progcache_rec_nx( rec );
    }
    dt += fd_tickcount();
    cache->metrics->cum_load_ticks += (ulong)dt;

  } else {
    rec->data_gaddr = 0UL;
    rec->data_max   = 0U;
  }

  cache->metrics->spill_cnt++;
  cache->metrics->spill_tot_sz += rec->rodata_sz;

  FD_TEST( rec->exists );
  return rec;
}

/* fd_progcache_insert allocates a cache entry, loads a program into it,
   and publishes the cache entry to the global index (recm).  If an OOM
   condition is detected, attempts to run the cache eviction algo, and
   finally falls back to using the spill buffer.  Returns NULL if the
   insertion raced with another thread (frees any previously allocated
   resource in that case). */

#define INVALID_PROGRAM ((fd_progcache_rec_t *)0x1)

static fd_progcache_rec_t * /* read locked */
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
    return INVALID_PROGRAM;
  }

  uchar const * bin    = (uchar const *)fd_accdb_ref_data_const( progdata ) + elf_offset;
  ulong         bin_sz = /*           */fd_accdb_ref_data_sz   ( progdata ) - elf_offset;

  /* Pre-flight checks, determine required buffer size */

  fd_features_t const * features  = env->features;
  ulong         const   load_slot = env->slot;
  fd_prog_versions_t versions = fd_prog_versions( features, load_slot );
  fd_sbpf_loader_config_t config = {
    .sbpf_min_version = versions.min_sbpf_version,
    .sbpf_max_version = versions.max_sbpf_version,
  };
  fd_sbpf_elf_info_t elf_info[1];
  int peek_err = fd_sbpf_elf_peek( elf_info, bin, bin_sz, &config );

  /* Derive the slot in which the account was modified in */

  fd_funk_txn_xid_t modify_xid = account_xid_lower_bound( accdb, progdata, load_xid );
  ulong target_slot = modify_xid.ul[0];
  /* Prevent cache entry from crossing epoch boundary */
  target_slot = fd_ulong_max( target_slot, env->epoch_slot0 );
  /* Prevent cache entry from shadowing invalidation */
  target_slot = (ulong)fd_long_max( (long)target_slot, slot_min );

  /* Allocate record and heap space */

  fd_progcache_rec_t * rec = fd_prog_recp_acquire( ljoin->rec.pool, NULL, 1, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    cache->metrics->oom_desc_cnt++;
    fd_progcache_clock_evict( cache );
    rec = fd_prog_recp_acquire( ljoin->rec.pool, NULL, 1, NULL );
    if( FD_UNLIKELY( !rec ) ) {
      /* Out of memory (record table) */
      if( peek_err==FD_SBPF_ELF_SUCCESS ) {
        rec = fd_progcache_spill_open( cache, elf_info, &config, load_slot, features, bin, bin_sz );
      } else {
        rec = fd_progcache_spill_open( cache, NULL,     NULL,    load_slot, features, NULL, 0UL   );
      }
      fd_accdb_close_ro( accdb, progdata );
      return rec;
    }
  }
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->exists = 1;
  rec->slot   = target_slot;

  if( FD_LIKELY( peek_err==FD_SBPF_ELF_SUCCESS ) ) {
    ulong val_align     = fd_progcache_val_align();
    ulong val_footprint = fd_progcache_val_footprint( elf_info );
    if( FD_UNLIKELY( !fd_progcache_val_alloc( rec, ljoin, val_align, val_footprint ) ) ) {
      cache->metrics->oom_heap_cnt++;
      fd_progcache_clock_evict( cache );
      if( FD_UNLIKELY( !fd_progcache_val_alloc( rec, ljoin, val_align, val_footprint ) ) ) {
        /* Out of memory (heap) */
        rec->exists = 0;
        fd_prog_recp_release( ljoin->rec.pool, rec, 1 );
        rec = fd_progcache_spill_open( cache, elf_info, &config, load_slot, features, bin, bin_sz );
        fd_accdb_close_ro( accdb, progdata );
        return rec;
      }
    }
  } else {
    fd_progcache_rec_nx( rec );
  }

  /* Publish cache entry to index */

  fd_progcache_txn_t * txn = fd_progcache_lock_best_txn( cache, target_slot );
  fd_rwlock_write( &rec->lock );
  int push_ok = fd_progcache_push( ljoin, txn, rec, prog_addr, target_slot );
  if( txn ) fd_rwlock_unwrite( &txn->lock );
  if( FD_UNLIKELY( !push_ok ) ) {
    fd_rwlock_unwrite( &rec->lock );
    fd_progcache_val_free( rec, ljoin );
    fd_prog_recp_release( ljoin->rec.pool, rec, 1 );
    fd_accdb_close_ro( accdb, progdata );
    return NULL;
  }

  /* Load program
     (The write lock was acquired before loading such that another
     thread trying to load the same record instead waits for us to
     complete) */

  if( FD_LIKELY( peek_err==FD_SBPF_ELF_SUCCESS ) ) {
    long dt = -fd_tickcount();
    if( FD_UNLIKELY( !fd_progcache_rec_load( rec, cache->join->wksp, elf_info, &config, load_slot, features, bin, bin_sz, cache->scratch, cache->scratch_sz ) ) ) {
      /* Not a valid program (mark cache entry as non-executable) */
      fd_progcache_val_free( rec, ljoin );
      fd_progcache_rec_nx( rec );
    }
    dt += fd_tickcount();
    cache->metrics->cum_load_ticks += (ulong)dt;
  }

  fd_rwlock_demote( &rec->lock );
  fd_accdb_close_ro( accdb, progdata );

  cache->metrics->fill_cnt++;
  cache->metrics->fill_tot_sz += rec->rodata_sz;
  FD_TEST( rec->exists );
  return rec;
}

fd_progcache_rec_t * /* read locked */
fd_progcache_pull( fd_progcache_t *           cache,
                   fd_accdb_user_t *          accdb,
                   fd_funk_txn_xid_t const *  xid,
                   void const *               prog_addr,
                   fd_prog_load_env_t const * env ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  long dt = -fd_tickcount();
  fd_progcache_load_fork( cache, xid, env->epoch_slot0 );
  cache->metrics->lookup_cnt++;

retry:;
  fd_progcache_rec_t * found_rec = fd_progcache_peek( cache, xid, prog_addr, env->epoch_slot0 );
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
    fd_rwlock_unread( &found_rec->lock );
    goto miss;
  }

  goto done;

miss:
  cache->metrics->miss_cnt++;
  found_rec = fd_progcache_insert( cache, accdb, xid, prog_addr, env, slot_min );
  if( !found_rec ) goto retry;
  if( found_rec==INVALID_PROGRAM ) return NULL;
done:
  dt += fd_tickcount();
  cache->metrics->cum_pull_ticks += (ulong)dt;
  return found_rec;
}

void
fd_progcache_invalidate( fd_progcache_t *          cache,
                         fd_funk_txn_xid_t const * xid,
                         void const *              prog_addr,
                         ulong                     slot ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_progcache_join_t * ljoin = cache->join;

  fd_progcache_rec_t * rec = NULL;
  for(;;) {
    rec = fd_prog_recp_acquire( ljoin->rec.pool, NULL, 1, NULL );
    if( FD_LIKELY( rec ) ) break;
    fd_progcache_clock_evict( cache );
  }
  rec->exists = 1;
  rec->slot   = slot;
  fd_progcache_rec_nx( rec );
  rec->invalidate = 1;

  fd_rwlock_read( &ljoin->shmem->txn.rwlock );
  fd_progcache_txn_t * txn = (fd_progcache_txn_t * )fd_prog_txnm_ele_query_const( ljoin->txn.map, xid, NULL, ljoin->txn.pool );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_invalidate(xid=%lu:%lu) failed: database transaction not found", xid->ul[0], xid->ul[1] ));
  }

  fd_rwlock_write( &txn->lock );
  fd_rwlock_unread( &ljoin->shmem->txn.rwlock );
  int push_ok = fd_progcache_push( cache->join, txn, rec, prog_addr, slot );
  fd_rwlock_unwrite( &txn->lock );
  if( FD_UNLIKELY( !push_ok ) ) {
    rec->exists = 0;
    fd_prog_recp_release( ljoin->rec.pool, rec, 1 );
  }

  cache->metrics->invalidate_cnt++;
  return;
}

static void
fd_progcache_spill_close( fd_progcache_t * cache ) {
  FD_TEST( cache->spill_active );
  cache->spill_active--;

  fd_progcache_shmem_t * shmem = cache->join->shmem;

  /* Cascade: rewind rec_used and spad_used while the top record is
     closed.  This reclaims spill spad memory in LIFO order. */
  while( shmem->spill.rec_used > 0 &&
         !shmem->spill.rec[ shmem->spill.rec_used-1 ].exists ) {
    shmem->spill.rec_used--;
    shmem->spill.spad_used = shmem->spill.spad_off[ shmem->spill.rec_used ];
  }

  if( cache->spill_active==0 ) {
    fd_rwlock_t * spill_lock = &shmem->spill.lock;
    FD_TEST( spill_lock->value==0xFFFF );
    FD_TEST( shmem->spill.rec_used==0 );
    FD_TEST( shmem->spill.spad_used==0 );
    fd_rwlock_unwrite( spill_lock );
  }
}

void
fd_progcache_rec_close( fd_progcache_t *     cache,
                        fd_progcache_rec_t * rec ) {
  if( FD_UNLIKELY( !rec ) ) return;
  if( FD_UNLIKELY( !rec->exists ) ) FD_LOG_CRIT(( "use-after-free: progcache record %p is dead", (void *)rec ));
  FD_TEST( FD_VOLATILE_CONST( rec->lock.value )!=0 );
  fd_rwlock_unread( &rec->lock );
  fd_progcache_shmem_t * shmem = cache->join->shmem;
  if( rec >= shmem->spill.rec &&
      rec <  shmem->spill.rec + FD_MAX_INSTRUCTION_STACK_DEPTH ) {
    rec->exists = 0;
    fd_progcache_spill_close( cache );
  }
}
