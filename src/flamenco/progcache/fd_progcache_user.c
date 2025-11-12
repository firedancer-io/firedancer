#include "fd_prog_load.h"
#include "fd_progcache_user.h"
#include "fd_progcache_rec.h"

FD_TL fd_progcache_metrics_t fd_progcache_metrics_default;

fd_progcache_t *
fd_progcache_join( fd_progcache_t * ljoin,
                   void *           shfunk,
                   uchar *          scratch,
                   ulong            scratch_sz ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
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
  if( FD_UNLIKELY( !fd_funk_join( ljoin->funk, shfunk ) ) ) return NULL;

  ljoin->metrics    = &fd_progcache_metrics_default;
  ljoin->scratch    = scratch;
  ljoin->scratch_sz = scratch_sz;

  return ljoin;
}

void *
fd_progcache_leave( fd_progcache_t * cache,
                    void **          opt_shfunk ) {
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL cache" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_funk_leave( cache->funk, opt_shfunk ) ) ) return NULL;
  cache->scratch    = NULL;
  cache->scratch_sz = 0UL;
  return cache;
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
  fd_funk_txn_xid_t next_xid = *xid;
  if( FD_UNLIKELY( next_xid.ul[0]<epoch_slot0 ) ) {
    FD_LOG_CRIT(( "fd_progcache_load_fork: attempted to load xid=%lu:%lu, which predates first slot of bank's epoch (epoch_slot0=%lu)",
                  next_xid.ul[0], next_xid.ul[1], epoch_slot0 ));
  }

  /* Walk transaction graph, recovering from overruns on-the-fly */
  cache->fork_depth = 0UL;

  ulong txn_max = fd_funk_txn_pool_ele_max( cache->funk->txn_pool );
  ulong i;
  for( i=0UL; i<FD_PROGCACHE_DEPTH_MAX; i++ ) {
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_t const *   candidate;
    fd_funk_txn_xid_t       found_xid;
    ulong                   parent_idx;
    fd_funk_txn_xid_t       parent_xid;
retry:
    /* Speculatively look up transaction from map */
    for(;;) {
      int query_err = fd_funk_txn_map_query_try( cache->funk->txn_map, &next_xid, NULL, query, 0 );
      if( FD_UNLIKELY( query_err==FD_MAP_ERR_AGAIN ) ) {
        /* FIXME random backoff */
        FD_SPIN_PAUSE();
        continue;
      }
      if( query_err==FD_MAP_ERR_KEY ) goto done;
      if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) {
        FD_LOG_CRIT(( "fd_funk_txn_map_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
      }
      break;
    }

    /* Lookup parent transaction while recovering from overruns
       FIXME This would be a lot easier if transactions specified
             parent by XID instead of by pointer ... */
    candidate = fd_funk_txn_map_query_ele_const( query );
    FD_COMPILER_MFENCE();
    do {
      found_xid  = FD_VOLATILE_CONST( candidate->xid );
      parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
      if( parent_idx<txn_max ) {
        FD_COMPILER_MFENCE();
        fd_funk_txn_t const * parent = &cache->funk->txn_pool->ele[ parent_idx ];
        parent_xid = FD_VOLATILE_CONST( parent->xid );
        FD_COMPILER_MFENCE();
      }
      parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
    } while(0);
    FD_COMPILER_MFENCE();

    /* Verify speculative loads by ensuring txn still exists in map */
    if( FD_UNLIKELY( fd_funk_txn_map_query_test( query )!=FD_MAP_SUCCESS ) ) {
      FD_SPIN_PAUSE();
      goto retry;
    }

    if( FD_UNLIKELY( !fd_funk_txn_xid_eq( &found_xid, &next_xid ) ) ) {
      FD_LOG_CRIT(( "fd_progcache_load_fork_slow detected memory corruption: expected xid %lu:%lu at %p, found %lu:%lu",
                    next_xid.ul[0], next_xid.ul[1],
                    (void *)candidate,
                    found_xid.ul[0], found_xid.ul[1] ));
    }

    cache->fork[ i ] = next_xid;
    if( fd_funk_txn_idx_is_null( parent_idx ) ||
        next_xid.ul[0]<epoch_slot0 ) {
      /* Reached root or fork graph node is from previous epoch */
      i++;
      break;
    }
    next_xid = parent_xid;
  }

done:
  cache->fork_depth = i;

  /* Only include published/rooted records if they include at least one
     cache entry from the current epoch. */
  if( fd_funk_last_publish( cache->funk )->ul[0] >= epoch_slot0 &&
      cache->fork_depth < FD_PROGCACHE_DEPTH_MAX ) {
    fd_funk_txn_xid_set_root( &cache->fork[ cache->fork_depth++ ] );
  }
}

static inline void
fd_progcache_load_fork( fd_progcache_t *          cache,
                        fd_funk_txn_xid_t const * xid,
                        ulong                     epoch_slot0 ) {
  /* Skip if already on the correct fork */
  if( FD_LIKELY( (!!cache->fork_depth) & (!!fd_funk_txn_xid_eq( &cache->fork[ 0 ], xid ) ) ) ) return;
  cache->metrics->fork_switch_cnt++;
  fd_progcache_load_fork_slow( cache, xid, epoch_slot0 ); /* switch fork */
}

/* fd_progcache_query searches for a program cache entry on the current
   fork.  Stops short of an epoch boundary. */

static int
fd_progcache_fork_has_xid( fd_progcache_t const *    cache,
                           fd_funk_txn_xid_t const * rec_xid ) {
  /* FIXME unroll this a little */
  ulong const fork_depth = cache->fork_depth;
  for( ulong i=0UL; i<fork_depth; i++ ) {
    if( fd_funk_txn_xid_eq( &cache->fork[i], rec_xid ) ) return 1;
  }
  return 0;
}

static int
fd_progcache_search_chain( fd_progcache_t const *    cache,
                           ulong                     chain_idx,
                           fd_funk_rec_key_t const * key,
                           ulong                     epoch_slot0,
                           fd_funk_rec_t **          out_rec ) {
  *out_rec = NULL;

  fd_funk_rec_map_shmem_t *                     shmap     = cache->funk->rec_map->map;
  fd_funk_rec_map_shmem_private_chain_t const * chain_tbl = fd_funk_rec_map_shmem_private_chain_const( shmap, 0UL );
  fd_funk_rec_map_shmem_private_chain_t const * chain     = chain_tbl + chain_idx;
  fd_funk_rec_t *                               rec_tbl   = cache->funk->rec_pool->ele;
  ulong                                         rec_max   = fd_funk_rec_pool_ele_max( cache->funk->rec_pool );
  ulong                                         ver_cnt   = FD_VOLATILE_CONST( chain->ver_cnt );
  ulong                                         root_slot = fd_funk_last_publish( cache->funk )->ul[0];

  /* Start a speculative transaction for the chain containing revisions
     of the program cache key we are looking for. */
  ulong cnt = fd_funk_rec_map_private_vcnt_cnt( ver_cnt );
  if( FD_UNLIKELY( fd_funk_rec_map_private_vcnt_ver( ver_cnt )&1 ) ) {
    return FD_MAP_ERR_AGAIN; /* chain is locked */
  }
  FD_COMPILER_MFENCE();
  uint ele_idx = chain->head_cidx;

  /* Walk the map chain, remember the best entry */
  fd_funk_rec_t * best      = NULL;
  long            best_slot = -1L;
  for( ulong i=0UL; i<cnt; i++, ele_idx=rec_tbl[ ele_idx ].map_next ) {
    fd_funk_rec_t * rec = &rec_tbl[ ele_idx ];

    /* Skip over unrelated records (hash collision) */
    if( FD_UNLIKELY( !fd_funk_rec_key_eq( rec->pair.key, key ) ) ) continue;

    /* Skip over records from an older epoch (FIXME could bail early
       here if the chain is ordered) */
    ulong found_slot = rec->pair.xid->ul[0];
    if( found_slot==ULONG_MAX ) found_slot = root_slot;

    if( FD_UNLIKELY( found_slot<epoch_slot0 ) ) continue;

    /* Skip over records that are older than what we already have */
    if( FD_UNLIKELY( (long)found_slot<best_slot ) ) continue;

    /* Confirm that record is part of the current fork
       FIXME this has bad performance / pointer-chasing */
    if( FD_UNLIKELY( !fd_progcache_fork_has_xid( cache, rec->pair.xid ) ) ) continue;

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

static fd_funk_rec_t *
fd_progcache_query( fd_progcache_t *          cache,
                    fd_funk_txn_xid_t const * xid,
                    fd_funk_rec_key_t const * key,
                    ulong                     epoch_slot0 ) {
  /* Hash key to chain */
  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_copy( pair->xid, xid );
  fd_funk_rec_key_copy( pair->key, key );
  fd_funk_rec_map_t const * rec_map = cache->funk->rec_map;
  ulong hash      = fd_funk_rec_map_key_hash( pair, rec_map->map->seed );
  ulong chain_idx = (hash & (rec_map->map->chain_cnt-1UL) );

  /* Traverse chain for candidate */
  fd_funk_rec_t * rec = NULL;
  for(;;) {
    int err = fd_progcache_search_chain( cache, chain_idx, key, epoch_slot0, &rec );
    if( FD_LIKELY( err==FD_MAP_SUCCESS ) ) break;
    FD_SPIN_PAUSE();
    /* FIXME backoff */
  }

  return rec;
}

fd_progcache_rec_t const *
fd_progcache_peek_exact( fd_progcache_t *          cache,
                         fd_funk_txn_xid_t const * xid,
                         void const *              prog_addr ) {
  fd_funk_xid_key_pair_t key[1];
  fd_funk_txn_xid_copy( key->xid, xid );
  memcpy( key->key->uc, prog_addr, 32UL );

  for(;;) {
    fd_funk_rec_map_query_t query[1];
    int query_err = fd_funk_rec_map_query_try( cache->funk->rec_map, key, NULL, query, 0 );
    if( query_err==FD_MAP_ERR_AGAIN ) {
      FD_SPIN_PAUSE();
      continue;
    }
    if( FD_UNLIKELY( query_err==FD_MAP_ERR_KEY ) ) return NULL;
    if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) {
      FD_LOG_CRIT(( "fd_funk_rec_map_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
    }
    return fd_funk_val_const( fd_funk_rec_map_query_ele_const( query ), fd_funk_wksp( cache->funk ) );
  }
}

fd_progcache_rec_t const *
fd_progcache_peek( fd_progcache_t *          cache,
                   fd_funk_txn_xid_t const * xid,
                   void const *              prog_addr,
                   ulong                     epoch_slot0 ) {
  if( FD_UNLIKELY( !cache || !cache->funk->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_progcache_load_fork( cache, xid, epoch_slot0 );
  fd_funk_rec_key_t key[1]; memcpy( key->uc, prog_addr, 32UL );
  fd_funk_rec_t const * rec = fd_progcache_query( cache, xid, key, epoch_slot0 );
  if( FD_UNLIKELY( !rec ) ) return NULL;

  fd_progcache_rec_t const * entry = fd_funk_val_const( rec, fd_funk_wksp( cache->funk ) );
  if( entry->slot < epoch_slot0 ) entry = NULL;

  cache->metrics->hit_cnt += !!entry;

  return entry;
}

static void
fd_funk_rec_push_tail( fd_funk_rec_t * rec_pool,
                       fd_funk_rec_t * rec,
                       uint *          rec_head_idx,
                       uint *          rec_tail_idx ) {
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
fd_progcache_push( fd_progcache_t * cache,
                   fd_funk_txn_t *  txn,
                   fd_funk_rec_t *  rec,
                   void const *     prog_addr,
                   fd_funk_rec_t ** dup_rec ) {
  fd_funk_t * funk = cache->funk;
  *dup_rec = NULL;

  /* Phase 1: Determine record's xid-key pair */

  rec->tag = 0;
  rec->prev_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;
  memcpy( rec->pair.key, prog_addr, 32UL );
  if( FD_UNLIKELY( txn ) ) {
    fd_funk_txn_xid_copy( rec->pair.xid, &txn->xid );
  } else {
    fd_funk_txn_xid_set_root( rec->pair.xid );
  }

  /* Phase 2: Lock rec_map chain, entering critical section */

  struct {
    fd_funk_rec_map_txn_t txn[1];
    fd_funk_rec_map_txn_private_info_t info[1];
  } _map_txn;
  fd_funk_rec_map_txn_t * map_txn = fd_funk_rec_map_txn_init( _map_txn.txn, funk->rec_map, 1UL );
  fd_funk_rec_map_txn_add( map_txn, &rec->pair, 1 );
  int txn_err = fd_funk_rec_map_txn_try( map_txn, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( txn_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to insert progcache record: canont lock funk rec map chain: %i-%s", txn_err, fd_map_strerror( txn_err ) ));
  }

  /* Phase 3: Check if record exists */

  fd_funk_rec_map_query_t query[1];
  int query_err = fd_funk_rec_map_txn_query( funk->rec_map, &rec->pair, NULL, query, 0 );
  if( FD_UNLIKELY( query_err==FD_MAP_SUCCESS ) ) {
    fd_funk_rec_map_txn_test( map_txn );
    fd_funk_rec_map_txn_fini( map_txn );
    *dup_rec = query->ele;
    return 0; /* another thread was faster */
  } else if( FD_UNLIKELY( query_err!=FD_MAP_ERR_KEY ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_map_txn_query failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
  }

  /* Phase 4: Insert new record */

  int insert_err = fd_funk_rec_map_txn_insert( funk->rec_map, rec );
  if( FD_UNLIKELY( insert_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_map_txn_insert failed: %i-%s", insert_err, fd_map_strerror( insert_err ) ));
  }

  /* At this point, another thread could aggressively evict this entry.
     But this entry is not yet present in rec_map!  This is why we hold
     a lock on the rec_map chain -- the rec_map_remove executed by the
     eviction will be sequenced after completion of phase 5. */

  /* Phase 5: Insert rec into rec_map */

  if( txn ) {
    fd_funk_rec_push_tail( funk->rec_pool->ele,
                           rec,
                           &txn->rec_head_idx,
                           &txn->rec_tail_idx );
  }

  /* Phase 6: Finish rec_map transaction */

  int test_err = fd_funk_rec_map_txn_test( map_txn );
  if( FD_UNLIKELY( test_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_txn_test failed: %i-%s", test_err, fd_map_strerror( test_err ) ));
  fd_funk_rec_map_txn_fini( map_txn );
  return 1;
}

static int
fd_progcache_txn_try_lock( fd_funk_txn_t * txn ) {
  for(;;) {
    ushort * lock  = &txn->lock->value;
    ushort   value = FD_VOLATILE_CONST( *lock );
    if( FD_UNLIKELY( value>=0xFFFE ) ) return 0; /* txn is write-locked */
    if( FD_LIKELY( FD_ATOMIC_CAS( lock, value, value+1 )==value ) ) {
      return 1; /* transaction now read-locked */
    }
  }
}

static void
fd_progcache_txn_unlock( fd_funk_txn_t * txn ) {
  if( !txn ) return;
  fd_rwlock_unread( txn->lock );
}

/* fd_progcache_lock_best_txn picks a fork graph node close to
   target_slot and write locks it for program cache entry insertion.

   The cache entry should be placed as far up the fork graph as
   possible (so it can be shared across more downstream forks), but not
   too early (or it would cause non-determinism).

   Influenced by a number of things:

   - Program modification time (cannot predate the program modification)
   - Epoch boundaries (cannot span across epochs)
   - Transaction publishing (cannot create a cache entry at a txn that
     is in the process of being published) */

static fd_funk_txn_t *
fd_progcache_lock_best_txn( fd_progcache_t * cache,
                            ulong            target_slot ) {

  fd_funk_txn_xid_t last_publish[1];
  fd_funk_txn_xid_ld_atomic( last_publish, fd_funk_last_publish( cache->funk ) );
  if( target_slot <= last_publish->ul[0] &&
      !fd_funk_txn_xid_eq_root( last_publish ) ) {
    return NULL; /* publishing record immediately */
  }

  /* Scan fork graph for oldest node (>= program update slot) */
  ulong target_xid_idx;
  ulong fork_depth = cache->fork_depth;
  for( target_xid_idx=0UL; target_xid_idx<fork_depth; target_xid_idx++ ) {
    if( cache->fork[ target_xid_idx ].ul[0]<=target_slot ) break;
  }

  /* Backtrack up to newer fork graph nodes (>= access slot)
     Very old slots could have been rooted at this point */
  fd_funk_txn_t * txn;
  do {
    /* Locate fork */
    fd_funk_txn_xid_t const * xid = &cache->fork[ target_xid_idx ];
    txn = fd_funk_txn_query( xid, cache->funk->txn_map );
    if( FD_LIKELY( txn ) ) {
      /* Attempt to read-lock transaction */
      if( FD_LIKELY( fd_progcache_txn_try_lock( txn ) ) ) return txn;
    }
    /* Cannot insert at this fork graph node, try one newer */
    target_xid_idx--;
  } while( target_xid_idx!=ULONG_MAX );

  /* There is no funk_txn in range [target_slot,load_slot] that we can
     create a cache entry at. */
  FD_LOG_CRIT(( "Could not find program cache fork graph node for target slot %lu", target_slot ));
}

static fd_progcache_rec_t const *
fd_progcache_insert( fd_progcache_t *           cache,
                     fd_funk_t *                accdb,
                     fd_funk_txn_xid_t const *  load_xid,
                     void const *               prog_addr,
                     fd_prog_load_env_t const * env,
                     long                       slot_min ) {

  /* XID overview:

     - load_xid:   tip of fork currently being executed
     - modify_xid: xid in which program was last modified / deployed
     - txn->xid:   xid in which program cache entry is inserted

     slot(load_xid) > slot(entry_xid) >= slot(txn->xid) */

  /* Acquire reference to ELF binary data */

  fd_funk_txn_xid_t modify_xid;
  ulong progdata_sz;
  uchar const * progdata = fd_prog_load_elf( accdb, load_xid, prog_addr, &progdata_sz, &modify_xid );
  if( FD_UNLIKELY( !progdata ) ) return NULL;
  ulong target_slot = modify_xid.ul[0];

  /* Prevent cache entry from crossing epoch boundary */

  target_slot = fd_ulong_max( target_slot, env->epoch_slot0 );

  /* Prevent cache entry from shadowing invalidation */

  target_slot = (ulong)fd_long_max( (long)target_slot, slot_min );

  /* Allocate a funk_rec */

  fd_funk_t * funk = cache->funk;
  fd_funk_rec_t * funk_rec = fd_funk_rec_pool_acquire( funk->rec_pool, NULL, 0, NULL );
  if( FD_UNLIKELY( !funk_rec ) ) {
    FD_LOG_ERR(( "Program cache is out of memory: fd_funk_rec_pool_acquire failed (rec_max=%lu)",
                 fd_funk_rec_pool_ele_max( funk->rec_pool ) ));
  }
  memset( funk_rec, 0, sizeof(fd_funk_rec_t) );
  fd_funk_val_init( funk_rec );

  /* Pick and lock a txn in which cache entry is created at */

  fd_funk_txn_t * txn = fd_progcache_lock_best_txn( cache, target_slot );

  /* Load program */

  fd_features_t const * features  = env->features;
  ulong         const   load_slot = env->slot;
  fd_prog_versions_t versions = fd_prog_versions( features, load_slot );
  fd_sbpf_loader_config_t config = {
    .sbpf_min_version = versions.min_sbpf_version,
    .sbpf_max_version = versions.max_sbpf_version,
  };
  fd_sbpf_elf_info_t elf_info[1];

  fd_progcache_rec_t * rec = NULL;
  if( FD_LIKELY( fd_sbpf_elf_peek( elf_info, progdata, progdata_sz, &config )==FD_SBPF_ELF_SUCCESS ) ) {

    fd_funk_t * funk          = cache->funk;
    ulong       rec_align     = fd_progcache_rec_align();
    ulong       rec_footprint = fd_progcache_rec_footprint( elf_info );

    void * rec_mem = fd_funk_val_truncate( funk_rec, funk->alloc, funk->wksp, rec_align, rec_footprint, NULL );
    if( FD_UNLIKELY( !rec_mem ) ) {
      FD_LOG_ERR(( "Program cache is out of memory: fd_alloc_malloc failed (requested align=%lu sz=%lu)",
                  rec_align, rec_footprint ));
    }

    rec = fd_progcache_rec_new( rec_mem, elf_info, &config, load_slot, features, progdata, progdata_sz, cache->scratch, cache->scratch_sz );
    if( !rec ) {
      fd_funk_val_flush( funk_rec, funk->alloc, funk->wksp );
    }

  }

  /* Convert to tombstone if load failed */

  if( !rec ) {  /* load fail */
    void * rec_mem = fd_funk_val_truncate( funk_rec, funk->alloc, funk->wksp, fd_progcache_rec_align(), fd_progcache_rec_footprint( NULL ), NULL );
    if( FD_UNLIKELY( !rec_mem ) ) {
      FD_LOG_ERR(( "Program cache is out of memory: fd_alloc_malloc failed (requested align=%lu sz=%lu)",
                   fd_progcache_rec_align(), fd_progcache_rec_footprint( NULL ) ));
    }
    rec = fd_progcache_rec_new_nx( rec_mem, load_slot );
  }

  /* Publish cache entry to funk index */

  fd_funk_rec_t * dup_rec = NULL;
  int push_ok = fd_progcache_push( cache, txn, funk_rec, prog_addr, &dup_rec );

  /* Done modifying transaction */

  fd_progcache_txn_unlock( txn );

  /* If another thread was faster publishing the same record, use that
     one instead.  FIXME POSSIBLE RACE CONDITION WHERE THE OTHER REC IS
     EVICTED AFTER PEEK? */

  if( !push_ok ) {
    FD_TEST( dup_rec );
    fd_funk_val_flush( funk_rec, funk->alloc, funk->wksp );
    fd_funk_rec_pool_release( funk->rec_pool, funk_rec, 1 );
    cache->metrics->dup_insert_cnt++;
    return fd_funk_val_const( dup_rec, funk->wksp );
  }

  cache->metrics->fill_cnt++;
  cache->metrics->fill_tot_sz += rec->rodata_sz;

  return rec;
}

fd_progcache_rec_t const *
fd_progcache_pull( fd_progcache_t *           cache,
                   fd_funk_t *                accdb,
                   fd_funk_txn_xid_t const *  xid,
                   void const *               prog_addr,
                   fd_prog_load_env_t const * env ) {
  if( FD_UNLIKELY( !cache || !cache->funk->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
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
  fd_funk_t * funk = cache->funk;

  if( FD_UNLIKELY( !cache || !funk->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));

  /* Select a fork node to create invalidate record in
     Do not create invalidation records at the funk root */

  if( fd_funk_txn_xid_eq( xid, cache->funk->shmem->last_publish ) ) return NULL;

  fd_funk_txn_t * txn = fd_funk_txn_query( xid, funk->txn_map );
  if( FD_UNLIKELY( !fd_progcache_txn_try_lock( txn ) ) ) {
    FD_LOG_CRIT(( "fd_progcache_invalidate(xid=%lu,...) failed: txn is write-locked", xid->ul[0] ));
  }

  /* Allocate a funk_rec */

  fd_funk_rec_t * funk_rec = fd_funk_rec_pool_acquire( funk->rec_pool, NULL, 0, NULL );
  if( FD_UNLIKELY( !funk_rec ) ) {
    FD_LOG_ERR(( "Program cache is out of memory: fd_funk_rec_pool_acquire failed (rec_max=%lu)",
                 fd_funk_rec_pool_ele_max( funk->rec_pool ) ));
  }
  memset( funk_rec, 0, sizeof(fd_funk_rec_t) );
  fd_funk_val_init( funk_rec );

  /* Create a tombstone */

  void * rec_mem = fd_funk_val_truncate( funk_rec, funk->alloc, funk->wksp, fd_progcache_rec_align(), fd_progcache_rec_footprint( NULL ), NULL );
  if( FD_UNLIKELY( !rec_mem ) ) {
    FD_LOG_ERR(( "Program cache is out of memory: fd_alloc_malloc failed (requested align=%lu sz=%lu)",
                  fd_progcache_rec_align(), fd_progcache_rec_footprint( NULL ) ));
  }
  fd_progcache_rec_t * rec = fd_progcache_rec_new_nx( rec_mem, slot );
  rec->invalidate = 1;

  /* Publish cache entry to funk index */

  fd_funk_rec_t * dup_rec = NULL;
  int push_ok = fd_progcache_push( cache, txn, funk_rec, prog_addr, &dup_rec );

  /* Done modifying transaction */

  fd_progcache_txn_unlock( txn );

  /* If another thread was faster publishing the same record, use that
     one instead.  FIXME POSSIBLE RACE CONDITION WHERE THE OTHER REC IS
     EVICTED AFTER PEEK? */

  if( !push_ok ) {
    FD_TEST( dup_rec );
    fd_funk_val_flush( funk_rec, funk->alloc, funk->wksp );
    fd_funk_rec_pool_release( funk->rec_pool, funk_rec, 1 );
    cache->metrics->dup_insert_cnt++;
    return fd_funk_val_const( dup_rec, funk->wksp );
  }

  cache->metrics->invalidate_cnt++;

  return rec;
}
