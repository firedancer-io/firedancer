#include "fd_prog_load.h"
#include "fd_progcache_user.h"
#include "fd_progcache_reclaim.h"

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

  while( cache->join->rec.reclaim_head!=UINT_MAX ) {
    fd_prog_reclaim_work( cache->join );
    FD_SPIN_PAUSE();
  }

  if( FD_UNLIKELY( !fd_progcache_shmem_leave( cache->join, opt_shmem ) ) ) return NULL;
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
fd_progcache_load_fork_slow( fd_progcache_t * cache,
                             fd_xid_t const * xid ) {
  fd_accdb_lineage_t *        lineage = cache->lineage;
  fd_progcache_join_t const * ljoin   = cache->join;
  fd_rwlock_read( &ljoin->shmem->txn.rwlock );
  lineage->fork_depth = 0UL;

  ulong txn_max = fd_prog_txnp_max( ljoin->txn.pool );
  fd_xid_t next_xid = *xid;
  ulong i;
  for( i=0UL;; i++ ) {
    if( FD_UNLIKELY( i>=FD_PROGCACHE_DEPTH_MAX ) ) {
      FD_LOG_CRIT(( "fd_progcache_load_fork: fork depth exceeded max of %lu", (ulong)FD_PROGCACHE_DEPTH_MAX ));
    }
    uint next_idx = (uint)fd_prog_txnm_idx_query_const( ljoin->txn.map, &next_xid, UINT_MAX, ljoin->txn.pool );
    if( FD_UNLIKELY( next_idx==UINT_MAX ) ) break;
    if( FD_UNLIKELY( (ulong)next_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (load_fork txn_idx=%u txn_max=%lu)", next_idx, txn_max ));
    fd_progcache_txn_t * candidate = &ljoin->txn.pool[ next_idx ];

    uint parent_idx = candidate->parent_idx;
    FD_TEST( parent_idx!=next_idx );
    lineage->fork[ i ] = next_xid;
    if( parent_idx==UINT_MAX ) {
      i++;
      break;
    }
    if( FD_UNLIKELY( (ulong)parent_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (load_fork parent_idx=%u txn_max=%lu)", parent_idx, txn_max ));
    next_xid = ljoin->txn.pool[ parent_idx ].xid;
  }

  lineage->fork_depth = i;

  fd_rwlock_unread( &ljoin->shmem->txn.rwlock );
}

static inline void
fd_progcache_load_fork( fd_progcache_t * cache,
                        fd_xid_t const * xid ) {
  /* Skip if already on the correct fork */
  fd_accdb_lineage_t * lineage = cache->lineage;
  if( FD_LIKELY( (!!lineage->fork_depth) & (!!fd_funk_txn_xid_eq( &lineage->fork[ 0 ], xid ) ) ) ) return;
  fd_progcache_load_fork_slow( cache, xid ); /* switch fork */
}

/* fd_progcache_query searches for a program cache entry on the current
   fork.  Stops short of an epoch boundary. */

static int
fd_progcache_search_chain( fd_progcache_t const *    cache,
                           ulong                     chain_idx,
                           fd_funk_rec_key_t const * key,
                           ulong                     revision_slot,
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
  fd_progcache_rec_t * best = NULL;
  for( ulong i=0UL; i<cnt; i++, ele_idx=FD_VOLATILE_CONST( rec_tbl[ ele_idx ].map_next ) ) {
    if( FD_UNLIKELY( (ulong)ele_idx >= rec_max ) ) return FD_MAP_ERR_AGAIN;
    fd_progcache_rec_t * rec = &rec_tbl[ ele_idx ];

    /* Skip over unrelated records (hash collision) */
    if( FD_UNLIKELY( !fd_funk_rec_key_eq( rec->pair.key, key ) ) ) continue;

    /* Skip over other revisions */
    if( FD_UNLIKELY( rec->slot!=revision_slot ) ) continue;
    fd_xid_t rec_xid[1];
    fd_funk_txn_xid_ld_atomic( rec_xid, rec->pair.xid );
    if( FD_UNLIKELY( !fd_accdb_lineage_has_xid( lineage, rec_xid ) ) ) continue;

    if( FD_UNLIKELY( rec->map_next==ele_idx ) ) return FD_MAP_ERR_AGAIN;
    if( FD_UNLIKELY( rec->map_next!=UINT_MAX && rec->map_next>=rec_max ) ) return FD_MAP_ERR_AGAIN;
    best = rec;
    break;
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
                    fd_xid_t const * xid,
                    fd_funk_rec_key_t const * key,
                    ulong                     revision_slot ) {
  /* Hash key to chain */
  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_copy( pair->xid, xid );
  fd_funk_rec_key_copy( pair->key, key );
  fd_prog_recm_t const * rec_map = cache->join->rec.map;
  ulong hash      = fd_funk_rec_key_hash( pair->key, rec_map->map->seed );
  ulong chain_idx = (hash & (rec_map->map->chain_cnt-1UL) );

  /* Traverse chain for candidate */
  fd_progcache_rec_t * rec = NULL;
  for(;;) {
    int err = fd_progcache_search_chain( cache, chain_idx, key, revision_slot, &rec );
    if( FD_LIKELY( err==FD_MAP_SUCCESS ) ) break;
    FD_SPIN_PAUSE();
    /* FIXME backoff */
  }

  return rec;
}

fd_progcache_rec_t * /* read locked */
fd_progcache_peek( fd_progcache_t * cache,
                   fd_xid_t const * xid,
                   void const *     prog_addr,
                   ulong            revision_slot ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  fd_progcache_load_fork( cache, xid );
  fd_funk_rec_key_t key[1]; memcpy( key->uc, prog_addr, 32UL );
  fd_progcache_rec_t * rec = fd_progcache_query( cache, xid, key, revision_slot );
  if( FD_UNLIKELY( !rec ) ) return NULL;
  return rec;
}

static void
fd_progcache_rec_push_tail( fd_progcache_rec_t * rec_pool,
                            fd_progcache_rec_t * rec,
                            uint *               rec_head_idx, /* write locked (txn) */
                            uint *               rec_tail_idx,
                            ulong                rec_max ) {
  uint rec_idx      = (uint)( rec - rec_pool );
  uint rec_prev_idx = *rec_tail_idx;

  if( FD_UNLIKELY( (ulong)rec_idx >= rec_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (push_tail rec_idx=%u rec_max=%lu)", rec_idx, rec_max ));
  if( FD_UNLIKELY( rec_prev_idx!=UINT_MAX && (ulong)rec_prev_idx >= rec_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (push_tail rec_prev_idx=%u rec_max=%lu)", rec_prev_idx, rec_max ));

  rec->prev_idx = rec_prev_idx;
  rec->next_idx = UINT_MAX;

  if( rec_prev_idx==UINT_MAX ) {
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
                   ulong                 revision_slot ) {

  /* Determine record's xid-key pair */

  rec->prev_idx = UINT_MAX;
  rec->next_idx = UINT_MAX;
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

  /* Check if record exists */

  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_txn_query( cache->rec.map, &rec->pair, NULL, query, 0 );
  if( FD_UNLIKELY( query_err==FD_MAP_SUCCESS ) ) {
    /* Always replace existing rooted records */
    fd_progcache_rec_t * prev_rec = query->ele;
    if( fd_funk_txn_xid_eq_root( rec->pair.xid ) && prev_rec->slot < revision_slot ) {
      fd_rwlock_write( &prev_rec->lock );
      fd_prog_recm_txn_remove( cache->rec.map, &rec->pair, NULL, query, FD_MAP_FLAG_USE_HINT );
      fd_progcache_val_free( prev_rec, cache );
      fd_rwlock_unwrite( &prev_rec->lock );
      fd_prog_clock_remove( cache->clock.bits, (ulong)( prev_rec - cache->rec.pool->ele ) );
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

  ulong rec_max = fd_prog_recp_ele_max( cache->rec.pool );
  if( txn ) {
    fd_progcache_rec_push_tail( cache->rec.pool->ele,
        rec,
        &txn->rec_head_idx,
        &txn->rec_tail_idx,
        rec_max );
    uint txn_idx_computed = (uint)( txn - cache->txn.pool );
    ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
    if( FD_UNLIKELY( (ulong)txn_idx_computed >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (push txn_idx=%u txn_max=%lu)", txn_idx_computed, txn_max ));
    atomic_store_explicit( &rec->txn_idx, txn_idx_computed, memory_order_release );
  }

  /* Phase 6: Finish rec_map transaction */

  int test_err = fd_prog_recm_txn_test( map_txn );
  if( FD_UNLIKELY( test_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_txn_test failed: %i-%s", test_err, fd_map_strerror( test_err ) ));
  fd_prog_recm_txn_fini( map_txn );

  /* Phase 7: Mark record as recently accessed */

  ulong rec_clock_idx = (ulong)( rec - cache->rec.pool->ele );
  if( FD_UNLIKELY( rec_clock_idx >= rec_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (push rec_idx=%lu rec_max=%lu)", rec_clock_idx, rec_max ));
  fd_prog_clock_touch( cache->clock.bits, rec_clock_idx );

  return 1;
}

/* insert_params captures all environment parameters required to load a
   program revision into cache. */

struct insert_params {
  void const *            prog_addr;
  ulong                   revision_slot;
  fd_sbpf_elf_info_t      elf_info;
  fd_sbpf_loader_config_t config;
  fd_features_t const *   features;
  uchar const *           bin;
  ulong                   bin_sz;
  int                     peek_err;
};

typedef struct insert_params insert_params_t;

static insert_params_t *
insert_params( insert_params_t *          p,
               fd_xid_t const *           load_xid,
               void const *               prog_addr,
               fd_prog_load_env_t const * env,
               fd_accdb_ro_t *            prog_ro,
               fd_prog_info_t const *     info ) {
  memset( p, 0, sizeof(insert_params_t) );

  /* Derive executable info */
  uchar const * bin           = (uchar const *)fd_accdb_ref_data_const( prog_ro ) + info->elf_off;
  ulong         bin_sz        = info->elf_sz;
  ulong         revision_slot = fd_progcache_revision_slot( env->epoch_slot0, info->deploy_slot );

  /* Pre-flight checks, determine required buffer size */

  fd_features_t const * features  = env->features;
  ulong         const   load_slot = load_xid->ul[0];
  fd_prog_versions_t versions = fd_prog_versions( features, load_slot );
  fd_sbpf_elf_info_t elf_info;
  fd_sbpf_loader_config_t config = {
    .sbpf_min_version = versions.min_sbpf_version,
    .sbpf_max_version = versions.max_sbpf_version,
  };
  int peek_err = fd_sbpf_elf_peek( &elf_info, bin, bin_sz, &config );

  *p = (insert_params_t) {
    .prog_addr     = prog_addr,
    .revision_slot = revision_slot,
    .features      = features,
    .bin           = !peek_err ? bin    : NULL,
    .bin_sz        = !peek_err ? bin_sz : 0UL,
    .peek_err      = peek_err,
    .elf_info      = elf_info,
    .config        = config
  };
  return p;
}

/* fd_progcache_spill_open loads a program into the cache spill buffer.
   The spill area is an "emergency" area for temporary program loads in
   case the record pool/heap are too contended. */

static fd_progcache_rec_t * /* read locked */
fd_progcache_spill_open( fd_progcache_t *        cache,
                         insert_params_t const * params ) {
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
  rec->slot       = params->revision_slot;

  /* Load program */

  if( !params->peek_err ) {
    ulong off0 = fd_ulong_align_up( shmem->spill.spad_used, fd_progcache_val_align() );
    ulong off1 = off0 + fd_progcache_val_footprint( &params->elf_info );
    if( FD_UNLIKELY( off1 > FD_PROGCACHE_SPAD_MAX ) ) {
      FD_LOG_CRIT(( "spill buffer overflow: spad_used=%u val_sz=%lu spad_max=%lu", shmem->spill.spad_used, off1-off0, FD_PROGCACHE_SPAD_MAX ));
    }
    rec->data_gaddr = fd_wksp_gaddr_fast( join->wksp, shmem->spill.spad + off0 );
    rec->data_max   = (uint)( off1 - off0 );

    long dt = -fd_tickcount();
    if( FD_LIKELY( fd_progcache_rec_load( rec, join->wksp, &params->elf_info, &params->config, params->revision_slot, params->features, params->bin, params->bin_sz, cache->scratch, cache->scratch_sz ) ) ) {
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

static fd_progcache_rec_t * /* read locked */
fd_progcache_insert( fd_progcache_t *        cache,
                     insert_params_t const * params ) {
  fd_progcache_join_t *           ljoin         = cache->join;
  void const *                    prog_addr     = params->prog_addr;
  int                             peek_err      = params->peek_err;
  fd_sbpf_elf_info_t const *      elf_info      = &params->elf_info;
  fd_sbpf_loader_config_t const * config        = &params->config;
  ulong                           revision_slot = params->revision_slot;
  fd_features_t const *           features      = params->features;
  uchar const *                   bin           = params->bin;
  ulong                           bin_sz        = params->bin_sz;


  /* Allocate record and heap space */

  fd_progcache_rec_t * rec = fd_prog_recp_acquire( ljoin->rec.pool, NULL, 1, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    cache->metrics->oom_desc_cnt++;
    fd_prog_clock_evict( cache, 4UL, 0UL );
    rec = fd_prog_recp_acquire( ljoin->rec.pool, NULL, 1, NULL );
    if( FD_UNLIKELY( !rec ) ) {
      /* Out of memory (record table) */
      return fd_progcache_spill_open( cache, params );
    }
  }
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->exists       = 1;
  rec->slot         = revision_slot;
  rec->txn_idx      = UINT_MAX;
  rec->reclaim_next = UINT_MAX;

  if( FD_LIKELY( peek_err==FD_SBPF_ELF_SUCCESS ) ) {
    ulong val_align     = fd_progcache_val_align();
    ulong val_footprint = fd_progcache_val_footprint( elf_info );
    if( FD_UNLIKELY( !fd_progcache_val_alloc( rec, ljoin, val_align, val_footprint ) ) ) {
      cache->metrics->oom_heap_cnt++;
      fd_prog_clock_evict( cache, 0UL, 16UL<<20 );
      if( FD_UNLIKELY( !fd_progcache_val_alloc( rec, ljoin, val_align, val_footprint ) ) ) {
        /* Out of memory (heap) */
        rec->exists = 0;
        fd_prog_recp_release( ljoin->rec.pool, rec, 1 );
        return fd_progcache_spill_open( cache, params );
      }
    }
  } else {
    fd_progcache_rec_nx( rec );
  }

  /* Publish cache entry to index */

  /* Acquires rec->lock before txn.rwlock (inverse of the documented
     lock order).  Safe because the record was just allocated and is not
     yet visible to other threads. */
  fd_rwlock_write( &rec->lock );
  fd_xid_t const * xid = fd_lineage_xid( cache->lineage, revision_slot );
  fd_rwlock_read( &ljoin->shmem->txn.rwlock );
  fd_progcache_txn_t * txn = NULL;
  if( xid ) txn = (fd_progcache_txn_t *)fd_prog_txnm_ele_query_const( ljoin->txn.map, xid, NULL, ljoin->txn.pool );
  if( txn ) fd_rwlock_write( &txn->lock );
  int push_ok = fd_progcache_push( ljoin, txn, rec, prog_addr, revision_slot );
  if( txn ) fd_rwlock_unwrite( &txn->lock );
  if( FD_UNLIKELY( !push_ok ) ) {
    fd_rwlock_unread( &ljoin->shmem->txn.rwlock );
    fd_rwlock_unwrite( &rec->lock );
    fd_progcache_val_free( rec, ljoin );
    fd_prog_recp_release( ljoin->rec.pool, rec, 1 );
    return NULL;
  }
  fd_rwlock_unread( &ljoin->shmem->txn.rwlock );

  /* Load program
     (The write lock was acquired before loading such that another
     thread trying to load the same record instead waits for us to
     complete) */

  if( FD_LIKELY( peek_err==FD_SBPF_ELF_SUCCESS ) ) {
    long dt = -fd_tickcount();
    if( FD_UNLIKELY( !fd_progcache_rec_load( rec, ljoin->wksp, elf_info, config, revision_slot, features, bin, bin_sz, cache->scratch, cache->scratch_sz ) ) ) {
      /* Not a valid program (mark cache entry as non-executable) */
      fd_progcache_val_free( rec, ljoin );
      fd_progcache_rec_nx( rec );
    }
    dt += fd_tickcount();
    cache->metrics->cum_load_ticks += (ulong)dt;
  }

  fd_rwlock_demote( &rec->lock );

  cache->metrics->fill_cnt++;
  cache->metrics->fill_tot_sz += rec->rodata_sz;
  FD_TEST( rec->exists );
  return rec;
}

fd_progcache_rec_t * /* read locked */
fd_progcache_pull( fd_progcache_t *           cache,
                   fd_xid_t const *           xid,
                   void const *               prog_addr,
                   fd_prog_load_env_t const * env,
                   fd_accdb_ro_t *            prog_ro ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  long dt = -fd_tickcount();
  fd_progcache_load_fork( cache, xid );
  cache->metrics->lookup_cnt++;

  fd_prog_info_t info[1];
  if( FD_UNLIKELY( !fd_prog_info( info, prog_ro ) ) ) return NULL;
  ulong revision_slot = fd_progcache_revision_slot( env->epoch_slot0, info->deploy_slot );

  insert_params_t insert[1];
  fd_progcache_rec_t * found_rec = NULL;
  for( int attempt=0;; attempt++ ) {
    found_rec = fd_progcache_peek( cache, xid, prog_addr, revision_slot );
    if( FD_LIKELY( found_rec ) ) {
      cache->metrics->hit_cnt++;
      break;
    }
    if( attempt==0 ) insert_params( insert, xid, prog_addr, env, prog_ro, info );
    found_rec = fd_progcache_insert( cache, insert );
    if( FD_LIKELY( found_rec ) ) {
      cache->metrics->miss_cnt++;
      break;
    }
    if( FD_UNLIKELY( attempt>=4 ) ) {
      /* Extremely unlikely case: four separate attempts resulted in
         contention */
      return fd_progcache_spill_open( cache, insert );
    }
  }

  dt += fd_tickcount();
  cache->metrics->cum_pull_ticks += (ulong)dt;
  return found_rec;
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
