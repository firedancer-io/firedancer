#include "fd_prog_load.h"
#include "fd_progcache_user.h"
#include "fd_progcache_reclaim.h"
#include "fd_progcache_clock.h"
#include "../../util/racesan/fd_racesan_target.h"
#include "../../disco/metrics/generated/fd_metrics_enums.h"

/* FD_PROGCACHE_METRICS_WRITE copies CLASS_CNT-sized arrays through the metrics
   enum, so a class added without regenerating the enum would read past them. */

FD_STATIC_ASSERT( FD_METRICS_ENUM_PROGCACHE_CLASS_CNT==FD_PROGCACHE_CACHE_CLASS_CNT,
                  progcache_metrics_class_cnt );

/* Counts sz's size class in a per-class metrics array.
   An oversized value classes out of range and goes uncounted. */

static inline void
progcache_metric_per_class( ulong * per_class,
                            ulong   c ) {
  if( FD_LIKELY( c<FD_PROGCACHE_CACHE_CLASS_CNT ) ) per_class[ c ]++;
}

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

  fd_prog_reclaim_work( cache->join );
  if( FD_UNLIKELY( !fd_progcache_shmem_leave( cache->join, opt_shmem ) ) ) return NULL;
  cache->scratch    = NULL;
  cache->scratch_sz = 0UL;
  return cache;
}

/* fd_progcache_load_fork pivots the progcache object to the selected fork
   (identified by tip XID): populates cache->lineage with the fork's XIDs,
   newest to oldest.  Cache lookups only respect records on that lineage.

   load_fork_slow and fd_progcache_query below are internal but not static:
   the test suite composes them into a lookup that does not fill (see
   test_progcache_common.c).  They are absent from fd_progcache_user.h. */

void
fd_progcache_load_fork_slow( fd_progcache_t *       cache,
                             fd_progcache_fork_id_t fork_id ) {
  fd_progcache_lineage_t *    lineage = cache->lineage;
  fd_progcache_join_t const * ljoin   = cache->join;
  fd_rwlock_read( &ljoin->shmem->txn.rwlock );
  lineage->fork_depth  = 0UL;
  lineage->tip_txn_idx = ULONG_MAX;
  lineage->root = __atomic_load_n( &ljoin->shmem->txn.root, memory_order_acquire );

  ulong txn_max = fd_prog_txnp_max( ljoin->txn.pool );
  ulong i;
  for( i=0UL;; i++ ) {
    if( FD_UNLIKELY( i>=FD_PROGCACHE_DEPTH_MAX ) ) {
      FD_LOG_CRIT(( "fd_progcache_load_fork: fork depth exceeded max of %lu", (ulong)FD_PROGCACHE_DEPTH_MAX ));
    }
    uint next_idx = (uint)fd_prog_txnm_idx_query_const( ljoin->txn.map, &fork_id, UINT_MAX, ljoin->txn.pool );
    if( FD_UNLIKELY( next_idx==UINT_MAX ) ) break;
    if( FD_UNLIKELY( (ulong)next_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (load_fork txn_idx=%u txn_max=%lu)", next_idx, txn_max ));
    fd_progcache_txn_t * candidate = &ljoin->txn.pool[ next_idx ];

    uint parent_idx = candidate->parent_idx;
    FD_TEST( parent_idx!=next_idx );
    lineage->fork[ i ] = fork_id;
    if( FD_LIKELY( !i ) ) lineage->tip_txn_idx = next_idx;
    if( parent_idx==UINT_MAX ) {
      i++;
      break;
    }
    if( FD_UNLIKELY( (ulong)parent_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (load_fork parent_idx=%u txn_max=%lu)", parent_idx, txn_max ));
    fork_id = ljoin->txn.pool[ parent_idx ].xid;
  }

  lineage->fork_depth = i;

  fd_rwlock_unread( &ljoin->shmem->txn.rwlock );

  lineage->root = __atomic_load_n( &ljoin->shmem->txn.root, memory_order_acquire );
}

static inline void
fd_progcache_load_fork( fd_progcache_t *       cache,
                        fd_progcache_fork_id_t fork_id ) {
  /* Skip if already on the correct fork */
  fd_progcache_lineage_t * lineage = cache->lineage;
  if( FD_LIKELY( (!!lineage->fork_depth) & (lineage->fork[ 0 ]==fork_id ) ) ) return;
  fd_progcache_load_fork_slow( cache, fork_id ); /* switch fork */
}

/* fd_prog_wait_if_loading waits out a peer's in-flight load of rec, so the caller
   only ever sees a record whose program is in.  Returns rec. */

static inline fd_progcache_rec_t *
fd_prog_wait_if_loading( fd_progcache_t *     cache,
                         fd_progcache_rec_t * rec ) {
  if( FD_UNLIKELY( fd_prog_state_is_loading( rec ) ) ) {
    cache->metrics->hit_loading_cnt++;
    while( fd_prog_state_is_loading( rec ) ) {
      fd_racesan_hook( "prog_wait_if_loading:spin" );
      FD_SPIN_PAUSE();
    }
  }
  return rec;
}

/* fd_progcache_query searches for a program cache entry on the current
   fork.  Stops short of an epoch boundary. */

static int
fd_progcache_search_chain( fd_progcache_t const * cache,
                           ulong                  chain_idx,
                           fd_pubkey_t const *    key,
                           ulong                  feature_slot,
                           ulong                  deploy_slot,
                           fd_progcache_rec_t **  out_rec ) { /* read locked */
  *out_rec = NULL;

  fd_progcache_join_t const *                ljoin     = cache->join;
  fd_progcache_lineage_t const *             lineage   = cache->lineage;
  fd_prog_recm_shmem_t *                     shmap     = ljoin->rec.map->map;
  fd_prog_recm_shmem_private_chain_t const * chain_tbl = fd_prog_recm_shmem_private_chain_const( shmap, 0UL );
  fd_prog_recm_shmem_private_chain_t const * chain     = chain_tbl + chain_idx;
  fd_progcache_rec_t *                       rec_tbl   = ljoin->rec.ele;
  ulong                                      rec_max   = ljoin->rec.max;
  ulong                                      ver_cnt   = FD_VOLATILE_CONST( chain->ver_cnt );

  /* Start a speculative transaction for the chain containing revisions
     of the program cache key we are looking for. */
  ulong cnt = fd_prog_recm_private_vcnt_cnt( ver_cnt );
  if( FD_UNLIKELY( fd_prog_recm_private_vcnt_ver( ver_cnt )&1 ) ) {
    return FD_MAP_ERR_AGAIN; /* chain is locked */
  }
  FD_COMPILER_MFENCE();
  fd_racesan_hook( "prog_search_chain:post_ver_cnt" );
  uint ele_idx = chain->head_cidx;

  /* Walk the map chain, remember the best entry */
  fd_progcache_rec_t * best = NULL;
  for( ulong i=0UL; i<cnt; i++, ele_idx=FD_VOLATILE_CONST( rec_tbl[ ele_idx ].map_next ) ) {
    if( FD_UNLIKELY( (ulong)ele_idx >= rec_max ) ) return FD_MAP_ERR_AGAIN;
    fd_progcache_rec_t * rec = &rec_tbl[ ele_idx ];

    if( FD_UNLIKELY( ( !fd_pubkey_eq( &rec->pair.prog, key ) ) |
                     ( rec->feature_slot != feature_slot   ) |
                     ( rec->deploy_slot  != deploy_slot    ) ) ) {
      continue;
    }

    fd_progcache_fork_id_t rec_fork_id = __atomic_load_n( &rec->pair.xid, memory_order_relaxed );
    if( FD_UNLIKELY( !fd_progcache_lineage_has_xid( lineage, rec_fork_id ) ) ) continue;

    if( FD_UNLIKELY( rec->map_next==ele_idx ) ) return FD_MAP_ERR_AGAIN;
    if( FD_UNLIKELY( rec->map_next!=UINT_MAX && rec->map_next>=rec_max ) ) return FD_MAP_ERR_AGAIN;
    best = rec;
    break;
  }
  fd_racesan_hook( "prog_search_chain:pre_tryread" );
  if( best && FD_UNLIKELY( !fd_rwlock_tryread( &best->lock ) ) ) {
    return FD_MAP_ERR_AGAIN;
  }
  fd_racesan_hook( "prog_search_chain:post_tryread" );

  /* Retry if we were overrun */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( chain->ver_cnt )!=ver_cnt ) ) {
    if( best ) fd_rwlock_unread( &best->lock );
    return FD_MAP_ERR_AGAIN;
  }

  *out_rec = best;
  return FD_MAP_SUCCESS;
}

fd_progcache_rec_t * /* read locked */
fd_progcache_query( fd_progcache_t *    cache,
                    fd_pubkey_t const * key,
                    ulong               feature_slot,
                    ulong               deploy_slot ) {
  /* Hash key to chain */
  fd_prog_recm_t const * rec_map = cache->join->rec.map;
  ulong hash      = fd_progcache_rec_key_hash( key, rec_map->map->seed );
  ulong chain_idx = (hash & (rec_map->map->chain_cnt-1UL) );

  /* Traverse chain for candidate */
  fd_progcache_rec_t * rec = NULL;
  for(;;) {
    int err = fd_progcache_search_chain( cache, chain_idx, key, feature_slot, deploy_slot, &rec );
    if( FD_LIKELY( err==FD_MAP_SUCCESS ) ) break;
    fd_racesan_hook( "prog_query:retry" );
    FD_SPIN_PAUSE();
    /* FIXME backoff */
  }
  if( FD_LIKELY( !rec ) ) return NULL; /* Program not found, need an insert */

  return fd_prog_wait_if_loading( cache, rec );
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

/* Publishes rec (complete, read-locked) under the txn.  Returns the record now
   serving this key: rec, or the winner's read-locked record if another tile won
   the race, or NULL if a mapped record has this key with different
   feature/deploy slots. */

__attribute__((warn_unused_result))
static fd_progcache_rec_t *
fd_progcache_push( fd_progcache_join_t * cache,
                   fd_progcache_txn_t *  txn, /* write locked */
                   fd_progcache_rec_t *  rec,
                   void const *          prog_addr ) {
  FD_TEST( fd_prog_state_is_loading( rec ) );

  /* Determine record's xid-key pair */

  rec->prev_idx = UINT_MAX;
  rec->next_idx = UINT_MAX;
  memcpy( &rec->pair.prog, prog_addr, 32UL );
  if( FD_UNLIKELY( !txn ) ) FD_LOG_CRIT(( "NULL txn" ));
  __atomic_store_n( &rec->pair.xid, txn->xid, memory_order_relaxed );

  /* Lock rec_map chain, entering critical section */

  struct {
    fd_prog_recm_txn_t txn[1];
    fd_prog_recm_txn_private_info_t info[1];
  } _map_txn;
  fd_prog_recm_txn_t * map_txn = fd_prog_recm_txn_init( _map_txn.txn, cache->rec.map, 1UL );
  fd_prog_recm_txn_add( map_txn, &rec->pair, 1 );
  int txn_err = fd_prog_recm_txn_try( map_txn, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( txn_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to insert progcache record: cannot lock rec map chain: %i-%s", txn_err, fd_map_strerror( txn_err ) ));
  }
  fd_racesan_hook( "prog_push:post_chain_lock" );

  /* Check if record exists */

  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_txn_query( cache->rec.map, &rec->pair, NULL, query, 0 );
  if( FD_UNLIKELY( query_err==FD_MAP_SUCCESS ) ) {
    /* Duplicate: adopt the winner.  Requires that a mapped record is never
       write-locked. */
    fd_progcache_rec_t * winner = query->ele;
    int match = ( winner->feature_slot==rec->feature_slot ) & ( winner->deploy_slot==rec->deploy_slot );
    if( FD_LIKELY( match ) ) fd_rwlock_read( &winner->lock );
    fd_prog_recm_txn_test( map_txn );
    fd_prog_recm_txn_fini( map_txn );
    return match ? winner : NULL;
  } else if( FD_UNLIKELY( query_err!=FD_MAP_ERR_KEY ) ) {
    FD_LOG_CRIT(( "fd_prog_recm_txn_query failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
  }

  ulong rec_max = cache->rec.max;

  /* Insert new record */

  /* Link record into the transaction's record list.  Ownership is established
     before the record becomes findable, so a mapped record has an owner unless
     rooting deliberately detached it. */

  fd_progcache_rec_push_tail( cache->rec.ele,
      rec,
      &txn->rec_head_idx,
      &txn->rec_tail_idx,
      rec_max );
  uint txn_idx_computed = (uint)( txn - cache->txn.pool );
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  if( FD_UNLIKELY( (ulong)txn_idx_computed >= txn_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (push txn_idx=%u txn_max=%lu)", txn_idx_computed, txn_max ));
  atomic_store_explicit( &rec->txn_idx, txn_idx_computed, memory_order_release );

  int insert_err = fd_prog_recm_txn_insert( cache->rec.map, rec );
  if( FD_UNLIKELY( insert_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_prog_recm_txn_insert failed: %i-%s", insert_err, fd_map_strerror( insert_err ) ));
  }
  fd_racesan_hook( "prog_push:post_map_insert" );

  /* Finish rec_map transaction */

  int test_err = fd_prog_recm_txn_test( map_txn );
  if( FD_UNLIKELY( test_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_txn_test failed: %i-%s", test_err, fd_map_strerror( test_err ) ));
  fd_prog_recm_txn_fini( map_txn );

  return rec;
}

/* insert_params captures all environment parameters required to load a
   program revision into cache. */

struct insert_params {
  fd_pubkey_t             prog_addr;
  ulong                   feature_slot;
  ulong                   deploy_slot;
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
               fd_pubkey_t const *        prog_addr,
               fd_prog_load_env_t const * env,
               fd_acc_t const *           prog_ro,
               fd_prog_info_t const *     info ) {
  memset( p, 0, sizeof(insert_params_t) );

  /* Derive executable info */
  uchar const * bin    = (uchar const *)prog_ro->data + info->elf_off;
  ulong         bin_sz = info->elf_sz;

  /* Pre-flight checks, determine required buffer size */

  fd_features_t const * features = env->features;
  fd_prog_versions_t versions = fd_prog_versions( features, env->feature_slot );
  fd_sbpf_elf_info_t elf_info = {0};
  fd_sbpf_loader_config_t config = {
    .sbpf_min_version = versions.min_sbpf_version,
    .sbpf_max_version = versions.max_sbpf_version,
  };
  int peek_err = fd_sbpf_elf_peek( &elf_info, bin, bin_sz, &config );

  *p = (insert_params_t) {
    .prog_addr    = *prog_addr,
    .feature_slot = env->feature_slot,
    .deploy_slot  = info->deploy_slot,
    .features     = features,
    .bin          = !peek_err ? bin    : NULL,
    .bin_sz       = !peek_err ? bin_sz : 0UL,
    .peek_err     = peek_err,
    .elf_info     = elf_info,
    .config       = config
  };
  return p;
}

/* fd_progcache_spill_acquire takes the next spill frame: an unloaded record with
   its spad slot reserved.  Requires the spill write lock. */

static fd_progcache_rec_t * /* read locked */
fd_progcache_spill_acquire( fd_progcache_t *        cache,
                            insert_params_t const * params ) {
  fd_progcache_join_t *  join  = cache->join;
  fd_progcache_shmem_t * shmem = join->shmem;
  FD_TEST( FD_VOLATILE_CONST( shmem->spill.lock.value )==FD_RWLOCK_WRITE_LOCK );
  /* Allocate record */

  if( FD_UNLIKELY( shmem->spill.rec_used >= FD_MAX_INSTRUCTION_STACK_DEPTH ) ) {
    FD_LOG_CRIT(( "spill buffer overflow: rec_used=%u rec_max=%lu", shmem->spill.rec_used, FD_MAX_INSTRUCTION_STACK_DEPTH ));
  }
  cache->spill_active++;
  uint rec_idx = shmem->spill.rec_used++;
  shmem->spill.spad_off[ rec_idx ] = shmem->spill.spad_used;
  fd_progcache_rec_t * rec = &shmem->spill.rec[ rec_idx ];
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->lock.value    = 1; /* read lock; no concurrency, don't need CAS */
  rec->exists        = 1;
  rec->feature_slot  = params->feature_slot;
  rec->deploy_slot   = params->deploy_slot;
  rec->calldests_off = UINT_MAX; /* non-executable until a load says otherwise */

  if( params->peek_err==FD_SBPF_ELF_SUCCESS ) {
    ulong off0 = fd_ulong_align_up( shmem->spill.spad_used, fd_progcache_val_align() );
    ulong off1 = off0 + fd_progcache_val_footprint( &params->elf_info );
    if( FD_UNLIKELY( off1 > FD_PROGCACHE_SPAD_MAX ) ) {
      FD_LOG_CRIT(( "spill buffer overflow: spad_used=%u val_sz=%lu spad_max=%lu", shmem->spill.spad_used, off1-off0, FD_PROGCACHE_SPAD_MAX ));
    }
    rec->data_gaddr        = fd_wksp_gaddr_fast( join->data_base, shmem->spill.spad + off0 );
    rec->data_max          = (uint)( off1 - off0 );
    shmem->spill.spad_used = (uint)off1;
  }

  return rec;
}

static fd_progcache_rec_t * /* read locked */
fd_progcache_insert( fd_progcache_t *        cache,
                     insert_params_t const * params ) {
  fd_progcache_join_t *  ljoin = cache->join;
  fd_progcache_shmem_t * shmem = ljoin->shmem;

  ulong val_footprint = ( params->peek_err==FD_SBPF_ELF_SUCCESS ) ? fd_progcache_val_footprint( &params->elf_info ) : 0UL;
  ulong size_class = fd_progcache_cache_class( val_footprint );

  fd_progcache_rec_t * rec        = NULL;
  int                  from_spill = 0;

  if( FD_UNLIKELY( cache->spill_active ) ) {
    rec        = fd_progcache_spill_acquire( cache, params );
    from_spill = 1;
  } else {
    /* first acquire attempt (outside loop to increase metrics) */
    rec = fd_progcache_rec_acquire( ljoin, val_footprint );
    if( FD_UNLIKELY( !rec ) ) cache->metrics->class_full_cnt++;
  }

  /* spin loop: evict, try spill, acquire (in case another thread freed a slot) */
  while( !rec ) {
    rec = fd_prog_evict( cache, val_footprint );
    if( FD_LIKELY( rec ) ) break;

    if( fd_rwlock_trywrite( &shmem->spill.lock ) ) {
      rec = fd_progcache_spill_acquire( cache, params );
      from_spill = 1;
      break;
    }

    FD_SPIN_PAUSE();
    rec = fd_progcache_rec_acquire( ljoin, val_footprint );
  }

  /* Claim the key before loading it.  A peer that wants this program finds the
     record LOADING and waits, so only one tile runs fd_sbpf_program_load for a
     given revision.  A spill record is never published. */

  rec->feature_slot = params->feature_slot;
  rec->deploy_slot  = params->deploy_slot;

  if( FD_LIKELY( !from_spill ) ) {
    /* Under the loading sentinel: not LIVE, so the sweep steps over it, and once
       push makes it findable a peer waits rather than loading it again. */
    fd_prog_state_load_begin( ljoin->rec.ele, (ulong)( rec - ljoin->rec.ele ) );

    fd_racesan_hook( "prog_insert:pre_push" );
    fd_rwlock_read( &shmem->txn.rwlock );
    ulong txn_idx = cache->lineage->tip_txn_idx;
    if( FD_UNLIKELY( txn_idx==ULONG_MAX ) ) FD_LOG_CRIT(( "progcache insert requires a non-root transaction" ));
    /* tip_txn_idx may be stale, so revalidate it against the map under the read
       lock.  A mismatch means execution was dispatched on a dead fork. */
    uint live_idx = (uint)fd_prog_txnm_idx_query_const( ljoin->txn.map, &cache->lineage->fork[ 0 ], UINT_MAX, ljoin->txn.pool );
    if( FD_UNLIKELY( (ulong)live_idx!=txn_idx ) )
      FD_LOG_CRIT(( "progcache insert on a published/canceled fork (fork_id=%lu txn_idx=%lu live_idx=%u)",
                    (ulong)cache->lineage->fork[ 0 ], txn_idx, live_idx ));
    fd_progcache_txn_t * txn = &ljoin->txn.pool[ txn_idx ];
    fd_rwlock_write( &txn->lock );
    fd_progcache_rec_t * mapped = fd_progcache_push( ljoin, txn, rec, &params->prog_addr );
    fd_rwlock_unwrite( &txn->lock );
    fd_rwlock_unread( &shmem->txn.rwlock );

    /* fd_progcache_push inserts the rec except 2 failure cases:
       1. mapped==NULL - this is impossible today because of delayed visibility,
          therefore the current impl simply spills.
          note that if we ever remove delayed visibility, a tx invoking an upgraded
          program in the same slot will always spill, which is not ideal (but also not
          incorrect). the fix/improvement is to tell progcache that a program is
          upgraded and delete the old version (so that the new version can be cached)
       2. mapped!=rec - another thread insert the same rec in parallel, in
          which case we need to wait it to finish loading. */
    if( FD_UNLIKELY( !mapped ) ) {
      /* Same key, different program revision (see fd_progcache_push).
         This can never happen so, for simplicity, just spill. */
      fd_progcache_rec_abandon( ljoin, rec );
      for( ;; ) {
        if( fd_rwlock_trywrite( &shmem->spill.lock ) ) {
          rec = fd_progcache_spill_acquire( cache, params );
          from_spill = 1;
          break;
        }
        FD_SPIN_PAUSE();
      }

    } else if( FD_UNLIKELY( mapped!=rec ) ) {
      /* Another thread published this revision first, and may still be loading */
      fd_progcache_rec_abandon( ljoin, rec );
      return fd_prog_wait_if_loading( cache, mapped );

    } else {
      fd_racesan_hook( "prog_insert:post_claim" );
    }
  }

  /* Load program */

  if( FD_LIKELY( params->peek_err==FD_SBPF_ELF_SUCCESS ) ) {
    cache->metrics->load_cnt++;
    long dt = -fd_tickcount();
    if( FD_UNLIKELY( !fd_progcache_rec_load( rec, ljoin->data_base, &params->elf_info, &params->config, params->feature_slot,
                                             params->features, params->bin, params->bin_sz, cache->scratch, cache->scratch_sz ) ) ) {
      /* Not a valid program (mark cache entry as non-executable) */
      fd_progcache_rec_nx( rec );
    }
    dt += fd_tickcount();
    cache->metrics->cum_load_ticks += (ulong)dt;
  } else {
    fd_progcache_rec_nx( rec );
  }

  if( FD_UNLIKELY( from_spill ) ) {
    cache->metrics->spill_cnt++;
    cache->metrics->spill_tot_sz += rec->rodata_sz;
    progcache_metric_per_class( cache->metrics->spill_per_class, size_class );

  } else {
    /* LOADING -> LIVE, releasing the program to waiters */
    fd_prog_state_touch( ljoin->rec.ele, (ulong)( rec - ljoin->rec.ele ) );

    cache->metrics->fill_cnt++;
    cache->metrics->fill_tot_sz += rec->rodata_sz;
    progcache_metric_per_class( cache->metrics->fill_per_class, size_class );
  }

  FD_TEST( rec->exists );
  return rec; /* read locked since acquire */
}

fd_progcache_rec_t * /* read locked */
fd_progcache_pull( fd_progcache_t *           cache,
                   fd_progcache_fork_id_t     fork_id,
                   fd_pubkey_t const *        prog_addr,
                   fd_prog_load_env_t const * env,
                   fd_acc_t const *           prog_ro ) {
  if( FD_UNLIKELY( !cache || !cache->join->shmem ) ) FD_LOG_CRIT(( "NULL progcache" ));
  long dt = -fd_tickcount();
  fd_progcache_load_fork( cache, fork_id );
  cache->metrics->lookup_cnt++;

  fd_prog_info_t info[1];
  if( FD_UNLIKELY( !fd_prog_info( info, prog_ro ) ) ) return NULL;

  fd_progcache_rec_t * found_rec =
      fd_progcache_query( cache, prog_addr, env->feature_slot, info->deploy_slot );
  if( FD_LIKELY( found_rec ) ) {
    cache->metrics->hit_cnt++;
    /* Mark the record as recently accessed for CLOCK replacement */
    fd_prog_state_touch( cache->join->rec.ele, (ulong)( found_rec - cache->join->rec.ele ) );
    progcache_metric_per_class( cache->metrics->hit_per_class, found_rec->size_class );
  } else {
    cache->metrics->miss_cnt++;
    insert_params_t insert[1];
    found_rec = fd_progcache_insert( cache, insert_params( insert, prog_addr, env, prog_ro, info ) );
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
    FD_TEST( spill_lock->value==FD_RWLOCK_WRITE_LOCK );
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
  }}
