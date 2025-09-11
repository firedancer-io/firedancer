#include "fd_policy.h"

#define NONCE_NULL (UINT_MAX)

void *
fd_policy_new( void * shmem, ulong dedup_max, ulong peer_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_policy_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_policy_footprint( dedup_max, peer_max );
  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_policy_t * policy     = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),            sizeof(fd_policy_t)                         );
  //void *        dedup      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_policy_dedup_t),   sizeof(fd_policy_dedup_t)                   );
  void *        dedup_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_map_align(),  fd_policy_dedup_map_footprint( dedup_max )  );
  void *        dedup_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_pool_align(), fd_policy_dedup_pool_footprint( dedup_max ) );
  //void *        peers      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_policy_peers_t),   sizeof(fd_policy_peers_t)                   );
  //void *        peers_arr  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pubkey_t),         sizeof(fd_pubkey_t) * peer_max              );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_policy_align() ) == (ulong)shmem + footprint );

  //policy->dedup       = dedup;
  policy->dedup.map  = fd_policy_dedup_map_new ( dedup_map,  dedup_max, seed );
  policy->dedup.pool = fd_policy_dedup_pool_new( dedup_pool, dedup_max       );
  //policy->dedup->lru  = NULL;
  //policy->peers       = peers;
  //policy->peers->arr  = peers_arr;
  //policy->peers->cnt  = 0;
  //policy->peers->idx  = ULONG_MAX;
  policy->iterf.ele_idx = ULONG_MAX;
  policy->tsreset = 0;

  return shmem;
}

fd_policy_t *
fd_policy_join( void * shpolicy ) {
  fd_policy_t * policy = (fd_policy_t *)shpolicy;

  if( FD_UNLIKELY( !policy ) ) {
    FD_LOG_WARNING(( "NULL policy" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)policy, fd_policy_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned policy" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( policy );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "policy must be part of a workspace" ));
    return NULL;
  }

  policy->dedup.map  = fd_policy_dedup_map_join ( policy->dedup.map  );
  policy->dedup.pool = fd_policy_dedup_pool_join( policy->dedup.pool );

  return policy;
}

void *
fd_policy_leave( fd_policy_t const * policy ) {

  if( FD_UNLIKELY( !policy ) ) {
    FD_LOG_WARNING(( "NULL policy" ));
    return NULL;
  }

  return (void *)policy;
}

void *
fd_policy_delete( void * policy ) {

  if( FD_UNLIKELY( !policy ) ) {
    FD_LOG_WARNING(( "NULL policy" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)policy, fd_policy_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned policy" ));
    return NULL;
  }

  return policy;
}

/* dedup_evict evicts the first element returned by the map iterator. */

static void
dedup_evict( fd_policy_t * policy ) {
  fd_policy_dedup_t * dedup = &policy->dedup;
  for( fd_policy_dedup_map_iter_t iter = fd_policy_dedup_map_iter_init( dedup->map, dedup->pool );
       !fd_policy_dedup_map_iter_done( iter, dedup->map, dedup->pool );
       iter = fd_policy_dedup_map_iter_next( iter, dedup->map, dedup->pool ) ) {
    fd_policy_dedup_ele_t * ele = fd_policy_dedup_map_iter_ele( iter, dedup->map, dedup->pool );
    fd_policy_dedup_map_ele_remove( dedup->map, &ele->key, NULL, dedup->pool );
    fd_policy_dedup_pool_ele_release( dedup->pool, ele );
    return;
  }
}

/* dedup_next returns 1 if key is deduped, 0 otherwise. */

static int
dedup_next( fd_policy_t * policy, ulong key ) {
  fd_policy_dedup_t *     dedup = &policy->dedup;
  fd_policy_dedup_ele_t * ele   = fd_policy_dedup_map_ele_query( dedup->map, &key, NULL, dedup->pool );
  if( FD_UNLIKELY( !ele ) ) {
    if( FD_UNLIKELY( !fd_policy_dedup_pool_free( dedup->pool ) ) ) dedup_evict( policy );
    ele           = fd_policy_dedup_pool_ele_acquire( dedup->pool );
    ele->key      = key;
    //ele->peer_idx = ULONG_MAX;
    ele->req_ts   = 0;
    fd_policy_dedup_map_ele_insert( dedup->map, ele, dedup->pool );
  }
  long now = fd_log_wallclock();
  if( FD_LIKELY( now < ele->req_ts + (long)80e6 ) ) {
    return 1;
  }
  //ele->peer_idx = policy->peers->idx;
  //policy->peers->idx++; // yes??? wrap?
  ele->req_ts   = now;
  return 0;
}

static ulong ts_ms( void ) {
  return (ulong)fd_log_wallclock() / (ulong)1e6;
}

fd_repair_msg_t const *
fd_policy_next( fd_policy_t * policy, fd_forest_t * forest /*, fd_repair_t * repair */, fd_repair_msg_t * out ) {
  fd_forest_blk_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_subtrees_t * subtrees = fd_forest_subtrees( forest );

  if( FD_UNLIKELY( forest->root == ULONG_MAX     ) ) return NULL;
  //if( FD_UNLIKELY( policy->peers->cnt == 0       ) ) return NULL;

  ulong now = ts_ms();

  //fd_policy_peer_t * peer = &policy->peers->arr[++policy->peers->idx % policy->peers->cnt];
  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
        !fd_forest_subtrees_iter_done( iter, subtrees, pool );
        iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_blk_t * orphan = fd_forest_subtrees_iter_ele( iter, subtrees, pool );
    ulong key                = fd_policy_dedup_key( FD_REPAIR_KIND_ORPHAN, orphan->slot, UINT_MAX );
    if( FD_UNLIKELY( !dedup_next( policy, key ) ) ) {
      out->kind = FD_REPAIR_KIND_ORPHAN;
      out->slot = orphan->slot;
      out->shred_idx = UINT_MAX;
      out->nonce = NONCE_NULL;
      out->ts = now;
      return out;
    }
  }

  /* TODO dble check: reset needed or not? */

  /* Every so often we'll need to reset the frontier iterator to the
     head of frontier, because we could end up traversing down a very
     long tree if we are far behind. */

  if( FD_UNLIKELY( now - policy->tsreset > 100UL /* ms */ ) ) {
    // reset iterator to the beginning of the forest frontier
    policy->iterf = fd_forest_iter_init( forest );
    policy->tsreset = now;
  }

  if( FD_UNLIKELY( policy->iterf.ele_idx == null ) ) return NULL;

  /* We are at the head of the turbine, so we should give turbine the
     chance to complete the shreds. !ele handles an edgecase where all
     frontier are fully complete and the iter is done */

  //fd_forest_blk_t * ele = fd_forest_pool_ele( pool, ctx->repair_iter.ele_idx );
  //if( FD_LIKELY( !ele || ( ele->slot==ctx->turbine_slot && (now-ctx->tsreset)<(long)30e6 ) ) ) return;

  fd_forest_blk_t const * ele = fd_forest_pool_ele_const( pool, policy->iterf.ele_idx );
  if( FD_UNLIKELY( !ele ) ) return NULL;

  for( ;; ) {  // TODO not sure if we should be forcing a req by looping, but try without a loop as well
    if( FD_UNLIKELY( policy->iterf.shred_idx == UINT_MAX ) ) {
      ulong key = fd_policy_dedup_key( FD_REPAIR_KIND_HIGHEST_SHRED, ele->slot, 0 );
      if( FD_UNLIKELY( !dedup_next( policy, key ) ) ) {
        out->kind = FD_REPAIR_KIND_HIGHEST_SHRED;
        out->slot = ele->slot;
        out->shred_idx = 0;
        out->nonce = NONCE_NULL;
        out->ts = now;
        return out;
      }
    }
    ulong key = fd_policy_dedup_key( FD_REPAIR_KIND_SHRED, ele->slot, policy->iterf.shred_idx );
    if( FD_UNLIKELY( !dedup_next( policy, key ) ) ) {
      out->kind = FD_REPAIR_KIND_SHRED;
      out->slot = ele->slot;
      out->shred_idx = policy->iterf.shred_idx;
      out->nonce = NONCE_NULL;
      out->ts = now;
      return out;
    }

    policy->iterf = fd_forest_iter_next( policy->iterf, forest );
    if( FD_UNLIKELY( fd_forest_iter_done( policy->iterf, forest ) ) ) {
      policy->iterf = fd_forest_iter_init( forest );
      return NULL;
    }
  }
  //--policy->peers->idx; return NULL; /* all candidate requests were deduped, so reset to previous peer */
}

void
fd_policy_publish( fd_policy_t * policy, fd_forest_t * forest ) {
  policy->iterf = fd_forest_iter_init( forest );
  policy->tsreset = ts_ms();
}

