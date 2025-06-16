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
  void *        dedup      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_policy_dedup_t),   sizeof(fd_policy_dedup_t)                   );
  void *        dedup_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_map_align(),  fd_policy_dedup_map_footprint( dedup_max )  );
  void *        dedup_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_pool_align(), fd_policy_dedup_pool_footprint( dedup_max ) );
  void *        peers      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_policy_peers_t),   sizeof(fd_policy_peers_t)                   );
  void *        peers_arr  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pubkey_t),         sizeof(fd_pubkey_t) * peer_max              );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_policy_align() ) == (ulong)shmem + footprint );

  policy->dedup       = dedup;
  policy->dedup->map  = fd_policy_dedup_map_new ( dedup_map,  dedup_max, seed );
  policy->dedup->pool = fd_policy_dedup_pool_new( dedup_pool, dedup_max       );
  policy->dedup->lru  = NULL;
  policy->peers       = peers;
  policy->peers->arr  = peers_arr;
  policy->peers->cnt  = 0;
  policy->peers->idx  = ULONG_MAX;

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

  policy->dedup->map  = fd_policy_dedup_map_join ( policy->dedup->map  );
  policy->dedup->pool = fd_policy_dedup_pool_join( policy->dedup->pool );

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
  fd_policy_dedup_t * dedup = policy->dedup;
  for( fd_policy_dedup_map_iter_t iter = fd_policy_dedup_map_iter_init( dedup->map, dedup->pool );
       !fd_policy_dedup_map_iter_done( iter, dedup->map, dedup->pool );
       iter = fd_policy_dedup_map_iter_next( iter, dedup->map, dedup->pool ) ) {
    fd_policy_dedup_ele_t * ele = fd_policy_dedup_map_iter_ele( iter, dedup->map, dedup->pool );
    fd_policy_dedup_map_ele_remove( dedup->map, &ele->key, NULL, dedup->pool );
    return;
  }
}

/* dedup_next returns 1 if key is deduped, 0 otherwise. */

static int
dedup_next( fd_policy_t * policy, ulong key ) {
  fd_policy_dedup_t *     dedup = policy->dedup;
  fd_policy_dedup_ele_t * ele   = fd_policy_dedup_map_ele_query( dedup->map, &key, NULL, dedup->pool );
  if( FD_UNLIKELY( !ele ) ) {
    if( FD_UNLIKELY( !fd_policy_dedup_pool_free( policy->dedup->pool ) ) ) dedup_evict( policy );
    ele           = fd_policy_dedup_pool_ele_acquire( dedup->pool );
    ele->key      = key;
    ele->peer_idx = ULONG_MAX;
    ele->req_ts   = 0;
    fd_policy_dedup_map_ele_insert( dedup->map, ele, dedup->pool );
  }
  long now = fd_log_wallclock();
  if( FD_LIKELY( now < ele->req_ts + (long)20e6 ) ) {
    // FD_LOG_NOTICE(( "deduped key %lu", key ));
    return 1;
  }
  ele->peer_idx = policy->peers->idx;
  ele->req_ts   = now;
  return 0;
}

fd_repair_req_t *
fd_policy_next( fd_policy_t * policy, fd_forest_t * forest, fd_repair_t * repair ) {
  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( policy->peers->cnt == 0   ) ) return NULL;

  fd_pubkey_t * peer = &policy->peers->arr[ ++policy->peers->idx % policy->peers->cnt ];

  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );

  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
        !fd_forest_orphaned_iter_done( iter, orphaned, pool );
        iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_ele_t * orphan    = fd_forest_orphaned_iter_ele( iter, orphaned, pool );
    ulong key                   = fd_policy_dedup_key( FD_REPAIR_KIND_ORPHAN_REQ, orphan->slot, UINT_MAX );
    if( FD_UNLIKELY( !dedup_next( policy, key ) ) ) return fd_repair_orphan_req( repair, peer, orphan->slot, NONCE_NULL );
  }

  // /* Every so often we'll need to reset the frontier iterator to the
  //    head of frontier, because we could end up traversing down a very
  //    long tree if we are far behind. */

  //   long now = fd_log_wallclock();
  // if( FD_UNLIKELY( policy->iterf.ele_idx == null || (now - policy->tsref) > (long)1e9 ) ) {
  if( FD_UNLIKELY( policy->iterf.ele_idx == null ) ) {
      // reset iterator to the beginning of the forest frontier
      policy->iterf = fd_forest_iter_init( forest );
      // policy->tsref = now;
  }

  if( FD_UNLIKELY( policy->iterf.ele_idx == null )) {
    --policy->peers->idx;
    return NULL; /* nothing to repair */
  }

  /* Our frontier is at the head of the turbine, so we should give
     turbine the chance to complete the shreds. !ele handles an edgecase
     where all frontier are fully complete and the iter is done */

  /* FIXME add back after forest rework */

  // fd_forest_ele_t const * ele = fd_forest_pool_ele_const( pool, ctx->repair_iter.ele_idx );
  // if( FD_LIKELY( !ele || ( ele->slot == fd_fseq_query( ctx->turbine_slot ) && ( now - ctx->tsreset ) < (long)30e6 ) ) ){
  //   return;
  // }

  fd_forest_ele_t const * ele = fd_forest_pool_ele_const( pool, policy->iterf.ele_idx );
  fd_repair_req_t *       out = NULL;
  ulong                   key = ULONG_MAX;
  if( FD_UNLIKELY( policy->iterf.shred_idx == UINT_MAX ) ) {
    out = fd_repair_highest_shred_req( repair, peer, ele->slot, 0, NONCE_NULL );
    key = fd_policy_dedup_key( FD_REPAIR_KIND_HIGHEST_SHRED_REQ, ele->slot, 0 );
  } else {
    out = fd_repair_shred_req( repair, peer, ele->slot, policy->iterf.shred_idx, NONCE_NULL );
    key = fd_policy_dedup_key( FD_REPAIR_KIND_SHRED_REQ, ele->slot, 0 );
  }
  policy->iterf = fd_forest_iter_next( policy->iterf, forest );
  if( FD_UNLIKELY( fd_forest_iter_done( policy->iterf, forest ) ) ) policy->iterf = fd_forest_iter_init( forest );
  if( FD_UNLIKELY( dedup_next( policy, key )                    ) ) {
    --policy->peers->idx;
    return NULL;
  }
  return out;
}
