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

  int lg_peer_max = fd_ulong_find_msb( fd_ulong_pow2_up( peer_max ) );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_policy_t * policy     = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),            sizeof(fd_policy_t)                         );
  void *        dedup_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_map_align(),  fd_policy_dedup_map_footprint ( dedup_max ) );
  void *        dedup_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_pool_align(), fd_policy_dedup_pool_footprint( dedup_max ) );
  void *        peers      = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_peer_map_align(),   fd_policy_peer_map_footprint( lg_peer_max ) );
  void *        peers_arr  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pubkey_t),         sizeof(fd_pubkey_t) * peer_max              );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_policy_align() ) == (ulong)shmem + footprint );

  policy->dedup.map     = fd_policy_dedup_map_new ( dedup_map,  dedup_max, seed );
  policy->dedup.pool    = fd_policy_dedup_pool_new( dedup_pool, dedup_max       );
  policy->peers.map     = fd_policy_peer_map_new  ( peers,      lg_peer_max     );
  policy->peers.arr     = peers_arr;
  policy->peers.cnt     = 0;
  policy->peers.idx     = 0;
  policy->iterf.ele_idx = ULONG_MAX;
  policy->tsreset       = 0;
  policy->nonce         = 1;

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
  policy->peers.map  = fd_policy_peer_map_join  ( policy->peers.map  );

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
  /* TODO evict by dlist */
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
    ele         = fd_policy_dedup_pool_ele_acquire( dedup->pool );
    ele->key    = key;
    ele->req_ts = 0;
    fd_policy_dedup_map_ele_insert( dedup->map, ele, dedup->pool );
  }
  long now = fd_log_wallclock();
  if( FD_LIKELY( now < ele->req_ts + (long)80e6 ) ) {
    return 1;
  }
  ele->req_ts = now;
  return 0;
}

static ulong ts_ms( void ) {
  return (ulong)fd_log_wallclock() / (ulong)1e6;
}

fd_repair_msg_t const *
fd_policy_next( fd_policy_t * policy, fd_forest_t * forest, fd_repair_t * repair, fd_repair_msg_t * out ) {
  fd_forest_blk_t *      pool     = fd_forest_pool( forest );
  fd_forest_subtrees_t * subtrees = fd_forest_subtrees( forest );

  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( policy->peers.cnt == 0    ) ) return NULL;

  ulong now = ts_ms();

  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
        !fd_forest_subtrees_iter_done( iter, subtrees, pool );
        iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_blk_t * orphan = fd_forest_subtrees_iter_ele( iter, subtrees, pool );
    ulong key                = fd_policy_dedup_key( FD_REPAIR_KIND_ORPHAN, orphan->slot, UINT_MAX );
    if( FD_UNLIKELY( !dedup_next( policy, key ) ) ) {
      out = fd_repair_orphan( repair, &policy->peers.arr[ policy->peers.idx ], now, policy->nonce, orphan->slot, out );
      policy->peers.idx = (policy->peers.idx + 1) % policy->peers.cnt;
      policy->nonce++;
      return out;
    }
  }

  /* Every so often we'll need to reset the frontier iterator to the
     head of frontier, because we could end up traversing down a very
     long tree if we are far behind. */

  if( FD_UNLIKELY( now - policy->tsreset > 100UL /* ms */ ) ) {
    fd_policy_reset( policy, forest );
  }

  /* We are at the head of the turbine, so we should give turbine the
     chance to complete the shreds. !ele handles an edgecase where all
     frontier are fully complete and the iter is done. Note: Agave waits
     around 200ms before eager repair. */

  // fd_forest_blk_t * ele = fd_forest_pool_ele( pool, ctx->repair_iter.ele_idx );
  // if( FD_LIKELY( !ele || ( ele->slot==ctx->turbine_slot && (now-ctx->tsreset)<(long)30e6 ) ) ) return;

  fd_forest_blk_t * ele = fd_forest_pool_ele( pool, policy->iterf.ele_idx );
  if( FD_UNLIKELY( !ele ) ) return NULL;


  int req_made = 0;
  while( !req_made ) {  // TODO: not sure if we should be forcing a req by looping, but this is equiv to original tile loop. Test both
    ele = fd_forest_pool_ele( pool, policy->iterf.ele_idx );

    if( FD_UNLIKELY( policy->iterf.shred_idx == UINT_MAX ) ) {
      ulong key = fd_policy_dedup_key( FD_REPAIR_KIND_HIGHEST_SHRED, ele->slot, 0 );
      if( FD_UNLIKELY( !dedup_next( policy, key ) ) ) {
        out = fd_repair_highest_shred( repair, &policy->peers.arr[ policy->peers.idx ], now, policy->nonce, ele->slot, 0, out );
        policy->peers.idx = (policy->peers.idx + 1) % policy->peers.cnt;
        policy->nonce++;
        req_made = 1;
      }
    }

    ulong key = fd_policy_dedup_key( FD_REPAIR_KIND_SHRED, ele->slot, policy->iterf.shred_idx );
    if( FD_UNLIKELY( !dedup_next( policy, key ) ) ) {
      out = fd_repair_shred( repair, &policy->peers.arr[ policy->peers.idx ], now, policy->nonce, ele->slot, policy->iterf.shred_idx, out );
      policy->peers.idx = (policy->peers.idx + 1) % policy->peers.cnt;
      policy->nonce++;
      if( FD_UNLIKELY( ele->first_req_ts == 0 ) ) ele->first_req_ts = fd_tickcount();
      req_made = 1;
    }

    /* Even if we have a request ready, we need to advance the iterator.
       Otherwise on the next call of policy_next, we'll try to re-request the
       same shred and it will get deduped. */

    policy->iterf = fd_forest_iter_next( policy->iterf, forest );
    if( FD_UNLIKELY( fd_forest_iter_done( policy->iterf, forest ) ) ) {
      policy->iterf = fd_forest_iter_init( forest );
      break;
    }
  }

  if( FD_UNLIKELY( !req_made ) ) return NULL;
  return out;
}

fd_policy_peer_t const *
fd_policy_add_peer( fd_policy_t * policy, fd_pubkey_t const * key, fd_ip4_port_t const * addr ) {
  fd_policy_peer_t * peer_map = policy->peers.map;
  fd_policy_peer_t * peer = fd_policy_peer_map_query( peer_map, *key, NULL );
  if( FD_UNLIKELY( !peer && fd_policy_peer_map_key_cnt( peer_map ) < fd_policy_peer_map_key_max( peer_map ) ) ) {
    peer = fd_policy_peer_map_insert( policy->peers.map, *key );
    peer->key  = *key;
    peer->ip4  = addr->addr;
    peer->port = addr->port;
    peer->req_cnt       = 0;
    peer->res_cnt       = 0;
    peer->first_req_ts  = 0;
    peer->last_req_ts   = 0;
    peer->first_resp_ts = 0;
    peer->last_resp_ts  = 0;
    peer->total_lat     = 0;
    peer->stake         = 0;

    policy->peers.arr[ policy->peers.cnt ] = *key;
    FD_COMPILER_MFENCE(); /* repair tool does non-blocking concurrent reads of the peer list */
    policy->peers.cnt++;
    return peer;
  }
  return NULL;
}

fd_policy_peer_t *
fd_policy_peer_query( fd_policy_t * policy, fd_pubkey_t const * key ) {
  return fd_policy_peer_map_query( policy->peers.map, *key, NULL );
}

void
fd_policy_peer_request_update( fd_policy_t * policy, fd_pubkey_t const * to ) {
  fd_policy_peer_t * active = fd_policy_peer_query( policy, to );
  if( FD_LIKELY( active ) ) {
    active->req_cnt++;
    active->last_req_ts = fd_tickcount();
    if( FD_UNLIKELY( active->first_req_ts == 0 ) ) active->first_req_ts = active->last_req_ts;
  }
}

void
fd_policy_peer_response_update( fd_policy_t * policy, fd_pubkey_t const * to, long rtt ) {
  fd_policy_peer_t * peer = fd_policy_peer_query( policy, to );
  if( FD_LIKELY( peer ) ) {
    long now = fd_tickcount();
    peer->res_cnt++;
    if( FD_UNLIKELY( peer->first_resp_ts == 0 ) ) peer->first_resp_ts = now;
    peer->last_resp_ts = now;
    peer->total_lat   += rtt;
  }
}

void
fd_policy_reset( fd_policy_t * policy, fd_forest_t * forest ) {
  policy->iterf   = fd_forest_iter_init( forest );
  policy->tsreset = ts_ms();
}

