#include "fd_policy.h"
#include "../../disco/metrics/fd_metrics.h"

#define NONCE_NULL        (UINT_MAX)
#define DEFER_REPAIR_MS   (200UL)
#define TARGET_TICK_PER_SLOT (64.0)
#define MS_PER_TICK          (400.0 / TARGET_TICK_PER_SLOT)

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
  fd_policy_t * policy      = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),            sizeof(fd_policy_t)                           );
  void *        dedup_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_map_align(),  fd_policy_dedup_map_footprint ( dedup_max   ) );
  void *        dedup_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_pool_align(), fd_policy_dedup_pool_footprint( dedup_max   ) );
  void *        dedup_lru   = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_dedup_lru_align(),  fd_policy_dedup_lru_footprint (             ) );
  void *        peers       = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_peer_map_align(),   fd_policy_peer_map_footprint  ( lg_peer_max ) );
  void *        peers_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_peer_pool_align(),         fd_peer_pool_footprint        ( peer_max    ) );
  void *        peers_dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_peer_dlist_align(),        fd_peer_dlist_footprint       (             ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_policy_align() ) == (ulong)shmem + footprint );

  policy->dedup.map     = fd_policy_dedup_map_new ( dedup_map,  dedup_max, seed );
  policy->dedup.pool    = fd_policy_dedup_pool_new( dedup_pool, dedup_max       );
  policy->dedup.lru     = fd_policy_dedup_lru_new ( dedup_lru                   );
  policy->peers.map     = fd_policy_peer_map_new  ( peers,      lg_peer_max     );
  policy->peers.pool    = fd_peer_pool_new        ( peers_pool, peer_max        );
  policy->peers.dlist   = fd_peer_dlist_new       ( peers_dlist                 );
  policy->iterf.ele_idx = ULONG_MAX;
  policy->turbine_slot0 = ULONG_MAX;
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

  policy->dedup.map   = fd_policy_dedup_map_join ( policy->dedup.map   );
  policy->dedup.pool  = fd_policy_dedup_pool_join( policy->dedup.pool  );
  policy->dedup.lru   = fd_policy_dedup_lru_join ( policy->dedup.lru   );
  policy->peers.map   = fd_policy_peer_map_join  ( policy->peers.map   );
  policy->peers.pool  = fd_peer_pool_join        ( policy->peers.pool  );
  policy->peers.dlist = fd_peer_dlist_join       ( policy->peers.dlist );
  policy->peers.iter  = fd_peer_dlist_iter_fwd_init( policy->peers.dlist, policy->peers.pool );

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
  fd_policy_dedup_ele_t * ele = fd_policy_dedup_lru_ele_pop_head( policy->dedup.lru, policy->dedup.pool );
  fd_policy_dedup_map_ele_remove( policy->dedup.map, &ele->key, NULL, policy->dedup.pool );
  fd_policy_dedup_pool_ele_release( policy->dedup.pool, ele );
}

/* dedup_next returns 1 if key is deduped, 0 otherwise. */
static int
dedup_next( fd_policy_t * policy, ulong key, long now ) {
  fd_policy_dedup_t *     dedup = &policy->dedup;
  fd_policy_dedup_ele_t * ele   = fd_policy_dedup_map_ele_query( dedup->map, &key, NULL, dedup->pool );
  if( FD_UNLIKELY( !ele ) ) {
    if( FD_UNLIKELY( !fd_policy_dedup_pool_free( dedup->pool ) ) ) dedup_evict( policy );
    ele         = fd_policy_dedup_pool_ele_acquire( dedup->pool );
    ele->key    = key;
    ele->req_ts = 0;
    fd_policy_dedup_map_ele_insert   ( dedup->map, ele, dedup->pool );
    fd_policy_dedup_lru_ele_push_tail( dedup->lru, ele, dedup->pool );
  }
  if( FD_LIKELY( now < ele->req_ts + (long)80e6 ) ) {
    return 1;
  }
  ele->req_ts = now;
  return 0;
}

static ulong ts_ms( long wallclock ) {
  return (ulong)wallclock / (ulong)1e6;
}

static int
passes_throttle_threshold( fd_policy_t * policy, fd_forest_blk_t * ele ) {
  if( FD_UNLIKELY( ele->slot < policy->turbine_slot0 ) ) return 1;
  /* Essentially is checking if current duration of block ( from the
     first shred received until now ) is greater than the highest tick
     received + 200ms. */
  double current_duration = (double)(fd_tickcount() - ele->first_shred_ts) / fd_tempo_tick_per_ns(NULL);
  double tick_plus_buffer = (ele->est_buffered_tick_recv * MS_PER_TICK + DEFER_REPAIR_MS) * 1e6; // change to 400e6 for a slot duration policy

  if( current_duration >= tick_plus_buffer ){
    FD_MCNT_INC( REPAIR, EAGER_REPAIR_AGGRESSES, 1 );
    return 1;
  }
  return 0;
}

fd_pubkey_t const *
fd_policy_peer_select( fd_policy_t * policy ) {
  fd_peer_dlist_t * dlist = policy->peers.dlist;
  fd_peer_t       * pool  = policy->peers.pool;
  if( FD_UNLIKELY( fd_peer_dlist_iter_done( policy->peers.iter, dlist, pool ) ) ) {
    policy->peers.iter = fd_peer_dlist_iter_fwd_init( dlist, pool );
  }
  fd_peer_t * select = fd_peer_dlist_iter_ele( policy->peers.iter, dlist, pool );
  policy->peers.iter = fd_peer_dlist_iter_fwd_next( policy->peers.iter, dlist, pool );
  return &select->identity;
}

fd_repair_msg_t const *
fd_policy_next( fd_policy_t * policy, fd_forest_t * forest, fd_repair_t * repair, long now, ulong highest_known_slot ) {
  fd_forest_blk_t *      pool     = fd_forest_pool( forest );
  fd_forest_subtrees_t * subtrees = fd_forest_subtrees( forest );

  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( fd_peer_pool_used( policy->peers.pool ) == 0 ) ) return NULL;

  fd_repair_msg_t * out = NULL;
  ulong now_ms = ts_ms( now );

  if( FD_UNLIKELY( forest->subtree_cnt > 0 ) ) {
    for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
          !fd_forest_subtrees_iter_done( iter, subtrees, pool );
          iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
      fd_forest_blk_t * orphan = fd_forest_subtrees_iter_ele( iter, subtrees, pool );
      ulong key                = fd_policy_dedup_key( FD_REPAIR_KIND_ORPHAN, orphan->slot, UINT_MAX );
      if( FD_UNLIKELY( !dedup_next( policy, key, now ) ) ) {
        out = fd_repair_orphan( repair, fd_policy_peer_select( policy ), now_ms, policy->nonce, orphan->slot );
        policy->nonce++;
        return out;
      }
    }
  }

  /* Every so often we'll need to reset the frontier iterator to the
     head of frontier, because we could end up traversing down a very
     long tree if we are far behind. */

  if( FD_UNLIKELY( now_ms - policy->tsreset > 100UL /* ms */ ||
                   policy->iterf.frontier_ver != fd_fseq_query( fd_forest_ver_const( forest ) ) ) ) {
    fd_policy_reset( policy, forest );
  }

  fd_forest_blk_t * ele = fd_forest_pool_ele( pool, policy->iterf.ele_idx );
  if( FD_UNLIKELY( !ele ) ) {
    // This happens when we are fully caught up i.e. we have all the shreds of every slot we know about.
    return NULL;
  }

  /* When we are at the head of the turbine, we should give turbine the
     chance to complete the shreds.  Agave waits 200ms from the
     estimated "correct time" of the highest shred received to repair.
     i.e. if we've received the first 200 shreds, the 200th has a tick
     of x. Translate that to millis, and we should wait to request shred
     201 until x + 200ms.  If we have a hole, i.e. first 200 shreds
     receive except shred 100, and the 101th shred has a tick of y, we
     should wait until y + 200ms to request shred 100.

     At the start of the loop, the policy iterf is valid and requestable.
     At the end of the loop, the policy iterf has been advanced to the
     next valid requestable element. */

  int req_made = 0;
  while( !req_made ) {
    ele = fd_forest_pool_ele( pool, policy->iterf.ele_idx );

    if( FD_UNLIKELY( !passes_throttle_threshold( policy, ele ) ) ) {
      /* We are not ready to repair this slot yet.  But it's possible we
         have another fork that we need to repair... so we just
         should skip to the next SLOT in the consumed iterator.  The
         likelihood that this ele is the head of turbine is high, which
         means that the shred_idx of the iterf is likely to be UINT_MAX,
         which means calling fd_forest_iter_next will advance the iterf
         to the next slot. */
      policy->iterf.shred_idx = UINT_MAX; // heinous... i'm sorry
      policy->iterf = fd_forest_iter_next( policy->iterf, forest );
      if( FD_UNLIKELY( fd_forest_iter_done( policy->iterf, forest ) ) ) {
         policy->iterf = fd_forest_iter_init( forest );
         break;
      }
      continue;
    }

    if( FD_UNLIKELY( policy->iterf.shred_idx == UINT_MAX ) ) {
      ulong key = fd_policy_dedup_key( FD_REPAIR_KIND_HIGHEST_SHRED, ele->slot, 0 );
      if( FD_UNLIKELY( ele->slot < highest_known_slot && !dedup_next( policy, key, now ) ) ) {
        // We'll never know the the highest shred for the current turbine slot, so there's no point in requesting it.
        out = fd_repair_highest_shred( repair, fd_policy_peer_select( policy ), now_ms, policy->nonce, ele->slot, 0 );
        policy->nonce++;
        req_made = 1;
      }
    } else {
      ulong key = fd_policy_dedup_key( FD_REPAIR_KIND_SHRED, ele->slot, policy->iterf.shred_idx );
      if( FD_UNLIKELY( !dedup_next( policy, key, now ) ) ) {
        out = fd_repair_shred( repair, fd_policy_peer_select( policy ), now_ms, policy->nonce, ele->slot, policy->iterf.shred_idx );
        policy->nonce++;
        if( FD_UNLIKELY( ele->first_req_ts == 0 ) ) ele->first_req_ts = fd_tickcount();
        req_made = 1;
      }
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
fd_policy_peer_insert( fd_policy_t * policy, fd_pubkey_t const * key, fd_ip4_port_t const * addr ) {
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

    fd_peer_t * peer_ele = fd_peer_pool_ele_acquire( policy->peers.pool );
    peer->pool_idx = fd_peer_pool_idx( policy->peers.pool, peer_ele );
    peer_ele->identity = *key;
    fd_peer_dlist_ele_push_tail( policy->peers.dlist, peer_ele, policy->peers.pool );
    return peer;
  }
  return NULL;
}

fd_policy_peer_t *
fd_policy_peer_query( fd_policy_t * policy, fd_pubkey_t const * key ) {
  return fd_policy_peer_map_query( policy->peers.map, *key, NULL );
}

int
fd_policy_peer_remove( fd_policy_t * policy, fd_pubkey_t const * key ) {
  fd_policy_peer_t * peer = fd_policy_peer_map_query( policy->peers.map, *key, NULL );
  if( FD_UNLIKELY( !peer ) ) return 0;
  fd_peer_t * peer_ele = fd_peer_pool_ele( policy->peers.pool, peer->pool_idx );
  fd_policy_peer_map_remove( policy->peers.map, peer );

  if( FD_UNLIKELY( policy->peers.iter == fd_peer_pool_idx( policy->peers.pool, peer_ele ) ) ) {
    /* In general removal during iteration is safe, except when the iterator is on the peer to be removed. */
    policy->peers.iter = fd_peer_dlist_iter_fwd_next( policy->peers.iter, policy->peers.dlist, policy->peers.pool );
  }
  fd_peer_dlist_ele_remove( policy->peers.dlist, peer_ele, policy->peers.pool );
  fd_peer_pool_ele_release( policy->peers.pool, peer_ele );
  return 1;
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
  policy->tsreset = ts_ms( fd_log_wallclock() );
}

void
fd_policy_set_turbine_slot0( fd_policy_t * policy, ulong slot ) {
  policy->turbine_slot0 = slot;
}

