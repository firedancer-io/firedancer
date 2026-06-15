#include "fd_policy.h"
#include "../../disco/metrics/fd_metrics.h"

#define NONCE_NULL        (UINT_MAX)
#define DEFER_REPAIR_MS   (200UL)
#define TARGET_TICK_PER_SLOT (64.0)
#define MS_PER_TICK          (400.0 / TARGET_TICK_PER_SLOT)

void *
fd_policy_new( void * shmem, ulong peer_max, ulong seed, fd_rnonce_ss_t const * rnonce_ss ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_policy_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_policy_footprint( peer_max );
  fd_memset( shmem, 0, footprint );

  ulong peer_chain_cnt = fd_policy_peer_map_chain_cnt_est( peer_max );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_policy_t * policy     = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),            sizeof(fd_policy_t)                            );
  void *        peers      = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_peer_map_align(),   fd_policy_peer_map_footprint( peer_chain_cnt ) );
  void *        peers_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_peer_pool_align(),  fd_policy_peer_pool_footprint( peer_max )      );
  void *        peers_fast = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_peer_dlist_align(), fd_policy_peer_dlist_footprint()               );
  void *        peers_slow = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_peer_dlist_align(), fd_policy_peer_dlist_footprint()               );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_policy_align() ) == (ulong)shmem + footprint );

  policy->peers.map     = fd_policy_peer_map_new  ( peers,      peer_chain_cnt, seed );
  policy->peers.pool    = fd_policy_peer_pool_new ( peers_pool, peer_max             );
  policy->peers.fast    = fd_policy_peer_dlist_new( peers_fast                       );
  policy->peers.slow    = fd_policy_peer_dlist_new( peers_slow                       );
  policy->turbine_slot0 = ULONG_MAX;
  policy->rnonce_ss[0]  = *rnonce_ss;

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

  policy->peers.map  = fd_policy_peer_map_join  ( policy->peers.map  );
  policy->peers.pool = fd_policy_peer_pool_join ( policy->peers.pool );
  policy->peers.fast = fd_policy_peer_dlist_join( policy->peers.fast );
  policy->peers.slow = fd_policy_peer_dlist_join( policy->peers.slow );

  policy->peers.select.fast_iter = fd_policy_peer_dlist_iter_fwd_init( policy->peers.fast, policy->peers.pool );
  policy->peers.select.slow_iter = fd_policy_peer_dlist_iter_fwd_init( policy->peers.slow, policy->peers.pool );
  policy->peers.select.cnt       = 0;

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
    FD_MCNT_INC( REPAIR, EAGER_THRESHOLD_EXCEEDED, 1 );
    return 1;
  }
  return 0;
}

static inline fd_policy_peer_dlist_iter_t
peer_iter_advance( fd_policy_peer_dlist_iter_t iter,
                   fd_policy_peer_dlist_t *    dlist,
                   fd_policy_peer_t *          pool ) {
  iter = fd_policy_peer_dlist_iter_fwd_next( iter, dlist, pool );
  if( FD_UNLIKELY( fd_policy_peer_dlist_iter_done( iter, dlist, pool ) ) ) {
    iter = fd_policy_peer_dlist_iter_fwd_init( dlist, pool );
  }
  return iter;
}

fd_pubkey_t const *
fd_policy_peer_select( fd_policy_t * policy ) {
  fd_policy_peer_dlist_t * fast = policy->peers.fast;
  fd_policy_peer_dlist_t * slow = policy->peers.slow;
  fd_policy_peer_t       * pool = policy->peers.pool;

  if( FD_UNLIKELY( fd_policy_peer_pool_used( pool ) == 0 ) ) return NULL;

  /* reinit stale iterators.  happens when peers are inserted into a
     previously-empty list after the iterator was initialized. */
  int fast_empty = fd_policy_peer_dlist_iter_done( fd_policy_peer_dlist_iter_fwd_init( fast, pool ), fast, pool );
  int slow_empty = fd_policy_peer_dlist_iter_done( fd_policy_peer_dlist_iter_fwd_init( slow, pool ), slow, pool );

  if( FD_UNLIKELY( !fast_empty && fd_policy_peer_dlist_iter_done( policy->peers.select.fast_iter, fast, pool ) ) ) {
    policy->peers.select.fast_iter = fd_policy_peer_dlist_iter_fwd_init( fast, pool );
  }
  if( FD_UNLIKELY( !slow_empty && fd_policy_peer_dlist_iter_done( policy->peers.select.slow_iter, slow, pool ) ) ) {
    policy->peers.select.slow_iter = fd_policy_peer_dlist_iter_fwd_init( slow, pool );
  }

  fd_policy_peer_t * select;

  /* select will be set to current iterator status. Then iterator should
     be advanced for the following peer_select call. */

  if( FD_UNLIKELY( fast_empty ) ) {
    select = fd_policy_peer_dlist_iter_ele( policy->peers.select.slow_iter, slow, pool );
    policy->peers.select.slow_iter = peer_iter_advance( policy->peers.select.slow_iter, slow, pool );
    return &select->key;
  }

  if( FD_UNLIKELY( slow_empty ) ) {
    select = fd_policy_peer_dlist_iter_ele( policy->peers.select.fast_iter, fast, pool );
    policy->peers.select.fast_iter = peer_iter_advance( policy->peers.select.fast_iter, fast, pool );
    return &select->key;
  }

  /* interleave FD_POLICY_FAST_PER_SLOW fast, 1 slow. */
  if( FD_LIKELY( policy->peers.select.cnt < FD_POLICY_FAST_PER_SLOW ) ) {
    select = fd_policy_peer_dlist_iter_ele( policy->peers.select.fast_iter, fast, pool );
    policy->peers.select.fast_iter = peer_iter_advance( policy->peers.select.fast_iter, fast, pool );
    policy->peers.select.cnt++;
    return &select->key;
  }

  select = fd_policy_peer_dlist_iter_ele( policy->peers.select.slow_iter, slow, pool );
  policy->peers.select.slow_iter = peer_iter_advance( policy->peers.select.slow_iter, slow, pool );
  policy->peers.select.cnt = 0;
  return &select->key;
}

fd_repair_msg_t const *
fd_policy_next( fd_policy_t * policy, fd_reqlim_t * dedup, fd_forest_t * forest, fd_repair_t * repair, long now, ulong highest_known_slot, int * charge_busy ) {
  fd_forest_blk_t *      pool     = fd_forest_pool( forest );
  fd_forest_subtlist_t * subtlist = fd_forest_subtlist( forest );
  *charge_busy = 0;

  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( fd_policy_peer_pool_used( policy->peers.pool ) == 0 ) ) return NULL;

  fd_repair_msg_t * out = NULL;
  ulong now_ms = ts_ms( now );

  for( fd_forest_subtlist_iter_t iter = fd_forest_subtlist_iter_fwd_init( subtlist, pool );
                                       !fd_forest_subtlist_iter_done    ( iter, subtlist, pool );
                                 iter = fd_forest_subtlist_iter_fwd_next( iter, subtlist, pool ) ) {
    *charge_busy = 1;
    fd_forest_blk_t * orphan = fd_forest_subtlist_iter_ele( iter, subtlist, pool );
    ulong key                = fd_reqlim_key( FD_REPAIR_KIND_ORPHAN, orphan->slot, UINT_MAX );
    if( FD_UNLIKELY( !fd_reqlim_next( dedup, key, now ) ) ) {
      uint nonce = fd_rnonce_ss_compute( policy->rnonce_ss, 0, orphan->slot, 0U, now );
      out = fd_repair_orphan( repair, fd_policy_peer_select( policy ), now_ms, nonce, orphan->slot );
      return out;
    }
  }

  /* Select a slot to operate on 🔪. Advance either the orphan iter or
     regular iter. */
  fd_forest_iter_t * iter = NULL;
  if( FD_UNLIKELY( fd_forest_reqslist_is_empty( fd_forest_reqslist( forest ), fd_forest_reqspool( forest ) ) ) ) {
    /* If the main tree has nothing to iterate at the moment, we can
       request down the ORPHAN trees on slots we know about. */
    iter = &forest->orphiter;
  } else {
    iter = &forest->iter;
  }

  fd_forest_iter_next( iter, forest );
  if( FD_UNLIKELY( fd_forest_iter_done( iter, forest ) ) ) {
    // This happens when we have already requested all the shreds we know about.
    return NULL;
  }

  fd_forest_blk_t * ele = fd_forest_pool_ele( pool, iter->ele_idx );
  if( FD_UNLIKELY( !passes_throttle_threshold( policy, ele ) ) ) {
    /* When we are at the head of the turbine, we should give turbine the
       chance to complete the shreds.  Agave waits 200ms from the
       estimated "correct time" of the highest shred received to repair.
       i.e. if we've received the first 200 shreds, the 200th has a tick
       of x. Translate that to millis, and we should wait to request shred
       201 until x + 200ms.  If we have a hole, i.e. first 200 shreds
       receive except shred 100, and the 101th shred has a tick of y, we
       should wait until y + 200ms to request shred 100.

       Here we did not pass the timeout threshold, so we are not ready
       to repair this slot yet.  But it's possible we have another fork
       that we need to repair... so we just should skip to the next SLOT
       in the main tree iterator.  The likelihood that this ele is the
       head of turbine is high, which means that the shred_idx of the
       iterf is likely to be UINT_MAX, which means calling
       fd_forest_iter_next will advance the iterf to the next slot. */
    iter->shred_idx = UINT_MAX;
    /* TODO: Heinous... but the easiest way to ensure this slot gets
       added back to the requests deque is if we set the shred_idx to
       UINT_MAX, but maybe there should be an explicit API for it. */

    return NULL;
  }

  *charge_busy = 1;

  if( FD_UNLIKELY( iter->shred_idx == UINT_MAX ) ) {
    // We'll never know the the highest shred for the current turbine slot, so there's no point in requesting it.
    if( FD_UNLIKELY( ele->slot < highest_known_slot && !fd_reqlim_next( dedup, fd_reqlim_key( FD_REPAIR_KIND_HIGHEST_SHRED, ele->slot, UINT_MAX ), now ) ) ) {
      uint nonce = fd_rnonce_ss_compute( policy->rnonce_ss, 0, ele->slot, 0U, now );
      out = fd_repair_highest_shred( repair, fd_policy_peer_select( policy ), now_ms, nonce, ele->slot, 0 );
    }
  } else {
    /* Regular repair requests are not deduped.  Any potential regular
       shred request that will be made needs to be handled at the repair
       tile level to allow repair tile to re-request the same shred if
       it gets deduped. */
    uint nonce = fd_rnonce_ss_compute( policy->rnonce_ss, 1, ele->slot, iter->shred_idx, now );
    out = fd_repair_shred( repair, fd_policy_peer_select( policy ), now_ms, nonce, ele->slot, iter->shred_idx );
    if( FD_UNLIKELY( ele->first_req_ts == 0 ) ) ele->first_req_ts = fd_tickcount();
  }
  return out;
}

fd_policy_peer_t const *
fd_policy_peer_upsert( fd_policy_t * policy, fd_pubkey_t const * key, fd_ip4_port_t const * addr ) {
  fd_policy_peer_map_t * peer_map = policy->peers.map;
  fd_policy_peer_t * pool = policy->peers.pool;
  fd_policy_peer_t * peer = fd_policy_peer_map_ele_query( peer_map, key, NULL, pool );
  if( FD_UNLIKELY( !peer && fd_policy_peer_pool_free( pool ) ) ) {
    peer = fd_policy_peer_pool_ele_acquire( pool );
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
    peer->ewma_lat      = 0;
    peer->stake         = 0;
    peer->unanswered    = 0;
    peer->ping          = 0;

    fd_policy_peer_map_ele_insert( peer_map, peer, pool );
    fd_policy_peer_dlist_ele_push_tail( policy->peers.slow, peer, pool );
    return peer;
  }
  if( FD_LIKELY( peer ) ) {
    peer->ip4  = addr->addr;
    peer->port = addr->port;
  }
  return NULL;
}

fd_policy_peer_t *
fd_policy_peer_query( fd_policy_t * policy, fd_pubkey_t const * key ) {
  if( FD_UNLIKELY( fd_pubkey_check_zero( key ) ) ) return NULL;
  fd_policy_peer_t * pool = policy->peers.pool;
  return fd_policy_peer_map_ele_query( policy->peers.map, key, NULL, pool );
}

int
fd_policy_peer_remove( fd_policy_t * policy, fd_pubkey_t const * key ) {
  fd_policy_peer_t * pool = policy->peers.pool;
  fd_policy_peer_t * peer = fd_policy_peer_map_ele_query( policy->peers.map, key, NULL, pool );
  if( FD_UNLIKELY( !peer ) ) return 0;

  ulong peer_idx = fd_policy_peer_pool_idx( pool, peer );
  fd_policy_peer_dlist_t * bucket = fd_policy_peer_latency_bucket( policy, peer->ewma_lat, peer->res_cnt );

  /* Advance iterators past the peer being removed while the dlist links
     are still intact, so iter_fwd_next can follow the forward pointer. */
  if( FD_UNLIKELY( policy->peers.select.fast_iter == peer_idx ) ) {
    policy->peers.select.fast_iter = fd_policy_peer_dlist_iter_fwd_next( policy->peers.select.fast_iter, bucket, pool );
  }
  if( FD_UNLIKELY( policy->peers.select.slow_iter == peer_idx ) ) {
    policy->peers.select.slow_iter = fd_policy_peer_dlist_iter_fwd_next( policy->peers.select.slow_iter, bucket, pool );
  }

  fd_policy_peer_dlist_ele_remove( bucket, peer, pool );
  fd_policy_peer_map_ele_remove  ( policy->peers.map, key, NULL, pool );
  fd_policy_peer_pool_ele_release( pool,   peer );
  return 1;
}

void
fd_policy_peer_request_update( fd_policy_t * policy, fd_pubkey_t const * to ) {
  fd_policy_peer_t * active = fd_policy_peer_query( policy, to );
  if( FD_LIKELY( active ) ) {
    active->req_cnt++;
    active->unanswered++;
    active->last_req_ts = fd_tickcount();
    if( FD_UNLIKELY( active->first_req_ts == 0 ) ) active->first_req_ts = active->last_req_ts;
  }
}

void
fd_policy_peer_response_update( fd_policy_t * policy, fd_pubkey_t const * to, long rtt /* ns */ ) {
  fd_policy_peer_t * peer = fd_policy_peer_query( policy, to );
  if( FD_LIKELY( peer ) ) {
    long now = fd_tickcount();
    fd_policy_peer_dlist_t * prev_bucket = fd_policy_peer_latency_bucket( policy, peer->ewma_lat, peer->res_cnt );
    peer->res_cnt++;
    peer->unanswered = 0;
    if( FD_UNLIKELY( peer->first_resp_ts == 0 ) ) peer->first_resp_ts = now;
    peer->last_resp_ts = now;
    peer->total_lat   += rtt;

    if( FD_UNLIKELY( peer->res_cnt == 1 ) ) {
      peer->ewma_lat = rtt;
    } else {
      peer->ewma_lat = peer->ewma_lat - peer->ewma_lat / (long)FD_POLICY_EWMA_ALPHA_DENOM
                      + rtt / (long)FD_POLICY_EWMA_ALPHA_DENOM;
    }
    fd_policy_peer_dlist_t * new_bucket = fd_policy_peer_latency_bucket( policy, peer->ewma_lat, peer->res_cnt );
    if( prev_bucket != new_bucket ) {
      /* Advance stale iterators */
      ulong peer_idx = fd_policy_peer_pool_idx( policy->peers.pool, peer );
      if( FD_UNLIKELY( policy->peers.select.fast_iter == peer_idx ) ) policy->peers.select.fast_iter = fd_policy_peer_dlist_iter_fwd_next( policy->peers.select.fast_iter, policy->peers.fast, policy->peers.pool );
      if( FD_UNLIKELY( policy->peers.select.slow_iter == peer_idx ) ) policy->peers.select.slow_iter = fd_policy_peer_dlist_iter_fwd_next( policy->peers.select.slow_iter, policy->peers.slow, policy->peers.pool );

      fd_policy_peer_dlist_ele_remove   ( prev_bucket, peer, policy->peers.pool );
      fd_policy_peer_dlist_ele_push_tail( new_bucket,  peer, policy->peers.pool );
    }
  }
}

void
fd_policy_set_turbine_slot0( fd_policy_t * policy, ulong slot ) {
  policy->turbine_slot0 = slot;
}

