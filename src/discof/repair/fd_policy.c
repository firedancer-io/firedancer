#include "fd_policy.h"
#include "../../disco/metrics/fd_metrics.h"

#define NONCE_NULL        (UINT_MAX)
#define DEFER_REPAIR_MS   (150UL)

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

/* throttle_remaining_ns returns how long (ns) until the candidate
   missing shred cand_idx of ele passes the eager repair threshold, 0 if
   it already passes.  A missing shred becomes eligible DEFER_REPAIR_MS
   after turbine was first observed reaching its FEC set (see
   fd_forest_blk_recv_ms).

   If the set has not been observed, we wait DEFER_REPAIR_MS from the
   last set turbine delivered before it; if no set has been observed the
   window runs from first_shred_ts. */

static long
throttle_remaining_ns( fd_policy_t * policy, fd_forest_t const * forest, fd_forest_blk_t const * ele, uint cand_idx ) {
  if( FD_UNLIKELY( ele->slot < policy->turbine_slot0 ) ) return 0L;
  if( FD_UNLIKELY( !ele->first_shred_ts ) ) return 0L; /* nothing observed yet, nothing to defer against */

  fd_forest_recv_t const * recv = fd_forest_blk_recv( forest, ele );
  uint fec_idx = (uint)fd_ulong_min( cand_idx/FD_FEC_SHRED_CNT, forest->shred_max/FD_FEC_SHRED_CNT-1UL );
  ushort ms = 0;

  for(;;) {
    ms = recv[ fec_idx ].first;
    if( FD_LIKELY( ms || !fec_idx ) ) break;
    fec_idx--;
  }

  double first_ms   = (double)ms; /* time since first_shred_ts */
  double elapsed_ms = (double)(fd_tickcount() - ele->first_shred_ts) / fd_tempo_tick_per_ns( NULL ) * 1e-6;
  double deadline   = first_ms + (double)DEFER_REPAIR_MS;
  if( elapsed_ms >= deadline ) {
    FD_MCNT_INC( REPAIR, EAGER_THRESHOLD_EXCEEDED, 1 );
    return 0L;
  }
  return (long)( (deadline - elapsed_ms) * 1e6 );
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
  fd_forest_blk_t * pool = fd_forest_pool( forest );
  *charge_busy = 0;

  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( fd_policy_peer_pool_used( policy->peers.pool ) == 0 ) ) return NULL;

  fd_repair_msg_t * out = NULL;
  ulong now_ms = ts_ms( now );

  fd_forest_orphan_ent_t * orphanq = fd_forest_orphanq( forest );
  ulong budget = 64UL;
  while( budget-- && fd_forest_orphanq_cnt( orphanq ) && orphanq[ 0 ].due<=now ) {
    *charge_busy = 1;
    fd_forest_orphan_ent_t ent = orphanq[ 0 ];
    fd_forest_orphanq_remove_min( orphanq );
    fd_forest_blk_t * orphan = fd_forest_subtrees_ele_query( fd_forest_subtrees( forest ), &ent.slot, NULL, pool );
    if( FD_UNLIKELY( !orphan || orphan->orphan_seq!=ent.seq ) ) continue;
    ulong key     = fd_reqlim_key( FD_REPAIR_KIND_ORPHAN, ent.slot, UINT_MAX );
    int   deduped = fd_reqlim_next( dedup, key, now );
    ulong seq = forest->orphan_seq_next++;
    orphan->orphan_seq = seq;
    fd_forest_orphan_ent_t nxt = { .due = fd_reqlim_next_due( dedup, key, now ), .slot = ent.slot, .seq = seq };
    fd_forest_orphanq_insert( orphanq, &nxt );
    if( FD_LIKELY( !deduped ) ) {
      uint nonce = fd_rnonce_ss_compute( policy->rnonce_ss, 0, ent.slot, 0U, now );
      out = fd_repair_orphan( repair, fd_policy_peer_select( policy ), now_ms, nonce, ent.slot );
      orphan->req_orphan_cnt++;
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

  /* The next request this call would produce.  If it was recently
     declined and nothing about it changed, skip the turn.  A throttle
     memo applies to any slot (see fd_policy_skip_t for why memos are
     per slot).  A dedup memo is only written for, and only applies to,
     the head slot: once highest_known_slot moves on, the same candidate
     maps to a highest-shred probe under a different reqlim key, so the
     memo would be stale.  Older slots with both their probe and tail
     request rate limited are simply re-evaluated each turn. */
  uint cand_idx = iter->shred_idx==UINT_MAX ? ele->buffered_idx+1U : iter->shred_idx;
  fd_policy_skip_t * skip = fd_policy_skip( policy, ele->slot );
  if( FD_UNLIKELY( ( skip->throttled || ( iter->shred_idx==UINT_MAX && ele->slot==highest_known_slot ) ) &&
                   skip->slot==ele->slot &&
                   skip->idx==cand_idx &&
                   now<skip->until ) ) {
    iter->shred_idx = UINT_MAX;
    return NULL;
  }

  long throttle_ns = throttle_remaining_ns( policy, forest, ele, cand_idx );
  if( FD_UNLIKELY( throttle_ns ) ) {
    /* When we are at the head of the turbine, we should give turbine the
       chance to complete the shreds.

       Here we did not pass the timeout threshold, so we are not ready
       to repair this slot yet.  But it's possible we have another slot
       (an older one still within its window, or another fork) that we
       need to repair... so we just should skip to the next SLOT in the
       main tree iterator.  Setting shred_idx to UINT_MAX makes the next
       fd_forest_iter_next advance the iter to the next slot (and
       re-queue this one at the tail while it is incomplete). */
    iter->shred_idx = UINT_MAX;

    /* Cap at 1ms: the deadline is derived from tick estimates that can
       move as more shreds land without changing the candidate. */
    skip->until     = now + fd_long_min( throttle_ns, (long)1e6 );
    skip->slot      = ele->slot;
    skip->idx       = cand_idx;
    skip->throttled = 1;
    return NULL;
  }

  *charge_busy = 1;

  if( FD_UNLIKELY( iter->shred_idx == UINT_MAX ) ) {
    /* No known interior missing shred: the next missing shred is the
       tail (cand_idx = buffered_idx+1) and the block's end is unknown.
       For a slot turbine has moved past, first probe the highest shred
       a peer holds. Only if that probe is still inside its reqlim rate
       window from an earlier turn, or this is the head turbine slot
       whose end no peer knows yet, ask for the tail shred directly
       instead */
    ulong highest_key = fd_reqlim_key( FD_REPAIR_KIND_HIGHEST_SHRED, ele->slot, UINT_MAX );
    if( FD_UNLIKELY( ele->slot < highest_known_slot && !fd_reqlim_next( dedup, highest_key, now ) ) ) {
      uint nonce = fd_rnonce_ss_compute( policy->rnonce_ss, 0, ele->slot, 0U, now );
      out = fd_repair_highest_shred( repair, fd_policy_peer_select( policy ), now_ms, nonce, ele->slot, 0 );
      ele->req_highest_cnt++;
    } else if( FD_LIKELY( (ulong)cand_idx < forest->shred_max ) ) {
      ulong key = fd_reqlim_key( FD_REPAIR_KIND_SHRED, ele->slot, cand_idx );
      if( FD_UNLIKELY( fd_reqlim_query( dedup, key, now ) ) ) {
        // TODO should this be gated on ele->slot == highest_known_slot?
        skip->slot      = ele->slot;
        skip->idx       = cand_idx;
        skip->throttled = 0;
        skip->until     = fd_reqlim_next_due( dedup, key, now );
        *charge_busy = 0;
        return NULL;
      }
      uint nonce = fd_rnonce_ss_compute( policy->rnonce_ss, 1, ele->slot, cand_idx, now );
      out = fd_repair_shred( repair, fd_policy_peer_select( policy ), now_ms, nonce, ele->slot, cand_idx );
    }
  } else {
    /* Regular repair requests are not deduped here.  The repair tile
       dedups them and parks a deduped one in its inflight table so it
       is retried on timeout.  Metrics increment also occurs in the tile. */
    uint nonce = fd_rnonce_ss_compute( policy->rnonce_ss, 1, ele->slot, iter->shred_idx, now );
    out = fd_repair_shred( repair, fd_policy_peer_select( policy ), now_ms, nonce, ele->slot, iter->shred_idx );
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
  if( FD_UNLIKELY( memcmp( key->key, null_pubkey.key, 32UL ) == 0 ) ) return NULL;
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

