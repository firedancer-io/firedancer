#include "fd_recorder.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/net/fd_net_headers.h"
#include "../../flamenco/fd_rwlock.h"
#include <stdbool.h>
#include <stdlib.h>

/* fd_recorder implementation

   IMPORTANT: All functions in this file assume that the caller has
   acquired the appropriate lock (read or write) as documented in the
   header file. This implementation does NOT acquire or release locks
   internally. View locking requirements in header file.
  */

void *
fd_recorder_new( void * shmem, ulong seed, ulong timeout_ns ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_recorder_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_recorder_footprint();
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }

  if( FD_UNLIKELY( !timeout_ns ) ) {
    FD_LOG_WARNING(( "zero timeout_ns" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_recorder_t * recorder = FD_SCRATCH_ALLOC_APPEND( l, fd_recorder_align(), sizeof( fd_recorder_t ) );
  void *        req_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_recorder_req_pool_align(),  fd_recorder_req_pool_footprint ( MAX_REQUESTS )                                       );
  void *        req_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_recorder_req_map_align(),   fd_recorder_req_map_footprint  ( fd_recorder_req_map_chain_cnt_est( MAX_REQUESTS ) )  );
  void *        req_dlist  = FD_SCRATCH_ALLOC_APPEND( l, fd_recorder_req_dlist_align(), fd_recorder_req_dlist_footprint()                                                     );
  void *        peer_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_recorder_peer_pool_align(), fd_recorder_peer_pool_footprint( FD_MAX_PEERS )                                       );
  void *        peer_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_recorder_peer_map_align(),  fd_recorder_peer_map_footprint ( fd_recorder_peer_map_chain_cnt_est( FD_MAX_PEERS ) ) );

  recorder->req_pool_gaddr  = fd_wksp_gaddr_fast( wksp, fd_recorder_req_pool_join ( fd_recorder_req_pool_new ( req_pool, MAX_REQUESTS ) )                                             );
  recorder->req_map_gaddr   = fd_wksp_gaddr_fast( wksp, fd_recorder_req_map_join  ( fd_recorder_req_map_new  ( req_map, fd_recorder_req_map_chain_cnt_est( MAX_REQUESTS ), seed ) )   );
  recorder->req_dlist_gaddr = fd_wksp_gaddr_fast( wksp, fd_recorder_req_dlist_join( fd_recorder_req_dlist_new( req_dlist ) )                                                          );
  recorder->peer_pool_gaddr = fd_wksp_gaddr_fast( wksp, fd_recorder_peer_pool_join( fd_recorder_peer_pool_new( peer_pool, FD_MAX_PEERS ) )                                            );
  recorder->peer_map_gaddr  = fd_wksp_gaddr_fast( wksp, fd_recorder_peer_map_join ( fd_recorder_peer_map_new ( peer_map, fd_recorder_peer_map_chain_cnt_est( FD_MAX_PEERS ), seed ) ) );

  recorder->recorder_gaddr = fd_wksp_gaddr_fast( wksp, recorder );
  recorder->seed                   = seed;
  recorder->timeout_ns             = timeout_ns;
  recorder->total_active_requests  = 0UL;
  recorder->total_expired_requests = 0UL;
  recorder->total_handled_requests = 0UL;
  recorder->peer_cnt               = 0UL;

  /* Initialize priority counts and indices */
  recorder->high_priority_cnt   = 0UL;
  recorder->medium_priority_cnt = 0UL;
  recorder->low_priority_cnt    = 0UL;
  recorder->zero_hr_cnt         = 0UL;

  recorder->high_priority_idx   = 0UL;
  recorder->medium_priority_idx = 0UL;
  recorder->low_priority_idx    = 0UL;
  recorder->zero_hr_idx         = 0UL;

  recorder->cycle_position = 0UL;
  recorder->cycle_count    = 0UL;

  /* Initialize the read-write lock */
  recorder->rw_lock = (fd_rwlock_t){0};

  FD_COMPILER_MFENCE();
  FD_VOLATILE( recorder->magic ) = FD_RECORDER_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_recorder_t *
fd_recorder_join( void * shrecorder ) {
  fd_recorder_t * recorder = (fd_recorder_t *)shrecorder;

  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_ERR(( "NULL recorder" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)recorder, fd_recorder_align() ) ) ) {
    FD_LOG_ERR(( "misaligned recorder" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( recorder );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_ERR(( "recorder must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( recorder->magic!=FD_RECORDER_MAGIC ) ) {
    FD_LOG_ERR(( "bad magic" ));
    return NULL;
  }

  return recorder;
}

void *
fd_recorder_leave( fd_recorder_t const * recorder ) {

  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return NULL;
  }

  return (void *)recorder;
}

void *
fd_recorder_delete( void * recorder ) {

  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_ERR(( "NULL recorder" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)recorder, fd_recorder_align() ) ) ) {
    FD_LOG_ERR(( "misaligned recorder" ));
    return NULL;
  }

  return recorder;
}

fd_recorder_req_t *
fd_recorder_req_insert( fd_recorder_t *             recorder,
                        ulong                       nonce,
                        ulong                       timestamp_ns,
                        fd_pubkey_t const *         pubkey,
                        fd_ip4_port_t               ip4,
                        ulong                       slot,
                        ulong                       shred_idx ) {

  /* Note: Caller must hold write lock on recorder->rw_lock */

  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return NULL;
  }

  #if FD_RECORDER_USE_HANDHOLDING
  if( FD_UNLIKELY( recorder->magic != FD_RECORDER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  #endif

  fd_recorder_req_map_t * req_map  = fd_recorder_req_map( recorder );
  fd_recorder_req_t *     req_pool = fd_recorder_req_pool( recorder );

  /* Check if nonce already exists */
  if( FD_UNLIKELY( fd_recorder_req_query( recorder, nonce ) ) ) {
    FD_LOG_WARNING(( "nonce %lu already exists", nonce ));
    return NULL;
  }

  /* Check if pool has space */
  #if FD_RECORDER_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_recorder_req_pool_free( req_pool ) ) ) {
    FD_LOG_WARNING(( "request pool full" ));
    return NULL;
  }
  #endif


  /* Allocate new request from pool */
  if (fd_recorder_req_pool_free(req_pool) == 0) {
    FD_LOG_WARNING(( "request pool full" ));
    return NULL;
  }

  fd_recorder_req_t * req = fd_recorder_req_pool_ele_acquire( req_pool );
  memset( req, 0, sizeof(fd_recorder_req_t) );

  if( FD_UNLIKELY( !req ) ) {
    FD_LOG_WARNING(( "failed to acquire request from pool" ));
    return NULL;
  }

  fd_recorder_peer_t * peer = fd_recorder_peer_query( recorder, pubkey );
  if( FD_UNLIKELY( !peer ) ) {
    FD_LOG_ERR(( "peer not found" ));
    return NULL;
  }
  if( FD_UNLIKELY( peer->ip4.addr != ip4.addr ) ) {
    FD_LOG_WARNING(( "IP mismatch" ));
    return NULL;
  }

  /* Initialize request fields */
  req->nonce        = nonce;
  req->timestamp_ns = timestamp_ns;
  req->pubkey       = *pubkey;
  req->slot         = slot;
  req->shred_idx    = shred_idx;

  /* Update or add peer */
  peer->inflight_to_peer_cnt++;

  fd_recorder_req_map_ele_insert( req_map, req, req_pool );

#if FD_RECORDER_USE_HANDHOLDING
  FD_TEST( !fd_recorder_req_map_verify( req_map, fd_recorder_req_pool_max( req_pool ), req_pool ) );
#endif

  /* Get the pool index of this request */

  /* Insert at tail of doubly linked list */
  fd_recorder_req_dlist_t * dlist = fd_recorder_req_dlist( recorder );
  fd_recorder_req_dlist_ele_push_tail( dlist, req, req_pool );

  recorder->total_active_requests++;
  return req;
}

int
fd_recorder_req_remove( fd_recorder_t * recorder, ulong nonce, int is_recv ) {

  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return -1;
  }

  #if FD_RECORDER_USE_HANDHOLDING
  if( FD_UNLIKELY( recorder->magic != FD_RECORDER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }
  #endif

  fd_recorder_req_map_t * req_map  = fd_recorder_req_map( recorder );
  fd_recorder_req_t *     req_pool = fd_recorder_req_pool( recorder );

  fd_recorder_req_t * req = fd_recorder_req_map_ele_query( req_map, &nonce, NULL, req_pool );
  if( FD_UNLIKELY( !req ) ) {
    return -1;
  }

  fd_recorder_peer_t * peer = fd_recorder_peer_query( recorder, &req->pubkey );
  if( FD_UNLIKELY( !peer ) ) {
    FD_LOG_WARNING(( "peer not found" ));
    return -1;
  }

  /* Update peer stats with the request information */
  fd_recorder_peer_update( recorder, &peer->key, peer->ip4, is_recv, req->timestamp_ns, (ulong)fd_log_wallclock());

  fd_recorder_req_dlist_t * dlist = fd_recorder_req_dlist( recorder );
  fd_recorder_req_dlist_ele_remove( dlist, req, req_pool );

  fd_recorder_req_map_ele_remove( req_map, &nonce, NULL, req_pool );
  fd_recorder_req_pool_ele_release( req_pool, req );

#if FD_RECORDER_USE_HANDHOLDING
  FD_TEST( !fd_recorder_req_map_verify( req_map, fd_recorder_req_pool_max( req_pool ), req_pool ) );
#endif

  if( FD_LIKELY(is_recv) ) recorder->total_handled_requests++;
  else                     recorder->total_expired_requests++;

  recorder->total_active_requests--;

  return 0;
}

ulong
fd_recorder_req_expire( fd_recorder_t * recorder, ulong current_ns, int is_recv ) {

  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return 0UL;
  }

  #if FD_RECORDER_USE_HANDHOLDING
  if( FD_UNLIKELY( recorder->magic != FD_RECORDER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return 0UL;
  }
  #endif

  fd_recorder_req_dlist_t * dlist    = fd_recorder_req_dlist( recorder );
  fd_recorder_req_t *       req_pool = fd_recorder_req_pool( recorder );
  ulong                     expired_cnt = 0UL;

  /* Traverse from head (oldest) and remove expired requests */
  fd_recorder_req_dlist_iter_t iter = fd_recorder_req_dlist_iter_fwd_init( dlist, req_pool );
  while( !fd_recorder_req_dlist_iter_done( iter, dlist, req_pool ) ) {
    fd_recorder_req_t * req = fd_recorder_req_dlist_iter_ele( iter, dlist, req_pool );

    /* Check if request has expired */
    if( FD_UNLIKELY( req->timestamp_ns + recorder->timeout_ns > current_ns ) ) break;

    iter = fd_recorder_req_dlist_iter_fwd_next( iter, dlist, req_pool );

    /* Remove request from list and map */
    fd_recorder_req_remove( recorder, req->nonce, is_recv );

    expired_cnt++;
  }

  return expired_cnt;
}

fd_recorder_peer_t *
fd_recorder_peer_add( fd_recorder_t *             recorder,
                      fd_pubkey_t const *         pubkey,
                      fd_ip4_port_t               ip4 ) {

  if( FD_UNLIKELY( !recorder) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return NULL;
  }

  if( FD_UNLIKELY( !pubkey ) ) {
    FD_LOG_WARNING(( "NULL pubkey" ));
    return NULL;
  }

  if( FD_UNLIKELY( recorder->peer_cnt > FD_MAX_PEERS) ) {
    FD_LOG_WARNING(( "peer list full" ));
    return NULL;
  }

  fd_recorder_peer_map_t * peer_map  = fd_recorder_peer_map( recorder );
  fd_recorder_peer_t *     peer_pool = fd_recorder_peer_pool( recorder );

  /* Check if peer already exists */
  fd_recorder_peer_t * existing = fd_recorder_peer_map_ele_query( peer_map, pubkey, NULL, peer_pool );
  if( FD_UNLIKELY( existing ) ) { // will be unlikley after gossip delta push outs are implemented
    /* Update existing peer info */
    existing->ip4 = ip4;
    return existing;
  }

  /* Allocate new peer */
  fd_recorder_peer_t * peer = fd_recorder_peer_pool_ele_acquire( peer_pool );
  if( FD_UNLIKELY( !peer ) ) {
    FD_LOG_WARNING(( "failed to acquire peer from pool" ));
    return NULL;
  }

  /* Initialize peer */
  peer->key               = *pubkey;
  peer->ip4               = ip4;
  peer->ewma_hr           = -1;
  peer->ewma_rtt          = 0UL;
  peer->inflight_to_peer_cnt  = 0UL;

  /* Insert into map */
  if( FD_UNLIKELY( !fd_recorder_peer_map_ele_insert( peer_map, peer, peer_pool ) ) ) {
    FD_LOG_WARNING(( "failed to insert peer into map" ));
    return NULL;
  }

#if FD_RECORDER_USE_HANDHOLDING
  FD_TEST( !fd_recorder_peer_map_verify( peer_map, fd_recorder_peer_pool_max( peer_pool ), peer_pool ) );
#endif

  recorder->peer_cnt++;

  return peer;
}

fd_recorder_peer_t *
fd_recorder_peer_update( fd_recorder_t *             recorder,
                         fd_pubkey_t const *         pubkey,
                         fd_ip4_port_t               ip4  FD_PARAM_UNUSED,
                         int                         is_recv,
                         ulong                       req_timestamp_ns,
                         ulong                       current_time ) {
  if( FD_UNLIKELY( !recorder || !pubkey ) ) {
    FD_LOG_WARNING(( "NULL recorder or pubkey" ));
    return NULL;
  }

  fd_recorder_peer_map_t * peer_map  = fd_recorder_peer_map( recorder );
  fd_recorder_peer_t *     peer_pool = fd_recorder_peer_pool( recorder );

  /* Check if peer already exists */
  fd_recorder_peer_t * existing = fd_recorder_peer_map_ele_query( peer_map, pubkey, NULL, peer_pool );
  if( FD_LIKELY( existing ) ) {
    /* Regardless of whether the request was received or expired, update
       the peer's hit rate and RTT */
    double hr_sample = is_recv ? 1.0 : 0.0;
    if (existing->ewma_hr == -1) {
        existing->ewma_hr = hr_sample;
    } else {
        existing->ewma_hr = existing->ewma_hr * 0.9 + hr_sample * 0.1;
    }

    /* Only update RTT if the request was received */
    if (FD_LIKELY(is_recv)) {
      double rtt_sample = (double)(current_time - req_timestamp_ns);
      existing->ewma_rtt = (existing->ewma_rtt == 0) ? rtt_sample : existing->ewma_rtt * 0.9 + rtt_sample * 0.1;
    }

    existing->inflight_to_peer_cnt--;
    return existing;
  }
  return NULL;
}

fd_recorder_peer_t *
fd_recorder_peer_remove( fd_recorder_t * recorder, fd_pubkey_t const * pubkey ) {
  fd_recorder_peer_map_t * peer_map  = fd_recorder_peer_map( recorder );
  fd_recorder_peer_t *     peer_pool = fd_recorder_peer_pool( recorder );
  fd_recorder_peer_t *     peer = fd_recorder_peer_map_ele_remove( peer_map, (void *)pubkey, NULL, peer_pool );
  if( peer ) {
    #if FD_RECORDER_USE_HANDHOLDING
        FD_TEST( !fd_recorder_peer_map_verify( peer_map, fd_recorder_peer_pool_max( peer_pool ), peer_pool ) );
    #endif

    recorder->peer_cnt--;
  }
  return peer;
}

/* Helper function to reshuffle peers into categories based on RTT and HR */
void FD_FN_UNUSED
fd_recorder_reshuffle_peers_boundaries( fd_recorder_t * recorder ) {
  recorder->high_priority_cnt = 0;
  recorder->medium_priority_cnt = 0;
  recorder->low_priority_cnt = 0;
  recorder->zero_hr_cnt = 0;

  recorder->high_priority_idx = 0;
  recorder->medium_priority_idx = 0;
  recorder->low_priority_idx = 0;
  recorder->zero_hr_idx = 0;

  fd_recorder_peer_map_t * peer_map = fd_recorder_peer_map( recorder );
  fd_recorder_peer_t * peer_pool = fd_recorder_peer_pool( recorder );

  for( fd_recorder_peer_map_iter_t iter = fd_recorder_peer_map_iter_init( peer_map, peer_pool );
       !fd_recorder_peer_map_iter_done( iter, peer_map, peer_pool );
       iter = fd_recorder_peer_map_iter_next( iter, peer_map, peer_pool ) ) {

      fd_recorder_peer_t * peer = fd_recorder_peer_map_iter_ele( iter, peer_map, peer_pool );

      /* Check if peer has zero hit rate */
      if( peer->ewma_hr <= 0.0 ) {
        recorder->zero_hr_peers[recorder->zero_hr_cnt++] = &peer->key;
      }
      else if( peer->ewma_rtt < 50000000UL ) { /* < 50ms */
        recorder->high_priority_peers[recorder->high_priority_cnt++] = &peer->key;
      }
      else if( peer->ewma_rtt < 100000000UL ) { /* 50-100ms */
        recorder->medium_priority_peers[recorder->medium_priority_cnt++] = &peer->key;
      }
      else { /* >= 100ms */
        recorder->low_priority_peers[recorder->low_priority_cnt++] = &peer->key;
      }

    }
}

/* Helper structure for sorting peers by RTT */
struct peer_rtt_pair {
  fd_pubkey_t * key;
  double        rtt;
};

/* Comparison function for qsort - sorts by RTT ascending (quickest first) */
static int
peer_rtt_compare( const void * a, const void * b ) {
  const struct peer_rtt_pair * pair_a = (const struct peer_rtt_pair *)a;
  const struct peer_rtt_pair * pair_b = (const struct peer_rtt_pair *)b;

  if( pair_a->rtt < pair_b->rtt ) return -1;
  if( pair_a->rtt > pair_b->rtt ) return 1;
  return 0;
}

/* Helper function to reshuffle peers into categories based on count.
   First 500 quickest -> high priority
   Next 500 quickest -> medium priority
   Remaining -> low priority
   Zero hit rate peers stay separate */
void
fd_recorder_reshuffle_peers_cnt( fd_recorder_t * recorder ) {
  recorder->high_priority_cnt = 0;
  recorder->medium_priority_cnt = 0;
  recorder->low_priority_cnt = 0;
  recorder->zero_hr_cnt = 0;

  recorder->high_priority_idx = 0;
  recorder->medium_priority_idx = 0;
  recorder->low_priority_idx = 0;
  recorder->zero_hr_idx = 0;

  fd_recorder_peer_map_t * peer_map = fd_recorder_peer_map( recorder );
  fd_recorder_peer_t * peer_pool = fd_recorder_peer_pool( recorder );

  /* First pass: count total peers and separate zero HR peers */
  ulong non_zero_hr_peers = 0;

  for( fd_recorder_peer_map_iter_t iter = fd_recorder_peer_map_iter_init( peer_map, peer_pool );
       !fd_recorder_peer_map_iter_done( iter, peer_map, peer_pool );
       iter = fd_recorder_peer_map_iter_next( iter, peer_map, peer_pool ) ) {

    fd_recorder_peer_t * peer = fd_recorder_peer_map_iter_ele( iter, peer_map, peer_pool );

    /* Separate zero hit rate peers immediately */
    if( peer->ewma_hr <= 0.0 ) recorder->zero_hr_peers[recorder->zero_hr_cnt++] = &peer->key;
    else                       non_zero_hr_peers++;
  }

  /* If no non-zero HR peers, we're done */
  if( FD_UNLIKELY( non_zero_hr_peers == 0 ) ) return;

  /* Allocate temporary array for sorting non-zero HR peers */
  struct peer_rtt_pair sorted_peers[FD_MAX_PEERS];
  ulong sorted_count = 0;

  /* Second pass: collect non-zero HR peers for sorting */
  for( fd_recorder_peer_map_iter_t iter = fd_recorder_peer_map_iter_init( peer_map, peer_pool );
       !fd_recorder_peer_map_iter_done( iter, peer_map, peer_pool );
       iter = fd_recorder_peer_map_iter_next( iter, peer_map, peer_pool ) ) {

    fd_recorder_peer_t * peer = fd_recorder_peer_map_iter_ele( iter, peer_map, peer_pool );

    /* Skip zero HR peers (already handled) */
    if( FD_UNLIKELY( peer->ewma_hr <= 0.0 ) ) continue;

    /* Add to sorting array */
    sorted_peers[sorted_count].key = &peer->key;
    sorted_peers[sorted_count].rtt = peer->ewma_rtt;
    sorted_count++;
  }

  /* Sort peers by RTT (quickest first) */
  qsort( sorted_peers, sorted_count, sizeof(struct peer_rtt_pair), peer_rtt_compare );

  /* Distribute sorted peers into buckets:
     - First 500: high priority
     - Next 500: medium priority
     - Remaining: low priority */

  for( ulong i = 0; i < sorted_count; i++ ) {
    if( i < 500 ) {
      /* First 500 quickest -> high priority */
      recorder->high_priority_peers[recorder->high_priority_cnt++] = sorted_peers[i].key;
    } else if( i < 1000 ) {
      /* Next 500 quickest -> medium priority */
      recorder->medium_priority_peers[recorder->medium_priority_cnt++] = sorted_peers[i].key;
    } else {
      /* Remaining -> low priority */
      recorder->low_priority_peers[recorder->low_priority_cnt++] = sorted_peers[i].key;
    }
  }
}

fd_pubkey_t *
fd_recorder_select_peer(fd_recorder_t * recorder) {
  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return NULL;
  }

  /* Check if we need to reshuffle */
  if( FD_UNLIKELY( recorder->cycle_position == 0 && (recorder->cycle_count % 10000) == 0 ) ) {
    fd_recorder_reshuffle_peers_cnt( recorder );
  }

  /* Define the weighted round-robin pattern:
     - High priority (<50ms): 10 polls per cycle
     - Medium priority (50-100ms): 5 polls per cycle
     - Low priority (>=100ms): 1 poll per cycle
     - Zero HR: 1 poll per cycle (handled separately)

     Pattern: H,H,H,M,H,H,H,M,H,H,H,M,H,H,H,M,H,H,M,L,Z (21 total positions) */

  static const int pattern[] = {
    0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 2, 3
  };
  static const ulong pattern_len = sizeof(pattern) / sizeof(pattern[0]);

  /* Try to find a peer following the pattern */
  for( ulong attempts = 0; attempts < pattern_len; attempts++ ) {
    int category = pattern[recorder->cycle_position];

    fd_pubkey_t * selected = NULL;

    switch( category ) {
      case 0: /* High priority */
        if( recorder->high_priority_cnt > 0 ) {
          selected = recorder->high_priority_peers[recorder->high_priority_idx];
          recorder->high_priority_idx = (recorder->high_priority_idx + 1) % recorder->high_priority_cnt;
        }
        break;

      case 1: /* Medium priority */
        if( recorder->medium_priority_cnt > 0 ) {
          selected = recorder->medium_priority_peers[recorder->medium_priority_idx];
          recorder->medium_priority_idx = (recorder->medium_priority_idx + 1) % recorder->medium_priority_cnt;
        }
        break;

      case 2: /* Low priority */
        if( recorder->low_priority_cnt > 0 ) {
          selected = recorder->low_priority_peers[recorder->low_priority_idx];
          recorder->low_priority_idx = (recorder->low_priority_idx + 1) % recorder->low_priority_cnt;
        }
        break;

      case 3: /* Zero HR */
        if( recorder->zero_hr_cnt > 0 ) {
          selected = recorder->zero_hr_peers[recorder->zero_hr_idx];
          recorder->zero_hr_idx = (recorder->zero_hr_idx + 1) % recorder->zero_hr_cnt;
        }
        break;
    }

    /* Move to next position in pattern */
    recorder->cycle_position = (recorder->cycle_position + 1) % pattern_len;
    if( FD_UNLIKELY( recorder->cycle_position == 0 ) ) recorder->cycle_count++;

    /* If we found a peer, return it */
    if( FD_LIKELY( selected ) ) {
      return selected;
    }

    /* If no peers available in any category, break to avoid infinite loop */
    if( FD_UNLIKELY( recorder->high_priority_cnt == 0 &&
                     recorder->medium_priority_cnt == 0 &&
                     recorder->low_priority_cnt == 0 &&
                     recorder->zero_hr_cnt == 0 ) ) {
      FD_LOG_WARNING(( "No peers available for selection" ));
      break;
    }
  }

  return NULL; /* No peer selected */
}


/* helpers */

int
fd_recorder_verify( fd_recorder_t const * recorder ) {
  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)recorder, fd_recorder_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned recorder" ));
    return -1;
  }

  fd_wksp_t * wksp = fd_wksp_containing( recorder );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "recorder must be part of a workspace" ));
    return -1;
  }

  if( FD_UNLIKELY( recorder->magic!=FD_RECORDER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }

  fd_recorder_req_t const *     req_pool = fd_recorder_req_pool_const( recorder );
  fd_recorder_req_map_t const * req_map  = fd_recorder_req_map_const( recorder );
  fd_recorder_req_dlist_t const * req_dlist  = fd_recorder_req_dlist_const( recorder );
  fd_recorder_peer_t const *     peer_pool = fd_recorder_peer_pool_const( recorder );
  fd_recorder_peer_map_t const * peer_map  = fd_recorder_peer_map_const( recorder );

  /* Verify map consistency */
  if( fd_recorder_req_map_verify( req_map, fd_recorder_req_pool_max( req_pool ), req_pool ) ) {
    FD_LOG_WARNING(( "map verification failed" ));
    return -1;
  }

  if( fd_recorder_peer_map_verify( peer_map, fd_recorder_peer_pool_max( peer_pool ), peer_pool ) ) {
    FD_LOG_WARNING(( "peer map verification failed" ));
    return -1;
  }

  if( fd_recorder_req_dlist_verify( req_dlist, fd_recorder_req_pool_max( req_pool ), req_pool ) ) {
    FD_LOG_WARNING(( "dlist verification failed" ));
    return -1;
  }

  return 0;
}

void
fd_recorder_peer_print( fd_recorder_peer_t * peer ) {
  FD_LOG_NOTICE(("Peer: %s, IP: "FD_IP4_ADDR_FMT", ewma_hr: %f, ewma_rtt: %f, inflight_to_peer_cnt: %lu",
                 FD_BASE58_ENC_32_ALLOCA(&peer->key), FD_IP4_ADDR_FMT_ARGS(peer->ip4.addr), peer->ewma_hr, peer->ewma_rtt, peer->inflight_to_peer_cnt));
}

void
fd_recorder_print_first_nonce( fd_recorder_t * recorder ) {
  fd_recorder_req_dlist_t * dlist = fd_recorder_req_dlist( recorder );
  fd_recorder_req_t * req = fd_recorder_req_dlist_iter_ele( fd_recorder_req_dlist_iter_fwd_init( dlist, fd_recorder_req_pool( recorder ) ), dlist, fd_recorder_req_pool( recorder ) );
  FD_LOG_NOTICE(("First nonce: %lu", req->nonce));
}

void
fd_recorder_print_summary( fd_recorder_t const * recorder ) {
  if( FD_UNLIKELY( !recorder ) ) {
    FD_LOG_WARNING(( "NULL recorder" ));
    return;
  }

  FD_LOG_NOTICE(("Peer active_requests: %lu, expired_requests: %lu, handled_requests: %lu", recorder->total_active_requests, recorder->total_expired_requests, recorder->total_handled_requests));
}
