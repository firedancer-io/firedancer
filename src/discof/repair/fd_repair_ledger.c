#include "fd_repair_ledger.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/net/fd_net_headers.h"
#include <stdbool.h>


void *
fd_repair_ledger_new( void * shmem, ulong seed, ulong timeout_ns ) {
  
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_repair_ledger_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_repair_ledger_footprint();
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
  fd_repair_ledger_t * repair_ledger = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_ledger_align(), sizeof( fd_repair_ledger_t ) );
  void *       req_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_ledger_req_pool_align(), fd_repair_ledger_req_pool_footprint( MAX_REQUESTS ) );
  void *       req_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_ledger_req_map_align(), fd_repair_ledger_req_map_footprint( fd_repair_ledger_req_map_chain_cnt_est( MAX_REQUESTS ) ) );
  void *       req_dlist  = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_ledger_req_dlist_align(), fd_repair_ledger_req_dlist_footprint() );
  void *       peer_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_ledger_peer_pool_align(), fd_repair_ledger_peer_pool_footprint( MAX_PEERS ) );
  void *       peer_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_ledger_peer_map_align(), fd_repair_ledger_peer_map_footprint( fd_repair_ledger_peer_map_chain_cnt_est( MAX_PEERS ) ) );

  repair_ledger->req_pool_gaddr  = fd_wksp_gaddr_fast( wksp, fd_repair_ledger_req_pool_join( fd_repair_ledger_req_pool_new( req_pool, MAX_REQUESTS ) ) );
  repair_ledger->req_map_gaddr   = fd_wksp_gaddr_fast( wksp, fd_repair_ledger_req_map_join( fd_repair_ledger_req_map_new( req_map, fd_repair_ledger_req_map_chain_cnt_est( MAX_REQUESTS ), seed ) ) );
  repair_ledger->req_dlist_gaddr = fd_wksp_gaddr_fast( wksp, fd_repair_ledger_req_dlist_join( fd_repair_ledger_req_dlist_new( req_dlist ) ) );
  repair_ledger->peer_pool_gaddr = fd_wksp_gaddr_fast( wksp, fd_repair_ledger_peer_pool_join( fd_repair_ledger_peer_pool_new( peer_pool, MAX_PEERS ) ) );
  repair_ledger->peer_map_gaddr  = fd_wksp_gaddr_fast( wksp, fd_repair_ledger_peer_map_join( fd_repair_ledger_peer_map_new( peer_map, fd_repair_ledger_peer_map_chain_cnt_est( MAX_PEERS ), seed ) ) );

  repair_ledger->peer_ledger_gaddr = fd_wksp_gaddr_fast( wksp, repair_ledger );
  repair_ledger->seed              = seed;
  repair_ledger->timeout_ns        = timeout_ns;
  repair_ledger->req_cnt           = 0UL;
  repair_ledger->req_expired_cnt   = 0UL;
  repair_ledger->req_handled_cnt   = 0UL;
  repair_ledger->peer_cnt          = 0UL;

  /* Initialize peer pubkeys array */
  memset( repair_ledger->peer_pubkeys, 0, sizeof(repair_ledger->peer_pubkeys) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( repair_ledger->magic ) = FD_REPAIR_LEDGER_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_repair_ledger_t *
fd_repair_ledger_join( void * shrepair_ledger ) {
  fd_repair_ledger_t * repair_ledger = (fd_repair_ledger_t *)shrepair_ledger;

  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)repair_ledger, fd_repair_ledger_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned repair_ledger" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( repair_ledger );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "repair_ledger must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( repair_ledger->magic!=FD_REPAIR_LEDGER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return repair_ledger;
}

void *
fd_repair_ledger_leave( fd_repair_ledger_t const * repair_ledger ) {

  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return NULL;
  }

  return (void *)repair_ledger;
}

void *
fd_repair_ledger_delete( void * repair_ledger ) {

  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)repair_ledger, fd_repair_ledger_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned repair_ledger" ));
    return NULL;
  }

  return repair_ledger;
}

fd_repair_ledger_req_t *
fd_repair_ledger_req_insert( fd_repair_ledger_t *        repair_ledger,
                             ulong                       nonce,
                             ulong                       timestamp_ns,
                             fd_pubkey_t const *         pubkey,
                             fd_ip4_port_t               ip4,
                             ulong                       slot,
                             ulong                       shred_idx,
                             uint                        req_type ) {

  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return NULL;
  }

  #if FD_PEER_LEDGER_USE_HANDHOLDING
  if( FD_UNLIKELY( repair_ledger->magic != FD_REPAIR_LEDGER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  #endif

  fd_repair_ledger_req_map_t * req_map  = fd_repair_ledger_req_map( repair_ledger );
  fd_repair_ledger_req_t *     req_pool = fd_repair_ledger_req_pool( repair_ledger );

  /* Check if nonce already exists */
  #if FD_PEER_LEDGER_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_repair_ledger_req_query( repair_ledger, nonce ) ) ) {
    FD_LOG_WARNING(( "nonce %lu already exists", nonce ));
    return NULL;
  }
  #endif

  /* Check if pool has space */
  #if FD_PEER_LEDGER_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_repair_ledger_req_pool_free( req_pool ) ) ) {
    FD_LOG_WARNING(( "request pool full" ));
    return NULL;
  }
  #endif


  /* Allocate new request from pool */
  fd_repair_ledger_req_t * req = fd_repair_ledger_req_pool_ele_acquire( req_pool );
  memset( req, 0, sizeof(fd_repair_ledger_req_t) );
  
  if( FD_UNLIKELY( !req ) ) {
    FD_LOG_WARNING(( "failed to acquire request from pool" ));
    return NULL;
  }

  fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_query( repair_ledger, pubkey );
  if( FD_UNLIKELY( !peer ) ) {
    FD_LOG_WARNING(( "peer not found" ));
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
  req->req_type     = req_type;
  req->prev_idx     = ULONG_MAX;
  req->next_idx     = ULONG_MAX;

  /* Update or add peer */

  peer->num_inflight_req++;
  peer->last_send = (long)timestamp_ns;
  /* Insert into map */
  fd_repair_ledger_req_map_ele_insert( req_map, req, req_pool );

  /* Get the pool index of this request */
  // ulong req_idx = fd_repair_ledger_req_pool_idx( req_pool, req );

  /* Insert at tail of doubly linked list */
  fd_repair_ledger_req_dlist_t * dlist = fd_repair_ledger_req_dlist( repair_ledger );
  fd_repair_ledger_req_dlist_ele_push_tail( dlist, req, req_pool );

  repair_ledger->req_cnt++;
  // FD_LOG_NOTICE(( "Request count: %lu", repair_ledger->req_cnt ));
  // FD_LOG_INFO(("Request added: %lu, IP: "FD_IP4_ADDR_FMT ", type: %u, slot: %lu, shred_idx: %lu", req->nonce, FD_IP4_ADDR_FMT_ARGS(ip4.addr), req->req_type, req->slot, req->shred_idx));
  return req;
}

int
fd_repair_ledger_req_remove( fd_repair_ledger_t * repair_ledger, ulong nonce ) {

  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return -1;
  }

  #if FD_PEER_LEDGER_USE_HANDHOLDING
  if( FD_UNLIKELY( repair_ledger->magic != FD_REPAIR_LEDGER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }
  #endif

  fd_repair_ledger_req_map_t * req_map  = fd_repair_ledger_req_map( repair_ledger );
  fd_repair_ledger_req_t *     req_pool = fd_repair_ledger_req_pool( repair_ledger );

  /* Find the request in the map */
  fd_repair_ledger_req_t * req = fd_repair_ledger_req_map_ele_query( req_map, &nonce, NULL, req_pool );
  if( FD_UNLIKELY( !req ) ) {
    FD_LOG_WARNING(( "nonce %lu not found", nonce ));
    return -1;
  }

  // ulong req_idx = fd_repair_ledger_req_pool_idx( req_pool, req );
  fd_repair_ledger_req_dlist_t * dlist = fd_repair_ledger_req_dlist( repair_ledger );
  fd_repair_ledger_req_dlist_ele_remove( dlist, req, req_pool );

  /* Remove from map */
  fd_repair_ledger_req_map_ele_remove( req_map, &nonce, NULL, req_pool );

  fd_repair_ledger_req_pool_ele_release( req_pool, req );

  repair_ledger->req_cnt--;
  repair_ledger->req_handled_cnt++;

  return 0;
}

ulong
fd_repair_ledger_req_expire( fd_repair_ledger_t * repair_ledger, ulong current_ns ) {

  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return 0UL;
  }

  #if FD_PEER_LEDGER_USE_HANDHOLDING
  if( FD_UNLIKELY( repair_ledger->magic != FD_REPAIR_LEDGER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return 0UL;
  }
  #endif

  fd_repair_ledger_req_dlist_t * dlist    = fd_repair_ledger_req_dlist( repair_ledger );
  fd_repair_ledger_req_map_t *   req_map  = fd_repair_ledger_req_map( repair_ledger );
  fd_repair_ledger_req_t *       req_pool = fd_repair_ledger_req_pool( repair_ledger );
  ulong                        expired_cnt = 0UL;

  /* Traverse from head (oldest) and remove expired requests */
  fd_repair_ledger_req_dlist_iter_t iter = fd_repair_ledger_req_dlist_iter_fwd_init( dlist, req_pool );
  while( !fd_repair_ledger_req_dlist_iter_done( iter, dlist, req_pool ) ) {
    fd_repair_ledger_req_t * req = fd_repair_ledger_req_dlist_iter_ele( iter, dlist, req_pool );
    
    /* Check if request has expired */
    if( FD_LIKELY( req->timestamp_ns + repair_ledger->timeout_ns > current_ns ) ) {
      /* This and all subsequent requests are not expired yet */
      break;
    }

    fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_query( repair_ledger, &req->pubkey );
    if( peer ) {
      peer->ewma_hr = (ulong)((double)peer->ewma_hr * 0.9) + (ulong)((double)(0) * 0.1);
      peer->num_inflight_req--;
    }

    /* Advance iterator before removing */
    iter = fd_repair_ledger_req_dlist_iter_fwd_next( iter, dlist, req_pool );

    /* Remove expired request */
    fd_repair_ledger_req_dlist_ele_remove( dlist, req, req_pool );
    fd_repair_ledger_req_map_ele_remove( req_map, &req->nonce, NULL, req_pool );
    fd_repair_ledger_req_pool_ele_release( req_pool, req );

    expired_cnt++;
    repair_ledger->req_cnt--;
    repair_ledger->req_expired_cnt++;
  }

  return expired_cnt;
}

int
fd_repair_ledger_verify( fd_repair_ledger_t const * repair_ledger ) {
  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)repair_ledger, fd_repair_ledger_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned repair_ledger" ));
    return -1;
  }

  fd_wksp_t * wksp = fd_wksp_containing( repair_ledger );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "repair_ledger must be part of a workspace" ));
    return -1;
  }

  if( FD_UNLIKELY( repair_ledger->magic!=FD_REPAIR_LEDGER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }

  fd_repair_ledger_req_t const *     req_pool = fd_repair_ledger_req_pool_const( repair_ledger );
  fd_repair_ledger_req_map_t const * req_map  = fd_repair_ledger_req_map_const( repair_ledger );
  fd_repair_ledger_req_dlist_t const * req_dlist  = fd_repair_ledger_req_dlist_const( repair_ledger );

  /* Verify map consistency */
  if( fd_repair_ledger_req_map_verify( req_map, fd_repair_ledger_req_pool_max( req_pool ), req_pool ) ) {
    FD_LOG_WARNING(( "map verification failed" ));
    return -1;
  }

  if( fd_repair_ledger_req_dlist_verify( req_dlist, fd_repair_ledger_req_pool_max( req_pool ), req_pool ) ) {
    FD_LOG_WARNING(( "dlist verification failed" ));
    return -1;
  }

  return 0;
}

void
fd_repair_ledger_print( fd_repair_ledger_t const * repair_ledger ) {
  if( FD_UNLIKELY( !repair_ledger ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger" ));
    return;
  }

  FD_LOG_NOTICE(( "Peer count: %lu, magic: 0x%lx", repair_ledger->peer_cnt, repair_ledger->magic ));
}

fd_repair_ledger_peer_t *
fd_repair_ledger_peer_add( fd_repair_ledger_t *        repair_ledger,
                            fd_pubkey_t const *         pubkey,
                            fd_ip4_port_t               ip4,
                            long                        current_time ) {
  
  if( FD_UNLIKELY( !repair_ledger || !pubkey ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger or pubkey" ));
    return NULL;
  }

  if( FD_UNLIKELY( repair_ledger->peer_cnt >= MAX_PEERS) ) {
    FD_LOG_WARNING(( "peer list full" ));
    return NULL;
  }

  fd_repair_ledger_peer_map_t * peer_map  = fd_repair_ledger_peer_map( repair_ledger );
  fd_repair_ledger_peer_t *     peer_pool = fd_repair_ledger_peer_pool( repair_ledger );

  /* Check if peer already exists */
  fd_repair_ledger_peer_t * existing = fd_repair_ledger_peer_map_ele_query( peer_map, pubkey, NULL, peer_pool );
  if( existing ) {
    /* Update existing peer info */
    existing->ip4 = ip4;
    existing->last_recv = current_time;
    return existing;
  }

  /* Allocate new peer */
  fd_repair_ledger_peer_t * peer = fd_repair_ledger_peer_pool_ele_acquire( peer_pool );
  if( FD_UNLIKELY( !peer ) ) {
    FD_LOG_WARNING(( "failed to acquire peer from pool" ));
    return NULL;
  }

  /* Initialize peer */
  peer->key               = *pubkey;
  peer->ip4               = ip4;
  peer->last_send         = 0L;
  peer->last_recv         = current_time;
  peer->ewma_hr           = 0UL;
  peer->ewma_rtt          = 0UL;
  peer->num_inflight_req  = 0UL;
  peer->pong_sent         = 0;

  /* Insert into map */
  fd_repair_ledger_peer_map_ele_insert( peer_map, peer, peer_pool );

  /* Add to pubkey array */
  repair_ledger->peer_pubkeys[repair_ledger->peer_cnt] = *pubkey;
  peer->peer_list_idx = repair_ledger->peer_cnt;
  repair_ledger->peer_cnt++;

  return peer;
}

// update
fd_repair_ledger_peer_t *
fd_repair_ledger_peer_update( fd_repair_ledger_t *        repair_ledger,
                               fd_pubkey_t const *         pubkey,
                               fd_ip4_port_t               ip4,
                               int                         is_recv,
                               long                        current_time ) {
  if( FD_UNLIKELY( !repair_ledger || !pubkey ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger or pubkey" ));
    return NULL;
  }

  fd_repair_ledger_peer_map_t * peer_map  = fd_repair_ledger_peer_map( repair_ledger );
  fd_repair_ledger_peer_t *     peer_pool = fd_repair_ledger_peer_pool( repair_ledger );

  /* Check if peer already exists */
  fd_repair_ledger_peer_t * existing = fd_repair_ledger_peer_map_ele_query( peer_map, pubkey, NULL, peer_pool );
  if( existing ) {
    existing->ip4 = ip4;
    existing->last_recv = current_time;
    existing->ewma_hr = (ulong)((double)existing->ewma_hr * 0.9) + (ulong)((double)(is_recv ? 1 : 0) * 0.1);
    existing->ewma_rtt = (ulong)((double)existing->ewma_rtt * 0.9) + (ulong)((double)(current_time - existing->last_send) * 0.1);
    if (is_recv) { existing->num_inflight_req++; } else { existing->num_inflight_req--; }
    // FD_LOG_NOTICE(("Peer updated to last_send: %ld, last_recv: %ld, ewma_hr: %lu, ewma_rtt: %lu, num_inflight_req: %lu", existing->last_send, existing->last_recv, existing->ewma_hr, existing->ewma_rtt, existing->num_inflight_req));
    return existing;
  }
  return NULL;
}

fd_repair_ledger_peer_t *
fd_repair_ledger_peer_remove( fd_repair_ledger_t * repair_ledger, fd_pubkey_t const * pubkey ) {
  fd_repair_ledger_peer_map_t * peer_map  = fd_repair_ledger_peer_map( repair_ledger );
  fd_repair_ledger_peer_t *     peer_pool = fd_repair_ledger_peer_pool( repair_ledger );
  fd_repair_ledger_peer_t *     peer = fd_repair_ledger_peer_map_ele_remove( peer_map, (void *)pubkey, NULL, peer_pool );
  if( peer ) {
    repair_ledger->peer_cnt--;
    repair_ledger->peer_pubkeys[peer->peer_list_idx] = repair_ledger->peer_pubkeys[repair_ledger->peer_cnt];
    fd_repair_ledger_peer_t * peer_to_swap = fd_repair_ledger_peer_query( repair_ledger, &repair_ledger->peer_pubkeys[repair_ledger->peer_cnt] );
    peer_to_swap->peer_list_idx = peer->peer_list_idx;
    repair_ledger->peer_pubkeys[repair_ledger->peer_cnt] = (fd_pubkey_t){0};
    repair_ledger->pubkeys_idx--;
  }
  return peer;
}

void
fd_repair_ledger_peer_print( fd_repair_ledger_peer_t * peer ) {
  FD_LOG_NOTICE(("Peer: %s, IP: "FD_IP4_ADDR_FMT", last_send: %ld, last_recv: %ld, ewma_hr: %lu, ewma_rtt: %lu, num_inflight_req: %lu", 
                 FD_BASE58_ENC_32_ALLOCA(&peer->key), FD_IP4_ADDR_FMT_ARGS(peer->ip4.addr), peer->last_send, peer->last_recv, peer->ewma_hr, peer->ewma_rtt, peer->num_inflight_req));
}


void
fd_repair_ledger_select_peers(fd_repair_ledger_t * repair_ledger, uint num_peers, fd_pubkey_t * selected_peers[]) {
  if( FD_UNLIKELY( !repair_ledger || !selected_peers ) ) {
    FD_LOG_WARNING(( "NULL repair_ledger or selected_peers" ));
    return;
  }
  /* Select peers starting from peeridx*/ 
  for (uint i = 0; i < num_peers; i++) {
    selected_peers[i] = &repair_ledger->peer_pubkeys[repair_ledger->pubkeys_idx];
    repair_ledger->pubkeys_idx = (repair_ledger->pubkeys_idx + 1) % repair_ledger->peer_cnt;
  }
}

// HELPERS
