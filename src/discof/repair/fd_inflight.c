#include "fd_inflight.h"

void *
fd_inflights_new( void * shmem,
                  ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong footprint = fd_inflights_footprint();
  ulong chain_cnt = fd_inflight_map_chain_cnt_est( FD_INFLIGHT_REQ_MAX );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_inflights_t * table = FD_SCRATCH_ALLOC_APPEND( l, fd_inflights_align(),     sizeof(fd_inflights_t) );
  void *           pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_pool_align(), fd_inflight_pool_footprint( FD_INFLIGHT_REQ_MAX ) );
  void *           map   = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_map_align(),  fd_inflight_map_footprint ( chain_cnt           ) );
  void *           pmap  = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_map_align(),  fd_inflight_map_footprint ( chain_cnt           ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_inflights_align() ) == (ulong)shmem + footprint );

  table->pool       = fd_inflight_pool_join ( fd_inflight_pool_new ( pool, FD_INFLIGHT_REQ_MAX    ) );
  table->map        = fd_inflight_map_join  ( fd_inflight_map_new  ( map,  chain_cnt, seed ) );
  table->popped_map = fd_inflight_map_join  ( fd_inflight_map_new  ( pmap, chain_cnt, seed ) );
  FD_TEST( table->outstanding_dl==fd_inflight_dlist_join( fd_inflight_dlist_new( table->outstanding_dl ) ) );
  FD_TEST( table->popped_dl     ==fd_inflight_dlist_join( fd_inflight_dlist_new( table->popped_dl      ) ) );

  FD_TEST( table->pool       );
  FD_TEST( table->map        );
  FD_TEST( table->popped_map );

  return shmem;
}

fd_inflights_t *
fd_inflights_join( void * shmem ) {
  fd_inflights_t * table = (fd_inflights_t *)shmem;

  if( FD_UNLIKELY( !table ) ) {
    FD_LOG_WARNING(( "NULL inflight table" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)table, fd_inflights_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned inflight table" ));
    return NULL;
  }

  return (fd_inflights_t *)shmem;
}

void
fd_inflights_request_insert( fd_inflights_t *    table,
                             ulong               nonce,
                             fd_pubkey_t const * pubkey,
                             ulong               slot,
                             ulong               shred_idx ) {
  if( FD_UNLIKELY( !fd_inflight_pool_free( table->pool ) ) ) {
    if( FD_LIKELY( !fd_inflight_dlist_is_empty( table->popped_dl, table->pool ) ) ) {
      fd_inflight_t * evict = fd_inflight_dlist_ele_pop_head( table->popped_dl, table->pool );
      fd_inflight_map_ele_remove_fast( table->popped_map, evict, table->pool );
      fd_inflight_pool_ele_release   ( table->pool,       evict );
    } else {
      /* (pool free cnt) + (popped_dl cnt) + (outstanding_dl cnt) ==
         INFLIGHT_REQ_MAX, so they can't all be 0. */
      fd_inflight_t * evict = fd_inflight_dlist_ele_pop_head( table->outstanding_dl, table->pool );
    FD_LOG_WARNING(( "ITS JOVER. evicting inflight " ));
      fd_inflight_map_ele_remove_fast( table->map,  evict, table->pool );
      fd_inflight_pool_ele_release   ( table->pool, evict );
    }
  }

  fd_inflight_t * inflight_req = fd_inflight_pool_ele_acquire( table->pool );
  inflight_req->key.nonce        = nonce;
  inflight_req->key.slot         = slot;
  inflight_req->key.shred_idx    = shred_idx;
  inflight_req->timestamp_ns     = fd_log_wallclock();
  inflight_req->pubkey           = *pubkey;

  fd_inflight_map_ele_insert     ( table->map,            inflight_req, table->pool );
  fd_inflight_dlist_ele_push_tail( table->outstanding_dl, inflight_req, table->pool );
}

long
fd_inflights_request_remove( fd_inflights_t * table,
                             ulong            nonce,
                             ulong            slot,
                             ulong            shred_idx,
                             fd_pubkey_t *    peer_out ) {
  fd_inflight_key_t query[1] = {{ .slot = slot, .shred_idx = shred_idx, .nonce = nonce }};
  /* In the unlikely case that there are multiple requests (outstanding
     or popped) with the same (slot, shred_idx, nonce) tuple, we'll
     remove them all and credit the response to the oldest one. */
  long now    = fd_log_wallclock();
  long req_ts = now;

  int query_idx = 0;
  while( query_idx<2 ) {
    /* Look in the outstanding map first */
    fd_inflight_map_t   * query_map  = fd_ptr_if( !query_idx, table->map,                                   table->popped_map );
    fd_inflight_dlist_t * query_list = fd_ptr_if( !query_idx, (fd_inflight_dlist_t *)table->outstanding_dl, table->popped_dl  );

    fd_inflight_t * inflight_req = fd_inflight_map_ele_remove( query_map, query, NULL, table->pool );
    if( FD_LIKELY( inflight_req ) ) {

      /* Take oldest one (probably only one, but req_ts initialized to
         now, so all are older than it. */
      if( FD_LIKELY( inflight_req->timestamp_ns<req_ts ) ) {
        req_ts    = inflight_req->timestamp_ns;
        *peer_out = inflight_req->pubkey;
      }

      /* Remove the element from the inflight table */
      fd_inflight_dlist_ele_remove( query_list,  inflight_req, table->pool );
      fd_inflight_pool_ele_release( table->pool, inflight_req              );
    } else {
      query_idx++;
    }
  }
  return now-req_ts; /* 0 if nothing found */
}

void
fd_inflights_request_pop( fd_inflights_t * table,
                          ulong *          nonce_out,
                          ulong *          slot_out,
                          ulong *          shred_idx_out ) {
  fd_inflight_t * inflight_req = fd_inflight_dlist_ele_pop_head( table->outstanding_dl, table->pool );
  fd_inflight_map_ele_remove_fast( table->map, inflight_req, table->pool );
  *nonce_out     = inflight_req->key.nonce;
  *slot_out      = inflight_req->key.slot;
  *shred_idx_out = inflight_req->key.shred_idx;
  fd_inflight_map_ele_insert     ( table->popped_map, inflight_req, table->pool );
  fd_inflight_dlist_ele_push_tail( table->popped_dl,  inflight_req, table->pool );
}


#include <stdio.h>

void
fd_inflights_print( fd_inflight_dlist_t * dlist, fd_inflight_t * pool ) {

  printf("%-15s %-8s %-15s %-44s\n", "Slot", "Idx", "Timestamp", "Peer");
  printf("%-15s %-8s %-15s %-44s\n",
          "---------------", "--------", "------------",
          "--------------------------------------------");
  for( fd_inflight_dlist_iter_t iter = fd_inflight_dlist_iter_fwd_init( dlist, pool );
       !fd_inflight_dlist_iter_done( iter, dlist, pool );
       iter = fd_inflight_dlist_iter_fwd_next( iter, dlist, pool ) ) {
    fd_inflight_t * inflight_req = fd_inflight_dlist_iter_ele( iter, dlist, pool );
    FD_BASE58_ENCODE_32_BYTES( inflight_req->pubkey.uc, peer );

    printf("%-15lu %-8lu %-15lu %-44.44s\n",
            inflight_req->key.slot,
            inflight_req->key.shred_idx,
            (ulong)inflight_req->timestamp_ns / (ulong)1e6,
            peer);
  }
  printf("\n");
}
