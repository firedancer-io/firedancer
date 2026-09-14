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

  table->pool       = fd_inflight_pool_join( fd_inflight_pool_new( pool, FD_INFLIGHT_REQ_MAX ) );
  table->map        = fd_inflight_map_join ( fd_inflight_map_new ( map,  chain_cnt, seed    ) );
  table->popped_map = fd_inflight_map_join ( fd_inflight_map_new ( pmap, chain_cnt, seed    ) );
  table->popped_cnt = 0UL;
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

  return table;
}

/* inflight_acquire returns a FREE record, evicting the oldest POPPED
   record if none is free, and the oldest OUTSTANDING one as a last
   resort.  The caller fills the key and payload, then commits it to
   the OUTSTANDING set with inflight_commit. */

static fd_inflight_t *
inflight_acquire( fd_inflights_t * table ) {
  if( FD_UNLIKELY( !fd_inflight_pool_free( table->pool ) ) ) {
    if( FD_LIKELY( !fd_inflight_dlist_is_empty( table->popped_dl, table->pool ) ) ) {
      fd_inflight_t * evict = fd_inflight_dlist_ele_pop_head( table->popped_dl, table->pool );
      table->popped_cnt--;
      fd_inflight_map_ele_remove_fast( table->popped_map, evict, table->pool );
      fd_inflight_pool_ele_release   ( table->pool,       evict );
    } else {
      /* (pool free cnt) + (popped_dl cnt) + (outstanding_dl cnt) ==
         FD_INFLIGHT_REQ_MAX, so they can't all be 0.  Should be
         impossible in practice: callers gate new requests on
         fd_inflights_outstanding_free. */
      fd_inflight_t * evict = fd_inflight_dlist_ele_pop_head( table->outstanding_dl, table->pool );
      FD_LOG_WARNING(( "evicting outstanding request kind %u slot %lu idx %u nonce %u", evict->key.kind, evict->key.slot, evict->key.idx, evict->key.nonce ));
      fd_inflight_map_ele_remove_fast( table->map,  evict, table->pool );
      fd_inflight_pool_ele_release   ( table->pool, evict );
    }
  }
  return fd_inflight_pool_ele_acquire( table->pool );
}

static void
inflight_commit( fd_inflights_t * table,
                 fd_inflight_t *  req,
                 long             now ) {
  req->timestamp_ns = now;
  fd_inflight_map_ele_insert     ( table->map,            req, table->pool );
  fd_inflight_dlist_ele_push_tail( table->outstanding_dl, req, table->pool );
}

/* inflight_match removes every record with key from the outstanding
   then the popped set, copying the oldest to *out.  Returns the number
   of records removed. */

static ulong
inflight_match( fd_inflights_t *          table,
                fd_inflight_key_t const * key,
                fd_inflight_t *           out ) {
  ulong cnt    = 0UL;
  long  oldest = LONG_MAX;
  for( int popped=0; popped<2; popped++ ) {
    fd_inflight_map_t   * map   = popped ? table->popped_map : table->map;
    fd_inflight_dlist_t * dlist = popped ? table->popped_dl  : table->outstanding_dl;
    for(;;) {
      fd_inflight_t * req = fd_inflight_map_ele_remove( map, key, NULL, table->pool );
      if( FD_LIKELY( !req ) ) break;
      if( FD_LIKELY( req->timestamp_ns<oldest ) ) { oldest = req->timestamp_ns; *out = *req; }
      fd_inflight_dlist_ele_remove( dlist,       req, table->pool );
      fd_inflight_pool_ele_release( table->pool, req              );
      table->popped_cnt -= (ulong)popped;
      cnt++;
    }
  }
  return cnt;
}

void
fd_inflights_shred_insert( fd_inflights_t *    table,
                           ulong               nonce,
                           fd_pubkey_t const * pubkey,
                           ulong               slot,
                           ulong               shred_idx,
                           fd_hash_t const *   block_id,
                           fd_hash_t const *   fec_root,
                           long                now ) {
  fd_inflight_t * req = inflight_acquire( table );
  fd_inflight_key_init( &req->key, FD_REPAIR_KIND_SHRED, slot, shred_idx, nonce, fec_root );
  req->pubkey = *pubkey;
  if( FD_LIKELY( block_id ) ) req->block_id = *block_id;
  else                        fd_memset( &req->block_id, 0, sizeof(fd_hash_t) );
  inflight_commit( table, req, now );
}

long
fd_inflights_shred_match( fd_inflights_t *  table,
                          ulong             nonce,
                          ulong             slot,
                          ulong             shred_idx,
                          fd_hash_t const * fec_root,
                          fd_pubkey_t *     peer_out,
                          fd_hash_t *       block_id_out,
                          long              now ) {
  fd_inflight_key_t key[1];
  fd_inflight_key_init( key, FD_REPAIR_KIND_SHRED, slot, shred_idx, nonce, fec_root );
  fd_inflight_t req[1];
  if( FD_UNLIKELY( !inflight_match( table, key, req ) ) ) return 0L;
  *peer_out = req->pubkey;
  if( FD_LIKELY( block_id_out ) ) *block_id_out = req->block_id;
  return fd_long_max( now-req->timestamp_ns, 1L ); /* >0 marks a match even if now has not advanced */
}

void
fd_inflights_meta_insert( fd_inflights_t *    table,
                          ulong               nonce,
                          uint                kind,
                          fd_pubkey_t const * pubkey,
                          ulong               slot,
                          fd_hash_t const *   block_id,
                          uint                fec_set_idx,
                          long                now ) {
  fd_inflight_t * req = inflight_acquire( table );
  fd_inflight_key_init( &req->key, kind, slot, fec_set_idx, nonce, NULL );
  req->pubkey   = *pubkey;
  req->block_id = *block_id;
  inflight_commit( table, req, now );
}

int
fd_inflights_meta_match( fd_inflights_t * table,
                         ulong            nonce,
                         fd_inflight_t *  out ) {
  fd_inflight_key_t key[1];
  fd_inflight_key_init( key, AG_REPAIR_KIND_PARENT_FEC_COUNT, 0UL, 0UL, nonce, NULL ); /* only the nonce is key material for metadata kinds */
  return !!inflight_match( table, key, out );
}

void
fd_inflights_pop( fd_inflights_t * table,
                  fd_inflight_t *  out ) {
  fd_inflight_t * req = fd_inflight_dlist_ele_pop_head( table->outstanding_dl, table->pool );
  fd_inflight_map_ele_remove_fast( table->map, req, table->pool );
  *out = *req;

  /* A null record (nonce 0) was never sent, release it rather than
     parking it in the popped set. */
  if( FD_UNLIKELY( !req->key.nonce ) ) {
    fd_inflight_pool_ele_release( table->pool, req );
    return;
  }

  fd_inflight_map_ele_insert     ( table->popped_map, req, table->pool );
  fd_inflight_dlist_ele_push_tail( table->popped_dl,  req, table->pool );
  table->popped_cnt++;
}

#include <stdio.h>

void
fd_inflights_print( fd_inflight_dlist_t * dlist, fd_inflight_t * pool ) {

  printf("%-5s %-15s %-8s %-15s %-44s\n", "Kind", "Slot", "Idx", "Timestamp", "Peer");
  printf("%-5s %-15s %-8s %-15s %-44s\n",
          "-----", "---------------", "--------", "------------",
          "--------------------------------------------");
  for( fd_inflight_dlist_iter_t iter = fd_inflight_dlist_iter_fwd_init( dlist, pool );
       !fd_inflight_dlist_iter_done( iter, dlist, pool );
       iter = fd_inflight_dlist_iter_fwd_next( iter, dlist, pool ) ) {
    fd_inflight_t * req = fd_inflight_dlist_iter_ele( iter, dlist, pool );
    FD_BASE58_ENCODE_32_BYTES( req->pubkey.uc, peer );
    printf("%-5u %-15lu %-8u %-15lu %-44.44s\n", req->key.kind, req->key.slot, req->key.idx, (ulong)req->timestamp_ns / (ulong)1e6, peer );
  }
  printf("\n");
}
