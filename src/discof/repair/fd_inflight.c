#include "fd_inflight.h"

void *
fd_inflights_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong footprint = fd_inflights_footprint();

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_inflights_t * table = FD_SCRATCH_ALLOC_APPEND( l, fd_inflights_align(),      sizeof(fd_inflights_t) );
  void *           pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_pool_align(),  fd_inflight_pool_footprint(FD_INFLIGHT_REQ_MAX) );
  void *           map   = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_map_align(),   fd_inflight_map_footprint(FD_INFLIGHT_REQ_MAX) );
  void *           dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_inflight_dlist_align(), fd_inflight_dlist_footprint() );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_inflights_align() ) == (ulong)shmem + footprint );

  table->pool  = fd_inflight_pool_join ( fd_inflight_pool_new ( pool, FD_INFLIGHT_REQ_MAX    ) );
  table->map   = fd_inflight_map_join  ( fd_inflight_map_new  ( map,  FD_INFLIGHT_REQ_MAX, 0 ) );
  table->dlist = fd_inflight_dlist_join( fd_inflight_dlist_new( dlist ) );

  FD_TEST( table->pool );
  FD_TEST( table->map );
  FD_TEST( table->dlist );

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
    FD_LOG_WARNING(( "misaligned inflighttable" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( table );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "inflight table must be part of a workspace" ));
    return NULL;
  }

  return (fd_inflights_t *)shmem;
}

void
fd_inflights_request_insert( fd_inflights_t * table, ulong nonce, fd_pubkey_t const * pubkey ) {
  if( FD_UNLIKELY( !fd_inflight_pool_free( table->pool ) ) ) {
    fd_inflight_t * evict = fd_inflight_dlist_ele_pop_head( table->dlist, table->pool );
    fd_inflight_map_ele_remove( table->map, &evict->nonce, NULL, table->pool );
    fd_inflight_pool_ele_release( table->pool, evict );
  }

  fd_inflight_t * inflight_req = fd_inflight_pool_ele_acquire( table->pool );
  inflight_req->nonce        = nonce;
  inflight_req->timestamp_ns = fd_log_wallclock();
  inflight_req->pubkey       = *pubkey;

  fd_inflight_map_ele_insert( table->map, inflight_req, table->pool );
  fd_inflight_dlist_ele_push_tail( table->dlist, inflight_req, table->pool );
}

long
fd_inflights_request_remove( fd_inflights_t * table, ulong nonce, fd_pubkey_t * peer_out ) {
  fd_inflight_t * inflight_req = fd_inflight_map_ele_remove( table->map, &nonce, NULL, table->pool );
  if( FD_LIKELY( inflight_req ) ) {
    long now = fd_log_wallclock();
    long rtt = now - inflight_req->timestamp_ns;

    *peer_out = inflight_req->pubkey;
    /* Remove the element from the inflight table */
    fd_inflight_map_ele_remove  ( table->map, &nonce, NULL, table->pool );
    fd_inflight_dlist_ele_remove( table->dlist, inflight_req, table->pool );
    fd_inflight_pool_ele_release( table->pool, inflight_req );
    return rtt;
  }
  return 0;
}

fd_inflight_t *
fd_inflights_request_query( fd_inflights_t * table, ulong nonce ) {
  return fd_inflight_map_ele_query( table->map, &nonce, NULL, table->pool );
}
