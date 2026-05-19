#include "fd_reqlim.h"

void *
fd_reqlim_new( void * shmem, ulong dedup_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_reqlim_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_reqlim_footprint( dedup_max );
  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_reqlim_t * dedup    = FD_SCRATCH_ALLOC_APPEND( l, fd_reqlim_align(),      sizeof(fd_reqlim_t)                      );
  void *       map      = FD_SCRATCH_ALLOC_APPEND( l, fd_reqlim_map_align(),  fd_reqlim_map_footprint ( dedup_max )    );
  void *       pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_reqlim_pool_align(), fd_reqlim_pool_footprint( dedup_max )    );
  void *       lru      = FD_SCRATCH_ALLOC_APPEND( l, fd_reqlim_lru_align(),  fd_reqlim_lru_footprint()                );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_reqlim_align() ) == (ulong)shmem + footprint );

  dedup->map  = fd_reqlim_map_new ( map,  dedup_max, seed );
  dedup->pool = fd_reqlim_pool_new( pool, dedup_max       );
  dedup->lru  = fd_reqlim_lru_new ( lru                   );

  return shmem;
}

fd_reqlim_t *
fd_reqlim_join( void * shdedup ) {
  fd_reqlim_t * dedup = (fd_reqlim_t *)shdedup;

  if( FD_UNLIKELY( !dedup ) ) {
    FD_LOG_WARNING(( "NULL dedup" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)dedup, fd_reqlim_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned dedup" ));
    return NULL;
  }

  dedup->map  = fd_reqlim_map_join ( dedup->map  );
  dedup->pool = fd_reqlim_pool_join( dedup->pool );
  dedup->lru  = fd_reqlim_lru_join ( dedup->lru  );

  return dedup;
}

void *
fd_reqlim_leave( fd_reqlim_t const * dedup ) {

  if( FD_UNLIKELY( !dedup ) ) {
    FD_LOG_WARNING(( "NULL dedup" ));
    return NULL;
  }

  return (void *)dedup;
}

void *
fd_reqlim_delete( void * dedup ) {

  if( FD_UNLIKELY( !dedup ) ) {
    FD_LOG_WARNING(( "NULL dedup" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)dedup, fd_reqlim_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned dedup" ));
    return NULL;
  }

  return dedup;
}

/* dedup_evict evicts the least recently used element from the cache. */

static void
dedup_evict( fd_reqlim_t * dedup ) {
  fd_reqlim_ele_t * ele = fd_reqlim_lru_ele_pop_head( dedup->lru, dedup->pool );
  fd_reqlim_map_ele_remove( dedup->map, &ele->key, NULL, dedup->pool );
  fd_reqlim_pool_ele_release( dedup->pool, ele );
}

int
fd_reqlim_next( fd_reqlim_t * dedup, ulong key, long now ) {
  fd_reqlim_ele_t * ele = fd_reqlim_map_ele_query( dedup->map, &key, NULL, dedup->pool );
  if( FD_UNLIKELY( !ele ) ) {
    if( FD_UNLIKELY( !fd_reqlim_pool_free( dedup->pool ) ) ) dedup_evict( dedup );
    ele         = fd_reqlim_pool_ele_acquire( dedup->pool );
    ele->key    = key;
    ele->req_ts = 0;
    fd_reqlim_map_ele_insert   ( dedup->map, ele, dedup->pool );
    fd_reqlim_lru_ele_push_tail( dedup->lru, ele, dedup->pool );
  }
  if( FD_LIKELY( now < ele->req_ts + (long)FD_REQLIM_DEDUP_TIMEOUT ) ) {
    fd_reqlim_lru_ele_remove   ( dedup->lru, ele, dedup->pool );
    fd_reqlim_lru_ele_push_tail( dedup->lru, ele, dedup->pool );
    return 1;
  }
  ele->req_ts = now;
  return 0;
}

int
fd_reqlim_query( fd_reqlim_t const * dedup, ulong key, long now ) {
  fd_reqlim_ele_t const * ele = fd_reqlim_map_ele_query_const( dedup->map, &key, NULL, dedup->pool );
  if( FD_LIKELY( ele && now < ele->req_ts + (long)FD_REQLIM_DEDUP_TIMEOUT ) ) {
    return 1;
  }
  return 0;
}
