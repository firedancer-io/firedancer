#include "fd_lru.h"
#include "fd_list.h"

#define DEPTH_OFFSET  (2UL)

ulong
fd_lru_align( void ) {
  return FD_LRU_ALIGN;
}

ulong
fd_lru_footprint( ulong depth,
                  ulong map_cnt ) {
  if( !map_cnt ) map_cnt = fd_lru_map_cnt_default( depth ); /* use default */

  if( FD_UNLIKELY( (!depth) | (map_cnt<(depth+2UL)) | (!fd_ulong_is_pow2( map_cnt )) ) ) return 0UL; /* Invalid depth / max_cnt */

  /* TODO overflow checks*/
  ulong footprint = sizeof(fd_lru_t);
  footprint += (depth + 1) * sizeof(fd_list_t);
  footprint += map_cnt * sizeof( ulong ); /* pointer-size */
  footprint = fd_ulong_align_up( footprint, fd_lru_align() );
  return footprint;
}

void *
fd_lru_new( void * shmem,
               ulong  depth,
               ulong  map_cnt ) {
  if( !map_cnt ) map_cnt = fd_lru_map_cnt_default( depth ); /* use default */

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_lru_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_lru_footprint( depth, map_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad depth (%lu) and/or map_cnt (%lu)", depth, map_cnt ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  fd_lru_t * lru = (fd_lru_t *)shmem;

  lru->depth   = depth;
  lru->free_top = 1UL;
  lru->map_cnt = map_cnt;
  fd_list_new( fd_lru_list_laddr( lru ), depth );

  // FD_LOG_HEXDUMP_NOTICE(("lru", lru, footprint));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( lru->magic ) = FD_LRU_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_lru_t *
fd_lru_join( void * _lru ) {

  if( FD_UNLIKELY( !_lru ) ) {
    FD_LOG_WARNING(( "NULL _lru" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_lru, fd_lru_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned _lru" ));
    return NULL;
  }

  fd_lru_t * lru = (fd_lru_t *)_lru;
  if( FD_UNLIKELY( lru->magic!=FD_LRU_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return lru;
}

void *
fd_lru_leave( fd_lru_t * lru ) {

  if( FD_UNLIKELY( !lru ) ) {
    FD_LOG_WARNING(( "NULL lru" ));
    return NULL;
  }

  return (void *)lru;
}

void *
fd_lru_delete( void * _lru ) {

  if( FD_UNLIKELY( !_lru ) ) {
    FD_LOG_WARNING(( "NULL _lru" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_lru, fd_lru_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned _lru" ));
    return NULL;
  }

  fd_lru_t * lru = (fd_lru_t *)_lru;
  if( FD_UNLIKELY( lru->magic != FD_LRU_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( lru->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return _lru;
}
