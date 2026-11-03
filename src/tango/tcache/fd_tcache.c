#include "fd_tcache.h"

ulong
fd_tcache_align( void ) {
  return FD_TCACHE_ALIGN;
}

ulong
fd_tcache_footprint( ulong depth,
                     ulong map_cnt ) {
  if( !map_cnt ) map_cnt = fd_tcache_map_cnt_default( depth ); /* use default */

  if( FD_UNLIKELY( (!depth) | (depth>UINT_MAX) | (map_cnt<(depth+2UL)) | (!fd_ulong_is_pow2( map_cnt )) ) ) return 0UL; /* Invalid depth / max_cnt */

  if( FD_UNLIKELY( map_cnt>(ULONG_MAX/sizeof(uint)) ) ) return 0UL; /* overflow */
  ulong cnt = (4UL+depth)*sizeof(ulong); /* depth<=UINT_MAX, no overflow */
  cnt += map_cnt*sizeof(uint); if( FD_UNLIKELY( cnt<map_cnt*sizeof(uint) ) ) return 0UL; /* overflow */
  ulong footprint = fd_ulong_align_up( cnt, FD_TCACHE_ALIGN ); if( FD_UNLIKELY( footprint<cnt ) ) return 0UL; /* overflow */
  return footprint;
}

void *
fd_tcache_new( void * shmem,
               ulong  depth,
               ulong  map_cnt ) {
  if( !map_cnt ) map_cnt = fd_tcache_map_cnt_default( depth ); /* use default */

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_tcache_footprint( depth, map_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad depth (%lu) and/or map_cnt (%lu)", depth, map_cnt ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  fd_tcache_t * tcache = (fd_tcache_t *)shmem;

  tcache->depth   = depth;
  tcache->map_cnt = map_cnt;
  tcache->oldest  = fd_tcache_reset( fd_tcache_ring_laddr( tcache ), depth, fd_tcache_map_laddr( tcache ), map_cnt );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tcache->magic ) = FD_TCACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_tcache_t *
fd_tcache_join( void * _tcache ) {

  if( FD_UNLIKELY( !_tcache ) ) {
    FD_LOG_WARNING(( "NULL _tcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_tcache, fd_tcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned _tcache" ));
    return NULL;
  }

  fd_tcache_t * tcache = (fd_tcache_t *)_tcache;
  if( FD_UNLIKELY( tcache->magic!=FD_TCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return tcache;
}

void *
fd_tcache_leave( fd_tcache_t * tcache ) {

  if( FD_UNLIKELY( !tcache ) ) {
    FD_LOG_WARNING(( "NULL tcache" ));
    return NULL;
  }

  return (void *)tcache;
}

void *
fd_tcache_delete( void * _tcache ) {

  if( FD_UNLIKELY( !_tcache ) ) {
    FD_LOG_WARNING(( "NULL _tcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_tcache, fd_tcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned _tcache" ));
    return NULL;
  }

  fd_tcache_t * tcache = (fd_tcache_t *)_tcache;
  if( FD_UNLIKELY( tcache->magic != FD_TCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tcache->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return _tcache;
}

