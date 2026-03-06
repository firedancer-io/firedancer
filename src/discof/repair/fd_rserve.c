#include "fd_rserve.h"

ulong
fd_rserve_footprint( ulong ping_cache_entries ) {
  if( FD_UNLIKELY( !ping_cache_entries ) ) return 0UL;

  int lg_entries  = fd_ulong_find_msb( fd_ulong_pow2_up( ping_cache_entries ) );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rserve_t), sizeof(fd_rserve_t) );
  l = FD_LAYOUT_APPEND( l, ping_cache_align(),   ping_cache_footprint( lg_entries ) );
  return FD_LAYOUT_FINI( l, fd_rserve_align() );
}

void *
fd_rserve_new( void * shmem,
               ulong  ping_cache_entries,
               ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_rserve_footprint( ping_cache_entries );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ping cache size (%lu)", ping_cache_entries ));
    return NULL;
  }

  int lg_entries  = fd_ulong_find_msb( fd_ulong_pow2_up( ping_cache_entries ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void * rserve_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rserve_t), sizeof(fd_rserve_t) );
  void * ping_cache_mem = FD_SCRATCH_ALLOC_APPEND( l, ping_cache_align(), ping_cache_footprint( lg_entries ) );

  fd_rserve_t * rserve = (fd_rserve_t *)rserve_mem;
  rserve->ping_cache = ping_cache_new( ping_cache_mem, lg_entries, seed );

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_rserve_align() )==(ulong)shmem + footprint );

  return shmem;
}

fd_rserve_t *
fd_rserve_join( void * shrserve ) {
  if( FD_UNLIKELY( !shrserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shrserve, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned rserve" ));
    return NULL;
  }

  fd_rserve_t * rserve = (fd_rserve_t *)shrserve;
  rserve->ping_cache = ping_cache_join( rserve->ping_cache );

  return (fd_rserve_t *)rserve;
}

void *
fd_rserve_leave( fd_rserve_t const * rserve ) {
  if( FD_UNLIKELY( !rserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  return (void *)rserve;
}

void *
fd_rserve_delete( void * rserve ) {
  if( FD_UNLIKELY( !rserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rserve, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned rserve" ));
    return NULL;
  }

  return rserve;
}
