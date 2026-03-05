#include "fd_rserve.h"
#include "../../disco/store/fd_ledger.h"

void *
fd_rserve_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }


  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_rserve_footprint();
  fd_memset( shmem, 0, footprint );

  return shmem;
}

fd_rserve_t *
fd_rserve_join( void * shrserve ) {
  fd_rserve_t * rserve = (fd_rserve_t *)shrserve;

  if( FD_UNLIKELY( !rserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rserve, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned rserve" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( rserve );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "rserve must be part of a workspace" ));
    return NULL;
  }

  return rserve;
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
