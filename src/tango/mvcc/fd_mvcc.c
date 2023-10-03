#include "fd_mvcc.h"

ulong
fd_mvcc_align( void ) {
  return FD_MVCC_ALIGN;
}

ulong
fd_mvcc_footprint( ulong app_sz ) {
  if( FD_UNLIKELY( app_sz > (ULONG_MAX-191UL) ) ) return 0UL; /* overflow */
  return FD_MVCC_FOOTPRINT( app_sz );
}

void *
fd_mvcc_new( void * shmem,
             ulong  app_sz ) {
  fd_mvcc_t * mvcc = (fd_mvcc_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_mvcc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_mvcc_footprint( app_sz );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad app_sz (%lu)", app_sz ));
    return NULL;
  }

  fd_memset( mvcc, 0, footprint );

  mvcc->app_sz     = app_sz;
  mvcc->version    = 0UL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( mvcc->magic ) = FD_MVCC_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)mvcc;
}

fd_mvcc_t *
fd_mvcc_join( void * shmvcc ) {

  if( FD_UNLIKELY( !shmvcc ) ) {
    FD_LOG_WARNING(( "NULL shmvcc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmvcc, fd_mvcc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmvcc" ));
    return NULL;
  }

  fd_mvcc_t * mvcc = (fd_mvcc_t *)shmvcc;

  if( FD_UNLIKELY( mvcc->magic!=FD_MVCC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return mvcc;
}

void *
fd_mvcc_leave( fd_mvcc_t const * mvcc ) {

  if( FD_UNLIKELY( !mvcc ) ) {
    FD_LOG_WARNING(( "NULL mvcc" ));
    return NULL;
  }

  return (void *)mvcc; /* Kinda ugly const cast */
}

void *
fd_mvcc_delete( void * shmvcc ) {

  if( FD_UNLIKELY( !shmvcc ) ) {
    FD_LOG_WARNING(( "NULL shmvcc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmvcc, fd_mvcc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmvcc" ));
    return NULL;
  }

  fd_mvcc_t * mvcc = (fd_mvcc_t *)shmvcc;

  if( FD_UNLIKELY( mvcc->magic!=FD_MVCC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( mvcc->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)mvcc;
}
