#include "fd_aio.h"

/* These are currently stubs in anticipation of future AIO
   functionality. */

ulong
fd_aio_align( void ) {
  return FD_AIO_ALIGN;
}

ulong
fd_aio_footprint( void ) {
  return FD_AIO_FOOTPRINT;
}

void *
fd_aio_new( void *             shmem,
            void *             ctx,
            fd_aio_send_func_t send_func ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !send_func ) ) {
    FD_LOG_WARNING(( "NULL send_func" ));
    return NULL;
  }

  fd_aio_t * aio = (fd_aio_t *)shmem;

  aio->ctx       = ctx;
  aio->send_func = send_func;

  return (void *)aio;
}

fd_aio_t *
fd_aio_join( void * shaio ) {
  if( FD_UNLIKELY( !shaio ) ) {
    FD_LOG_WARNING(( "NULL shaio" ));
    return NULL;
  }
  return (fd_aio_t *)shaio;
}

void *
fd_aio_leave( fd_aio_t * aio ) {
  if( FD_UNLIKELY( !aio ) ) {
    FD_LOG_WARNING(( "NULL aio" ));
    return NULL;
  }
  return (void *)aio;
}

void *
fd_aio_delete( void * shaio ) {
  if( FD_UNLIKELY( !shaio ) ) {
    FD_LOG_WARNING(( "NULL shaio" ));
    return NULL;
  }
  return shaio;
}

char const *
fd_aio_strerror( int err ) {
  switch( err ) {
  case FD_AIO_SUCCESS:   return "success";
  case FD_AIO_ERR_INVAL: return "bad input arguments";
  case FD_AIO_ERR_AGAIN: return "try again later";
  default: break;
  }
  return "unknown";
}

