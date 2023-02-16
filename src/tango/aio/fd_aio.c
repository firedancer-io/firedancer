#include "fd_aio.h"

void *
fd_aio_new( void *        mem,
            void *        ctx,
            fd_aio_recv_t recv ) {
  if( FD_UNLIKELY( !mem || !recv ) )
    return NULL;

  fd_aio_t * aio = (fd_aio_t *)mem;
  aio->ctx  = ctx;
  aio->recv = recv;
  return (void *)aio;
}

fd_aio_t *
fd_aio_join( void * _aio ) {
  fd_aio_t * aio = (fd_aio_t *)_aio;

  if( FD_UNLIKELY( !aio || !aio->recv ) )
    return NULL;

  return (fd_aio_t *)_aio;
}

void *
fd_aio_delete( void * _aio ) {
  if( FD_UNLIKELY( !_aio ) )
    return NULL;

  fd_aio_t * aio = (fd_aio_t *)_aio;
  memset( aio, 0, sizeof(fd_aio_t) );

  return _aio;
}
