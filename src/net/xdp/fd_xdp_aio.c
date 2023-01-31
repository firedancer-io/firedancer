#include "fd_xdp_aio.h"
#include "../../util/fd_util.h"


/* callback used by the aio interface to deliver data to the caller */
size_t
fd_xdp_aio_recv_cb( void * context, fd_aio_buffer_t * batch, size_t batch_sz );


/* get alignment and footprint */
size_t fd_xdp_aio_align( void ) {
  return alignof( fd_xdp_aio_t );
}

size_t fd_xdp_aio_footprint( fd_xdp_t * xdp ) {
  (void)xdp;
  return sizeof( fd_xdp_aio_t );
}


/* create a new xdp_aio instance
   this wraps fd_xdp_t for use in aio interfaces

   args
     mem        the memory to use for the instance
                  must be aligned consistent with fd_xdp_aio_align()
                  and be at least fd_xdp_aio_footprint(...) bytes
     xdp        the existing fully initialized xdp to be wrapped

   returns
     the newly created fd_xdp_aio_t instance */
fd_xdp_aio_t *
fd_xdp_aio_new( void * mem, fd_xdp_t * xdp ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "fd_xdp_aio_new called without memory to use" ));
  }

  if( FD_UNLIKELY( !xdp ) ) {
    FD_LOG_ERR(( "fd_xdp_aio_new called without an xdp instance to use" ));
  }

  fd_xdp_aio_t * xdp_aio = (fd_xdp_aio_t*)mem;

  memset( xdp_aio, 0, sizeof( *xdp_aio ) );

  /* initialize the members */
  xdp_aio->xdp            = xdp;

  return xdp_aio;
}


/* frees any resources associated withe the xdp_aio instance in question */
void
fd_xdp_aio_delete( fd_xdp_aio_t * xdp_aio ) {
  memset( xdp_aio, 0, sizeof( * xdp_aio ) );
}


/* obtain the aio instance for sending data out to the network via xdp */
fd_aio_t *
fd_xdp_aio_egress_get( fd_xdp_aio_t * xdp_aio ) {
  return &xdp_aio->egress;
}


/* set the aio instance for receiving data from the network via xdp */
void
fd_xdp_aio_ingress_set( fd_xdp_aio_t * xdp_aio, fd_aio_t * aio ) {
  xdp_aio->ingress = *aio;
}

