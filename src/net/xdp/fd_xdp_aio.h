#ifndef HEADER_fd_xdp_aio_h
#define HEADER_fd_xdp_aio_h

#include "fd_xdp.h"
#include "../aio/fd_aio.h"

struct fd_xdp_aio {
  fd_xdp_t *            xdp;
  fd_aio_t              ingress;     /* from outside to user */
  fd_aio_t              egress;      /* from user to outside */

  size_t                rx_offs;     /* frame offset in frame memory to start of rx frames */
  size_t                tx_offs;     /* frame offset in frame memory to start of tx frames */

  uchar *               frame_mem;   /* frame memory */
  size_t                batch_sz;    /* the max size of any batch */
  fd_xdp_frame_meta_t * meta;        /* xdp metadata for handling batches */
  fd_aio_buffer_t *     aio_batch;   /* aio metadata for handling batches */

  ulong *               tx_stack;    /* stack of unused tx frames */
  size_t                tx_stack_sz; /* stack of unused tx frames */
  size_t                tx_top;      /* top of stack. Also represents the number
                                          of items on the stack */
};

typedef struct fd_xdp_aio fd_xdp_aio_t;

FD_PROTOTYPES_BEGIN

/* get alignment and footprint */
size_t fd_xdp_aio_align( void );
size_t fd_xdp_aio_footprint( fd_xdp_t * xdp, size_t batch_sz );


/* create a new xdp_aio instance
   this wraps fd_xdp_t for use in aio interfaces

   args
     mem        the memory to use for the instance
                  must be aligned consistent with fd_xdp_aio_align()
                  and be at least fd_xdp_aio_footprint(...) bytes
     xdp        the existing fully initialized xdp to be wrapped
     batch_sz   the max number of buffers to handle at once

   returns
     the newly created fd_xdp_aio_t instance */
fd_xdp_aio_t *
fd_xdp_aio_new( void * mem, fd_xdp_t * xdp, size_t batch_sz );


/* frees any resources associated withe the xdp_aio instance in question */
void
fd_xdp_aio_delete( fd_xdp_aio_t * xdp_aio );


/* obtain the aio instance for sending data out to the network via xdp */
fd_aio_t *
fd_xdp_aio_egress_get( fd_xdp_aio_t * xdp_aio );


/* set the aio instance for receiving data from the network via xdp */
void
fd_xdp_aio_ingress_set( fd_xdp_aio_t * xdp_aio, fd_aio_t * aio );


FD_PROTOTYPES_END

#endif // HEADER_fd_xdp_aio_h

