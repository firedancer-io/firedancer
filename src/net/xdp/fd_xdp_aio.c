#include "fd_xdp_aio.h"
#include "../../util/fd_util.h"
#include "fd_xdp_private.h"

/* TODO this is already defined in fd_quic_common.h
   don't want that as dependency, so move into fd_net_util.h or similar */
#define FD_QUIC_POW2_ALIGN( x, a ) (((x)+((a)-1)) & (~((a)-1)))


/* callback used by the aio interface to forward data to the caller */
size_t
fd_xdp_aio_forward_cb( void * context, fd_aio_buffer_t * batch, size_t batch_sz );


/* get alignment and footprint */
size_t fd_xdp_aio_align( void ) {
  size_t align = alignof( fd_xdp_aio_t );
  align = fd_ulong_max( align, alignof( fd_xdp_frame_meta_t ) );
  align = fd_ulong_max( align, alignof( fd_aio_buffer_t ) );
  align = fd_ulong_max( align, alignof( ulong ) );
  return align;
}

size_t fd_xdp_aio_footprint( fd_xdp_t * xdp, size_t batch_sz ) {
  (void)xdp;
  size_t align = fd_xdp_aio_align();
  size_t offs  = FD_QUIC_POW2_ALIGN( sizeof( fd_xdp_aio_t ), align );
  offs += FD_QUIC_POW2_ALIGN( batch_sz * sizeof( fd_xdp_frame_meta_t ), align );
  offs += FD_QUIC_POW2_ALIGN( batch_sz * sizeof( fd_aio_buffer_t ), align );
  offs += FD_QUIC_POW2_ALIGN( xdp->config.tx_ring_size * sizeof( ulong ), align );

  return offs;
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
fd_xdp_aio_new( void * mem, fd_xdp_t * xdp, size_t batch_sz ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "fd_xdp_aio_new called without memory to use" ));
  }

  if( FD_UNLIKELY( !xdp ) ) {
    FD_LOG_ERR(( "fd_xdp_aio_new called without an xdp instance to use" ));
  }

  size_t  offs  = 0;
  uchar * base  = (uchar*)mem;
  size_t  align = fd_xdp_aio_align();
  size_t  fp    = fd_xdp_aio_footprint( xdp, batch_sz );

  memset( mem, 0, fp );

  fd_xdp_aio_t * xdp_aio = (fd_xdp_aio_t*)( base + offs );

  offs += FD_QUIC_POW2_ALIGN( sizeof( fd_xdp_aio_t ), align );
  fd_xdp_frame_meta_t * meta = (fd_xdp_frame_meta_t*)( base + offs );

  offs += FD_QUIC_POW2_ALIGN( batch_sz * sizeof( fd_xdp_frame_meta_t ), align );
  fd_aio_buffer_t * aio_batch = (fd_aio_buffer_t*)( base + offs );

  offs += FD_QUIC_POW2_ALIGN( batch_sz * sizeof( fd_aio_buffer_t ), align );
  ulong * tx_stack = (ulong*)( base + offs );

  /* initialize the members */
  xdp_aio->xdp            = xdp;
  /* xdp_aio->ingress */
  /* xdp_aio->egress */
  xdp_aio->rx_offs        = 0;
  xdp_aio->tx_offs        = xdp->config.rx_ring_size;
  xdp_aio->frame_mem      = xdp->config.frame_memory;
  xdp_aio->batch_sz       = batch_sz;
  xdp_aio->meta           = meta;
  xdp_aio->aio_batch      = aio_batch;
  xdp_aio->tx_stack       = tx_stack;
  xdp_aio->tx_stack_sz    = xdp->config.tx_ring_size;
  xdp_aio->tx_top         = 0;

  /* enqueue frames to rx ring for receive */
  size_t frame_offset = xdp_aio->rx_offs;
  size_t frame_size   = xdp->config.frame_size;
  for( size_t j = 0; j < xdp->config.rx_ring_size; ++j ) {
    size_t enq_cnt = fd_xdp_rx_enqueue( xdp, &frame_offset, 1u );
    frame_offset += frame_size;

    if( FD_UNLIKELY( !enq_cnt ) ) {
      FD_LOG_ERR(( "%s : unable to enqueue to rx ring", __func__ ));
    }
  }

  /* add all tx frames to the free stack */
  frame_offset = xdp_aio->tx_offs * frame_size;
  for( size_t j = 0; j < xdp->config.tx_ring_size; ++j ) {
    xdp_aio->tx_stack[xdp_aio->tx_top++] = frame_offset;
    frame_offset += frame_size;
  }

  /* set up egress callback */
  xdp_aio->egress.cb_receive = fd_xdp_aio_forward_cb;
  xdp_aio->egress.context    = (void*)xdp_aio;

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


void
fd_xdp_aio_service( fd_xdp_aio_t * xdp_aio ) {
  /* convenience */
  fd_xdp_t *            xdp        = xdp_aio->xdp;
  fd_aio_t *            ingress    = &xdp_aio->ingress;
  fd_xdp_frame_meta_t * meta       = xdp_aio->meta;
  fd_aio_buffer_t *     aio_batch  = xdp_aio->aio_batch;
  size_t                batch_sz   = xdp_aio->batch_sz;
  uchar *               frame_mem  = xdp_aio->frame_mem;

  /* try completing receives */
  size_t rx_avail = fd_xdp_rx_complete( xdp, meta, batch_sz );

  /* forward to aio */
  if( rx_avail ) {
    for( size_t j = 0; j < rx_avail; ++j ) {
      aio_batch[j] = (fd_aio_buffer_t){ frame_mem + meta[j].offset, meta[j].sz };
    }

    fd_aio_send( ingress, aio_batch, rx_avail );
    /* TODO frames may not all be processed at this point
       we should count them, and possibly buffer them */

    /* return frames to rx ring */
    size_t enq_rc = fd_xdp_rx_enqueue2( xdp, meta, rx_avail );
    if( FD_UNLIKELY( enq_rc < rx_avail ) ) {
      /* this should not be possible */
      FD_LOG_WARNING(( "%s : frames lost trying to replenish rx ring", __func__ ));
    }
  }

  /* any tx to complete? */
  size_t tx_completed = fd_xdp_tx_complete( xdp, xdp_aio->tx_stack + xdp_aio->tx_top, xdp_aio->tx_stack_sz - xdp_aio->tx_top );
  xdp_aio->tx_top += tx_completed;
}


void
fd_xdp_aio_tx_complete( fd_xdp_aio_t * xdp_aio ) {
  fd_xdp_t *     xdp     = xdp_aio->xdp;
  size_t tx_completed = fd_xdp_tx_complete( xdp, xdp_aio->tx_stack + xdp_aio->tx_top, xdp_aio->tx_stack_sz - xdp_aio->tx_top );
  xdp_aio->tx_top += tx_completed;
}


size_t
fd_xdp_aio_forward_cb( void *            context,
                       fd_aio_buffer_t * batch,
                       size_t            batch_sz ) {
  fd_xdp_aio_t * xdp_aio = (fd_xdp_aio_t*)context;
  fd_xdp_t *     xdp     = xdp_aio->xdp;

  fd_xdp_aio_tx_complete( xdp_aio );

  size_t                cap        = xdp_aio->batch_sz;  /* capacity of xdp_aio batch */
  uchar *               frame_mem  = xdp_aio->frame_mem; /* frame memory */
  size_t                frame_size = xdp->config.frame_size;
  fd_xdp_frame_meta_t * meta       = xdp_aio->meta;      /* frame metadata */

  size_t k = 0;
  for( size_t j = 0; j < batch_sz; ++j ) {
    /* find a buffer */
    if( FD_UNLIKELY( !xdp_aio->tx_top ) ) {
      /* none available */
      return j;
    }

    --xdp_aio->tx_top;
    size_t offset = xdp_aio->tx_stack[xdp_aio->tx_top];

    uchar const * data    = batch[j].data;
    size_t        data_sz = batch[j].data_sz;

    /* copy frame into tx memory */
    if( FD_UNLIKELY( batch[j].data_sz > frame_size ) ) {
      FD_LOG_ERR(( "%s : frame too large for xdp ring, dropping", __func__ ));
      /* fail */
    } else {
      memcpy( frame_mem + offset, data, data_sz );
      if( k == cap ) {
        size_t tx_tot = k;
        size_t sent   = 0;
        while(1) {
          sent += fd_xdp_tx_enqueue( xdp, meta + sent, k - sent );
          if( sent == tx_tot ) break;

          /* we didn't send all
             complete, then try again */

          fd_xdp_aio_tx_complete( xdp_aio );
        }

        k = 0;
      }

      meta[k] = (fd_xdp_frame_meta_t){ offset, (unsigned)data_sz, 0 };
      k++;
    }
  }

  /* any left to send? */
  if( k ) {
    fd_xdp_tx_enqueue( xdp, meta, k );
  }

  return batch_sz;
}

