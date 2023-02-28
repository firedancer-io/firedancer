#if !defined(__linux__) || !FD_HAS_LIBBPF
#error "fd_xsk_aio requires Linux operating system with XDP support"
#endif

#include "../../util/fd_util.h"
#include "fd_xsk_private.h"
#include "fd_xsk_aio_private.h"

/* Forward declaration */
static ulong
fd_xsk_aio_send( void *            ctx,
                 fd_aio_buf_t *    batch,
                 ulong             batch_cnt );

ulong
fd_xsk_aio_align( void ) {
  return FD_XSK_AIO_ALIGN;
}

ulong
fd_xsk_aio_footprint( ulong tx_depth,
                      ulong batch_cnt ) {
  ulong sz =       1UL*sizeof( fd_xsk_aio_t        )
           + batch_cnt*sizeof( fd_xsk_frame_meta_t )
           + batch_cnt*sizeof( fd_aio_buf_t        )
           + tx_depth *sizeof( ulong               );

  sz = fd_ulong_align_up( sz, FD_XSK_AIO_ALIGN );
  /* assert( sz%FD_XSK_AIO_ALIGN==0UL ) */
  return sz;
}

void *
fd_xsk_aio_new( void * mem,
                ulong  tx_depth,
                ulong  batch_cnt ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_xsk_aio_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( tx_depth==0UL ) ) {
    FD_LOG_WARNING(( "zero tx_depth" ));
    return NULL;
  }

  if( FD_UNLIKELY( batch_cnt==0UL ) ) {
    FD_LOG_WARNING(( "zero batch_cnt" ));
    return NULL;
  }

  ulong footprint = fd_xsk_aio_footprint( tx_depth, batch_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for tx_depth (%lu), batch_cnt (%lu)",
                      tx_depth, batch_cnt ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  /* Allocate objects in fd_xsk_aio_t */

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)mem;

  /* Assumes alignment of `fd_xsk_aio_t` matches alignment of
     `fd_xsk_frame_meta_t` and `fd_aio_buf_t`. */

  ulong meta_off     =                       sizeof(fd_xsk_aio_t       );
  ulong batch_off    = meta_off  + batch_cnt*sizeof(fd_xsk_frame_meta_t);
  ulong tx_stack_off = batch_off + batch_cnt*sizeof(fd_aio_buf_t       );

  xsk_aio->batch_cnt    = batch_cnt;
  xsk_aio->tx_depth     = tx_depth;
  xsk_aio->meta_off     = meta_off;
  xsk_aio->batch_off    = batch_off;
  xsk_aio->tx_stack_off = tx_stack_off;

  /* Mark object as valid */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( xsk_aio->magic ) = FD_XSK_AIO_MAGIC;
  FD_COMPILER_MFENCE();

  return xsk_aio;
}


fd_xsk_aio_t *
fd_xsk_aio_join( void *     shxsk_aio,
                 fd_xsk_t * xsk ) {

  if( FD_UNLIKELY( !shxsk_aio ) ) {
    FD_LOG_WARNING(( "NULL shxsk_aio" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shxsk_aio, fd_xsk_aio_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shxsk_aio" ));
    return NULL;
  }

  /* Validate memory layout */

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)shxsk_aio;

  if( FD_UNLIKELY( xsk_aio->magic!=FD_XSK_AIO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic (not an fd_xsk_aio_t?)" ));
    return NULL;
  }

  if( FD_UNLIKELY( xsk_aio->xsk ) ) {
    FD_LOG_WARNING(( "xsk_aio in an unclean state, resetting" ));
    xsk_aio->xsk = NULL;
    /* continue */
  }

  if( FD_UNLIKELY( xsk->tx_depth != xsk_aio->tx_depth ) ) {
    FD_LOG_WARNING(( "incompatible xsk (tx_depth=%lu) and xsk_aio (tx_depth=%lu)",
                     xsk->tx_depth, xsk_aio->tx_depth ));
    return NULL;
  }

  /* Reset state */

  xsk_aio->xsk = xsk;
  fd_aio_delete( &xsk_aio->rx );
  fd_aio_delete( &xsk_aio->tx );

  xsk_aio->frame_mem   = fd_xsk_umem_area( xsk );
  xsk_aio->rx_off      = 0;
  xsk_aio->tx_off      = xsk->rx_depth;
  xsk_aio->tx_stack    = fd_xsk_aio_tx_stack( xsk_aio );
  xsk_aio->tx_stack_sz = xsk_aio->tx_depth;
  xsk_aio->tx_top      = 0;

  /* Set up TX callback (local address) */

  fd_aio_t * rx = fd_aio_join( fd_aio_new( &xsk_aio->rx, xsk_aio, fd_xsk_aio_send ) );
  if( FD_UNLIKELY( !rx ) ) {
    FD_LOG_WARNING(( "Failed to join rx aio" ));
    return NULL;
  }

  /* Enqueue frames to RX ring for receive (via fill ring) */

  ulong frame_off = xsk_aio->rx_off;
  ulong frame_sz  = xsk->frame_sz;
  for( ulong j=0; j<xsk->rx_depth; j++ ) {
    ulong enq_cnt =  fd_xsk_rx_enqueue( xsk, &frame_off, 1U );
    frame_off     += frame_sz;

    if( FD_UNLIKELY( !enq_cnt ) ) {
      FD_LOG_WARNING(( "fd_xsk_rx_enqueue() failed, was fd_xsk_t properly flushed?" ));
      return NULL;
    }
  }

  /* Add all TX frames to the free stack */

  frame_off = xsk_aio->tx_off*frame_sz;
  for( ulong j=0; j<xsk->tx_depth; j++ ) {
    xsk_aio->tx_stack[xsk_aio->tx_top] =  frame_off;
                      xsk_aio->tx_top++;
    frame_off                          += frame_sz;
  }

  return (fd_xsk_aio_t *)xsk_aio;
}


void *
fd_xsk_aio_leave( fd_xsk_aio_t * xsk_aio ) {

  if( FD_UNLIKELY( !xsk_aio ) ) {
    FD_LOG_WARNING(( "NULL xsk_aio" ));
    return NULL;
  }

  xsk_aio->xsk = NULL;

  fd_aio_leave( fd_aio_delete( &xsk_aio->rx ) );
  fd_aio_leave( fd_aio_delete( &xsk_aio->tx ) );

  return (void *)xsk_aio;
}

void *
fd_xsk_aio_delete( void * shxsk_aio ) {

  if( FD_UNLIKELY( !shxsk_aio ) ) {
    FD_LOG_WARNING(( "NULL shxsk_aio" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shxsk_aio, fd_xsk_aio_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned xsk_aio" ));
    return NULL;
  }

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)shxsk_aio;

  if( FD_UNLIKELY( xsk_aio->magic!=FD_XSK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( xsk_aio->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)xsk_aio;
}


fd_aio_t *
fd_xsk_aio_get_tx( fd_xsk_aio_t * xsk_aio ) {
  return &xsk_aio->tx;
}

void
fd_xsk_aio_set_rx( fd_xsk_aio_t * xsk_aio,
                   fd_aio_t *     aio ) {
  fd_memcpy( &xsk_aio->rx, aio, sizeof(fd_aio_t) );
}


void
fd_xsk_aio_housekeep( fd_xsk_aio_t * xsk_aio ) {
  fd_xsk_t *            xsk         = xsk_aio->xsk;
  fd_aio_t *            ingress     = &xsk_aio->rx;
  fd_xsk_frame_meta_t * meta        = fd_xsk_aio_meta ( xsk_aio );
  fd_aio_buf_t *        aio_batch   = fd_xsk_aio_batch( xsk_aio );
  ulong                 batch_sz    = xsk_aio->batch_cnt;
  ulong                 frame_laddr = (ulong)fd_xsk_umem_laddr( xsk_aio->xsk );

  /* try completing receives */
  ulong rx_avail = fd_xsk_rx_complete( xsk, meta, batch_sz );

  /* forward to aio */
  if( rx_avail ) {
    for( ulong j=0; j<rx_avail; j++ ) {
      aio_batch[j] = (fd_aio_buf_t) {
        .data    = (void *)(frame_laddr + meta[j].off),
        .data_sz = meta[j].sz
      };
    }

    fd_aio_send( ingress, aio_batch, rx_avail );
    /* TODO frames may not all be processed at this point
       we should count them, and possibly buffer them */

    /* return frames to rx ring */
    ulong enq_rc = fd_xsk_rx_enqueue2( xsk, meta, rx_avail );
    if( FD_UNLIKELY( enq_rc < rx_avail ) ) {
      /* this should not be possible */
      FD_LOG_WARNING(( "frames lost trying to replenish rx ring" ));
    }
  }

  /* any tx to complete? */
  ulong tx_completed = fd_xsk_tx_complete( xsk,
                                           xsk_aio->tx_stack    + xsk_aio->tx_top,
                                           xsk_aio->tx_stack_sz - xsk_aio->tx_top );
  xsk_aio->tx_top += tx_completed;
}


void
fd_xsk_aio_tx_complete( fd_xsk_aio_t * xsk_aio ) {
  ulong tx_completed = fd_xsk_tx_complete( xsk_aio->xsk,
                                           xsk_aio->tx_stack    + xsk_aio->tx_top,
                                           xsk_aio->tx_stack_sz - xsk_aio->tx_top );
  xsk_aio->tx_top += tx_completed;
}


/* fd_xsk_aio_send is an aio callback that transmits the given batch of
   packets through the XSK. */
static ulong
fd_xsk_aio_send( void *         ctx,
                 fd_aio_buf_t * batch,
                 ulong          batch_cnt ) {
  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t*)ctx;
  fd_xsk_t *     xsk     = xsk_aio->xsk;

  /* Check if any previous send operations completed
     to reclaim transmit frames. */
  fd_xsk_aio_tx_complete( xsk_aio );

  ulong                 cap        = xsk_aio->batch_cnt; /* capacity of xsk_aio batch */
  uchar *               frame_mem  = xsk_aio->frame_mem; /* frame memory */
  ulong                 frame_size = xsk->frame_sz;
  fd_xsk_frame_meta_t * meta       = fd_xsk_aio_meta( xsk_aio );  /* frame metadata */

  ulong k=0;
  for( ulong j=0; j<batch_cnt; ++j ) {
    /* find a buffer */
    if( FD_UNLIKELY( !xsk_aio->tx_top ) ) {
      /* none available */
      return j;
    }

    --xsk_aio->tx_top;
    ulong offset = xsk_aio->tx_stack[xsk_aio->tx_top];

    uchar const * data    = batch[j].data;
    ulong         data_sz = batch[j].data_sz;

    /* copy frame into tx memory */
    if( FD_UNLIKELY( batch[j].data_sz > frame_size ) ) {
      FD_LOG_ERR(( "%s : frame too large for xsk ring, dropping", __func__ ));
      /* fail */
    } else {
      fd_memcpy( frame_mem + offset, data, data_sz );
      if( k == cap ) {
        ulong tx_tot = k;
        ulong sent   = 0;
        while(1) {
          sent += fd_xsk_tx_enqueue( xsk, meta + sent, k - sent );
          if( sent == tx_tot ) break;

          /* we didn't send all
             complete, then try again */

          fd_xsk_aio_tx_complete( xsk_aio );
        }

        k = 0;
      }

      meta[k] = (fd_xsk_frame_meta_t){ offset, (unsigned)data_sz, 0 };
      k++;
    }
  }

  /* any left to send? */
  if( k ) {
    fd_xsk_tx_enqueue( xsk, meta, k );
  }

  return batch_cnt;
}
