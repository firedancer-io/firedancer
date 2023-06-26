#if !defined(__linux__)
#error "fd_xsk_aio requires Linux operating system with XDP support"
#endif

#include "../../util/fd_util.h"
#include "fd_xsk_aio_private.h"

/* Forward declarations */
static int
fd_xsk_aio_send( void *                    ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush );

ulong
fd_xsk_aio_align( void ) {
  return FD_XSK_AIO_ALIGN;
}

FD_FN_CONST ulong
fd_xsk_aio_footprint( ulong tx_depth,
                      ulong pkt_cnt ) {
  if( FD_UNLIKELY( tx_depth==0UL ) ) return 0UL;
  if( FD_UNLIKELY( pkt_cnt ==0UL ) ) return 0UL;

  ulong sz =      1UL*sizeof( fd_xsk_aio_t        )
           +  pkt_cnt*sizeof( fd_xsk_frame_meta_t )
           +  pkt_cnt*sizeof( fd_aio_pkt_info_t   )
           + tx_depth*sizeof( ulong               );

  sz = fd_ulong_align_up( sz, FD_XSK_AIO_ALIGN );
  /* assert( sz%FD_XSK_AIO_ALIGN==0UL ) */
  return sz;
}

void *
fd_xsk_aio_new( void * mem,
                ulong  tx_depth,
                ulong  pkt_cnt ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_xsk_aio_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_xsk_aio_footprint( tx_depth, pkt_cnt );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for tx_depth (%lu), pkt_cnt (%lu)",
                      tx_depth, pkt_cnt ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  /* Allocate objects in fd_xsk_aio_t */

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)mem;

  /* Assumes alignment of `fd_xsk_aio_t` matches alignment of
     `fd_xsk_frame_meta_t` and `fd_aio_pkt_info_t`. */

  ulong meta_off     =                    sizeof(fd_xsk_aio_t       );
  ulong pkt_off      = meta_off + pkt_cnt*sizeof(fd_xsk_frame_meta_t);
  ulong tx_stack_off = pkt_off  + pkt_cnt*sizeof(fd_aio_pkt_info_t  );

  xsk_aio->pkt_depth    = pkt_cnt;
  xsk_aio->tx_depth     = tx_depth;
  xsk_aio->meta_off     = meta_off;
  xsk_aio->pkt_off      = pkt_off;
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

  if( FD_UNLIKELY( !xsk ) ) {
    FD_LOG_WARNING(( "NULL xsk" ));
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

  fd_xsk_params_t const * params = fd_xsk_get_params( xsk );

  if( FD_UNLIKELY( params->tx_depth != xsk_aio->tx_depth ) ) {
    FD_LOG_WARNING(( "incompatible xsk (tx_depth=%lu) and xsk_aio (tx_depth=%lu)",
                     params->tx_depth, xsk_aio->tx_depth ));
    return NULL;
  }

  /* Reset state */

  xsk_aio->xsk = xsk;
  fd_aio_delete( &xsk_aio->rx );
  fd_aio_delete( &xsk_aio->tx );

  xsk_aio->frame_mem      = fd_xsk_umem_laddr( xsk );
  xsk_aio->frame_sz       = params->frame_sz;
  xsk_aio->rx_off         = 0;
  xsk_aio->tx_off         = params->rx_depth;
  xsk_aio->tx_stack       = fd_xsk_aio_tx_stack( xsk_aio );
  xsk_aio->tx_stack_depth = params->tx_depth;
  xsk_aio->tx_top         = 0;

  /* Setup local TX */

  fd_aio_t * tx = fd_aio_join( fd_aio_new( &xsk_aio->tx, xsk_aio, fd_xsk_aio_send ) );
  if( FD_UNLIKELY( !tx ) ) {
    FD_LOG_WARNING(( "Failed to join local tx aio" ));
    return NULL;
  }

  /* Reset RX callback (laddr pointers to external object) */

  memset( &xsk_aio->rx, 0, sizeof(fd_aio_t) );

  /* Enqueue frames to RX ring for receive (via fill ring) */

  ulong frame_off = xsk_aio->rx_off;
  ulong frame_sz  = params->frame_sz;
  ulong rx_depth  = params->rx_depth;
  ulong tx_depth  = params->tx_depth;

  for( ulong j=0; j<rx_depth; j++ ) {
    ulong enq_cnt =  fd_xsk_rx_enqueue( xsk, &frame_off, 1U );
    frame_off     += frame_sz;

    if( FD_UNLIKELY( !enq_cnt ) ) {
      FD_LOG_WARNING(( "fd_xsk_rx_enqueue() failed, was fd_xsk_t properly flushed?" ));
      return NULL;
    }
  }

  /* Add all TX frames to the free stack */

  frame_off = xsk_aio->tx_off*frame_sz;
  for( ulong j=0; j<tx_depth; j++ ) {
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

  fd_aio_delete( fd_aio_leave( &xsk_aio->rx ) );
  fd_aio_delete( fd_aio_leave( &xsk_aio->tx ) );

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

  if( FD_UNLIKELY( xsk_aio->magic!=FD_XSK_AIO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( xsk_aio->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)xsk_aio;
}


fd_aio_t const *
fd_xsk_aio_get_tx( fd_xsk_aio_t const * xsk_aio ) {
  return &xsk_aio->tx;
}

void
fd_xsk_aio_set_rx( fd_xsk_aio_t *   xsk_aio,
                   fd_aio_t const * aio ) {
  fd_memcpy( &xsk_aio->rx, aio, sizeof(fd_aio_t) );
}


void
fd_xsk_aio_service( fd_xsk_aio_t * xsk_aio ) {
  fd_xsk_t *            xsk         = xsk_aio->xsk;
  fd_aio_t *            ingress     = &xsk_aio->rx;
  fd_xsk_frame_meta_t * meta        = fd_xsk_aio_meta( xsk_aio );
  fd_aio_pkt_info_t *   pkt         = fd_xsk_aio_pkts( xsk_aio );
  ulong                 pkt_depth   = xsk_aio->pkt_depth;
  ulong                 frame_laddr = (ulong)fd_xsk_umem_laddr( xsk_aio->xsk );

  /* try completing receives */
  ulong rx_avail = fd_xsk_rx_complete( xsk, meta, pkt_depth );

  /* forward to aio */
  if( rx_avail ) {
    for( ulong j=0; j<rx_avail; j++ ) {
      pkt[j] = (fd_aio_pkt_info_t) {
        .buf    = (void *)(frame_laddr + meta[j].off),
        .buf_sz = (ushort)meta[j].sz
      };
    }

    fd_aio_send( ingress, pkt, rx_avail, NULL, 1 );
    /* TODO frames may not all be processed at this point
       we should count them, and possibly buffer them */

    /* return frames to rx ring */
    ulong enq_rc = fd_xsk_rx_enqueue2( xsk, meta, rx_avail );
    if( FD_UNLIKELY( enq_rc < rx_avail ) ) {
      /* keep trying indefinitely */
      /* TODO consider adding a timeout */
      ulong j = enq_rc;
      while( rx_avail > j ) {
        ulong enq_rc = fd_xsk_rx_enqueue2( xsk, meta + j, rx_avail - j );
        j += enq_rc;
      }
    }
  }

  /* any tx to complete? */
  ulong tx_completed = fd_xsk_tx_complete( xsk,
                                           xsk_aio->tx_stack       + xsk_aio->tx_top,
                                           xsk_aio->tx_stack_depth - xsk_aio->tx_top );
  xsk_aio->tx_top += tx_completed;
}


void
fd_xsk_aio_tx_complete( fd_xsk_aio_t * xsk_aio ) {
  ulong tx_completed = fd_xsk_tx_complete( xsk_aio->xsk,
                                           xsk_aio->tx_stack       + xsk_aio->tx_top,
                                           xsk_aio->tx_stack_depth - xsk_aio->tx_top );
  xsk_aio->tx_top += tx_completed;
}


/* fd_xsk_aio_send is an aio callback that transmits the given batch of
   packets through the XSK. */
static int
fd_xsk_aio_send( void *                    ctx,
                 fd_aio_pkt_info_t const * pkt,
                 ulong                     pkt_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush ) {

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t*)ctx;
  fd_xsk_t *     xsk     = xsk_aio->xsk;

  if( FD_UNLIKELY( pkt_cnt==0UL ) ) {
    if( flush ) {
      fd_xsk_frame_meta_t meta[1] = {{0}};
      ulong sent_cnt = fd_xsk_tx_enqueue( xsk, meta, 0, 1 );
      (void)sent_cnt;
    }
    return FD_AIO_SUCCESS;
  }

  /* Check if any previous send operations completed
     to reclaim transmit frames. */
  fd_xsk_aio_tx_complete( xsk_aio );

  /* Refuse to send more packets than we have metadata frames */
  ulong       batch_cnt = pkt_cnt; /* Number of frames to attempt to send */
  ulong const pkt_depth = xsk_aio->pkt_depth;
  if( FD_UNLIKELY( batch_cnt>pkt_depth ) )
    batch_cnt = pkt_depth;

  /* Find UMEM and meta params */
  uchar *               frame_mem  = xsk_aio->frame_mem;          /* UMEM region     */
  ulong                 frame_sz   = xsk_aio->frame_sz;           /* UMEM frame sz   */
  fd_xsk_frame_meta_t * meta       = fd_xsk_aio_meta( xsk_aio );  /* frame meta heap */

  /* Number of packets pending fd_xsk_tx_enqueue */
  ulong pending_cnt=0;

  /* XSK send prepare loop.  Terminates when the largest possible tx
     batch has been formed.  meta[0..pkt_idx] is populated with frames
     to be handed off to fd_xsk_tx_enqueue. */
  ulong pkt_idx;
  for( pkt_idx=0; pkt_idx<batch_cnt; ++pkt_idx ) {
    /* Pop a TX frame from our stack */
    if( FD_UNLIKELY( !xsk_aio->tx_top ) )
      break;
    --xsk_aio->tx_top;
    ulong offset = xsk_aio->tx_stack[xsk_aio->tx_top];

    uchar const * data    = pkt[ pkt_idx ].buf;
    ulong         data_sz = pkt[ pkt_idx ].buf_sz;

    /* MTU check */
    if( FD_UNLIKELY( data_sz>frame_sz ) ) {
      FD_LOG_WARNING(( "frame too large for xsk ring (%lu > %lu), aborting send",
                       data_sz, frame_sz ));
      if( opt_batch_idx ) *opt_batch_idx = 0UL;
      return FD_AIO_ERR_INVAL;
    }

    /* Copy aio packet payload into TX frame */
    fd_memcpy( frame_mem + offset, data, data_sz );

    /* Write XSK meta */
    meta[pending_cnt] = (fd_xsk_frame_meta_t){
      .off   = offset,
      .sz    = (uint)data_sz,
      .flags = 0U
    };
    pending_cnt++;
  }

  /* Enqueue send */
  ulong sent_cnt=0UL;
  if( FD_LIKELY( pending_cnt>0UL || flush ) )
    sent_cnt = fd_xsk_tx_enqueue( xsk, meta, pending_cnt, flush );

  /* Sent less than user requested? */
  if( FD_UNLIKELY( sent_cnt<pkt_cnt ) ) {
    if( FD_LIKELY( opt_batch_idx ) ) *opt_batch_idx = sent_cnt;
    return FD_AIO_ERR_AGAIN;
  }

  return FD_AIO_SUCCESS;
}
