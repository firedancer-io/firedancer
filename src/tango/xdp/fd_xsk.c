#if !defined(__linux__) || !FD_HAS_LIBBPF
#error "fd_xsk requires Linux operating system with XDP support"
#endif

#include <linux/if_xdp.h>
#include <linux/limits.h>

#include <sys/socket.h>

#include "fd_xsk_private.h"

/* TODO move this into more appropriate header file
   and set based on architecture, etc. */
#define FD_ACQUIRE FD_COMPILER_MFENCE
#define FD_RELEASE FD_COMPILER_MFENCE

/* RX/TX implementation ***********************************************/

ulong
fd_xsk_rx_enqueue( fd_xsk_t * xsk,
                   ulong *    offset,
                   ulong      count ) {
  /* to make frames available for receive, we enqueue onto the fill ring */

  /* fill ring */
  fd_ring_desc_t * fill = &xsk->ring_fr;

  /* fetch cached consumer, producer */
  ulong prod = fill->cached_prod;
  ulong cons = fill->cached_cons;

  /* ring capacity */
  ulong cap  = fill->depth;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = fill->cached_cons = *fill->cons;
  }

  /* sz is min( available, count ) */
  ulong sz = cap - ( prod - cons );
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  ulong * ring = fill->frame_ring;
  ulong mask = fill->depth - 1UL;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = prod & mask;
    ring[k] = offset[j];

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
  fill->cached_prod = *fill->prod = prod;

  /* TODO do we need to check for wakeup here? */

  return sz;
}

ulong
fd_xsk_rx_enqueue2( fd_xsk_t *            xsk,
                    fd_xsk_frame_meta_t * meta,
                    ulong                 count ) {
  /* to make frames available for receive, we enqueue onto the fill ring */

  /* fill ring */
  fd_ring_desc_t * fill = &xsk->ring_fr;

  /* fetch cached consumer, producer */
  ulong prod = fill->cached_prod;
  ulong cons = fill->cached_cons;

  /* assuming frame sizes are powers of 2 */
  ulong frame_mask = xsk->params.frame_sz - 1UL;

  /* ring capacity */
  ulong cap  = fill->depth;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = fill->cached_cons = *fill->cons;
  }

  /* sz is min( available, count ) */
  ulong sz = cap - ( prod - cons );
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  ulong * ring = fill->frame_ring;
  ulong mask = fill->depth - 1;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = prod & mask;
    ring[k] = meta[j].off & frame_mask;

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
  fill->cached_prod = *fill->prod = prod;

  /* TODO do we need to check for wakeup here? */

  return sz;
}

ulong
fd_xsk_tx_enqueue( fd_xsk_t *            xsk,
                   fd_xsk_frame_meta_t * meta,
                   ulong                 count ) {
  /* to submit frames for tx, we enqueue onto the tx ring */

  /* tx ring */
  fd_ring_desc_t * tx = &xsk->ring_tx;

  /* fetch cached consumer, producer */
  ulong prod = tx->cached_prod;
  ulong cons = tx->cached_cons;

  /* ring capacity */
  ulong cap  = tx->depth;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = tx->cached_cons = *tx->cons;
  }

  /* sz is min( available, count ) */
  ulong sz = cap - ( prod - cons );
  /* TODO this doesn't work as expected
     if we early exit here, no wakeup occurs, sendto doesn't get called again
     and the ring doesn't get serviced
     This implies we need to call sendto AGAIN even if the ring hasn't changed
  if( sz == 0 )    return 0;
  */
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  struct xdp_desc * ring = tx->packet_ring;
  ulong mask = tx->depth - 1;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = prod & mask;
    ring[k].addr    = meta[j].off;
    ring[k].len     = meta[j].sz;
    ring[k].options = 0;

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
  tx->cached_prod = *tx->prod = prod;

  /* XDP tells us whether we need to specifically wake up the driver/hw */
  if( fd_xsk_tx_need_wakeup( xsk ) ) {
    sendto( xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0 );
  }

  return sz;
}

ulong
fd_xsk_rx_complete( fd_xsk_t *            xsk,
                    fd_xsk_frame_meta_t * batch,
                    ulong                 capacity ) {
  /* rx ring */
  fd_ring_desc_t * rx = &xsk->ring_rx;

  ulong prod = rx->cached_prod;
  ulong cons = rx->cached_cons;

  /* how many frames are available? */
  ulong avail = prod - cons;

  /* should we update the cache */
  if( avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = rx->cached_prod = *rx->prod;
    avail = prod - cons;
  }

  ulong sz = avail;
  if( sz > capacity ) sz = capacity;

  ulong mask = rx->depth - 1;
  struct xdp_desc * ring = rx->packet_ring;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = cons & mask;
    batch[j].off   = ring[k].addr;
    batch[j].sz    = ring[k].len;
    batch[j].flags = 0;

    cons++;
  }

  FD_RELEASE();

  rx->cached_cons = *rx->cons = cons;

  return sz;
}

ulong
fd_xsk_tx_complete( fd_xsk_t * xsk, ulong * batch, ulong capacity ) {
  /* cr ring */
  fd_ring_desc_t * cr = &xsk->ring_cr;

  ulong prod = cr->cached_prod;
  ulong cons = cr->cached_cons;

  /* how many frames are available? */
  ulong avail = prod - cons;

  /* should we update the cache */
  if( avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = cr->cached_prod = *cr->prod;
    avail = prod - cons;
  }

  ulong sz = avail;
  if( sz > capacity ) sz = capacity;

  ulong mask = cr->depth - 1;
  ulong * ring = cr->frame_ring;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = cons & mask;
    batch[j] = ring[k];

    cons++;
  }

  FD_RELEASE();

  cr->cached_cons = *cr->cons = cons;

  return sz;
}

ulong
fd_xsk_tx_complete2( fd_xsk_t *            xsk,
                     fd_xsk_frame_meta_t * batch,
                     ulong                 capacity ) {
  /* cr ring */
  fd_ring_desc_t * cr = &xsk->ring_cr;

  ulong prod = cr->cached_prod;
  ulong cons = cr->cached_cons;

  /* how many frames are available? */
  ulong avail = prod - cons;

  /* should we update the cache */
  if( avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = cr->cached_prod = *cr->prod;
    avail = prod - cons;
  }

  ulong sz = avail;
  if( sz > capacity ) sz = capacity;

  ulong mask = cr->depth - 1;
  ulong * ring = cr->frame_ring;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = cons & mask;
    batch[j].off = ring[k];

    cons++;
  }

  FD_RELEASE();

  cr->cached_cons = *cr->cons = cons;

  return sz;
}

fd_xsk_params_t const *
fd_xsk_get_params( fd_xsk_t const * xsk ) {
  return &xsk->params;
}
