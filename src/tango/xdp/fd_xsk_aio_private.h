#ifndef HEADER_fd_src_tango_xdp_fd_xsk_aio_private_h
#define HEADER_fd_src_tango_xdp_fd_xsk_aio_private_h

#include "fd_xsk_aio.h"
#include "../aio/fd_aio.h"

/* Private definition of an fd_xsk_aio_t */

#define FD_XSK_AIO_MAGIC (0xf17ed2c778736b61UL) /* firednc hex(xska) */

struct __attribute__((aligned(FD_XSK_AIO_ALIGN))) fd_xsk_aio_private {
  /* Data Layout Config ***********************************************/

  ulong magic;          /* ==FD_XSK_AIO_MAGIC                         */
  ulong pkt_depth;      /* depth of fd_aio_pkt_info_t buffer          */
  ulong tx_depth;       /* depth of the fd_xsk_t tx_depth/cr_depth    */
  ulong meta_off;       /* offset of fd_xsk_frame_meta_t[ batch_cnt ] */
  ulong pkt_off;        /* offset of fd_aio_pkt_info_t  [ batch_cnt ] */
  ulong tx_stack_off;   /* offset of ulong              [ tx_depth  ] */

  /* Join Config ******************************************************/

  fd_xsk_t * xsk;
  fd_aio_t   rx;  /* from outside to user (externally owned) */
  fd_aio_t   tx;  /* from user to outside (owned by fd_xsk_aio) */
  void *     frame_mem; /* Address of start of frame memory */

  /* {rx,tx}_off: Offset from frame_mem to {rx,tx} frames.
     Unit is xsk->frame_sz. TODO consider using byte offset */
  ulong   rx_off;
  ulong   tx_off;

  ulong * tx_stack;       /* stack of unused tx frame indices
                             TODO consider using uint array */
  ulong   tx_stack_depth; /* item count capacity of stack */
  ulong   tx_top;         /* number of items currently on stack */

  ulong   frame_sz;       /* Frame size from fd_xsk_params_t */

  /* Variable-length data *********************************************/

  /* ... fd_xsk_frame_meta_t[ pkt_depth ] follows ... */
  /* ... fd_aio_pkt_info_t  [ pkt_depth ] follows ... */
  /* ... ulong              [ tx_depth  ] follows ... */
};

FD_FN_PURE static inline fd_xsk_frame_meta_t *
fd_xsk_aio_meta( fd_xsk_aio_t * xsk_aio ) {
  return (fd_xsk_frame_meta_t *)( (ulong)xsk_aio + xsk_aio->meta_off );
}

FD_FN_PURE static inline fd_aio_pkt_info_t *
fd_xsk_aio_pkts( fd_xsk_aio_t * xsk_aio ) {
  return (fd_aio_pkt_info_t *)( (ulong)xsk_aio + xsk_aio->pkt_off );
}

FD_FN_PURE static inline ulong *
fd_xsk_aio_tx_stack( fd_xsk_aio_t * xsk_aio ) {
  return (ulong *)( (ulong)xsk_aio + xsk_aio->tx_stack_off );
}

#endif /* HEADER_fd_src_tango_xdp_fd_xsk_aio_private_h */
