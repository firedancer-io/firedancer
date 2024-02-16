#ifndef HEADER_fd_src_waltz_xdp_fd_xsk_aio_h
#define HEADER_fd_src_waltz_xdp_fd_xsk_aio_h

#if defined(__linux__)

#include "fd_xsk.h"
#include "../aio/fd_aio.h"

/* fd_xsk_aio_t is an fd_aio driver for AF_XDP.  May not be shared
   across thread groups. */

#define FD_XSK_AIO_ALIGN (32UL)

struct __attribute__((aligned(FD_XSK_AIO_ALIGN))) fd_xsk_aio_private;
typedef struct fd_xsk_aio_private fd_xsk_aio_t;

FD_PROTOTYPES_BEGIN

/* fd_xsk_aio_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use an fd_xsk_aio_t where
   tx_depth is the depth of the TX ring buffer of the fd_xsk_t, and
   pkt_cnt is the max number of packets to handle at per
   fd_xsk_aio_service() operation. */

FD_FN_CONST ulong
fd_xsk_aio_align( void );

FD_FN_CONST ulong
fd_xsk_aio_footprint( ulong tx_depth,
                      ulong pkt_cnt );


/* fd_xsk_aio_new formats an unused memory region for use as an
   fd_xsk_aio_t.  mem must point to a memory region that matches
   fd_xsk_aio_align() and fd_xsk_aio_footprint().  pkt_cnt is the
   number of packets this fd_xsk_aio_t instance can handle per
   fd_xsk_aio_service() operation.  Returns handle suitable for
   fd_xsk_aio_join() on success. */

void *
fd_xsk_aio_new( void * mem,
                ulong  tx_depth,
                ulong  pkt_cnt );

/* fd_xsk_aio_join joins the caller to the xsk_aio/xsk pair.  xsk_aio
   points to the first byte of the memory region backing the
   fd_xsk_aio_t in the caller's address space.
   xsk must be a locally joined fd_xsk_t instance with a lifetime at
   least that of this xsk_aio join.  Returns a pointer in the local
   address space to the fd_xsk_aio_t on success or NULL on failure (logs
   details).  Reasons for failure include the xsk_aio is obviously not a
   local pointer to a memory region holding a fd_xsk_aio_t.  Every
   successful join should have a matching leave.  The lifetime of the
   join is until the matching leave of the caller's thread group is
   terminated.  The may only be one active join for a single
   fd_xsk_aio_t at any given time. U.B. if multiple xsk_aio are joined
   to the same xsk. */

fd_xsk_aio_t *
fd_xsk_aio_join( void *     xsk_aio,
                 fd_xsk_t * xsk );

/* fd_xsk_aio_leave leaves a current local join.  Any aio connections
   must be destroyed at this point.  Returns a pointer to the underlying
   shared memory region on success and NULL on failure (logs details).
   Reasons for failure include xsk_aio is NULL. */

void *
fd_xsk_aio_leave( fd_xsk_aio_t * xsk_aio );

/* fd_xsk_aio_delete unformats a memory region used as an fd_xsk_aio_t.
   Assumes nobody is joined to the region.  Returns a pointer to the
   underlying memory region or NULL if used obviously in error.  The
   ownership of the memory region is transferred to the caller on
   success.  Does not delete the underlying fd_xsk_t instance. */
void *
fd_xsk_aio_delete( void * xsk_aio );

/* fd_xsk_aio_set_rx sets the fd_aio_t instance called back when
   fd_xsk_t receives data.  Requires periodic fd_xsk_aio_service()
   calls to poll AF_XDP buffers for RX events and TX completions. */

void
fd_xsk_aio_set_rx( fd_xsk_aio_t *   xsk_aio,
                   fd_aio_t const * aio );

/* fd_xsk_aio_get_tx gets the fd_aio_t instance to send data out to the
   network via the underlying fd_xsk_t.  Each aio send does at most one
   call to fd_xsk_tx_enqueue and may yield FD_AIO_ERR_AGAIN if the XSK
   tx_depth or aio pkt_cnt buffers are too small.  If attempting to send
   any packet larger than the underlying XSK frame_sz (minus headroom),
   aborts the entire batch and yields FD_AIO_ERR_INVAL. */

FD_FN_CONST fd_aio_t const *
fd_xsk_aio_get_tx( fd_xsk_aio_t const * xsk_aio );

/* fd_xsk_aio_service services aio callbacks for incoming packets and
   handles completions for tx requests. */

void
fd_xsk_aio_service( fd_xsk_aio_t * xsk_aio );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */
#endif /* HEADER_fd_src_waltz_xdp_fd_xsk_aio_h */

