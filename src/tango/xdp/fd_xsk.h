#ifndef HEADER_fd_src_tango_xdp_fd_xsk_h
#define HEADER_fd_src_tango_xdp_fd_xsk_h

#if defined(__linux__) && FD_HAS_LIBBPF

#include <linux/if_link.h>
#include <net/if.h>

#include "../../util/fd_util_base.h"

/* FD_XSK_ALIGN: alignment of fd_xsk_t. */
#define FD_XSK_ALIGN      (4096UL)

/* FD_XSK_UMEM_ALIGN: byte alignment of UMEM area within fd_xsk_t.
   This requirement is set by the kernel as of Linux 4.18. */
#define FD_XSK_UMEM_ALIGN (4096UL)

/* Forward declarations */
struct fd_xsk_private;
typedef struct fd_xsk_private fd_xsk_t;

/* fd_xsk_frame_meta_t: Frame metadata used to identify packet */

#define FD_XDP_FRAME_META_ALIGN (16UL)

struct __attribute__((aligned(FD_XDP_FRAME_META_ALIGN))) fd_xsk_frame_meta {
  ulong off;   /* Offset to start of packet */
  uint  sz;    /* Size of packet data starting at `off` */
  uint  flags; /* Undefined for now */
};
typedef struct fd_xsk_frame_meta fd_xsk_frame_meta_t;

/* fd_xsk_params_t: Memory layout parameters of XSK.
   Can be retrieved using fd_xsk_get_params() */

struct fd_xsk_params {
  /* {fr,rx,tx,cr}_depth: Number of frames allocated for the Fill, RX,
    TX, Completion XSK rings respectively. */
  ulong fr_depth;
  ulong rx_depth;
  ulong tx_depth;
  ulong cr_depth;

  /* frame_sz: Controls the frame size used in the UMEM ring buffers. */
  ulong frame_sz;

  /* umem_sz: Total size of XSK ring shared memory area (contiguous).
     Aligned by FD_XSK_ALIGN. */
  ulong umem_sz;
};
typedef struct fd_xsk_params fd_xsk_params_t;

FD_PROTOTYPES_BEGIN

/* I/O API ************************************************************/

/* fd_xsk_rx_enqueue: Enqueues a batch of frames for RX.

   An RX enqueue transfers ownership of frames to the kernel using the
   fill ring, providing it space for incoming packet data.  Successful
   enqueue does not imply that packets have actually been received, but
   rather just indicates that the frame memory is registered with the
   AF_XDP socket.

   offsets points to an array containing offsets_cnt items.
   Each offsets[k] for k in [0;offsets_cnt-1] is the frame's byte offset
   relative to the start of the UMEM region.  Returns the number of
   frames n enqueued where n<=offsets_cnt.  Each frame (identified by
   its offset) may not be reused in another enqueue until it is returned
   in fd_xsk_rx_complete.  The frames that failed to enqueue are in
   [n;offsets_cnt-1] and may be retried in a later call. */

ulong
fd_xsk_rx_enqueue( fd_xsk_t * xsk,
                   ulong *    offsets,
                   ulong      offsets_cnt );

/* fd_xsk_rx_enqueue2: See fd_xsk_rx_enqueue.

   meta points to an array containing meta_cnt items.  For each k in
   [0;meta_cnt-1], meta[k].off is the frame's byte offset relative to
   the start of the UMEM region.  meta[k].{sz,flags} are ignored. */

ulong
fd_xsk_rx_enqueue2( fd_xsk_t *            xsk,
                    fd_xsk_frame_meta_t * meta,
                    ulong                 meta_cnt );

/* fd_xsk_rx_complete: Receives RX completions for a batch of frames.

   An RX completion means that a packet has been received and transfers
   ownership of the frame holding the packet over to userspace.
   meta_cnt is the number of packets that the caller is able to receive.
   meta points to an array containing meta_cnt records where each k in
   [0,count-1] may fill a packet meta at meta[k].  Returns the number of
   packets actually received, which may be less than meta_cnt. */

ulong
fd_xsk_rx_complete( fd_xsk_t *            xsk,
                    fd_xsk_frame_meta_t * meta,
                    ulong                 meta_cnt );


/* fd_xsk_tx_enqueue: Enqueues a batch of frames for TX.

   meta_cnt is the number of packets to attempt to enqueue for transmit.
   meta points to an array containing meta_cnt records where each k in
   [0,count-1] enqueues frame at meta[k].  Returns the number of frames
   actually enqueued, which may be less than meta_cnt.  Successful en-
   queue does not imply that packets have actually been sent out to the
   network, but rather just indicates that the frame memory is
   registered with the AF_XDP sockets.  The frames that failed to
   enqueue are referred to by meta[N+] and may be retried in a later
   call. */

ulong
fd_xsk_tx_enqueue( fd_xsk_t *            xsk,
                   fd_xsk_frame_meta_t * meta,
                   ulong                 meta_cnt );


/* fd_xsk_tx_complete: Check for TX completions and reclaim frames.

   A TX completion occurs when a previously enqueued TX packet has been
   fully handed off to the NIC or dropped.  This transfers the ownership
   of the corresponding frame back to the XSK, where the caller can
   retrieve it for future writes using this function.  Note that this
   does not guarantee successful delivery to the network destination.

   offsets points to an array containing offsets_cnt items.
   Returns the number of frames n completed where n<=offsets_cnt.
   Each k in [0;n-1] writes a completion at offsets[k] where offsets[k]
   is the frame byte offset relative to the start of the UMEM region. */

ulong
fd_xsk_tx_complete( fd_xsk_t * xsk,
                    ulong *    offsets,
                    ulong      offsets_cnt );

/* fd_xsk_tx_complete2: See fd_xsk_tx_complete.

   fd_xsk_tx_complete2 behaves similar to fd_xsk_tx_complete, except
   that it takes a pointer to an array of fd_xsk_frame_meta_t instead
   of ulong.  meta points to an array containing meta_cnt.
   Each k in [0;n-1] writes a frame meta at meta[k] where
   meta[k].off is the frame offset relative to the UMEM region's start
   and `meta[k].{sz,flags}` are undefined. */

ulong
fd_xsk_tx_complete2( fd_xsk_t *            xsk,
                     fd_xsk_frame_meta_t * meta,
                     ulong                 meta_cnt );

FD_PROTOTYPES_END

#endif /* defined(__linux__) && FD_HAS_LIBBPF */
#endif /* HEADER_fd_src_tango_xdp_fd_xsk_h */
