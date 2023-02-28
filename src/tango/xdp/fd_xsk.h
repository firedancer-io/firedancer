#ifndef HEADER_fd_src_tango_xdp_fd_xsk_h
#define HEADER_fd_src_tango_xdp_fd_xsk_h

/* fd_xsk manages an XSK file descriptor and provides RX/TX buffers. */

#if defined(__linux__) && FD_HAS_LIBBPF

#include <linux/if_link.h>
#include <net/if.h>

#include "../../util/fd_util_base.h"

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

FD_PROTOTYPES_BEGIN

/* Setup API **********************************************************/

/* fd_xsk_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as an fd_xsk_t. */

FD_FN_CONST ulong
fd_xsk_align( void );

FD_FN_CONST ulong
fd_xsk_footprint( ulong frame_sz,
                  ulong fr_depth,
                  ulong rx_depth,
                  ulong tx_depth,
                  ulong cr_depth );

/* fd_xsk_new formats an unused memory region for use as an fd_xsk_t.
   shmem must point to a memory region that matches fd_xsk_align() and
   fd_xsk_footprint().  frame_sz controls the frame size used in the
   UMEM ring buffers.  {fr,rx,tx,cr}_depth control the number of frames
   allocated for the Fill, RX, TX, Completion rings respectively.
   Returns handle suitable for fd_xsk_join() on success. */

void *
fd_xsk_new( void *       shmem,
            ulong        frame_sz,
            ulong        fr_depth,
            ulong        rx_depth,
            ulong        tx_depth,
            ulong        cr_depth);

/* fd_xsk_bind assigns an XSK buffer to the network device with name
   ifname and RX queue index ifqueue.  fd_xsk_unbind unassigns an XSK
   buffer from any netdev queue.  shxsk points to the first byte of the
   memory region backing the fd_xsk_t in the caller's address space.
   Returns shxsk on success or NULL on failure (logs details).

   The app_name is used to discover the XSKMAP on join at path
   "/sys/fs/bpf/{bpf_app_name}/{ifname}/xsks". */

void *
fd_xsk_bind( void *       shxsk,
             char const * app_name,
             char const * ifname,
             uint         ifqueue );

void *
fd_xsk_unbind( void * shxsk );

/* fd_xsk_join joins the caller to the fd_xsk_t and starts packet
   redirection.  shxsk points to the first byte of the memory region
   backing the fd_xsk_t in the caller's address space.  Returns a
   pointer in the local address space to the fd_xsk on success or NULL
   on failure (logs details).  Reasons for failure include the shxsk is
   obviously not a local pointer to a memory region holding a xsk.
   Every successful join should have a matching leave.  The lifetime of
   the join is until the matching leave or caller's thread group is
   terminated.  There may only be one active join for a single fd_xsk_t
   at any given time.

   Requires prior system configuration via fd_xsk_install.  Creates an
   XSK, attaches the UMEM rings in fd_xsk_t with the XSK, updates the
   pre-installed XDP program's XSKMAP to start up packet redirection.
   Detaches any existing packet redirection on this XDP program. */

fd_xsk_t *
fd_xsk_join( void * shxsk );

/* fd_xsk_leave leaves a current local join and releases all kernel
   resources.  Returns a pointer to the underlying shared memory region
   on success and NULL on failure (logs details).  Reasons for failure
   include xsk is NULL. */

void *
fd_xsk_leave( fd_xsk_t * xsk );

/* fd_xsk_delete unformats a memory region used as an fd_xsk_t. Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g. shxsk
   does not point to an fd_xsk_t ... logs details).  The ownership of
   the memory region is transferred to the caller on success. */

void *
fd_xsk_delete( fd_xsk_t * xsk );

/* I/O API ************************************************************/

/* fd_xsk_rx_enqueue: Enqueues a batch of frames for RX.

   An RX enqueue transfers ownership of frames to the kernel, providing
   it space for incoming packet data.  Successful enqueue does not imply
   that packets have actually been received, but rather just indicates
   that the frame memory is registered with the AF_XDP socket.

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

/* fd_xsk_fd: Returns the XSK file descriptor. */

FD_FN_PURE int
fd_xsk_fd( fd_xsk_t * const xsk );

/* fd_xsk_app_name: Returns the name of the BPF FS dir that XSK will
   register itself to.  fd_xsk_activate will register XSK at
   "/sys/fs/bpf/{bpf_app_name}/{ifname}/xsks" on queue index ifidx. */

FD_FN_PURE char const *
fd_xsk_app_name( fd_xsk_t * const xsk );

/* fd_xsk_ifname: Returns the network interface name of that the
   XSK is currently bound to.  Return value points to memory owned by
   `xsk` and is valid for the lifetime of the local join.  May return
   NULL if the XSK is not bound. */

FD_FN_PURE char const *
fd_xsk_ifname( fd_xsk_t * const xsk );

/* fd_xsk_ifidx: Returns the network interface index of that the
   XSK is currently bound to.  May return zero if the XSK is not bound. */

FD_FN_PURE uint
fd_xsk_ifidx( fd_xsk_t * const xsk );

/* fd_xsk_ifqueue: Returns the queue index that the XSK is currently
   bound to (a network interface can have multiple queues). U.B if
   fd_xsk_ifname() returns NULL. */

FD_FN_PURE uint
fd_xsk_ifqueue( fd_xsk_t * const xsk );

/* fd_xsk_umem_laddr returns a pointer to the XSK frame memory region in
   the caller's local address space. */

FD_FN_CONST void *
fd_xsk_umem_laddr( fd_xsk_t * xsk );

FD_PROTOTYPES_END

#endif /* defined(__linux__) && FD_HAS_LIBBPF */
#endif /* HEADER_fd_src_tango_xdp_fd_xsk_h */
