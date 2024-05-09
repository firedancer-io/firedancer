#ifndef HEADER_fd_src_waltz_xdp_fd_xsk_h
#define HEADER_fd_src_waltz_xdp_fd_xsk_h

#if defined(__linux__)

/* fd_xsk manages an XSK file descriptor and provides RX/TX buffers.

   ### Background

   AF_XDP is a Linux API providing kernel-bypass networking in the form
   of shared memory ring buffers accessible from userspace.  The kernel
   redirects packets from/to these buffers with the appropriate XDP
   configuration (XDP_REDIRECT).  AF_XDP is hardware-agnostic and allows
   sharing a NIC with the Linux networking stack (unlike e.g. DPDK).
   This allows for deployment in existing, heterogeneous networks. An
   AF_XDP socket is called "XSK".  The shared memory region storing the
   packet data flowing through an XSK is called "UMEM".

   XDP (eXpress Data Path) is a framework for installing hooks in the
   form of eBPF programs at an early stage of packet processing (i.e.
   before tc and netfilter).  eBPF is user-deployable JIT-compiled
   bytecode that usually runs inside the kernel. Some hardware/driver
   combinations optionally allow offloading eBPF processing to NICs.
   This is not to be confused with other BPF-derived ISAs such as sBPF
   (Solana BPF).

     +--- Figure 1: AF_XDP RX Block Diagram -----------------+
     |                                                       |
     |   ┌─────┐  ┌────────┐  ┌─────┐ XDP_PASS ┌─────────┐   |
     |   │ NIC ├──> Driver ├──> XDP ├──────────> sk_buff │   |
     |   └─────┘  └────────┘  └─┬───┘          └─────────┘   |
     |                          │                            |
     |                          │ XDP_REDIRECT               |
     |                          │                            |
     |                       ┌──▼───────┐      ┌─────────┐   |
     |                       │ XSK/UMEM ├──────> fd_aio  │   |
     |                       └──────────┘      └─────────┘   |
     |                                                       |
     +-------------------------------------------------------+

   Figure 1 shows a simplified block diagram of RX packet flow within
   the kernel in `XDP_FLAGS_DRV_MODE` mode.  Notably, the chain of eBPF
   programs installed in the XDP facility get invoked for every incoming
   packet.  If all programs return the `XDP_PASS` action, the packet
   continues its usual path to the Linux networking stack, where it will
   be allocated in sk_buff, and eventually flow through ip_rcv(), tc,
   and netfilter before reaching downstream sockets.
   If the `XDP_REDIRECT` action is taken however, the packet is copied
   to the UMEM of an XSK, and a RX queue entry is allocated.  An fd_aio
   backend is provided by fd_xdp_aio.
   The more generic `XDP_FLAGS_SKB_MODE` XDP mode falls back to sk_buff-
   based memory mgmt (still skipping the rest of the generic path), but
   is more widely available.

     +--- Figure 2: AF_XDP TX Block Diagram -------------+
     |                                                   |
     |   ┌────────┐  ┌──────────┐  ┌────────┐  ┌─────┐   |
     |   │ fd_aio ├──> XSK/UMEM ├──> Driver ├──> NIC │   |
     |   └────────┘  └──────────┘  └────────┘  └─────┘   |
     |                                                   |
     +---------------------------------------------------+

   Figure 2 shows a simplified block diagram of the TX packet flow.
   Userspace applications deliver packets to the XSK/UMEM buffers.  The
   kernel then forwards these packets to the NIC.  This also means that
   the application is responsible for maintaining a routing table to
   resolve layer-3 dest addrs to NICs and layer-2 addrs.  As in the RX
   flow, netfilter (iptables, nftables) is not available.

   ### Memory Management

   The UMEM area is allocated from userspace.  It is recommended to use
   the fd_util shmem/wksp APIs to obtain large page-backed memory.  UMEM
   is divided into equally sized frames. At any point in time, each
   frame is either owned by userspace or the kernel.  On initialization,
   all frames are owned by userspace.

   Changes in UMEM frame ownership and packet RX/TX events are
   transmitted via four rings allocated by the kernel (mmap()ed in by
   the user). This allows for out-of-order processing of packets.

      Data flow:
      (U->K) is userspace-to-kernel communication, and
      (K->U) is kernel-to-userspace.

      FILL         Free frames are provided to the kernel using the FILL
      (U->K)       ring. The kernel may populate these frames with RX
                   packet data.

      RX           Once the kernel has populated a FILL frame with RX
      (K->U)       packet data, it passes back the frame to userspace
                   via the RX queue.

      TX           TX frames sent by userspace are provided to the
      (U->K)       kernel using the TX ring.

      COMPLETION   Once the kernel has processed a TX frame, it passes
      (K->U)       back the frame to the userspace via the COMPLETION
                   queue.

   Combined, the FILL-RX and TX-COMPLETION rings form two pairs.  The
   kernel will not move frames between the pairs. */

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
  ulong off;   /* Byte offset from UMEM start to start of packet */
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

  /* zerocopy controls zero copy related flags.

       0             default
       XDP_COPY      Force "copy" mode
       XDP_ZEROCOPY  Force "zero copy" mode (faster, but unstable on some NICs) */
  ushort zerocopy;
};
typedef struct fd_xsk_params fd_xsk_params_t;

FD_PROTOTYPES_BEGIN

/* Setup API **********************************************************/

/* fd_xsk_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as an fd_xsk_t.
   See fd_xsk_new for explanations on parameters. */

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
   UMEM ring buffers and should be either 2048 or 4096.
   {fr,rx,tx,cr}_depth control the number of frames allocated for the
   Fill, RX, TX, Completion rings respectively.  If zero_copy is
   non-zero, the xsk will be created in zero-copy mode.  Returns handle
   suitable for fd_xsk_join() on success. */

void *
fd_xsk_new( void * shmem,
            ulong  frame_sz,
            ulong  fr_depth,
            ulong  rx_depth,
            ulong  tx_depth,
            ulong  cr_depth,
            int    zero_copy );

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
fd_xsk_delete( void * shxsk );

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
                   ulong                 meta_cnt,
                   int                   flush );


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

FD_FN_CONST char const *
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

/* fd_xsk_get_params returns a pointer to the memory layout params from
   xsk. The caller should zero-initialize the params buffer before use.
   xsk must be a valid join to fd_xsk_t and params must point to a
   memory region in the caller's local address space.  The returned
   params struct is valid during the lifetime of the xsk. */

FD_FN_CONST fd_xsk_params_t const *
fd_xsk_get_params( fd_xsk_t const * xsk );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */
#endif /* HEADER_fd_src_waltz_xdp_fd_xsk_h */
