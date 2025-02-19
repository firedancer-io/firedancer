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
#include <linux/if_xdp.h>
#include <net/if.h>

#include "../../util/fd_util_base.h"

/* FD_XSK_UMEM_ALIGN: byte alignment of UMEM area within fd_xsk_t.
   This requirement is set by the kernel as of Linux 4.18. */
#define FD_XSK_UMEM_ALIGN (4096UL)

/* fd_xdp_ring_t describes an XSK descriptor ring in the thread group's
   local address space.  All pointers fall into kernel-managed XSK
   descriptor buffer at [mem;mem+mem_sz) that are valid during the
   lifetime of an fd_xsk_t join.  The ring producer and consumer are
   synchronized via incrementing sequence numbers that wrap at 2^64. */

struct __attribute__((aligned(64UL))) fd_xdp_ring {
  /* This point is 64-byte aligned */

  /* mmap() params, only used during join/leave for munmap() */

  void *  mem;    /* Points to start of shared descriptor ring mmap region */
  ulong   map_sz; /* Size of shared descriptor ring mmap region */
  ulong   _pad_0x10;
  ulong   _pad_0x18;

  /* This point is 64-byte aligned */

  /* Pointers to fields opaque XSK ring structure.
     This indirection is required because the memory layout of the
     kernel-provided descriptor rings is unstable.  The field offsets
     can be queried using getsockopt(SOL_XDP, XDP_MMAP_OFFSETS). */

  union {
    void *            ptr;         /* Opaque pointer */
    struct xdp_desc * packet_ring; /* For RX, TX rings */
    ulong *           frame_ring;  /* For FILL, COMPLETION rings */
  };
  uint *  flags;       /* Points to flags in shared descriptor ring */
  uint *  prod;        /* Points to producer seq in shared descriptor ring */
  uint *  cons;        /* Points to consumer seq in shared descriptor ring */

  /* This point is 64-byte aligned */

  /* Managed by fd_xsk_t */

  uint    depth;       /* Capacity of ring in no of entries */
  uint    cached_prod; /* Cached value of *prod */
  uint    cached_cons; /* Cached value of *cons */
};
typedef struct fd_xdp_ring fd_xdp_ring_t;

/* fd_xsk_params_t: Memory layout parameters of XSK.
   Can be retrieved using fd_xsk_get_params() */

struct fd_xsk_params {
  /* {fr,rx,tx,cr}_depth: Number of frames allocated for the Fill, RX,
    TX, Completion XSK rings respectively. */
  ulong fr_depth;
  ulong rx_depth;
  ulong tx_depth;
  ulong cr_depth;

  /* umem_addr: Pointer to UMEM in local address space */
  void * umem_addr;

  /* frame_sz: Controls the frame size used in the UMEM ring buffers. */
  ulong frame_sz;

  /* umem_sz: Total size of XSK ring shared memory area (contiguous).
     Aligned by FD_XSK_ALIGN. */
  ulong umem_sz;

  /* Linux interface index */
  uint if_idx;

  /* Interface queue index */
  uint if_queue_id;

  /* sockaddr_xdp.sxdp_flags additional params, e.g. XDP_ZEROCOPY */
  uint bind_flags;
};

typedef struct fd_xsk_params fd_xsk_params_t;

struct fd_xsk {
  /* Informational */
  uint if_idx;       /* index of net device */
  uint if_queue_id;  /* net device combined queue index */
  long log_suppress_until_ns; /* suppress log messages until this time */

  /* Kernel descriptor of XSK rings in local address space
     returned by getsockopt(SOL_XDP, XDP_MMAP_OFFSETS) */
  struct xdp_mmap_offsets offsets;

  /* AF_XDP socket file descriptor */
  int xsk_fd;

  /* ring_{rx,tx,fr,cr}: XSK ring descriptors */

  fd_xdp_ring_t ring_rx;
  fd_xdp_ring_t ring_tx;
  fd_xdp_ring_t ring_fr;
  fd_xdp_ring_t ring_cr;
};

typedef struct fd_xsk fd_xsk_t;

FD_PROTOTYPES_BEGIN

/* fd_xsk_init creates an XSK, registers UMEM, maps rings, and binds the
   socket to the given interface queue.  This is a potentially
   destructive operation.  As of 2024-Jun, AF_XDP zero copy support is
   still buggy in some device drivers.

   Assume that all traffic sent to this interface is compromised.  On
   some devices, the NIC is instructed to DMA all incoming packets into
   UMEM, even ones not belonging to Firedancer.  Those are then later
   on software-copied out to skbs again.  This further implies that
   enabling AF_XDP can slow down the regular kernel receive path.

   Requires CAP_SYS_ADMIN. May issue the following syscalls:

   - socket( AF_XDP, SOCK_RAW, 0 ) = fd
   - setsockopt( fd, SOL_XDP, ... )
   - getsockopt( fd, SOL_XDP, ... )
   - mmap( ..., fd, ... )
   - bind( fd, ... )
   - munmap  ; on fail
   - close   ; on fail */

fd_xsk_t *
fd_xsk_init( fd_xsk_t *              xsk,
             fd_xsk_params_t const * params );

void *
fd_xsk_delete( void * shxsk );

/* fd_xsk_rx_need_wakeup: returns whether a wakeup is required to
   complete a rx operation */

static inline int
fd_xsk_rx_need_wakeup( fd_xsk_t * xsk ) {
  return !!( *xsk->ring_fr.flags & XDP_RING_NEED_WAKEUP );
}

/* fd_xsk_tx_need_wakeup: returns whether a wakeup is required to
   complete a tx operation */

static inline int
fd_xsk_tx_need_wakeup( fd_xsk_t * xsk ) {
  return !!( *xsk->ring_tx.flags & XDP_RING_NEED_WAKEUP );
}


FD_PROTOTYPES_END

#endif /* defined(__linux__) */
#endif /* HEADER_fd_src_waltz_xdp_fd_xsk_h */
