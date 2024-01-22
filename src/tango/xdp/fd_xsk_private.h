#ifndef HEADER_fd_src_tango_xdp_fd_xsk_private_h
#define HEADER_fd_src_tango_xdp_fd_xsk_private_h

#if defined(__linux__)

#include "fd_xsk.h"
#include "../../util/fd_util.h"

#include <linux/if_xdp.h>

/* fd_ring_desc_t describes an XSK descriptor ring in the thread group's
   local address space.  All pointers fall into kernel-managed XSK
   descriptor buffer at [mem;mem+mem_sz) that are valid during the
   lifetime of an fd_xsk_t join.  The ring producer and consumer are
   synchronized via incrementing sequence numbers that wrap at 2^64. */

struct __attribute__((aligned(64UL))) fd_ring_desc {
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
typedef struct fd_ring_desc fd_ring_desc_t;

/* Private definition of an fd_xsk_t */

#define FD_XSK_MAGIC (0xf17eda2c3778736bUL) /* firedancer hex(xsk) */

struct __attribute__((aligned(FD_XSK_ALIGN))) fd_xsk_private {
  ulong magic;   /* ==FD_XSK_MAGIC */
  ulong session; /* TODO, use as mutex lock */

  /* Network interface config *****************************************/

  /* app_name_cstr: Name of BPF FS dir of app.  Used to discover the
     XSKMAP on join at path "/sys/fs/bpf/{bpf_app_name}/{ifname}/xsks". */

  char app_name_cstr[ NAME_MAX ];

  /* if_name_cstr: Name of network interface.
     if_id:        Index of network interface (volatile).
     if_queue_id:  Queue ID of interface that XSK binds to.

     Note: fd_xsk_t lives in shm, so technically, it cannot outlive an
     if_idx, whose lifetime is the system uptime.  We save the interface
     name regardless, which is less likely to change on modern kernels. */
  char if_name_cstr[ IF_NAMESIZE ];
  uint if_idx;
  uint if_queue_id;

  /* Memory layout parameters */

  fd_xsk_params_t params;

  /* xdp_mode: XDP processing mode.  Defined by <linux/if_link.h>

     Valid values:

       0                   kernel default mode
       XDP_FLAGS_SKB_MODE  sk_buff generic mode (hardware-agnostic)
       XDP_FLAGS_DRV_MODE  driver XDP (requires driver support)
       XDP_FLAGS_HW_MODE   hardware-accelerated XDP
                           (requires NIC and driver support) */
  ulong xdp_mode;

  /* Per-join thread-group-local objects ******************************/

  /* Kernel descriptor of UMEM in local address space */
  struct xdp_umem_reg umem;

  /* Kernel descriptor of XSK rings in local address space
     returned by getsockopt(SOL_XDP, XDP_MMAP_OFFSETS) */
  struct xdp_mmap_offsets offsets;

  /* Open file descriptors */
  int xsk_fd;         /* AF_XDP socket file descriptor */
  int xdp_map_fd;     /* eBPF XSKMAP */
  int xdp_udp_map_fd; /* eBPF UDP map */

  /* ring_{rx,tx,fr,cr}: XSK ring descriptors */

  fd_ring_desc_t ring_rx;
  fd_ring_desc_t ring_tx;
  fd_ring_desc_t ring_fr;
  fd_ring_desc_t ring_cr;

  /* Variable-length data *********************************************/

  /* ... UMEM area follows ... */
};

FD_PROTOTYPES_BEGIN

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
#endif /* HEADER_fd_src_tango_xdp_fd_xsk_private_h */
