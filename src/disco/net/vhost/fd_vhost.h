#ifndef HEADER_fd_src_disco_net_vhost_fd_vhost_h
#define HEADER_fd_src_disco_net_vhost_fd_vhost_h

/* fd_vhost.h implements a pure-C vhost-user (virtio-user) frontend
   client for zero-kernel-overhead userspace container networking
   against a vhost-user backend such as VPP.

   This feature is strictly for firedancer-dev. */

#include "../../../util/fd_util_base.h"

#if defined(__linux__)

/* Virtio ring constants (Virtio 1.1 split virtqueue) */
#define FD_VHOST_VRING_DESC_F_NEXT     (1U)
#define FD_VHOST_VRING_DESC_F_WRITE    (2U)
#define FD_VHOST_VRING_AVAIL_F_NO_INTR (1U)
#define FD_VHOST_VRING_USED_F_NO_NOTIF (1U)

/* Virtio feature bits */
#define FD_VIRTIO_NET_F_MAC            (1UL<<5)
#define FD_VIRTIO_NET_F_MRG_RXBUF      (1UL<<15)
#define FD_VIRTIO_NET_F_STATUS         (1UL<<16)
#define FD_VIRTIO_F_VERSION_1          (1UL<<32)
#define FD_VHOST_USER_F_PROTOCOL_FEAT  (1UL<<30)

/* vhost-user protocol constants */
#define FD_VHOST_USER_VERSION          (0x1U)
#define FD_VHOST_USER_NEED_REPLY       (0x8U)
#define FD_VHOST_USER_VRING_NOFD_MASK  (1UL<<8)

#define FD_VHOST_USER_GET_FEATURES          (1U)
#define FD_VHOST_USER_SET_FEATURES          (2U)
#define FD_VHOST_USER_SET_OWNER             (3U)
#define FD_VHOST_USER_RESET_OWNER           (4U)
#define FD_VHOST_USER_SET_MEM_TABLE         (5U)
#define FD_VHOST_USER_SET_VRING_NUM         (8U)
#define FD_VHOST_USER_SET_VRING_ADDR        (9U)
#define FD_VHOST_USER_SET_VRING_BASE        (10U)
#define FD_VHOST_USER_GET_VRING_BASE        (11U)
#define FD_VHOST_USER_SET_VRING_KICK        (12U)
#define FD_VHOST_USER_SET_VRING_CALL        (13U)
#define FD_VHOST_USER_GET_PROTOCOL_FEATURES (15U)
#define FD_VHOST_USER_SET_PROTOCOL_FEATURES (16U)
#define FD_VHOST_USER_SET_VRING_ENABLE      (18U)

/* Limits and defaults */
#define FD_VHOST_BATCH_SIZE            (64U)
#define FD_VHOST_QUEUE_DEPTH_MIN       (128U)
#define FD_VHOST_QUEUE_DEPTH_MAX       (4096U)
#define FD_VHOST_BUF_STRIDE            (2048UL)
#define FD_VHOST_PAGE_SZ               (4096UL)
#define FD_VHOST_TILE_MAX              (1UL)

/* Split virtqueue structures (standard Linux/Virtio ABI, naturally aligned) */
struct fd_vring_desc {
  ulong  addr;
  uint   len;
  ushort flags;
  ushort next;
};
typedef struct fd_vring_desc fd_vring_desc_t;

struct fd_vring_avail {
  ushort flags;
  ushort idx;
  ushort ring[];
};
typedef struct fd_vring_avail fd_vring_avail_t;

struct fd_vring_used_elem {
  uint id;
  uint len;
};
typedef struct fd_vring_used_elem fd_vring_used_elem_t;

struct fd_vring_used {
  ushort               flags;
  ushort               idx;
  fd_vring_used_elem_t ring[];
};
typedef struct fd_vring_used fd_vring_used_t;

/* Virtio-net packet header (12 bytes when VIRTIO_F_VERSION_1, 10 bytes legacy) */
struct __attribute__((packed)) fd_virtio_net_hdr_v1 {
  uchar  flags;
  uchar  gso_type;
  ushort hdr_len;
  ushort gso_size;
  ushort csum_start;
  ushort csum_offset;
  ushort num_buffers;
};
typedef struct fd_virtio_net_hdr_v1 fd_virtio_net_hdr_v1_t;

/* Single split virtqueue state */
struct fd_vhost_vring {
  uint               depth;        /* power of 2 */
  uint               mask;         /* depth - 1 */
  fd_vring_desc_t *  desc;
  fd_vring_avail_t * avail;
  fd_vring_used_t *  used;
  uchar *            bufs;         /* depth * FD_VHOST_BUF_STRIDE contiguous */
  ushort             avail_idx;    /* local shadow of avail->idx */
  ushort             last_used_idx;/* next used ring entry to consume */
  int                kick_fd;      /* eventfd to notify backend */
  int                call_fd;      /* eventfd for backend->frontend wakeup (-1 if unused) */
};
typedef struct fd_vhost_vring fd_vhost_vring_t;

/* Connected vhost-user client instance (one RX + one TX virtqueue) */
struct fd_vhost {
  int              sock_fd;        /* Unix domain socket to backend */
  void *           shm;            /* mmap'd memfd shared with backend */
  ulong            shm_sz;         /* total size of shm in bytes */
  ulong            features;       /* negotiated virtio features */
  ulong            proto_features; /* negotiated vhost-user protocol features */
  ulong            virtio_hdr_sz;  /* 12 (VERSION_1) or 10 (legacy) */
  fd_vhost_vring_t rx;
  fd_vhost_vring_t tx;
};
typedef struct fd_vhost fd_vhost_t;

FD_PROTOTYPES_BEGIN

/* fd_vhost_shm_footprint returns the size in bytes of the memfd region
   needed for RX and TX virtqueues and their packet buffers. */
ulong
fd_vhost_shm_footprint( uint rx_depth,
                        uint tx_depth );

/* fd_vhost_connect connects to a vhost-user server Unix domain socket
   at socket_path, allocates a shared memfd, completes the vhost-user
   handshake, and pre-fills the RX virtqueue with receive buffers.
   Returns 0 on success, -1 on failure (with errno set). */
int
fd_vhost_connect( fd_vhost_t * vhost,
                  char const * socket_path,
                  uint         rx_depth,
                  uint         tx_depth );

/* fd_vhost_close tears down a connected vhost-user instance. */
void
fd_vhost_close( fd_vhost_t * vhost );

/* fd_vhost_is_connected performs a non-blocking check on the Unix
   domain control socket.  Returns 1 if still connected, 0 if the peer
   disconnected or errored. */
int
fd_vhost_is_connected( fd_vhost_t const * vhost );

/* fd_vhost_kick notifies the backend via eventfd if notifications are
   not suppressed by the backend (VRING_USED_F_NO_NOTIF). */
static inline void
fd_vhost_kick( fd_vhost_vring_t const * vr ) {
  if( FD_LIKELY( vr->kick_fd<0 ) ) return;
  ushort const used_flags = __atomic_load_n( &vr->used->flags, __ATOMIC_ACQUIRE );
  if( FD_UNLIKELY( !(used_flags & FD_VHOST_VRING_USED_F_NO_NOTIF) ) ) {
    ulong val = 1UL;
    extern long write( int fd, void const * buf, unsigned long count );
    (void)write( vr->kick_fd, &val, sizeof(val) );
  }
}

/* fd_vhost_buf_ptr returns the buffer pointer for descriptor index idx. */
static inline uchar *
fd_vhost_buf_ptr( fd_vhost_vring_t const * vr,
                  uint                     idx ) {
  return vr->bufs + ((ulong)(idx & vr->mask) * FD_VHOST_BUF_STRIDE);
}

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_disco_net_vhost_fd_vhost_h */
