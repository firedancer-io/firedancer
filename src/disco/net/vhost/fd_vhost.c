#define _GNU_SOURCE
#include "fd_vhost.h"

#include "../../../util/log/fd_log.h"
#include "../../../util/bits/fd_bits.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Wire-format vhost-user messages */

struct __attribute__((packed)) fd_vhost_msg_hdr {
  uint request;
  uint flags;
  uint size;
};
typedef struct fd_vhost_msg_hdr fd_vhost_msg_hdr_t;

struct __attribute__((packed)) fd_vhost_mem_region {
  ulong guest_phys_addr;
  ulong memory_size;
  ulong userspace_addr;
  ulong mmap_offset;
};
typedef struct fd_vhost_mem_region fd_vhost_mem_region_t;

struct __attribute__((packed)) fd_vhost_mem_table {
  uint                  nregions;
  uint                  padding;
  fd_vhost_mem_region_t regions[1];
};
typedef struct fd_vhost_mem_table fd_vhost_mem_table_t;

struct __attribute__((packed)) fd_vhost_vring_state {
  uint index;
  uint num;
};
typedef struct fd_vhost_vring_state fd_vhost_vring_state_t;

struct __attribute__((packed)) fd_vhost_vring_addr {
  uint  index;
  uint  flags;
  ulong desc_user_addr;
  ulong used_user_addr;
  ulong avail_user_addr;
  ulong log_guest_addr;
};
typedef struct fd_vhost_vring_addr fd_vhost_vring_addr_t;

static ulong
vring_desc_sz( uint depth ) {
  return fd_ulong_align_up( (ulong)depth * sizeof(fd_vring_desc_t), FD_VHOST_PAGE_SZ );
}

static ulong
vring_avail_sz( uint depth ) {
  /* flags (2) + idx (2) + ring[depth] (2*depth) + used_event (2) */
  return fd_ulong_align_up( sizeof(fd_vring_avail_t) + ((ulong)depth + 1UL)*sizeof(ushort), FD_VHOST_PAGE_SZ );
}

static ulong
vring_used_sz( uint depth ) {
  /* flags (2) + idx (2) + ring[depth] (8*depth) + avail_event (2) */
  return fd_ulong_align_up( sizeof(fd_vring_used_t) + (ulong)depth*sizeof(fd_vring_used_elem_t) + sizeof(ushort), FD_VHOST_PAGE_SZ );
}

static ulong
vring_total_sz( uint depth ) {
  return vring_desc_sz( depth ) + vring_avail_sz( depth ) + vring_used_sz( depth ) +
         fd_ulong_align_up( (ulong)depth * FD_VHOST_BUF_STRIDE, FD_VHOST_PAGE_SZ );
}

ulong
fd_vhost_shm_footprint( uint rx_depth,
                        uint tx_depth ) {
  return vring_total_sz( rx_depth ) + vring_total_sz( tx_depth );
}

static void
vring_layout( fd_vhost_vring_t * vr,
              uchar *            base,
              uint               depth ) {
  vr->depth         = depth;
  vr->mask          = depth - 1U;
  vr->avail_idx     = 0U;
  vr->last_used_idx = 0U;

  ulong off = 0UL;
  vr->desc  = (fd_vring_desc_t *)(base + off);  off += vring_desc_sz( depth );
  vr->avail = (fd_vring_avail_t *)(base + off); off += vring_avail_sz( depth );
  vr->used  = (fd_vring_used_t *)(base + off);  off += vring_used_sz( depth );
  vr->bufs  = base + off;
}

static int
vhost_send_msg( int          sock_fd,
                uint         request,
                void const * payload,
                uint         payload_sz,
                int const *  fds,
                ulong        fd_cnt ) {
  fd_vhost_msg_hdr_t hdr = {
    .request = request,
    .flags   = FD_VHOST_USER_VERSION,
    .size    = payload_sz,
  };

  struct iovec iov[2];
  ulong iov_cnt = 1UL;
  iov[0].iov_base = &hdr;
  iov[0].iov_len  = sizeof(hdr);
  if( payload_sz>0U ) {
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len  = payload_sz;
    iov_cnt         = 2UL;
  }

  union {
    char           buf[ CMSG_SPACE( sizeof(int)*8UL ) ];
    struct cmsghdr align;
  } cmsg_buf;
  memset( &cmsg_buf, 0, sizeof(cmsg_buf) );

  struct msghdr msg;
  memset( &msg, 0, sizeof(msg) );
  msg.msg_iov    = iov;
  msg.msg_iovlen = iov_cnt;

  if( fd_cnt>0UL ) {
    if( FD_UNLIKELY( fd_cnt>8UL ) ) { errno = EINVAL; return -1; }
    msg.msg_control    = cmsg_buf.buf;
    msg.msg_controllen = CMSG_SPACE( sizeof(int)*fd_cnt );
    struct cmsghdr * cmsg = CMSG_FIRSTHDR( &msg );
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN( sizeof(int)*fd_cnt );
    memcpy( CMSG_DATA( cmsg ), fds, sizeof(int)*fd_cnt );
  }

  long total = (long)sizeof(hdr) + (long)payload_sz;
  long n;
  do {
    n = sendmsg( sock_fd, &msg, MSG_NOSIGNAL );
  } while( n<0L && errno==EINTR );
  if( FD_UNLIKELY( n!=total ) ) {
    if( n>=0L ) errno = EIO;
    return -1;
  }
  return 0;
}

static int
vhost_recv_exact( int    sock_fd,
                  void * buf,
                  ulong  sz ) {
  uchar * p = (uchar *)buf;
  ulong rem = sz;
  while( rem>0UL ) {
    long n;
    do {
      n = recv( sock_fd, p, rem, 0 );
    } while( n<0L && errno==EINTR );
    if( FD_UNLIKELY( n<=0L ) ) {
      if( n==0L ) errno = ECONNRESET;
      return -1;
    }
    p   += (ulong)n;
    rem -= (ulong)n;
  }
  return 0;
}

static int
vhost_recv_u64( int     sock_fd,
                uint    expected_req,
                ulong * out_val ) {
  fd_vhost_msg_hdr_t hdr;
  if( FD_UNLIKELY( 0!=vhost_recv_exact( sock_fd, &hdr, sizeof(hdr) ) ) ) return -1;
  if( FD_UNLIKELY( hdr.request!=expected_req || hdr.size!=sizeof(ulong) ) ) {
    errno = EPROTO;
    return -1;
  }
  return vhost_recv_exact( sock_fd, out_val, sizeof(ulong) );
}

static int
vhost_setup_vring( int                      sock_fd,
                   uint                     qidx,
                   fd_vhost_vring_t const * vr ) {
  fd_vhost_vring_state_t state = { .index = qidx, .num = vr->depth };
  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_VRING_NUM, &state, sizeof(state), NULL, 0UL ) ) ) return -1;

  fd_vhost_vring_addr_t addr = {
    .index           = qidx,
    .flags           = 0U,
    .desc_user_addr  = (ulong)vr->desc,
    .used_user_addr  = (ulong)vr->used,
    .avail_user_addr = (ulong)vr->avail,
    .log_guest_addr  = 0UL,
  };
  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr), NULL, 0UL ) ) ) return -1;

  fd_vhost_vring_state_t base = { .index = qidx, .num = 0U };
  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_VRING_BASE, &base, sizeof(base), NULL, 0UL ) ) ) return -1;

  /* Pure userspace polling: disable backend->frontend call interrupts */
  ulong call_u64 = (ulong)qidx | FD_VHOST_USER_VRING_NOFD_MASK;
  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_VRING_CALL, &call_u64, sizeof(call_u64), NULL, 0UL ) ) ) return -1;

  /* Provide kick eventfd so backend knows the vring is active */
  ulong kick_u64 = (ulong)qidx;
  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_VRING_KICK, &kick_u64, sizeof(kick_u64), &vr->kick_fd, 1UL ) ) ) return -1;

  return 0;
}

int
fd_vhost_connect( fd_vhost_t * vhost,
                  char const * socket_path,
                  uint         rx_depth,
                  uint         tx_depth ) {
  memset( vhost, 0, sizeof(*vhost) );
  vhost->sock_fd    = -1;
  vhost->rx.kick_fd = -1;
  vhost->tx.kick_fd = -1;

  if( FD_UNLIKELY( !socket_path || !socket_path[0] ||
                   !fd_uint_is_pow2( rx_depth ) || rx_depth<FD_VHOST_QUEUE_DEPTH_MIN || rx_depth>FD_VHOST_QUEUE_DEPTH_MAX ||
                   !fd_uint_is_pow2( tx_depth ) || tx_depth<FD_VHOST_QUEUE_DEPTH_MIN || tx_depth>FD_VHOST_QUEUE_DEPTH_MAX ) ) {
    errno = EINVAL;
    return -1;
  }

  /* 1. Connect to the vhost-user backend Unix domain socket */
  int sock_fd = socket( AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( sock_fd<0 ) ) return -1;

  struct sockaddr_un sun;
  memset( &sun, 0, sizeof(sun) );
  sun.sun_family = AF_UNIX;
  ulong path_len = strlen( socket_path );
  if( FD_UNLIKELY( path_len>=sizeof(sun.sun_path) ) ) {
    close( sock_fd );
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy( sun.sun_path, socket_path, path_len+1UL );

  if( FD_UNLIKELY( 0!=connect( sock_fd, (struct sockaddr *)&sun, sizeof(sun) ) ) ) {
    int err = errno;
    close( sock_fd );
    errno = err;
    return -1;
  }
  vhost->sock_fd = sock_fd;

  /* 2. Allocate shared memory via memfd_create */
  ulong shm_sz = fd_vhost_shm_footprint( rx_depth, tx_depth );
  int mem_fd = memfd_create( "fd_vhost", MFD_CLOEXEC );
  if( FD_UNLIKELY( mem_fd<0 ) ) goto fail;

  if( FD_UNLIKELY( 0!=ftruncate( mem_fd, (off_t)shm_sz ) ) ) {
    int err = errno;
    close( mem_fd );
    errno = err;
    goto fail;
  }

  void * shm = mmap( NULL, shm_sz, PROT_READ|PROT_WRITE, MAP_SHARED, mem_fd, 0 );
  if( FD_UNLIKELY( shm==MAP_FAILED ) ) {
    int err = errno;
    close( mem_fd );
    errno = err;
    goto fail;
  }
  memset( shm, 0, shm_sz );
  vhost->shm    = shm;
  vhost->shm_sz = shm_sz;

  /* Layout RX and TX split virtqueues inside shm */
  uchar * base = (uchar *)shm;
  vring_layout( &vhost->rx, base, rx_depth );
  vring_layout( &vhost->tx, base + vring_total_sz( rx_depth ), tx_depth );

  /* Create non-blocking eventfds for kicking backend if needed */
  vhost->rx.kick_fd = eventfd( 0U, EFD_NONBLOCK|EFD_CLOEXEC );
  vhost->tx.kick_fd = eventfd( 0U, EFD_NONBLOCK|EFD_CLOEXEC );
  if( FD_UNLIKELY( vhost->rx.kick_fd<0 || vhost->tx.kick_fd<0 ) ) {
    int err = errno;
    close( mem_fd );
    errno = err;
    goto fail;
  }

  /* 3. vhost-user handshake: GET_FEATURES -> SET_OWNER -> SET_FEATURES */
  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_GET_FEATURES, NULL, 0U, NULL, 0UL ) ) ) {
    int err = errno; close( mem_fd ); errno = err; goto fail;
  }
  ulong backend_features = 0UL;
  if( FD_UNLIKELY( 0!=vhost_recv_u64( sock_fd, FD_VHOST_USER_GET_FEATURES, &backend_features ) ) ) {
    int err = errno; close( mem_fd ); errno = err; goto fail;
  }

  ulong wanted = FD_VIRTIO_F_VERSION_1 | FD_VIRTIO_NET_F_MRG_RXBUF | FD_VHOST_USER_F_PROTOCOL_FEAT;
  vhost->features = backend_features & wanted;
  vhost->virtio_hdr_sz = (vhost->features & (FD_VIRTIO_F_VERSION_1 | FD_VIRTIO_NET_F_MRG_RXBUF)) ? 12UL : 10UL;

  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_OWNER, NULL, 0U, NULL, 0UL ) ) ) {
    int err = errno; close( mem_fd ); errno = err; goto fail;
  }

  if( vhost->features & FD_VHOST_USER_F_PROTOCOL_FEAT ) {
    if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_GET_PROTOCOL_FEATURES, NULL, 0U, NULL, 0UL ) ) ) {
      int err = errno; close( mem_fd ); errno = err; goto fail;
    }
    ulong proto_feat = 0UL;
    if( FD_UNLIKELY( 0!=vhost_recv_u64( sock_fd, FD_VHOST_USER_GET_PROTOCOL_FEATURES, &proto_feat ) ) ) {
      int err = errno; close( mem_fd ); errno = err; goto fail;
    }
    vhost->proto_features = 0UL; /* Keep protocol features minimal */
    if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_PROTOCOL_FEATURES, &vhost->proto_features, sizeof(vhost->proto_features), NULL, 0UL ) ) ) {
      int err = errno; close( mem_fd ); errno = err; goto fail;
    }
  }

  if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_FEATURES, &vhost->features, sizeof(vhost->features), NULL, 0UL ) ) ) {
    int err = errno; close( mem_fd ); errno = err; goto fail;
  }

  /* 4. Share memfd region with backend (guest_phys_addr == userspace_addr == shm) */
  fd_vhost_mem_table_t mem_tbl = {
    .nregions = 1U,
    .padding  = 0U,
    .regions  = {{
      .guest_phys_addr = (ulong)shm,
      .memory_size     = shm_sz,
      .userspace_addr  = (ulong)shm,
      .mmap_offset     = 0UL,
    }},
  };
  int send_rc = vhost_send_msg( sock_fd, FD_VHOST_USER_SET_MEM_TABLE, &mem_tbl, sizeof(mem_tbl), &mem_fd, 1UL );
  int send_err = errno;
  close( mem_fd ); /* Mapping stays valid in both processes */
  if( FD_UNLIKELY( 0!=send_rc ) ) { errno = send_err; goto fail; }

  /* 5. Pre-populate RX virtqueue descriptors & avail ring before enabling */
  vhost->rx.avail->flags = FD_VHOST_VRING_AVAIL_F_NO_INTR;
  vhost->tx.avail->flags = FD_VHOST_VRING_AVAIL_F_NO_INTR;
  for( uint i=0U; i<rx_depth; i++ ) {
    vhost->rx.desc[ i ].addr  = (ulong)fd_vhost_buf_ptr( &vhost->rx, i );
    vhost->rx.desc[ i ].len   = (uint)FD_VHOST_BUF_STRIDE;
    vhost->rx.desc[ i ].flags = FD_VHOST_VRING_DESC_F_WRITE;
    vhost->rx.desc[ i ].next  = 0U;
    vhost->rx.avail->ring[ i ] = (ushort)i;
  }
  vhost->rx.avail_idx = (ushort)rx_depth;
  __atomic_store_n( &vhost->rx.avail->idx, vhost->rx.avail_idx, __ATOMIC_RELEASE );

  /* Pre-initialize TX descriptor buffer addresses */
  for( uint i=0U; i<tx_depth; i++ ) {
    vhost->tx.desc[ i ].addr  = (ulong)fd_vhost_buf_ptr( &vhost->tx, i );
    vhost->tx.desc[ i ].len   = 0U;
    vhost->tx.desc[ i ].flags = 0U;
    vhost->tx.desc[ i ].next  = 0U;
  }

  /* 6. Configure RX (qidx=0) and TX (qidx=1) vrings */
  if( FD_UNLIKELY( 0!=vhost_setup_vring( sock_fd, 0U, &vhost->rx ) ) ) goto fail;
  if( FD_UNLIKELY( 0!=vhost_setup_vring( sock_fd, 1U, &vhost->tx ) ) ) goto fail;

  /* 7. Enable both vrings if VHOST_USER_F_PROTOCOL_FEATURES was negotiated */
  if( vhost->features & FD_VHOST_USER_F_PROTOCOL_FEAT ) {
    fd_vhost_vring_state_t en0 = { .index = 0U, .num = 1U };
    fd_vhost_vring_state_t en1 = { .index = 1U, .num = 1U };
    if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_VRING_ENABLE, &en0, sizeof(en0), NULL, 0UL ) ) ) goto fail;
    if( FD_UNLIKELY( 0!=vhost_send_msg( sock_fd, FD_VHOST_USER_SET_VRING_ENABLE, &en1, sizeof(en1), NULL, 0UL ) ) ) goto fail;
  }

  /* Initial kick on both RX and TX so backend marks both vrings started and link UP */
  ulong kick_val = 1UL;
  (void)write( vhost->rx.kick_fd, &kick_val, sizeof(kick_val) );
  (void)write( vhost->tx.kick_fd, &kick_val, sizeof(kick_val) );

  return 0;

fail:
  {
    int saved_err = errno;
    fd_vhost_close( vhost );
    errno = saved_err;
    return -1;
  }
}

void
fd_vhost_close( fd_vhost_t * vhost ) {
  if( !vhost ) return;
  if( vhost->rx.kick_fd>=0 ) { close( vhost->rx.kick_fd ); vhost->rx.kick_fd = -1; }
  if( vhost->tx.kick_fd>=0 ) { close( vhost->tx.kick_fd ); vhost->tx.kick_fd = -1; }
  if( vhost->shm && vhost->shm!=MAP_FAILED ) {
    munmap( vhost->shm, vhost->shm_sz );
    vhost->shm    = NULL;
    vhost->shm_sz = 0UL;
  }
  if( vhost->sock_fd>=0 ) { close( vhost->sock_fd ); vhost->sock_fd = -1; }
}

int
fd_vhost_is_connected( fd_vhost_t const * vhost ) {
  if( FD_UNLIKELY( vhost->sock_fd<0 ) ) return 0;
  uchar b;
  long n = recvfrom( vhost->sock_fd, &b, 1UL, MSG_PEEK|MSG_DONTWAIT, NULL, NULL );
  if( FD_LIKELY( n<0L && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) ) ) return 1;
  if( n==0L ) return 0; /* Peer closed (VPP restarted / exited) */
  if( n<0L )  return 0; /* Socket error (ECONNRESET, EPIPE, etc.) */
  return 1;
}
