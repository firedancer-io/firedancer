#define _GNU_SOURCE
#include "fd_vhost.h"
#include "../../../util/fd_util.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct __attribute__((packed)) mock_hdr {
  uint request;
  uint flags;
  uint size;
};

struct __attribute__((packed)) mock_mem_region {
  ulong guest_phys_addr;
  ulong memory_size;
  ulong userspace_addr;
  ulong mmap_offset;
};

struct __attribute__((packed)) mock_mem_table {
  uint                   nregions;
  uint                   padding;
  struct mock_mem_region regions[1];
};

struct __attribute__((packed)) mock_vring_state {
  uint index;
  uint num;
};

struct __attribute__((packed)) mock_vring_addr {
  uint  index;
  uint  flags;
  ulong desc_user_addr;
  ulong used_user_addr;
  ulong avail_user_addr;
  ulong log_guest_addr;
};

struct mock_server_ctx {
  int                listen_fd;
  int                conn_fd;
  uchar *            shm;
  ulong              shm_sz;
  ulong              client_shm_base;
  fd_vring_desc_t *  rx_desc;
  fd_vring_avail_t * rx_avail;
  fd_vring_used_t *  rx_used;
  fd_vring_desc_t *  tx_desc;
  fd_vring_avail_t * tx_avail;
  fd_vring_used_t *  tx_used;
  uint               rx_depth;
  uint               tx_depth;
  volatile int       ready;
  volatile int       stop;
};

static int
recv_msg_with_fd( int               fd,
                  struct mock_hdr * hdr,
                  void *            payload,
                  ulong             payload_cap,
                  int *             out_fd ) {
  *out_fd = -1;
  struct iovec iov = { .iov_base = hdr, .iov_len = sizeof(*hdr) };
  union {
    char           buf[ CMSG_SPACE( sizeof(int)*4UL ) ];
    struct cmsghdr align;
  } cmsg_buf;
  struct msghdr msg;
  memset( &msg, 0, sizeof(msg) );
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = cmsg_buf.buf;
  msg.msg_controllen = sizeof(cmsg_buf.buf);

  long n = recvmsg( fd, &msg, 0 );
  if( n!=(long)sizeof(*hdr) ) return -1;

  for( struct cmsghdr * c = CMSG_FIRSTHDR( &msg ); c; c = CMSG_NXTHDR( &msg, c ) ) {
    if( c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS ) {
      memcpy( out_fd, CMSG_DATA( c ), sizeof(int) );
      break;
    }
  }
  if( hdr->size>0U ) {
    FD_TEST( hdr->size<=payload_cap );
    ulong rem = hdr->size;
    uchar * p = (uchar *)payload;
    while( rem>0UL ) {
      long r = recv( fd, p, rem, 0 );
      if( r<=0L ) return -1;
      p   += (ulong)r;
      rem -= (ulong)r;
    }
  }
  return 0;
}

static void
send_u64_reply( int   fd,
                uint  req,
                ulong val ) {
  struct mock_hdr hdr = { .request = req, .flags = FD_VHOST_USER_VERSION | 0x4U, .size = sizeof(ulong) };
  FD_TEST( send( fd, &hdr, sizeof(hdr), 0 )==(long)sizeof(hdr) );
  FD_TEST( send( fd, &val, sizeof(val), 0 )==(long)sizeof(val) );
}

static void *
mock_server_thread( void * arg ) {
  struct mock_server_ctx * s = (struct mock_server_ctx *)arg;
  s->conn_fd = accept( s->listen_fd, NULL, NULL );
  FD_TEST( s->conn_fd>=0 );

  uchar payload[ 1024 ];
  int vring_enabled = 0;
  while( !s->stop ) {
    struct mock_hdr hdr;
    int rfd = -1;
    if( 0!=recv_msg_with_fd( s->conn_fd, &hdr, payload, sizeof(payload), &rfd ) ) break;

    switch( hdr.request ) {
    case FD_VHOST_USER_GET_FEATURES:
      send_u64_reply( s->conn_fd, hdr.request, FD_VIRTIO_F_VERSION_1 | FD_VHOST_USER_F_PROTOCOL_FEAT );
      break;
    case FD_VHOST_USER_GET_PROTOCOL_FEATURES:
      send_u64_reply( s->conn_fd, hdr.request, 0UL );
      break;
    case FD_VHOST_USER_SET_OWNER:
    case FD_VHOST_USER_SET_FEATURES:
    case FD_VHOST_USER_SET_PROTOCOL_FEATURES:
    case FD_VHOST_USER_SET_VRING_BASE:
    case FD_VHOST_USER_SET_VRING_CALL:
      break;
    case FD_VHOST_USER_SET_MEM_TABLE: {
      struct mock_mem_table const * tbl = (struct mock_mem_table const *)payload;
      FD_TEST( tbl->nregions==1U );
      FD_TEST( rfd>=0 );
      s->shm_sz          = tbl->regions[0].memory_size;
      s->client_shm_base = tbl->regions[0].userspace_addr;
      s->shm             = mmap( NULL, s->shm_sz, PROT_READ|PROT_WRITE, MAP_SHARED, rfd, 0 );
      FD_TEST( s->shm!=MAP_FAILED );
      close( rfd );
      break;
    }
    case FD_VHOST_USER_SET_VRING_NUM: {
      struct mock_vring_state const * st = (struct mock_vring_state const *)payload;
      if( st->index==0U ) s->rx_depth = st->num;
      else                s->tx_depth = st->num;
      break;
    }
    case FD_VHOST_USER_SET_VRING_ADDR: {
      struct mock_vring_addr const * a = (struct mock_vring_addr const *)payload;
      ulong d_off = a->desc_user_addr  - s->client_shm_base;
      ulong u_off = a->used_user_addr  - s->client_shm_base;
      ulong a_off = a->avail_user_addr - s->client_shm_base;
      if( a->index==0U ) {
        s->rx_desc  = (fd_vring_desc_t  *)(s->shm + d_off);
        s->rx_used  = (fd_vring_used_t  *)(s->shm + u_off);
        s->rx_avail = (fd_vring_avail_t *)(s->shm + a_off);
        s->rx_used->flags = FD_VHOST_VRING_USED_F_NO_NOTIF;
      } else {
        s->tx_desc  = (fd_vring_desc_t  *)(s->shm + d_off);
        s->tx_used  = (fd_vring_used_t  *)(s->shm + u_off);
        s->tx_avail = (fd_vring_avail_t *)(s->shm + a_off);
        s->tx_used->flags = FD_VHOST_VRING_USED_F_NO_NOTIF;
      }
      break;
    }
    case FD_VHOST_USER_SET_VRING_KICK:
      if( rfd>=0 ) close( rfd );
      break;
    case FD_VHOST_USER_SET_VRING_ENABLE:
      vring_enabled++;
      if( vring_enabled==2 ) {
        __atomic_store_n( &s->ready, 1, __ATOMIC_RELEASE );
        goto done_handshake;
      }
      break;
    default:
      FD_LOG_ERR(( "unexpected vhost-user req %u", hdr.request ));
    }
  }

done_handshake:
  /* Echo loop: forward any TX packet back to RX */
  {
    ushort tx_last = 0U;
    ushort rx_last = 0U;
    while( !__atomic_load_n( &s->stop, __ATOMIC_ACQUIRE ) ) {
      ushort tx_avail = __atomic_load_n( &s->tx_avail->idx, __ATOMIC_ACQUIRE );
      if( tx_last==tx_avail ) {
        usleep( 1000 );
        continue;
      }
      ushort tx_id  = s->tx_avail->ring[ tx_last & (s->tx_depth - 1U) ];
      ulong  tx_off = s->tx_desc[ tx_id ].addr - s->client_shm_base;
      uint   tx_len = s->tx_desc[ tx_id ].len;

      ushort rx_avail = __atomic_load_n( &s->rx_avail->idx, __ATOMIC_ACQUIRE );
      FD_TEST( rx_last!=rx_avail );
      ushort rx_id  = s->rx_avail->ring[ rx_last & (s->rx_depth - 1U) ];
      ulong  rx_off = s->rx_desc[ rx_id ].addr - s->client_shm_base;
      memcpy( s->shm + rx_off, s->shm + tx_off, tx_len );

      s->rx_used->ring[ rx_last & (s->rx_depth - 1U) ].id  = rx_id;
      s->rx_used->ring[ rx_last & (s->rx_depth - 1U) ].len = tx_len;
      rx_last++;
      __atomic_store_n( &s->rx_used->idx, rx_last, __ATOMIC_RELEASE );

      s->tx_used->ring[ tx_last & (s->tx_depth - 1U) ].id  = tx_id;
      s->tx_used->ring[ tx_last & (s->tx_depth - 1U) ].len = 0U;
      tx_last++;
      __atomic_store_n( &s->tx_used->idx, tx_last, __ATOMIC_RELEASE );
    }
  }

  close( s->conn_fd );
  s->conn_fd = -1;
  if( s->shm ) munmap( s->shm, s->shm_sz );
  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char sock_path[ 128 ];
  snprintf( sock_path, sizeof(sock_path), "/tmp/test_fd_vhost_%d.sock", (int)getpid() );
  unlink( sock_path );

  int lfd = socket( AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0 );
  FD_TEST( lfd>=0 );
  struct sockaddr_un sun;
  memset( &sun, 0, sizeof(sun) );
  sun.sun_family = AF_UNIX;
  strncpy( sun.sun_path, sock_path, sizeof(sun.sun_path)-1UL );
  FD_TEST( 0==bind( lfd, (struct sockaddr *)&sun, sizeof(sun) ) );
  FD_TEST( 0==listen( lfd, 1 ) );

  struct mock_server_ctx srv;
  memset( &srv, 0, sizeof(srv) );
  srv.listen_fd = lfd;
  srv.conn_fd   = -1;

  pthread_t thr;
  FD_TEST( 0==pthread_create( &thr, NULL, mock_server_thread, &srv ) );

  fd_vhost_t vhost;
  FD_TEST( 0==fd_vhost_connect( &vhost, sock_path, 256U, 256U ) );
  FD_TEST( vhost.virtio_hdr_sz==12UL );
  FD_TEST( 1==fd_vhost_is_connected( &vhost ) );

  while( !__atomic_load_n( &srv.ready, __ATOMIC_ACQUIRE ) ) usleep( 1000 );

  /* Transmit a test packet over TX virtqueue and receive echoed packet on RX */
  char const msg[] = "hello vhost-user!";
  uchar * tx_buf = fd_vhost_buf_ptr( &vhost.tx, 0U );
  memset( tx_buf, 0, vhost.virtio_hdr_sz );
  memcpy( tx_buf + vhost.virtio_hdr_sz, msg, sizeof(msg) );
  vhost.tx.desc[ 0 ].len = (uint)(vhost.virtio_hdr_sz + sizeof(msg));
  vhost.tx.avail->ring[ 0 ] = 0U;
  vhost.tx.avail_idx = 1U;
  __atomic_store_n( &vhost.tx.avail->idx, 1U, __ATOMIC_RELEASE );

  /* Wait for RX echo */
  while( __atomic_load_n( &vhost.rx.used->idx, __ATOMIC_ACQUIRE )==0U ) usleep( 1000 );
  FD_TEST( __atomic_load_n( &vhost.tx.used->idx, __ATOMIC_ACQUIRE )==1U );
  uint rx_id  = vhost.rx.used->ring[ 0 ].id;
  uint rx_len = vhost.rx.used->ring[ 0 ].len;
  FD_TEST( rx_len==vhost.virtio_hdr_sz + sizeof(msg) );
  uchar const * rx_buf = fd_vhost_buf_ptr( &vhost.rx, rx_id ) + vhost.virtio_hdr_sz;
  FD_TEST( 0==memcmp( rx_buf, msg, sizeof(msg) ) );

  /* Test disconnect detection (simulating VPP restart) */
  __atomic_store_n( &srv.stop, 1, __ATOMIC_RELEASE );
  pthread_join( thr, NULL );
  FD_TEST( 0==fd_vhost_is_connected( &vhost ) );

  fd_vhost_close( &vhost );
  close( lfd );
  unlink( sock_path );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
