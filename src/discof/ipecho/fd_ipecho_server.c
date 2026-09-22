#define _GNU_SOURCE
#include "fd_ipecho_server.h"
#include "fd_ipecho_server_port_check.h"

#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define STATE_READING (0)
#define STATE_WRITING (1)

#define CLOSE_OK            ( 0)
#define CLOSE_EXPECTED_EOF  (-1)
#define CLOSE_PEER_RESET    (-2)
#define CLOSE_LARGE_REQUEST (-3)
#define CLOSE_BAD_HEADER    (-4)
#define CLOSE_BAD_TRAILER   (-5)
#define CLOSE_BAD_LENGTH    (-6)
#define CLOSE_EVICTED       (-7)

struct fd_ipecho_server_connection {
  int state;

  uint ipv4;

  ushort parent;

  ulong request_bytes_read;
  uchar request_bytes[ 22UL ];
  ulong response_bytes_written;
  uchar response_bytes[ 27UL ];
};

typedef struct fd_ipecho_server_connection fd_ipecho_server_connection_t;

#define POOL_NAME  conn_pool
#define POOL_T     fd_ipecho_server_connection_t
#define POOL_IDX_T ushort
#define POOL_NEXT  parent
#include "../../util/tmpl/fd_pool.c"

struct fd_ipecho_server {
  int sockfd;

  int epoll_fd;

  ushort shred_version;

  ulong evict_idx;
  ulong max_connection_cnt;

  fd_ipecho_server_connection_t * pool;
  struct pollfd *                 pollfds;

  fd_ipecho_server_port_check_t * port_check;

  fd_ipecho_server_metrics_t metrics[ 1 ];

  ulong magic;
};

FD_FN_CONST ulong
fd_ipecho_server_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_ipecho_server_footprint( ulong max_connection_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_ipecho_server_align(),            sizeof(fd_ipecho_server_t)                     );
  l = FD_LAYOUT_APPEND( l, conn_pool_align(),                   conn_pool_footprint( max_connection_cnt )      );
  l = FD_LAYOUT_APPEND( l, alignof(struct pollfd),              (1UL+max_connection_cnt)*sizeof(struct pollfd) );
  l = FD_LAYOUT_APPEND( l, fd_ipecho_server_port_check_align(), fd_ipecho_server_port_check_footprint() );
  return FD_LAYOUT_FINI( l, fd_ipecho_server_align() );
}

void *
fd_ipecho_server_new( void * shmem,
                      ulong  max_connection_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ipecho_server_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ipecho_server_t * server = FD_SCRATCH_ALLOC_APPEND( l, fd_ipecho_server_align(), sizeof(fd_ipecho_server_t)                     );
  void * pool                 = FD_SCRATCH_ALLOC_APPEND( l, conn_pool_align(),        conn_pool_footprint( max_connection_cnt )      );
  server->pollfds             = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct pollfd),   (1UL+max_connection_cnt)*sizeof(struct pollfd) );
  void * port_check           = FD_SCRATCH_ALLOC_APPEND( l, fd_ipecho_server_port_check_align(), fd_ipecho_server_port_check_footprint() );

  server->pool = conn_pool_join( conn_pool_new( pool, max_connection_cnt ) );
  FD_TEST( server->pool );

  server->port_check = fd_ipecho_server_port_check_join( fd_ipecho_server_port_check_new( port_check ) );
  FD_TEST( server->port_check );

  server->sockfd   = -1;
  server->epoll_fd = -1;

  for( ulong i=0UL; i<max_connection_cnt; i++ ) {
    server->pollfds[ i ].fd = -1;
    server->pollfds[ i ].events = POLLIN;
  }
  server->pollfds[ max_connection_cnt ].fd = -1;

  server->evict_idx = 0UL;
  server->max_connection_cnt = max_connection_cnt;

  memset( &server->metrics, 0, sizeof(server->metrics) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( server->magic ) = FD_IPECHO_SERVER_MAGIC;
  FD_COMPILER_MFENCE();

  return server;
}

fd_ipecho_server_t *
fd_ipecho_server_join( void * shipe ) {
  if( FD_UNLIKELY( !shipe ) ) {
    FD_LOG_WARNING(( "NULL shipe" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shipe, fd_ipecho_server_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shipe" ));
    return NULL;
  }

  fd_ipecho_server_t * server = (fd_ipecho_server_t *)shipe;

  if( FD_UNLIKELY( server->magic!=FD_IPECHO_SERVER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return server;
}

/* We handle epoll events for 3 kinds of sockets: already active
   clients, the listening socket, and the port check TCP connections.

   We use the high 32 bits of the data word to distinguish the socket
   type, and the low 32 bits to determine the connection.
   For active clients, the low 32 bits is the index into the
   server's connection pool. For the port check TCP sockets, the
   low 32 bits is the id returned by fd_ipecho_server_port_check_tcp. */

#define EPOLL_DATA_FLAG_CONN       (0UL<<32) /* active client */
#define EPOLL_DATA_FLAG_LISTENER   (1UL<<32) /* the listening socket */
#define EPOLL_DATA_FLAG_PORT_CHECK (2UL<<32) /* port check TCP socket */
#define EPOLL_DATA_FLAG_MASK       (0xFFFFFFFFUL)
#define EPOLL_DATA_FLAG( d )       ((d) & ~EPOLL_DATA_FLAG_MASK)
#define EPOLL_DATA_CONN_IDX( d )   ((d) &  EPOLL_DATA_FLAG_MASK)

static void
epoll_maybe_add_listener( fd_ipecho_server_t * server ) {
  if( FD_UNLIKELY( -1==server->sockfd ) ) return;
  if( FD_UNLIKELY( server->shred_version==0U ) ) return;
  struct epoll_event ev = { .events = EPOLLIN, .data.u64 = EPOLL_DATA_FLAG_LISTENER };
  if( FD_UNLIKELY( -1==epoll_ctl( server->epoll_fd, EPOLL_CTL_ADD, server->sockfd, &ev ) ) ) {
    if( FD_LIKELY( errno==EEXIST ) ) return;
    FD_LOG_ERR(( "epoll_ctl(ADD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

void
fd_ipecho_server_init( fd_ipecho_server_t * server,
                       int                  epoll_fd,
                       uint                 address,
                       ushort               port,
                       ushort               shred_version ) {

  FD_TEST( -1!=epoll_fd );
  server->epoll_fd = epoll_fd;

  /* If the shred version is 0 that means that the shred version has not
     been set yet. */
  server->shred_version = shred_version;

  server->sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==server->sockfd ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( server->sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) ) ) )
    FD_LOG_ERR(( "setsockopt failed (%i-%s)", errno, strerror( errno ) ));

  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( port ),
    .sin_addr.s_addr = address,
  };

  if( FD_UNLIKELY( -1==bind( server->sockfd, fd_type_pun( &addr ), sizeof( addr ) ) ) ) {
    FD_LOG_ERR(( "bind(%i,AF_INET," FD_IP4_ADDR_FMT ":%u) failed (%i-%s)",
                 server->sockfd, FD_IP4_ADDR_FMT_ARGS( address ), port,
                 errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==listen( server->sockfd, (int)server->max_connection_cnt ) ) ) FD_LOG_ERR(( "listen() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  server->pollfds[ server->max_connection_cnt ] = (struct pollfd){ .fd = server->sockfd, .events = POLLIN, .revents = 0 };
  epoll_maybe_add_listener( server );

  fd_ipecho_server_port_check_init( server->port_check, address );
}

void
fd_ipecho_server_fini( fd_ipecho_server_t * server ) {
  fd_ipecho_server_close_conns( server );
  if( FD_UNLIKELY( -1!=server->sockfd ) ) {
    FD_TEST( -1!=close( server->sockfd ) );
    server->sockfd = -1;
    server->pollfds[ server->max_connection_cnt ].fd = -1;
  }
  fd_ipecho_server_port_check_fini( server->port_check );
}

void
fd_ipecho_server_close_conns( fd_ipecho_server_t * server ) {
  for( ulong i=0UL; i<server->max_connection_cnt; i++ ) {
    if( FD_UNLIKELY( -1!=server->pollfds[ i ].fd ) ) {
      FD_TEST( -1!=close( server->pollfds[ i ].fd ) );
      server->pollfds[ i ].fd = -1;
      conn_pool_ele_release( server->pool, &server->pool[ i ] );
    }
  }
  server->metrics->connection_cnt = 0UL;
  server->evict_idx               = 0UL;

  fd_ipecho_server_port_check_close_all( server->port_check );
}

void
fd_ipecho_server_set_shred_version( fd_ipecho_server_t * server,
                                    ushort               shred_version ) {
  server->shred_version = shred_version;
  epoll_maybe_add_listener( server );
}

static inline int
is_expected_network_error( int err ) {
  return
    err==ENETDOWN ||
    err==EPROTO ||
    err==ENOPROTOOPT ||
    err==EHOSTDOWN ||
    err==ENONET ||
    err==EHOSTUNREACH ||
    err==EOPNOTSUPP ||
    err==ENETUNREACH ||
    err==ETIMEDOUT ||
    err==ENETRESET ||
    err==ECONNABORTED ||
    err==ECONNRESET ||
    err==EPIPE ||
    err==EPERM || /* iptables */
    err==ENOMEM; /* net stack OOM */
}

static void
close_conn( fd_ipecho_server_t * server,
            ulong                conn_idx,
            int                  reason ) {
  (void)reason;
  FD_TEST( server->pollfds[ conn_idx ].fd!=-1 );

  if( FD_UNLIKELY( -1==close( server->pollfds[ conn_idx ].fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, strerror( errno ) ));
  server->pollfds[ conn_idx ].fd = -1;
  conn_pool_ele_release( server->pool, &server->pool[ conn_idx ] );

  FD_TEST( server->metrics->connection_cnt );
  server->metrics->connection_cnt--;
  if( FD_UNLIKELY( reason==CLOSE_OK ) ) server->metrics->connections_closed_ok++;
  else                                  server->metrics->connections_closed_error++;
}

static void
epoll_conn_add( fd_ipecho_server_t * server,
                ulong                conn_idx ) {
  struct epoll_event ev = { .events = EPOLLIN, .data.u64 = EPOLL_DATA_FLAG_CONN|conn_idx };
  if( FD_UNLIKELY( -1==epoll_ctl( server->epoll_fd, EPOLL_CTL_ADD, server->pollfds[ conn_idx ].fd, &ev ) ) )
    FD_LOG_ERR(( "epoll_ctl(ADD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  server->pollfds[ conn_idx ].events = POLLIN;
}

static void
epoll_port_check_add( fd_ipecho_server_t * server,
                      ulong                check_id ) {
  int fd = fd_ipecho_server_port_check_conn_fd( server->port_check, check_id );
  struct epoll_event ev = { .events = EPOLLOUT, .data.u64 = EPOLL_DATA_FLAG_PORT_CHECK|check_id };
  if( FD_UNLIKELY( -1==epoll_ctl( server->epoll_fd, EPOLL_CTL_ADD, fd, &ev ) ) )
    FD_LOG_ERR(( "epoll_ctl(ADD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
epoll_update_out( fd_ipecho_server_t * server,
                  ulong                conn_idx ) {
  if( FD_UNLIKELY( -1==server->pollfds[ conn_idx ].fd ) ) return;
  short events = server->pool[ conn_idx ].state==STATE_WRITING ? POLLOUT : POLLIN;
  if( FD_LIKELY( server->pollfds[ conn_idx ].events==events ) ) return;
  struct epoll_event ev = {
    .events   = ((events & POLLIN) ? EPOLLIN : 0U) | ((events & POLLOUT) ? EPOLLOUT : 0U),
    .data.u64 = EPOLL_DATA_FLAG_CONN|conn_idx,
  };
  if( FD_UNLIKELY( -1==epoll_ctl( server->epoll_fd, EPOLL_CTL_MOD, server->pollfds[ conn_idx ].fd, &ev ) ) )
    FD_LOG_ERR(( "epoll_ctl(MOD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  server->pollfds[ conn_idx ].events = events;
}


static void
accept_conns( fd_ipecho_server_t * server ) {
  for(;;) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = accept4( server->pollfds[ server->max_connection_cnt ].fd, fd_type_pun( &addr ), &addr_len, SOCK_NONBLOCK|SOCK_CLOEXEC );

    if( FD_UNLIKELY( -1==fd ) ) {
      if( FD_LIKELY( EAGAIN==errno ) ) break;
      else if( FD_LIKELY( is_expected_network_error( errno ) ) ) continue;
      else FD_LOG_ERR(( "accept4() failed (%i-%s)", errno, strerror( errno ) ));
    }

    if( FD_UNLIKELY( !conn_pool_free( server->pool ) ) ) {
      close_conn( server, server->evict_idx, CLOSE_EVICTED );
      server->evict_idx = (server->evict_idx+1UL) % server->max_connection_cnt;
    }
    ulong conn_id = conn_pool_idx_acquire( server->pool );

    server->pollfds[ conn_id ].fd     = fd;
    server->pollfds[ conn_id ].events = POLLIN;
    epoll_conn_add( server, conn_id );
    server->pool[ conn_id ].ipv4                   = addr.sin_addr.s_addr;
    server->pool[ conn_id ].state                  = STATE_READING;
    server->pool[ conn_id ].request_bytes_read     = 0UL;
    server->pool[ conn_id ].response_bytes_written = 0UL;

    server->metrics->connection_cnt++;
  }
}

static void
read_conn( fd_ipecho_server_t * server,
           ulong                conn_idx,
           long                 now ) {
  fd_ipecho_server_connection_t * conn = &server->pool[ conn_idx ];

  if( FD_UNLIKELY( conn->state!=STATE_READING ) ) {
    close_conn( server, conn_idx, CLOSE_EXPECTED_EOF );
    return;
  }

  long sz = read( server->pollfds[ conn_idx ].fd, conn->request_bytes+conn->request_bytes_read, sizeof(conn->request_bytes)-conn->request_bytes_read );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data to read, continue. */
  else if( -1==sz && is_expected_network_error( errno ) ) {
    close_conn( server, conn_idx, CLOSE_PEER_RESET );
    return;
  }
  else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  if( FD_UNLIKELY( !sz && conn->request_bytes_read!=21UL ) ) {
    close_conn( server, conn_idx, CLOSE_BAD_LENGTH );
    return;
  }

  /* New data was read... process it */
  server->metrics->bytes_read += (ulong)sz;
  conn->request_bytes_read += (ulong)sz;
  if( FD_UNLIKELY( conn->request_bytes_read==sizeof(conn->request_bytes) ) ) {
    close_conn( server, conn_idx, CLOSE_LARGE_REQUEST );
    return;
  }

  if( FD_UNLIKELY( conn->request_bytes_read<21UL ) ) return;

  if( FD_UNLIKELY( memcmp( conn->request_bytes, "\0\0\0\0", 4UL ) ) ) {
    close_conn( server, conn_idx, CLOSE_BAD_HEADER );
    return;
  }

  if( FD_UNLIKELY( conn->request_bytes[ 20UL ]!='\n' ) ) {
    close_conn( server, conn_idx, CLOSE_BAD_TRAILER );
    return;
  }

  /* Send a UDP datagram to each non-zero UDP port in the
     IpEchoServerMessage, and try to connect to each non-zero TCP port.

     These are the same semantics as Agave's IP echo server. If we
     don't do this Agave nodes without --no-port-check will fail to
     join our entrypoint.

     https://github.com/anza-xyz/agave/blob/v4.3.0/net-utils/src/ip_echo_server.rs#L132-L165 */
  for( ulong i=0UL; i<4UL; i++ ) {
    /* Safe because we read up to conn->request_bytes[19] here, and
       the checks above ensure that request_bytes is exactly 21 bytes. */
    ushort tcp_port = FD_LOAD( ushort, conn->request_bytes+4UL+2UL*i  );
    ushort udp_port = FD_LOAD( ushort, conn->request_bytes+12UL+2UL*i );

    /* We expect most operators to have port checks disabled */
    if( FD_UNLIKELY( tcp_port ) ) {
      ulong check_id = fd_ipecho_server_port_check_tcp( server->port_check, conn->ipv4, tcp_port, now );
      if( FD_LIKELY( check_id!=ULONG_MAX ) ) epoll_port_check_add( server, check_id );
    }
    if( FD_UNLIKELY( udp_port ) ) {
      fd_ipecho_server_port_check_udp( server->port_check, conn->ipv4, udp_port );
    }
  }

  uchar response[ 27UL ] = {
    0, 0, 0, 0, /* Magic */
    0, 0, 0, 0, /* IP address variant */
    0, 0, 0, 0, /* IP address */
    1,          /* Shred version option variant */
    0, 0,       /* Shred version */
    0,          /* [...] 12 bytes of trailing garbage, as in Agave */
  };

  FD_STORE( uint,   response+8UL,  conn->ipv4 );
  FD_STORE( ushort, response+13UL, server->shred_version );

  /* Now have a complete request ... buffer response */
  conn->state = STATE_WRITING;
  conn->response_bytes_written = 0UL;
  memcpy( conn->response_bytes, response, sizeof(response) );
}

static void
write_conn( fd_ipecho_server_t * server,
            ulong                conn_idx ) {
  fd_ipecho_server_connection_t * conn = &server->pool[ conn_idx ];

  if( FD_LIKELY( conn->state==STATE_READING ) ) return;

  long sz = sendto( server->pollfds[ conn_idx ].fd, conn->response_bytes+conn->response_bytes_written, sizeof(conn->response_bytes)-conn->response_bytes_written, MSG_NOSIGNAL, NULL, 0 );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data was written, continue. */
  if( FD_UNLIKELY( -1==sz && is_expected_network_error( errno ) ) ) {
    close_conn( server, conn_idx, CLOSE_PEER_RESET );
    return;
  }
  if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  server->metrics->bytes_written += (ulong)sz;
  conn->response_bytes_written += (ulong)sz;
  if( FD_UNLIKELY( conn->response_bytes_written<sizeof(conn->response_bytes) ) ) return;

  close_conn( server, conn_idx, CLOSE_OK );
}


int
fd_ipecho_server_epoll_poll( fd_ipecho_server_t * server,
                             long                 now,
                             int *                charge_busy ) {
  FD_TEST( -1!=server->epoll_fd );

  if( FD_UNLIKELY( server->shred_version==0U ) ) return 0;

  struct epoll_event evs[ 64 ];
  int nfds = epoll_pwait( server->epoll_fd, evs, 64, 0, NULL );
  if( FD_UNLIKELY( -1==nfds ) ) {
    if( FD_LIKELY( errno==EINTR ) ) return 0;
    FD_LOG_ERR(( "epoll_pwait failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY( !nfds ) ) return 0;

  *charge_busy = 1;
  for( int i=0; i<nfds; i++ ) {
    ulong data = evs[ i ].data.u64;
    switch( EPOLL_DATA_FLAG( data ) ) {
    case EPOLL_DATA_FLAG_LISTENER:
      /* New connections to the ipecho server */
      accept_conns( server );
      break;
    case EPOLL_DATA_FLAG_PORT_CHECK:
      /* Port check TCP sockets (handshake succeeded or errored) */
      fd_ipecho_server_port_check_handle_event( server->port_check, EPOLL_DATA_CONN_IDX( data ) );
      break;
    case EPOLL_DATA_FLAG_CONN: {
      /* Existing non-port-check connections to the ipecho server */
      ulong conn_idx = EPOLL_DATA_CONN_IDX( data );
      if( FD_UNLIKELY( -1==server->pollfds[ conn_idx ].fd ) ) break;
      if( FD_LIKELY(   evs[ i ].events & (EPOLLIN|EPOLLHUP|EPOLLERR) ) ) read_conn(  server, conn_idx, now );
      if( FD_UNLIKELY( -1==server->pollfds[ conn_idx ].fd ) ) break;
      if( FD_LIKELY(   evs[ i ].events & EPOLLOUT             ) ) write_conn( server, conn_idx );
      if( FD_UNLIKELY( -1==server->pollfds[ conn_idx ].fd ) ) break;
      epoll_update_out( server, conn_idx );
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected epoll data flag 0x%lx", EPOLL_DATA_FLAG( data ) ));
    }
  }

  return 1;
}

fd_ipecho_server_metrics_t *
fd_ipecho_server_metrics( fd_ipecho_server_t * server ) {
  return server->metrics;
}

int
fd_ipecho_server_sockfd( fd_ipecho_server_t * server ) {
  return server->sockfd;
}

fd_ipecho_server_port_check_t *
fd_ipecho_server_port_check( fd_ipecho_server_t * server ) {
  return server->port_check;
}
