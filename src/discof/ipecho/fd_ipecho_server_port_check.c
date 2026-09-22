#define _GNU_SOURCE
#include "fd_ipecho_server_port_check.h"

#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"
#include "../../tango/tempo/fd_tempo.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* The maximum number of outgoing TCP connections the port check makes
   for each joiner IP address. We use 4 because that is the maximum
   number of TCP ports that can be listed in an IpEchoServerMessage.
   This enables us to create all connections for a joiner node at once,
   whilst protecting us from malicious joiner nodes flooding us with
   IpEchoServerMessages. */

#define FD_IPECHO_SERVER_PORT_CHECK_MAX_PER_IP (4UL)

/* How long we wait for the TCP handshake to be completed before
   closing the connection. We use 4s because Linux re-transmits
   unanswered SYN packets after 1s and 3s, so we want to give the
   kernel time to re-transmit unanswered SYNs. The Agave joining node
   gives up after 5s, so there is no point waiting close to 5s.
   Therefore, we wait 4s. */

#define FD_IPECHO_SERVER_PORT_CHECK_TIMEOUT_NS ((long)4e9)

struct conn {
  int    fd;
  long   deadline_ticks;
  uint   ipv4;
  ushort gen;
};

typedef struct conn conn_t;

/* A connection's ID is a combination of the index into the connections
   array and the "generation" - every time we re-use a connection
   index we increment the generation. This is to distinguish events
   relating to connections that do not exist anymore. */

#define CONN_ID( gen, idx ) ( ((ulong)(gen)<<16) | (ulong)(idx) )
#define CONN_ID_IDX( t )    ( (t) & 0xFFFFUL )
#define CONN_ID_GEN( t )    ( ((t)>>16) & 0xFFFFUL )

struct fd_ipecho_server_port_check {
  int  udp_sockfd;
  long timeout_ticks;

  ulong  conn_cnt;
  conn_t conns[ FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX ];

  fd_ipecho_server_port_check_metrics_t metrics[ 1 ];

  ulong magic;
};

FD_FN_CONST ulong
fd_ipecho_server_port_check_align( void ) {
  return alignof(fd_ipecho_server_port_check_t);
}

FD_FN_CONST ulong
fd_ipecho_server_port_check_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, fd_ipecho_server_port_check_align(), sizeof(fd_ipecho_server_port_check_t) );
  return FD_LAYOUT_FINI( l, fd_ipecho_server_port_check_align() );
}

void *
fd_ipecho_server_port_check_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ipecho_server_port_check_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_ipecho_server_port_check_t * pc = shmem;
  for( ulong i=0UL; i<FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX; i++ ) pc->conns[ i ] = (conn_t){ .fd = -1 };
  pc->conn_cnt = 0UL;

  pc->udp_sockfd = -1;

  memset( pc->metrics, 0, sizeof(pc->metrics) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pc->magic ) = FD_IPECHO_SERVER_PORT_CHECK_MAGIC;
  FD_COMPILER_MFENCE();

  return pc;
}

fd_ipecho_server_port_check_t *
fd_ipecho_server_port_check_join( void * shpc ) {
  if( FD_UNLIKELY( !shpc ) ) {
    FD_LOG_WARNING(( "NULL shpc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shpc, fd_ipecho_server_port_check_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shpc" ));
    return NULL;
  }

  fd_ipecho_server_port_check_t * pc = (fd_ipecho_server_port_check_t *)shpc;

  if( FD_UNLIKELY( pc->magic!=FD_IPECHO_SERVER_PORT_CHECK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return pc;
}

void
fd_ipecho_server_port_check_init( fd_ipecho_server_port_check_t * pc,
                                  uint                            address ) {
  pc->timeout_ticks = (long)( (double)FD_IPECHO_SERVER_PORT_CHECK_TIMEOUT_NS*fd_tempo_tick_per_ns( NULL ) );
  pc->udp_sockfd    = socket( AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( -1==pc->udp_sockfd ) ) {
    FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = address };
  if( FD_UNLIKELY( -1==bind( pc->udp_sockfd, fd_type_pun( &addr ), sizeof(addr) ) ) ) {
    FD_LOG_ERR(( "bind(" FD_IP4_ADDR_FMT ":0) failed (%i-%s)",
      FD_IP4_ADDR_FMT_ARGS( address ), errno, fd_io_strerror( errno ) ));
  }

  /* We don't need to ever read from this socket, so set the receive
     buffer to the minimum so that the kernel will drop any inbound
     packets. */
  int rcvbuf = 0;
  if( FD_UNLIKELY( -1==setsockopt( pc->udp_sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf) ) ) ) {
    FD_LOG_ERR(( "setsockopt(SO_RCVBUF) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

void
fd_ipecho_server_port_check_fini( fd_ipecho_server_port_check_t * pc ) {
  fd_ipecho_server_port_check_close_all( pc );
  if( FD_LIKELY( -1!=pc->udp_sockfd ) ) {
    FD_TEST( -1!=close( pc->udp_sockfd ) );
    pc->udp_sockfd = -1;
  }
}

void
fd_ipecho_server_port_check_close_all( fd_ipecho_server_port_check_t * pc ) {
  for( ulong i=0UL; i<FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX; i++ ) {
    if( FD_LIKELY( -1==pc->conns[ i ].fd ) ) continue;
    FD_TEST( -1!=close( pc->conns[ i ].fd ) );
    pc->conns[ i ].fd = -1;
  }
  pc->conn_cnt        = 0UL;
  pc->metrics->active = 0UL;
}

static void
conn_finish( fd_ipecho_server_port_check_t * pc,
             conn_t *                        conn,
             int                             outcome ) {
  if( FD_UNLIKELY( -1==close( conn->fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  conn->fd = -1;

  pc->metrics->tcp[ outcome ]++;
  pc->conn_cnt--;
  pc->metrics->active--;
}

void
fd_ipecho_server_port_check_udp( fd_ipecho_server_port_check_t * pc,
                                 uint                            ipv4,
                                 ushort                          port ) {
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = fd_ushort_bswap( port ), .sin_addr.s_addr = ipv4 };
  uchar const        zero = 0;
  if( FD_UNLIKELY( -1L==sendto(
    pc->udp_sockfd, &zero, 1UL, MSG_NOSIGNAL, fd_type_pun_const( &addr ), sizeof(addr) ) ) ) {
    if( FD_UNLIKELY( errno==EBADF || errno==ENOTSOCK || errno==EFAULT ) ) {
      FD_LOG_ERR(( "sendto failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    return;
  }
  pc->metrics->udp_sent++;
}

ulong
fd_ipecho_server_port_check_tcp( fd_ipecho_server_port_check_t * pc,
                                 uint                            ipv4,
                                 ushort                          port,
                                 long                            now ) {
  /* Check that we haven't exceeded the maximum amount of active
     connections to this IP. */
  ulong in_flight_cnt = 0UL;
  for( ulong i=0UL; i<FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX; i++ ) {
    in_flight_cnt += (ulong)( pc->conns[ i ].fd!=-1 && pc->conns[ i ].ipv4==ipv4 );
  }
  if( FD_UNLIKELY( in_flight_cnt>=FD_IPECHO_SERVER_PORT_CHECK_MAX_PER_IP ) ) {
    pc->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_REJECTED_PER_IP ]++;
    return ULONG_MAX;
  }

  /* Check that we haven't exceeded the maximum amount of total active
     connections. If we have, evict the oldest one. */
  if( FD_UNLIKELY( pc->conn_cnt>=FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX ) ) {
    ulong oldest                = 0UL;
    long  oldest_deadline_ticks = LONG_MAX;
    for( ulong i=0UL; i<FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX; i++ ) {
      long deadline_ticks = pc->conns[ i ].deadline_ticks;
      if( FD_UNLIKELY( deadline_ticks<oldest_deadline_ticks ) ) {
        oldest                = i;
        oldest_deadline_ticks = deadline_ticks;
      }
    }
    conn_finish( pc, &pc->conns[ oldest ], FD_IPECHO_SERVER_PORT_CHECK_TCP_EVICTED );
  }

  /* Open a TCP connection to the given ip and port. */
  int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( -1==fd ) ) {
    if( FD_UNLIKELY( errno==EBADF || errno==ENOTSOCK || errno==EFAULT ) ) {
      FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    pc->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_DROPPED ]++;
    return ULONG_MAX;
  }

  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = fd_ushort_bswap( port ), .sin_addr.s_addr = ipv4 };
  if( FD_UNLIKELY( -1==connect( fd, fd_type_pun_const( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
    if( FD_UNLIKELY( errno==EBADF || errno==ENOTSOCK || errno==EFAULT ) ) {
      FD_LOG_ERR(( "connect() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( -1==close( fd ) ) ) {
      FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    pc->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_FAILED ]++;
    return ULONG_MAX;
  }

  /* Return the index of the connection for the caller to pass in
     to fd_ipecho_server_port_check_handle_event */
  ulong idx = 0UL;
  while( pc->conns[ idx ].fd!=-1 ) idx++;
  ushort gen = (ushort)( pc->conns[ idx ].gen+1 );
  pc->conns[ idx ] = (conn_t){ .fd = fd, .deadline_ticks = now+pc->timeout_ticks, .ipv4 = ipv4, .gen = gen };
  pc->conn_cnt++;
  pc->metrics->active++;
  return CONN_ID( gen, idx );
}

void
fd_ipecho_server_port_check_handle_event( fd_ipecho_server_port_check_t * pc,
                                          ulong                           id ) {
  ulong idx = CONN_ID_IDX( id );
  FD_TEST( idx<FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX );
  conn_t * conn = &pc->conns[ idx ];
  if( FD_UNLIKELY( conn->fd==-1 || conn->gen!=CONN_ID_GEN( id ) ) ) return; /* stale event */

  int err = 0;
  socklen_t err_len = sizeof(err);
  if( FD_UNLIKELY( -1==getsockopt( conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len ) ) ) err = errno;

  conn_finish( pc, conn, err ? FD_IPECHO_SERVER_PORT_CHECK_TCP_FAILED : FD_IPECHO_SERVER_PORT_CHECK_TCP_CONNECTED );
}

void
fd_ipecho_server_port_check_prune( fd_ipecho_server_port_check_t * pc,
                                   long                            now ) {
  if( FD_LIKELY( !pc->conn_cnt ) ) return;
  for( ulong i=0UL; i<FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX; i++ ) {
    conn_t * conn = &pc->conns[ i ];
    if( FD_UNLIKELY( conn->fd!=-1 && now>=conn->deadline_ticks ) ) {
      conn_finish( pc, conn, FD_IPECHO_SERVER_PORT_CHECK_TCP_TIMEOUT );
    }
  }
}

fd_ipecho_server_port_check_metrics_t *
fd_ipecho_server_port_check_metrics( fd_ipecho_server_port_check_t * pc ) {
  return pc->metrics;
}

int
fd_ipecho_server_port_check_conn_fd( fd_ipecho_server_port_check_t * pc,
                                     ulong                           id ) {
  ulong idx = CONN_ID_IDX( id );
  FD_TEST( idx<FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX );
  FD_TEST( pc->conns[ idx ].fd!=-1 && pc->conns[ idx ].gen==CONN_ID_GEN( id ) );
  return pc->conns[ idx ].fd;
}

int
fd_ipecho_server_port_check_udp_sockfd( fd_ipecho_server_port_check_t * pc ) {
  return pc->udp_sockfd;
}
