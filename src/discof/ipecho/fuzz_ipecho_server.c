#define _GNU_SOURCE
#include "fd_ipecho_server.h"
#include "../../util/fd_util.h"

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define MAX_CONN_CNT     (16UL)
#define MAX_CLIENT_CNT   (256UL)

static uchar server_mem[ 8192 ] __attribute__((aligned(128)));
static uint  loopback_addr;

static fd_ipecho_server_t * server;
static struct sockaddr_in   srv;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set( 4 );

  FD_TEST( fd_ipecho_server_footprint( MAX_CONN_CNT )<=sizeof(server_mem) );
  FD_TEST( 1==inet_pton( AF_INET, "127.0.0.1", &loopback_addr ) );

  server = fd_ipecho_server_join( fd_ipecho_server_new( server_mem, MAX_CONN_CNT ) );
  FD_TEST( server );

  fd_ipecho_server_init( server, loopback_addr, 0, 42 );

  int server_fd = fd_ipecho_server_sockfd( server );
  struct sockaddr_in bound_addr;
  uint bound_len = sizeof(bound_addr);
  FD_TEST( -1!=getsockname( server_fd, fd_type_pun( &bound_addr ), &bound_len ) );

  srv = (struct sockaddr_in){
    .sin_family      = AF_INET,
    .sin_port        = bound_addr.sin_port,
    .sin_addr.s_addr = loopback_addr,
  };

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<1UL ) ) return 0;

  ulong action_cnt = data[ 0 ];

#define ACTION_CONNECT    0 /* Followed by 1 byte connection index */
#define ACTION_DISCONNECT 1 /* Followed by 1 byte connection index */
#define ACTION_SEND       2 /* Followed by 1 byte connection index, 1 byte data length, then data */
#define ACTION_READ       3 /* Followed by 1 byte connection index, 1 byte read length */
#define ACTION_POLL       4 /* Single byte */
#define ACTION_SHUTDOWN   5 /* Followed by 1 byte connection index */
#define ACTION_CNT        6

  /* Pre-scan actions to compute total bytes needed, so we can reject
     undersized inputs upfront without inline bounds checks. */
  ulong needed = 0UL;
  {
    uchar const * scan = data+1UL;
    for( ulong i=0UL; i<action_cnt; i++ ) {
      if( FD_UNLIKELY( needed+1UL>size-1UL ) ) return 0;
      uchar action = scan[ needed ] % ACTION_CNT;
      needed++;
      switch( action ) {
        case ACTION_CONNECT:    needed += 1UL;                           break; /* 1+1 bytes */
        case ACTION_POLL:                                                break; /* 1 byte total */
        case ACTION_DISCONNECT: needed += 1UL;                           break; /* 1+1 bytes */
        case ACTION_SHUTDOWN:   needed += 1UL;                           break; /* 1+1 bytes */
        case ACTION_READ:       needed += 2UL;                           break; /* 1+2 bytes */
        case ACTION_SEND: {     /* 1+2 bytes header + send_sz payload */
          if( FD_UNLIKELY( needed+2UL>size-1UL ) ) return 0;
          needed += 2UL;
          ulong send_sz = (ulong)scan[ needed-1UL ];
          needed += send_sz;
          break;
        }
        default: break;
      }
    }
    if( FD_UNLIKELY( needed>size-1UL ) ) return 0;
  }

  int    client_fds[ MAX_CLIENT_CNT ];
  for( ulong i=0UL; i<MAX_CLIENT_CNT; i++ ) client_fds[ i ] = -1;

  uchar const * cur = data+1UL;

  for( ulong i=0UL; i<action_cnt; i++ ) {
    uchar action = cur[ 0 ] % ACTION_CNT;
    cur++;

    switch( action ) {
      case ACTION_CONNECT: {
        ulong idx = cur[ 0 ] % MAX_CLIENT_CNT;
        cur++;
        if( FD_UNLIKELY( client_fds[ idx ]!=-1 ) ) break;

        int cfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
        FD_TEST( cfd!=-1 );

        int one = 1;
        FD_TEST( -1!=setsockopt( cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one) ) );

        /* Force RST on close to avoid TIME_WAIT buildup across
           fuzzer iterations, which exhausts ephemeral ports. */
        struct linger lo = { .l_onoff=1, .l_linger=0 };
        FD_TEST( -1!=setsockopt( cfd, SOL_SOCKET, SO_LINGER, &lo, sizeof(lo) ) );
        if( FD_UNLIKELY( -1==connect( cfd, fd_type_pun( &srv ), sizeof(srv) ) && errno!=EINPROGRESS ) ) {
          FD_TEST( errno==ECONNREFUSED );
          FD_TEST( -1!=close( cfd ) );
          break;
        }
        client_fds[ idx ] = cfd;
        break;
      }

      case ACTION_DISCONNECT: {
        ulong idx = cur[ 0 ] % MAX_CLIENT_CNT;
        cur++;
        if( FD_UNLIKELY( client_fds[ idx ]==-1 ) ) break;
        FD_TEST( -1!=close( client_fds[ idx ] ) );
        client_fds[ idx ] = -1;
        break;
      }

      case ACTION_SEND: {
        ulong idx     = cur[ 0 ] % MAX_CLIENT_CNT;
        ulong send_sz = cur[ 1 ];
        cur += 2;
        if( FD_UNLIKELY( client_fds[ idx ]==-1 ) ) {
          cur += send_sz;
          break;
        }

        if( FD_LIKELY( send_sz ) ) {
          long written = send( client_fds[ idx ], cur, send_sz, MSG_NOSIGNAL );
          if( FD_UNLIKELY( -1==written ) ) {
            FD_TEST( errno==EAGAIN || errno==EPIPE || errno==ECONNRESET || errno==ENOTCONN );
            if( FD_UNLIKELY( errno==EPIPE || errno==ECONNRESET || errno==ENOTCONN ) ) {
              FD_TEST( -1!=close( client_fds[ idx ] ) );
              client_fds[ idx ] = -1;
            }
          }
        }
        cur += send_sz;
        break;
      }

      case ACTION_READ: {
        ulong idx     = cur[ 0 ] % MAX_CLIENT_CNT;
        ulong read_sz = cur[ 1 ] % 256UL;
        cur += 2;
        if( FD_UNLIKELY( client_fds[ idx ]==-1 ) ) break;

        uchar buf[ 256 ];
        long rd = read( client_fds[ idx ], buf, read_sz );
        if( FD_UNLIKELY( -1L==rd ) ) {
          FD_TEST( errno==EAGAIN || errno==ECONNRESET || errno==ENOTCONN );
          if( FD_UNLIKELY( errno==ECONNRESET || errno==ENOTCONN ) ) {
            FD_TEST( -1!=close( client_fds[ idx ] ) );
            client_fds[ idx ] = -1;
          }
        }
        break;
      }

      case ACTION_POLL: {
        int charge_busy = 0;
        fd_ipecho_server_poll( server, &charge_busy, 0 );
        break;
      }

      case ACTION_SHUTDOWN: {
        ulong idx = cur[ 0 ] % MAX_CLIENT_CNT;
        cur++;
        if( FD_UNLIKELY( client_fds[ idx ]==-1 ) ) break;
        if( FD_UNLIKELY( -1==shutdown( client_fds[ idx ], SHUT_WR ) ) ) FD_TEST( errno==ENOTCONN );
        break;
      }

      default: break;
    }
  }

  /* Drain and close all client sockets */
  for( ulong i=0UL; i<MAX_CLIENT_CNT; i++ ) {
    if( FD_LIKELY( client_fds[ i ]==-1 ) ) continue;
    FD_TEST( -1!=close( client_fds[ i ] ) );
  }

  /* Close accepted connections but keep the listen socket alive */
  fd_ipecho_server_close_conns( server );
  return 0;
}
