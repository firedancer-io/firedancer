/* fd_tlscat is a netcat-like command-line utility. */

#include "fd_tlsrec.h"
#include "fd_tlsrec_frag.h"
#include "../../util/net/fd_ip4.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"

#if !FD_HAS_HOSTED
#error "fd_tlscat requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>

int
usage( int code ) {
  fprintf( stderr,
    "usage: fd_tlscat [options] [hostname] [port]\n"
    "\n"
    "fd_tlscat connects to a TLS 1.3 peer and forwards stdin/stdout.\n"
    "It is intended as a debug tool and does not offer high performance.\n"
    "Only supports IPv4.\n"
    "\n"
    "OPTIONS\n"
    "  -l         Server mode\n"
    "  -p <port>  Listen port\n"
    "\n" );
  return code;
}

static uchar rx_buf[ FD_TLSREC_CAP ];
static uchar tx_buf[ FD_TLSREC_CAP ];

static int
handshake( fd_tlsrec_conn_t * conn,
           int                sock_fd ) {

  fd_tlsrec_slice_t rx[1];
  fd_tlsrec_slice_init( rx, NULL, 0UL );
  for(;;) {

    ulong tx_buf_sz = sizeof(tx_buf);
    int hs_res = fd_tlsrec_conn_rx( conn, rx, tx_buf, &tx_buf_sz, NULL, 0UL );
    if( FD_UNLIKELY( hs_res!=FD_TLSREC_SUCCESS ) )
      FD_LOG_ERR(( "fd_tlsrec_conn_handshake() failed (%d-%s)", hs_res, fd_tlsrec_strerror( hs_res ) ));

    if( !fd_tlsrec_conn_is_server( conn ) ) assert( tx_buf_sz>0UL );

    if( tx_buf_sz ) {
      long send_res = send( sock_fd, tx_buf, tx_buf_sz, 0 );
      if( FD_UNLIKELY( send_res<0L ) )
        FD_LOG_ERR(( "send(sock_fd,%p,%lu) failed (%d-%s)", (void *)tx_buf, tx_buf_sz, errno, fd_io_strerror( errno ) ));
    }

    if( fd_tlsrec_conn_is_ready ( conn ) ) return 1;
    if( fd_tlsrec_conn_is_failed( conn ) ) return 0;

    if( fd_tlsrec_slice_is_empty( rx ) ) {
      long recv_res = recv( sock_fd, rx_buf, sizeof(rx_buf), 0 );
      if( recv_res<0L )
        FD_LOG_ERR(( "read(sock_fd,%p,%lu) failed (%d-%s)", (void *)rx_buf, sizeof(rx_buf), errno, fd_io_strerror( errno ) ));
      fd_tlsrec_slice_init( rx, rx_buf, (ulong)recv_res );
    }

  }

}

static void
serve_rx( fd_tlsrec_conn_t * tls,
          int                sock_fd,
          int                sock_poll ) {

  if( !sock_poll ) return;

  if( FD_UNLIKELY( !( sock_poll & POLLIN ) ) )
    FD_LOG_ERR(( "Unexpected sock_fd event: %#x", sock_poll ));

  for(;;) {

    /* Read buffer from socket */

    long recv_res = recv( sock_fd, rx_buf, sizeof(rx_buf), MSG_DONTWAIT );
    if( recv_res<0L ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EWOULDBLOCK ) ) break;
      FD_LOG_ERR(( "read(sock_fd) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( recv_res==0L ) ) {
      FD_LOG_NOTICE(( "Peer closed connection" ));
      exit( EXIT_SUCCESS );
    }

    fd_tlsrec_slice_t rx[1];
    fd_tlsrec_slice_init( rx, rx_buf, (ulong)recv_res );

    /* Forward new app data to stdout */

    do {

      uchar app[ FD_TLSREC_CAP ];
      ulong app_sz = FD_TLSREC_CAP;
      ulong tx_sz  = sizeof(tx_buf);
      int rx_res = fd_tlsrec_conn_rx( tls, rx, tx_buf, &tx_sz, app, &app_sz );
      if( FD_UNLIKELY( rx_res!=FD_TLSREC_SUCCESS ) )
        FD_LOG_ERR(( "fd_tlsrec_conn_rx() failed (%d-%s)", rx_res, fd_tlsrec_strerror( rx_res ) ));

      if( app_sz>0L ) {
        long write_res = write( STDOUT_FILENO, app, app_sz );
        if( FD_UNLIKELY( write_res<0L ) )
          FD_LOG_ERR(( "write(STDOUT_FILENO,%p,%lu) failed (%d-%s)",(void *)app, app_sz, errno, fd_io_strerror( errno ) ));
      }

      if( FD_UNLIKELY( tx_sz ) ) {
        /* Occasionally, need to transmit out of band messages */
        long send_res = send( sock_fd, tx_buf, tx_sz, 0 );
        if( FD_UNLIKELY( send_res<0L ) )
          FD_LOG_ERR(( "send(sock_fd,%p,%lu) failed (%d-%s)", (void *)tx_buf, tx_sz, errno, fd_io_strerror( errno ) ));
      }

    } while( FD_UNLIKELY( !fd_tlsrec_slice_is_empty( rx ) ) );

  }
}

static void
serve_tx( fd_tlsrec_conn_t * tls,
          int                sock_fd,
          int                stdin_poll ) {

  if( !stdin_poll ) return;

  if( FD_UNLIKELY( !( stdin_poll & POLLIN ) ) ) {
    FD_LOG_ERR(( "TODO sock_events=%d", stdin_poll ));
  }

  for(;;) {

    /* Read buffer from pipe */

    long recv_res = read( STDIN_FILENO, rx_buf, sizeof(rx_buf) );
    if( recv_res<0L ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EWOULDBLOCK ) ) break;
      FD_LOG_ERR(( "read(STDIN_FILENO) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( recv_res==0L ) ) {
      /* TODO gracefully close TLS */
      FD_LOG_NOTICE(( "EOF on stdin" ));
      exit( EXIT_SUCCESS );
    }

    fd_tlsrec_slice_t app[1];
    fd_tlsrec_slice_init( app, rx_buf, (ulong)recv_res );

    /* Forward new app data to TLS */

    while( !fd_tlsrec_slice_is_empty( app ) ) {

      ulong tx_sz = sizeof(tx_buf);
      int tx_res = fd_tlsrec_conn_tx( tls, tx_buf, &tx_sz, app );
      if( FD_UNLIKELY( tx_res!=FD_TLSREC_SUCCESS ) )
        FD_LOG_ERR(( "fd_tlsrec_conn_tx() failed (%d-%s)", tx_res, fd_tlsrec_strerror( tx_res ) ));

      if( FD_UNLIKELY( tx_sz ) ) {
        long send_res = send( sock_fd, tx_buf, tx_sz, 0 );
        if( FD_UNLIKELY( send_res<0L ) )
          FD_LOG_ERR(( "send(sock_fd,%p,%lu) failed (%d-%s)", (void *)tx_buf, tx_sz, errno, fd_io_strerror( errno ) ));
      }

    }

  }
}

static void *
tls_rand( void * ctx,
          void * buf,
          ulong  bufsz ) {
  (void)ctx;
  long rd = getrandom( buf, bufsz, 0 );
  assert( rd==32L );
  return buf;
}

int
main( int     argc,
      char ** argv ) {
  fd_log_level_core_set( 5 );

  /* Command line handling */

  int server = 0;
  do {
    int new_argc = 1;
    for( int arg=1; arg<argc; arg++ ) {
      if( 0==strcmp( argv[arg], "--help" ) ) return usage( EXIT_SUCCESS );
      else if( 0==strcmp( argv[arg], "-l" ) ) server = 1;
      else if( 0==strcmp( argv[arg], "-v" ) ) fd_log_level_core_set( 6 );
      else argv[new_argc++] = argv[arg];
    }
    argc         = new_argc;
    argv[ argc ] = NULL;
  } while(0);

  ushort src_port = (ushort)fd_env_strip_cmdline_ushort( &argc, &argv, "-p", NULL, 0 );
  uint   dst_addr = 0U;
  ushort dst_port = 0U;

  if( server ) {
    if( FD_UNLIKELY( argc!=1 ) ) return usage( EXIT_FAILURE );
  } else {
    if( FD_UNLIKELY( argc!=3 ) ) return usage( EXIT_FAILURE );

    struct addrinfo req;
    fd_memset( &req, 0, sizeof(struct addrinfo) );
    req.ai_family   = AF_INET;
    req.ai_socktype = SOCK_STREAM;

    struct addrinfo * res;
    int info_err = getaddrinfo( argv[1], NULL, &req, &res );
    if( FD_UNLIKELY( info_err ) )
      FD_LOG_ERR(( "getaddrinfo(%s) failed (%d-%s)", argv[1], info_err, gai_strerror( info_err ) ));

    for( struct addrinfo * a = res; a; a = a->ai_next ) {
      if( a->ai_family==AF_INET ) {
        dst_addr = ((struct sockaddr_in *)a->ai_addr)->sin_addr.s_addr;
        break;
      }
    }
    if( !dst_addr )
      FD_LOG_ERR(( "getaddrinfo(%s) failed (no IPv4 address)", argv[1] ));

    dst_port = (ushort)fd_cstr_to_ushort( argv[2] );
  }

  /* Prepare stdin for polling */

  FD_TEST( 0==fcntl( STDIN_FILENO, F_SETFL, fcntl( STDIN_FILENO, F_GETFL, 0 ) | O_NONBLOCK ) );

  /* Set up TCP socket */

  int listen_fd = -1;
  int sock_fd;

  if( server ) {

    /* Create socket, then bind and listen */

    listen_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
    if( FD_UNLIKELY( listen_fd<0 ) )
      FD_LOG_ERR(( "socket(AF_INET, SOCK_STREAM, IPPROTO_IP) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    union {
      struct sockaddr    s;
      struct sockaddr_in sin;
    } bind_addr;
    memset( &bind_addr, 0, sizeof(struct sockaddr_in) );
    bind_addr.sin.sin_family      = AF_INET;
    bind_addr.sin.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin.sin_port        = (ushort)fd_ushort_bswap( src_port );

    if( FD_UNLIKELY( 0!=bind( listen_fd, &bind_addr.s, sizeof(struct sockaddr_in) ) ) )
      FD_LOG_ERR(( "bind(listen_fd," FD_IP4_ADDR_FMT ":%u) failed (%d-%s)",
                   FD_IP4_ADDR_FMT_ARGS( bind_addr.sin.sin_addr.s_addr ), src_port,
                   errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( 0!=listen( listen_fd, 1 ) ) )
      FD_LOG_ERR(( "listen(listen_fd) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    /* Get actual listen address (if port unspecified) */

    union {
      struct sockaddr    s;
      struct sockaddr_in sin;
    } listen_addr;
    socklen_t listen_addr_sz = sizeof(struct sockaddr_in);
    if( FD_UNLIKELY( 0!=getsockname( listen_fd, &listen_addr.s, &listen_addr_sz ) ) )
      FD_LOG_ERR(( "getsockname(listen_fd) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    assert( listen_addr.sin.sin_family==AF_INET );
    assert( listen_addr_sz==sizeof(struct sockaddr_in) );

    FD_LOG_NOTICE(( "Listening on " FD_IP4_ADDR_FMT ":%u",
                    FD_IP4_ADDR_FMT_ARGS( listen_addr.sin.sin_addr.s_addr ),
                    (uint)fd_ushort_bswap( listen_addr.sin.sin_port ) ));

    /* Wait for client to connect */

    union {
      struct sockaddr    s;
      struct sockaddr_in sin;
    } remote_addr;
    socklen_t remote_addr_sz = sizeof(struct sockaddr_in);
    sock_fd = accept( listen_fd, &remote_addr.s, &remote_addr_sz );
    if( FD_UNLIKELY( sock_fd<0 ) )
      FD_LOG_ERR(( "accept(listen_fd) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    assert( listen_addr.sin.sin_family==AF_INET );
    assert( listen_addr_sz==sizeof(struct sockaddr_in) );

    FD_LOG_NOTICE(( "Connected to " FD_IP4_ADDR_FMT ":%u",
                    FD_IP4_ADDR_FMT_ARGS( remote_addr.sin.sin_addr.s_addr ),
                    (uint)fd_ushort_bswap( remote_addr.sin.sin_port ) ));

  } else {

    /* Make outgoing connection */

    sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
    if( FD_UNLIKELY( sock_fd<0 ) )
      FD_LOG_ERR(( "socket(AF_INET, SOCK_STREAM, IPPROTO_IP) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    union {
      struct sockaddr    s;
      struct sockaddr_in sin;
    } remote_addr;
    memset( &remote_addr, 0, sizeof(struct sockaddr_in) );
    remote_addr.sin.sin_family      = AF_INET;
    remote_addr.sin.sin_addr.s_addr = dst_addr;
    remote_addr.sin.sin_port        = (ushort)fd_ushort_bswap( dst_port );

    if( FD_UNLIKELY( 0!=connect( sock_fd, &remote_addr.s, sizeof(struct sockaddr_in) ) ) )
      FD_LOG_ERR(( "connect(sock_fd," FD_IP4_ADDR_FMT ":%u) failed (%d-%s)",
                   FD_IP4_ADDR_FMT_ARGS( dst_addr ), dst_port,
                   errno, fd_io_strerror( errno ) ));

  }

  fd_tls_t tls[1];
  fd_memset( tls, 0, sizeof(fd_tls_t) );
  tls->rand =(fd_tls_rand_t) { .rand_fn = tls_rand };

  /* Generate encryption secrets */

  do {
    FD_TEST( 32L==getrandom( tls->kex_private_key, 32UL, 0 ) );
    fd_x25519_public( tls->kex_public_key, tls->kex_private_key );

    fd_sha512_t sha_[1];
    FD_TEST( 32L==getrandom( tls->cert_private_key, 32UL, 0 ) );
    fd_ed25519_public_from_private( tls->cert_public_key, tls->cert_private_key, sha_ );

    fd_x509_mock_cert( tls->cert_x509, tls->cert_public_key );
    tls->cert_x509_sz = FD_X509_MOCK_CERT_SZ;
  } while(0);

  /* Set up TLS connection */

  fd_tlsrec_conn_t conn[1];
  fd_tlsrec_conn_init( conn, tls, server );

  /* Perform handshake */

  if( FD_UNLIKELY( !handshake( conn, sock_fd ) ) )
    FD_LOG_ERR(( "TLS handshake failed" ));
  FD_LOG_NOTICE(( "TLS handshake OK" ));

  /* Event loop */

  struct pollfd poll_fds[2] =
    { { .fd = STDIN_FILENO, .events = POLLIN },
      { .fd = sock_fd,      .events = POLLIN } };

  for(;;) {
    int poll_res = poll( poll_fds, 2, -1 );
    if( FD_UNLIKELY( poll_res<0 ) )
      FD_LOG_ERR(( "poll() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    serve_rx( conn, sock_fd, poll_fds[1].revents );
    serve_tx( conn, sock_fd, poll_fds[0].revents );
  }

  /* Clean up */

  close( sock_fd );
  if( server ) close( listen_fd );
  return 0;
}
