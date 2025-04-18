/* test_h2_server is a dummy HTTP/2 server for testing purposes.
   It responds to GET and POST requests with status 200.
   The server uses single threaded blocking sockets without timeouts. */

#include "fd_h2.h"
#include "fd_h2_rbuf_sock.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <stdlib.h> /* exit(2) */
#include <unistd.h> /* close(2) */
#include <netinet/in.h> /* IPPROTO_TCP */
#include <sys/socket.h> /* socket(2) */

/* App logic */

struct test_h2_app {
  fd_h2_rbuf_t   rbuf_tx[1];
  fd_h2_conn_t   conn[1];
  fd_h2_stream_t stream[1];
  fd_h2_tx_op_t  tx_op[1];
};

typedef struct test_h2_app test_h2_app_t;

static test_h2_app_t * g_app;

static fd_h2_callbacks_t test_h2_callbacks;

static void
test_response_continue( void ) {
  fd_h2_stream_t * stream = g_app->stream;
  if( !stream->stream_id ) return;
  fd_h2_tx_op_copy( g_app->conn, stream, g_app->rbuf_tx, g_app->tx_op );
  if( stream->state==FD_H2_STREAM_STATE_CLOSED ) {
    FD_LOG_NOTICE(( "Request %u: Response complete", stream->stream_id ));
    memset( g_app->tx_op,  0, sizeof(g_app->tx_op ) );
    memset( g_app->stream, 0, sizeof(g_app->stream) );
  }
}

static void
test_response_init( fd_h2_conn_t *   conn,
                    fd_h2_stream_t * stream ) {
  (void)conn;
  uint stream_id = stream->stream_id;
  FD_LOG_NOTICE(( "Request %u: Done reading, sending response", stream_id ));

  fd_h2_rbuf_t * rbuf_tx = g_app->rbuf_tx;
  uchar hpack[] = { 0x88 /* :status: 200 */ };
  fd_h2_tx( rbuf_tx, hpack, sizeof(hpack), FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, stream_id );

  fd_h2_tx_op_t * tx_op = g_app->tx_op;
  fd_h2_tx_op_init( tx_op, "Ok", 2UL, FD_H2_FLAG_END_STREAM );
  test_response_continue();
  if( stream->state!=FD_H2_STREAM_STATE_CLOSED ) {
    FD_LOG_NOTICE(( "Request %u: Blocked trying to write response, wrote %lu bytes", stream_id, 2UL - tx_op->chunk_sz ));
  } else {
    FD_LOG_NOTICE(( "Request %u: Response complete", stream_id ));
  }
}

/* fd_h2 callbacks */

static fd_h2_stream_t *
test_cb_stream_create( fd_h2_conn_t * conn,
                       uint           stream_id ) {
  (void)conn;
  fd_h2_stream_t * stream = g_app->stream;
  if( FD_UNLIKELY( stream->stream_id ) ) return NULL;
  fd_h2_stream_open( fd_h2_stream_init( stream ), conn, stream_id );
  return stream;
}

static fd_h2_stream_t *
test_cb_stream_query( fd_h2_conn_t * conn,
                      uint           stream_id ) {
  (void)conn;
  fd_h2_stream_t * stream = g_app->stream;
  if( stream->stream_id!=stream_id ) return NULL;
  return stream;
}

static void
test_cb_conn_established( fd_h2_conn_t * conn ) {
  (void)conn;
  FD_LOG_NOTICE(( "HTTP/2 conn established" ));
}

static void
test_cb_conn_final( fd_h2_conn_t * conn,
                    uint           h2_err,
                    int            closed_by ) {
  (void)conn; (void)closed_by;
  FD_LOG_NOTICE(( "HTTP/2 conn closed (%u-%s)", h2_err, fd_h2_strerror( h2_err ) ));
}

static void
test_cb_rst_stream( fd_h2_conn_t *   conn,
                    fd_h2_stream_t * stream,
                    uint             error_code,
                    int              closed_by ) {
  (void)conn;
  FD_LOG_NOTICE(( "Request %u: %s RST_STREAM (%u-%s)",
                  stream->stream_id,
                  closed_by ? "received" : "sending",
                  error_code, fd_h2_strerror( error_code ) ));
  memset( g_app->tx_op, 0, sizeof(fd_h2_tx_op_t) );
}

static void
test_cb_window_update( fd_h2_conn_t * conn,
                       uint           delta ) {
  (void)conn; (void)delta;
  test_response_continue();
}

static void
test_cb_stream_window_update( fd_h2_conn_t *   conn,
                              fd_h2_stream_t * stream,
                              uint             delta ) {
  (void)conn; (void)stream; (void)delta;
  test_response_continue();
}

static void
test_cb_headers( fd_h2_conn_t *   conn,
                 fd_h2_stream_t * stream,
                 void const *     data,
                 ulong            data_sz,
                 ulong            flags ) {
  FD_LOG_HEXDUMP_DEBUG(( "Header field block", data, data_sz ));

  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, data, data_sz );
  while( !fd_hpack_rd_done( hpack_rd ) )  {
    static uchar scratch_buf[ 4096 ];
    uchar * scratch = scratch_buf;
    fd_h2_hdr_t hdr[1];
    uint err = fd_hpack_rd_next( hpack_rd, hdr, &scratch, scratch_buf+sizeof(scratch_buf) );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Error reading headers (%u-%s)", err, fd_h2_strerror( err ) ));
      fd_h2_conn_error( conn, err );
      return;
    }

    FD_LOG_NOTICE(( "-> %.*s: %.*s",
                    (int)hdr->name_len,  (char const *)hdr->name,
                    (int)hdr->value_len, (char const *)hdr->value ));
  }

  if( flags & FD_H2_FLAG_END_HEADERS ) {
    FD_LOG_NOTICE(( "Request %u: Headers complete", stream->stream_id ));
  }
  if( flags & FD_H2_FLAG_END_STREAM ) {
    test_response_init( conn, stream );
  }
}

static void
test_cb_data( fd_h2_conn_t *   conn,
              fd_h2_stream_t * stream,
              void const *     data,
              ulong            data_sz,
              ulong            flags ) {
  if( FD_UNLIKELY( stream->state==FD_H2_STREAM_STATE_ILLEGAL ) ) {
    fd_h2_conn_error( conn, FD_H2_ERR_PROTOCOL );
    return;
  }

  FD_LOG_HEXDUMP_DEBUG(( "Request data", data, data_sz ));

  if( flags & FD_H2_FLAG_END_STREAM ) {
    test_response_init( conn, stream );
  }
}

static int
read_preface( int tcp_sock ) {
  ulong preface_sz = 0UL;
  uchar preface[ 24 ];

  do {
    long res = read( tcp_sock, preface+preface_sz, sizeof(preface)-preface_sz );
    if( FD_UNLIKELY( res<0L ) ) {
      FD_LOG_WARNING(( "Failed to read client preface (%i-%s)", errno, fd_io_strerror( errno ) ));
      return 0;
    }
    if( FD_UNLIKELY( res==0L ) ) {
      FD_LOG_WARNING(( "Client closed connection before sending preface" ));
      return 0;
    }
    if( FD_UNLIKELY( !fd_memeq( preface+preface_sz, fd_h2_client_preface+preface_sz, (ulong)res ) ) ) {
      FD_LOG_WARNING(( "Not a HTTP/2 client" ));
      return 0;
    }
    preface_sz += (ulong)res;
  } while( preface_sz<24 );

  return 1;
}

static void
handle_conn( int tcp_sock ) {
  test_h2_app_t app[1] = {0};
  static uchar scratch[ 16384 ];
  static uchar rx_buf [ 16384 ];
  static uchar tx_buf [ 16384 ];

  if( FD_UNLIKELY( !read_preface( tcp_sock ) ) ) return;

  g_app = app;
  fd_h2_conn_t * conn = g_app->conn;
  fd_h2_conn_init_server( conn );
  conn->self_settings.max_concurrent_streams = 1;

  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t * rbuf_tx = g_app->rbuf_tx;
  fd_h2_rbuf_init( rbuf_rx, rx_buf, sizeof(rx_buf) );
  fd_h2_rbuf_init( rbuf_tx, tx_buf, sizeof(tx_buf) );

  for(;;) {
    fd_h2_tx_control( conn, rbuf_tx, &test_h2_callbacks );

    while( fd_h2_rbuf_used_sz( rbuf_tx ) ) {
      int err = fd_h2_rbuf_sendmsg( rbuf_tx, tcp_sock, MSG_NOSIGNAL );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "sendmsg failed (%i-%s)", err, fd_io_strerror( err ) ));
        return;
      }
    }

    if( FD_UNLIKELY( conn->flags & FD_H2_CONN_FLAGS_DEAD ) ) {
      FD_LOG_NOTICE(( "Closing TCP conn" ));
      return;
    }

    int err = fd_h2_rbuf_recvmsg( rbuf_rx, tcp_sock, MSG_NOSIGNAL );
    if( FD_UNLIKELY( err==EPIPE ) ) {
      FD_LOG_NOTICE(( "Peer closed TCP connection" ));
      return;
    }
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "recvmsg failed (%i-%s)", err, fd_io_strerror( err ) ));
      return;
    }

    fd_h2_rx( conn, rbuf_rx, rbuf_tx, scratch, sizeof(scratch), &test_h2_callbacks );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_h2_callbacks_init( &test_h2_callbacks );
  test_h2_callbacks.stream_create        = test_cb_stream_create;
  test_h2_callbacks.stream_query         = test_cb_stream_query;
  test_h2_callbacks.conn_established     = test_cb_conn_established;
  test_h2_callbacks.conn_final           = test_cb_conn_final;
  test_h2_callbacks.headers              = test_cb_headers;
  test_h2_callbacks.data                 = test_cb_data;
  test_h2_callbacks.rst_stream           = test_cb_rst_stream;
  test_h2_callbacks.window_update        = test_cb_window_update;
  test_h2_callbacks.stream_window_update = test_cb_stream_window_update;

  char const * bind_cstr = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--bind", NULL, "0.0.0.0" );
  ushort       port      = fd_env_strip_cmdline_ushort( &argc, &argv, "--port", NULL, 8080      );
  char const * mode      = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--mode", NULL, "simple"  );

  int do_fork = 0;
  if( !strcmp( mode, "simple" ) ) {
    do_fork = 0;
  } else if( !strcmp( mode, "fork" ) ) {
    do_fork = 1;
  } else {
    FD_LOG_ERR(( "Unknown --mode '%s'", mode ));
  }

  int listen_sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
  if( FD_UNLIKELY( listen_sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_STREAM,IPPROTO_TCP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr = {0};
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port        = fd_ushort_bswap( port );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( bind_cstr, &addr.sin_addr.s_addr ) ) ) {
    FD_LOG_ERR(( "invalid --bind address" ));
  }
  if( FD_UNLIKELY( 0!=bind( listen_sock, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) ) ) ) {
    FD_LOG_ERR(( "bind(:%hu) failed (%i-%s)", port, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=listen( listen_sock, 2 ) ) ) {
    FD_LOG_ERR(( "listen(listen_sock,1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "Listening at :%hu", port ));

  for(;;) {
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_sz = sizeof(struct sockaddr_storage);
    int tcp_sock = accept( listen_sock, fd_type_pun( &peer_addr ), &peer_addr_sz );
    if( FD_UNLIKELY( tcp_sock<0 ) ) FD_LOG_ERR(( "accept(listen_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    FD_LOG_NOTICE(( "Accepted TCP conn" ));
    if( do_fork ) {
      pid_t pid = fork();
      if( FD_UNLIKELY( pid<0 ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( pid==0 ) {
        fd_log_private_tid_set( (ulong)getpid() );
        handle_conn( tcp_sock );
        exit( 0 );
      }
    } else {
      handle_conn( tcp_sock );
    }

    if( FD_UNLIKELY( 0!=close( tcp_sock ) ) ) FD_LOG_ERR(( "close(tcp_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=close( listen_sock ) ) ) FD_LOG_ERR(( "close(listen_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_halt();
  return 0;
}
