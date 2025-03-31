/* test_h2_server is a dummy HTTP/2 server for testing purposes.
   It responds to GET and POST requests by echoing the request path.
   The server uses single threaded blocking sockets without timeouts. */

#include "fd_h2_callback.h"
#include "fd_h2_conn.h"
#include "fd_h2_rbuf_sock.h"
#include "fd_hpack.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <unistd.h> /* close(2) */
#include <netinet/in.h> /* IPPROTO_TCP */
#include <sys/socket.h> /* socket(2) */

static fd_h2_callbacks_t test_h2_callbacks;
static uint test_h2_stream_id;

static void
test_cb_conn_established( fd_h2_conn_t * conn ) {
  (void)conn;
  FD_LOG_NOTICE(( "HTTP/2 conn established" ));
}

static void
test_cb_conn_final( fd_h2_conn_t * conn,
                    uint           h2_err ) {
  (void)conn;
  FD_LOG_NOTICE(( "HTTP/2 conn closed (%u-%s)", h2_err, fd_h2_strerror( h2_err ) ));
}

static void
test_cb_headers( fd_h2_conn_t * conn,
                 uint           stream_id,
                 void const *   data,
                 ulong          data_sz,
                 ulong          flags ) {
  (void)flags;

  if( stream_id!=test_h2_stream_id ) {
    FD_LOG_NOTICE(( "Request %u", stream_id ));
    test_h2_stream_id = stream_id;
  }

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
  if( FD_UNLIKELY( !read_preface( tcp_sock ) ) ) return;

  fd_h2_conn_t conn[1];
  fd_h2_conn_init_server( conn );

  static uchar scratch[ 16384 ];
  static uchar rx_buf [ 16384 ];
  static uchar tx_buf [ 16384 ];
  fd_h2_rbuf_t rbuf_rx[1];
  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_init( rbuf_rx, rx_buf, sizeof(rx_buf) );
  fd_h2_rbuf_init( rbuf_tx, tx_buf, sizeof(tx_buf) );

  for(;;) {
    fd_h2_tx_control( conn, rbuf_tx );

    while( fd_h2_rbuf_used_sz( rbuf_tx ) ) {
      int err = fd_h2_rbuf_sendmsg( rbuf_tx, tcp_sock, MSG_NOSIGNAL );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "sendmsg failed (%i-%s)", err, fd_io_strerror( err ) ));
        return;
      }
    }

    int err = fd_h2_rbuf_recvmsg( rbuf_rx, tcp_sock, MSG_NOSIGNAL );
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
  test_h2_callbacks.conn_established = test_cb_conn_established;
  test_h2_callbacks.conn_final       = test_cb_conn_final;
  test_h2_callbacks.headers          = test_cb_headers;

  ushort port = fd_env_strip_cmdline_ushort( &argc, &argv, "--port", NULL, 8080 );

  int listen_sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
  if( FD_UNLIKELY( listen_sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_STREAM,IPPROTO_TCP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr = {0};
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port        = fd_ushort_bswap( port );
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
    handle_conn( tcp_sock );

    if( FD_UNLIKELY( 0!=close( tcp_sock ) ) ) FD_LOG_ERR(( "close(tcp_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=close( listen_sock ) ) ) FD_LOG_ERR(( "close(listen_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_halt();
  return 0;
}
