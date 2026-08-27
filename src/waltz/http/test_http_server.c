#include "fd_http_server.h"
#include "fd_http_server_private.h"
#include "../../util/fd_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct overflow_close_state {
  ulong close_cnt;
  int   last_reason;
};

typedef struct overflow_close_state overflow_close_state_t;

#define WS_MSG_MAX (256UL)

struct ws_msg_state {
  ulong msg_cnt;                /* Number of ws_message callbacks received */
  ulong last_len;              /* Payload length of the most recent message */
  uchar last_msg[ WS_MSG_MAX ]; /* Payload of the most recent message */
  int   open;                  /* Set once ws_open has fired */
  ulong close_cnt;
};

typedef struct ws_msg_state ws_msg_state_t;

static fd_http_server_response_t
request_upgrade( fd_http_server_request_t const * request ) {
  fd_http_server_response_t response = {
    .status            = 200,
    .upgrade_websocket = request->headers.upgrade_websocket,
  };
  return response;
}

static void
ws_open_capture( ulong  ws_conn_id,
                 void * ctx ) {
  (void)ws_conn_id;
  ws_msg_state_t * state = (ws_msg_state_t *)ctx;
  state->open = 1;
}

static void
ws_message_capture( ulong         ws_conn_id,
                    uchar const * data,
                    ulong         data_len,
                    void *        ctx ) {
  (void)ws_conn_id;
  ws_msg_state_t * state = (ws_msg_state_t *)ctx;
  state->msg_cnt++;
  state->last_len = data_len;
  FD_TEST( data_len<=WS_MSG_MAX );
  fd_memcpy( state->last_msg, data, data_len );
}

static void
ws_close_capture( ulong  ws_conn_id,
                  int    reason,
                  void * ctx ) {
  (void)ws_conn_id;
  (void)reason;
  ws_msg_state_t * state = (ws_msg_state_t *)ctx;
  state->close_cnt++;
}

static fd_http_server_params_t
default_test_params( void );

static fd_http_server_response_t
request_noop( fd_http_server_request_t const * request ) {
  (void)request;
  fd_http_server_response_t response = {
    .status = 400,
  };
  return response;
}

static ulong request_cnt;

static fd_http_server_response_t
request_count( fd_http_server_request_t const * request ) {
  request_cnt++;
  return request_noop( request );
}

static fd_http_server_response_t
request_redirect( fd_http_server_request_t const * request ) {
  static char const prefix[] = "http://127.0.0.1:8902";
  return (fd_http_server_response_t) {
    .status       = 302UL,
    .location     = { prefix, request->path_raw },
    .location_len = { sizeof(prefix)-1UL, request->path_len },
  };
}

static fd_http_server_response_t
request_websocket( fd_http_server_request_t const * request ) {
  return (fd_http_server_response_t) {
    .status            = 200UL,
    .upgrade_websocket = request->headers.upgrade_websocket,
  };
}

static void
ws_message_noop( ulong         ws_conn_id,
                 uchar const * data,
                 ulong         data_sz,
                 void *        ctx ) {
  (void)ws_conn_id;
  (void)data;
  (void)data_sz;
  (void)ctx;
}

static void
close_capture( ulong  conn_id,
               int    reason,
               void * ctx ) {
  (void)conn_id;
  overflow_close_state_t * state = (overflow_close_state_t *)ctx;
  state->close_cnt++;
  state->last_reason = reason;
}

static void
send_all( int          fd,
          char const * req,
          ulong        req_sz ) {
  ulong sent = 0UL;
  while( sent<req_sz ) {
    long n = send( fd, req+sent, req_sz-sent, 0 );
    if( FD_UNLIKELY( n<0L ) ) {
      FD_LOG_ERR(( "send failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    sent += (ulong)n;
  }
}

void
test_oring( void ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 5UL,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = 1<<16,
    .max_ws_recv_frame_len = 2048,
    .max_ws_send_frame_cnt = 100,
    .outgoing_buffer_sz    = 8UL,
  };

  fd_http_server_callbacks_t callbacks = {
    .request    = NULL,
    .close      = NULL,
    .ws_open    = NULL,
    .ws_close   = NULL,
    .ws_message = NULL,
  };

  /* zstd cctx estimate assumes the single-threaded vendored build */
  uchar scratch[ 1633280 ] __attribute__((aligned(128UL)));
#if FD_HAS_ZSTD
  FD_TEST( fd_http_server_footprint( params )==1633280 );
#else
  FD_TEST( fd_http_server_footprint( params )==329600 );
  FD_TEST( fd_http_server_footprint( params )<=sizeof( scratch ) );
#endif
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, NULL ) );

  http->stage_off = 6UL;
  fd_http_server_printf( http, "A" );
  fd_http_server_printf( http, "B" );
  fd_http_server_printf( http, "C" );
  FD_TEST( http->stage_off==8UL );
  FD_TEST( http->stage_len==3UL );
  FD_TEST( http->stage_comp_len==0UL );
  FD_TEST( !memcmp( "ABC", http->oring, 3UL ) );
  fd_http_server_unstage( http );

  for( ulong i=1UL; i<=7UL; i++ ) {
    for( ulong j=0UL; j<1024UL; j++ ) {
      for( ulong k=0UL; k<i; k++ ) fd_http_server_printf( http, "%c", (char)('a'+i) );

      fd_http_server_response_t response;
      FD_TEST( !fd_http_server_stage_body( http, &response ) );
      FD_TEST( response._body_len==i );
      FD_TEST( (response._body_off%8UL)<=8-i );
      for( ulong l=0UL; l<i; l++ ) {
        FD_TEST( http->oring[(response._body_off%8UL)+l]==(uchar)('a'+i) );
      }
    }
  }

  /* Verify overflow is handled correctly for body sizes exceeding the
     oring (only one iteration needed per size since no wrapping occurs). */
  for( ulong i=8UL; i<32UL; i++ ) {
    for( ulong k=0UL; k<i; k++ ) fd_http_server_printf( http, "%c", (char)('a'+i) );
    fd_http_server_response_t response;
    FD_TEST( fd_http_server_stage_body( http, &response ) );
  }

  fd_http_server_response_t response;

  http->stage_off = 1UL;
  fd_http_server_printf( http, "0123456" );
  FD_TEST( http->stage_off==8UL );
  FD_TEST( http->stage_len==7UL );
  FD_TEST( !fd_http_server_stage_body( http, &response ) );
  FD_TEST( http->stage_comp_len==0UL );

  http->stage_off = 7UL;
  fd_http_server_printf( http, "0123456" );
  FD_TEST( http->stage_off==8UL );
  FD_TEST( http->stage_len==7UL );
  fd_http_server_unstage( http );
  FD_TEST( http->stage_comp_len==0UL );

  http->stage_off = 16UL;
  fd_http_server_printf( http, "0123456" );
  FD_TEST( http->stage_off==16UL );
  FD_TEST( http->stage_len==7UL );
  FD_TEST( !fd_http_server_stage_body( http, &response ) );
  FD_TEST( http->stage_comp_len==0UL );

  http->stage_off = 0UL;
  fd_http_server_printf( http, "012345678" );
  FD_TEST( fd_http_server_stage_body( http, &response ) );
  FD_TEST( http->stage_comp_len==0UL );
}

void
test_content_length_overflow_close( void ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = 1024UL,
  };

  overflow_close_state_t state = {0};
  fd_http_server_callbacks_t callbacks = {
    .request    = request_noop,
    .close      = close_capture,
    .ws_open    = NULL,
    .ws_close   = NULL,
    .ws_message = NULL,
  };

  FD_LOG_NOTICE(( "footprint %lu", fd_http_server_footprint( params ) ));
  uchar scratch[ 1306624 ] __attribute__((aligned(128UL)));
#if FD_HAS_ZSTD
  FD_TEST( fd_http_server_footprint( params )==sizeof( scratch ) );
#else
  FD_TEST( fd_http_server_footprint( params )==3072 );
  FD_TEST( fd_http_server_footprint( params )<=sizeof( scratch ) );
#endif

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, &state ) );
  FD_TEST( http );
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  struct sockaddr_in server_addr = {0};
  socklen_t server_addr_sz = sizeof( server_addr );
  FD_TEST( !getsockname( fd_http_server_fd( http ), fd_type_pun( &server_addr ), &server_addr_sz ) );
  ushort server_port = ntohs( server_addr.sin_port );

  int client_fd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( client_fd>=0 );

  struct sockaddr_in connect_addr = {
    .sin_family      = AF_INET,
    .sin_port        = htons( server_port ),
    .sin_addr.s_addr = htonl( INADDR_LOOPBACK ),
  };

  FD_TEST( !connect( client_fd, fd_type_pun( &connect_addr ), sizeof( connect_addr ) ) );

  char const * req =
      "POST / HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: 30000000000000000000\r\n"
      "\r\n"
      "x";
  send_all( client_fd, req, strlen( req ) );

  for( ulong i=0UL; i<200UL && !state.close_cnt; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
  }

  FD_TEST( state.close_cnt==1UL );
  FD_TEST( state.last_reason==FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST );

  close( client_fd );
  close( fd_http_server_fd( http ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
}

static void
test_poll_conn_max( void ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 2UL,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = 1024UL,
  };
  fd_http_server_callbacks_t callbacks = {
    .request = request_count,
  };

  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, NULL ) );
  FD_TEST( http );
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  struct sockaddr_in server_addr = {0};
  socklen_t server_addr_sz = sizeof( server_addr );
  FD_TEST( !getsockname( fd_http_server_fd( http ), fd_type_pun( &server_addr ), &server_addr_sz ) );

  struct sockaddr_in connect_addr = {
    .sin_family      = AF_INET,
    .sin_port        = server_addr.sin_port,
    .sin_addr.s_addr = htonl( INADDR_LOOPBACK ),
  };
  int client_fds[ 2 ];
  char const req[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
  for( ulong i=0UL; i<2UL; i++ ) {
    client_fds[ i ] = socket( AF_INET, SOCK_STREAM, 0 );
    FD_TEST( client_fds[ i ]>=0 );
    FD_TEST( !connect( client_fds[ i ], fd_type_pun( &connect_addr ), sizeof( connect_addr ) ) );
    send_all( client_fds[ i ], req, sizeof( req )-1UL );
  }

  request_cnt = 0UL;
  FD_TEST( fd_http_server_poll( http, 1, 1UL ) ); /* Accept both clients. */
  FD_TEST( http->metrics.connection_cnt==2UL );
  FD_TEST( request_cnt==0UL );

  FD_TEST( fd_http_server_poll( http, 1, 1UL ) );
  FD_TEST( request_cnt==1UL );
  FD_TEST( fd_http_server_poll( http, 1, 1UL ) );
  FD_TEST( request_cnt==2UL );

  for( ulong i=0UL; i<2UL; i++ ) FD_TEST( !close( client_fds[ i ] ) );
  FD_TEST( !close( fd_http_server_fd( http ) ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}

static void
test_location_raw_path( void ) {
  fd_http_server_params_t params = default_test_params();
  fd_http_server_callbacks_t callbacks = {
    .request = request_redirect,
  };

  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, NULL ) );
  FD_TEST( http );
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  struct sockaddr_in server_addr = {0};
  socklen_t server_addr_sz = sizeof( server_addr );
  FD_TEST( !getsockname( fd_http_server_fd( http ), fd_type_pun( &server_addr ), &server_addr_sz ) );

  struct sockaddr_in connect_addr = {
    .sin_family      = AF_INET,
    .sin_port        = server_addr.sin_port,
    .sin_addr.s_addr = htonl( INADDR_LOOPBACK ),
  };
  int client_fd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( client_fd>=0 );
  FD_TEST( !connect( client_fd, fd_type_pun( &connect_addr ), sizeof( connect_addr ) ) );

  char const req[] = "GET /snapshot-123-hash.tar.zst HTTP/1.1\r\nHost: localhost\r\n\r\n";
  send_all( client_fd, req, sizeof(req)-1UL );

  char response[ 1024 ];
  ulong response_sz = 0UL;
  char const expected[] = "Location: http://127.0.0.1:8902/snapshot-123-hash.tar.zst\r\n";
  for( ulong i=0UL; i<200UL; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
    long received = recv( client_fd, response+response_sz, sizeof(response)-1UL-response_sz, MSG_DONTWAIT );
    if( FD_UNLIKELY( received<0L && errno!=EAGAIN && errno!=EWOULDBLOCK ) )
      FD_LOG_ERR(( "recv failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( received>0L ) response_sz += (ulong)received;
    response[ response_sz ] = '\0';
    if( strstr( response, expected ) ) break;
  }
  FD_TEST( strstr( response, expected ) );

  FD_TEST( !close( client_fd ) );
  FD_TEST( !close( fd_http_server_fd( http ) ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}

static void
test_close_reason( char const * req,
                   int          expected_reason,
                   fd_http_server_params_t params ) {
  overflow_close_state_t state = {0};
  fd_http_server_callbacks_t callbacks = {
    .request    = request_noop,
    .close      = close_capture,
    .ws_open    = NULL,
    .ws_close   = NULL,
    .ws_message = NULL,
  };

  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, &state ) );
  FD_TEST( http );
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  struct sockaddr_in server_addr = {0};
  socklen_t server_addr_sz = sizeof( server_addr );
  FD_TEST( !getsockname( fd_http_server_fd( http ), fd_type_pun( &server_addr ), &server_addr_sz ) );
  ushort server_port = ntohs( server_addr.sin_port );

  int client_fd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( client_fd>=0 );

  struct sockaddr_in connect_addr = {
    .sin_family      = AF_INET,
    .sin_port        = htons( server_port ),
    .sin_addr.s_addr = htonl( INADDR_LOOPBACK ),
  };

  FD_TEST( !connect( client_fd, fd_type_pun( &connect_addr ), sizeof( connect_addr ) ) );

  send_all( client_fd, req, strlen( req ) );

  for( ulong i=0UL; i<200UL && !state.close_cnt; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
  }

  FD_TEST( state.close_cnt==1UL );
  FD_TEST( state.last_reason==expected_reason );

  close( client_fd );
  close( fd_http_server_fd( http ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}

static fd_http_server_params_t
default_test_params( void ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = 1024UL,
  };
  return params;
}

static void
test_treap_seed( void ) {
  fd_http_server_params_t params = default_test_params();
  params.treap_seed = 0x0123456789abcdefUL;
  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), fd_http_server_align() );
  void * scratch = aligned_alloc( fd_http_server_align(), footprint );
  FD_TEST( scratch );

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( http );
  FD_TEST( http->conns   [ 0 ].prio==11498U );
  FD_TEST( http->ws_conns[ 0 ].prio==11498U );

  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}

static void
test_poll_interest( void ) {
  fd_http_server_params_t params = default_test_params();
  fd_http_server_callbacks_t callbacks = {
    .request    = request_websocket,
    .ws_message = ws_message_noop,
  };

  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, NULL ) );
  FD_TEST( http );
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  struct sockaddr_in server_addr = {0};
  socklen_t server_addr_sz = sizeof(server_addr);
  FD_TEST( !getsockname( fd_http_server_fd( http ), fd_type_pun( &server_addr ), &server_addr_sz ) );

  struct sockaddr_in connect_addr = {
    .sin_family      = AF_INET,
    .sin_port        = server_addr.sin_port,
    .sin_addr.s_addr = htonl( INADDR_LOOPBACK ),
  };
  int client_fd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( client_fd>=0 );
  FD_TEST( !connect( client_fd, fd_type_pun( &connect_addr ), sizeof(connect_addr) ) );

  FD_TEST( fd_http_server_poll( http, 1, ULONG_MAX ) );
  FD_TEST( http->metrics.connection_cnt==1UL );
  FD_TEST( http->pollfds[ 0 ].events==POLLIN );
  FD_TEST( !fd_http_server_poll( http, 1, ULONG_MAX ) );

  char const upgrade[] =
      "GET / HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "\r\n";
  send_all( client_fd, upgrade, sizeof(upgrade)-1UL );
  FD_TEST( fd_http_server_poll( http, 1, ULONG_MAX ) );
  FD_TEST( http->pollfds[ 0 ].events==(POLLIN|POLLOUT) );
  FD_TEST( fd_http_server_poll( http, 1, ULONG_MAX ) );
  FD_TEST( http->metrics.ws_connection_cnt==1UL );
  FD_TEST( http->pollfds[ http->max_conns ].events==POLLIN );
  FD_TEST( !fd_http_server_poll( http, 1, ULONG_MAX ) );

  fd_http_server_printf( http, "test" );
  FD_TEST( !fd_http_server_ws_send( http, 0UL ) );
  FD_TEST( http->pollfds[ http->max_conns ].events==(POLLIN|POLLOUT) );
  FD_TEST( fd_http_server_poll( http, 1, ULONG_MAX ) );
  FD_TEST( http->pollfds[ http->max_conns ].events==POLLIN );
  FD_TEST( !fd_http_server_poll( http, 1, ULONG_MAX ) );

  uchar ping[] = { 0x89U, 0x80U, 0U, 0U, 0U, 0U };
  FD_TEST( send( client_fd, ping, sizeof(ping), 0 )==(long)sizeof(ping) );
  FD_TEST( fd_http_server_poll( http, 1, ULONG_MAX ) );
  FD_TEST( http->pollfds[ http->max_conns ].events==(POLLIN|POLLOUT) );
  FD_TEST( fd_http_server_poll( http, 1, ULONG_MAX ) );
  FD_TEST( http->pollfds[ http->max_conns ].events==POLLIN );

  FD_TEST( !close( client_fd ) );
  FD_TEST( !close( fd_http_server_fd( http ) ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}

void
test_transfer_encoding_close( void ) {
  FD_LOG_NOTICE(( "Testing Transfer-Encoding rejection" ));
  test_close_reason(
      "POST / HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Transfer-Encoding: chunked\r\n"
      "Content-Length: 1\r\n"
      "\r\n"
      "x",
      FD_HTTP_SERVER_CONNECTION_CLOSE_UNSUPPORTED_TRANSFER_ENCODING,
      default_test_params() );
}

void
test_duplicate_content_length_different_close( void ) {
  FD_LOG_NOTICE(( "Testing duplicate Content-Length with different values" ));
  test_close_reason(
      "POST / HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Content-Length: 1\r\n"
      "Content-Length: 2\r\n"
      "\r\n"
      "xx",
      FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST,
      default_test_params() );
}

void
test_ws_bad_key_close( void ) {
  FD_LOG_NOTICE(( "Testing WebSocket bad Sec-WebSocket-Key" ));
  /* Key is 24 chars but unpadded, so it decodes to 18 bytes and
     fd_base64_decode returns != 16 (regression test for decoded_key). */
  test_close_reason(
      "GET / HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAAA\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "\r\n",
      FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_KEY,
      default_test_params() );
}

void
test_ws_early_data_close( void ) {
  FD_LOG_NOTICE(( "Testing WebSocket early data after headers" ));
  /* Valid WebSocket upgrade but with trailing data after the
     headers — the client must not send WebSocket frames before
     receiving the 101 response (RFC 6455 s4.2.2). */
  test_close_reason(
      "GET / HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "\r\n"
      "extradata",
      FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST,
      default_test_params() );
}

/* recv_until_header_end drains bytes until "\r\n\r\n". */

static void
recv_until_header_end( int fd ) {
  char win[ 4 ] = {0};
  char status[ 34 ];
  ulong total = 0UL;
  for(;;) {
    char c;
    long n = recv( fd, &c, 1UL, 0 );
    if( FD_UNLIKELY( n==0L ) ) FD_LOG_ERR(( "peer closed connection during handshake" ));
    if( FD_UNLIKELY( n<0L ) ) {
      if( errno==EINTR ) continue;
      FD_LOG_ERR(( "recv failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( total<sizeof( status ) ) status[ total ] = c;
    total++;
    win[ 0 ] = win[ 1 ]; win[ 1 ] = win[ 2 ]; win[ 2 ] = win[ 3 ]; win[ 3 ] = c;
    if( win[ 0 ]=='\r' && win[ 1 ]=='\n' && win[ 2 ]=='\r' && win[ 3 ]=='\n' ) break;
  }
  FD_TEST( total>=sizeof( status ) );
  FD_TEST( !memcmp( status, "HTTP/1.1 101 Switching Protocols\r\n", sizeof( status ) ) );
}

/* ws_frame appends a masked WebSocket frame with the given opcode, fin
   bit, and payload to buf (at offset *off, which is advanced). */

static void
ws_frame( uchar *       buf,
          ulong *       off,
          int           opcode,
          int           fin,
          uchar const * payload,
          ulong         payload_len ) {
  FD_TEST( payload_len<126UL );
  static uchar const mask[ 4 ] = { 0x12, 0x34, 0x56, 0x78 };
  ulong o = *off;
  buf[ o++ ] = (uchar)( ( fin ? 0x80 : 0x00 ) | ( opcode & 0x0F ) );
  buf[ o++ ] = (uchar)( 0x80 | payload_len ); /* mask bit set + length */
  buf[ o++ ] = mask[ 0 ];
  buf[ o++ ] = mask[ 1 ];
  buf[ o++ ] = mask[ 2 ];
  buf[ o++ ] = mask[ 3 ];
  for( ulong i=0UL; i<payload_len; i++ ) buf[ o++ ] = (uchar)( payload[ i ] ^ mask[ i % 4 ] );
  *off = o;
}

/* ws_connect performs a WebSocket handshake against the server on
   client_fd and drains the response. */

static void
ws_connect( fd_http_server_t * http,
            int                client_fd,
            ws_msg_state_t *   state ) {
  char const * req =
      "GET / HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "\r\n";
  send_all( client_fd, req, strlen( req ) );

  for( ulong i=0UL; i<200UL && !state->open; i++ ) fd_http_server_poll( http, 1, ULONG_MAX );
  FD_TEST( state->open );

  recv_until_header_end( client_fd );
}

static fd_http_server_params_t
ws_test_params( void ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = 4096UL,
  };
  return params;
}

static fd_http_server_t *
ws_test_server_new( uchar **         out_scratch,
                    ws_msg_state_t * state,
                    int *            out_client_fd ) {
  fd_http_server_params_t params = ws_test_params();

  fd_http_server_callbacks_t callbacks = {
    .request    = request_upgrade,
    .close      = NULL,
    .ws_open    = ws_open_capture,
    .ws_close   = ws_close_capture,
    .ws_message = ws_message_capture,
  };

  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );
  *out_scratch = scratch;

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, state ) );
  FD_TEST( http );
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  struct sockaddr_in server_addr = {0};
  socklen_t server_addr_sz = sizeof( server_addr );
  FD_TEST( !getsockname( fd_http_server_fd( http ), fd_type_pun( &server_addr ), &server_addr_sz ) );
  ushort server_port = ntohs( server_addr.sin_port );

  int client_fd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( client_fd>=0 );

  int one = 1;
  FD_TEST( !setsockopt( client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof( one ) ) );

  struct sockaddr_in connect_addr = {
    .sin_family      = AF_INET,
    .sin_port        = htons( server_port ),
    .sin_addr.s_addr = htonl( INADDR_LOOPBACK ),
  };
  FD_TEST( !connect( client_fd, fd_type_pun( &connect_addr ), sizeof( connect_addr ) ) );

  *out_client_fd = client_fd;
  return http;
}

static void
ws_test_server_delete( fd_http_server_t * http,
                       uchar *            scratch,
                       int                client_fd ) {
  close( client_fd );
  close( fd_http_server_fd( http ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}

static void
test_ws_send_after_staging_eviction( void ) {
  FD_LOG_NOTICE(( "Testing WebSocket send after staging eviction" ));

  ws_msg_state_t state = {0};
  uchar * scratch;
  int client_fd;
  fd_http_server_t * http = ws_test_server_new( &scratch, &state, &client_fd );

  ws_connect( http, client_fd, &state );

  http->oring_sz = 4UL;
  fd_http_server_printf( http, "x" );
  FD_TEST( !fd_http_server_ws_send( http, 0UL ) );

  /* Wrapping the first print evicts the connection.  The second print
     then overflows the ring, leaving both a closed connection and a
     staging error for fd_http_server_ws_send to handle. */
  fd_http_server_printf( http, "abc" );
  FD_TEST( state.close_cnt==1UL );
  FD_TEST( http->pollfds[ http->max_conns ].fd==-1 );
  fd_http_server_printf( http, "d" );
  FD_TEST( http->stage_err );

  FD_TEST( !fd_http_server_ws_send( http, 0UL ) );
  FD_TEST( !http->stage_err );
  FD_TEST( !http->stage_len );
  FD_TEST( !http->stage_comp_len );

  ws_test_server_delete( http, scratch, client_fd );
}

/* test_ws_fragmented_coalesced sends a multi-fragment WebSocket message
   in a single write. */

static void
test_ws_fragmented_coalesced( void ) {
  FD_LOG_NOTICE(( "Testing WebSocket fragmented message (coalesced in one write)" ));

  ws_msg_state_t state = {0};
  uchar * scratch;
  int client_fd;
  fd_http_server_t * http = ws_test_server_new( &scratch, &state, &client_fd );

  ws_connect( http, client_fd, &state );

  /* Three fragments: text (fin=0), continuation (fin=0), continuation
     (fin=1).  All in a single write so the server sees them in one
     read and walks them via `goto again`. */
  uchar buf[ 512 ];
  ulong off = 0UL;
  ws_frame( buf, &off, 0x1, 0, (uchar const *)"Hello, ",     7UL );
  ws_frame( buf, &off, 0x0, 0, (uchar const *)"fragmented ", 11UL );
  ws_frame( buf, &off, 0x0, 1, (uchar const *)"world!",      6UL );
  send_all( client_fd, (char const *)buf, off );

  for( ulong i=0UL; i<200UL && !state.msg_cnt; i++ ) fd_http_server_poll( http, 1, ULONG_MAX );

  char const * expected = "Hello, fragmented world!";
  FD_TEST( state.msg_cnt==1UL );
  FD_TEST( state.last_len==strlen( expected ) );
  FD_TEST( !memcmp( state.last_msg, expected, state.last_len ) );

  ws_test_server_delete( http, scratch, client_fd );
}

/* test_ws_fragmented_split sends the same fragmented message but splits
   each fragment (and even individual frames) across separate writes. */

static void
test_ws_fragmented_split( void ) {
  FD_LOG_NOTICE(( "Testing WebSocket fragmented message (split across writes)" ));

  ws_msg_state_t state = {0};
  uchar * scratch;
  int client_fd;
  fd_http_server_t * http = ws_test_server_new( &scratch, &state, &client_fd );

  ws_connect( http, client_fd, &state );

  uchar frames[ 512 ];
  ulong total = 0UL;
  ws_frame( frames, &total, 0x1, 0, (uchar const *)"abc",  3UL );
  ws_frame( frames, &total, 0x0, 0, (uchar const *)"defg", 4UL );
  ws_frame( frames, &total, 0x0, 1, (uchar const *)"hi",   2UL );

  /* Send one byte at a time, polling in between, so the server must
     handle every possible partial-frame boundary. */
  for( ulong i=0UL; i<total; i++ ) {
    send_all( client_fd, (char const *)( frames+i ), 1UL );
    fd_http_server_poll( http, 1, ULONG_MAX );
  }

  for( ulong i=0UL; i<200UL && !state.msg_cnt; i++ ) fd_http_server_poll( http, 1, ULONG_MAX );

  char const * expected = "abcdefghi";
  FD_TEST( state.msg_cnt==1UL );
  FD_TEST( state.last_len==strlen( expected ) );
  FD_TEST( !memcmp( state.last_msg, expected, state.last_len ) );

  ws_test_server_delete( http, scratch, client_fd );
}

/* test_ws_fragmented_interleaved_control interleaves a ping and a pong
   control frame between data fragments, all coalesced in a single
   write. */

static void
test_ws_fragmented_interleaved_control( void ) {
  FD_LOG_NOTICE(( "Testing WebSocket fragmented message with interleaved ping/pong" ));

  ws_msg_state_t state = {0};
  uchar * scratch;
  int client_fd;
  fd_http_server_t * http = ws_test_server_new( &scratch, &state, &client_fd );

  ws_connect( http, client_fd, &state );

  /* text(fin=0) | ping | cont(fin=0) | pong | cont(fin=1), all in one
     write. */
  uchar buf[ 512 ];
  ulong off = 0UL;
  ws_frame( buf, &off, 0x1, 0, (uchar const *)"one ",   4UL );
  ws_frame( buf, &off, 0x9, 1, (uchar const *)"pingpl", 6UL ); /* ping */
  ws_frame( buf, &off, 0x0, 0, (uchar const *)"two ",   4UL );
  ws_frame( buf, &off, 0xA, 1, (uchar const *)"pongpl", 6UL ); /* pong */
  ws_frame( buf, &off, 0x0, 1, (uchar const *)"three",  5UL );
  send_all( client_fd, (char const *)buf, off );

  for( ulong i=0UL; i<200UL && !state.msg_cnt; i++ ) fd_http_server_poll( http, 1, ULONG_MAX );

  char const * expected = "one two three";
  FD_TEST( state.msg_cnt==1UL );
  FD_TEST( state.last_len==strlen( expected ) );
  FD_TEST( !memcmp( state.last_msg, expected, state.last_len ) );

  ws_test_server_delete( http, scratch, client_fd );
}

/* test_keep_alive covers connection reuse: sequential requests on one
   connection, Connection token parsing, explicit close, HTTP/1.0, and
   pipelined requests, and body framing on GET. */

static fd_http_server_t * keep_alive_http;

static fd_http_server_response_t
request_ok_body( fd_http_server_request_t const * request ) {
  (void)request;
  fd_http_server_printf( keep_alive_http, "ok" );
  fd_http_server_response_t response = {
    .status       = 200,
    .content_type = "text/plain",
  };
  FD_TEST( !fd_http_server_stage_body( keep_alive_http, &response ) );
  return response;
}

static void
keep_alive_recv( fd_http_server_t * http,
                 int                client_fd,
                 char *             buf,
                 ulong              buf_sz ) {
  ulong len = 0UL;
  for( ulong i=0UL; i<400UL; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
    long n = recv( client_fd, buf+len, buf_sz-len-1UL, MSG_DONTWAIT );
    if( n>0L ) {
      len += (ulong)n;
      buf[ len ] = '\0';
      if( strstr( buf, "\r\n\r\nok" ) ) return;
    }
  }
  FD_LOG_ERR(( "no response received" ));
}

static void
keep_alive_wait_close( fd_http_server_t *       http,
                       overflow_close_state_t * state,
                       ulong                    close_cnt ) {
  for( ulong i=0UL; i<400UL && state->close_cnt<close_cnt; i++ ) fd_http_server_poll( http, 1, ULONG_MAX );
  FD_TEST( state->close_cnt==close_cnt );
}

static int
keep_alive_connect( fd_http_server_t * http ) {
  struct sockaddr_in server_addr = {0};
  socklen_t server_addr_sz = sizeof( server_addr );
  FD_TEST( !getsockname( fd_http_server_fd( http ), fd_type_pun( &server_addr ), &server_addr_sz ) );
  struct sockaddr_in connect_addr = {
    .sin_family      = AF_INET,
    .sin_port        = server_addr.sin_port,
    .sin_addr.s_addr = htonl( INADDR_LOOPBACK ),
  };
  int client_fd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( client_fd>=0 );
  FD_TEST( !connect( client_fd, fd_type_pun( &connect_addr ), sizeof( connect_addr ) ) );
  return client_fd;
}

static void
test_keep_alive( void ) {
  FD_LOG_NOTICE(( "Testing keep-alive connection reuse" ));

  overflow_close_state_t state = {0};
  fd_http_server_callbacks_t callbacks = {
    .request = request_ok_body,
    .close   = close_capture,
  };

  fd_http_server_params_t params = default_test_params();
  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, &state ) );
  FD_TEST( http );
  keep_alive_http = http;
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  char buf[ 1024 ];

  /* two sequential requests on one connection */
  int client_fd = keep_alive_connect( http );
  char const * get = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
  send_all( client_fd, get, strlen( get ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "Connection: keep-alive" ) );
  FD_TEST( !state.close_cnt );
  send_all( client_fd, get, strlen( get ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "Connection: keep-alive" ) );
  FD_TEST( !state.close_cnt );
  close( client_fd );
  keep_alive_wait_close( http, &state, 1UL );

  /* extension tokens are not close */
  client_fd = keep_alive_connect( http );
  char const * get_ext = "GET / HTTP/1.1\r\nConnection: close-timeout, xclose\r\n\r\n";
  send_all( client_fd, get_ext, strlen( get_ext ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "Connection: keep-alive" ) );

  /* a close token in a list is */
  char const * get_close = "GET / HTTP/1.1\r\nConnection: keep-alive, close\r\n\r\n";
  send_all( client_fd, get_close, strlen( get_close ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "Connection: close" ) );
  keep_alive_wait_close( http, &state, 2UL );
  close( client_fd );

  /* HTTP/1.0 closes */
  client_fd = keep_alive_connect( http );
  char const * get_10 = "GET / HTTP/1.0\r\n\r\n";
  send_all( client_fd, get_10, strlen( get_10 ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "Connection: close" ) );
  keep_alive_wait_close( http, &state, 3UL );
  close( client_fd );

  /* pipelined requests are served sequentially regardless of read
     boundaries */
  client_fd = keep_alive_connect( http );
  char const * get_two = "GET / HTTP/1.1\r\nHost: test\r\n\r\nGET / HTTP/1.1\r\nHost: test\r\n\r\n";
  send_all( client_fd, get_two, strlen( get_two ) );
  ulong len = 0UL;
  for( ulong i=0UL; i<400UL; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
    long n = recv( client_fd, buf+len, sizeof( buf )-len-1UL, MSG_DONTWAIT );
    if( n>0L ) { len += (ulong)n; buf[ len ] = '\0'; }
    char * second = len ? strstr( buf, "\r\n\r\nok" ) : NULL;
    if( second && strstr( second+6UL, "\r\n\r\nok" ) ) break;
  }
  FD_TEST( strstr( buf, "\r\n\r\nok" ) && strstr( strstr( buf, "\r\n\r\nok" )+6UL, "\r\n\r\nok" ) );
  FD_TEST( !strstr( buf, "Connection: close" ) );
  close( client_fd );
  keep_alive_wait_close( http, &state, 4UL );

  /* pipelined requests totaling more than max_request_len are all
     served as the buffer drains, not closed as one oversized request */
  client_fd = keep_alive_connect( http );
  ulong close_cnt = state.close_cnt;
  char pipeline[ 35UL*30UL ]; /* 1050 bytes > max_request_len, in one write */
  for( ulong i=0UL; i<35UL; i++ ) memcpy( pipeline+30UL*i, get_two, 30UL );
  send_all( client_fd, pipeline, sizeof( pipeline ) );
  ulong ok_cnt = 0UL;
  char  tail[ 8 ] = {0};
  for( ulong i=0UL; i<4000UL && ok_cnt<35UL; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
    char chunk[ 256 ];
    long n = recv( client_fd, chunk, sizeof( chunk )-1UL, MSG_DONTWAIT );
    if( n>0L ) {
      /* count "\r\n\r\nok" across chunk boundaries via a small carry */
      char scan[ 256+8 ];
      ulong tail_len = strlen( tail );
      memcpy( scan, tail, tail_len );
      memcpy( scan+tail_len, chunk, (ulong)n );
      scan[ tail_len+(ulong)n ] = '\0';
      for( char * p=scan; (p=strstr( p, "\r\n\r\nok" )); p+=6UL ) ok_cnt++;
      ulong keep = fd_ulong_min( tail_len+(ulong)n, 5UL );
      memcpy( tail, scan+tail_len+(ulong)n-keep, keep );
      tail[ keep ] = '\0';
    }
  }
  FD_TEST( ok_cnt==35UL );
  FD_TEST( state.close_cnt==close_cnt );
  close( client_fd );
  keep_alive_wait_close( http, &state, close_cnt+1UL );

  /* a GET with Content-Length waits for and consumes the body, keeping
     the request stream framed */
  client_fd = keep_alive_connect( http );
  char const * get_body = "GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
  send_all( client_fd, get_body, strlen( get_body ) );
  for( ulong i=0UL; i<50UL; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
    char c;
    FD_TEST( recv( client_fd, &c, 1UL, MSG_DONTWAIT )<0L ); /* no response until the body arrives */
  }
  send_all( client_fd, "12345", 5UL );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "Connection: keep-alive" ) );
  send_all( client_fd, get, strlen( get ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "Connection: keep-alive" ) );
  close( client_fd );
  keep_alive_wait_close( http, &state, close_cnt+2UL );

  close( fd_http_server_fd( http ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}


/* A 302 whose handler also staged a body: the header declares
   Content-Length: 0, so the stray bytes must not reach the stream */

static fd_http_server_response_t
request_redirect_with_junk( fd_http_server_request_t const * request ) {
  (void)request;
  fd_http_server_printf( keep_alive_http, "junk" );
  static char const prefix[] = "/elsewhere";
  fd_http_server_response_t response = {
    .status       = 302UL,
    .location     = { prefix },
    .location_len = { sizeof(prefix)-1UL },
  };
  FD_TEST( !fd_http_server_stage_body( keep_alive_http, &response ) );
  return response;
}

static void
test_zero_length_status_body( void ) {
  FD_LOG_NOTICE(( "Testing body suppression on Content-Length: 0 statuses" ));

  overflow_close_state_t state = {0};
  fd_http_server_callbacks_t callbacks = {
    .request = request_redirect_with_junk,
    .close   = close_capture,
  };

  fd_http_server_params_t params = default_test_params();
  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, &state ) );
  FD_TEST( http );
  keep_alive_http = http;
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  int client_fd = keep_alive_connect( http );
  char const * get = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
  char buf[ 2048 ] = {0};
  ulong len = 0UL;
  send_all( client_fd, get, strlen( get ) );
  send_all( client_fd, get, strlen( get ) );
  for( ulong i=0UL; i<400UL; i++ ) {
    fd_http_server_poll( http, 1, ULONG_MAX );
    long n = recv( client_fd, buf+len, sizeof( buf )-len-1UL, MSG_DONTWAIT );
    if( n>0L ) { len += (ulong)n; buf[ len ] = '\0'; }
    char * second = len ? strstr( buf, "302 Found" ) : NULL;
    if( second && strstr( second+9UL, "302 Found" ) ) break;
  }
  FD_TEST( strstr( buf, "302 Found" ) && strstr( strstr( buf, "302 Found" )+9UL, "302 Found" ) );
  FD_TEST( strstr( buf, "Content-Length: 0" ) );
  FD_TEST( !strstr( buf, "junk" ) ); /* staged body suppressed, stream framed */
  FD_TEST( !state.close_cnt );
  close( client_fd );

  close( fd_http_server_fd( http ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}


/* test_close_in_pipelined_callback: the second pipelined request's
   callback closes the connection while the first response's stale
   fields still sit in conn->response; membership inference must not
   remove the treap node twice. */

static ulong pipeline_close_req_cnt;

static fd_http_server_response_t
request_close_second( fd_http_server_request_t const * request ) {
  pipeline_close_req_cnt++;
  if( FD_UNLIKELY( pipeline_close_req_cnt==2UL ) ) {
    fd_http_server_close( keep_alive_http, request->connection_id, FD_HTTP_SERVER_CONNECTION_CLOSE_OK );
    return request_noop( request );
  }
  fd_http_server_printf( keep_alive_http, "ok" );
  fd_http_server_response_t response = {
    .status       = 200,
    .content_type = "text/plain",
  };
  FD_TEST( !fd_http_server_stage_body( keep_alive_http, &response ) );
  return response;
}

static void
test_close_in_pipelined_callback( void ) {
  FD_LOG_NOTICE(( "Testing close from the second pipelined request's callback" ));

  overflow_close_state_t state = {0};
  fd_http_server_callbacks_t callbacks = {
    .request = request_close_second,
    .close   = close_capture,
  };

  fd_http_server_params_t params = default_test_params();
  ulong footprint = fd_ulong_align_up( fd_http_server_footprint( params ), 128UL );
  uchar * scratch = aligned_alloc( 128UL, footprint );
  FD_TEST( scratch );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, &state ) );
  FD_TEST( http );
  keep_alive_http        = http;
  pipeline_close_req_cnt = 0UL;
  FD_TEST( fd_http_server_listen( http, 0U, 0U ) );

  char buf[ 1024 ];

  int client_fd = keep_alive_connect( http );
  char const * get_two = "GET / HTTP/1.1\r\nHost: test\r\n\r\nGET / HTTP/1.1\r\nHost: test\r\n\r\n";
  send_all( client_fd, get_two, strlen( get_two ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "\r\n\r\nok" ) );
  keep_alive_wait_close( http, &state, 1UL );
  FD_TEST( pipeline_close_req_cnt==2UL );
  close( client_fd );

  /* treap intact: the server keeps serving dynamic responses */
  client_fd = keep_alive_connect( http );
  char const * get = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
  send_all( client_fd, get, strlen( get ) );
  keep_alive_recv( http, client_fd, buf, sizeof( buf ) );
  FD_TEST( strstr( buf, "\r\n\r\nok" ) );
  close( client_fd );
  keep_alive_wait_close( http, &state, 2UL );

  close( fd_http_server_fd( http ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
  free( scratch );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_oring();
  test_content_length_overflow_close();
  test_poll_conn_max();
  test_treap_seed();
  test_poll_interest();
  test_ws_send_after_staging_eviction();
  test_location_raw_path();
  test_keep_alive();
  test_zero_length_status_body();
  test_close_in_pipelined_callback();
  test_transfer_encoding_close();
  test_duplicate_content_length_different_close();
  test_ws_bad_key_close();
  test_ws_early_data_close();
  test_ws_fragmented_coalesced();
  test_ws_fragmented_split();
  test_ws_fragmented_interleaved_control();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
