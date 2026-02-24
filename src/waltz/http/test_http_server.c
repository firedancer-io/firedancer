#include "fd_http_server.h"
#include "fd_http_server_private.h"
#include "../../util/fd_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct overflow_close_state {
  ulong close_cnt;
  int   last_reason;
};

typedef struct overflow_close_state overflow_close_state_t;

static fd_http_server_response_t
request_noop( fd_http_server_request_t const * request ) {
  (void)request;
  fd_http_server_response_t response = {
    .status = 400,
  };
  return response;
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

  ulong actual_footprint = fd_http_server_footprint( params );
  uchar scratch[ 329344 ] __attribute__((aligned(128UL)));
  FD_TEST( actual_footprint==329344 );
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

  for( ulong i=1UL; i<32UL; i++ ) {
    for( ulong j=0UL; j<1024UL; j++ ) {
      for( ulong k=0UL; k<i; k++ ) fd_http_server_printf( http, "%c", (char)('a'+i) );

      fd_http_server_response_t response;
      if( i>8 ) {
        FD_TEST( fd_http_server_stage_body( http, &response ) );
      } else {
        FD_TEST( !fd_http_server_stage_body( http, &response ) );
        FD_TEST( response._body_len==i );
        FD_TEST( (response._body_off%8UL)<=8-i );
        for( ulong l=0UL; l<i; l++ ) {
          FD_TEST( http->oring[(response._body_off%8UL)+l]==(uchar)('a'+i) );
        }
      }
    }
  }

  fd_http_server_response_t response;

  http->stage_off = 1UL;
  fd_http_server_printf( http, "01234567" );
  FD_TEST( http->stage_off==8UL );
  FD_TEST( http->stage_len==8UL );
  FD_TEST( !fd_http_server_stage_body( http, &response ) );
  FD_TEST( http->stage_comp_len==0UL );

  http->stage_off = 7UL;
  fd_http_server_printf( http, "01234567" );
  FD_TEST( http->stage_off==8UL );
  FD_TEST( http->stage_len==8UL );
  fd_http_server_unstage( http );
  FD_TEST( http->stage_comp_len==0UL );

  http->stage_off = 16UL;
  fd_http_server_printf( http, "01234567" );
  FD_TEST( http->stage_off==16UL );
  FD_TEST( http->stage_len==8UL );
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
  uchar scratch[ 3072 ] __attribute__((aligned(128UL)));
  FD_TEST( fd_http_server_footprint( params )==3072 );

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
    fd_http_server_poll( http, 1 );
  }

  FD_TEST( state.close_cnt==1UL );
  FD_TEST( state.last_reason==FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST );

  close( client_fd );
  close( fd_http_server_fd( http ) );
  fd_http_server_delete( fd_http_server_leave( http ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_oring();
  test_content_length_overflow_close();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
