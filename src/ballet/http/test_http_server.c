#include "../fd_ballet.h"

#include "fd_http_server.h"
#include "fd_http_server_private.h"

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

  uchar scratch[ 329088 ] __attribute__((aligned(128UL)));
  FD_TEST( fd_http_server_footprint( params )==329088 );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( scratch, params, callbacks, NULL ) );

  http->stage_off = 6UL;
  fd_http_server_printf( http, "A" );
  fd_http_server_printf( http, "B" );
  fd_http_server_printf( http, "C" );
  FD_TEST( http->stage_off==8UL );
  FD_TEST( http->stage_len==3UL );
  FD_TEST( !memcmp( "ABC", http->oring, 3UL ) );
  fd_http_server_unstage( http );

  for( ulong i=1UL; i<32UL; i++ ) {
    for( ulong j=0UL; j<1024UL; j++ ) {
      for( ulong k=0UL; k<i; k++ ) fd_http_server_printf( http, "%c", 'a'+i );

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

  http->stage_off = 7UL;
  fd_http_server_printf( http, "01234567" );
  FD_TEST( http->stage_off==8UL );
  FD_TEST( http->stage_len==8UL );
  fd_http_server_unstage( http );

  http->stage_off = 16UL;
  fd_http_server_printf( http, "01234567" );
  FD_TEST( http->stage_off==16UL );
  FD_TEST( http->stage_len==8UL );
  FD_TEST( !fd_http_server_stage_body( http, &response ) );

  http->stage_off = 0UL;
  fd_http_server_printf( http, "012345678" );
  FD_TEST( fd_http_server_stage_body( http, &response ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_oring();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
