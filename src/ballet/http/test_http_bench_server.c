#include "../fd_ballet.h"

#include "fd_http_server.h"

#include <malloc.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>

static volatile int stop = 0;

static void
signal_handler( int sig ) {
  (void)sig;
  stop = 1;
}

static void
install_signal_handler( void ) {
  struct sigaction sa = {
    .sa_handler = signal_handler,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

struct test_http_server {
  fd_http_server_t * http;
};

typedef struct test_http_server test_http_server_t;

#define SMALL_SIZE 8
#define BIG_SIZE (1<<18)
static uchar response_data[BIG_SIZE];

static fd_http_server_response_t
request( fd_http_server_request_t const * request ) {
  test_http_server_t * state = (test_http_server_t *)request->ctx;

  if( FD_LIKELY( request->method==FD_HTTP_SERVER_METHOD_GET ) ) {
    if( FD_LIKELY( request->headers.upgrade_websocket ) ) {
      fd_http_server_response_t response = {
        .status            = 200,
        .upgrade_websocket = 1,
        .content_type      = "text/html"
      };
      return response;
    }

    if( !strcmp(request->path, "/small") ) {
      fd_http_server_memcpy( state->http, response_data, SMALL_SIZE );
      fd_http_server_response_t response = {
        .status            = 200,
        .upgrade_websocket = 0,
        .content_type      = "text/html"
      };
      FD_TEST( !fd_http_server_stage_body( state->http, &response ) );
      return response;
    }

    if( !strcmp(request->path, "/big") ) {
      fd_http_server_memcpy( state->http, response_data, BIG_SIZE );
      fd_http_server_response_t response = {
        .status            = 200,
        .upgrade_websocket = 0,
        .content_type      = "text/html"
      };
      FD_TEST( !fd_http_server_stage_body( state->http, &response ) );
      return response;
    }

  } else if( FD_LIKELY( request->method==FD_HTTP_SERVER_METHOD_POST ) ) {
    if( !strcmp(request->path, "/echo") ) {
      /* path "/echo" just echoes the post */
      fd_http_server_memcpy( state->http, request->post.body, request->post.body_len );
      fd_http_server_response_t response = {
        .status            = 200,
        .upgrade_websocket = 0,
        .content_type      = "text/html"
      };
      FD_TEST( !fd_http_server_stage_body( state->http, &response ) );
      return response;
    }
  }

  fd_http_server_printf( state->http, "INVALID TEST POST\n" );
  fd_http_server_response_t response = {
    .status            = 400,
    .upgrade_websocket = 0,
    .content_type      = "text/html"
  };
  FD_TEST( !fd_http_server_stage_body( state->http, &response ) );
  return response;
}

static void
http_close( ulong  conn_id,
            int    reason,
            void * ctx ) {
  (void)conn_id;
  (void)reason;
  (void)ctx;
}

static void
ws_open( ulong  ws_conn_id,
         void * ctx ) {
  (void)ws_conn_id;
  (void)ctx;
}

static void
ws_close( ulong  ws_conn_id,
          int    reason,
          void * ctx ) {
  (void)ws_conn_id;
  (void)reason;
  (void)ctx;
}

static void
ws_message( ulong         ws_conn_id,
            uchar const * data,
            ulong         data_len,
            void *        ctx ) {
  (void)ws_conn_id;
  (void)data;
  (void)data_len;
  (void)ctx;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  for( uint i=0; i < BIG_SIZE; ++i ) {
    response_data[i] = (uchar)(' ' + (char)(i&63));
  }
  response_data[SMALL_SIZE-1] = '\n';
  response_data[BIG_SIZE-1] = '\n';

  fd_http_server_params_t params = {
    .max_connection_cnt    = 150UL,
    .max_ws_connection_cnt = 2UL,
    .max_request_len       = 2048UL,
    .max_ws_recv_frame_len = 2048UL,
    .max_ws_send_frame_cnt = 100UL,
    .outgoing_buffer_sz    = 10*BIG_SIZE,
  };

  fd_http_server_callbacks_t callbacks = {
    .request    = request,
    .close      = http_close,
    .ws_open    = ws_open,
    .ws_close   = ws_close,
    .ws_message = ws_message,
  };

  test_http_server_t state;
  state.http = fd_http_server_join( fd_http_server_new( aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) ),
                                                        params,
                                                        callbacks,
                                                        &state ) );

  FD_TEST( fd_http_server_listen( state.http, 0, 4321U ) );

  FD_LOG_NOTICE(( "serving http://localhost:4321" ));

  install_signal_handler();

  while( !stop ) {
    fd_http_server_poll( state.http );
  }

  free( fd_http_server_delete( fd_http_server_leave( state.http ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
