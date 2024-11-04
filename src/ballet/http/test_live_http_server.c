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

static fd_http_server_response_t
request( fd_http_server_request_t const * request ) {
  test_http_server_t * state = (test_http_server_t *)request->ctx;

  FD_LOG_NOTICE(( "REQUEST id=%lu method=%s path=\"%s\" content_type=\"%s\" ctx=%lx",
                  request->connection_id,
                  fd_http_server_method_str( request->method ),
                  request->path,
                  request->headers.content_type,
                  (ulong)request->ctx ));

  if( FD_LIKELY( request->method==FD_HTTP_SERVER_METHOD_GET ) ) {
    if( FD_LIKELY( request->headers.upgrade_websocket ) ) {
        fd_http_server_response_t response = {
          .status            = 200,
          .upgrade_websocket = 1,
          .content_type      = "application/json"
        };
        return response;
      }

      fd_http_server_printf( state->http, "<!doctype html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <title>Nothing</title> </head> <body> <h1>Hello, world!</h1> </body> </html>\r\n" );
      fd_http_server_response_t response = {
        .status            = 200,
        .upgrade_websocket = 0,
        .content_type      = "text/html",
      };
      FD_TEST( !fd_http_server_stage_body( state->http, &response ) );
      return response;
  } else {
    fwrite( ">>>", 1, 3, stdout );
    fwrite( request->post.body, 1, request->post.body_len, stdout );
    printf( "<<<\n" );

    fd_http_server_printf( state->http, "{\"jsonrpc\": \"2.0\", \"result\": {\"absoluteSlot\": 166598, \"blockHeight\": 166500, \"epoch\": 27, \"slotIndex\": 2790, \"slotsInEpoch\": 8192, \"transactionCount\": 22661093}, \"id\": 1}\r\n" );
    fd_http_server_response_t response = {
      .status            = 200,
      .upgrade_websocket = 0,
      .content_type      = "application/json",
    };
    FD_TEST( !fd_http_server_stage_body( state->http, &response ) );
    return response;
  }
}

static void
http_close( ulong  conn_id,
            int    reason,
            void * ctx ) {
  FD_LOG_NOTICE(( "CLOSE id=%lu reason=%s ctx=%lx", conn_id, fd_http_server_connection_close_reason_str( reason ), (ulong)ctx ));
}

static void
ws_open( ulong  ws_conn_id,
         void * ctx ) {
  FD_LOG_NOTICE(( "WS OPEN id=%lu ctx=%lx", ws_conn_id, (ulong)ctx ));
}

static void
ws_close( ulong  ws_conn_id,
          int    reason,
          void * ctx ) {
  FD_LOG_NOTICE(( "WS CLOSE id=%lu reason=%s ctx=%lx", ws_conn_id, fd_http_server_connection_close_reason_str( reason ), (ulong)ctx ));
}

static void
ws_message( ulong         ws_conn_id,
            uchar const * data,
            ulong         data_len,
            void *        ctx ) {
  FD_LOG_NOTICE(( "WS id=%lu ctx=%lx", ws_conn_id, (ulong)ctx ));
  fwrite( ">>>", 1, 3, stdout );
  fwrite( data, 1, data_len, stdout );
  printf( "<<<\n" );
}

static void
ws_send_all( fd_http_server_t * http ) {
  fd_http_server_printf( http, "{ \"jsonrpc\": \"2.0\", \"result\": 0, \"id\": 1 }" );
  FD_TEST( !fd_http_server_ws_broadcast( http ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_http_server_params_t params = {
    .max_connection_cnt    = 5UL,
    .max_ws_connection_cnt = 2UL,
    .max_request_len       = 1<<16,
    .max_ws_recv_frame_len = 2048UL,
    .max_ws_send_frame_cnt = 100UL,
    .outgoing_buffer_sz    = 4096UL,
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
  FD_LOG_NOTICE(( "try running\npython3 test_http_server.py" ));

  install_signal_handler();

  long now = fd_log_wallclock();
  while( !stop ) {
    long current = fd_log_wallclock();

    fd_http_server_poll( state.http );

    if( FD_UNLIKELY( current-now>1000L*1000L*1000L ) ) {
      ws_send_all( state.http );
      now = current;
    }
  }

  free( fd_http_server_delete( fd_http_server_leave( state.http ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
