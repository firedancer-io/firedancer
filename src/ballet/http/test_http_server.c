#include "../fd_ballet.h"

#include "fd_http_server.h"
#include "fd_hcache.h"

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
  fd_http_server_t * server;
  fd_hcache_t *      hcache;
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

      fd_hcache_printf( state->hcache, "<!doctype html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <title>Nothing</title> </head> <body> <h1>Hello, world!</h1> </body> </html>\r\n" );
      ulong body_len     = body_len;
      uchar const * body = fd_hcache_snap_response( state->hcache, &body_len );
      FD_TEST( body );

      fd_http_server_response_t response = {
        .status            = 200,
        .upgrade_websocket = 0,
        .content_type      = "text/html",
        .body              = body,
        .body_len          = body_len,
      };
      return response;
  } else {
    fwrite( ">>>", 1, 3, stdout );
    fwrite( request->post.body, 1, request->post.body_len, stdout );
    printf( "<<<\n" );

    fd_hcache_printf( state->hcache, "{\"jsonrpc\": \"2.0\", \"result\": {\"absoluteSlot\": 166598, \"blockHeight\": 166500, \"epoch\": 27, \"slotIndex\": 2790, \"slotsInEpoch\": 8192, \"transactionCount\": 22661093}, \"id\": 1}\r\n" );
    ulong body_len     = body_len;
    uchar const * body = fd_hcache_snap_response( state->hcache, &body_len );
    FD_TEST( body );
    
    fd_http_server_response_t response = {
      .status            = 200,
      .upgrade_websocket = 0,
      .content_type      = "application/json",
      .body              = body,
      .body_len          = body_len,
    };
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
ws_send_all( fd_hcache_t * hcache ) {
  fd_hcache_printf( hcache, "{ \"jsonrpc\": \"2.0\", \"result\": 0, \"id\": 1 }" );
  FD_TEST( !fd_hcache_snap_ws_broadcast( hcache ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_http_server_params_t params = {
    .max_connection_cnt    = 5,
    .max_ws_connection_cnt = 2,
    .max_request_len       = 1<<16,
    .max_ws_recv_frame_len = 2048,
    .max_ws_send_frame_cnt = 100
  };

  fd_http_server_callbacks_t callbacks = {
    .request    = request,
    .close      = http_close,
    .ws_open    = ws_open,
    .ws_close   = ws_close,
    .ws_message = ws_message,
  };

  test_http_server_t state;
  state.server = fd_http_server_join( fd_http_server_new( aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) ),
                                                          params,
                                                          callbacks,
                                                          &state ) );
  state.hcache = fd_hcache_join( fd_hcache_new( aligned_alloc( fd_hcache_align(), fd_hcache_footprint( 1<<16 ) ), state.server, 1<<16 ) );

  FD_TEST( fd_http_server_listen( state.server, 4321U ) );
  FD_LOG_NOTICE(( "try running `python3 test_http_server.py`" ));

  install_signal_handler();

  long now = fd_log_wallclock();
  while( !stop ) {
    long current = fd_log_wallclock();

    fd_http_server_poll( state.server );

    if( FD_UNLIKELY( current-now>1000L*1000L*1000L ) ) {
      ws_send_all( state.hcache );
      now = current;
    }
  }

  free( fd_http_server_delete( fd_http_server_leave( state.server ) ) );
  free( fd_hcache_delete( fd_hcache_leave( state.hcache ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
