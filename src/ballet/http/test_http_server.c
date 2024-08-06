#include "../fd_ballet.h"
#include "fd_http_server.h"
#include <malloc.h>
#include <signal.h>
#include <sys/time.h>

static volatile int stopflag = 0;
static void sighandler(int sig) {
  (void)sig;
  stopflag = 1;
}

static fd_http_server_response_t
request_get( ulong connection_id, char const * path, int upgrade_websocket, void * ctx ) {
  FD_LOG_NOTICE(( "GET id=%lu path=\"%s\" ctx=%lx", connection_id, path, (ulong)ctx ));

  if( upgrade_websocket ) {
    fd_http_server_response_t response = {
      .status = 200,
      .upgrade_websocket = 1,
      .content_type = "application/json"
    };
    return response;
  }

  static const char* TEXT = "<!doctype html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <title>Nothing</title> </head> <body> <h1>Hello, world!</h1> </body> </html>\r\n";
  fd_http_server_response_t response = {
    .status = 200,
    .upgrade_websocket = 0,
    .content_type = "text/html",
    .body = (const uchar*)strdup(TEXT),
    .body_len = strlen(TEXT),
  };
  return response;
}

static fd_http_server_response_t
request_post( ulong connection_id, char const * path, char const * content_type, uchar const * data, ulong data_len, void * ctx ) {
  FD_LOG_NOTICE(( "POST id=%lu path=\"%s\" content_type=\"%s\" ctx=%lx", connection_id, path, content_type, (ulong)ctx ));
  fwrite(">>>", 1, 3, stdout);
  fwrite(data, 1, data_len, stdout);
  printf("<<<\n");
  static const char* TEXT = "{\"jsonrpc\": \"2.0\", \"result\": {\"absoluteSlot\": 166598, \"blockHeight\": 166500, \"epoch\": 27, \"slotIndex\": 2790, \"slotsInEpoch\": 8192, \"transactionCount\": 22661093}, \"id\": 1}\r\n";
  fd_http_server_response_t response = {
    .status = 200,
    .upgrade_websocket = 0,
    .content_type = "application/json",
    .body = (const uchar*)strdup(TEXT),
    .body_len = strlen(TEXT),
  };
  return response;
}

static void
http_close( ulong connection_id, int reason, fd_http_server_response_t * last_response, void * ctx ) {
  FD_LOG_NOTICE(( "CLOSE id=%lu reason=%d ctx=%lx", connection_id, reason, (ulong)ctx ));
  if( last_response->body ) free( (uchar*)last_response->body );
}

struct conn_list {
  ulong conn_list[20];
  ulong conn_list_cnt;
};

static void
ws_open( ulong connection_id, void * ctx ) {
  FD_LOG_NOTICE(( "WS OPEN id=%lu ctx=%lx", connection_id, (ulong)ctx ));
  struct conn_list * conns = (struct conn_list *)ctx;
  if( conns->conn_list_cnt < 20 )
    conns->conn_list[conns->conn_list_cnt ++] = connection_id;
}

static void
ws_close( ulong connection_id, int reason, void * ctx ) {
  FD_LOG_NOTICE(( "WS CLOSE id=%lu reason=%d ctx=%lx", connection_id, reason, (ulong)ctx ));
  struct conn_list * conns = (struct conn_list *)ctx;
  for( ulong i = 0; i < conns->conn_list_cnt; ++i ) {
    if( conns->conn_list[i] == connection_id ) {
      conns->conn_list[i] = conns->conn_list[ --(conns->conn_list_cnt) ];
      return;
    }
  }
  FD_LOG_ERR(( "not a connection!" ));
}

static void
ws_message( ulong connection_id, uchar const * data, ulong data_len, void * ctx ) {
  FD_LOG_NOTICE(( "WS id=%lu ctx=%lx", connection_id, (ulong)ctx ));
  fwrite(">>>", 1, 3, stdout);
  fwrite(data, 1, data_len, stdout);
  printf("<<<\n");
}

void
ws_send_all( fd_http_server_t * server, struct conn_list * conns ) {
  for( ulong i = 0; i < conns->conn_list_cnt; ++i ) {
    const char * TEXT = "{ \"jsonrpc\": \"2.0\", \"result\": 0, \"id\": 1 }";
    fd_http_server_ws_frame_t data = {
      .data = (const uchar*)strdup(TEXT),
      .data_len = strlen(TEXT),
    };
    fd_http_server_ws_send( server, conns->conn_list[i], data );
  }
}

static void
ws_sent( ulong connection_id, fd_http_server_ws_frame_t * frame, void * ctx ) {
  FD_LOG_NOTICE(( "WS SENT id=%lu ctx=%lx", connection_id, (ulong)ctx ));
  free((uchar*)frame->data);
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  struct conn_list conns = { .conn_list_cnt = 0 };

  fd_http_server_params_t params = {
    .max_connection_cnt = 5,
    .max_ws_connection_cnt = 2,
    .max_request_len = 1<<16,
    .max_ws_recv_frame_len = 2048,
    .max_ws_send_frame_cnt = 100
  };

  fd_http_server_callbacks_t callbacks = {
    .request_get = request_get,
    .request_post = request_post,
    .close = http_close,
    .ws_open = ws_open,
    .ws_close = ws_close,
    .ws_message = ws_message,
    .ws_sent = ws_sent
  };

  void* server_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  fd_http_server_t * server = fd_http_server_join( fd_http_server_new( server_mem, params, callbacks, &conns ) );

  FD_TEST( fd_http_server_listen( server, 4321U ) != NULL );

  FD_LOG_NOTICE(( "try running\npython3 test_http_server.py" ));

  signal( SIGINT, sighandler );
  struct timeval last_tv = { .tv_sec = 0 };
  while( !stopflag ) {
    fd_http_server_poll( server );
    struct timeval tv;
    gettimeofday( &tv, NULL );
    if( tv.tv_sec != last_tv.tv_sec ) {
      ws_send_all( server, &conns );
      last_tv = tv;
    }
  }

  free( fd_http_server_delete( fd_http_server_leave( server ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
