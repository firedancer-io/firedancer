#include "../../util/fd_util.h"
#include "../../ballet/base64/fd_base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "fd_methods.h"
#include "fd_webserver.h"

struct fd_websocket_ctx {
  fd_webserver_t * ws;
  ulong connection_id;
};

// Parse the top level json request object
static void
json_parse_root(fd_webserver_t * ws, json_lex_state_t* lex) {
  struct json_values values;
  json_values_new(&values);

  struct json_path path;
  path.len = 0;
  if (json_values_parse(lex, &values, &path)) {
    json_values_printout(&values);
    fd_webserver_method_generic(&values, ws->cb_arg);
  } else {
    ulong sz;
    const char* text = json_lex_get_text(lex, &sz);
    FD_LOG_WARNING(( "json parsing error: %s", text ));
    fd_web_simple_error(ws, text, (uint)sz);
  }

  json_values_delete(&values);
}

void fd_web_error( fd_webserver_t * ws, const char* format, ... ) {
  char text[4096];
  va_list ap;
  va_start(ap, format);
  /* Would be nice to vsnprintf directly into the textstream, but that's messy */
  int x = vsnprintf(text, sizeof(text), format, ap);
  va_end(ap);
  fd_web_simple_error(ws, text, (uint)x);
}

void fd_web_ws_error( fd_webserver_t * ws, ulong conn_id, const char* format, ... ) {
  char text[4096];
  va_list ap;
  va_start(ap, format);
  /* Would be nice to vsnprintf directly into the textstream, but that's messy */
  int x = vsnprintf(text, sizeof(text), format, ap);
  va_end(ap);
  fd_web_ws_simple_error(ws, conn_id, text, (uint)x);
}

void fd_web_simple_error( fd_webserver_t * ws, const char* text, uint text_size ) {
#define CRLF "\r\n"
  static const char* DOC1 =
"<html>" CRLF
"<head>" CRLF
"<title>ERROR</title>" CRLF
"</head>" CRLF
"<body>" CRLF
"<p><em>";
  static const char* DOC2 =
"</em></p>" CRLF
"<p>Request: <pre>";
  static const char* DOC3 =
"</pre></p>" CRLF
"</body>" CRLF
"</html>" CRLF;

  fd_hcache_memcpy(ws->hcache, (const uchar*)DOC1, strlen(DOC1));
  fd_hcache_memcpy(ws->hcache, (const uchar*)text, text_size);
  fd_hcache_memcpy(ws->hcache, (const uchar*)DOC2, strlen(DOC2));
  fd_hcache_memcpy(ws->hcache, ws->upload_data, ws->upload_data_size);
  fd_hcache_memcpy(ws->hcache, (const uchar*)DOC3, strlen(DOC3));

  ws->status_code = 400; // BAD_REQUEST
}

static fd_http_server_response_t
request( fd_http_server_request_t const * request ) {
  fd_webserver_t * ws = (fd_webserver_t *)request->ctx;

  if( FD_LIKELY( request->method==FD_HTTP_SERVER_METHOD_GET ) ) {
    if( FD_LIKELY( request->headers.upgrade_websocket ) ) {
      fd_http_server_response_t response = {
        .status            = 200,
        .upgrade_websocket = 1,
        .content_type      = "application/json"
      };
      return response;
    }

    fd_hcache_printf( ws->hcache, "<!doctype html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <title>Error</title> </head> <body> <h1>GET method not supported!</h1> </body> </html>\r\n" );
    ulong body_len     = body_len;
    uchar const * body = fd_hcache_snap_response( ws->hcache, &body_len );
    FD_TEST( body );

    fd_http_server_response_t response = {
      .status            = 400,
      .upgrade_websocket = 0,
      .content_type      = "text/html",
      .body              = body,
      .body_len          = body_len,
    };
    return response;

  } else {
    ws->upload_data = request->post.body;
    ws->upload_data_size = request->post.body_len;
    ws->status_code = 200; // OK

    if( strcmp(request->path, "/") != 0 ) {
      fd_web_error( ws, "POST path must be \"/\"" );

    } else if( strcasecmp(request->headers.content_type, "application/json") != 0 ) {
      fd_web_error( ws, "content type must be \"application/json\"" );

    } else {
      json_lex_state_t lex;
      json_lex_state_new(&lex, (const char*)request->post.body, request->post.body_len);
      json_parse_root(ws, &lex);
      json_lex_state_delete(&lex);
    }

    ulong body_len     = body_len;
    uchar const * body = fd_hcache_snap_response( ws->hcache, &body_len );
    FD_TEST( body );
    fd_http_server_response_t response = {
      .status            = ws->status_code,
      .upgrade_websocket = 0,
      .content_type      = (ws->status_code == 200 ? "application/json" : "text/html"),
      .body              = (const uchar*)body,
      .body_len          = body_len,
    };
    return response;
  }
}

static void
http_open( ulong connection_id, int sockfd, void * ctx ) {
  (void)connection_id;
  (void)ctx;

  int newsize = 1<<20;
  int rc = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &newsize, sizeof(newsize));
  if( FD_UNLIKELY( -1==rc ) ) FD_LOG_ERR(( "setsockopt failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */
}

static void
http_close( ulong connection_id, int reason, void * ctx ) {
  (void)connection_id;
  (void)reason;
  (void)ctx;
}

static void
ws_open( ulong connection_id, void * ctx ) {
  (void)connection_id;
  (void)ctx;
}

static void
ws_close( ulong connection_id, int reason, void * ctx ) {
  (void)reason;
  fd_webserver_t * ws = (fd_webserver_t *)ctx;
  fd_webserver_ws_closed( connection_id, ws->cb_arg );
}

static void
ws_message( ulong conn_id, uchar const * data, ulong data_len, void * ctx ) {
  fd_webserver_t * ws = (fd_webserver_t *)ctx;

  json_lex_state_t lex;
  json_lex_state_new(&lex, (const char*)data, data_len);
  struct json_values values;
  json_values_new(&values);
  struct json_path path;
  path.len = 0;
  int ret = json_values_parse(&lex, &values, &path);
  if (ret) {
    json_values_printout(&values);
    ret = fd_webserver_ws_subscribe(&values, conn_id, ws->cb_arg);
  } else {
    ulong sz;
    const char* text = json_lex_get_text(&lex, &sz);
    FD_LOG_WARNING(( "json parsing error: %s", text ));
    fd_web_ws_simple_error( ws, conn_id, text, (uint)sz );
  }
  json_values_delete(&values);
  json_lex_state_delete(&lex);
}

void fd_web_ws_simple_error( fd_webserver_t * ws, ulong conn_id, const char* text, uint text_size) {
#define CRLF "\r\n"
  static const char* DOC1 =
"<html>" CRLF
"<head>" CRLF
"<title>ERROR</title>" CRLF
"</head>" CRLF
"<body>" CRLF
"<p><em>";
  static const char* DOC2 =
"</em></p>" CRLF
"</body>" CRLF
"</html>" CRLF;

  fd_hcache_memcpy(ws->hcache, (const uchar*)DOC1, strlen(DOC1));
  fd_hcache_memcpy(ws->hcache, (const uchar*)text, text_size);
  fd_hcache_memcpy(ws->hcache, (const uchar*)DOC2, strlen(DOC2));

  fd_hcache_snap_ws_send( ws->hcache, conn_id );
}

void fd_web_ws_send( fd_webserver_t * ws, ulong conn_id ) {
  fd_hcache_snap_ws_send( ws->hcache, conn_id );
}

int fd_webserver_start( ushort portno, fd_http_server_params_t params, ulong hcache_size, fd_webserver_t * ws, void * cb_arg ) {
  ws->cb_arg = cb_arg;

  fd_http_server_callbacks_t callbacks = {
    .request    = request,
    .open       = http_open,
    .close      = http_close,
    .ws_open    = ws_open,
    .ws_close   = ws_close,
    .ws_message = ws_message,
  };

  void* server_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  ws->server = fd_http_server_join( fd_http_server_new( server_mem, params, callbacks, ws ) );

  void * hcache_mem = aligned_alloc( fd_hcache_align(), fd_hcache_footprint( hcache_size ) );
  ws->hcache = fd_hcache_join( fd_hcache_new( hcache_mem, ws->server, hcache_size ) );

  FD_TEST( fd_http_server_listen( ws->server, portno ) != NULL );

  return 0;
}

int fd_webserver_stop(fd_webserver_t * ws) {
  free( fd_http_server_delete( fd_http_server_leave( ws->server ) ) );
  free( fd_hcache_delete( fd_hcache_leave( ws->hcache ) ) );
  return 0;
}

void fd_webserver_poll(fd_webserver_t * ws) {
  fd_http_server_poll( ws->server );
}
