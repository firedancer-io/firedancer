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
#include "fd_methods.h"
#include "fd_webserver.h"

struct fd_websocket_ctx {
  fd_webserver_t * ws;
  ulong connection_id;
};

// Parse the top level json request object
void json_parse_root(struct fd_web_replier* replier, json_lex_state_t* lex, void* cb_arg) {
  struct json_values values;
  json_values_new(&values);

  struct json_path path;
  path.len = 0;
  if (json_values_parse(lex, &values, &path)) {
    json_values_printout(&values);
    fd_webserver_method_generic(replier, &values, cb_arg);
  } else {
    ulong sz;
    const char* text = json_lex_get_text(lex, &sz);
    FD_LOG_WARNING(( "json parsing error: %s", text ));
    fd_web_replier_simple_error(replier, text, (uint)sz);
  }

  json_values_delete(&values);
}

struct fd_web_replier {
  const char* upload_data;
  size_t upload_data_size;
  unsigned int status_code;
  fd_textstream_t textstream;
};

struct fd_web_replier* fd_web_replier_new(void) {
  struct fd_web_replier* r = (struct fd_web_replier*)malloc(sizeof(struct fd_web_replier));
  r->upload_data = NULL;
  r->upload_data_size = 0;
  r->status_code = 200; // OK
  fd_textstream_new(&r->textstream, fd_libc_alloc_virtual(), 1UL<<18); // 256KB chunks
  return r;
}

void fd_web_replier_delete(struct fd_web_replier* r) {
  fd_textstream_destroy(&r->textstream);
  free(r);
}

fd_textstream_t * fd_web_replier_textstream(struct fd_web_replier* r) {
  return &r->textstream;
}

void fd_web_replier_error( struct fd_web_replier* r, const char* format, ... ) {
  char text[4096];
  va_list ap;
  va_start(ap, format);
  /* Would be nice to vsnprintf directly into the textstream, but that's messy */
  int x = vsnprintf(text, sizeof(text), format, ap);
  va_end(ap);
  fd_web_replier_simple_error(r, text, (uint)x);
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

void fd_web_replier_simple_error( struct fd_web_replier* r, const char* text, uint text_size) {
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

  fd_textstream_t * ts = &r->textstream;
  fd_textstream_clear(ts);
  fd_textstream_append(ts, DOC1, strlen(DOC1));
  fd_textstream_append(ts, text, text_size);
  fd_textstream_append(ts, DOC2, strlen(DOC2));
  fd_textstream_append(ts, r->upload_data, r->upload_data_size);
  fd_textstream_append(ts, DOC3, strlen(DOC3));

  r->status_code = 400; // BAD_REQUEST
}

static fd_http_server_response_t
request_get( ulong connection_id, char const * path, int upgrade_websocket, void * ctx ) {
  (void)connection_id;
  (void)path;
  (void)ctx;

  if( upgrade_websocket ) {
    fd_http_server_response_t response = {
      .status = 200,
      .upgrade_websocket = 1,
      .content_type = "application/json"
    };
    return response;
  }

  static const char* TEXT = "<!doctype html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <title>Error</title> </head> <body> <h1>GET method not supported!</h1> </body> </html>\r\n";
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
  (void)connection_id;

  fd_webserver_t * ws = (fd_webserver_t *)ctx;

  struct fd_web_replier * replier = fd_web_replier_new();

  if( strcmp(path, "/") != 0 ) {
    fd_web_replier_error( replier, "POST path must be \"/\"" );

  } else if( strcasecmp(content_type, "application/json") != 0 ) {
    fd_web_replier_error( replier, "content type must be \"application/json\"" );

  } else {
    replier->upload_data = (const char*)data;
    replier->upload_data_size = data_len;
    json_lex_state_t lex;
    json_lex_state_new(&lex, (const char*)data, data_len);
    json_parse_root(replier, &lex, ws->cb_arg);
    json_lex_state_delete(&lex);
  }

  fd_textstream_t * ts = &replier->textstream;
  ulong reply_len = fd_textstream_total_size(ts);
  char * reply = malloc(reply_len);
  fd_textstream_get_output( ts, reply );

  fd_http_server_response_t response = {
    .status = replier->status_code,
    .upgrade_websocket = 0,
    .content_type = (replier->status_code == 200 ? "application/json" : "text/html"),
    .body = (const uchar*)reply,
    .body_len = reply_len,
  };

  fd_web_replier_delete(replier);

  return response;
}

static void
http_close( ulong connection_id, int reason, fd_http_server_response_t * last_response, void * ctx ) {
  (void)connection_id;
  (void)reason;
  (void)ctx;

  if( last_response->body ) {
    free( (uchar*)last_response->body );
    last_response->body = NULL;
  }
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

  fd_textstream_t ts;
  fd_textstream_new(&ts, fd_libc_alloc_virtual(), 1UL<<12);
  fd_textstream_append(&ts, DOC1, strlen(DOC1));
  fd_textstream_append(&ts, text, text_size);
  fd_textstream_append(&ts, DOC2, strlen(DOC2));

  ulong reply_len = fd_textstream_total_size(&ts);
  char * reply = malloc(reply_len);
  fd_textstream_get_output( &ts, reply );
  fd_http_server_ws_frame_t data = {
    .data = (const uchar*)reply,
    .data_len = reply_len
  };
  fd_http_server_ws_send( ws->server, conn_id, data );

  fd_textstream_destroy(&ts);
}

void fd_web_ws_reply( fd_webserver_t * ws, ulong conn_id, fd_textstream_t * ts) {
  ulong reply_len = fd_textstream_total_size(ts);
  char * reply = malloc(reply_len);
  fd_textstream_get_output( ts, reply );
  fd_http_server_ws_frame_t data = {
    .data = (const uchar*)reply,
    .data_len = reply_len
  };
  fd_http_server_ws_send( ws->server, conn_id, data );
}

static void
ws_sent( ulong connection_id, fd_http_server_ws_frame_t * frame, void * ctx ) {
  (void)connection_id;
  (void)ctx ;
  if( frame->data ) {
    free((uchar*)frame->data);
    frame->data = NULL;
  }
}

int fd_webserver_start( ushort portno, fd_http_server_params_t params, fd_webserver_t * ws, void * cb_arg ) {
  ws->cb_arg = cb_arg;

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
  ws->server = fd_http_server_join( fd_http_server_new( server_mem, params, callbacks, ws ) );

  FD_TEST( fd_http_server_listen( ws->server, portno ) != NULL );

  return 0;
}

int fd_webserver_stop(fd_webserver_t * ws) {
  free( fd_http_server_delete( fd_http_server_leave( ws->server ) ) );
  return 0;
}

void fd_webserver_poll(fd_webserver_t * ws) {
  fd_http_server_poll( ws->server );
}
