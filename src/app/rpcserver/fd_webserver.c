#include "../../util/fd_util.h"
#include "../../ballet/base64/fd_base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <microhttpd.h>
#include "fd_methods.h"
#include "fd_webserver.h"

struct fd_websocket_ctx {
  struct MHD_UpgradeResponseHandle *urh;
  MHD_socket sock;
  fd_webserver_t * ws;
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
  struct MHD_Response* response;
  fd_textstream_t textstream;
};

struct fd_web_replier* fd_web_replier_new(void) {
  struct fd_web_replier* r = (struct fd_web_replier*)malloc(sizeof(struct fd_web_replier));
  r->upload_data = NULL;
  r->upload_data_size = 0;
  r->status_code = MHD_HTTP_OK;
  r->response = NULL;
  fd_textstream_new(&r->textstream, fd_libc_alloc_virtual(), 1UL<<18); // 256KB chunks
  return r;
}

void fd_web_replier_delete(struct fd_web_replier* r) {
  if (r->response != NULL)
    MHD_destroy_response(r->response);
  fd_textstream_destroy(&r->textstream);
  free(r);
}

fd_textstream_t * fd_web_replier_textstream(struct fd_web_replier* r) {
  return &r->textstream;
}

void fd_web_replier_done(struct fd_web_replier* r) {
  struct fd_iovec iov[100];
  ulong numiov = fd_textstream_get_iov_count(&r->textstream);
  if (numiov > 100 || fd_textstream_get_iov(&r->textstream, iov)) {
    fd_web_replier_error(r, "failure in reply generator");
    return;
  }
  r->status_code = MHD_HTTP_OK;
  if (r->response != NULL)
    MHD_destroy_response(r->response);
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
  r->response = MHD_create_response_from_iovec((struct MHD_IoVec *)iov, (uint)numiov, NULL, NULL);
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

void fd_web_ws_error( fd_websocket_ctx_t * ctx, const char* format, ... ) {
  char text[4096];
  va_list ap;
  va_start(ap, format);
  /* Would be nice to vsnprintf directly into the textstream, but that's messy */
  int x = vsnprintf(text, sizeof(text), format, ap);
  va_end(ap);
  fd_web_ws_simple_error(ctx, text, (uint)x);
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

  struct fd_iovec iov[100];
  ulong numiov = fd_textstream_get_iov_count(&r->textstream);
  if (numiov > 100 || fd_textstream_get_iov(&r->textstream, iov)) {
    FD_LOG_ERR(("failure in error reply generator"));
    return;
  }

  r->status_code = MHD_HTTP_BAD_REQUEST;
  if (r->response != NULL)
    MHD_destroy_response(r->response);
  r->response = MHD_create_response_from_iovec((struct MHD_IoVec *)iov, (uint)numiov, NULL, NULL);
}

/**
 * Signature of the callback used by MHD to notify the
 * application about completed requests.
 *
 * @param cls client-defined closure
 * @param connection connection handle
 * @param con_cls value as set by the last call to
 *        the MHD_AccessHandlerCallback
 * @param toe reason for request termination
 * @see MHD_OPTION_NOTIFY_COMPLETED
 */
static void completed_cb(void* cls,
                         struct MHD_Connection* connection,
                         void** con_cls,
                         enum MHD_RequestTerminationCode toe)
{
  (void) cls;         /* Unused. Silent compiler warning. */
  (void) connection;  /* Unused. Silent compiler warning. */
  (void) toe;         /* Unused. Silent compiler warning. */

  if (*con_cls != NULL) {
    fd_web_replier_delete((struct fd_web_replier*) (*con_cls));
    *con_cls = NULL;
  }
}

/**
 * Main MHD callback for handling requests.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param connection handle identifying the incoming connection
 * @param url the requested url
 * @param method the HTTP method used ("GET", "PUT", etc.)
 * @param version the HTTP version string (i.e. "HTTP/1.1")
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param ptr pointer that the callback can set to some
 *        address and that will be preserved by MHD for future
 *        calls for this request; since the access handler may
 *        be called many times (i.e., for a PUT/POST operation
 *        with plenty of upload data) this allows the application
 *        to easily associate some request-specific state.
 *        If necessary, this state can be cleaned up in the
 *        global "MHD_RequestCompleted" callback (which
 *        can be set with the MHD_OPTION_NOTIFY_COMPLETED).
 *        Initially, <tt>*con_cls</tt> will be NULL.
 * @return MHS_YES if the connection was handled successfully,
 *         MHS_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static enum MHD_Result handler(void* cls,
                               struct MHD_Connection* connection,
                               const char* url,
                               const char* method,
                               const char* version,
                               const char* upload_data,
                               size_t* upload_data_size,
                               void** con_cls)
{
  (void) url;               /* Unused. Silent compiler warning. */
  (void) version;           /* Unused. Silent compiler warning. */

  fd_webserver_t * ws = (fd_webserver_t *)cls;

  if (0 != strcmp (method, "POST"))
    return MHD_NO;              /* unexpected method */

  struct fd_web_replier* replier;
  if (*con_cls == NULL)
    *con_cls = replier = fd_web_replier_new();
  else
    replier = (struct fd_web_replier*) (*con_cls);

  size_t sz = *upload_data_size;
  if (sz) {
    replier->upload_data = upload_data;
    replier->upload_data_size = sz;
    json_lex_state_t lex;
    json_lex_state_new(&lex, upload_data, sz);
    json_parse_root(replier, &lex, ws->cb_arg);
    json_lex_state_delete(&lex);
    *upload_data_size = 0;
  }

  // Check if we are done with the request. This is clunky as hell,
  // but I didn't design the API.
  if (!sz && replier->upload_data_size) {
    if (replier->response != NULL)
      return MHD_queue_response (connection, replier->status_code, replier->response);
    return MHD_NO;
  }
  return MHD_YES;
}

int
fd_webserver_ws_request( fd_websocket_ctx_t * ctx, char const * msg, ulong msglen ) {
  json_lex_state_t lex;
  json_lex_state_new(&lex, msg, msglen);
  struct json_values values;
  json_values_new(&values);
  struct json_path path;
  path.len = 0;
  int ret = json_values_parse(&lex, &values, &path);
  if (ret) {
    json_values_printout(&values);
    ret = fd_webserver_ws_subscribe(&values, ctx, ctx->ws->cb_arg);
  } else {
    ulong sz;
    const char* text = json_lex_get_text(&lex, &sz);
    FD_LOG_WARNING(( "json parsing error: %s", text ));
    fd_web_ws_simple_error( ctx, text, (uint)sz );
  }
  json_values_delete(&values);
  json_lex_state_delete(&lex);
  return ret;
}

#include "fd_websocket_support.h"

void fd_web_ws_simple_error( fd_websocket_ctx_t * ctx, const char* text, uint text_size) {
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

  char buf[2048];
  ulong sz = fd_textstream_total_size(&ts);
  if ( sz <= sizeof(buf) ) {
    fd_textstream_get_output( &ts, buf );
    ws_send_frame( ctx->sock, WS_OPCODE_TEXT_FRAME, buf, sz );
  }

  fd_textstream_destroy(&ts);
}

void fd_web_ws_reply( fd_websocket_ctx_t * ctx, fd_textstream_t * ts) {
  char buf[2048];
  ulong sz = fd_textstream_total_size(ts);
  if ( sz + WS_MAX_HDR_SIZE <= sizeof(buf) ) {
    fd_textstream_get_output( ts, buf + WS_MAX_HDR_SIZE );
    ws_send_frame_prepend_hdr( ctx->sock, WS_OPCODE_TEXT_FRAME, buf + WS_MAX_HDR_SIZE, sz );
  } else {
    char * buf2 = malloc(sz + WS_MAX_HDR_SIZE);
    fd_textstream_get_output( ts, buf2 + WS_MAX_HDR_SIZE );
    ws_send_frame_prepend_hdr( ctx->sock, WS_OPCODE_TEXT_FRAME, buf2 + WS_MAX_HDR_SIZE, sz );
    free( buf2 );
  }
}

int fd_webserver_start(ulong num_threads, ushort portno, ushort ws_portno, fd_webserver_t * ws, void * cb_arg) {
  ws->cb_arg = cb_arg;

  ws->daemon = MHD_start_daemon(
    MHD_USE_INTERNAL_POLLING_THREAD
      | MHD_USE_SUPPRESS_DATE_NO_CLOCK
      | MHD_USE_AUTO | MHD_USE_TURBO,
    portno,
    NULL, NULL, &handler, ws,
    MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
    MHD_OPTION_THREAD_POOL_SIZE, (unsigned int) num_threads,
    MHD_OPTION_NOTIFY_COMPLETED, &completed_cb, ws,
    MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 1000,
    MHD_OPTION_END);
  if (ws->daemon == NULL)
    return -1;

  ws->ws_daemon = MHD_start_daemon(MHD_ALLOW_UPGRADE | MHD_USE_AUTO_INTERNAL_THREAD,
                                   ws_portno, NULL, NULL, &ahc_cb, ws,
                                   MHD_OPTION_THREAD_POOL_SIZE, (unsigned int) 1,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 1000,
                                   MHD_OPTION_END);
  if (ws->ws_daemon == NULL)
    return -1;

  ws->ws_epoll_fd = epoll_create1(0);
  if( ws->ws_epoll_fd == -1 )
    return -1;

  return 0;
}

int fd_webserver_stop(fd_webserver_t * ws) {
  MHD_stop_daemon(ws->daemon);
  MHD_stop_daemon(ws->ws_daemon);
  close( ws->ws_epoll_fd );
  return 0;
}

void fd_webserver_ws_poll(fd_webserver_t * ws) {
  struct epoll_event events[16];
  int cnt = epoll_wait( ws->ws_epoll_fd, events, 16, 0 );
  if( cnt < 0 ) {
    FD_LOG_ERR(( "epoll_wait failed: %s", strerror(errno) ));
  }
  for(int i = 0; i < cnt; ++i) {
    epoll_selected(events + i);
  }
}
