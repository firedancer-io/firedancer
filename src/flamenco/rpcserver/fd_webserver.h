#ifndef HEADER_fd_src_tango_webserver_fd_webserver_h
#define HEADER_fd_src_tango_webserver_fd_webserver_h

#include "fd_methods.h"
#include "../../ballet/http/fd_http_server.h"

// #define FD_RPC_VERBOSE 1

struct fd_webserver {
  fd_http_server_t * server;
  void *             cb_arg;
  unsigned int       status_code;
  ulong              prev_reply_len;
  ulong              quick_size;
#define FD_WEBSERVER_QUICK_MAX (1U<<14U)
  char               quick_buf[FD_WEBSERVER_QUICK_MAX];
};
typedef struct fd_webserver fd_webserver_t;

int fd_webserver_start(ushort portno, fd_http_server_params_t params, fd_valloc_t valloc, fd_webserver_t * ws, void * cb_arg);

int fd_webserver_stop(fd_valloc_t valloc, fd_webserver_t * ws);

int fd_webserver_poll(fd_webserver_t * ws);

int fd_webserver_fd(fd_webserver_t * ws);

#ifndef KEYW_UNKNOWN
#define KEYW_UNKNOWN -1L
#endif
long fd_webserver_json_keyword(const char* keyw, size_t keyw_sz);
const char* un_fd_webserver_json_keyword(long id);

void fd_webserver_method_generic(struct json_values* values, void * cb_arg);

int fd_webserver_ws_subscribe(struct json_values* values, ulong conn_id, void * cb_arg);

void fd_webserver_ws_closed(ulong conn_id, void * cb_arg);

void fd_web_ws_send( fd_webserver_t * ws, ulong conn_id );

void fd_web_reply_new( fd_webserver_t * ws );

void fd_web_reply_error( fd_webserver_t * ws, int errcode, const char * text, const char * call_id );

int fd_web_reply_append( fd_webserver_t * ws,
                         const char *     text,
                         ulong            text_sz );

int fd_web_reply_encode_base58( fd_webserver_t * ws,
                                const void *     data,
                                ulong            data_sz );

int fd_web_reply_encode_base64( fd_webserver_t * ws,
                                const void *     data,
                                ulong            data_sz );

int fd_web_reply_encode_hex( fd_webserver_t * ws,
                             const void *     data,
                             ulong            data_sz );

int fd_web_reply_sprintf( fd_webserver_t * ws, const char* format, ... )
  __attribute__ ((format (printf, 2, 3)));

int fd_web_reply_encode_json_string( fd_webserver_t * ws, const char* str );

#endif /* HEADER_fd_src_tango_webserver_fd_webserver_h */
