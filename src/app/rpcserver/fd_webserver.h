#ifndef HEADER_fd_src_tango_webserver_fd_webserver_h
#define HEADER_fd_src_tango_webserver_fd_webserver_h

#include "fd_methods.h"
#include "../../util/textstream/fd_textstream.h"
#include "../../ballet/http/fd_http_server.h"

struct fd_webserver {
  fd_http_server_t * server;
  void * cb_arg;
};
typedef struct fd_webserver fd_webserver_t;

int fd_webserver_start(ushort portno, fd_http_server_params_t params, fd_webserver_t * ws, void * cb_arg );

int fd_webserver_stop(fd_webserver_t * ws);

void fd_webserver_poll(fd_webserver_t * ws);

#ifndef KEYW_UNKNOWN
#define KEYW_UNKNOWN -1L
#endif
long fd_webserver_json_keyword(const char* keyw, size_t keyw_sz);
const char* un_fd_webserver_json_keyword(long id);

struct fd_web_replier;
void fd_webserver_method_generic(struct fd_web_replier* replier, struct json_values* values, void * cb_arg);

fd_textstream_t * fd_web_replier_textstream(struct fd_web_replier* replier);
void fd_web_replier_done(struct fd_web_replier* replier);

int fd_webserver_ws_subscribe(struct json_values* values, ulong conn_id, void * cb_arg);

void fd_webserver_ws_closed(ulong conn_id, void * cb_arg);

void fd_web_ws_reply( fd_webserver_t * ws, ulong conn_id, fd_textstream_t * ts);

void fd_web_replier_error( struct fd_web_replier* replier, const char* format, ... )
  __attribute__ ((format (printf, 2, 3)));
void fd_web_replier_simple_error( struct fd_web_replier* replier, const char* text, uint text_size);

void fd_web_ws_error( fd_webserver_t * ws, ulong conn_id, const char* format, ... )
  __attribute__ ((format (printf, 3, 4)));
void fd_web_ws_simple_error( fd_webserver_t * ws, ulong conn_id, const char* text, uint text_size);

#endif /* HEADER_fd_src_tango_webserver_fd_webserver_h */
