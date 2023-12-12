#ifndef HEADER_fd_src_tango_webserver_fd_webserver_h
#define HEADER_fd_src_tango_webserver_fd_webserver_h

#include "fd_methods.h"
#include "../../util/textstream/fd_textstream.h"

struct fd_webserver {
    struct MHD_Daemon* daemon;
};
typedef struct fd_webserver fd_webserver_t;

int fd_webserver_start(uint portno, fd_webserver_t * ws, void * cb_arg);

int fd_webserver_stop(fd_webserver_t * ws);

#ifndef KEYW_UNKNOWN
#define KEYW_UNKNOWN -1L
#endif
long fd_webserver_json_keyword(const char* keyw, size_t keyw_sz);
const char* un_fd_webserver_json_keyword(long id);

struct fd_web_replier;
void fd_webserver_method_generic(struct fd_web_replier* replier, struct json_values* values, void * cb_arg);

fd_textstream_t * fd_web_replier_textstream(struct fd_web_replier* replier);
void fd_web_replier_done(struct fd_web_replier* replier);

void fd_web_replier_error( struct fd_web_replier* replier, const char* format, ... )
  __attribute__ ((format (printf, 2, 3)));

#endif /* HEADER_fd_src_tango_webserver_fd_webserver_h */
