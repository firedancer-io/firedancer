struct fd_webserver {
    struct MHD_Daemon* daemon;
};
typedef struct fd_webserver fd_webserver_t;

int fd_webserver_start(uint portno, fd_webserver_t * ws);

int fd_webserver_stop(fd_webserver_t * ws);

void fd_webserver_reply_ok(struct fd_web_replier* replier);

#ifndef KEYW_UNKNOWN
#define KEYW_UNKNOWN -1L
#endif
long fd_webserver_json_keyword(const char* keyw, size_t keyw_sz);
const char* un_fd_webserver_json_keyword(long id);

int fd_webserver_method_generic(struct fd_web_replier* replier, struct json_values* values);
