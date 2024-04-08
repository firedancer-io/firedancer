#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_http_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_http_h

#include "fd_snapshot_load.h"

/* fd_snapshot_http.h provides APIs for streaming download of Solana
   snapshots via HTTP.  It is currently hardcoded to use non-blocking
   sockets. */

/* FD_SNAPSHOT_HTTP_STATE_{...} manage the state machine */

#define FD_SNAPSHOT_HTTP_STATE_INIT  (0) /* start */
#define FD_SNAPSHOT_HTTP_STATE_REQ   (1) /* sending request */
#define FD_SNAPSHOT_HTTP_STATE_RESP  (2) /* receiving response headers */
#define FD_SNAPSHOT_HTTP_STATE_DL    (3) /* downloading response body */
#define FD_SNAPSHOT_HTTP_STATE_FAIL (-1) /* fatal error */

/* Request size limits */

#define FD_SNAPSHOT_HTTP_REQ_HDRS_MAX   (512UL)
#define FD_SNAPSHOT_HTTP_REQ_PATH_MAX   (508UL)
#define FD_SNAPSHOT_HTTP_RESP_HDR_CNT    (32UL)
#define FD_SNAPSHOT_HTTP_RESP_BUF_MAX (65536UL)

/* FD_SNAPSHOT_HTTP_DEFAULT_HOPS is the number of directs to follow
   by default. */

#define FD_SNAPSHOT_HTTP_DEFAULT_HOPS (4UL)

/* fd_snapshot_http_t is the snapshot HTTP client class. */

struct fd_snapshot_http {
  uint   next_ipv4;  /* big-endian, see fd_ip4.h */
  ushort next_port;
  ushort hops;       /* number of redirects still permitted */

  int    socket_fd;
  int    state;
  long   req_timeout;
  long   req_deadline;

  /* HTTP request buffer */

  union __attribute__((packed)) {
    struct __attribute__((packed)) {
      char path    [ 4+FD_SNAPSHOT_HTTP_REQ_PATH_MAX ];
      char req_hdrs[   FD_SNAPSHOT_HTTP_REQ_HDRS_MAX ];
    };
    char req_buf[ 4+FD_SNAPSHOT_HTTP_REQ_PATH_MAX+FD_SNAPSHOT_HTTP_REQ_HDRS_MAX ];
  };

  ushort req_tail;  /* index of first unsent char */
  ushort req_head;  /* index of end of request buf */
  ushort path_off;
  ushort _pad;

  /* HTTP response header buffer */

  uchar resp_buf[ FD_SNAPSHOT_HTTP_RESP_BUF_MAX ];
  uint  resp_tail;
  uint  resp_head;
};

typedef struct fd_snapshot_http fd_snapshot_http_t;

FD_PROTOTYPES_BEGIN

fd_snapshot_http_t *
fd_snapshot_http_new( void * mem,
                      uint   dst_ipv4,
                      ushort dst_port );

void *
fd_snapshot_http_delete( fd_snapshot_http_t * this );

/* fd_snapshot_http_set_timeout sets the request timeout of the HTTP
   client.  Measured in ns from first connection attempt to response
   headers received.  Resets in case of a redirect. */

void
fd_snapshot_http_set_timeout( fd_snapshot_http_t * this,
                              long                 req_timeout );

/* fd_snapshot_http_set_path sets the path of the next request.  Should
   start with '/'. */

int
fd_snapshot_http_set_path( fd_snapshot_http_t * this,
                           char const *         path, 
                           ulong                path_len );

int
fd_io_istream_snapshot_http_read( void *  _this,
                                  void *  dst,
                                  ulong   dst_max,
                                  ulong * dst_sz );

extern fd_io_istream_vt_t const fd_io_istream_snapshot_http_vt;

static inline fd_io_istream_obj_t
fd_io_istream_snapshot_http_virtual( fd_snapshot_http_t * this ) {
  return (fd_io_istream_obj_t) {
    .this = this,
    .vt   = &fd_io_istream_snapshot_http_vt
  };
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_http_h */
