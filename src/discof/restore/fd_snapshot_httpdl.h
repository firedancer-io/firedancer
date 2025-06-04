#ifndef HEADER_fd_src_discof_restore_fd_snapshot_httpdl_h
#define HEADER_fd_src_discof_restore_fd_snapshot_httpdl_h

#include "../../util/fd_util_base.h"

/* fd_snapshot_httpdl.h provides APIs for streaming download of Solana
   snapshots via HTTP.  It is currently hardcoded to use non-blocking
   sockets. */

/* FD_SNAPSHOT_HTTP_STATE_{...} manage the state machine */

#define FD_SNAPSHOT_HTTP_STATE_INIT  (0) /* start */
#define FD_SNAPSHOT_HTTP_STATE_REQ   (1) /* sending request */
#define FD_SNAPSHOT_HTTP_STATE_RESP  (2) /* receiving response headers */
#define FD_SNAPSHOT_HTTP_STATE_DL    (3) /* downloading response body */
#define FD_SNAPSHOT_HTTP_STATE_DONE  (4) /* downloading done */
#define FD_SNAPSHOT_HTTP_STATE_READ  (5) /* reading snapshot file */
#define FD_SNAPSHOT_HTTP_STATE_FAIL (-1) /* fatal error */

/* Request size limits */

#define FD_SNAPSHOT_HTTP_REQ_HDRS_MAX   (512UL)
#define FD_SNAPSHOT_HTTP_REQ_PATH_MAX   (508UL)
#define FD_SNAPSHOT_HTTP_RESP_HDR_CNT    (32UL)
#define FD_SNAPSHOT_HTTP_RESP_BUF_MAX (1UL<<20)
#define FD_SNAPSHOT_HTTP_FILE_PATH_MAX (4096UL)

/* FD_SNAPSHOT_HTTP_DEFAULT_HOPS is the number of directs to follow
   by default. */

#define FD_SNAPSHOT_HTTP_DEFAULT_HOPS (4UL)

struct fd_snapshot_httpdl {
  /* Http parameters */
  uint   ipv4;
  ushort port;

  /* Internal state */
  ushort hops;
  int    socket_fd;
  int    state;
  long   req_timeout;
  long   req_deadline;

  /* Http request path */
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

  /* value from "content-length:" */

  ulong content_len;

  /* Total downloaded so far */

  ulong dl_total;

  /* Total written out so far */

  ulong write_total;

  /* Snapshot file to download into */
  char  snapshot_path[ FD_SNAPSHOT_HTTP_FILE_PATH_MAX ];
  int   snapshot_fd;

};

typedef struct fd_snapshot_httpdl fd_snapshot_httpdl_t;

FD_FN_CONST static inline ulong
fd_snapshot_httpdl_align( void ) {
  return alignof(fd_snapshot_httpdl_t);
}

FD_FN_CONST static inline ulong
fd_snapshot_httpdl_footprint( void ) {
  return sizeof(fd_snapshot_httpdl_t);
}

fd_snapshot_httpdl_t *
fd_snapshot_httpdl_new( void * mem );

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_httpdl_h */
