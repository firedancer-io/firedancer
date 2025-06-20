#ifndef HEADER_fd_src_discof_restore_fd_snapshot_httpdl_h
#define HEADER_fd_src_discof_restore_fd_snapshot_httpdl_h

#include "../../util/fd_util_base.h"
#include "../../util/net/fd_net_headers.h"
#include "fd_snapshot_archive.h"
#include "fd_snapshot_reader_metrics.h"

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

#define FD_SNAPSHOT_HTTP_MAX_NODES (16UL)

#define FD_SNAPSHOT_REQUEST_TIMEOUT (10e9) /* 10 seconds */

struct fd_snapshot_httpdl {
  /* List of RPC node addresses */
  fd_ip4_port_t peers[ 16UL ];
  ulong         peers_cnt;

  uint   ipv4;
  ushort port;

  /* Internal state */
  ushort hops;
  int    socket_fd;
  int    state;
  int    snapshot_type; /* 0 for full, 1 for incremental */
  long   req_deadline;

  /* Http request path */
  union __attribute__((packed)) {
    struct __attribute__((packed)) {
      char path    [ 4+FD_SNAPSHOT_HTTP_REQ_PATH_MAX ];
      char req_hdrs[   FD_SNAPSHOT_HTTP_REQ_HDRS_MAX ];
    };
    char req_buf[ 4+FD_SNAPSHOT_HTTP_REQ_PATH_MAX+FD_SNAPSHOT_HTTP_REQ_HDRS_MAX ];
  };

  ulong req_tail;  /* index of first unsent char */
  ulong req_head;  /* index of end of request buf */
  ulong path_off;

  /* HTTP response header buffer */

  uchar resp_buf[ FD_SNAPSHOT_HTTP_RESP_BUF_MAX ];
  ulong resp_tail;
  ulong resp_head;

  /* value from "content-length:" */

  ulong content_len;

  /* Total downloaded so far */

  ulong dl_total;

  /* Total written out so far */

  ulong write_total;

  /* full snapshot base slot used to verify incremental snapshot */
  ulong base_slot;

  /* File to store downloaded snapshot contents.
     Named as <snapshot-type>-<slot>-<hash>-partial.tar.zst */
  char  snapshot_archive_path[ PATH_MAX ];
  int   current_snapshot_fd;

  /* snapshot entries */
  fd_snapshot_archive_entry_t *             full_snapshot_entry;
  fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry;

  /* metrics */
  fd_snapshot_reader_metrics_t metrics;
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
fd_snapshot_httpdl_new( void *                                    mem,
                        ulong                                     peers_cnt,
                        fd_ip4_port_t const                       peers[ FD_SNAPSHOT_HTTP_MAX_NODES ],
                        char const *                              snapshot_archive_path,
                        fd_snapshot_archive_entry_t *             full_snapshot_entry,
                        fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry );

void
fd_snapshot_httpdl_set_source_full( fd_snapshot_httpdl_t * self );

void
fd_snapshot_httpdl_set_source_incremental( fd_snapshot_httpdl_t * self );

void
fd_snapshot_httpdl_set_path( fd_snapshot_httpdl_t * self,
                             char const *           path,
                             ulong                  path_len );

fd_snapshot_reader_metrics_t
fd_snapshot_httpdl_read( void *  _self,
                         uchar * dst,
                         ulong   dst_max,
                         ulong * sz );

void *
fd_snapshot_httpdl_delete( fd_snapshot_httpdl_t * self );

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_httpdl_h */
