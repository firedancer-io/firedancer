#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_httpdl_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_httpdl_h

#include "../../../util/fd_util_base.h"
#include "../../../util/net/fd_net_headers.h"
#include "fd_snapshot_archive.h"
#include "fd_snapshot_reader_metrics.h"
#include "fd_snapshot_peers_manager.h"

/* fd_snapshot_httpdl.h provides APIs for streaming download of Solana
   snapshots via HTTP.  It is currently hardcoded to use non-blocking
   sockets. */

/* FD_SNAPSHOT_HTTPDL_STATE_{...} manage the state machine */

#define FD_SNAPSHOT_HTTPDL_STATE_INIT  (0) /* start */
#define FD_SNAPSHOT_HTTPDL_STATE_REQ   (1) /* sending request */
#define FD_SNAPSHOT_HTTPDL_STATE_RESP  (2) /* receiving response headers */
#define FD_SNAPSHOT_HTTPDL_STATE_DL    (3) /* downloading response body */
#define FD_SNAPSHOT_HTTPDL_STATE_DONE  (4) /* downloading done */
#define FD_SNAPSHOT_HTTPDL_STATE_FAIL (-1) /* fatal error */

/* Request size limits */

#define FD_SNAPSHOT_HTTPDL_REQ_HDRS_MAX   (512UL)
#define FD_SNAPSHOT_HTTPDL_REQ_PATH_MAX   (508UL)
#define FD_SNAPSHOT_HTTPDL_RESP_HDR_CNT    (32UL)
#define FD_SNAPSHOT_HTTPDL_RESP_BUF_MAX (1UL<<20)
#define FD_SNAPSHOT_HTTPDL_FILE_PATH_MAX (4096UL)

/* FD_SNAPSHOT_HTTPDL_DEFAULT_HOPS is the number of directs to follow
   by default. */

#define FD_SNAPSHOT_HTTPDL_DEFAULT_HOPS (4UL)

#define FD_SNAPSHOT_HTTPDL_REQUEST_TIMEOUT (10e9) /* 10 seconds */
#define FD_SNAPSHOT_HTTPDL_DL_PERIOD (10UL<<20) /* 10 mib */
#define FD_SNAPSHOT_HTTPDL_SPEED_CHECK_PERIOD (100UL<<20) /* 100 mib */

struct fd_snapshot_httpdl {
  /* List of RPC node addresses */
  fd_snapshot_peers_manager_t * peers_manager;
  fd_snapshot_peer_t const *    current_peer;

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
      char path    [ 4+FD_SNAPSHOT_HTTPDL_REQ_PATH_MAX ];
      char req_hdrs[   FD_SNAPSHOT_HTTPDL_REQ_HDRS_MAX ];
    };
    char req_buf[ 4+FD_SNAPSHOT_HTTPDL_REQ_PATH_MAX+FD_SNAPSHOT_HTTPDL_REQ_HDRS_MAX ];
  };

  ulong req_tail;  /* index of first unsent char */
  ulong req_head;  /* index of end of request buf */
  ulong path_off;

  /* HTTP response header buffer */

  uchar resp_buf[ FD_SNAPSHOT_HTTPDL_RESP_BUF_MAX ];
  ulong resp_tail;
  ulong resp_head;

  /* value from "content-length:" */

  ulong content_len;

  /* Progress and speed tracking */

  ulong minimum_download_speed_mib;
  ulong dl_total;      /* total bytes downloaded */
  ulong last_dl_total; /* total bytes downloaded at last speed check */
  long  last_nanos;    /* last time speed was checked */

  /* Total written out so far */

  ulong write_total;

  /* full snapshot base slot used to verify incremental snapshot */
  ulong base_slot;

  /* File to store downloaded snapshot contents.
     Named as <snapshot-type>-<slot>-<hash>-partial.tar.zst */
  char  snapshot_archive_path[ PATH_MAX ];
  char  snapshot_filename_temp[ PATH_MAX ];
  char  snapshot_filename[ PATH_MAX ];
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
                        fd_snapshot_peers_manager_t *             peers_manager,
                        char                                      snapshot_archive_path[ PATH_MAX ],
                        fd_snapshot_archive_entry_t *             full_snapshot_entry,
                        fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry,
                        int                                       should_download_full,
                        int                                       should_download_incremental,
                        ulong                                     minimum_download_speed_mib );

void
fd_snapshot_httpdl_set_source_full( fd_snapshot_httpdl_t * self );

void
fd_snapshot_httpdl_set_source_incremental( fd_snapshot_httpdl_t * self );

/* fd_snapshot_httpdl_read receives bytes over http
   and writes up to dst_max bytes into dst.

   It is an implementation of the fd_snapshot_istream_obj_t
   virtual read interface used by fd_snapshot_reader_t */
fd_snapshot_reader_metrics_t
fd_snapshot_httpdl_read( void *  _self,
                         uchar * dst,
                         ulong   dst_max,
                         ulong * sz );

void *
fd_snapshot_httpdl_delete( fd_snapshot_httpdl_t * self );

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapshot_httpdl_h */
