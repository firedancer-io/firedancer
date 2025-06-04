#ifndef HEADER_fd_src_discof_restore_fd_snapshot_istream_h
#define HEADER_fd_src_discof_restore_fd_snapshot_istream_h

#include "../../util/fd_util_base.h"
#include "fd_snapshot_reader_metrics.h"
#include "fd_snapshot_file.h"

#define SRC_FILE (0)
#define SRC_HTTP (1)

struct fd_snapshot_istream_vt {

  /* Virtual version of fd_io_read
     Assumed to be blocking (TODO fix) */

  fd_snapshot_reader_metrics_t
  (* read)( void *  _self,
            uchar * dst,
            ulong   dst_max,
            ulong * sz );

};

typedef struct fd_snapshot_istream_vt fd_snapshot_istream_vt_t;

struct fd_snapshot_istream_obj {
  int                              src_type;
  void *                           this;
  fd_snapshot_istream_vt_t const * vt;
};

typedef struct fd_snapshot_istream_obj fd_snapshot_istream_obj_t;

extern fd_snapshot_istream_vt_t const fd_snapshot_istream_file_vt;

FD_PROTOTYPES_BEGIN

static inline fd_snapshot_istream_obj_t
fd_snapshot_istream_file( fd_snapshot_file_t * file ) {
  return (fd_snapshot_istream_obj_t) {
    .this = file,
    .vt   = &fd_snapshot_istream_file_vt,
    .src_type = SRC_FILE,
  };
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_istream_h */
