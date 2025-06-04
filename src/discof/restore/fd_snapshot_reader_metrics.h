#ifndef HEADER_fd_src_discof_restore_fd_snapshot_reader_metrics_h
#define HEADER_fd_src_discof_restore_fd_snapshot_reader_metrics_h

#include "../../util/fd_util_base.h"

#define FD_SNAPSHOT_READER_INIT  (0)
#define FD_SNAPSHOT_READER_READ  (1)
#define FD_SNAPSHOT_READER_DONE  (2)
#define FD_SNAPSHOT_READER_ABORT (3)

struct fd_snapshot_reader_metrics {
  int   status;
  ulong bytes_read;
  ulong bytes_total;
};

typedef struct fd_snapshot_reader_metrics fd_snapshot_reader_metrics_t;

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_reader_metrics_h */
