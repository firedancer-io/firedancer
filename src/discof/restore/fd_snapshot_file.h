#ifndef HEADER_fd_src_discof_restore_fd_snapshot_file_h
#define HEADER_fd_src_discof_restore_fd_snapshot_file_h

#include "fd_snapshot_reader_metrics.h"
#include "../../util/bits/fd_bits.h"
#include "../../util/log/fd_log.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct fd_snapshot_file {
  int fd;

  fd_snapshot_reader_metrics_t metrics;
};

typedef struct fd_snapshot_file fd_snapshot_file_t;

FD_FN_CONST static inline ulong
fd_snapshot_file_align( void ) {
  return alignof(fd_snapshot_file_t);
}

FD_FN_CONST static inline ulong
fd_snapshot_file_footprint( void ) {
  return sizeof(fd_snapshot_file_t);
}

fd_snapshot_file_t *
fd_snapshot_file_new( void * mem,
                      int    fd );

fd_snapshot_reader_metrics_t
fd_snapshot_file_read( void *               _self,
                       uchar *              dst,
                       ulong                dst_max,
                       ulong *              sz );

static inline void
fd_snapshot_file_close( fd_snapshot_file_t * self ) {
  if( FD_UNLIKELY( close( self->fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  self->fd = -1;
}

static inline void *
fd_snapshot_file_delete( fd_snapshot_file_t * self ) {
  memset( self, 0, sizeof(fd_snapshot_file_t) );
  return self;
}

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_file_h */