#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_file_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_file_h

#include "fd_snapshot_reader_metrics.h"
#include "../../../util/bits/fd_bits.h"
#include "../../../util/log/fd_log.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* fd_snapshot_file provides APIs for streaming read of snapshots
   files stored locally on disk.  It implements the virtual interface
   provided by fd_snapshot_istream_obj_t */
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

/* fd_snapshot_file_read receives bytes from a file descriptor
   and writes up to dst_max bytes into dst.

   It is an implementation of the fd_snapshot_istream_obj_t
   virtual read interface used by fd_snapshot_reader_t */
fd_snapshot_reader_metrics_t
fd_snapshot_file_read( void *               _self,
                       uchar *              dst,
                       ulong                dst_max,
                       ulong *              sz );

static inline void
fd_snapshot_file_close( fd_snapshot_file_t * self ) {
  if( FD_UNLIKELY( self->fd>0 ) ) {
    if( FD_UNLIKELY( close( self->fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    self->fd = -1;
  }
}

static inline void *
fd_snapshot_file_delete( fd_snapshot_file_t * self ) {
  fd_snapshot_file_close( self );
  memset( self, 0, sizeof(fd_snapshot_file_t) );
  return self;
}

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapshot_file_h */
