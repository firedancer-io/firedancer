#include "fd_snapshot_file.h"
#include "fd_snapshot_istream.h"

fd_snapshot_file_t *
fd_snapshot_file_new( void * mem,
                      int    fd ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_file_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_file_t * self = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_file_align(), fd_snapshot_file_footprint() );
  self->fd = fd;

  struct stat snapshot_stat;
  if( FD_UNLIKELY( 0!=fstat( self->fd, &snapshot_stat ) ) ) {
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  self->metrics.bytes_total = (ulong)snapshot_stat.st_size;
  self->metrics.bytes_read  = 0UL;
  self->metrics.status      = FD_SNAPSHOT_READER_INIT;
  return self;
}

fd_snapshot_reader_metrics_t
fd_snapshot_file_read( void *               _self,
                       uchar *              dst,
                       ulong                dst_max,
                       ulong *              sz ) {
  fd_snapshot_file_t * self = fd_type_pun( _self );

  long res = read( self->fd, dst, dst_max );

  if( FD_UNLIKELY( res<=0L ) ) {
    if( FD_UNLIKELY( res==0 ) ) {
      self->metrics.status = FD_SNAPSHOT_READER_DONE;
    }
    else if( FD_LIKELY( errno==EAGAIN ) ) {
      *sz = 0;
    } else {
      /* aborts app */
      FD_LOG_WARNING(( "readv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      *sz                  = 0;
      self->metrics.err    = errno;
      self->metrics.status = FD_SNAPSHOT_READER_FAIL;
    }
  } else {
    *sz = (ulong)res;
  }

  self->metrics.bytes_read += *sz;
  return self->metrics;
}

fd_snapshot_istream_vt_t const fd_snapshot_istream_file_vt =
  { .read = fd_snapshot_file_read };
