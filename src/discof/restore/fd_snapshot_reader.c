#include "fd_snapshot_reader.h"
#include "fd_snapshot_istream.h"
#include "../../util/log/fd_log.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

fd_snapshot_reader_t *
fd_snapshot_reader_new_local( void *                                    mem,
                              fd_snapshot_archive_entry_t *             full_snapshot_entry,
                              fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry,
                              int                                       incremental_snapshot_fetch ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_reader_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_reader_t * self   = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_reader_align(), fd_snapshot_reader_footprint() );

  void * full_snapshot_file_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_file_align(),   fd_snapshot_file_footprint() );
  int full_fd = open( full_snapshot_entry->filename, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( full_fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  self->full_snapshot_file = fd_snapshot_file_new( full_snapshot_file_mem, full_fd );

  if( incremental_snapshot_fetch && incremental_snapshot_entry ) {
    void * incremental_snapshot_file_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_file_align(),   fd_snapshot_file_footprint() );
    int inc_fd = open( incremental_snapshot_entry->inner.filename, O_RDONLY|O_CLOEXEC );
    if( FD_UNLIKELY( inc_fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    self->incremental_snapshot_file = fd_snapshot_file_new( incremental_snapshot_file_mem, inc_fd );
  } else {
    self->incremental_snapshot_file = NULL;
    fd_memset( &self->incremental_src, 0, sizeof(fd_snapshot_istream_obj_t) );
  }

  self->http = NULL;

  /* set up virtual source */
  self->full_src        = fd_snapshot_istream_file( self->full_snapshot_file );
  self->incremental_src = fd_snapshot_istream_file( self->incremental_snapshot_file );
  self->vsrc            = &self->full_src;
  return self;
}
