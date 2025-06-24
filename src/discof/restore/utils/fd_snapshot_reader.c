#include "fd_snapshot_reader.h"
#include "fd_snapshot_istream.h"
#include "../../../util/log/fd_log.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

fd_snapshot_reader_t *
fd_snapshot_reader_new( void *                                    mem,
                        int                                       should_download_full,
                        int                                       should_download_incremental,
                        char                                      snapshot_archive_path[ PATH_MAX ],
                        fd_snapshot_peers_manager_t *             peers_manager,
                        fd_snapshot_archive_entry_t *             full_snapshot_entry,
                        fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry,
                        int                                       incremental_snapshot_fetch,
                        ulong                                     minimum_download_speed_mib ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_reader_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_reader_t * self   = FD_SCRATCH_ALLOC_APPEND( l,
                                                           alignof(fd_snapshot_reader_t),
                                                           sizeof(fd_snapshot_reader_t) );
  fd_memset( self, 0, sizeof(fd_snapshot_reader_t) );

  if( should_download_full || should_download_incremental ) {
    void * http_mem = FD_SCRATCH_ALLOC_APPEND( l,
                                               fd_snapshot_httpdl_align(),
                                               fd_snapshot_httpdl_footprint() );
    self->http = fd_snapshot_httpdl_new( http_mem,
                                         peers_manager,
                                         snapshot_archive_path,
                                         full_snapshot_entry,
                                         incremental_snapshot_entry,
                                         should_download_full,
                                         should_download_incremental,
                                         minimum_download_speed_mib );
    if( should_download_full ) {
      self->full_src = fd_snapshot_istream_httpdl( self->http );
    } else {
      self->incremental_src = fd_snapshot_istream_httpdl( self->http );
    }
  }

  if( !should_download_full ) {
    /* Set up local snapshot file sources */
    if( FD_UNLIKELY( !full_snapshot_entry->filename[0] ) ) {
      FD_LOG_WARNING(( "NULL full_snapshot_entry" ));
      return NULL;
    }

    void * full_snapshot_file_mem = FD_SCRATCH_ALLOC_APPEND( l,
                                                             fd_snapshot_file_align(),
                                                             fd_snapshot_file_footprint() );
    int full_fd = open( full_snapshot_entry->filename, O_RDONLY|O_CLOEXEC );
    if( FD_UNLIKELY( full_fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    FD_LOG_NOTICE(( "Retrieving full snapshot from %s", full_snapshot_entry->filename ));

    self->full_snapshot_file = fd_snapshot_file_new( full_snapshot_file_mem, full_fd );
    self->full_src           = fd_snapshot_istream_file( self->full_snapshot_file );
  }

  if( incremental_snapshot_fetch && !should_download_incremental ) {
    if( !incremental_snapshot_entry->inner.filename[0] ) {
      FD_LOG_WARNING(( "NULL incremental_snapshot_entry" ));
      return NULL;
    }

    void * incremental_snapshot_file_mem = FD_SCRATCH_ALLOC_APPEND( l,
                                                                    fd_snapshot_file_align(),
                                                                    fd_snapshot_file_footprint() );
    int inc_fd = open( incremental_snapshot_entry->inner.filename, O_RDONLY|O_CLOEXEC );
    if( FD_UNLIKELY( inc_fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    FD_LOG_NOTICE(( "Retrieving incremental snapshot from %s", incremental_snapshot_entry->inner.filename ));

    self->incremental_snapshot_file = fd_snapshot_file_new( incremental_snapshot_file_mem, inc_fd );
    self->incremental_src           = fd_snapshot_istream_file( self->incremental_snapshot_file );
  }

  self->vsrc = &self->full_src;
  return self;
}
