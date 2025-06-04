#ifndef HEADER_fd_src_discof_restore_fd_snapshot_reader_h
#define HEADER_fd_src_discof_restore_fd_snapshot_reader_h

#include "../../util/fd_util_base.h"
#include "../../util/bits/fd_bits.h"
#include "fd_snapshot_reader_metrics.h"
#include "fd_snapshot_httpdl.h"
#include "fd_snapshot_istream.h"
#include "fd_snapshot_archive.h"

struct fd_snapshot_reader {
  /* http source */
  fd_snapshot_httpdl_t *      http;

  /* file sources */
  fd_snapshot_file_t *        full_snapshot_file;
  fd_snapshot_file_t *        incremental_snapshot_file;

  /* virtual sources */
  fd_snapshot_istream_obj_t full_src;
  fd_snapshot_istream_obj_t incremental_src;

  /* current source */
  fd_snapshot_istream_obj_t * vsrc;
};

typedef struct fd_snapshot_reader fd_snapshot_reader_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_snapshot_reader_align( void ) {
  return fd_ulong_max( alignof(fd_snapshot_reader_t),
                       fd_ulong_max( fd_snapshot_httpdl_align(), fd_snapshot_file_align() ) );
}

FD_FN_CONST static inline ulong
fd_snapshot_reader_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_reader_t), sizeof(fd_snapshot_reader_t) );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_httpdl_align(), fd_snapshot_httpdl_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_file_align(),   fd_snapshot_file_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_file_align(),   fd_snapshot_file_footprint() );
  return FD_LAYOUT_FINI( l, fd_snapshot_reader_align() );
}

fd_snapshot_reader_t *
fd_snapshot_reader_new_local( void * mem,
                              fd_snapshot_archive_entry_t *             full_snapshot_entry,
                              fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry,
                              int                                       incremental_snapshot_fetch );

static inline fd_snapshot_reader_metrics_t
fd_snapshot_reader_read( fd_snapshot_reader_t * self,
                         uchar *                dst,
                         ulong                  dst_max,
                         ulong *                sz ) {
  return self->vsrc->vt->read( self->vsrc->this,
                                dst,
                                dst_max,
                                sz );
}

static inline void
fd_snapshot_reader_set_source_incremental( fd_snapshot_reader_t * self ) {
  FD_TEST( self->incremental_src.this );

  if( self->incremental_src.src_type == SRC_FILE ) {
    self->vsrc = &self->incremental_src;
  } else if( self->incremental_src.src_type == SRC_HTTP ) {
    /* TODO: set http to point to incremental path */
  }
}

static inline void
fd_snapshot_reader_delete( fd_snapshot_reader_t * self ) {
  if( self->full_snapshot_file ) {
    fd_snapshot_file_close( self->full_snapshot_file );
    fd_snapshot_file_delete( self->full_snapshot_file );
  }

  if( self->incremental_snapshot_file ) {
    fd_snapshot_file_close( self->incremental_snapshot_file );
    fd_snapshot_file_delete( self->incremental_snapshot_file );
  }

  if( self->http ) {
    /* TODO: delete http here */
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_snapshot_reader_h */
