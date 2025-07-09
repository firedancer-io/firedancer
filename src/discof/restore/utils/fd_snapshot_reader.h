#ifndef HEADER_fd_src_discof_restore_utils_fd_snapshot_reader_h
#define HEADER_fd_src_discof_restore_utils_fd_snapshot_reader_h

#include "../../../util/fd_util_base.h"
#include "../../../util/bits/fd_bits.h"
#include "fd_snapshot_reader_metrics.h"
#include "fd_snapshot_httpdl.h"
#include "fd_snapshot_istream.h"
#include "fd_snapshot_archive.h"
#include "fd_snapshot_peer.h"

/* fd_snapshot_reader reads both full and incremental
   snapshots from either a file or http source, using
   fd_snapshot_istream_obj_t virtual dispatch objects to abstract away
   the snapshot source. */
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
fd_snapshot_reader_new( void *                                    mem,
                        int                                       should_download_full,
                        int                                       should_download_incremental,
                        char                                      snapshot_archive_path[ PATH_MAX ],
                        fd_snapshot_peers_manager_t *             peers_manager,
                        fd_snapshot_archive_entry_t *             full_snapshot_entry,
                        fd_incremental_snapshot_archive_entry_t * incremental_snapshot_entry,
                        int                                       incremental_snapshot_fetch,
                        ulong                                     minimum_download_speed_mib );

/* fd_snapshot_reader_read is an entrypoint to receive bytes of a
   snapshot into the specified dst buffer.  Returns a
   fd_snapshot_reader_metrics_t struct that contains reader's
   status, result of the read call, and metrics. */
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

/* fd_snapshot_reader_set_source_incremental sets the snapshot reader's
   source to the incremental snapshot. */
static inline void
fd_snapshot_reader_set_source_incremental( fd_snapshot_reader_t * self ) {
  FD_TEST( self->full_src.this );

  /* There can be only be three different snapshot source configurations:
     - Both full and incremental snapshot files exist on disk locally
     - A valid local full snapshot file exists but no local incremental snapshot file exists
     - Both the full and incremental snapshots must be downloaded */
  if( self->full_src.src_type == SRC_FILE ) {
    /* If the full snapshot was read from disk,
       set the source to the incremental snapshot source, which could be
       a file or from http */
    FD_TEST( self->incremental_src.this );
    self->vsrc = &self->incremental_src;
  } else if( self->full_src.src_type == SRC_HTTP ) {
    /* If the full snapshot was downloaded via http, then the incremental
       snapshot must also be downloaded via http, so there is no need to
       switch sources */
    fd_snapshot_httpdl_set_source_incremental( self->http );
  }
}

static inline int
fd_snapshot_reader_get_source_type( fd_snapshot_reader_t * self ) {
  return self->vsrc->src_type;
}

static inline void
fd_snapshot_reader_delete( fd_snapshot_reader_t * self ) {
  if( self->full_snapshot_file ) {
    fd_snapshot_file_delete( self->full_snapshot_file );
  }

  if( self->incremental_snapshot_file ) {
    fd_snapshot_file_delete( self->incremental_snapshot_file );
  }

  if( self->http ) {
    fd_snapshot_httpdl_delete( self->http );
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapshot_reader_h */
