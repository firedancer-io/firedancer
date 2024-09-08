#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_loader_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_loader_h

/* fd_snapshot_loader.h provides APIs for constructing the upstream
   parts of the snapshot loading pipeline.

    read => unzstd => untar => restore
    ^^^^^^^^^^^^^^^^^^^^^^^

   This header provides high-level APIs for streaming loading of a
   snapshot from the local file system or over HTTP (regular sockets).
   The loader is currently a single-threaded streaming pipeline.  This
   is subject to change to the tile architecture in the future. */

#include "../snapshot/fd_snapshot.h"
#include "../snapshot/fd_snapshot_restore.h"

/* fd_snapshot_loader_t manages file descriptors and buffers used during
   snapshot load. */

struct fd_snapshot_loader;
typedef struct fd_snapshot_loader fd_snapshot_loader_t;

/* FD_SNAPSHOT_SRC_{...} specifies the type of snapshot source. */

#define FD_SNAPSHOT_SRC_FILE    (1)
#define FD_SNAPSHOT_SRC_HTTP    (2)
#define FD_SNAPSHOT_SRC_ARCHIVE (3)

/* fd_snapshot_src_t specifies the snapshot source. */

struct fd_snapshot_src {
  int type;
  union {

    struct {
      char const * path;
    } file;

    struct {
      char         dest[128];
      uint         ip4;
      ushort       port;
      char const * path;
      ulong        path_len;
    } http;

  };
};

typedef struct fd_snapshot_src fd_snapshot_src_t;

FD_PROTOTYPES_BEGIN

/* Constructor API for fd_snapshot_loader_t. */

ulong
fd_snapshot_loader_align( void );

ulong
fd_snapshot_loader_footprint( ulong zstd_window_sz );

fd_snapshot_loader_t *
fd_snapshot_loader_new( void * mem,
                        ulong  zstd_window_sz );

void *
fd_snapshot_loader_delete( fd_snapshot_loader_t * loader );

/* fd_snapshot_loader methods *****************************************/

/* fd_snapshot_loader_init configures a local join to the loader object
   to send data into the given restore object.  src describes the source
   of the snapshot (file system or HTTPS path). */

fd_snapshot_loader_t *
fd_snapshot_loader_init( fd_snapshot_loader_t *    loader,
                         fd_snapshot_restore_t *   restore,
                         fd_snapshot_src_t const * src,
                         ulong                     base_slot );

/* fd_snapshot_loader_advance polls the tar reader for data.  This data
   is synchronously passed down the pipeline (ending in a manifest
   callback and new funk record insertions).  This is the primary
   polling entrypoint into fd_snapshot_loader_t.  Returns 0 if advance
   was successful.  Returns -1 on successful EOF.  On failure, returns
   errno-compatible code and logs error. */

int
fd_snapshot_loader_advance( fd_snapshot_loader_t * loader );

FD_FN_CONST fd_snapshot_name_t const *  /* nullable */
fd_snapshot_loader_get_name( fd_snapshot_loader_t const * loader );

/* fd_snapshot_src_parse determines the snapshot source from the given
   cstr. */

fd_snapshot_src_t *
fd_snapshot_src_parse( fd_snapshot_src_t * src,
                       char *              cstr );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_loader_h */
