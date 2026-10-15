#ifndef HEADER_fd_src_discof_backup_fd_strmk_tile_h
#define HEADER_fd_src_discof_backup_fd_strmk_tile_h

/* fd_strmk_tile.h specifies the fast boot stream files.  The strmk tile
   writes them and the snapsv tile serves them over HTTP. */

#include "fd_backup.h"

/* The fast boot stream files are a small pool like the snapshot
   pool.  One stream is written at a time; at each incremental
   snapshot the current file is ended and the next one is started in
   the other file.  The file just ended stays as it is until then,
   so the file server has long stopped serving it when it is
   rewritten. */

#define FD_STRMK_POOL (2UL)

/* Well known fast boot stream file descriptors

   run.c opens the pool before the tiles start, like the snapshot pool:
   FD_STRMK_FD( i ) is the read-write handle the stream maker writes
   through and FD_STRMK_RO_FD( i ) the read-only handle the file server
   serves from. */

#define FD_STRMK_FD_BASE (210000)
#define FD_STRMK_FD(    i ) (FD_STRMK_FD_BASE                   +(int)(i))
#define FD_STRMK_RO_FD( i ) (FD_STRMK_FD_BASE+(int)FD_STRMK_POOL+(int)(i))

/* Messages from the stream maker to the file server: a fast boot stream
   file is ready to serve, or is no longer served.  idx is the pool
   file, slot the slot the stream starts at, and hash the hash of the
   bank at that slot, which names the stream to a peer. */

#define FD_STRMK_MSG_OPEN  (1UL)
#define FD_STRMK_MSG_CLOSE (2UL)

struct fd_strmk_msg {
  ulong slot;
  uint  idx;
  uchar hash[ 32 ];
};

typedef struct fd_strmk_msg fd_strmk_msg_t;

FD_PROTOTYPES_BEGIN

/* fd_strmk_stream_name formats the on-disk name of pool file idx. */

FD_FN_UNUSED static char *
fd_strmk_stream_name( char name[ static FD_SNAP_NAME_MAX ],
                      ulong idx ) {
  FD_TEST( fd_cstr_printf_check( name, FD_SNAP_NAME_MAX, NULL, "fast-boot-stream-%lu.tar.zst", idx ) );
  return name;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_strmk_tile_h */
