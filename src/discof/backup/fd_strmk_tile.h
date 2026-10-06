#ifndef HEADER_fd_src_discof_backup_fd_strmk_tile_h
#define HEADER_fd_src_discof_backup_fd_strmk_tile_h

/* fd_strmk_tile.h specifies the boot stream files.  The strmk tile
   writes them and the snapsv tile serves them over HTTP. */

#include "fd_backup.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Well known boot stream file descriptors

   Firedancer's sandbox bans opening files, so the stream tile and the
   file server both open the boot files before they enter the sandbox,
   at the same descriptor numbers.  Stream i is FD_STRMK_FD( i ) and
   the index follows the streams. */

#define FD_STRMK_FD_BASE (210000)
#define FD_STRMK_FD( i ) (FD_STRMK_FD_BASE+(int)(i))

/* FD_STRMK_STREAM_MAX bounds
   [snapshots.instant_boot.serve.max_open_streams]. */

#define FD_STRMK_STREAM_MAX (8UL)

/* FD_STRMK_JOIN_MIN_SECONDS is how much of a stream's lifetime a
   booting peer insists on having left before it joins, so a stream
   served for less than that is of no use to anyone. */

#define FD_STRMK_JOIN_MIN_SECONDS (180UL)

/* The boot files live in their own directory below the snapshots
   directory. */

#define FD_STRMK_DIR   "boot"
#define FD_STRMK_INDEX "boot-index"

FD_PROTOTYPES_BEGIN

/* Formats the file name of the stream at pool index idx. */

FD_FN_UNUSED static char *
fd_strmk_stream_name( char name[ static FD_SNAP_NAME_MAX ],
                      uint idx ) {
  FD_TEST( fd_cstr_printf_check( name, FD_SNAP_NAME_MAX, NULL, "boot-stream-partial-%u.tar.zst", idx ) );
  return name;
}

/* Returns a descriptor for the directory that holds the boot files,
   creating the directory if it is missing. */

FD_FN_UNUSED static int
fd_strmk_dir_open( char const * path ) {
  if( FD_UNLIKELY( -1==mkdir( path, S_IRWXU ) && errno!=EEXIST ) ) {
    FD_LOG_ERR(( "mkdir(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  int dir_fd = open( path, O_RDONLY|O_DIRECTORY );
  if( FD_UNLIKELY( -1==dir_fd ) ) {
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  return dir_fd;
}

/* Opens a boot file at its well known descriptor, creating the file if
   it is missing.  flags is O_RDWR for the stream tile and O_RDONLY for
   the file server, which may start before the stream tile. */

FD_FN_UNUSED static void
fd_strmk_file_open( int          dir_fd,
                    char const * dir_path,
                    char const * name,
                    int          flags,
                    int          fd ) {
  int file_fd = openat( dir_fd, name, flags|O_CREAT|O_NOFOLLOW, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( -1==file_fd ) ) {
    FD_LOG_ERR(( "openat(%s/%s) failed (%i-%s)", dir_path, name, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==dup2( file_fd, fd ) ) ) {
    FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==close( file_fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_strmk_tile_h */
