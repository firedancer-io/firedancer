#ifndef HEADER_fd_src_app_platform_fd_file_util_h
#define HEADER_fd_src_app_platform_fd_file_util_h

#include "../../util/fd_util.h"

/* Read a uint from the provided file path.  On success, returns zero
   and writes the value to the provided pointer.  On failure, -1 is
   returned and errno is set appropriately.

   If the file does not start with a single line, with a uint followed
   by EOF or a newline character, it is an error and the errno will
   be ERANGE. */

int
fd_file_util_read_ulong( char const * path,
                         ulong *      value );

int
fd_file_util_read_uint( char const * path,
                        uint *       value );

/* Write a uint to the provided file path.  On success, returns zero.
   On failure, -1 is returned and errno is set appropriately.  */

int
fd_file_util_write_ulong( char const * path,
                          ulong        value );

static inline int
fd_file_util_write_uint( char const * path,
                         uint         value ) {
  return fd_file_util_write_ulong( path, value );
}

/* fd_file_util_mkdir_all() recursively creates directories such that
   the full path provided can exist.  Directories that already exist are
   left as they are, and new directories that are created will be owned
   by the given uid and gid and have mode 0700 (rwx for the owner only).

   On success, returns zero.  On failure, returns -1 and errno is set
   appropriately.  Reasons for failure include all of the reasons from
   mkdir(2), chown(2) and chmod(2).

   On failure, it is possible for a partial directory structure to have
   been created, and this will not be cleaned up.  A directory might
   have been created, but failed to be chown() or chmod() in which case
   it will be left with a different owner. */

int
fd_file_util_mkdir_all( const char * path,
                        uint         uid,
                        uint         gid,
                        int          is_dir );

/* fd_file_util_rmtree() recursively removes all the contents of a
   directory, and then (if remove_root is non-zero) also removes the
   directory itself.  If remove_root is zero, the directory is left
   empty but not removed.

   On success, returns zero.  On failure, returns -1 and errno is set
   appropriately.

   On failure, the directory may be in any state, with some files and
   directories being deleted, and some not. */

int
fd_file_util_rmtree( char const * path,
                     int          remove_root );

/* fd_file_util_self_exe() retrieves the full path of the current
   executable into the path provided.  Path should be a buffer with at
   least PATH_MAX elements.

   On success, the path is written to the provided buffer and zero is
   returned.  On failure, -1 is returned and errno is set appropriately. */

int
fd_file_util_self_exe( char path[ PATH_MAX ] );

/* fd_file_util_read_all() reads all the file contents from the provided
   path into a newly `mmap(2)`ed region.  Returns MAP_FAILED on failure.
   The caller is responsible for unmapping the region when done.
   On success, out_sz will be set to the file size.  Otherwise, the
   value of out_sz is undefined. */

char *
fd_file_util_read_all( char const * path,
                       ulong *      out_sz );

#endif /* HEADER_fd_src_app_platform_fd_file_util_h */
