#ifndef HEADER_fd_src_app_shared_fd_file_util_h
#define HEADER_fd_src_app_shared_fd_file_util_h

#include "../../util/fd_util.h"

/* Read a uint from the provided path.  On success, returns zero and
   writes the value to the provided pointer.  On failure, -1 is returned
   and errno is set appropriately.  */

int
fd_file_util_read_uint( char const * path,
                        uint *       value );

#endif /* HEADER_fd_src_app_shared_fd_file_util_h */
