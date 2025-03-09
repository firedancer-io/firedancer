#ifndef HEADER_fd_src_app_shared_fd_sys_util_h
#define HEADER_fd_src_app_shared_fd_sys_util_h

#include "../../util/fd_util.h"

/* fd_sys_util_exit_group() exits the calling process immediately with
   the provided exit code.  This function does not return.

   This function is a wrapper around the exit_group(2) system call, and
   in paticular it bypasses the normal exit handlers and atexit(3) junk
   which gets installed by the C runtime. */

void
fd_sys_util_exit_group( int code );

/* fd_sys_util_nanosleep() sleeps the calling thread for the provided
   number of nanoseconds, ensuring it continues to sleep if it is
   interrupted.

   On success, the function returns zero.  On failure, the function
   returns -1 and errno is set appropriately. */

int
fd_sys_util_nanosleep( uint secs,
                       uint nanos );

#endif /* HEADER_fd_src_app_shared_fd_sys_util_h */
