#ifndef HEADER_fd_src_app_platform_fd_sys_util_h
#define HEADER_fd_src_app_platform_fd_sys_util_h

#include "../../util/fd_util.h"

/* fd_sys_util_exit_group() exits the calling process immediately with
   the provided exit code.  This function does not return.

   This function is a wrapper around the exit_group(2) system call, and
   in particular it bypasses the normal exit handlers and atexit(3) junk
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

/* fd_sys_util_modprobe() runs modprobe for module_name.  A dry run does
   everything except actually load the module, and is used to test whether
   the module will load correctly (main reason it would not load is the
   module is not installed on the system).  Returns zero on success and -1
   on failure. */
int
fd_sys_util_modprobe( char const * module_name,
                      int          is_dry_run );

/* fd_sys_util_username() returns the best guess at the currently logged
   in user.  This is not necessarily the same as the user running the
   process.  The function returns NULL on failure, or the (probable)
   logged in user on success.  The returned string has static lifetime. */

char const *
fd_sys_util_login_user( void );

int
fd_sys_util_user_to_uid( char const * user,
                         uint *       uid,
                         uint *       gid );

#endif /* HEADER_fd_src_app_platform_fd_sys_util_h */
