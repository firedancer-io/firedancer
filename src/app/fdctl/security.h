#ifndef HEADER_fd_src_app_fdctl_security_h
#define HEADER_fd_src_app_fdctl_security_h

/* The security helpers can determine whether the program has the
   capabilities it needs to operate. The expected usage is that a caller
   will initialize an empty security context, and then repeatedly call
   `check_*` functions on it which will insert an error entry into the
   context if the required permission is not held. Once all permission
   checks are performed, the program can print a helpful diagnostic.

   These functions do not silently fail, and any issue retrieving
   security information will cause the program to log an error and exit.
   */
#include "fdctl.h"

#include <sys/resource.h>

#define MAX_SECURITY_ERRORS 16

typedef struct security {
  ulong idx;
  char  errors[ MAX_SECURITY_ERRORS ][ 256 ];
} security_t;

/* check_root() checks if the current process is running as the root
   user (uid 0). If it's not, an error entry is added to the security
   context with the given reason. */
void
check_root( security_t * security,
            const char * name,
            const char * reason );

/* check_cap() checks if the current process is running with the
   provided capability. If it's not, an error entry is added to the
   security context with the given reason. */
void
check_cap( security_t * security,
           const char * name,
           uint         cap,
           const char * reason );

/* check_res() checks if the current process is running with the
   provided resource at or above the desired limit, or if it can
   increase the resource itself (which it will do). If it cannot, an
   error entry is added to the security context with the given reason. */
void
check_res( security_t *        security,
           const char *        name,
           __rlimit_resource_t resource,
           ulong               limit,
           const char *        reason );

#endif /* HEADER_fd_src_app_fdctl_security_h */
