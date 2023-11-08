#ifndef HEADER_fd_src_app_fdctl_caps_h
#define HEADER_fd_src_app_fdctl_caps_h

#include "fdctl.h"

/* API for checking capabilities, and accumulating information about
   what capabilities or permissions are missing that are required to run
   a particular binary or command.  The expected usage is that a caller
   will initialize an empty caps context, and then repeatedly call
   `check_*` functions on it which will insert an error entry into the
   context if the required permission is not held.  Once all permission
   checks are performed, the program can print a helpful diagnostic.

   These functions do not silently fail, and any issue retrieving
   capability information will cause the program to log an error and
   exit. */

#include <sys/resource.h>

#define MAX_ERROR_MSG_LEN 256UL
#define MAX_ERROR_ENTRIES 16UL

struct fd_caps_ctx {
  ulong err_cnt;
  char  err[ MAX_ERROR_ENTRIES ][ MAX_ERROR_MSG_LEN ];
};
typedef struct fd_caps_ctx fd_caps_ctx_t;

/* fd_rlimit_res_t is the appropriate type for RLIMIT_{...} for the
   libc flavor in use.  glibc with GNU_SOURCE redefines the type of
   the first arg to {get,set}rlimit(2), sigh ... */

#ifdef __GLIBC__
typedef __rlimit_resource_t fd_rlimit_res_t;
#else /* non-glibc */
typedef int fd_rlimit_res_t;
#endif /* __GLIBC__ */

FD_PROTOTYPES_BEGIN

/* fd_caps_check_root() checks if the current process is running as the
   root user (with uid 0).  If it's not, an entry is added to the caps
   context with the given reason indicating this.  The function does not
   fail or return an error if the user is not root, it only adds an
   error to the context.

   ctx is a capability context to add any error into.  If the context is
   full (the error cannot be added) the process will be aborted.  The
   error message added to the context will include the name and reason
   strings provided. */
void
fd_caps_check_root( fd_caps_ctx_t * ctx,
                    char const *    name,
                    char const *    reason );

/* fd_caps_check_cap() checks if the current process is running with the
   provided Linux capability.  If it's not, an error entry is added to
   the caps context with the given reason.  The function does not fail
   or return an error if the process does not have the capability, it
   only adds an error to the context.

   ctx is a capability context to add any error into.  If the context is
   full (the error cannot be added) the process will be aborted.  The
   error message added to the context will include the name and reason
   strings provided. */
void
fd_caps_check_capability( fd_caps_ctx_t * ctx,
                          char const *    name,
                          uint            capability,
                          char const *    reason ); 

/* fd_caps_check_resource() checks if the current process is running
   with the provided resource, a RLIMIT_* constant, at or above the
   desired limit.  If it is not, but the limit can be increased because
   the user is root or has the CAP_SYS_RESOURCE capability, then the
   limit will be increased within this function and the check will still
   succeed, no error entry will be generated.  Only if we do not have
   the resource limit desired, and cannot increase it to get there, an
   error entry will be added to the caps context.  If the resource is
   RLIMIT_NICE, the check will also succeed if the process has the
   CAP_SYS_NICE capability, and it successfully increases the NICE
   value on its own.

   ctx is a capability context to add any error into.  If the context is
   full (the error cannot be added) the process will be aborted.  The
   error message added to the context will include the name and reason
   strings provided. */
void
fd_caps_check_resource( fd_caps_ctx_t * ctx,
                        char const *    name,
                        fd_rlimit_res_t resource,
                        ulong           limit,
                        char const *    reason );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_fdctl_caps_h */
