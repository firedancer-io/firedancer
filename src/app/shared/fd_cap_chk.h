#ifndef HEADER_fd_src_app_shared_fd_cap_chk_h
#define HEADER_fd_src_app_shared_fd_cap_chk_h

#include "../../util/fd_util_base.h"

/* A fd_cap_chk provides mechanisms to check what capabilities or
   permissions are available to the caller, and if they are missing,
   accumulates error information to be reported later.

   A typical caller will repeatedly call check_* functions for all
   the required capabilities, and then after that, if there are errors,
   it could exit or print them to a user.

   Functions in the capability checker do not return errors and do not
   silently fail.  If there is any environment issue which prevents the
   correct information being retrieved, the program will log an error
   and terminate immediately. */

struct fd_cap_chk_private;
typedef struct fd_cap_chk_private fd_cap_chk_t;

#define FD_CAP_CHK_ALIGN     (8UL)
#define FD_CAP_CHK_FOOTPRINT (4104UL)

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_cap_chk_align( void ) {
   return FD_CAP_CHK_ALIGN;
}

FD_FN_CONST static inline ulong
fd_cap_chk_footprint( void ) {
   return FD_CAP_CHK_FOOTPRINT;
}

void *
fd_cap_chk_new( void * shmem );

fd_cap_chk_t *
fd_cap_chk_join( void * shchk );

/* fd_cap_chk_root() checks if the current process is running as the
   root user (with uid 0).  If it's not, an entry is accumulated with
   an appropriate reason indicating this.

   name and reason are strings which are used to format the diagnostic
   error missage, in case the caller is not running as the root user. */

void
fd_cap_chk_root( fd_cap_chk_t * chk,
                 char const *   name,
                 char const *   reason );

/* fd_cap_chk_cap() checks if the current process is running with the
   given Linux capability.  If it's not, an entry is accumulated with an
   appropriate reason indicating this.

   name and reason are strings which are used to format the diagnostic
   error missage, in case the caller is not running as the root user. */

void
fd_cap_chk_cap( fd_cap_chk_t * chk,
                char const *   name,
                uint           capability,
                char const *   reason );

/* fd_cap_chk_raise_rlimit() checks if the current process is running
   with the provided resource, a RLIMIT_* constant, at or above the
   desired limit.

   If it is not, but the limit can be raised to the required level
   because the user is root or has the CAP_SYS_RESOURCE capability, then
   the limit will be increased within this function and the check will
   still succeed, no error entry will be accumulated.  Only if the
   calling process does not have the resource limit desired, and cannot
   increase it to get there, an error entry will be accumulated.

   If the resource is RLIMIT_NICE, the check will also succeed if the
   process has the CAP_SYS_NICE capability, and it successfully
   increases the NICE value on its own.

   name and reason are strings which are used to format the diagnostic
   error missage, in case the caller is not running as the root user. */

void
fd_cap_chk_raise_rlimit( fd_cap_chk_t *  chk,
                         char const *    name,
                         int             resource,
                         ulong           limit,
                         char const *    reason );

/* fd_cap_chk_err_cnt() returns the number of error entries accumulated
   in the capability checker. */

ulong
fd_cap_chk_err_cnt( fd_cap_chk_t const * chk );

/* fd_cap_chk_err() returns the error message at the given index.  The
   index must be less than the number of errors returned by
   fd_cap_chk_err_cnt(). */

char const *
fd_cap_chk_err( fd_cap_chk_t const * chk,
                ulong                idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_fd_cap_chk_h */
