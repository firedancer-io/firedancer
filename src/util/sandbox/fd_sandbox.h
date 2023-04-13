#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_h

#include "../log/fd_log.h"

enum fd_sandbox_profile {
  FD_SANDBOX_PROFILE_COMMON,
  FD_SANDBOX_PROFILE_DISABLED,
};

typedef enum fd_sandbox_profile fd_sandbox_profile_t;

FD_PROTOTYPES_BEGIN

/* fd_sandbox sandboxes the current process. Since sandboxing is
   platform specific, look in fd_sandbox_{platform}.h for
   more information. Each platform should do as much as it can
   in order to match the intent of the requested profile.

   Firedancer is written in C, a memory-unsafe language. Therefore, we must
   consider controls that can be levied during firedancer’s execution as a
   primary component of risk reduction. Sandboxing aims to isolate different
   Firedancer components from each other as well as from the system.
   Although we will try to take several preventative steps to reduce the
   likelihood of memory corruption bugs in the codebase, we acknowledge that,
   even with infinite resources, the number of memory corruption bugs in
   Firedancer at any given time is non-zero and that an exploiter will in
   some future attempt to weaponize such a bug in main net.

   When starting, before executing any task code and/or processing
   user-provided input, a Firedancer process prepares everything it needs
   in order to function properly.

   Immediately after performing those operations, Firedancer must sandbox itself.

   fd_sandbox must be used in pair with `fd_boot_secure`.
*/
void
fd_sandbox( int *    pargc,
            char *** pargv );

/* fd_sandbox_set_max_open_files sets the maximum number of files that can be opened after being sandboxed. */
void
fd_sandbox_set_max_open_files( uint max );

/* fd_sandbox_set_max_fd_to_keep sets the highest fd to keep when entering the sandbox. */
void
fd_sandbox_set_highest_fd_to_keep( int max );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_h */
