#if defined(__linux__)
#include "fd_util_linux.c"
#endif

#include "fd_util.h"

void
fd_boot( int *    pargc,
         char *** pargv ) {
  /* At this point, we are immediately after the program start, there is
     only one thread of execution and fd has not yet been booted. */
  fd_log_private_boot  ( pargc, pargv );
# if defined(__linux__)
  fd_linux_private_boot( pargc, pargv );
# endif
  fd_shmem_private_boot( pargc, pargv );
  fd_tile_private_boot ( pargc, pargv ); /* The caller is now tile 0 */
}

void
fd_boot_secure1( int *    pargc,
                 char *** pargv ) {
  // 1. Initialize logging and some shared memory information. This
  //    is done first because it requires opening /dev/null, the log
  //    file, and some /proc/... info which will not be present after
  //    the privileged step of sandboxing
  //
  //    It's also needed because the caller process might want to
  //    initialize some privileged resources with code that does
  //    logging, or needs information from the shared memory domain.
  fd_log_private_boot          ( pargc, pargv );
  fd_shmem_private_boot        ( pargc, pargv );
}

void
fd_boot_secure2( int *    pargc,
                 char *** pargv ) {
  // 2. Do any sandboxing operations which require capabilities. This
  //    enters a mount namespace and makes the filesystem unavailable.
  //    When this returns the caller is in a new usernamespace and
  //    has no capabilities.
  fd_sandbox_private_privileged        ( pargc, pargv );

  // 3. Boot the tiles. Must be done after dropping capabilities so
  //    tiles start without any.
  fd_tile_private_boot                 ( pargc, pargv ); /* The caller is now tile 0 */

  // 4. Enter sandbox and restrict all system calls
  fd_sandbox_private                   ( pargc, pargv );
}

void
fd_halt( void ) {
  /* At this point, we are immediately before normal program
     termination, and fd has already been booted. */
  fd_tile_private_halt ();
  fd_shmem_private_halt();
  fd_log_private_halt  ();
}

#if FD_HAS_HOSTED

#include <sched.h>

void fd_yield( void ) { sched_yield(); }

#endif

