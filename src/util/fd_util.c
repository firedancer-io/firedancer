#if defined(__linux__)
#include "fd_util_linux.c"
#endif

#include "fd_util.h"

#if FD_HAS_LIBBPF
#include "fd_util_libbpf.c"
#endif

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
# if FD_HAS_LIBBPF
  fd_libbpf_boot();
# endif
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

