#include "fd_util.h"
#include "tile/fd_tile.h"

void
fd_boot( int *    pargc,
         char *** pargv ) {

  /* Parse command line option/env variable for using normal size pages (4k) if present,
     and set a global variable accordingly. */
  char const *use_normal_pages = fd_env_strip_cmdline_cstr(pargc, pargv, "--use-normal-pages", "FD_USE_NORMAL_PAGES", NULL);
  if ( FD_LIKELY( use_normal_pages ) ) using_normal_pages = 1;

  /* At this point, we are immediately after the program start, there is
     only one thread of execution and fd has not yet been booted. */
  fd_log_private_boot  ( pargc, pargv );
  fd_shmem_private_boot( pargc, pargv );
  fd_tile_private_boot ( pargc, pargv ); /* The caller is now tile 0 */
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

