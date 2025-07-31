#define _GNU_SOURCE
#include "fd_util.h"

void
fd_boot( int *    pargc,
         char *** pargv ) {
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

long
_fd_tickcount( void const * _ ) {
  (void)_;
  return fd_tickcount();
}

#if FD_HAS_HOSTED

#include <poll.h>
#include <sched.h>
#include <time.h>

void fd_yield( void ) { sched_yield(); }

int
fd_syscall_poll( struct pollfd * fds,
                 uint            nfds,
                 int             timeout ) {
#if defined(__linux__)
  if( timeout<0 ) {
    return ppoll( fds, nfds, NULL, NULL );
  } else {
    struct timespec ts = {
      .tv_sec  = (long)( timeout/1000 ),
      .tv_nsec = (long)((timeout%1000)*1000000),
    };
    return ppoll( fds, nfds, &ts, NULL );
  }
#else
  return poll( fds, nfds, timeout );
#endif
}

#endif
