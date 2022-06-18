#include "fd_util.h"

void
fd_boot( int *    pargc,
         char *** pargv ) {
  /* At this point, we are immediately after the program start, there is
     only one thread of execution and fd has not yet been booted. */
  fd_log_private_boot( pargc, pargv );
}

void
fd_halt( void ) {
  /* At this point, we are immediately before normal program
     termination, and fd has already been booted. */
  fd_log_private_halt();
}

