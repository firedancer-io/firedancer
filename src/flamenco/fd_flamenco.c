#include "fd_flamenco_base.h"

void
fd_flamenco_boot( int *    pargc __attribute__((unused)),
                  char *** pargv __attribute__((unused)) ) {
  /* Since the removal of custom format string specifiers there is no
     technical need for boot/halt anymore.  However, if such a need arises in
     the future it is good to have the functions and calls to it in place.
     Until then these are no-ops. */
}

void
fd_flamenco_halt( void ) {}
