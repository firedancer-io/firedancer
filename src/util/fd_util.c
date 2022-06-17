#include "fd_util.h"

#if FD_HAS_HOSTED
#include <stdlib.h> /* For atexit */
static int fd_util_private_booted; /* 0 at program start */
#endif

void
fd_boot( int *    pargc,
         char *** pargv ) {
  fd_log_private_boot ( pargc, pargv );

# if FD_HAS_HOSTED
  if( FD_UNLIKELY( atexit( fd_halt ) ) ) FD_LOG_ERR(( "atexit failed" ));
  fd_util_private_booted = 1;
# endif
}

void
fd_halt( void ) {
# if FD_HAS_HOSTED
  if( FD_UNLIKELY( !fd_util_private_booted ) ) return;
  fd_util_private_booted = 0;
# endif

  fd_log_private_halt ();
}

