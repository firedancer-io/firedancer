#include "fd_sandbox_util_private.h"
#include "../log/fd_log.h"


void
fd_sandbox_proc_boot_hook( int *    pargc,
                           char *** pargv ) {
  char const * unsafe_notice = fd_env_strip_cmdline_cstr(
    pargc, pargv,
    "unsafe-no-sandboxing-available", "FD_SANDBOX_UNSUPPORTED",
    NULL
    );

  if ( FD_UNLIKELY( !unsafe_notice || strcmp( unsafe_notice, "1" ) ) ) {
    FD_LOG_ERR(( "sandbox unavailable on this current target - look around where this line was emitted if you need to override" ));
  }
  return;
}

void
fd_sandbox_tile_boot_hook( void ) {
  return;
}


/* fd_sandbox */
void
fd_sandbox( int *    pargc,
            char *** pargv ) {
  (void) pargc;
  (void) pargv;
  return;
}

void
fd_sandbox_set_max_open_files( uint max ) {}

/* fd_sandbox_set_highest_fd_to_keep sets the highest fd to keep when entering the sandbox. */
void
fd_sandbox_set_highest_fd_to_keep( int max ) {}
