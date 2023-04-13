#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_util_private_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_util_private_h

#include "fd_sandbox.h"

FD_PROTOTYPES_BEGIN

/* fd_sandbox_tile_boot_hook gets executed by every new tile on boot. */
void fd_sandbox_tile_boot_hook( void );

/* fd_sandbox_fd_boot_secure_called_hook is called by fd_boot_secure as
   a check that the call sequence is the one expected. */
void fd_sandbox_proc_boot_hook( int * pargc, char *** pargv );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_util_private_h */
