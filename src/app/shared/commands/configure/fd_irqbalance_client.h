#ifndef HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h
#define HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h

/* fd_irqbalance_client.h sends commands to the irqbalance socket.

   Both functions return 0 on success.  They return -1 only for the
   expected condition that the irqbalance daemon cannot be reached, with
   errno set to one of:

     ENOENT       irqbalance is not installed / no socket present
     ECONNREFUSED irqbalance is not running (stale socket)
     EACCES       insufficient permissions to connect to the socket

   Any other failure (I/O error on a connected socket, a malformed
   daemon response, resource exhaustion, etc.) is unexpected and fatal. */

#include "../../../../util/tile/fd_tile_private.h"

FD_PROTOTYPES_BEGIN

int
fd_irqbalance_ban_cpus_get( fd_cpuset_t * cpuset );

int
fd_irqbalance_ban_cpus_set( fd_cpuset_t const * cpuset );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h */
