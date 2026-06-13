#ifndef HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h
#define HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h

/* fd_irqbalance_client.h sends commands to the irqbalance socket. */

#include "../../../../util/tile/fd_tile_private.h"

FD_PROTOTYPES_BEGIN

char const *
fd_irqbalance_socket_path( char * path,
                           ulong  path_max );

void
fd_irqbalance_ban_cpus( fd_cpuset_t const * cpuset,
                        char const *        irqbalance_path );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h */
