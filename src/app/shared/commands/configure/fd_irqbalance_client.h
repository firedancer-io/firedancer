#ifndef HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h
#define HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h

/* fd_irqbalance_client.h sends commands to the irqbalance socket. */

#include "../../../../util/tile/fd_tile_private.h"

FD_PROTOTYPES_BEGIN

int
fd_irqbalance_ban_cpus_get( fd_cpuset_t * cpuset );

int
fd_irqbalance_ban_cpus_set( fd_cpuset_t const * cpuset );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_irqbalance_client_h */
