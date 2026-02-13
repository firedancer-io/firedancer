#ifndef HEADER_fd_src_app_platform_fd_net_util_h
#define HEADER_fd_src_app_platform_fd_net_util_h

#include "../../util/fd_util.h"

/* fd_net_util_internet_ifindex() returns the ifindex which routes to
   the public internet at 8.8.8.8.  If multiple interfaces route there,
   the first one returned by rtnetlink is returned.

   Returns zero on success, and the ifindex is written to the provided
   pointer.  On failure, -1 is returned and errno is set appropriately,
   the value of ifindex is undefined.

   If no interface can be found that routes to 8.8.8.8, -1 is returned
   and the errno is set to ENODEV. */

int
fd_net_util_internet_ifindex( uint * ifindex );

/* fd_net_util_if_addr() attempts to get the IP address of the provided
   interface.

   Returns zero on success, and the IP address is written to the provided
   pointer.  On failure, -1 is returned and errno is set appropriately,
   the value of addr is undefined. */

int
fd_net_util_if_addr( const char * interface,
                     uint *       addr );

#endif /* HEADER_fd_src_app_platform_fd_net_util_h */
