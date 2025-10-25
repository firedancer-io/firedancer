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

/* fd_net_util_netns_enter() attempts to enter the calling process into
   the network namespace with the provided name.

   Returns zero on success, and the process is now inside the network
   namespace.  On failure, -1 is returned and errno is set appropriately.

   If the original_netns is not NULL, on both success and failure, the
   original network namespace might be written to the provided pointer.
   This file descriptor should be closed by the caller when it is no
   longer needed.  The original network namespace can be re-entered by
   calling setns(2) with this original file descriptor.  The original
   network namespace might be set even if the function returns an error.

   On failure, the process might still have successfully entered the
   network namespace.  This can happen if, for example, the process
   entered successfully, but failed to close a lingering file descriptor
   afterwards.  The caller should not assume any valid state on failure
   and likely needs to abort. */

int
fd_net_util_netns_enter( const char * name,
                         int *        original_netns );

/* fd_net_util_netns_restore() attempts to restore the calling process
   to the original network namespace.

   Returns zero on success, and the process is now inside the original
   network namespace.  On failure, -1 is returned and errno is set
   appropriately.

   The original_fd is the file descriptor to the original network
   namespace, which was obtained from fd_net_util_netns_enter().  This
   file descriptor is closed by the function when it succeeds, and does
   not need to be closed by the caller.

   On failure, the process might still have successfully entered the
   original network namespace.  This can happen if, for example, the
   process entered successfully, but failed to close a lingering file
   descriptor afterwards.  The caller should not assume any valid state
   on failure and likely needs to abort. */

int
fd_net_util_netns_restore( int original_fd );

/* fd_net_util_if_addr() attempts to get the IP address of the provided
   interface.

   Returns zero on success, and the IP address is written to the provided
   pointer.  On failure, -1 is returned and errno is set appropriately,
   the value of addr is undefined. */

int
fd_net_util_if_addr( const char * interface,
                     uint *       addr );

#endif /* HEADER_fd_src_app_platform_fd_net_util_h */
