#ifndef HEADER_fd_src_waltz_mib_fd_netdev_netlink_h
#define HEADER_fd_src_waltz_mib_fd_netdev_netlink_h

/* fd_netdev_netlink.h provides APIs for importing network interfaces from
   Linux netlink. */

#if defined(__linux__)

#include "fd_netdev_tbl.h"
#include "../ip/fd_netlink1.h"

FD_PROTOTYPES_BEGIN

int
fd_netdev_netlink_load_table( fd_netdev_tbl_join_t * tbl,
                              fd_netlink_t *         netlink );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_mib_fd_netdev_netlink_h */
