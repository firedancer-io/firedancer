#ifndef HEADER_fd_src_waltz_neigh_fd_neigh4_netlink_h
#define HEADER_fd_src_waltz_neigh_fd_neigh4_netlink_h

/* fd_neigh4_netlink.h provides APIs for importing IPv4 neighbors from
   Linux netlink.  Assumes link-layer addresses are 6 bytes long. */

#if defined(__linux__)

#include "fd_neigh4_map.h"
#include "../ip/fd_netlink1.h"

struct nlmsghdr; /* forward declaration */

/* FD_NEIGH_NETLINK_* gives error codes for netlink import operations. */

FD_PROTOTYPES_BEGIN

/* fd_neigh4_netlink_request_dump requests a dump of the IPv4 neighbor
   table for the given interface index.  The kernel typically responds with
   multi-part messages.  Uses sendto(2) syscall.  Returns 0 on success and
   errno on failure. */

int
fd_neigh4_netlink_request_dump( fd_netlink_t * netlink,
                                uint           if_idx );

/* fd_neigh4_netlink_ingest_message imports an RTM_NEWNEIGH or RTM_DELNEIGH
   message.  Logs warning if a netlink message with a different type is
   inserted.  Logs warning if link-layer addresses is not 6 bytes long.
   (The caller is expected to verify that if_idx is an Ethernet interface.)
   Ignores messages with an interface index other than if_idx.  Causes
   insert, update, or remove of a neighbor table entry.   Only respects
   IPv4 neighbor entries.  Silently ignores IPv6 neighbor entries. */

void
fd_neigh4_netlink_ingest_message( fd_neigh4_hmap_t *      map,
                                  struct nlmsghdr const * msg,
                                  uint                    if_idx );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_neigh_fd_neigh4_netlink_h */
