#ifndef HEADER_fd_src_disco_netlink_fd_netlink_tile_h
#define HEADER_fd_src_disco_netlink_fd_netlink_tile_h

/* fd_netlink_tile.h provides APIs for working with the netlink tile. */

#include "../topo/fd_topo.h"

/* Hardcoded limits */
#define NETDEV_MAX      (256U)
#define BOND_MASTER_MAX (256U)

/* fd_tile_netlnk provides the netlink tile.

   Consult /book/guide/netlink.md for more information.
   Web mirror: https://docs.firedancer.io/guide/netlink.html */

extern fd_topo_run_tile_t fd_tile_netlnk;

struct fdctl_config;

FD_PROTOTYPES_BEGIN

void
fd_netlink_topo_create( fd_topo_tile_t * netlink_tile,
                        fd_topo_t *      topo,
                        ulong            netlnk_max_routes,
                        ulong            netlnk_max_peer_routes,
                        ulong            netlnk_max_neighbors,
                        char const *     bind_interface );

void
fd_netlink_topo_join( fd_topo_t *      topo,
                      fd_topo_tile_t * netlink_tile,
                      fd_topo_tile_t * join_tile );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_netlink_fd_netlink_tile_h */
