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

/* fd_netlink_neigh4_solicit_link_t holds information required to send
   neighbor solicitation requests to the netlink tile. */

struct fd_netlink_neigh4_solicit_link {
  fd_frag_meta_t * mcache;
  ulong            depth;
  ulong            seq;
};

typedef struct fd_netlink_neigh4_solicit_link fd_netlink_neigh4_solicit_link_t;

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

/* fd_netlink_neigh4_solicit requests a neighbor solicitation (i.e. ARP
   request) for an IPv4 address.  Safe to call at a high rate.  The
   netlink tile will deduplicate requests.  ip4_addr is big endian. */

static inline void
fd_netlink_neigh4_solicit( fd_netlink_neigh4_solicit_link_t * link,
                           uint                               ip4_addr,
                           uint                               if_idx,
                           ulong                              tspub_comp ) {
  ulong seq = link->seq;
  ulong sig = (ulong)ip4_addr | ( (ulong)if_idx<<32 );
  fd_mcache_publish( link->mcache, link->depth, seq, sig, 0UL, 0UL, 0UL, 0UL, tspub_comp );
  link->seq = fd_seq_inc( seq, 1UL );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_netlink_fd_netlink_tile_h */
