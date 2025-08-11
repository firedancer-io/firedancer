#ifndef HEADER_fd_src_disco_net_fd_net_router_h
#define HEADER_fd_src_disco_net_fd_net_router_h

/* fd_net_router.h provides an internal API for userland routing. */

#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/neigh/fd_neigh4_map.h"

#include <linux/if_arp.h>

struct fd_net_router {
  /* Route and neighbor tables */
  fd_fib4_t const *    fib_local;
  fd_fib4_t const *    fib_main;
  fd_neigh4_hmap_t     neigh4[1];
  fd_netdev_tbl_join_t netdev_tbl;

  uint if_idx;
  uint bind_address;
  uint default_address;
};

typedef struct fd_net_router fd_net_router_t;

struct fd_net_next_hop {
  uchar mac_addrs[12]; /* First 12 bytes of Ethernet header */
  uint  src_ip;

  uint  gre_src_ip;
  uint  gre_dst_ip;
};

typedef struct fd_net_next_hop fd_next_hop_t;

/* FD_NET_HOP_* give the result types of a route lookup. */

#define FD_NET_HOP_RAW      0
#define FD_NET_HOP_GRE      1
#define FD_NET_HOP_FALLBACK 2

/* fd_net_tx_route routes an outgoing packet based on its destination IP
   address.  Returns an action FD_NET_HOP_*.

   Saves out routing instructions to net_ctx->tx_op, including:
   - XSK index
   - source IP address
   - source and dest MAC addresses
   - GRE tunnelling info */

static FD_FN_UNUSED uint
fd_net_tx_route( fd_net_router_t const * router,
                 fd_next_hop_t *     out,
                 uint                    dst_ip ) {
  /* Route lookup */

  fd_fib4_hop_t hop[2] = {0};
  fd_fib4_lookup( router->fib_local, hop+0, dst_ip, 0UL );
  fd_fib4_lookup( router->fib_main,  hop+1, dst_ip, 0UL );
  fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );

  uint rtype   = next_hop->rtype;
  uint if_idx  = next_hop->if_idx;
  uint ip4_src = next_hop->ip4_src;

  if( FD_UNLIKELY( rtype!=FD_FIB4_RTYPE_UNICAST           ) ) return FD_NET_HOP_FALLBACK;
  if( FD_UNLIKELY( if_idx>router->netdev_tbl.hdr->dev_cnt ) ) return FD_NET_HOP_FALLBACK;
  fd_netdev_t const * netdev = &router->netdev_tbl.dev_tbl[ if_idx ];

  ip4_src = fd_uint_if( !!router->bind_address, router->bind_address, ip4_src );
  out->src_ip = ip4_src;

  if( netdev->dev_type==ARPHRD_IPGRE ) {
    /* Packet targets a GRE tunnel */
    if( netdev->gre_src_ip ) out->gre_src_ip = netdev->gre_src_ip;
    out->gre_dst_ip = netdev->gre_dst_ip;
    return FD_NET_HOP_GRE;
  }

  if( FD_UNLIKELY( if_idx!=router->if_idx ) ) return FD_NET_HOP_FALLBACK;

  /* Neighbor resolve */
  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_hmap_query_t neigh_query[1];
  int neigh_res = fd_neigh4_hmap_query_try( router->neigh4, &neigh_ip, NULL, neigh_query, 0 );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) return FD_NET_HOP_FALLBACK;
  fd_neigh4_entry_t const * neigh = fd_neigh4_hmap_query_ele_const( neigh_query );
  if( FD_UNLIKELY( neigh->state != FD_NEIGH4_STATE_ACTIVE ) ) return FD_NET_HOP_FALLBACK;
  ip4_src = fd_uint_if( !ip4_src, router->default_address, ip4_src );
  out->src_ip = ip4_src;
  memcpy( out->mac_addrs+0, neigh->mac_addr,  6 );
  memcpy( out->mac_addrs+6, netdev->mac_addr, 6 );

  if( FD_UNLIKELY( fd_neigh4_hmap_query_test( neigh_query ) ) ) return FD_NET_HOP_FALLBACK;

  return FD_NET_HOP_RAW;
}

#endif /* HEADER_fd_src_disco_net_xdp_fd_xdp_route_h */
