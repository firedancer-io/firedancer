#ifndef HEADER_fd_src_disco_net_fd_net_router_h
#define HEADER_fd_src_disco_net_fd_net_router_h

/* fd_net_router.h provides an internal API for userland routing. */

#include "fd_net_tile_private.h"
#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../netlink/fd_netlink_tile.h" /* neigh4_solicit */
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"

#include <linux/if_arp.h> /* ARPHRD_LOOPBACK */

struct fd_net_router {
  /* Route and neighbor tables */
  fd_fib4_t fib_local[1];
  fd_fib4_t fib_main[1];
  fd_neigh4_hmap_t  neigh4[1];

  ulong netlnk_out_idx;
  uint  solicit_ip;
  uint  solicit_if_idx;

  /* Netdev table */
  fd_netdev_tbl_join_t netdev_tbl;    /* local copy in scratch */
  fd_netdev_tbl_join_t netdev_shared; /* shared seqlock-protected table */

  uint if_virt;
  uint bind_address;
  uint default_address;

  struct {
    ulong tx_neigh_fail_cnt;
  } metrics;
};
typedef struct fd_net_router fd_net_router_t;

FD_PROTOTYPES_BEGIN

/* fd_net_tx_route resolves the destination interface index, src MAC
   address, and dst MAC address.  Returns 1 on success, 0 on failure.
   On success, writes the complete route result to out. */

static int
fd_net_tx_route( fd_net_router_t *   ctx,
                 fd_net_tile_t *     net,
                 uint                dst_ip,
                 fd_net_tx_route_t * out ) {

  if( FD_UNLIKELY( !out ) ) return 0;
  *out = (fd_net_tx_route_t) {0};

  /* Route lookup */

  fd_fib4_hop_t hop[2] = {0};
  hop[0] = fd_fib4_lookup( ctx->fib_local, dst_ip, 0UL );
  hop[1] = fd_fib4_lookup( ctx->fib_main,  dst_ip, 0UL );
  fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );

  uint rtype   = next_hop->rtype;
  uint if_idx  = next_hop->if_idx;
  uint ip4_src = next_hop->ip4_src;

  if( FD_UNLIKELY( rtype==FD_FIB4_RTYPE_LOCAL ) ) {
    rtype  = FD_FIB4_RTYPE_UNICAST;
    if_idx = 1;
  }

  if( FD_UNLIKELY( rtype!=FD_FIB4_RTYPE_UNICAST ) ) {
    uint const reason = fd_uint_if( rtype==FD_FIB4_RTYPE_THROW,
                                    FD_METRICS_ENUM_ROUTE_FAIL_V_NO_ROUTE_IDX,
                                    FD_METRICS_ENUM_ROUTE_FAIL_V_ROUTE_TYPE_IDX );
    net->metrics.tx_route_fail_cnt[ reason ]++;
    return 0;
  }

  fd_netdev_t * netdev = fd_netdev_tbl_query( &ctx->netdev_tbl, if_idx );
  if( !netdev ) {
    net->metrics.tx_route_fail_cnt[ FD_METRICS_ENUM_ROUTE_FAIL_V_INTERFACE_IDX ]++;
    return 0;
  }

  ip4_src = fd_uint_if( !!ctx->bind_address, ctx->bind_address, ip4_src );
  out->mtu    = netdev->mtu;
  out->src_ip = ip4_src;
  out->if_idx = if_idx;

  if( netdev->dev_type==ARPHRD_LOOPBACK ) {
    memset( out->mac_addrs, 0, sizeof(out->mac_addrs) );
    out->src_ip       = fd_uint_if( !ip4_src, FD_IP4_ADDR( 127,0,0,1 ), ip4_src );
    out->use_loopback = 1U;
    return 1;
  } else if( netdev->dev_type==ARPHRD_IPGRE ) {
    /* skip MAC addrs lookup for GRE inner dst ip */
    out->gre_outer_src_ip = netdev->gre_src_ip;
    out->gre_outer_dst_ip = netdev->gre_dst_ip;
    out->use_gre = 1U;
    return 1;
  }

  if( FD_UNLIKELY( netdev->dev_type!=ARPHRD_ETHER ) ) {
    net->metrics.tx_route_fail_cnt[ FD_METRICS_ENUM_ROUTE_FAIL_V_UNSUPPORTED_INTERFACE_IDX ]++;
    return 0;
  }

  if( FD_UNLIKELY( if_idx!=ctx->if_virt ) ) {
    net->metrics.tx_route_fail_cnt[ FD_METRICS_ENUM_ROUTE_FAIL_V_UNSUPPORTED_INTERFACE_IDX ]++;
    return 0;
  }

  /* Neighbor resolve */
  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_entry_t neigh[1];
  int neigh_res = fd_neigh4_hmap_query_entry( ctx->neigh4, neigh_ip, neigh );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) {
    /* Neighbor not found */
    ctx->solicit_ip     = neigh_ip;
    ctx->solicit_if_idx = if_idx;
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }
  if( FD_UNLIKELY( neigh->state != FD_NEIGH4_STATE_ACTIVE ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }
  ip4_src = fd_uint_if( !ip4_src, ctx->default_address, ip4_src );
  out->src_ip = ip4_src;
  memcpy( out->mac_addrs+0, neigh->mac_addr,  6 );
  memcpy( out->mac_addrs+6, netdev->mac_addr, 6 );

  return 1;
}

static inline void
fd_net_router_solicit( fd_net_router_t *   ctx,
                       fd_stem_context_t * stem ) {
  if( FD_LIKELY( !ctx->solicit_ip ) ) return;

  fd_stem_publish( stem, ctx->netlnk_out_idx, fd_netlink_neigh4_solicit_sig( ctx->solicit_ip, ctx->solicit_if_idx ), 0UL, 0UL, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->solicit_ip = 0U;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_router_h */
