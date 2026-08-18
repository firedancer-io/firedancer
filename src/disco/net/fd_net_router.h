#ifndef HEADER_fd_src_disco_net_fd_net_router_h
#define HEADER_fd_src_disco_net_fd_net_router_h

/* fd_net_router.h provides an internal API for userland routing. */

#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../netlink/fd_netlink_tile.h" /* neigh4_solicit */
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"

#include <linux/if_arp.h> /* ARPHRD_LOOPBACK */

#define FD_NET_ROUTE_FAIL_NO_ROUTE              (0U)
#define FD_NET_ROUTE_FAIL_ROUTE_TYPE            (1U)
#define FD_NET_ROUTE_FAIL_MISSING_INTERFACE     (2U)
#define FD_NET_ROUTE_FAIL_SOURCE_IP             (3U)
#define FD_NET_ROUTE_FAIL_UNSUPPORTED_INTERFACE (4U)
#define FD_NET_ROUTE_FAIL_CNT                   (5U)

#define FD_NET_TX_FILL_INVALID   (-1)
#define FD_NET_TX_FILL_NO_SOURCE ( 0)
#define FD_NET_TX_FILL_OK        ( 1)

struct fd_net_router {
  /* Route and neighbor tables */
  fd_fib4_t fib_local[1];
  fd_fib4_t fib_main[1];
  fd_neigh4_hmap_t  neigh4[1];
  fd_netlink_neigh4_solicit_link_t neigh4_solicit[1];

  /* Netdev table */
  fd_netdev_tbl_join_t netdev_tbl;    /* local copy in scratch */
  fd_netdev_tbl_join_t netdev_shared; /* shared seqlock-protected table */

  uint if_virt;
  uint bind_address;
  uint default_address;

  struct {
    ulong tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_CNT ];
    ulong tx_neigh_fail_cnt;
  } metrics;
};
typedef struct fd_net_router fd_net_router_t;

struct fd_net_tx_route {
  uchar mac_addrs[12];
  uint  src_ip;
  uint  if_idx;
  uint  use_loopback;
  uint  use_gre;
  uint  gre_outer_src_ip;
  uint  gre_outer_dst_ip;
};
typedef struct fd_net_tx_route fd_net_tx_route_t;

FD_PROTOTYPES_BEGIN

/* fd_net_tx_route resolves the destination interface index, src MAC
   address, and dst MAC address.  Returns 1 on success, 0 on failure.
   On success, writes the complete route result to out. */

static int
fd_net_tx_route( fd_net_router_t * ctx,
                 uint              dst_ip,
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
                                    FD_NET_ROUTE_FAIL_NO_ROUTE,
                                    FD_NET_ROUTE_FAIL_ROUTE_TYPE );
    ctx->metrics.tx_route_fail_cnt[ reason ]++;
    return 0;
  }

  fd_netdev_t * netdev = fd_netdev_tbl_query( &ctx->netdev_tbl, if_idx );
  if( !netdev ) {
    ctx->metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_MISSING_INTERFACE ]++;
    return 0;
  }

  ip4_src = fd_uint_if( !!ctx->bind_address, ctx->bind_address, ip4_src );
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
    ctx->metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_UNSUPPORTED_INTERFACE ]++;
    return 0;
  }

  if( FD_UNLIKELY( if_idx!=ctx->if_virt ) ) {
    ctx->metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_UNSUPPORTED_INTERFACE ]++;
    return 0;
  }

  /* Neighbor resolve */
  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_entry_t neigh[1];
  int neigh_res = fd_neigh4_hmap_query_entry( ctx->neigh4, neigh_ip, neigh );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) {
    /* Neighbor not found */
    fd_netlink_neigh4_solicit( ctx->neigh4_solicit, neigh_ip, if_idx, fd_frag_meta_ts_comp( fd_tickcount() ) );
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

static int
fd_net_tx_validate_ip4( fd_ip4_hdr_t const * ip4_hdr,
                        ulong                ip4_buf_sz ) {
  if( FD_UNLIKELY( !ip4_hdr || ip4_buf_sz<sizeof(fd_ip4_hdr_t) ) ) return 0;
  ulong const ip4_hdr_sz = FD_IP4_GET_LEN( *ip4_hdr );
  return FD_IP4_GET_VERSION( *ip4_hdr )==4U &&
         ip4_hdr_sz>=sizeof(fd_ip4_hdr_t) && ip4_hdr_sz<=ip4_buf_sz;
}

static int
fd_net_tx_validate_frame( void const * frame,
                          ulong        frame_sz ) {
  if( FD_UNLIKELY( !frame ||
                   frame_sz<sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t) ||
                   frame_sz>FD_ETH_PAYLOAD_MAX ) ) return 0;
  fd_eth_hdr_t const * eth_hdr = (fd_eth_hdr_t const *)frame;
  return eth_hdr->net_type==fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) &&
         fd_net_tx_validate_ip4( (fd_ip4_hdr_t const *)(eth_hdr+1), frame_sz-sizeof(fd_eth_hdr_t) );
}

/* fd_net_tx_fill_ip4 validates an IPv4 packet and fills a missing source
   address from its selected route. */
static int
fd_net_tx_fill_ip4( fd_net_router_t *         ctx,
                    fd_net_tx_route_t const * route,
                    fd_ip4_hdr_t *            ip4_hdr,
                    ulong                     ip4_buf_sz ) {
  if( FD_UNLIKELY( !route || !fd_net_tx_validate_ip4( ip4_hdr, ip4_buf_sz ) ) ) {
    return FD_NET_TX_FILL_INVALID;
  }

  if( ip4_hdr->saddr==0U ) {
    if( FD_UNLIKELY( route->src_ip==0U ) ) {
      ctx->metrics.tx_route_fail_cnt[ FD_NET_ROUTE_FAIL_SOURCE_IP ]++;
      return FD_NET_TX_FILL_NO_SOURCE;
    }

    ip4_hdr->saddr = route->src_ip;
    ip4_hdr->check = 0U;
    ip4_hdr->check = fd_ip4_hdr_check( ip4_hdr );
  }
  return FD_NET_TX_FILL_OK;
}

/* fd_net_tx_fill_addrs validates the Ethernet and IPv4 headers, sets both
   Ethernet addresses, and fills a missing IPv4 source address. */
static int
fd_net_tx_fill_addrs( fd_net_router_t *         ctx,
                      fd_net_tx_route_t const * route,
                      uchar *                   packet,
                      ulong                     sz ) {
  if( FD_UNLIKELY( !route || !fd_net_tx_validate_frame( packet, sz ) ) ) {
    return FD_NET_TX_FILL_INVALID;
  }

  fd_eth_hdr_t * eth_hdr = (fd_eth_hdr_t *)packet;
  fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)(eth_hdr+1);
  int const fill_result = fd_net_tx_fill_ip4( ctx, route, ip4_hdr, sz-sizeof(fd_eth_hdr_t) );
  if( FD_UNLIKELY( fill_result!=FD_NET_TX_FILL_OK ) ) return fill_result;

  memcpy( eth_hdr->dst, route->mac_addrs, 12UL );
  return FD_NET_TX_FILL_OK;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_router_h */
