#ifndef HEADER_fd_src_disco_net_xdp_fd_xdp_route_h
#define HEADER_fd_src_disco_net_xdp_fd_xdp_route_h

/* fd_net_router.h provides an internal API for userland routing. */

#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/mib/fd_dbl_buf.h"
#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../netlink/fd_netlink_tile.h" /* neigh4_solicit */

#include <linux/if_arp.h> /* ARPHRD_LOOPBACK */

struct fd_net_router {
  /* Route and neighbor tables */
  fd_fib4_t fib_local[1];
  fd_fib4_t fib_main[1];
  fd_neigh4_hmap_t  neigh4[1];
  fd_netlink_neigh4_solicit_link_t neigh4_solicit[1];

  /* Netdev table */
  fd_dbl_buf_t *       netdev_dbl_buf;    /* remote copy of device table */
  uchar *              netdev_buf;        /* local copy of device table */
  ulong                netdev_buf_sz;
  fd_netdev_tbl_join_t netdev_tbl;        /* join to local copy of device table */
  int                  has_gre_interface; /* enable GRE support? */

  uint if_virt;
  uint bind_address;
  uint default_address;

  /* Details pertaining to an inflight send op */
  struct {
    uchar  mac_addrs[12]; /* First 12 bytes of Ethernet header */
    uint   src_ip;        /* net order */

    uint   use_gre;           /* The tx packet will be GRE-encapsulated */
    uint   gre_outer_src_ip;  /* For GRE: Outer iphdr's src_ip in net order */
    uint   gre_outer_dst_ip;  /* For GRE: Outer iphdr's dst_ip in net order */
  } tx_op;

  struct {
    ulong tx_route_fail_cnt;
    ulong tx_neigh_fail_cnt;
  } metrics;
};
typedef struct fd_net_router fd_net_router_t;

FD_PROTOTYPES_BEGIN

/* fd_net_tx_route resolves the destination interface index, src MAC
   address, and dst MAC address.  Returns 1 on success, 0 on failure.
   On success, tx_op->{if_idx,mac_addrs} is set. */

static int
fd_net_tx_route( fd_net_router_t * ctx,
                 uint              dst_ip,
                 uint *            is_gre_inf ) {

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
    ctx->metrics.tx_route_fail_cnt++;
    return 0;
  }

  fd_netdev_t * netdev = fd_netdev_tbl_query( &ctx->netdev_tbl, if_idx );
  if( !netdev ) {
    ctx->metrics.tx_route_fail_cnt++;
    return 0;
  }

  ip4_src = fd_uint_if( !!ctx->bind_address, ctx->bind_address, ip4_src );
  ctx->tx_op.src_ip = ip4_src;

  FD_TEST( is_gre_inf );
  *is_gre_inf = 0;
  if( netdev->dev_type==ARPHRD_LOOPBACK ) {
    /* FIXME loopback support */
    return 0;
  } else if( netdev->dev_type==ARPHRD_IPGRE ) {
    /* skip MAC addrs lookup for GRE inner dst ip */
    if( netdev->gre_src_ip ) ctx->tx_op.gre_outer_src_ip = netdev->gre_src_ip;
    ctx->tx_op.gre_outer_dst_ip = netdev->gre_dst_ip;
    *is_gre_inf = 1;
    return 1;
  }

  if( FD_UNLIKELY( netdev->dev_type!=ARPHRD_ETHER ) ) {
    ctx->metrics.tx_route_fail_cnt++;
    return 0;
  }

  if( FD_UNLIKELY( if_idx!=ctx->if_virt ) ) {
    ctx->metrics.tx_route_fail_cnt++;
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
  ctx->tx_op.src_ip = ip4_src;
  memcpy( ctx->tx_op.mac_addrs+0, neigh->mac_addr,  6 );
  memcpy( ctx->tx_op.mac_addrs+6, netdev->mac_addr, 6 );

  return 1;
}

/* fd_net_tx_fill_addrs sets the Ethernet src and dst MAC, and optionally
   the IPv4 source address. */

static int
fd_net_tx_fill_addrs( fd_net_router_t * ctx,
                      uchar *           packet,
                      ulong             sz ) {
  /* Select Ethernet addresses */
  memcpy( packet, ctx->tx_op.mac_addrs, 12 );

  /* Select IPv4 source address */
  uint   ihl       = packet[ 14 ] & 0x0f;
  ushort ethertype = FD_LOAD( ushort, packet+12 );
  uint   ip4_saddr = FD_LOAD( uint,   packet+26 );
  if( ethertype==fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) && ip4_saddr==0 ) {
    if( FD_UNLIKELY( ctx->tx_op.src_ip==0 ||
                     ihl<5 || (14+(ihl<<2))>sz ) ) {
      /* Outgoing IPv4 packet with unknown src IP or invalid IHL */
      /* FIXME should select first IPv4 address of device table here */
      ctx->metrics.tx_route_fail_cnt++;
      return 0;
    }

    /* Recompute checksum after changing header */
    FD_STORE( uint,   packet+26, ctx->tx_op.src_ip );
    FD_STORE( ushort, packet+24, 0 );
    FD_STORE( ushort, packet+24, fd_ip4_hdr_check( packet+14 ) );
  }
  return 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_xdp_fd_xdp_route_h */
