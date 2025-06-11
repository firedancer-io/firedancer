#ifndef HEADER_fd_src_disco_net_xdp_fd_xdp_route_h
#define HEADER_fd_src_disco_net_xdp_fd_xdp_route_h

/* fd_net_router.h provides an internal API for userland routing. */

#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../netlink/fd_netlink_tile.h" /* neigh4_solicit */

struct fd_net_router {
  /* Route and neighbor tables */
  fd_fib4_t const * fib_local;
  fd_fib4_t const * fib_main;
  fd_neigh4_hmap_t  neigh4[1];
  fd_netlink_neigh4_solicit_link_t neigh4_solicit[1];

  uint   bind_address;
  uint   default_address;
  uchar  src_mac_addr[6];

  /* Details pertaining to an inflight send op */
  struct {
    uint   if_idx;
    uchar  mac_addrs[12]; /* First 12 bytes of Ethernet header */
    uint   src_ip;
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
                 uint              dst_ip ) {

  /* Route lookup */

  fd_fib4_hop_t hop[2] = {0};
  fd_fib4_lookup( ctx->fib_local, hop+0, dst_ip, 0UL );
  fd_fib4_lookup( ctx->fib_main,  hop+1, dst_ip, 0UL );
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

  ip4_src = fd_uint_if( !!ctx->bind_address, ctx->bind_address, ip4_src );

  if( if_idx==1 ) {
    /* Set Ethernet src and dst address to 00:00:00:00:00:00 */
    memset( ctx->tx_op.mac_addrs, 0, 12UL );
    ctx->tx_op.if_idx = 1;
    /* Set preferred src address to 127.0.0.1 if no bind address is set */
    if( !ip4_src ) ip4_src = FD_IP4_ADDR( 127,0,0,1 );
    ctx->tx_op.src_ip = ip4_src;
    return 1;
  }

  /* Neighbor resolve */

  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_hmap_query_t neigh_query[1];
  int neigh_res = fd_neigh4_hmap_query_try( ctx->neigh4, &neigh_ip, NULL, neigh_query, 0 );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) {
    /* Neighbor not found */
    if( FD_LIKELY( ctx->neigh4_solicit->mcache ) ) {
      fd_netlink_neigh4_solicit(
          ctx->neigh4_solicit,
          neigh_ip,
          if_idx,
          fd_frag_meta_ts_comp( fd_tickcount() )
      );
      ctx->metrics.tx_neigh_fail_cnt++;
    }
    return 0;
  }
  fd_neigh4_entry_t const * neigh = fd_neigh4_hmap_query_ele_const( neigh_query );
  if( FD_UNLIKELY( neigh->state != FD_NEIGH4_STATE_ACTIVE ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }
  ip4_src = fd_uint_if( !ip4_src, ctx->default_address, ip4_src );
  memcpy( ctx->tx_op.mac_addrs+0, neigh->mac_addr,   6 );
  memcpy( ctx->tx_op.mac_addrs+6, ctx->src_mac_addr, 6 );

  if( FD_UNLIKELY( fd_neigh4_hmap_query_test( neigh_query ) ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }

  ctx->tx_op.if_idx = if_idx;
  ctx->tx_op.src_ip = ip4_src;

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
