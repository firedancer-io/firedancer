#ifndef HEADER_fd_src_disco_net_fd_net_tile_private_h
#define HEADER_fd_src_disco_net_fd_net_tile_private_h

/* fd_net_tile_private.h defines private APIs used by network tiles. */

#include "fd_net_tile.h"

#include <net/if.h>
#include <linux/if_arp.h>

#include "../metrics/fd_metrics.h"
#include "../netlink/fd_netlink_tile.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"
#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/neigh/fd_neigh4_map.h"

#include "../../waltz/ip/fd_iproute.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_gre.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "fd_net_sock.h"

#define FD_NET_IN_KIND_TX      (0U)
#define FD_NET_IN_KIND_IPROUTE (1U)

/* FD_NET_IN_MAX is the max number of input links per net tile */
#define FD_NET_IN_MAX (32UL)

/* FD_NET_GRE_MAX is the max number of GRE tunnels the net tile will
   monitor.  If a packet comes in with a source IP that doesn't match
   the endpoint of one of the first FD_NET_GRE_MAX tunnels (in the order
   the OS enumerates them), it will be dropped.  This is limited for
   performance reasons. */
#define FD_NET_GRE_MAX (4UL)

/* fd_net_router_t stores userland route and neighbor state. */
struct fd_net_router {
  ulong netlnk_out_idx;
  uint  solicit_ip;
  uint  solicit_if_idx;

  /* Route and neighbor tables */
  fd_fib4_t        fib_local[1];
  fd_fib4_t        fib_main[1];
  fd_neigh4_hmap_t neigh4[1];

  /* Netdev table */
  fd_netdev_tbl_join_t netdev_tbl;    /* local copy in scratch */
  fd_netdev_tbl_join_t netdev_shared; /* shared seqlock-protected table */

  uint if_virt;
  uint default_address;
};
typedef struct fd_net_router fd_net_router_t;

/* fd_net_tx_route_t stores a resolved TX route.  It includes src_ip to fill
   an unset source address in the original IPv4 header, but no original
   destination address because packet preparation leaves that field
   unchanged.  IP addresses are in network byte order. */
struct fd_net_tx_route {
  uchar  mac_addrs[12];
  ushort mtu;
  uint   src_ip;
  uint   if_idx;
  uint   use_loopback;
  uint   use_gre;
  uint   gre_outer_src_ip;
  uint   gre_outer_dst_ip;
  /* routing_failure is set if userland routing failed.  The packet is
     then sent on fd_net_tile_t::sock and routed by the kernel.  For a
     GRE route whose outer endpoint failed routing, use_gre is also set
     and the encapsulated packet is sent to gre_outer_dst_ip. */
  int    routing_failure;
};
typedef struct fd_net_tx_route fd_net_tx_route_t;

/* fd_net_in_dcache_ctx_t stores info needed to validate and locate a frag
   in an input link's dcache. */
typedef struct {
  void * wksp_base;
  ulong  chunk0;    /* Lowest allowed starting chunk */
  ulong  wmark;     /* Highest allowed starting chunk */
} fd_net_in_dcache_ctx_t;

/* fd_net_tile_t stores provider agnostic private tile state */
struct fd_net_tile {
  ulong kind_id;
  ulong tile_cnt;

  fd_net_in_dcache_ctx_t in_dcache_ctx[ FD_NET_IN_MAX ];
  uchar                  in_kind[ FD_NET_IN_MAX ];

  fd_net_router_t router;

  /* iproute_msg stages route updates between during_frag and after_frag */
  fd_iproute_msg_t iproute_msg;
  fd_net_tx_route_t tx_route;

  void * pkt_buf_wksp_base;
  ulong  pkt_buf_chunk0;
  ulong  pkt_buf_wmark;
  uint   bind_address;

  ulong  rx_dest_cnt;
  ushort rx_listen_ports[ FD_NET_RX_DEST_CNT ];
  ulong  rx_proto_ids   [ FD_NET_RX_DEST_CNT ];
  ulong  rx_out_link_idx[ FD_NET_RX_DEST_CNT ];
  ulong  rx_out_cnt;
  uint   gre_tunnel_ip[ FD_NET_GRE_MAX ];

  /* sock is a raw socket for packets that failed userland routing */
  fd_net_sock_t sock;

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong rx_gre_cnt;
    ulong rx_vlan_cnt;
    ulong rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_CNT ];

    ulong tx_pkt_cnt;
    ulong tx_bytes_total;
    ulong tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_CNT ];
    ulong tx_route_result_cnt[ FD_METRICS_ENUM_PKT_TX_ROUTE_RESULT_CNT ];
    ulong tx_slow_path_reason_cnt[ FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_CNT ];
    ulong tx_gre_cnt;
    ulong tx_slow_path_submit_cnt;
  } metrics;
};
typedef struct fd_net_tile fd_net_tile_t;

FD_PROTOTYPES_BEGIN

/* fd_net_tx_route_lookup resolves one destination and returns 1 on
   success, 0 on failure.  For GRE, returns the tunnel settings without
   resolving the outer route. */
static inline int
fd_net_tx_route_lookup( fd_net_tile_t *     net,
                        uint                dst_ip,
                        fd_net_tx_route_t * out ) {

  if( FD_UNLIKELY( !out ) ) return 0;
  *out = (fd_net_tx_route_t) {0};
  fd_net_router_t * router = &net->router;

  /* Route lookup */

  fd_fib4_hop_t hop[2] = {0};
  hop[0] = fd_fib4_lookup( router->fib_local, dst_ip, 0UL );
  hop[1] = fd_fib4_lookup( router->fib_main,  dst_ip, 0UL );
  fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );

  uint rtype   = next_hop->rtype;
  uint if_idx  = next_hop->if_idx;
  uint ip4_src = fd_uint_if( !!net->bind_address, net->bind_address, next_hop->ip4_src );
  /* if the provider uses a socket fallback it'll need the src ip.
     Success paths below overwrite it. */
  out->src_ip  = fd_uint_if( !ip4_src, router->default_address, ip4_src );

  if( FD_UNLIKELY( rtype==FD_FIB4_RTYPE_LOCAL ) ) {
    rtype  = FD_FIB4_RTYPE_UNICAST;
    if_idx = 1;
  }

  if( FD_UNLIKELY( rtype!=FD_FIB4_RTYPE_UNICAST ) ) {
    uint const reason = fd_uint_if( rtype==FD_FIB4_RTYPE_THROW,
                                    FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_V_NO_ROUTE_IDX,
                                    FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_V_UNSUPPORTED_ROUTE_IDX );
    net->metrics.tx_slow_path_reason_cnt[ reason ]++;
    out->routing_failure = 1;
    return 0;
  }

  fd_netdev_t * netdev = fd_netdev_tbl_query( &router->netdev_tbl, if_idx );
  if( !netdev ) {
    net->metrics.tx_slow_path_reason_cnt[ FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_V_INTERFACE_MISSING_IDX ]++;
    out->routing_failure = 1;
    return 0;
  }

  out->mtu    = netdev->mtu;
  out->if_idx = if_idx;

  if( netdev->dev_type==ARPHRD_LOOPBACK ) {
    memset( out->mac_addrs, 0, sizeof(out->mac_addrs) );
    out->src_ip       = fd_uint_if( !ip4_src, FD_IP4_ADDR( 127,0,0,1 ), ip4_src );
    out->use_loopback = 1U;
    return 1;
  } else if( netdev->dev_type==ARPHRD_IPGRE ) {
    out->src_ip = ip4_src;
    if( FD_UNLIKELY( !ip4_src || !netdev->gre_dst_ip ) ) {
      net->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_GRE_NO_ROUTE_IDX ]++;
      return 0;
    }
    /* skip MAC addrs lookup for GRE inner dst ip */
    out->gre_outer_src_ip = netdev->gre_src_ip;
    out->gre_outer_dst_ip = netdev->gre_dst_ip;
    out->use_gre          = 1U;
    return 1;
  }

  if( FD_UNLIKELY( netdev->dev_type!=ARPHRD_ETHER ) ) {
    net->metrics.tx_slow_path_reason_cnt[ FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_V_UNSUPPORTED_INTERFACE_IDX ]++;
    out->routing_failure = 1;
    return 0;
  }

  if( FD_UNLIKELY( if_idx!=router->if_virt ) ) {
    net->metrics.tx_slow_path_reason_cnt[ FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_V_UNSUPPORTED_INTERFACE_IDX ]++;
    out->routing_failure = 1;
    return 0;
  }

  /* Neighbor resolve */
  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_entry_t neigh[1];
  int neigh_res = fd_neigh4_hmap_query_entry( router->neigh4, neigh_ip, neigh );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) {
    /* Neighbor not found */
    router->solicit_ip     = neigh_ip;
    router->solicit_if_idx = if_idx;
    net->metrics.tx_slow_path_reason_cnt[ FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_V_NO_NEIGHBOR_IDX ]++;
    out->routing_failure = 1;
    return 0;
  }
  if( FD_UNLIKELY( neigh->state != FD_NEIGH4_STATE_ACTIVE ) ) {
    net->metrics.tx_slow_path_reason_cnt[ FD_METRICS_ENUM_PKT_TX_SLOW_PATH_REASON_V_NO_NEIGHBOR_IDX ]++;
    out->routing_failure = 1;
    return 0;
  }
  ip4_src = fd_uint_if( !ip4_src, router->default_address, ip4_src );
  out->src_ip = ip4_src;
  memcpy( out->mac_addrs+0, neigh->mac_addr,  6 );
  memcpy( out->mac_addrs+6, netdev->mac_addr, 6 );

  return 1;
}

/* fd_net_tx_route resolves dst_ip into out, including the remote endpoint
   for GRE tunnels.  src_ip remains the inner source IP, while if_idx, mtu,
   and mac_addrs come from the outer route.  Rejects GRE or loopback outer
   routes.  Returns 1 on success, 0 on failure.  If kernel socket fallback
   is allowed, sets routing_failure and retains the source and tunnel
   addresses needed to prepare the packet. */
static inline int
fd_net_tx_route( fd_net_tile_t *     net,
                 uint                dst_ip,
                 fd_net_tx_route_t * out ) {
  if( FD_UNLIKELY( !fd_net_tx_route_lookup( net, dst_ip, out ) ) ) return 0;
  if( FD_LIKELY( !out->use_gre ) ) return 1;

  fd_net_tx_route_t outer_route;
  if( FD_UNLIKELY( !fd_net_tx_route_lookup( net, out->gre_outer_dst_ip, &outer_route ) &&
                   !outer_route.routing_failure ) ) return 0;
  if( FD_UNLIKELY( outer_route.use_gre || outer_route.use_loopback ) ) {
    net->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_GRE_NO_ROUTE_IDX ]++;
    return 0;
  }

  memcpy( out->mac_addrs, outer_route.mac_addrs, sizeof(out->mac_addrs) );
  out->mtu              = outer_route.mtu;
  out->if_idx           = outer_route.if_idx;
  out->gre_outer_src_ip = fd_uint_if( !out->gre_outer_src_ip, outer_route.src_ip, out->gre_outer_src_ip );
  out->routing_failure = outer_route.routing_failure;
  return !out->routing_failure;
}

static inline void
fd_net_router_solicit( fd_net_router_t *   router,
                       fd_stem_context_t * stem ) {
  if( FD_LIKELY( !router->solicit_ip ) ) return;

  fd_stem_publish( stem, router->netlnk_out_idx, fd_netlink_neigh4_solicit_sig( router->solicit_ip, router->solicit_if_idx ), 0UL, 0UL, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  router->solicit_ip = 0U;
}

/* fd_net_gre_tunnels_refresh fills ctx->gre_tunnel_ip with the IP
   addresses of (up to) the first FD_NET_GRE_MAX remote GRE tunnel
   endpoints.  Any remaining entries are set to zero. */
static inline void
fd_net_gre_tunnels_refresh( fd_net_tile_t *              ctx,
                            fd_netdev_tbl_join_t const * netdev_tbl ) {
  fd_netdev_t const * dev_tbl = netdev_tbl->dev_tbl;
  ushort              dev_cnt = netdev_tbl->hdr->dev_cnt;

  fd_memset( ctx->gre_tunnel_ip, 0, sizeof(ctx->gre_tunnel_ip) );

  ulong gre_tunnel_cnt = 0UL;
  for( ushort if_idx=0U; if_idx<dev_cnt && gre_tunnel_cnt<FD_NET_GRE_MAX; if_idx++ ) {
    fd_netdev_t const * netdev = dev_tbl+if_idx;
    if( netdev->dev_type==ARPHRD_IPGRE && netdev->gre_dst_ip ) {
      ctx->gre_tunnel_ip[ gre_tunnel_cnt++ ] = netdev->gre_dst_ip;
    }
  }
}

/* fd_net_tx_route_result_increment counts a transmit job this tile
   accepted after route resolution.  Packets that failed userland routing
   take the slow path through the kernel, all others take the fast path
   (sent by the provider). */
static inline void
fd_net_tx_route_result_increment( fd_net_tile_t * ctx ) {
  ulong const idx = fd_ulong_if( !!ctx->tx_route.routing_failure,
                                 FD_METRICS_ENUM_PKT_TX_ROUTE_RESULT_V_SLOW_PATH_IDX,
                                 FD_METRICS_ENUM_PKT_TX_ROUTE_RESULT_V_FAST_PATH_IDX );
  ctx->metrics.tx_route_result_cnt[ idx ]++;
}

/* fd_net_tx_probe_loopback returns 1 if dst_ip routes to a loopback
   device and 0 otherwise.  It updates no metrics and requests no
   neighbor solicit, so tile 0 can use it to find loopback packets
   owned by another net tile without counting that tile's routing
   failures. */

static inline int
fd_net_tx_probe_loopback( fd_fib4_t const *      fib_local,
                          fd_fib4_t const *      fib_main,
                          fd_netdev_tbl_join_t * netdev_tbl,
                          uint                   dst_ip ) {
  fd_fib4_hop_t hop[2];
  hop[0] = fd_fib4_lookup( fib_local, dst_ip, 0UL );
  hop[1] = fd_fib4_lookup( fib_main,  dst_ip, 0UL );
  fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );
  if( next_hop->rtype!=FD_FIB4_RTYPE_LOCAL && next_hop->rtype!=FD_FIB4_RTYPE_UNICAST ) return 0;
  uint const if_idx = next_hop->rtype==FD_FIB4_RTYPE_LOCAL ? 1U : next_hop->if_idx;
  fd_netdev_t const * netdev = fd_netdev_tbl_query( netdev_tbl, if_idx );
  return NULL!=netdev && netdev->dev_type==ARPHRD_LOOPBACK;
}

/* fd_net_in_frag_validate checks input dcache bounds and TX packet length. */
static inline void
fd_net_in_frag_validate( fd_net_tile_t const * ctx,
                         ulong                 in_idx,
                         ulong                 chunk,
                         ulong                 frame_sz ) {
  fd_net_in_dcache_ctx_t const * input_ctx = &ctx->in_dcache_ctx[ in_idx ];
  if( FD_UNLIKELY( chunk<input_ctx->chunk0 ||
                   chunk>input_ctx->wmark  ||
                   frame_sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                 chunk, frame_sz, input_ctx->chunk0, input_ctx->wmark ));
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==FD_NET_IN_KIND_IPROUTE ) ) return;
  if( FD_UNLIKELY( frame_sz<sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t) ) ) {
    FD_LOG_ERR(( "packet too small %lu (in_idx=%lu)", frame_sz, in_idx ));
  }
  if( FD_UNLIKELY( frame_sz>FD_ETH_PAYLOAD_MAX ) ) {
    FD_LOG_ERR(( "packet too big %lu (in_idx=%lu)", frame_sz, in_idx ));
  }
}

/* fd_net_iproute_msg_stage returns 1 if it staged an IPROUTE message, 0 otherwise. */
static inline int
fd_net_iproute_msg_stage( fd_net_tile_t * ctx,
                          ulong           in_idx,
                          ulong           chunk,
                          ulong           frame_sz ) {
  if( ctx->in_kind[ in_idx ]!=FD_NET_IN_KIND_IPROUTE ) return 0;
  if( FD_UNLIKELY( frame_sz!=sizeof(fd_iproute_msg_t) ) ) {
    FD_LOG_ERR(( "invalid iproute message size %lu", frame_sz ));
  }
  fd_memcpy( &ctx->iproute_msg, fd_chunk_to_laddr_const( ctx->in_dcache_ctx[ in_idx ].wksp_base, chunk ), sizeof(fd_iproute_msg_t) );
  return 1;
}

/* fd_net_tx_pkt_cpy copies a validated TX frag from an input dcache into
   the passed dst buffer, using chunk to locate the src frag. */
static inline void
fd_net_tx_pkt_cpy( fd_net_tile_t const * ctx,
                   uchar *               dst,
                   ulong                 chunk,
                   ulong                 frame_sz,
                   ulong                 in_idx ) {
  uchar const * src = fd_chunk_to_laddr_const( ctx->in_dcache_ctx[ in_idx ].wksp_base, chunk );
  if( FD_UNLIKELY( ctx->tx_route.use_gre ) ) {
    ulong const inner_ip_off = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t);
    fd_memcpy( dst,              src,                      sizeof(fd_eth_hdr_t) );
    fd_memcpy( dst+inner_ip_off, src+sizeof(fd_eth_hdr_t), frame_sz-sizeof(fd_eth_hdr_t) );
  } else {
    fd_memcpy( dst, src, frame_sz );
  }
}

/* fd_net_tx_ip4_fill fills a missing source address with src_ip and
   updates the checksum.  An existing source address is left unchanged. */
static inline void
fd_net_tx_ip4_fill( fd_ip4_hdr_t * ip4_hdr,
                    uint           src_ip ) {
  if( ip4_hdr->saddr==0U ) {
    ip4_hdr->saddr = src_ip;
    ip4_hdr->check = 0U;
    ip4_hdr->check = fd_ip4_hdr_check( ip4_hdr );
  }
}

/* fd_net_tx_pkt_prep checks for IPv4 EtherType, IP version 4, and an IPv4
   header length of at least 20 bytes that fits within the packet.
   Sets Ethernet src and dst MAC addresses from ctx->tx_route.mac_addrs.
   If the IPv4 src address is zero, sets it from ctx->tx_route.src_ip
   and recomputes the IPv4 checksum.

   For GRE, that source address update applies to the inner IPv4 header.
   Constructs an outer IPv4 header using ctx->tx_route.gre_outer_src_ip
   and ctx->tx_route.gre_outer_dst_ip, computes its checksum, and writes
   a GRE header.  Updates *frame_sz to include the outer IPv4 and GRE
   headers.

   Returns 1 on success, 0 on failure. */
static inline int
fd_net_tx_pkt_prep( fd_net_tile_t * ctx,
                    uchar *         frame,
                    ulong *         frame_sz,
                    ulong           in_idx ) {
  fd_net_tx_route_t const * route = &ctx->tx_route;
  fd_eth_hdr_t * eth_hdr = (fd_eth_hdr_t *)frame;
  if( FD_UNLIKELY( eth_hdr->net_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) {
    FD_LOG_CRIT(( "in link %lu attempted to send packet with invalid ethertype %04x",
                  in_idx, fd_ushort_bswap( eth_hdr->net_type ) ));
  }

  ulong const    ip4_off    = sizeof(fd_eth_hdr_t) + (route->use_gre ? sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t) : 0UL);
  fd_ip4_hdr_t * ip4_hdr    = (fd_ip4_hdr_t *)(frame+ip4_off);
  ulong const    ip4_sz     = *frame_sz-sizeof(fd_eth_hdr_t);
  ulong const    ip4_hdr_sz = FD_IP4_GET_LEN( *ip4_hdr );
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4_hdr )!=4U ||
                   ip4_hdr_sz<sizeof(fd_ip4_hdr_t)    ||
                   ip4_hdr_sz>ip4_sz ) ) {
    ctx->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_INVALID_IDX ]++;
    return 0;
  }
  if( FD_UNLIKELY( !ip4_hdr->saddr && !route->src_ip ) ) {
    ctx->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_SOURCE_IP_MISSING_IDX ]++;
    return 0;
  }

  memcpy( eth_hdr->dst, route->mac_addrs, sizeof(eth_hdr->dst)+sizeof(eth_hdr->src) );
  fd_net_tx_ip4_fill( ip4_hdr, route->src_ip );
  if( FD_LIKELY( !route->use_gre ) ) return 1;

  if( FD_UNLIKELY( fd_ushort_bswap( ip4_hdr->net_tot_len )!=ip4_sz ) ) {
    ctx->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_INVALID_IDX ]++;
    return 0;
  }
  if( FD_UNLIKELY( !route->gre_outer_src_ip || !route->gre_outer_dst_ip ) ) {
    ctx->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_GRE_NO_ROUTE_IDX ]++;
    return 0;
  }

  ulong const outer_ip_sz = sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t)+ip4_sz;
  if( FD_UNLIKELY( sizeof(fd_eth_hdr_t)+outer_ip_sz>FD_NET_MTU || (route->mtu && outer_ip_sz>route->mtu) ) ) {
    ctx->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_INVALID_IDX ]++;
    return 0;
  }

  fd_ip4_hdr_t outer_ip4 = {
    .verihl       = FD_IP4_VERIHL( 4,5 ),
    .net_tot_len  = fd_ushort_bswap( (ushort)outer_ip_sz ),
    .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
    .ttl          = 64U,
    .protocol     = FD_IP4_HDR_PROTOCOL_GRE,
    .daddr        = route->gre_outer_dst_ip
  };
  fd_net_tx_ip4_fill( &outer_ip4, route->gre_outer_src_ip );
  FD_STORE( fd_ip4_hdr_t, frame+sizeof(fd_eth_hdr_t), outer_ip4 );

  fd_gre_hdr_t const gre_hdr = {
    .flags_version = FD_GRE_HDR_FLG_VER_BASIC,
    .protocol      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
  };
  FD_STORE( fd_gre_hdr_t, frame+sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t), gre_hdr );
  *frame_sz = sizeof(fd_eth_hdr_t)+outer_ip_sz;
  return 1;
}

/* fd_net_tx_sock_send sends a prepared frame on ctx->sock.  frame
   points to the Ethernet header and frame_sz is the size of the whole
   frame.  The Ethernet header is not sent: the kernel routes the packet
   to the daddr of the first IPv4 header and builds its own L2 header.
   For GRE that is the outer header built by fd_net_tx_pkt_prep, so the
   packet goes to the tunnel endpoint.  Returns 1 if the packet was sent and 0
   after counting a dropped packet.  The caller updates the packet and
   byte counters, because they differ between providers. */
static inline int
fd_net_tx_sock_send( fd_net_tile_t * ctx,
                     uchar const *   frame,
                     ulong           frame_sz ) {
  fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)( frame+sizeof(fd_eth_hdr_t) );
  if( FD_UNLIKELY( !fd_net_sock_send( &ctx->sock, ip4, frame_sz-sizeof(fd_eth_hdr_t) ) ) ) {
    ctx->metrics.tx_drop_cnt[ FD_METRICS_ENUM_PKT_TX_DROP_REASON_V_SOCKET_SEND_FAILURE_IDX ]++;
    return 0;
  }
  ctx->metrics.tx_slow_path_submit_cnt++;
  return 1;
}

/* fd_net_rx_dest_add fills in ctx's mappings between a UDP port, protocol
   and output link for one rx dest. */
static inline void
fd_net_rx_dest_add( fd_net_tile_t *        ctx,
                    fd_topo_t const *      topo,
                    fd_topo_tile_t const * tile,
                    ulong                  proto_id,
                    char const *           out_link,
                    ushort                 listen_port,
                    int                    out_link_required ) {
  if( FD_UNLIKELY( !listen_port ) ) return;
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, out_link, tile->kind_id );

  if( FD_UNLIKELY( out_idx==ULONG_MAX ) ) {
    if( FD_UNLIKELY( out_link_required ) ) {
      FD_LOG_ERR(( "net output link `%s` is missing for UDP port %hu", out_link, listen_port ));
    }
    return;
  }

  if( FD_UNLIKELY( ctx->rx_dest_cnt>=FD_NET_RX_DEST_CNT ) ) {
    FD_LOG_ERR(( "net tile RX destination count exceeds max of %lu", FD_NET_RX_DEST_CNT ));
  }

  ctx->rx_proto_ids   [ ctx->rx_dest_cnt ] = proto_id;
  ctx->rx_listen_ports[ ctx->rx_dest_cnt ] = listen_port;
  ctx->rx_out_link_idx[ ctx->rx_dest_cnt ] = out_idx;
  ctx->rx_dest_cnt++;
}

static inline void
fd_net_rx_dests_init( fd_net_tile_t *        ctx,
                      fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile ) {
  ctx->rx_out_cnt = tile->out_cnt;

  fd_net_rx_dest_t dests[ FD_NET_RX_DEST_CNT ];
  fd_net_rx_dest_list( dests, &tile->net );
  for( ulong i=0UL; i<FD_NET_RX_DEST_CNT; i++ ) {
    fd_net_rx_dest_add( ctx, topo, tile, dests[ i ].proto_id, dests[ i ].out_link, dests[ i ].listen_port, dests[ i ].out_link_required );
  }
}

static inline int
fd_net_rx_dest_lookup( fd_net_tile_t const * ctx,
                       ushort                dst_port,
                       ulong *               out_idx,
                       ulong *               proto_id ) {
  ulong rule_idx = ULONG_MAX;
  for( ulong i=0UL; i<ctx->rx_dest_cnt; i++ ) {
    if( ctx->rx_listen_ports[ i ]==dst_port ) {
      rule_idx = i;
      break;
    }
  }
  if( FD_UNLIKELY( rule_idx==ULONG_MAX ) ) return 0;

  *out_idx  = ctx->rx_out_link_idx[ rule_idx ];
  *proto_id = ctx->rx_proto_ids   [ rule_idx ];
  return *out_idx<ctx->rx_out_cnt;
}

/* fd_net_rx_pkt validates and publishes an RX packet.  It returns whether
   publication succeeded and sets freed_chunk to a reusable buffer. */
static inline int
fd_net_rx_pkt( fd_net_tile_t *     ctx,
               fd_stem_context_t * stem,
               ulong               chunk, /* offset high bits */
               ulong               ctl,   /* offset low bits */
               ulong               byte_len,
               ulong               tspub,
               ulong *             freed_chunk,
               ulong *             iavf_non_fd_pkts_rx_total ) {
  *freed_chunk = chunk;

  ulong const min_udp_frame_sz = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  ulong const min_frame_sz = iavf_non_fd_pkts_rx_total ? sizeof(fd_eth_hdr_t) : min_udp_frame_sz;
  if( FD_UNLIKELY( byte_len<min_frame_sz || byte_len>FD_NET_MTU ) ) {
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }

  uchar * frame = (uchar *)fd_chunk_to_laddr( ctx->pkt_buf_wksp_base, chunk ) + ctl;
  fd_eth_hdr_t * eth_hdr = (fd_eth_hdr_t *)frame;

  /* Strip a single 802.1Q tag in place.  The Ethernet header is moved
     forward so that it abuts the next header and takes its net_type
     from the tag.  The regions overlap, so the header is staged in a
     temporary.  Frames whose tag was already stripped by the NIC are
     not counted in rx_vlan_cnt. */
  int is_vlan = fd_ushort_bswap( eth_hdr->net_type )==FD_ETH_HDR_TYPE_VLAN;
  if( FD_UNLIKELY( is_vlan ) ) {
    if( FD_UNLIKELY( byte_len<sizeof(fd_eth_hdr_t)+sizeof(fd_vlan_tag_t) ) ) {
      ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
      return 0;
    }
    fd_vlan_tag_t const * vlan_tag    = (fd_vlan_tag_t const *)(eth_hdr+1);
    fd_eth_hdr_t          tmp_eth_hdr = *eth_hdr;
    tmp_eth_hdr.net_type = vlan_tag->net_type;
    FD_STORE( fd_eth_hdr_t, frame+sizeof(fd_vlan_tag_t), tmp_eth_hdr );
    frame    += sizeof(fd_vlan_tag_t);
    ctl      += sizeof(fd_vlan_tag_t);
    byte_len -= sizeof(fd_vlan_tag_t);
    eth_hdr   = (fd_eth_hdr_t *)frame;
  }

  if( FD_UNLIKELY( fd_ushort_bswap( eth_hdr->net_type )!=FD_ETH_HDR_TYPE_IP ) ) {
    if( iavf_non_fd_pkts_rx_total ) goto iavf_non_fd_pkt;
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }
  if( FD_UNLIKELY( byte_len<sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t) ) ) {
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }

  fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)(eth_hdr+1);
  ulong const ip4_hdr_sz = sizeof(fd_ip4_hdr_t);
  ulong ip4_total_sz = fd_ushort_bswap( ip4_hdr->net_tot_len );
  if( FD_UNLIKELY( ip4_hdr->verihl!=FD_IP4_VERIHL( 4,5 ) ) ) {
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }
  if( FD_UNLIKELY( ip4_total_sz<ip4_hdr_sz ||
                   sizeof(fd_eth_hdr_t)+ip4_total_sz>byte_len ) ) {
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }

  int is_gre = ip4_hdr->protocol==FD_IP4_HDR_PROTOCOL_GRE;
  if( FD_UNLIKELY( is_gre ) ) {
    if( FD_UNLIKELY( !ctx->gre_tunnel_ip[0] ) ) {
      if( iavf_non_fd_pkts_rx_total ) goto iavf_non_fd_pkt;
      ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_GRE_UNCONFIGURED_IDX ]++;
      return 0;
    }

    int tunnel_found = 0;
    for( ulong i=0UL; i<FD_NET_GRE_MAX; i++ ) tunnel_found |= ip4_hdr->saddr==ctx->gre_tunnel_ip[ i ];
    ulong const overhead = ip4_hdr_sz+sizeof(fd_gre_hdr_t);
    if( FD_UNLIKELY( !tunnel_found || !ip4_hdr->saddr ||
                     overhead+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)>ip4_total_sz ) ) {
      ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_GRE_INVALID_IDX ]++;
      return 0;
    }

    fd_gre_hdr_t const * gre_hdr = (fd_gre_hdr_t const *)((uchar *)ip4_hdr+ip4_hdr_sz);
    if( FD_UNLIKELY( gre_hdr->flags_version!=FD_GRE_HDR_FLG_VER_BASIC ||
                     gre_hdr->protocol!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) {
      ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_GRE_INVALID_IDX ]++;
      return 0;
    }

    frame += overhead;
    fd_memcpy( frame, eth_hdr, sizeof(fd_eth_hdr_t) );

    byte_len    -= overhead;
    ctl         += overhead;
    eth_hdr      = (fd_eth_hdr_t *)frame;
    ip4_hdr      = (fd_ip4_hdr_t *)(eth_hdr+1);
    ip4_total_sz = fd_ushort_bswap( ip4_hdr->net_tot_len );
  }

  if( FD_UNLIKELY( ip4_hdr->verihl!=FD_IP4_VERIHL( 4,5 ) ||
                   ip4_total_sz<ip4_hdr_sz ||
                   sizeof(fd_eth_hdr_t)+ip4_total_sz>byte_len ) ) {
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }
  if( FD_UNLIKELY( ip4_hdr->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) {
    if( iavf_non_fd_pkts_rx_total ) goto iavf_non_fd_pkt;
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }
  if( FD_UNLIKELY( ctx->bind_address && ip4_hdr->daddr!=ctx->bind_address ) ) {
    if( iavf_non_fd_pkts_rx_total ) goto iavf_non_fd_pkt;
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_DST_IP_MISMATCH_IDX ]++;
    return 0;
  }

  ulong const udp_off   = sizeof(fd_eth_hdr_t)+ip4_hdr_sz;
  ulong const dgram_off = udp_off+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( dgram_off>byte_len ) ) {
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }

  fd_udp_hdr_t const * udp_hdr = (fd_udp_hdr_t const *)((uchar const *)eth_hdr+udp_off);
  ulong const          udp_sz  = fd_ushort_bswap( udp_hdr->net_len );
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) || udp_sz>ip4_total_sz-ip4_hdr_sz ||
                   fd_ip4_addr_is_mcast( ip4_hdr->saddr ) ) ) {
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_MALFORMED_IDX ]++;
    return 0;
  }

  ushort const dst_port = fd_ushort_bswap( udp_hdr->net_dport );
  ulong out_idx;
  ulong proto_id;
  if( FD_UNLIKELY( !fd_net_rx_dest_lookup( ctx, dst_port, &out_idx, &proto_id ) ) ) {
    /* Missing output links for configured ports still count as drops. */
    if( iavf_non_fd_pkts_rx_total ) {
      ulong dest_idx = 0UL;
      for( ; dest_idx<ctx->rx_dest_cnt; dest_idx++ ) {
        if( ctx->rx_listen_ports[ dest_idx ]==dst_port ) break;
      }
      if( dest_idx==ctx->rx_dest_cnt ) goto iavf_non_fd_pkt;
    }
    ctx->metrics.rx_drop_cnt[ FD_METRICS_ENUM_PKT_RX_DROP_REASON_V_DST_PORT_UNBOUND_IDX ]++;
    return 0;
  }

  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong const      depth  = stem->depths [ out_idx ];
  ulong const      seq    = stem->seqs[ out_idx ];

  *freed_chunk = mcache[ fd_mcache_line_idx( seq, depth ) ].chunk;

  ushort const src_port = fd_ushort_bswap( udp_hdr->net_sport );
  ulong const  sig      = fd_disco_netmux_sig( ip4_hdr->saddr, src_port, ip4_hdr->saddr, proto_id, dgram_off );
  ulong const  tsorig   = 0UL;

  fd_stem_publish( stem, out_idx, sig, chunk, byte_len, ctl, tsorig, tspub );

  ctx->metrics.rx_gre_cnt  += (ulong)is_gre;
  ctx->metrics.rx_vlan_cnt += (ulong)is_vlan;
  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += byte_len;

  return 1;

iavf_non_fd_pkt:
  (*iavf_non_fd_pkts_rx_total)++;
  return 0;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_tile_private_h */
