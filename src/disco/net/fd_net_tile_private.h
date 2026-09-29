#ifndef HEADER_fd_src_disco_net_fd_net_tile_private_h
#define HEADER_fd_src_disco_net_fd_net_tile_private_h

/* fd_net_tile_private.h defines private APIs used by network tiles. */

#include <net/if.h>

#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"
#include "../../waltz/mib/fd_netdev_tbl.h"
#include "../../discof/repair/fd_repair.h"

#include "../../waltz/ip/fd_iproute.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_gre.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

#include <linux/if_arp.h>

#define FD_NET_IN_KIND_TX      (0U)
#define FD_NET_IN_KIND_IPROUTE (1U)

/* FD_NET_IN_MAX is the max number of input links per net tile */
#define FD_NET_IN_MAX (32UL)

/* FD_NET_GRE_MAX is the maximum number of GRE tunnels the net tile will
   monitor.  If a packet comes in with a source IP that doesn't match
   the endpoint of one of the first FD_NET_GRE_MAX tunnels (in the order
   the OS enumerates them), it will be dropped.  This is limited for
   performance reasons. */
#define FD_NET_GRE_MAX (4UL)

/* FD_NET_RX_PORT_MAX is the max number of UDP ports which the network
   stack can receive on. */
#define FD_NET_RX_PORT_MAX (64UL)

/* fd_net_in_dcache_ctx_t stores info needed to validate and locate a frag
   in an input link's dcache. */
typedef struct {
  void * wksp_base;
  ulong  chunk0;    /* Lowest allowed starting chunk */
  ulong  wmark;     /* Highest allowed starting chunk */
} fd_net_in_dcache_ctx_t;

/* fd_net_tile_t stores provider agnostic private tile state */
struct fd_net_tile {
  ulong net_tile_id;
  ulong net_tile_cnt;

  fd_net_in_dcache_ctx_t in_dcache_ctx[ FD_NET_IN_MAX ];
  uchar                  in_kind[ FD_NET_IN_MAX ];

  /* iproute_msg stages route updates between during_frag and after_frag */
  fd_iproute_msg_t iproute_msg;

  void * pkt_buf_wksp_base;
  ulong  pkt_buf_chunk0;
  ulong  pkt_buf_wmark;
  uint   bind_address;

  ulong  dst_port_cnt;
  ushort dst_ports[ FD_NET_RX_PORT_MAX ];
  ulong  dst_protos[ FD_NET_RX_PORT_MAX ];
  ulong  dst_out_idx[ FD_NET_RX_PORT_MAX ];
  ulong  repair_out_idx;
  ulong  rx_out_cnt;
  uint   gre_tunnel_ip[ FD_NET_GRE_MAX ];

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong rx_malformed_cnt;
    ulong rx_route_fail_cnt;
    ulong rx_gre_cnt;
    ulong rx_gre_invalid_cnt;
    ulong rx_gre_ignored_cnt;
  } metrics;
};
typedef struct fd_net_tile fd_net_tile_t;

FD_PROTOTYPES_BEGIN

/* fd_net_gre_tunnels_refresh fills ctx->gre_tunnel_ip with the IP
   addresses of (up to) the first FD_NET_GRE_MAX remote GRE tunnel
   endpoints.  Any remaining entries are set to zero. */
static void
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

/* fd_net_rx_dst_port_add maps an IPv4 UDP destination port to the
   output link with the requested name and tile kind. */
static inline void
fd_net_rx_dst_port_add( fd_net_tile_t *        ctx,
                        fd_topo_t const *      topo,
                        fd_topo_tile_t const * tile,
                        ulong                  dst_proto,
                        char const *           out_link,
                        ushort                 dst_port,
                        int                    required ) {
  if( FD_UNLIKELY( !dst_port ) ) return;
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, out_link, tile->kind_id );

  if( FD_UNLIKELY( out_idx==ULONG_MAX ) ) {
    if( FD_UNLIKELY( required ) ) {
      FD_LOG_ERR(( "net output link `%s` is missing for UDP port %hu", out_link, dst_port ));
    }
    return;
  }

  if( FD_UNLIKELY( ctx->dst_port_cnt>=FD_NET_RX_PORT_MAX ) ) {
    FD_LOG_ERR(( "net tile RX port count exceeds max of %lu", FD_NET_RX_PORT_MAX ));
  }

  ctx->dst_protos [ ctx->dst_port_cnt ] = dst_proto;
  ctx->dst_ports  [ ctx->dst_port_cnt ] = dst_port;
  ctx->dst_out_idx[ ctx->dst_port_cnt ] = out_idx;
  ctx->dst_port_cnt++;
}

static inline void
fd_net_rx_dst_ports_init( fd_net_tile_t *        ctx,
                          fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile ) {
  ctx->rx_out_cnt     = tile->out_cnt;
  ctx->repair_out_idx = ULONG_MAX;

  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_TPU_UDP,  "net_quic",   tile->net.legacy_transaction_listen_port, 1 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_TPU_QUIC, "net_quic",   tile->net.quic_transaction_listen_port,   1 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_SHRED,    "net_shred",  tile->net.shred_listen_port,              1 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_GOSSIP,   "net_gossvf", tile->net.gossip_listen_port,             1 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_REPAIR,   "net_shred",  tile->net.repair_client_listen_port,      1 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_RSERVE,   "net_rserve", tile->net.repair_serve_listen_port,       0 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_SEND,     "net_txsend", tile->net.txsend_src_port,                1 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_VOTOR,    "net_votor",  tile->net.votor_quic_client_listen_port,  1 );
  fd_net_rx_dst_port_add( ctx, topo, tile, DST_PROTO_VOTOR,    "net_votor",  tile->net.votor_quic_server_listen_port,  1 );

  if( tile->net.repair_client_listen_port ) {
    ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "net_repair", tile->kind_id );
    if( FD_UNLIKELY( out_idx==ULONG_MAX ) ) {
      FD_LOG_ERR(( "net output link `net_repair` is missing for repair pings" ));
    }
    ctx->repair_out_idx = out_idx;
  }
}

static inline int
fd_net_rx_dst_port_lookup( fd_net_tile_t const * ctx,
                           ushort                net_dport,
                           ulong                 payload_sz,
                           ulong *               out_idx,
                           ulong *               dst_proto ) {
  ulong rule_idx = ULONG_MAX;
  for( ulong i=0UL; i<ctx->dst_port_cnt; i++ ) {
    if( ctx->dst_ports[ i ]==net_dport ) {
      rule_idx = i;
      break;
    }
  }
  if( FD_UNLIKELY( rule_idx==ULONG_MAX ) ) return 0;

  *out_idx   = ctx->dst_out_idx[ rule_idx ];
  *dst_proto = ctx->dst_protos [ rule_idx ];
  if( FD_UNLIKELY( *dst_proto==DST_PROTO_REPAIR && payload_sz<=AG_REPAIR_RESPONSE_MAX_SZ ) ) {
    if( FD_UNLIKELY( ctx->repair_out_idx==ULONG_MAX ) ) return 0;
    *out_idx = ctx->repair_out_idx;
  }
  return *out_idx<ctx->rx_out_cnt;
}

/* fd_net_rx_pkt validates and publishes an RX packet.  It returns whether
   publication succeeded and sets freed_chunk to a reusable buffer. */
static inline int
fd_net_rx_pkt( fd_net_tile_t *     ctx,
               fd_stem_context_t * stem,
               ulong               chunk,
               ulong               byte_len,
               ulong               tspub,
               ulong *             freed_chunk ) {
  *freed_chunk = chunk;

  ulong const min_udp_frame_sz = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( byte_len<min_udp_frame_sz || byte_len>FD_NET_MTU ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  uchar * frame = fd_chunk_to_laddr( ctx->pkt_buf_wksp_base, chunk );
  fd_eth_hdr_t * eth_hdr = (fd_eth_hdr_t *)frame;
  if( FD_UNLIKELY( fd_ushort_bswap( eth_hdr->net_type )!=FD_ETH_HDR_TYPE_IP ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)(eth_hdr+1);
  ulong ip4_hdr_sz = FD_IP4_GET_LEN( *ip4_hdr );
  ulong ip4_total_sz = fd_ushort_bswap( ip4_hdr->net_tot_len );
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4_hdr )!=4 || ip4_hdr_sz<sizeof(fd_ip4_hdr_t) ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }
  if( FD_UNLIKELY( ip4_total_sz<ip4_hdr_sz ||
                   sizeof(fd_eth_hdr_t)+ip4_total_sz>byte_len ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  ulong ctl = 0UL;
  int is_gre = ip4_hdr->protocol==FD_IP4_HDR_PROTOCOL_GRE;
  if( FD_UNLIKELY( is_gre ) ) {
    if( FD_UNLIKELY( !ctx->gre_tunnel_ip[0] ) ) {
      ctx->metrics.rx_gre_ignored_cnt++;
      return 0;
    }

    int tunnel_found = 0;
    for( ulong i=0UL; i<FD_NET_GRE_MAX; i++ ) tunnel_found |= ip4_hdr->saddr==ctx->gre_tunnel_ip[ i ];
    ulong const overhead = ip4_hdr_sz+sizeof(fd_gre_hdr_t);
    if( FD_UNLIKELY( !tunnel_found || !ip4_hdr->saddr ||
                     overhead+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)>ip4_total_sz ) ) {
      ctx->metrics.rx_gre_invalid_cnt++;
      return 0;
    }

    fd_gre_hdr_t const * gre_hdr = (fd_gre_hdr_t const *)((uchar *)ip4_hdr+ip4_hdr_sz);
    if( FD_UNLIKELY( gre_hdr->flags_version!=FD_GRE_HDR_FLG_VER_BASIC ||
                     gre_hdr->protocol!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) {
      ctx->metrics.rx_gre_invalid_cnt++;
      return 0;
    }

    frame += overhead;
    fd_memcpy( frame, eth_hdr, sizeof(fd_eth_hdr_t) );

    byte_len    -= overhead;
    ctl          = overhead;
    eth_hdr      = (fd_eth_hdr_t *)frame;
    ip4_hdr      = (fd_ip4_hdr_t *)(eth_hdr+1);
    ip4_hdr_sz   = FD_IP4_GET_LEN( *ip4_hdr );
    ip4_total_sz = fd_ushort_bswap( ip4_hdr->net_tot_len );
  }

  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4_hdr )!=4 ||
                   ip4_hdr->protocol!=FD_IP4_HDR_PROTOCOL_UDP ||
                   ip4_hdr_sz<sizeof(fd_ip4_hdr_t) || ip4_total_sz<ip4_hdr_sz ||
                   sizeof(fd_eth_hdr_t)+ip4_total_sz>byte_len ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }
  if( FD_UNLIKELY( ctx->bind_address && ip4_hdr->daddr!=ctx->bind_address ) ) {
    ctx->metrics.rx_route_fail_cnt++;
    return 0;
  }

  ulong const udp_off   = sizeof(fd_eth_hdr_t)+ip4_hdr_sz;
  ulong const dgram_off = udp_off+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( dgram_off>byte_len ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  fd_udp_hdr_t const * udp_hdr = (fd_udp_hdr_t const *)((uchar const *)eth_hdr+udp_off);
  ulong const          udp_sz  = fd_ushort_bswap( udp_hdr->net_len );
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) || udp_sz>ip4_total_sz-ip4_hdr_sz ||
                   fd_ip4_addr_is_mcast( ip4_hdr->saddr ) ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  ushort const dst_port = fd_ushort_bswap( udp_hdr->net_dport );
  ulong out_idx;
  ulong dst_proto;
  if( FD_UNLIKELY( !fd_net_rx_dst_port_lookup( ctx, dst_port, udp_sz-sizeof(fd_udp_hdr_t), &out_idx, &dst_proto ) ) ) {
    ctx->metrics.rx_route_fail_cnt++;
    return 0;
  }

  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong const      depth  = stem->depths [ out_idx ];
  ulong const      seq    = stem->seqs[ out_idx ];

  *freed_chunk = mcache[ fd_mcache_line_idx( seq, depth ) ].chunk;

  ushort const src_port = fd_ushort_bswap( udp_hdr->net_sport );
  ulong const  sig      = fd_disco_netmux_sig( ip4_hdr->saddr, src_port, ip4_hdr->saddr, dst_proto, dgram_off );
  ulong const  tsorig   = 0UL;

  fd_stem_publish( stem, out_idx, sig, chunk, byte_len, ctl, tsorig, tspub );

  ctx->metrics.rx_gre_cnt += (ulong)is_gre;
  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += byte_len;

  return 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_tile_private_h */
