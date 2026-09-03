/* The IAVF tile translates Ethernet frames between one Intel SR-IOV
   Virtual Function queue pair and fd_tango traffic. */

#include "../fd_net_tile.h"
#include "fd_iavf.h"

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../fd_net_common.h"
#include "../../metrics/fd_metrics.h"
#include "../fd_net_router.h"
#include "../fd_linux_bond.h"
#include "../../topo/fd_topo.h"
#include "../../../discof/repair/fd_repair.h"

#include "../../../waltz/ip/fd_iproute.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_gre.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../util/net/fd_udp.h"
#include "../../../util/pod/fd_pod_format.h"

#include <linux/if_arp.h>
#include <linux/rtnetlink.h>

#include "generated/fd_iavf_tile_seccomp.h"

#define IN_KIND_NET     (0U)
#define IN_KIND_IPROUTE (1U)

#define FD_IAVF_TILE_PAGE_SZ        (4096UL)
#define FD_IAVF_TILE_FLOW_CAP       (64UL)
#define FD_IAVF_TILE_GRE_MAX        (4UL)
#define FD_IAVF_TILE_STATS_NS       (1000000000L)
#define FD_IAVF_TX_FLUSH_TIMEOUT_NS (20000L) /* 20us */
#define FD_IAVF_TILE_ADMINQ_IOVA    (0x100000000UL)
#define FD_IAVF_TILE_QUEUE_IOVA     (0x100100000UL)
#define FD_IAVF_TILE_PACKET_IOVA    (0x200000000UL)

FD_STATIC_ASSERT( FD_NET_ROUTE_FAIL_CNT==FD_METRICS_ENUM_ROUTE_FAIL_CNT, route_fail_metric_cnt );

/* fd_iavf_tile_arp is the Ethernet/IPv4 ARP packet format. */
struct __attribute__((packed)) fd_iavf_tile_arp {
  ushort net_hardware_type;
  ushort net_protocol_type;
  uchar  hardware_addr_sz;
  uchar  protocol_addr_sz;
  ushort net_operation;
  uchar  sender_hardware_addr[ 6 ];
  uint   sender_protocol_addr;
  uchar  target_hardware_addr[ 6 ];
  uint   target_protocol_addr;
};
typedef struct fd_iavf_tile_arp fd_iavf_tile_arp_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_tile_arp_t)==28UL, iavf_arp_sz );

struct fd_iavf_tile_input_ctx {
  void * wksp_base;
  ulong  chunk0;
  ulong  wmark;
};
typedef struct fd_iavf_tile_input_ctx fd_iavf_tile_input_ctx_t;

/* fd_iavf_tile is the private tile state. */
struct fd_iavf_tile {
  fd_iavf_hw_pci_info_t pci;
  fd_iavf_hw_vfio_t     vfio;
  fd_iavf_hw_adminq_t   adminq;
  fd_iavf_hw_vf_info_t  vf_info;
  fd_iavf_hw_queue_t    queue;
  fd_iavf_hw_stats_t    hw_stats;
  uint                  prepared;
  long                  stats_deadline_ticks;
  long                  tx_flush_timeout_ticks;
  long                  tx_flush_deadline_ticks;

  uint rx_pending_chunk[ FD_IAVF_BATCH_SIZE ];
  uint rx_pending_cnt;

  uchar *  pkt_buf_wksp_base;
  uint     pkt_buf_chunk0;
  uint     pkt_buf_wmark;
  ulong    pkt_buf_iova0;
  uint *   rx_desc_chunk;
  uint *   tx_desc_chunk;
  ushort * tx_desc_sz;

  fd_iavf_tile_input_ctx_t input_ctx[ FD_TOPO_MAX_TILE_IN_LINKS ];
  uchar                    in_kind[ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_iproute_msg_t         iproute_msg;

  fd_net_router_t   router;
  fd_net_tx_route_t tx_route;

  uint   dst_port_cnt;
  ushort dst_ports[ FD_IAVF_TILE_FLOW_CAP ];
  uchar  dst_protos[ FD_IAVF_TILE_FLOW_CAP ];
  uchar  dst_out_idx[ FD_IAVF_TILE_FLOW_CAP ];
  uchar  repair_out_idx;
  uchar  rx_out_cnt;
  uint   gre_tunnel_ip[ FD_IAVF_TILE_GRE_MAX ];

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong rx_malformed_cnt;
    ulong rx_route_fail_cnt;
    ulong rx_desc_error_cnt;
    ulong rx_no_buffer_cnt;
    ulong rx_gre_cnt;
    ulong rx_gre_invalid_cnt;
    ulong rx_gre_ignored_cnt;
    ulong rx_arp_cnt;
    ulong tx_pkt_cnt;
    ulong tx_bytes_total;
    ulong tx_no_buffer_cnt;
    ulong tx_invalid_cnt;
    ulong tx_gre_cnt;
    ulong tx_gre_route_fail_cnt;
    ulong tx_gre_oversize_cnt;
    ulong tx_arp_cnt;
    ulong tx_arp_drop_cnt;
    ulong adminq_fail_cnt;
    ulong link_change_cnt;
  } metrics;
};
typedef struct fd_iavf_tile fd_iavf_tile_t;

static inline ulong
fd_iavf_tile_buffer_iova( fd_iavf_tile_t const * ctx,
                          ulong                  chunk ) {
  return ctx->pkt_buf_iova0 + ((chunk-(ulong)ctx->pkt_buf_chunk0)<<FD_CHUNK_LG_SZ);
}

static inline ulong
fd_iavf_tile_tx_chunk( fd_iavf_tile_t const * ctx,
                       ulong                  tx_idx ) {
  return ctx->tx_desc_chunk[ tx_idx & (ctx->queue.tx_depth-1U) ];
}

static inline int
fd_iavf_tile_tx_full( fd_iavf_tile_t const * ctx ) {
  return ctx->queue.tx_prod-ctx->queue.tx_cons>=ctx->queue.tx_depth-1UL;
}

static inline int
fd_iavf_tile_tx_submit( fd_iavf_tile_t * ctx,
                        ulong            frame_sz ) {
  ulong const tx_idx = ctx->queue.tx_prod;
  ulong const chunk  = fd_iavf_tile_tx_chunk( ctx, tx_idx );
  if( FD_UNLIKELY( fd_iavf_hw_tx_submit( &ctx->queue, fd_iavf_tile_buffer_iova( ctx, chunk ), frame_sz ) ) ) {
    return -1;
  }
  ctx->tx_desc_sz[ tx_idx & (ctx->queue.tx_depth-1U) ] = (ushort)frame_sz;

  ulong const tx_pending = ctx->queue.tx_prod-ctx->queue.tx_posted;
  if( tx_pending>=FD_IAVF_BATCH_SIZE ||
      ctx->queue.tx_prod-ctx->queue.tx_cons>=ctx->queue.tx_depth-1UL ) {
    fd_iavf_hw_tx_flush( &ctx->queue );
  } else if( tx_pending==1UL ) {
    ctx->tx_flush_deadline_ticks = fd_tickcount()+ctx->tx_flush_timeout_ticks;
  }
  return 0;
}

static inline void
fd_iavf_tile_rx_flush( fd_iavf_tile_t * ctx ) {
  for( uint i=0U; i<ctx->rx_pending_cnt; i++ ) {
    ulong const chunk = ctx->rx_pending_chunk[ i ];
    uint desc_idx;
    if( FD_UNLIKELY( fd_iavf_hw_rx_post( &ctx->queue, fd_iavf_tile_buffer_iova( ctx, chunk ), &desc_idx ) ) ) {
      ctx->metrics.rx_no_buffer_cnt++;
      FD_LOG_ERR(( "IAVF receive buffer post failed for chunk %lu with RX producer %lu consumer %lu depth %u (%i-%s)",
                   chunk, ctx->queue.rx_prod, ctx->queue.rx_cons, ctx->queue.rx_depth, errno, fd_io_strerror( errno ) ));
    }
    ctx->rx_desc_chunk[ desc_idx ] = (uint)chunk;
  }
  fd_iavf_hw_rx_flush( &ctx->queue );
  ctx->rx_pending_cnt = 0U;
}

static inline void
fd_iavf_tile_rx_recycle( fd_iavf_tile_t * ctx,
                         ulong            chunk ) {
  ctx->rx_pending_chunk[ ctx->rx_pending_cnt++ ] = (uint)chunk;

  /* Hold partial recycle batches so RX descriptor updates require one
     device-ordering barrier and tail write per batch. */
  if( ctx->rx_pending_cnt==FD_IAVF_BATCH_SIZE ) fd_iavf_tile_rx_flush( ctx );
}

static inline int
fd_iavf_tile_rx_dst_port_lookup( fd_iavf_tile_t const * ctx,
                                 ushort                 net_dport,
                                 ulong                  frame_sz,
                                 ulong *                out_idx,
                                 ulong *                dst_proto ) {
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
  if( FD_UNLIKELY( *dst_proto==DST_PROTO_REPAIR ) ) {
    ulong const max_hdr_sz     = sizeof(fd_eth_hdr_t) + 15UL*4UL + sizeof(fd_udp_hdr_t);
    ulong const min_payload_sz = frame_sz>max_hdr_sz ? frame_sz-max_hdr_sz : 0UL;
    if( FD_UNLIKELY( min_payload_sz<=AG_REPAIR_RESPONSE_MAX_SZ ) ) {
      if( FD_UNLIKELY( ctx->repair_out_idx==UCHAR_MAX ) ) return 0;
      *out_idx = ctx->repair_out_idx;
    }
  }
  return *out_idx<ctx->rx_out_cnt;
}

static inline int
fd_iavf_tile_arp_reply( fd_iavf_tile_t * ctx,
                        uchar const *    request,
                        ulong            request_sz ) {
  ulong const arp_frame_sz = sizeof(fd_eth_hdr_t)+sizeof(fd_iavf_tile_arp_t);
  if( FD_UNLIKELY( request_sz<arp_frame_sz ) ) return 0;

  fd_eth_hdr_t const *      request_eth = (fd_eth_hdr_t const *)request;
  fd_iavf_tile_arp_t const * request_arp = (fd_iavf_tile_arp_t const *)(request_eth+1);
  if( FD_UNLIKELY( request_arp->net_hardware_type!=fd_ushort_bswap( ARPHRD_ETHER ) ||
                   request_arp->net_protocol_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ||
                   request_arp->hardware_addr_sz!=6U || request_arp->protocol_addr_sz!=4U ||
                   request_arp->net_operation!=fd_ushort_bswap( 1U ) ||
                   request_arp->target_protocol_addr!=ctx->router.bind_address ) ) return 0;

  ctx->metrics.rx_arp_cnt++;
  if( FD_UNLIKELY( fd_iavf_tile_tx_full( ctx ) ) ) {
    ctx->metrics.tx_no_buffer_cnt++;
    ctx->metrics.tx_arp_drop_cnt++;
    return 1;
  }

  ulong const chunk = fd_iavf_tile_tx_chunk( ctx, ctx->queue.tx_prod );
  uchar * reply = fd_chunk_to_laddr( ctx->pkt_buf_wksp_base, chunk );
  fd_memset( reply, 0, 60UL );

  fd_eth_hdr_t * reply_eth = (fd_eth_hdr_t *)reply;
  fd_memcpy( reply_eth->dst, request_arp->sender_hardware_addr, 6UL );
  fd_memcpy( reply_eth->src, ctx->vf_info.mac_addr, 6UL );
  reply_eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP );

  fd_iavf_tile_arp_t * reply_arp = (fd_iavf_tile_arp_t *)(reply_eth+1);
  reply_arp->net_hardware_type = fd_ushort_bswap( ARPHRD_ETHER );
  reply_arp->net_protocol_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );
  reply_arp->hardware_addr_sz  = 6U;
  reply_arp->protocol_addr_sz  = 4U;
  reply_arp->net_operation     = fd_ushort_bswap( 2U );
  fd_memcpy( reply_arp->sender_hardware_addr, ctx->vf_info.mac_addr, 6UL );
  reply_arp->sender_protocol_addr = ctx->router.bind_address;
  fd_memcpy( reply_arp->target_hardware_addr, request_arp->sender_hardware_addr, 6UL );
  reply_arp->target_protocol_addr = request_arp->sender_protocol_addr;

  if( FD_UNLIKELY( fd_iavf_tile_tx_submit( ctx, 60UL ) ) ) {
    ctx->metrics.tx_arp_drop_cnt++;
    FD_LOG_ERR(( "IAVF ARP reply submission failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->metrics.tx_arp_cnt++;
  return 1;
}

/* fd_iavf_tile_rx_pkt validates and publishes an RX packet.  It returns
   whether publication succeeded and sets freed_chunk to a reusable buffer. */
static inline int
fd_iavf_tile_rx_pkt( fd_iavf_tile_t *    ctx,
                     fd_stem_context_t * stem,
                     ulong               chunk,
                     ulong               byte_len,
                     ulong               tspub,
                     ulong *             freed_chunk ) {
  *freed_chunk = chunk;
  if( FD_UNLIKELY( byte_len<sizeof(fd_eth_hdr_t) || byte_len>FD_NET_MTU ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  uchar *        frame   = fd_chunk_to_laddr( ctx->pkt_buf_wksp_base, chunk );
  fd_eth_hdr_t * eth_hdr = (fd_eth_hdr_t *)frame;
  ushort const  eth_type = fd_ushort_bswap( eth_hdr->net_type );
  if( FD_UNLIKELY( eth_type==FD_ETH_HDR_TYPE_ARP ) ) {
    if( !fd_iavf_tile_arp_reply( ctx, frame, byte_len ) ) ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  ulong const min_udp_frame_sz = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( eth_type!=FD_ETH_HDR_TYPE_IP || byte_len<min_udp_frame_sz ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)(eth_hdr+1);
  ulong ip4_hdr_sz = FD_IP4_GET_LEN( *ip4_hdr );
  ulong ip4_total_sz = fd_ushort_bswap( ip4_hdr->net_tot_len );
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4_hdr )!=4 || ip4_hdr_sz<sizeof(fd_ip4_hdr_t) ||
                   ip4_total_sz<ip4_hdr_sz || sizeof(fd_eth_hdr_t)+ip4_total_sz>byte_len ) ) {
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
    for( ulong i=0UL; i<FD_IAVF_TILE_GRE_MAX; i++ ) tunnel_found |= ip4_hdr->saddr==ctx->gre_tunnel_ip[ i ];
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
  if( FD_UNLIKELY( ctx->router.bind_address && ip4_hdr->daddr!=ctx->router.bind_address ) ) {
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
  ulong const udp_sz = fd_ushort_bswap( udp_hdr->net_len );
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) || udp_sz>ip4_total_sz-ip4_hdr_sz ||
                   fd_ip4_addr_is_mcast( ip4_hdr->saddr ) ) ) {
    ctx->metrics.rx_malformed_cnt++;
    return 0;
  }

  ushort const dst_port = fd_ushort_bswap( udp_hdr->net_dport );
  ulong out_idx;
  ulong dst_proto;
  if( FD_UNLIKELY( !fd_iavf_tile_rx_dst_port_lookup( ctx, dst_port, byte_len, &out_idx, &dst_proto ) ) ) {
    ctx->metrics.rx_route_fail_cnt++;
    return 0;
  }

  fd_frag_meta_t * mcache = stem->mcaches[ out_idx ];
  ulong const depth = stem->depths[ out_idx ];
  ulong const seq   = stem->seqs[ out_idx ];
  *freed_chunk = mcache[ fd_mcache_line_idx( seq, depth ) ].chunk;

  ushort const src_port = fd_ushort_bswap( udp_hdr->net_sport );
  ulong const sig = fd_disco_netmux_sig( ip4_hdr->saddr, src_port, ip4_hdr->saddr, dst_proto, dgram_off );
  fd_stem_publish( stem, out_idx, sig, chunk, byte_len, ctl, 0UL, tspub );

  ctx->metrics.rx_gre_cnt += (ulong)is_gre;
  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += byte_len;
  return 1;
}

static inline int
fd_iavf_tile_poll_rx( fd_iavf_tile_t *    ctx,
                      fd_stem_context_t * stem ) {
  fd_iavf_hw_rx_comp_t comp[ FD_IAVF_BATCH_SIZE ];
  int comp_cnt = fd_iavf_hw_rx_poll( &ctx->queue, comp, FD_IAVF_BATCH_SIZE );
  if( FD_UNLIKELY( comp_cnt<0 ) ) FD_LOG_ERR(( "IAVF RX poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !comp_cnt ) ) return 0;

  ulong const tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  for( uint i=0U; i<(uint)comp_cnt; i++ ) {
    ulong const chunk = ctx->rx_desc_chunk[ comp[ i ].desc_idx ];
    if( FD_UNLIKELY( chunk<ctx->pkt_buf_chunk0 || chunk>ctx->pkt_buf_wmark ) ) {
      FD_LOG_CRIT(( "IAVF RX descriptor %u chunk %lu out of bounds [%u,%u]",
                    comp[ i ].desc_idx, chunk, ctx->pkt_buf_chunk0, ctx->pkt_buf_wmark ));
    }
    __builtin_prefetch( fd_chunk_to_laddr_const( ctx->pkt_buf_wksp_base, chunk ), 0, 3 );
  }

  for( uint i=0U; i<(uint)comp_cnt; i++ ) {
    ulong const chunk = ctx->rx_desc_chunk[ comp[ i ].desc_idx ];
    ulong freed_chunk = chunk;
    if( FD_UNLIKELY( comp[ i ].error_flags ) ) ctx->metrics.rx_desc_error_cnt++;
    else fd_iavf_tile_rx_pkt( ctx, stem, chunk, comp[ i ].frame_sz, tspub, &freed_chunk );
    if( FD_UNLIKELY( !freed_chunk ) ) FD_LOG_CRIT(( "invalid chunk in mcache" ));
    fd_iavf_tile_rx_recycle( ctx, freed_chunk );
  }
  return 1;
}

static inline int
fd_iavf_tile_poll_tx( fd_iavf_tile_t * ctx ) {
  ulong const old_cons     = ctx->queue.tx_cons;
  ulong const complete_cnt = fd_iavf_hw_tx_complete( &ctx->queue );
  if( !complete_cnt ) return 0;

  ulong bytes = 0UL;
  for( ulong i=0UL; i<complete_cnt; i++ ) {
    ulong const idx = (old_cons+i) & (ctx->queue.tx_depth-1U);
    bytes += ctx->tx_desc_sz[ idx ];
    ctx->tx_desc_sz[ idx ] = 0U;
  }
  ctx->metrics.tx_pkt_cnt     += complete_cnt;
  ctx->metrics.tx_bytes_total += bytes;
  return 1;
}

static inline void
before_credit( fd_iavf_tile_t *    ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  ulong const tx_pending = ctx->queue.tx_prod-ctx->queue.tx_posted;
  if( FD_UNLIKELY( tx_pending && fd_tickcount()>=ctx->tx_flush_deadline_ticks ) ) {
    fd_iavf_hw_tx_flush( &ctx->queue );
    *charge_busy = 1;
  }
  if( ctx->queue.tx_cons!=ctx->queue.tx_posted ) *charge_busy |= fd_iavf_tile_poll_tx( ctx );
}

static inline void
after_credit( fd_iavf_tile_t *    ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;
  *charge_busy |= fd_iavf_tile_poll_rx( ctx, stem );
}

static inline int
before_frag( fd_iavf_tile_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig ) {
  (void)seq;
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) return 0;
  if( FD_UNLIKELY( fd_disco_netmux_sig_proto( sig )!=DST_PROTO_OUTGOING ) ) return 1;

  uint const dst_ip = fd_disco_netmux_sig_ip( sig );
  if( FD_UNLIKELY( !fd_net_tx_route( &ctx->router, dst_ip, &ctx->tx_route ) ) ) return 1;
  if( FD_UNLIKELY( ctx->tx_route.use_gre ) ) {
    fd_net_tx_route_t outer_route;
    uint const inner_src_ip = ctx->tx_route.src_ip;
    uint const outer_src_ip = ctx->tx_route.gre_outer_src_ip;
    uint const outer_dst_ip = ctx->tx_route.gre_outer_dst_ip;
    if( FD_UNLIKELY( !inner_src_ip || !outer_dst_ip ||
                     !fd_net_tx_route( &ctx->router, outer_dst_ip, &outer_route ) ||
                     outer_route.use_gre || outer_route.use_loopback ) ) {
      ctx->metrics.tx_gre_route_fail_cnt++;
      return 1;
    }
    ctx->tx_route                  = outer_route;
    ctx->tx_route.src_ip           = inner_src_ip;
    ctx->tx_route.gre_outer_src_ip = fd_uint_if( !outer_src_ip, outer_route.src_ip, outer_src_ip );
    ctx->tx_route.gre_outer_dst_ip = outer_dst_ip;
    ctx->tx_route.use_gre          = 1U;
  }

  if( FD_UNLIKELY( fd_iavf_tile_tx_full( ctx ) ) ) {
    ctx->metrics.tx_no_buffer_cnt++;
    return 1;
  }
  return 0;
}

static inline void
during_frag( fd_iavf_tile_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig,
             ulong            chunk,
             ulong            frame_sz,
             ulong            ctl ) {
  (void)seq; (void)sig; (void)ctl;
  fd_iavf_tile_input_ctx_t * input_ctx = &ctx->input_ctx[ in_idx ];
  if( FD_UNLIKELY( chunk<input_ctx->chunk0 || chunk>input_ctx->wmark || frame_sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, frame_sz, input_ctx->chunk0, input_ctx->wmark ));
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) {
    if( FD_UNLIKELY( frame_sz!=sizeof(fd_iproute_msg_t) ) ) FD_LOG_ERR(( "invalid iproute message size %lu", frame_sz ));
    fd_memcpy( &ctx->iproute_msg, fd_chunk_to_laddr_const( input_ctx->wksp_base, chunk ), sizeof(fd_iproute_msg_t) );
    return;
  }

  ulong const min_frame_sz = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t);
  if( FD_UNLIKELY( frame_sz<min_frame_sz || frame_sz>FD_ETH_PAYLOAD_MAX ) ) {
    FD_LOG_ERR(( "invalid packet size %lu on input %lu", frame_sz, in_idx ));
  }

  uchar const * src = fd_chunk_to_laddr_const( input_ctx->wksp_base, chunk );
  ulong const dst_chunk = fd_iavf_tile_tx_chunk( ctx, ctx->queue.tx_prod );
  uchar * dst = fd_chunk_to_laddr( ctx->pkt_buf_wksp_base, dst_chunk );
  if( FD_UNLIKELY( ctx->tx_route.use_gre ) ) {
    ulong const inner_ip_off = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t);
    fd_memcpy( dst+offsetof(fd_eth_hdr_t, net_type), src+offsetof(fd_eth_hdr_t, net_type), sizeof(ushort) );
    fd_memcpy( dst+inner_ip_off, src+sizeof(fd_eth_hdr_t), frame_sz-sizeof(fd_eth_hdr_t) );
  } else {
    fd_memcpy( dst, src, frame_sz );
  }
}

static void
after_frag( fd_iavf_tile_t *    ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               frame_sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)tsorig; (void)tspub;
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_IPROUTE ) ) {
    fd_iproute_msg_t const * msg = &ctx->iproute_msg;
    if( msg->op==FD_IPROUTE_OP_FLUSH ) {
      fd_fib4_clear( ctx->router.fib_local );
      fd_fib4_clear( ctx->router.fib_main );
      return;
    }

    fd_fib4_t * fib;
    if( msg->table_id==RT_TABLE_LOCAL )     fib = ctx->router.fib_local;
    else if( msg->table_id==RT_TABLE_MAIN ) fib = ctx->router.fib_main;
    else return;

    if( msg->op==FD_IPROUTE_OP_UPSERT && FD_UNLIKELY( !fd_fib4_insert( fib, msg->dst_addr, msg->prefix, msg->prio, &msg->hop ) ) ) {
      FD_LOG_WARNING(( "route update dropped: route table full (increase [net.max_routes] or [net.max_peer_routes])" ));
      fd_netlink_route4_sync( ctx->router.neigh4_solicit, fd_frag_meta_ts_comp( fd_tickcount() ) );
    } else if( msg->op==FD_IPROUTE_OP_DELETE ) {
      fd_fib4_remove( fib, msg->dst_addr, msg->prefix, msg->prio );
    }
    return;
  }

  ulong const chunk = fd_iavf_tile_tx_chunk( ctx, ctx->queue.tx_prod );
  uchar * frame = fd_chunk_to_laddr( ctx->pkt_buf_wksp_base, chunk );
  ulong tx_frame_sz = frame_sz;
  int fill_result;

  fd_eth_hdr_t * eth_hdr = (fd_eth_hdr_t *)frame;
  if( FD_UNLIKELY( eth_hdr->net_type!=fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) ) ) {
    FD_LOG_CRIT(( "input %lu attempted to send packet with invalid ethertype %04x",
                  in_idx, fd_ushort_bswap( eth_hdr->net_type ) ));
  }

  if( FD_UNLIKELY( ctx->tx_route.use_gre ) ) {
    ulong const inner_ip_off = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t);
    fd_ip4_hdr_t * inner_ip4 = (fd_ip4_hdr_t *)(frame+inner_ip_off);
    fill_result = fd_net_tx_fill_ip4( &ctx->router, &ctx->tx_route, inner_ip4, frame_sz-sizeof(fd_eth_hdr_t) );
    if( FD_LIKELY( fill_result==FD_NET_TX_FILL_OK ) ) {
      ulong const outer_ip_sz = sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t)+frame_sz-sizeof(fd_eth_hdr_t);
      if( FD_UNLIKELY( ctx->tx_route.mtu && outer_ip_sz>ctx->tx_route.mtu ) ) {
        ctx->metrics.tx_gre_oversize_cnt++;
        return;
      }

      fd_memcpy( eth_hdr->dst, ctx->tx_route.mac_addrs, 6UL );
      fd_memcpy( eth_hdr->src, ctx->vf_info.mac_addr, 6UL );
      eth_hdr->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

      fd_ip4_hdr_t outer_ip4 = {
        .verihl       = FD_IP4_VERIHL( 4,5 ),
        .net_tot_len  = fd_ushort_bswap( (ushort)outer_ip_sz ),
        .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
        .ttl          = 64U,
        .protocol     = FD_IP4_HDR_PROTOCOL_GRE,
        .saddr        = ctx->tx_route.gre_outer_src_ip,
        .daddr        = ctx->tx_route.gre_outer_dst_ip
      };
      if( FD_UNLIKELY( !outer_ip4.saddr || !outer_ip4.daddr ) ) {
        ctx->metrics.tx_gre_route_fail_cnt++;
        return;
      }
      outer_ip4.check = fd_ip4_hdr_check_fast( &outer_ip4 );
      FD_STORE( fd_ip4_hdr_t, frame+sizeof(fd_eth_hdr_t), outer_ip4 );
      fd_gre_hdr_t const gre_hdr = {
        .flags_version = FD_GRE_HDR_FLG_VER_BASIC,
        .protocol      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
      };
      FD_STORE( fd_gre_hdr_t, frame+sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t), gre_hdr );
      tx_frame_sz += sizeof(fd_ip4_hdr_t)+sizeof(fd_gre_hdr_t);
    }
  } else {
    fill_result = fd_net_tx_fill_addrs( &ctx->router, &ctx->tx_route, frame, frame_sz );
    if( FD_LIKELY( fill_result==FD_NET_TX_FILL_OK ) ) fd_memcpy( eth_hdr->src, ctx->vf_info.mac_addr, 6UL );
  }
  if( FD_UNLIKELY( fill_result!=FD_NET_TX_FILL_OK ) ) {
    ctx->metrics.tx_invalid_cnt += (ulong)(fill_result==FD_NET_TX_FILL_INVALID);
    return;
  }

  if( FD_UNLIKELY( ctx->tx_route.use_loopback ) ) {
    ulong freed_chunk;
    if( fd_iavf_tile_rx_pkt( ctx, stem, chunk, frame_sz, (ulong)fd_frag_meta_ts_comp( fd_tickcount() ), &freed_chunk ) ) {
      ctx->tx_desc_chunk[ ctx->queue.tx_prod & (ctx->queue.tx_depth-1U) ] = (uint)freed_chunk;
    }
    ctx->metrics.tx_pkt_cnt++;
    ctx->metrics.tx_bytes_total += frame_sz;
    return;
  }

  if( FD_UNLIKELY( fd_iavf_tile_tx_submit( ctx, tx_frame_sz ) ) ) {
    FD_LOG_ERR(( "IAVF TX submission failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->metrics.tx_gre_cnt += (ulong)ctx->tx_route.use_gre;
}

static inline void
metrics_write( fd_iavf_tile_t * ctx ) {
  ulong const rx_idle = fd_ulong_min( ctx->queue.rx_prod-ctx->queue.rx_cons, ctx->queue.rx_depth );
  ulong const tx_busy = fd_ulong_min( ctx->queue.tx_prod-ctx->queue.tx_cons, ctx->queue.tx_depth-1UL );

  FD_MCNT_SET( IAVF, PKT_RX,             ctx->metrics.rx_pkt_cnt           );
  FD_MCNT_SET( IAVF, PKT_RX_BYTES,       ctx->metrics.rx_bytes_total       );
  FD_MCNT_SET( IAVF, PKT_RX_MALFORMED,   ctx->metrics.rx_malformed_cnt     );
  FD_MCNT_SET( IAVF, PKT_RX_ROUTE_FAIL,  ctx->metrics.rx_route_fail_cnt    );
  FD_MCNT_SET( IAVF, RX_DESC_ERROR,      ctx->metrics.rx_desc_error_cnt    );
  FD_MCNT_SET( IAVF, RX_OUT_OF_BUFFER,   ctx->hw_stats.rx_discards         );
  FD_MCNT_SET( IAVF, RX_ARP,             ctx->metrics.rx_arp_cnt           );
  FD_MCNT_SET( IAVF, GRE_PKT_RX,         ctx->metrics.rx_gre_cnt           );
  FD_MCNT_SET( IAVF, GRE_PKT_RX_INVALID, ctx->metrics.rx_gre_invalid_cnt   );
  FD_MCNT_SET( IAVF, GRE_PKT_RX_IGNORED, ctx->metrics.rx_gre_ignored_cnt   );
  FD_MGAUGE_SET( IAVF, RX_BUFFER_BUSY,   ctx->queue.rx_depth-rx_idle       );
  FD_MGAUGE_SET( IAVF, RX_BUFFER_IDLE,   rx_idle                           );

  FD_MCNT_SET( IAVF, PKT_TX_COMPLETED,      ctx->metrics.tx_pkt_cnt               );
  FD_MCNT_SET( IAVF, PKT_TX_BYTES,          ctx->metrics.tx_bytes_total           );
  FD_MCNT_SET( IAVF, PKT_TX_NO_BUFFER,      ctx->metrics.tx_no_buffer_cnt         );
  FD_MCNT_ENUM_COPY( IAVF, PKT_TX_ROUTE_FAIL, ctx->router.metrics.tx_route_fail_cnt );
  FD_MCNT_SET( IAVF, PKT_TX_INVALID,        ctx->metrics.tx_invalid_cnt           );
  FD_MCNT_SET( IAVF, PKT_TX_NO_NEIGHBOR,    ctx->router.metrics.tx_neigh_fail_cnt );
  FD_MCNT_SET( IAVF, TX_ERROR,              ctx->hw_stats.tx_errors+ctx->hw_stats.tx_discards );
  FD_MCNT_SET( IAVF, TX_ARP,                ctx->metrics.tx_arp_cnt               );
  FD_MCNT_SET( IAVF, TX_ARP_DROP,           ctx->metrics.tx_arp_drop_cnt          );
  FD_MCNT_SET( IAVF, GRE_PKT_TX_SUBMITTED,  ctx->metrics.tx_gre_cnt               );
  FD_MCNT_SET( IAVF, GRE_PKT_TX_NO_ROUTE,   ctx->metrics.tx_gre_route_fail_cnt    );
  FD_MCNT_SET( IAVF, GRE_PKT_TX_OVERSIZE,   ctx->metrics.tx_gre_oversize_cnt      );
  FD_MCNT_SET( IAVF, ADMINQ_FAIL,           ctx->metrics.adminq_fail_cnt          );
  FD_MCNT_SET( IAVF, LINK_CHANGE,           ctx->metrics.link_change_cnt          );
  FD_MGAUGE_SET( IAVF, LINK_UP,             (ulong)ctx->vf_info.link_up           );
  FD_MGAUGE_SET( IAVF, TX_BUFFER_BUSY,      tx_busy                              );
  FD_MGAUGE_SET( IAVF, TX_BUFFER_IDLE,      ctx->queue.tx_depth-1UL-tx_busy       );
}

static void
fd_iavf_tile_gre_tunnels_refresh( fd_iavf_tile_t * ctx ) {
  fd_memset( ctx->gre_tunnel_ip, 0, sizeof(ctx->gre_tunnel_ip) );
  ulong tunnel_cnt = 0UL;
  for( ushort i=0U; i<ctx->router.netdev_tbl.hdr->dev_cnt && tunnel_cnt<FD_IAVF_TILE_GRE_MAX; i++ ) {
    fd_netdev_t const * netdev = ctx->router.netdev_tbl.dev_tbl+i;
    if( netdev->dev_type==ARPHRD_IPGRE && netdev->gre_dst_ip ) ctx->gre_tunnel_ip[ tunnel_cnt++ ] = netdev->gre_dst_ip;
  }
}

static inline void
during_housekeeping( fd_iavf_tile_t * ctx ) {
  if( FD_LIKELY( !fd_seqlock_locked_hint( &ctx->router.netdev_shared.hdr->seqlock ) ) ) {
    fd_netdev_tbl_copy( &ctx->router.netdev_tbl, &ctx->router.netdev_shared );
    fd_iavf_tile_gre_tunnels_refresh( ctx );
  }

  long const now = fd_tickcount();
  if( FD_UNLIKELY( now>=ctx->stats_deadline_ticks ) ) {
    ctx->stats_deadline_ticks = now + (long)(FD_IAVF_TILE_STATS_NS*fd_tempo_tick_per_ns( NULL ));
    if( FD_UNLIKELY( fd_iavf_hw_get_stats( &ctx->vfio, &ctx->adminq, &ctx->vf_info, &ctx->hw_stats ) ) ) {
      ctx->metrics.adminq_fail_cnt++;
      FD_LOG_WARNING(( "IAVF statistics request failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
  int link_changed;
  if( FD_UNLIKELY( fd_iavf_hw_poll_link( &ctx->vfio, &ctx->adminq, &ctx->vf_info, &link_changed ) ) ) {
    int const err = errno;
    ctx->metrics.adminq_fail_cnt++;
    if( FD_UNLIKELY( err==ECONNRESET || err==ESHUTDOWN ) ) {
      FD_LOG_ERR(( "IAVF Physical Function reset or shutdown invalidated the queues (%i-%s)",
                   err, fd_io_strerror( err ) ));
    }
    FD_LOG_WARNING(( "IAVF link event poll failed (%i-%s)", err, fd_io_strerror( err ) ));
  } else {
    ctx->metrics.link_change_cnt += (ulong)link_changed;
  }
}

static ulong
scratch_align( void ) {
  ulong align = alignof(fd_iavf_tile_t);
  align = fd_ulong_max( align, FD_IAVF_TILE_PAGE_SZ );
  align = fd_ulong_max( align, fd_netdev_tbl_align() );
  align = fd_ulong_max( align, fd_fib4_align() );
  return align;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong const adminq_footprint = fd_iavf_hw_adminq_footprint();
  ulong const queue_footprint = fd_iavf_hw_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size );
  if( FD_UNLIKELY( !adminq_footprint || !queue_footprint ) ) return 0UL;

  ulong layout = FD_LAYOUT_INIT;
  layout = FD_LAYOUT_APPEND( layout, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  layout = FD_LAYOUT_APPEND( layout, FD_IAVF_TILE_PAGE_SZ, adminq_footprint );
  layout = FD_LAYOUT_APPEND( layout, FD_IAVF_TILE_PAGE_SZ, queue_footprint );
  layout = FD_LAYOUT_APPEND( layout, alignof(uint), tile->iavf.rx_queue_size*sizeof(uint) );
  layout = FD_LAYOUT_APPEND( layout, alignof(uint), tile->iavf.tx_queue_size*sizeof(uint) );
  layout = FD_LAYOUT_APPEND( layout, alignof(ushort), tile->iavf.tx_queue_size*sizeof(ushort) );
  layout = FD_LAYOUT_APPEND( layout, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(), fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  layout = FD_LAYOUT_APPEND( layout, fd_fib4_align(), fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  return FD_LAYOUT_FINI( layout, scratch_align() );
}

static void
fd_iavf_tile_rx_dst_port_add( fd_iavf_tile_t *       ctx,
                              fd_topo_t const *      topo,
                              fd_topo_tile_t const * tile,
                              ulong                  dst_proto,
                              char const *           out_link,
                              ushort                 dst_port,
                              int                    required ) {
  if( FD_UNLIKELY( !dst_port ) ) return;
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, out_link, tile->kind_id );
  if( FD_UNLIKELY( out_idx==ULONG_MAX ) ) {
    if( required ) FD_LOG_ERR(( "IAVF output link `%s` is missing for UDP port %hu", out_link, dst_port ));
    return;
  }
  if( FD_UNLIKELY( ctx->dst_port_cnt>=FD_IAVF_TILE_FLOW_CAP ) ) FD_LOG_ERR(( "IAVF flow rule capacity exceeded" ));
  uint const rule_idx = ctx->dst_port_cnt++;
  ctx->dst_protos [ rule_idx ] = (uchar)dst_proto;
  ctx->dst_ports  [ rule_idx ] = dst_port;
  ctx->dst_out_idx[ rule_idx ] = (uchar)out_idx;
}

static void
fd_iavf_tile_rx_dst_ports_init( fd_iavf_tile_t *       ctx,
                                fd_topo_t const *      topo,
                                fd_topo_tile_t const * tile ) {
  ctx->rx_out_cnt     = (uchar)tile->out_cnt;
  ctx->repair_out_idx = UCHAR_MAX;
  fd_iavf_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_TPU_UDP,  "net_quic",   tile->iavf.net.legacy_transaction_listen_port, 1 );
  fd_iavf_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_TPU_QUIC, "net_quic",   tile->iavf.net.quic_transaction_listen_port,   1 );
  fd_iavf_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_SHRED,    "net_shred",  tile->iavf.net.shred_listen_port,              1 );
  fd_iavf_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_GOSSIP,   "net_gossvf", tile->iavf.net.gossip_listen_port,             1 );
  fd_iavf_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_REPAIR,   "net_shred",  tile->iavf.net.repair_client_listen_port,      1 );
  fd_iavf_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_RSERVE,   "net_rserve", tile->iavf.net.repair_serve_listen_port,       0 );
  fd_iavf_tile_rx_dst_port_add( ctx, topo, tile, DST_PROTO_SEND,     "net_txsend", tile->iavf.net.txsend_src_port,                1 );
  if( tile->iavf.net.repair_client_listen_port ) {
    ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "net_repair", tile->kind_id );
    if( FD_UNLIKELY( out_idx==ULONG_MAX ) ) FD_LOG_ERR(( "IAVF output link `net_repair` is missing for repair pings" ));
    ctx->repair_out_idx = (uchar)out_idx;
  }
}

static void
fd_iavf_tile_packet_memory( fd_topo_t const *      topo,
                            fd_topo_tile_t const * tile,
                            fd_iavf_tile_t *       ctx,
                            void **                map_memory,
                            ulong *                map_memory_sz,
                            ulong *                map_iova ) {
  void * const dcache_memory = fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id );
  void * const packet_memory = fd_dcache_join( dcache_memory );
  if( FD_UNLIKELY( !packet_memory ) ) FD_LOG_ERR(( "failed to join IAVF packet dcache" ));
  ulong const data_sz = fd_ulong_align_dn( fd_dcache_data_sz( packet_memory ), FD_NET_MTU );
  void * const wksp_base = fd_wksp_containing( dcache_memory );
  if( FD_UNLIKELY( !wksp_base || data_sz<FD_NET_MTU ) ) FD_LOG_ERR(( "invalid IAVF packet dcache" ));

  ulong const chunk0 = ((ulong)packet_memory-(ulong)wksp_base)>>FD_CHUNK_LG_SZ;
  ulong const wmark  = chunk0 + ((data_sz-FD_NET_MTU)>>FD_CHUNK_LG_SZ);
  if( FD_UNLIKELY( !chunk0 || chunk0>UINT_MAX || wmark>UINT_MAX || chunk0>wmark ) ) {
    FD_LOG_ERR(( "invalid IAVF packet buffer bounds [%lu,%lu]", chunk0, wmark ));
  }

  ulong const map_start = fd_ulong_align_dn( (ulong)packet_memory, FD_IAVF_TILE_PAGE_SZ );
  ulong const map_end   = fd_ulong_align_up( (ulong)packet_memory+data_sz, FD_IAVF_TILE_PAGE_SZ );
  ctx->pkt_buf_wksp_base = wksp_base;
  ctx->pkt_buf_chunk0    = (uint)chunk0;
  ctx->pkt_buf_wmark     = (uint)wmark;
  ctx->pkt_buf_iova0     = FD_IAVF_TILE_PACKET_IOVA + (ulong)packet_memory-map_start;
  if( map_memory )    *map_memory    = (void *)map_start;
  if( map_memory_sz ) *map_memory_sz = map_end-map_start;
  if( map_iova )      *map_iova      = FD_IAVF_TILE_PACKET_IOVA;
}

static void
fd_iavf_tile_buffers_init( fd_topo_t const *      topo,
                           fd_topo_tile_t const * tile,
                           fd_iavf_tile_t *       ctx ) {
  ulong const frame_chunks = FD_NET_MTU>>FD_CHUNK_LG_SZ;
  ulong next_chunk = ctx->pkt_buf_chunk0;

  ctx->rx_pending_cnt = 0U;
  FD_TEST( tile->iavf.rx_queue_size>FD_IAVF_BATCH_SIZE );
  ulong const rx_fill_cnt = tile->iavf.rx_queue_size-FD_IAVF_BATCH_SIZE;
  for( ulong i=0UL; i<rx_fill_cnt; i++ ) {
    fd_iavf_tile_rx_recycle( ctx, next_chunk );
    next_chunk += frame_chunks;
  }
  FD_TEST( !ctx->rx_pending_cnt );
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_frag_meta_t * mcache = topo->links[ tile->out_link_id[ i ] ].mcache;
    ulong const depth = fd_mcache_depth( mcache );
    for( ulong j=0UL; j<depth; j++ ) {
      mcache[ j ].chunk = (uint)next_chunk;
      mcache[ j ].seq   = fd_seq_dec( j, 1UL );
      next_chunk += frame_chunks;
    }
  }
  for( ulong i=0UL; i<tile->iavf.tx_queue_size; i++ ) {
    ctx->tx_desc_chunk[ i ] = (uint)next_chunk;
    next_chunk += frame_chunks;
  }
  if( FD_UNLIKELY( next_chunk>ctx->pkt_buf_wmark ) ) FD_LOG_ERR(( "IAVF packet dcache is too small" ));
}

static uint
fd_iavf_tile_if_ip4_addr( char const * if_name ) {
  int sock_fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock_fd<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct ifreq ifr = { .ifr_addr.sa_family = AF_INET };
  fd_cstr_ncpy( ifr.ifr_name, if_name, sizeof(ifr.ifr_name) );

  if( FD_UNLIKELY( ioctl( sock_fd, SIOCGIFADDR, &ifr ) ) ) {
    FD_LOG_ERR(( "could not get IP address of interface `%s` (%i-%s)",
                 if_name, errno, fd_io_strerror( errno ) ));
  }
  uint ip4_addr = ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;
  if( FD_UNLIKELY( close( sock_fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  return ip4_addr;
}

static int
fd_iavf_tile_vf_pci( fd_topo_tile_t const * tile,
                     char                   vf_pci[ 13 ] ) {
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/virtfn%u",
                                          tile->iavf.if_name, tile->iavf.vf_idx ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * slash = strrchr( resolved, '/' );
  char const * pci = slash ? slash+1 : resolved;
  if( FD_UNLIKELY( strlen( pci )!=12UL ) ) {
    errno = ENODEV;
    return -1;
  }
  fd_cstr_ncpy( vf_pci, pci, 13UL );
  return 0;
}

FD_FN_UNUSED static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( scratch, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_iavf_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  void * adminq_memory = FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_TILE_PAGE_SZ, fd_iavf_hw_adminq_footprint() );
  void * queue_memory  = FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_TILE_PAGE_SZ,
                                                  fd_iavf_hw_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size ) );
  uint * rx_desc_chunk = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint), tile->iavf.rx_queue_size*sizeof(uint) );
  uint * tx_desc_chunk = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint), tile->iavf.tx_queue_size*sizeof(uint) );
  ushort * tx_desc_sz  = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(ushort), tile->iavf.tx_queue_size*sizeof(ushort) );

  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->rx_desc_chunk = rx_desc_chunk;
  ctx->tx_desc_chunk = tx_desc_chunk;
  ctx->tx_desc_sz    = tx_desc_sz;
  fd_memset( rx_desc_chunk, 0, tile->iavf.rx_queue_size*sizeof(uint) );
  fd_memset( tx_desc_chunk, 0, tile->iavf.tx_queue_size*sizeof(uint) );
  fd_memset( tx_desc_sz,    0, tile->iavf.tx_queue_size*sizeof(ushort) );
  fd_iavf_tile_rx_dst_ports_init( ctx, topo, tile );

  if( FD_UNLIKELY( fd_topo_tile_name_cnt( topo, "iavf" )!=1UL ) ) FD_LOG_ERR(( "IAVF requires exactly one tile" ));
  char vf_pci[ 13 ];
  if( FD_UNLIKELY( fd_iavf_tile_vf_pci( tile, vf_pci ) ) ) {
    FD_LOG_ERR(( "failed to resolve VF %u on `%s` (%i-%s)",
                 tile->iavf.vf_idx, tile->iavf.if_name, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( fd_iavf_hw_pci_probe( &ctx->pci, vf_pci ) ) ) {
    FD_LOG_ERR(( "invalid IAVF device `%s` (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( fd_iavf_hw_init_vfio( &ctx->vfio, &ctx->pci ) ) ) {
    FD_LOG_ERR(( "VFIO initialization failed for `%s` (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  ulong const dma_page_sz = ctx->vfio.iova_pgsizes & -ctx->vfio.iova_pgsizes;
  if( FD_UNLIKELY( dma_page_sz>FD_IAVF_TILE_PAGE_SZ ) ) {
    FD_LOG_ERR(( "IAVF VFIO requires unsupported DMA page size %lu", dma_page_sz ));
  }
  if( FD_UNLIKELY( fd_iavf_hw_init_adminq( &ctx->vfio, &ctx->adminq, adminq_memory,
                                           fd_iavf_hw_adminq_footprint(), FD_IAVF_TILE_ADMINQ_IOVA ) ||
                   fd_iavf_hw_virtchnl_version( &ctx->vfio, &ctx->adminq ) ||
                   fd_iavf_hw_get_vf_resources( &ctx->vfio, &ctx->adminq, &ctx->vf_info ) ) ) {
    FD_LOG_ERR(( "IAVF control initialization failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( fd_iavf_hw_init_queue( &ctx->vfio, &ctx->adminq, &ctx->vf_info, &ctx->queue,
                                          queue_memory,
                                          fd_iavf_hw_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size ),
                                          FD_IAVF_TILE_QUEUE_IOVA, tile->iavf.tx_queue_size, tile->iavf.rx_queue_size,
                                          FD_NET_MTU, FD_NET_MTU ) ) ) {
    FD_LOG_ERR(( "IAVF queue initialization failed (%i-%s), virtchnl operation %u status %i",
                 errno, fd_io_strerror( errno ), ctx->adminq.last_operation, ctx->adminq.last_status ));
  }

  void * packet_map;
  ulong packet_map_sz;
  ulong packet_map_iova;
  fd_iavf_tile_packet_memory( topo, tile, ctx, &packet_map, &packet_map_sz, &packet_map_iova );
  if( FD_UNLIKELY( fd_iavf_hw_dma_map( &ctx->vfio, packet_map, packet_map_sz, packet_map_iova ) ) ) {
    FD_LOG_ERR(( "IAVF packet DMA mapping failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_iavf_tile_buffers_init( topo, tile, ctx );
  if( FD_UNLIKELY( fd_iavf_hw_enable_queue( &ctx->vfio, &ctx->adminq, &ctx->vf_info, &ctx->queue ) ) ) {
    FD_LOG_ERR(( "IAVF queue enable failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  for( ulong flow_idx=0UL; flow_idx<ctx->dst_port_cnt; flow_idx++ ) {
    if( FD_UNLIKELY( fd_iavf_hw_add_udp_flow( &ctx->vfio, &ctx->adminq, &ctx->vf_info,
                                              tile->iavf.net.bind_address,
                                              ctx->dst_ports[ flow_idx ] ) ) ) {
      FD_LOG_ERR(( "IAVF Flow Director rule for UDP port %hu failed (%i-%s), virtchnl operation %u status %i, FDIR status %i",
                   ctx->dst_ports[ flow_idx ], errno, fd_io_strerror( errno ),
                   ctx->adminq.last_operation, ctx->adminq.last_status,
                   ctx->adminq.last_fdir_status ));
    }
    if( FD_UNLIKELY( fd_iavf_hw_add_gre_udp_flow( &ctx->vfio, &ctx->adminq, &ctx->vf_info,
                                                  tile->iavf.net.bind_address,
                                                  ctx->dst_ports[ flow_idx ] ) ) ) {
      FD_LOG_ERR(( "IAVF Flow Director GRE rule for inner UDP port %hu failed (%i-%s), virtchnl operation %u status %i, FDIR status %i",
                   ctx->dst_ports[ flow_idx ], errno, fd_io_strerror( errno ),
                   ctx->adminq.last_operation, ctx->adminq.last_status,
                   ctx->adminq.last_fdir_status ));
    }
  }
  FD_LOG_INFO(( "Installed %u IAVF Flow Director rules", 2U*ctx->dst_port_cnt ));
  if( FD_UNLIKELY( fd_iavf_hw_get_stats( &ctx->vfio, &ctx->adminq, &ctx->vf_info, &ctx->hw_stats ) ) ) {
    FD_LOG_ERR(( "IAVF initial statistics failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->router.default_address = fd_iavf_tile_if_ip4_addr( tile->iavf.if_name );
  ctx->prepared = 1U;
  FD_LOG_INFO(( "IAVF VF %s MAC %02x:%02x:%02x:%02x:%02x:%02x link %s speed %u Mbps",
                  ctx->pci.pci_addr,
                  (uint)ctx->vf_info.mac_addr[0], (uint)ctx->vf_info.mac_addr[1],
                  (uint)ctx->vf_info.mac_addr[2], (uint)ctx->vf_info.mac_addr[3],
                  (uint)ctx->vf_info.mac_addr[4], (uint)ctx->vf_info.mac_addr[5],
                  ctx->vf_info.link_state_valid ? (ctx->vf_info.link_up ? "up" : "down") : "unknown",
                  ctx->vf_info.link_speed_mbps ));
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( scratch, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_iavf_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(fd_iavf_tile_t), sizeof(fd_iavf_tile_t) );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_TILE_PAGE_SZ, fd_iavf_hw_adminq_footprint() );
  (void)FD_SCRATCH_ALLOC_APPEND( scratch, FD_IAVF_TILE_PAGE_SZ,
                                 fd_iavf_hw_queue_footprint( tile->iavf.tx_queue_size, tile->iavf.rx_queue_size ) );
  ctx->rx_desc_chunk = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint), tile->iavf.rx_queue_size*sizeof(uint) );
  ctx->tx_desc_chunk = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(uint), tile->iavf.tx_queue_size*sizeof(uint) );
  ctx->tx_desc_sz    = FD_SCRATCH_ALLOC_APPEND( scratch, alignof(ushort), tile->iavf.tx_queue_size*sizeof(ushort) );
  if( FD_UNLIKELY( !ctx->prepared ) ) FD_LOG_ERR(( "IAVF hardware was not initialized" ));

  void * netdev_tbl_local = FD_SCRATCH_ALLOC_APPEND( scratch, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  void * fib_local_mem = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(), fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );
  void * fib_main_mem  = FD_SCRATCH_ALLOC_APPEND( scratch, fd_fib4_align(), fd_fib4_footprint( tile->iavf.route_max, tile->iavf.route_peer_max ) );

  fd_iavf_tile_packet_memory( topo, tile, ctx, NULL, NULL, NULL );

  if( FD_UNLIKELY( tile->in_cnt>FD_TOPO_MAX_TILE_IN_LINKS ) ) FD_LOG_ERR(( "IAVF tile has too many input links" ));
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "iproute_out" ) ) ctx->in_kind[ i ] = IN_KIND_IPROUTE;
    else {
      ctx->in_kind[ i ] = IN_KIND_NET;
      if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "IAVF input link has invalid MTU" ));
    }
    ctx->input_ctx[ i ].wksp_base = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->input_ctx[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->input_ctx[ i ].wksp_base, link->dcache );
    ctx->input_ctx[ i ].wmark  = fd_dcache_compact_wmark( ctx->input_ctx[ i ].wksp_base, link->dcache, link->mtu );
  }

  FD_TEST( fd_fib4_join( ctx->router.fib_local, fd_fib4_new( fib_local_mem, tile->iavf.route_max, tile->iavf.route_peer_max, tile->iavf.route_peer_seed ) ) );
  FD_TEST( fd_fib4_join( ctx->router.fib_main,  fd_fib4_new( fib_main_mem,  tile->iavf.route_max, tile->iavf.route_peer_max, tile->iavf.route_peer_seed ) ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_shared, fd_topo_obj_laddr( topo, tile->iavf.netdev_tbl_obj_id ) ) );
  FD_TEST( fd_netdev_tbl_new( netdev_tbl_local, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( fd_netdev_tbl_join( &ctx->router.netdev_tbl, netdev_tbl_local ) );
  fd_netdev_tbl_copy( &ctx->router.netdev_tbl, &ctx->router.netdev_shared );
  fd_iavf_tile_gre_tunnels_refresh( ctx );

  ctx->router.if_virt = if_nametoindex( tile->iavf.if_name );
  if( FD_UNLIKELY( !ctx->router.if_virt ) ) FD_LOG_ERR(( "route interface `%s` does not exist", tile->iavf.if_name ));
  ctx->router.bind_address = tile->iavf.net.bind_address;
  ctx->stats_deadline_ticks   = fd_tickcount();
  ctx->tx_flush_timeout_ticks = (long)( FD_IAVF_TX_FLUSH_TIMEOUT_NS*fd_tempo_tick_per_ns( NULL ) );

  ulong const neigh4_obj_id = tile->iavf.neigh4_obj_id;
  ulong const ele_max   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong const probe_max = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong const seed      = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  if( FD_UNLIKELY( (ele_max==ULONG_MAX) | (probe_max==ULONG_MAX) | (seed==ULONG_MAX) ) ) FD_LOG_ERR(( "neigh4 hmap properties not set" ));
  if( FD_UNLIKELY( !fd_neigh4_hmap_join( ctx->router.neigh4, fd_topo_obj_laddr( topo, neigh4_obj_id ), ele_max, probe_max, seed ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  ulong const net_netlnk_id = fd_topo_find_link( topo, "net_netlnk", 0UL );
  if( FD_UNLIKELY( net_netlnk_id==ULONG_MAX ) ) FD_LOG_ERR(( "netlink request link not found" ));
  fd_topo_link_t const * net_netlnk = &topo->links[ net_netlnk_id ];
  if( FD_UNLIKELY( !net_netlnk->mcache ) ) FD_LOG_ERR(( "netlink request link not initialized" ));
  ctx->router.neigh4_solicit->mcache = net_netlnk->mcache;
  ctx->router.neigh4_solicit->depth  = fd_mcache_depth( net_netlnk->mcache );
  ctx->router.neigh4_solicit->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr( net_netlnk->mcache ) );

  ulong const scratch_top = FD_SCRATCH_ALLOC_FINI( scratch, scratch_align() );
  if( FD_UNLIKELY( scratch_top>(ulong)ctx+scratch_footprint( tile ) ) ) FD_LOG_ERR(( "IAVF scratch overflow" ));
}

FD_FN_UNUSED static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_iavf_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_iavf_tile_instr_cnt;
}

FD_FN_UNUSED static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_iavf_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<5UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2;
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  out_fds[ out_cnt++ ] = ctx->vfio.container_fd;
  out_fds[ out_cnt++ ] = ctx->vfio.group_fd;
  out_fds[ out_cnt++ ] = ctx->vfio.device_fd;
  return out_cnt;
}

#define STEM_CALLBACK_CONTEXT_TYPE        fd_iavf_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_iavf_tile_t)
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_BURST                        FD_IAVF_BATCH_SIZE
#define STEM_LAZY                         270000UL
#include "../../stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_iavf = {
  .name                     = "iavf",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
