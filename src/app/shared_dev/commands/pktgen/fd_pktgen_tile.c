/* fd_pktgen_tile floods a net tile with small outgoing packets.

   Each packet is a minimal Ethernet frame containing IPv4 and
   UDP headers. TTL is set to 0 so packets get dropped at the first hop
   and don't leak to the Internet (although they will reach the destination
   if there's a direct L2 connection).

   Each packet contains a 16 bit sequence number in the ip4 net_id field
   such that each payload is different.  Experiments revealed that some NICs
   stop sending if we send the same payload over and over again.
   (probably protection against a buggy driver melting the network). */

#include "../../../../disco/topo/fd_topo.h"

extern uint fd_pktgen_active;
uint fd_pktgen_active = 0U;

struct fd_pktgen_tile_ctx {
  void * out_base;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;
  ushort tag;
  uint   fake_dst_ip;
  ushort dst_port;
};

typedef struct fd_pktgen_tile_ctx fd_pktgen_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_pktgen_tile_ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_pktgen_tile_ctx_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_pktgen_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( tile->out_cnt==1UL );
  void * out_base   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  void * out_dcache = topo->links[ tile->out_link_id[ 0 ] ].dcache;
  ctx->out_base    = out_base;
  ctx->chunk0      = fd_dcache_compact_chunk0( out_base, out_dcache );
  ctx->wmark       = fd_dcache_compact_wmark( out_base, out_dcache, FD_NET_MTU );
  ctx->chunk       = ctx->chunk0;
  ctx->tag         = 0UL;
  ctx->fake_dst_ip = tile->pktgen.fake_dst_ip;
  ctx->dst_port    = tile->pktgen.dst_port;

  /* Assume dcache was zero initialized */
}

static void
before_credit( fd_pktgen_tile_ctx_t * ctx,
               fd_stem_context_t *    stem,
               int *                  charge_busy ) {
  if( FD_VOLATILE_CONST( fd_pktgen_active )!=1U ) return;

  *charge_busy = 1;

  /* Select an arbitrary public IP as the fake destination.  With TTL=0,
     packets will be dropped at the first hop unless there's a direct L2
     connection to the destination. The net tile, however, needs a valid dst
     IP to select the dst MAC address. */
  ulong sig = fd_disco_netmux_sig( 0U, 0U, ctx->fake_dst_ip, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );

  ulong   chunk = ctx->chunk;
  uchar * frame = fd_chunk_to_laddr( ctx->out_base, chunk );
  ushort  tag   = ctx->tag;

  /* Calculate payload size to make a minimal Ethernet frame */
  ulong   sz         = 64UL;
  ulong   payload_sz = sz - (sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t));

  /* Build Ethernet header */
  fd_eth_hdr_t * eth = (fd_eth_hdr_t *)frame;
  eth->net_type      = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

  /* Build IPv4 header */
  fd_ip4_hdr_t * ip4 = (fd_ip4_hdr_t *)(eth+1);
  ip4->verihl        = FD_IP4_VERIHL( 4, 5 );
  ip4->tos           = 0;
  ip4->net_tot_len   = fd_ushort_bswap( (ushort)(payload_sz-sizeof(fd_eth_hdr_t)) );
  ip4->net_id        = tag; /* unique seq number */
  ip4->net_frag_off  = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
  ip4->ttl           = 0; /* Drop at router to avoid flooding */
  ip4->protocol      = FD_IP4_HDR_PROTOCOL_UDP;
  ip4->daddr         = ctx->fake_dst_ip;
  ip4->check         = 0;
  ip4->check         = fd_ip4_hdr_check_fast( ip4 );

  /* Build UDP header */
  fd_udp_hdr_t * udp = (fd_udp_hdr_t *)(ip4+1);
  udp->net_dport     = fd_ushort_bswap( ctx->dst_port );
  udp->net_len       = fd_ushort_bswap( (ushort)(sizeof(fd_udp_hdr_t) + payload_sz) );
  udp->check         = 0;

  /* Leave payload uninitialized */

  fd_stem_publish( stem, 0UL, sig, chunk, sz, 0UL, 0UL, 0UL );

  /* Wind up for next iteration */
  chunk++; /* Min sz Ethernet frames are exactly FD_CHUNK_SZ */
  chunk      = fd_ulong_if( chunk>ctx->wmark, ctx->chunk0, chunk );
  ctx->tag   = tag+1;
  ctx->chunk = chunk;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE fd_pktgen_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_pktgen_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#define STEM_LAZY ((ulong)1e9) /* max possible */

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_pktgen = {
  .name              = "pktgen",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
