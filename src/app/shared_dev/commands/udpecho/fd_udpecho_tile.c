/* fd_udpecho_tile mirrors incoming UDP packets back to the source.
   Useful for testing connectivity issues, but somewhat dangerous to run
   in prod on the Internet. */

#include "../../../../disco/topo/fd_topo.h"

struct fd_udpecho_tile_ctx {
  void * in_base;
  void * out_base;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;
  ulong  pkt_sz;
  uint   ip4_dst;
};

typedef struct fd_udpecho_tile_ctx fd_udpecho_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_udpecho_tile_ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_udpecho_tile_ctx_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_udpecho_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_TEST( tile->out_cnt==1UL );
  void * out_base   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  void * out_dcache = topo->links[ tile->out_link_id[ 0 ] ].dcache;
  ctx->out_base    = out_base;
  ctx->chunk0      = fd_dcache_compact_chunk0( out_base, out_dcache );
  ctx->wmark       = fd_dcache_compact_wmark( out_base, out_dcache, FD_NET_MTU );
  ctx->chunk       = ctx->chunk0;

  FD_TEST( tile->in_cnt==1UL );
  void * in_base = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->in_base = in_base;
}

static inline void
during_frag( fd_udpecho_tile_ctx_t * ctx,
             ulong                   in_idx FD_PARAM_UNUSED,
             ulong                   seq,
             ulong                   sig    FD_PARAM_UNUSED,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl ) {
  FD_TEST( sz<=FD_NET_MTU );
  ctx->pkt_sz = 0;

  ulong const minsz = sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( sz<minsz ) ) return;

  uchar      * frame_out = /*           */fd_chunk_to_laddr      ( ctx->out_base, ctx->chunk );
  void const * frame_in  = (uchar const *)fd_chunk_to_laddr_const( ctx->in_base,  chunk ) + ctl;

  fd_eth_hdr_t const * eth_hdr_in = fd_type_pun_const( frame_in );
  if( FD_UNLIKELY( fd_ushort_bswap( eth_hdr_in->net_type )!=FD_ETH_HDR_TYPE_IP ) ) return;

  fd_ip4_hdr_t const * ip4_hdr_in = fd_type_pun_const( (eth_hdr_in+1) );
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4_hdr_in )!=4 ) ) return;
  ulong ip4_len = FD_IP4_GET_LEN( *ip4_hdr_in );
  ulong ip4_sz  = fd_ushort_bswap( ip4_hdr_in->net_tot_len );
  sz = fd_ulong_min( sz, ip4_sz+sizeof(fd_eth_hdr_t) );
  if( FD_UNLIKELY( sz < sizeof(fd_eth_hdr_t)+ip4_len+sizeof(fd_udp_hdr_t) ) ) return;
  if( FD_UNLIKELY( ip4_hdr_in->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) return;

  fd_udp_hdr_t const * udp_hdr_in = fd_type_pun_const( (ip4_hdr_in+1) );
  if( FD_UNLIKELY( fd_ushort_bswap( udp_hdr_in->net_len )<sizeof(fd_udp_hdr_t) ) ) return;
  ulong const udp_len = fd_ushort_bswap( udp_hdr_in->net_len );
  if( FD_UNLIKELY( udp_len<sizeof(fd_udp_hdr_t) ) ) return;

  void const * dgram_in = (udp_hdr_in+1);
  ulong const  dgram_sz = udp_len-sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( (ulong)dgram_in+dgram_sz > (ulong)frame_in+sz ) ) return;

  fd_eth_hdr_t eth_hdr_out = {
    .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP )
  };
  FD_STORE( fd_eth_hdr_t, frame_out, eth_hdr_out );
  fd_ip4_hdr_t ip4_hdr = {
    .verihl       = FD_IP4_VERIHL( 4, 5 ),
    .net_tot_len  = fd_ushort_bswap( (ushort)( 28+dgram_sz ) ),
    .net_id       = fd_ushort_bswap( (ushort)seq ),
    .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
    .ttl          = 64,
    .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
    .saddr        = ip4_hdr_in->daddr,
    .daddr        = ip4_hdr_in->saddr,
  };
  ip4_hdr.check = fd_ip4_hdr_check_fast( &ip4_hdr );
  ctx->ip4_dst = ip4_hdr.daddr;
  FD_STORE( fd_ip4_hdr_t, frame_out+14, ip4_hdr );

  fd_udp_hdr_t udp_hdr = {
    .net_sport = udp_hdr_in->net_dport,
    .net_dport = udp_hdr_in->net_sport,
    .net_len   = udp_hdr_in->net_len
  };
  FD_STORE( fd_udp_hdr_t, frame_out+34, udp_hdr );

  fd_memcpy( frame_out+42, dgram_in, dgram_sz );
  ctx->pkt_sz = 42+dgram_sz;
}

static inline void
after_frag( fd_udpecho_tile_ctx_t * ctx,
            ulong                   in_idx FD_PARAM_UNUSED,
            ulong                   in_seq FD_PARAM_UNUSED,
            ulong                   in_sig FD_PARAM_UNUSED,
            ulong                   in_sz  FD_PARAM_UNUSED,
            ulong                   in_tsorig,
            ulong                   in_tspub FD_PARAM_UNUSED,
            fd_stem_context_t *     stem ) {
  ulong out_sig   = fd_disco_netmux_sig( 0U, 0, ctx->ip4_dst, DST_PROTO_OUTGOING, 42 );
  ulong out_chunk = ctx->chunk;
  ulong out_sz    = ctx->pkt_sz;
  fd_stem_publish( stem, 0UL, out_sig, out_chunk, out_sz, 0, in_tsorig, 0UL );
  ctx->chunk = fd_dcache_compact_next( out_chunk, out_sz, ctx->chunk0, ctx->wmark );
}

#define STEM_BURST (1UL)
#define STEM_LAZY ((long)10e6)

#define STEM_CALLBACK_CONTEXT_TYPE fd_udpecho_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_udpecho_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_udpecho = {
  .name              = "l4swap",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
