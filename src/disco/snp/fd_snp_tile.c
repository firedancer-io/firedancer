#include "../tiles.h"

#include "generated/fd_snp_tile_seccomp.h"
#include "../topo/fd_pod_format.h"
#include "../shred/fd_shredder.h"
#include "../shred/fd_shred_dest.h"
#include "../shred/fd_fec_resolver.h"
#include "../fd_disco.h"
#include "../../waltz/snp/fd_snp.h"

#include <linux/unistd.h>


#define FD_SNP_TILE_SCRATCH_ALIGN (128UL)

#define IN_KIND_NET      (0UL)
#define IN_KIND_SHRED    (1UL)
#define IN_KIND_GOSSIP   (2UL)
#define IN_KIND_SIGN     (3UL)

/* The order here depends on the order in which fd_topob_tile_out(...)
    are called inside topology.c (in the corresponding folder) */
#define NET_OUT_IDX      (0)
#define SHRED_OUT_IDX    (1)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_snp_in_ctx_t;

typedef struct {

  int              skip_frag;
  ulong            round_robin_id;
  ulong            round_robin_cnt;

  fd_snp_in_ctx_t  in[ 32 ];
  int              in_kind[ 32 ];

  /* Channels */
  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t *      net_out_mem;
  ulong            net_out_chunk0;
  ulong            net_out_wmark;
  ulong            net_out_chunk;

  fd_frag_meta_t * shred_out_mcache;
  ulong *          shred_out_sync;
  ulong            shred_out_depth;
  ulong            shred_out_seq;

  fd_wksp_t *      shred_out_mem;
  ulong            shred_out_chunk0;
  ulong            shred_out_wmark;
  ulong            shred_out_chunk;

  /* SNP */
  uchar            packet[ FD_NET_MTU ];
  ulong            packet_sz;
  fd_snp_t *       snp;

  ushort            net_id;
  fd_ip4_udp_hdrs_t net_hdr[1];

  /* App-specific */
  ulong            shred_cnt;

  /* Metrics */
  struct {
    fd_histf_t contact_info_cnt[ 1 ];
  } metrics[ 1 ];
} fd_snp_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_SNP_TILE_SCRATCH_ALIGN;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) { /* TODO */
  (void) tile;

  fd_snp_limits_t limits = {
    .conn_cnt = 8 // FIXME
  };

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snp_ctx_t),  sizeof(fd_snp_ctx_t)        );
  l = FD_LAYOUT_APPEND( l, fd_snp_align(),         fd_snp_footprint( &limits ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_snp_ctx_t * ctx ) { /* TODO */
  (void)ctx;
}

static inline void
metrics_write( fd_snp_ctx_t * ctx ) {
  /* TODO expand? */
  FD_MHIST_COPY( SHRED, CLUSTER_CONTACT_INFO_CNT, ctx->metrics->contact_info_cnt );
}

static inline int
before_frag( fd_snp_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq,
             ulong            sig ) { /* TODO */
  (void) ctx;
  (void) in_idx;
  (void) seq;
  (void) sig;

  /* TODO: load balance using sig */
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED ) )    return 0;
  else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED; /* TODO change DST_PROTO_SHRED name? */

  return 0;
}

static void
during_frag( fd_snp_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq FD_PARAM_UNUSED,
             ulong          sig FD_PARAM_UNUSED,
             ulong          chunk,
             ulong          sz,
             ulong          ctl FD_PARAM_UNUSED ) {

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_SHRED:
    case IN_KIND_NET: {
      /* Either net and applications are unreliable channels, we copy the incoming packet
         and we'll process it in after_frag. */
      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>sizeof(ctx->packet) ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
              ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      memcpy( ctx->packet, dcache_entry, sz );
      ctx->packet_sz = sz;
    } break;

    case IN_KIND_GOSSIP:
      /* Gossip is a reliable channel, we can process new contacts here */
      break;

    case IN_KIND_SIGN:
      /* Sign is a reliable channel, we can process new signatures here */
      break;
  }
}

static void
after_frag( fd_snp_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               _tspub,
            fd_stem_context_t * stem ) { /* TODO */
  (void) ctx;
  (void) in_idx;
  (void) seq;
  (void) sig;
  (void) sz;
  (void) tsorig;
  (void) _tspub;
  (void) stem;

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_SHRED: {
      /* Process all applications (with multicast) */
      fd_snp_meta_t meta = (fd_snp_meta_t)sig;
      fd_snp_send( ctx->snp, ctx->packet, ctx->packet_sz, meta );

#if 0
      uchar * dst = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
      memcpy( dst, ctx->packet, ctx->packet_sz );
      ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk, ctx->packet_sz, 0UL, tsorig, tspub );
      ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
      ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, ctx->packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
#endif
    } break;

    case IN_KIND_NET: {
      /* Process incoming network packets */

      fd_snp_process_packet( ctx->snp, ctx->packet, ctx->packet_sz );
#if 0
      uchar * dst = fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
      memcpy( dst, ctx->packet, ctx->packet_sz );  
      ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_mcache_publish( ctx->shred_out_mcache, ctx->shred_out_depth, ctx->shred_out_seq, sig, ctx->shred_out_chunk, ctx->packet_sz, 0UL, tsorig, tspub );
      ctx->shred_out_seq   = fd_seq_inc( ctx->shred_out_seq, 1UL );
      ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, ctx->packet_sz, ctx->shred_out_chunk0, ctx->shred_out_wmark );
#endif
    } break;

    case IN_KIND_GOSSIP:
      /* Gossip */
      break;

    case IN_KIND_SIGN:
      /* Sign */
      break;
  }
}

static int
snp_callback_tx( void const *  _ctx,
                 uchar const * packet,
                 ulong         packet_sz,
                 fd_snp_meta_t meta ) {
  fd_snp_ctx_t * ctx = (fd_snp_ctx_t *)_ctx;
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = (ulong)meta; //FIXME: sig should be for net tile

  uint dst_ip;
  ushort dst_port;
  fd_snp_meta_into_parts( NULL, &dst_ip, &dst_port, meta );

  //FIXME: this part should go inside snp_send
  fd_ip4_udp_hdrs_t * hdr  = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *( ctx->net_hdr );
  memset( hdr->eth->dst, 0, 6UL );
  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr  = dst_ip;
  ip4->net_id = fd_ushort_bswap( ctx->net_id++ );
  ip4->check  = 0U;
  ip4->check  = fd_ip4_hdr_check_fast( ip4 );
  hdr->udp->net_dport  = dst_port;
  hdr->udp->net_len    = fd_ushort_bswap( (ushort)(packet_sz - sizeof(fd_ip4_udp_hdrs_t) + sizeof(fd_udp_hdr_t)) );

  uchar * dst = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
  memcpy( dst, packet, packet_sz );
  fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk, packet_sz, 0UL, 0UL /* tsorig */, tspub );
  ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );

  return FD_SNP_SUCCESS;
}

static int
snp_callback_rx( void const *  _ctx,
                 uchar const * packet,
                 ulong         packet_sz,
                 fd_snp_meta_t meta ) {
  fd_snp_ctx_t * ctx = (fd_snp_ctx_t *)_ctx;
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = (ulong)meta;

  //TODO: based on ... (port?) ... we should send it to the correct application, e.g. shred tile

  uchar * dst = fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
  memcpy( dst, packet, packet_sz );  
  fd_mcache_publish( ctx->shred_out_mcache, ctx->shred_out_depth, ctx->shred_out_seq, sig, ctx->shred_out_chunk, packet_sz, 0UL, 0UL /* tsorig */, tspub );
  ctx->shred_out_seq   = fd_seq_inc( ctx->shred_out_seq, 1UL );
  ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, packet_sz, ctx->shred_out_chunk0, ctx->shred_out_wmark );

  return FD_SNP_SUCCESS;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snp_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_snp_ctx_t ), sizeof( fd_snp_ctx_t ) );
  (void) ctx;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_LIKELY( tile->out_cnt==2UL ) ) { /* frankendancer */
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[NET_OUT_IDX]].name,    "snp_net"    ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SHRED_OUT_IDX]].name,  "snp_shred"  ) );
  } else if( FD_LIKELY( tile->out_cnt==2UL ) ) { /* firedancer */
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[NET_OUT_IDX]].name,    "snp_net"    ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SHRED_OUT_IDX]].name,  "snp_shred"  ) );
  } else {
    FD_LOG_ERR(( "snp tile has unexpected cnt of output links %lu", tile->out_cnt ));
  }

  if( FD_UNLIKELY( !tile->out_cnt ) )
    FD_LOG_ERR(( "snp tile has no primary output link" ));

  ulong snp_store_mcache_depth = tile->snp.depth;
  if( topo->links[ tile->out_link_id[ 0 ] ].depth != snp_store_mcache_depth )
    FD_LOG_ERR(( "snp tile out depths are not equal %lu %lu",
                 topo->links[ tile->out_link_id[ 0 ] ].depth, snp_store_mcache_depth ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snp_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_snp_ctx_t ), sizeof( fd_snp_ctx_t ) );

  /* Round robin */
  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;

  /* SNP */
  fd_snp_limits_t limits = {
    .conn_cnt = 8 // FIXME
  };

  void * _snp      = FD_SCRATCH_ALLOC_APPEND( l, fd_snp_align(), fd_snp_footprint( &limits ) );

  fd_snp_t * snp = fd_snp_join( fd_snp_new( _snp, &limits ) );
  snp->cb.ctx = ctx;
  snp->cb.rx = snp_callback_rx;
  snp->cb.tx = snp_callback_tx;
  ctx->snp = snp;

  ctx->net_id   = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->net_hdr, 0, 0, 8003 ); //FIXME: remove / configure by app

  /* Channels */
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY(      !strcmp( link->name, "shred_snp"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SHRED;    /* TODO name should be "net_snp", but that requires changes to src/disco/net/xdp/fd_xdp_tile.c(1193) */
    else if( FD_LIKELY( !strcmp( link->name, "net_shred"   ) ) ) ctx->in_kind[ i ] = IN_KIND_NET;
    else FD_LOG_ERR(( "shred tile has unexpected input link %lu %s", i, link->name ));

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ NET_OUT_IDX ] ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_topo_link_t * shred_out = &topo->links[ tile->out_link_id[ SHRED_OUT_IDX ] ];

  ctx->shred_out_mcache = shred_out->mcache;
  ctx->shred_out_sync   = fd_mcache_seq_laddr( ctx->shred_out_mcache );
  ctx->shred_out_depth  = fd_mcache_depth( ctx->shred_out_mcache );
  ctx->shred_out_seq    = fd_mcache_seq_query( ctx->shred_out_sync );
  ctx->shred_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( shred_out->dcache ), shred_out->dcache );
  ctx->shred_out_mem    = topo->workspaces[ topo->objs[ shred_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->shred_out_wmark  = fd_dcache_compact_wmark ( ctx->shred_out_mem, shred_out->dcache, shred_out->mtu );
  ctx->shred_out_chunk  = ctx->shred_out_chunk0;

  ctx->shred_cnt = 0UL;

  fd_histf_join( fd_histf_new( ctx->metrics->contact_info_cnt,     FD_MHIST_MIN(         SHRED, CLUSTER_CONTACT_INFO_CNT   ),
                                                                   FD_MHIST_MAX(         SHRED, CLUSTER_CONTACT_INFO_CNT   ) ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;
  populate_sock_filter_policy_fd_snp_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snp_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) { /* TODO */
  (void)topo;
  (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (2UL) /* TODO adjust as needed */

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snp_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snp_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snp = {
  .name                     = "snp",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
