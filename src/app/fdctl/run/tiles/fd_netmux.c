#include "tiles.h"

#include "generated/netmux_seccomp.h"
#include <linux/unistd.h>


typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_netmux_in_ctx_t;

typedef struct {
  fd_netmux_in_ctx_t in[ 32 ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_netmux_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_netmux_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_netmux_ctx_t ), sizeof( fd_netmux_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_netmux_ctx_t ) );
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_netmux_ctx_t * ctx = (fd_netmux_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );


  fd_memcpy( dst, src, sz );

  uchar * packet = dst;
  uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
  if( FD_UNLIKELY( test_ethip!=0x080011 ) ) {
    FD_LOG_WARNING(("E: %lu %lu %lu %u", sz, sig, in_idx, fd_disco_netmux_sig_src_tile(sig) ));
    FD_LOG_HEXDUMP_WARNING(("HEY3", packet, sz));
    FD_LOG_ERR(( "Firedancer received a packet from the XDP program that was either "
                  "not an IPv4 packet, or not a UDP packet. It is likely your XDP program "
                  "is not configured correctly." ));
    
  }
}

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int   *            opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_tsorig;
  (void)mux;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_filter;

  fd_netmux_ctx_t * ctx = (fd_netmux_ctx_t *)_ctx;

  uchar * packet = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  /* Filter for UDP/IPv4 packets. Test for ethtype and ipproto in 1
      branch */

  uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
  if( FD_UNLIKELY( test_ethip!=0x080011 ) ) {
    FD_LOG_WARNING(("C: %lu %lu %lu", *opt_sz, *opt_sig, in_idx ));
    FD_LOG_HEXDUMP_WARNING(("HEY2", packet, *opt_sz));
    FD_LOG_ERR(( "Firedancer received a packet from the XDP program that was either "
                  "not an IPv4 packet, or not a UDP packet. It is likely your XDP program "
                  "is not configured correctly." ));
    
  }
  
  ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mux_publish( mux, *opt_sig, ctx->out_chunk, *opt_sz, 0, 0, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, *opt_sz, ctx->out_chunk0, ctx->out_wmark );
}

// static inline void
// during_housekeeping( void * _ctx ) {
//   fd_netmux_ctx_t * ctx = (fd_netmux_ctx_t *)_ctx;

//   fd_mux
// }

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_netmux_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_netmux_ctx_t ), sizeof( fd_netmux_ctx_t ) );

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ link->wksp_id ];

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_netmux( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_netmux_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_tile_config_t fd_tile_netmux = {
  .mux_flags                = FD_MUX_FLAG_DEFAULT,
  .burst                    = 1UL,
  .mux_ctx                  = NULL,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = NULL,
  .scratch_footprint        = NULL,
  .privileged_init          = NULL,
  .unprivileged_init        = NULL,
};
