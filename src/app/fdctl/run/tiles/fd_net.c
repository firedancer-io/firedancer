#include "tiles.h"

#include <sys/socket.h> /* MSG_DONTWAIT needed before importing the net seccomp filter */
#include "generated/net_seccomp.h"
#include "../../../../tango/quic/fd_quic.h"
#include "../../../../tango/xdp/fd_xdp.h"
#include "../../../../tango/xdp/fd_xsk_private.h"

#include <linux/unistd.h>

#define FD_NET_PORT_ALLOW_CNT (sizeof(((fd_topo_tile_t*)0)->net.allow_ports)/sizeof(((fd_topo_tile_t*)0)->net.allow_ports[ 0 ]))

typedef struct {
  ulong xsk_aio_cnt;
  fd_xsk_aio_t * xsk_aio[ 2 ];

  ulong round_robin_cnt;
  ulong round_robin_id;

  const fd_aio_t * tx;

  uchar frame[ FD_NET_MTU ];

  fd_mux_context_t * mux;

  ushort allow_ports[ FD_NET_PORT_ALLOW_CNT ];

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_net_ctx_t;

typedef struct {
  fd_xsk_t * xsk;
  void *     xsk_aio;

  fd_xsk_t * lo_xsk;
  void *     lo_xsk_aio;
} fd_net_init_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_net_init_ctx_t ), sizeof( fd_net_init_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_net_ctx_t ),      sizeof( fd_net_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_aio_align(),               fd_aio_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_xsk_align(),               fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) );
  l = FD_LAYOUT_APPEND( l, fd_xsk_aio_align(),           fd_xsk_aio_footprint( tile->net.xdp_tx_queue_size, tile->net.xdp_aio_depth ) );
  if( FD_UNLIKELY( strcmp( tile->net.interface, "lo" ) && !tile->kind_id ) ) {
    l = FD_LAYOUT_APPEND( l, fd_xsk_align(),     fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) );
    l = FD_LAYOUT_APPEND( l, fd_xsk_aio_align(), fd_xsk_aio_footprint( tile->net.xdp_tx_queue_size, tile->net.xdp_aio_depth ) );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  ulong net_init = fd_ulong_align_up( (ulong)scratch, alignof( fd_net_init_ctx_t ) );
  return (void*)fd_ulong_align_up( net_init + sizeof( fd_net_init_ctx_t ), alignof( fd_net_ctx_t ) );
}

/* net_rx_aio_send is a callback invoked by aio when new data is
   received on an incoming xsk.  The xsk might be bound to any interface
   or ports, so the purpose of this callback is to determine if the
   packet might be a valid transaction, and whether it is QUIC or
   non-QUIC (raw UDP) before forwarding to the appropriate handler.

   This callback is supposed to return the number of packets in the
   batch which were successfully processed, but we always return
   batch_cnt since there is no logic in place to backpressure this far
   up the stack, and there is no sane way to "not handle" an incoming
   packet. */
static int
net_rx_aio_send( void *                    _ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush ) {
  (void)flush;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    uchar const * packet = batch[i].buf;
    uchar const * packet_end = packet + batch[i].buf_sz;

    if( FD_UNLIKELY( batch[i].buf_sz > FD_NET_MTU ) )
      FD_LOG_ERR(( "received a UDP packet with a too large payload (%u)", batch[i].buf_sz ));

    uchar const * iphdr = packet + 14U;

    /* Filter for UDP/IPv4 packets. Test for ethtype and ipproto in 1
       branch */
    uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
    if( FD_UNLIKELY( test_ethip!=0x080011 ) )
      FD_LOG_ERR(( "Firedancer received a packet from the XDP program that was either "
                   "not an IPv4 packet, or not a UDP packet. It is likely your XDP program "
                   "is not configured correctly." ));

    /* IPv4 is variable-length, so lookup IHL to find start of UDP */
    uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
    uchar const * udp = iphdr + iplen;

    /* Ignore if UDP header is too short */
    if( FD_UNLIKELY( udp+8U > packet_end ) ) continue;

    /* Extract IP dest addr and UDP dest port */
    uint ip_srcaddr    =                  *(uint   *)( iphdr+12UL );
    ushort udp_dstport = fd_ushort_bswap( *(ushort *)( udp+2UL    ) );

    int allow_port = 0;
    for( ulong i=0UL; i<FD_NET_PORT_ALLOW_CNT; i++ ) allow_port |= udp_dstport==ctx->allow_ports[ i ];
    if( FD_UNLIKELY( !allow_port ) )
      FD_LOG_ERR(( "Firedancer received a UDP packet on port %hu which was not expected. "
                   "Only ports %hu, %hu, and %hu should be configured to forward packets. Do "
                   "you need to reload the XDP program?",
                   udp_dstport, ctx->allow_ports[ 0 ], ctx->allow_ports[ 1 ], ctx->allow_ports[ 2 ] ));

    fd_memcpy( fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk ), packet, batch[i].buf_sz );

    /* tile can decide how to partition based on src ip addr and port */
    ulong sig = fd_disco_netmux_sig( ip_srcaddr, udp_dstport, 14UL+8UL+iplen, SRC_TILE_NET, 0 );

    ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mux_publish( ctx->mux, sig, ctx->out_chunk, batch[i].buf_sz, 0, 0, tspub );

    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, FD_NET_MTU, ctx->out_chunk0, ctx->out_wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

static void
before_credit( void * _ctx,
               fd_mux_context_t * mux ) {
  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  ctx->mux = mux;

  for( ulong i=0; i<ctx->xsk_aio_cnt; i++ ) {
    fd_xsk_aio_service( ctx->xsk_aio[i] );
  }
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  ushort src_tile = fd_disco_netmux_sig_src_tile( sig );

  /* round robin by sequence number for now, quic should be modified to
     echo the net tile index back so we can transmit on the same queue */
  int handled_packet = (seq % ctx->round_robin_cnt) == ctx->round_robin_id;
  if( FD_UNLIKELY( src_tile == SRC_TILE_NET || !handled_packet ) ) {
    *opt_filter = 1;
  }
}

static void
during_frag( void * _ctx,
             ulong in_idx,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  (void)in_idx;
  (void)sig;
  (void)opt_filter;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
  fd_memcpy( ctx->frame, src, sz ); // TODO: Change xsk_aio interface to eliminate this copy
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_filter;
  (void)mux;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  fd_aio_pkt_info_t aio_buf = { .buf = ctx->frame, .buf_sz = (ushort)*opt_sz };
  ctx->tx->send_func( ctx->xsk_aio[ 0 ], &aio_buf, 1, NULL, 1 );

  *opt_filter = 1;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_init_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_init_ctx_t ), sizeof( fd_net_init_ctx_t ) );

  /* Initialize XSK and xsk_aio which requires being privileged. */
  void * xsk = fd_xsk_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_align(), fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) ),
                           FD_NET_MTU,
                           tile->net.xdp_rx_queue_size,
                           tile->net.xdp_rx_queue_size,
                           tile->net.xdp_tx_queue_size,
                           tile->net.xdp_tx_queue_size );
  if( FD_UNLIKELY( !fd_xsk_bind( xsk, tile->net.app_name, tile->net.interface, (uint)tile->kind_id ) ) )
    FD_LOG_ERR(( "failed to bind xsk for net tile %lu", tile->kind_id ));

  ctx->xsk = fd_xsk_join( xsk );
  if( FD_UNLIKELY( !ctx->xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

  ctx->xsk_aio = fd_xsk_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_aio_align(), fd_xsk_aio_footprint( tile->net.xdp_tx_queue_size, tile->net.xdp_aio_depth ) ),
                                 tile->net.xdp_tx_queue_size,
                                 tile->net.xdp_aio_depth );
  if( FD_UNLIKELY( !ctx->xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_new failed" ));

  /* Networking tile at index 0 also binds to loopback (only queue 0 available on lo) */
  ctx->lo_xsk     = NULL;
  ctx->lo_xsk_aio = NULL;
  if( FD_UNLIKELY( strcmp( tile->net.interface, "lo" ) && !tile->kind_id ) ) {
    void * lo_xsk = fd_xsk_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_align(), fd_xsk_footprint( FD_NET_MTU, tile->net.xdp_rx_queue_size, tile->net.xdp_rx_queue_size, tile->net.xdp_tx_queue_size, tile->net.xdp_tx_queue_size ) ),
                                FD_NET_MTU,
                                tile->net.xdp_rx_queue_size,
                                tile->net.xdp_rx_queue_size,
                                tile->net.xdp_tx_queue_size,
                                tile->net.xdp_tx_queue_size );
    if( FD_UNLIKELY( !fd_xsk_bind( lo_xsk, tile->net.app_name, "lo", (uint)tile->kind_id ) ) )
      FD_LOG_ERR(( "failed to bind lo_xsk for net tile %lu", tile->kind_id ));

    ctx->lo_xsk = fd_xsk_join( lo_xsk );
    if( FD_UNLIKELY( !ctx->lo_xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

    ctx->lo_xsk_aio = fd_xsk_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_aio_align(), fd_xsk_aio_footprint( tile->net.xdp_tx_queue_size, tile->net.xdp_aio_depth ) ),
                                      tile->net.xdp_tx_queue_size,
                                      tile->net.xdp_aio_depth );
    if( FD_UNLIKELY( !ctx->lo_xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_new failed" ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_init_ctx_t * init_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_init_ctx_t ), sizeof( fd_net_init_ctx_t ) );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );
  fd_aio_t * net_rx_aio = fd_aio_join( fd_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_aio_align(), fd_aio_footprint() ), ctx, net_rx_aio_send ) );
  if( FD_UNLIKELY( !net_rx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  ctx->round_robin_cnt = fd_topo_tile_kind_cnt( topo, tile->kind );
  ctx->round_robin_id  = tile->kind_id;

  ctx->xsk_aio_cnt = 1;
  ctx->xsk_aio[ 0 ] = fd_xsk_aio_join( init_ctx->xsk_aio, init_ctx->xsk );
  if( FD_UNLIKELY( !ctx->xsk_aio[ 0 ] ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));
  fd_xsk_aio_set_rx( ctx->xsk_aio[ 0 ], net_rx_aio );
  if( FD_UNLIKELY( init_ctx->lo_xsk ) ) {
    ctx->xsk_aio[ 1 ] = fd_xsk_aio_join( init_ctx->lo_xsk_aio, init_ctx->lo_xsk );
    if( FD_UNLIKELY( !ctx->xsk_aio[ 1 ] ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));
    fd_xsk_aio_set_rx( ctx->xsk_aio[ 1 ], net_rx_aio );
    ctx->xsk_aio_cnt = 2;
  }
  ctx->tx = fd_xsk_aio_get_tx( init_ctx->xsk_aio );

  for( ulong i=0UL; i<FD_NET_PORT_ALLOW_CNT; i++ ) {
    if( FD_UNLIKELY( !tile->net.allow_ports[ i ] ) ) FD_LOG_ERR(( "net tile listen port %lu was 0", i ));
    ctx->allow_ports[ i ] = tile->net.allow_ports[ i ];
  }

  /* Put a bound on chunks we read from the input, to make sure they
      are within in the data region of the workspace. */
  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "net tile in link cnt is zero" ));
  fd_topo_link_t * link0 = &topo->links[ tile->in_link_id[ 0 ] ];

  for( ulong i=1; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];

    if( FD_UNLIKELY( link0->wksp_id != link->wksp_id ) ) FD_LOG_ERR(( "net tile reads input from multiple workspaces" ));
    if( FD_UNLIKELY( link0->mtu != link->mtu         ) ) FD_LOG_ERR(( "net tile reads input from multiple links with different MTUs" ));
  }

  ctx->in_mem    = topo->workspaces[ link0->wksp_id ].wksp;
  ctx->in_chunk0 = fd_disco_compact_chunk0( ctx->in_mem );
  ctx->in_wmark  = fd_disco_compact_wmark ( ctx->in_mem, link0->mtu );

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
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_init_ctx_t * init_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_init_ctx_t ), sizeof( fd_net_init_ctx_t ) );

  /* A bit of a hack, if there is no loopback XSK for this tile, we still need to pass
     two "allow" FD arguments to the net policy, so we just make them both the same. */
  int allow_fd2 = init_ctx->lo_xsk ? init_ctx->lo_xsk->xsk_fd : init_ctx->xsk->xsk_fd;
  FD_TEST( init_ctx->xsk->xsk_fd >= 0 && allow_fd2 >= 0 );
  populate_sock_filter_policy_net( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)init_ctx->xsk->xsk_fd, (uint)allow_fd2 );
  return sock_filter_policy_net_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_init_ctx_t * init_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_init_ctx_t ), sizeof( fd_net_init_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt < 4 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = init_ctx->xsk->xsk_fd;
  if( FD_UNLIKELY( init_ctx->lo_xsk ) )
    out_fds[ out_cnt++ ] = init_ctx->lo_xsk->xsk_fd;
  return out_cnt;
}

fd_tile_config_t fd_tile_net = {
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_credit        = before_credit,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
