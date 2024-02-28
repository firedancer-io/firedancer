#include "fd_net_tile.h"

#include <sys/socket.h> /* MSG_DONTWAIT needed before importing the net seccomp filter */
#include "generated/fd_net_tile_seccomp.h"

#include <linux/unistd.h>

struct fd_net_tile_init {
  fd_xsk_t * xsk;
  void *     xsk_aio;

  fd_xsk_t * lo_xsk;
  void *     lo_xsk_aio;

  fd_ip_t *  ip;
};

typedef struct fd_net_tile_init fd_net_tile_init_t;

FD_FN_CONST inline ulong
fd_net_tile_align( void ) {
  return FD_NET_TILE_ALIGN;
}

FD_FN_PURE inline ulong
fd_net_tilefootprint( fd_net_tile_args_t const * args ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_net_tile_t ),      sizeof( fd_net_tile_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_net_tile_init_t ), sizeof( fd_net_tile_init_t ) );
  l = FD_LAYOUT_APPEND( l, fd_aio_align(),                fd_aio_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_xsk_align(),                fd_xsk_footprint( FD_NET_MTU, args->xdp_rx_queue_size, args->xdp_rx_queue_size, args->xdp_tx_queue_size, args->xdp_tx_queue_size ) );
  l = FD_LAYOUT_APPEND( l, fd_xsk_aio_align(),            fd_xsk_aio_footprint( args->xdp_tx_queue_size, args->xdp_aio_depth ) );
  if( FD_UNLIKELY( strcmp( args->interface, "lo" ) && !args->tidx ) ) {
    l = FD_LAYOUT_APPEND( l, fd_xsk_align(),     fd_xsk_footprint( FD_NET_MTU, args->xdp_rx_queue_size, args->xdp_rx_queue_size, args->xdp_tx_queue_size, args->xdp_tx_queue_size ) );
    l = FD_LAYOUT_APPEND( l, fd_xsk_aio_align(), fd_xsk_aio_footprint( args->xdp_tx_queue_size, args->xdp_aio_depth ) );
  }
  l = FD_LAYOUT_APPEND( l, fd_ip_align(), fd_ip_footprint( 0U, 0U ) );
  return FD_LAYOUT_FINI( l, fd_net_tile_align() );
}

ulong
fd_net_tile_seccomp_policy( void *               shnet,
                            struct sock_filter * out,
                            ulong                out_cnt ) {
  FD_SCRATCH_ALLOC_INIT( l, shnet );
  FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_t ), sizeof( fd_net_tile_t ) );
  fd_net_tile_init_t * init_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_init_t ), sizeof( fd_net_tile_init_t ) );

  /* A bit of a hack, if there is no loopback XSK for this tile, we still need to pass
     two "allow" FD arguments to the net policy, so we just make them both the same. */
  int allow_fd2 = init_ctx->lo_xsk ? init_ctx->lo_xsk->xsk_fd : init_ctx->xsk->xsk_fd;
  FD_TEST( init_ctx->xsk->xsk_fd >= 0 && allow_fd2 >= 0 );
  int netlink_fd = fd_ip_netlink_get( init_ctx->ip )->fd;
  populate_sock_filter_policy_fd_net_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)init_ctx->xsk->xsk_fd, (uint)allow_fd2, (uint)netlink_fd );
  return sock_filter_policy_fd_net_tile_instr_cnt;
}

ulong
fd_net_tile_allowed_fds( void * shnet,
                         int *  out,
                         ulong  out_cnt ) {
  FD_SCRATCH_ALLOC_INIT( l, shnet );
  FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_t ), sizeof( fd_net_tile_t ) );
  fd_net_tile_init_t * init_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_init_t ), sizeof( fd_net_tile_init_t ) );

  if( FD_UNLIKELY( out_cnt<5UL ) ) FD_LOG_ERR(( "out_cnt %lu", out_cnt ));

  ulong out_idx = 0;
  out[ out_idx++ ] = 2; /* stderr */
  out[ out_idx++ ] = init_ctx->xsk->xsk_fd;
  out[ out_idx++ ] = fd_ip_netlink_get( init_ctx->ip )->fd;

  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out[ out_idx++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_UNLIKELY( init_ctx->lo_xsk ) ) out[ out_idx++ ] = init_ctx->lo_xsk->xsk_fd;
  return out_idx;
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

  fd_net_tile_t * ctx = (fd_net_tile_t *)_ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    uchar const * packet = batch[i].buf;
    uchar const * packet_end = packet + batch[i].buf_sz;

    if( FD_UNLIKELY( batch[i].buf_sz>FD_NET_MTU ) )
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
    for( ulong i=0UL; i<FD_NET_TILE_PORT_ALLOW_CNT; i++ ) allow_port |= udp_dstport==ctx->allow_ports[ i ];
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
before_credit( void *             _ctx,
               fd_mux_context_t * mux ) {
  fd_net_tile_t * ctx = (fd_net_tile_t *)_ctx;

  ctx->mux = mux;

  for( ulong i=0; i<ctx->xsk_aio_cnt; i++ ) {
    fd_xsk_aio_service( ctx->xsk_aio[i] );
  }
}

static void
during_housekeeping( void * _ctx ) {
  fd_net_tile_t * ctx = (fd_net_tile_t *)_ctx;

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now > ctx->ip_next_upd ) ) {
    ctx->ip_next_upd = now + (long)60e9;
    fd_ip_arp_fetch( ctx->ip );
    fd_ip_route_fetch( ctx->ip );
  }
}

FD_FN_PURE static int
route_loopback( uint  tile_ip_addr,
                ulong sig ) {
  return fd_disco_netmux_sig_ip_addr( sig )==FD_IP4_ADDR(127,0,0,1) ||
    fd_disco_netmux_sig_ip_addr( sig )==tile_ip_addr;
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;

  fd_net_tile_t * ctx = (fd_net_tile_t *)_ctx;

  ushort src_tile = fd_disco_netmux_sig_src_tile( sig );

  /* Round robin by sequence number for now, QUIC should be modified to
     echo the net tile index back so we can transmit on the same queue.

     127.0.0.1 packets for localhost must go out on net tile 0 which
     owns the loopback interface XSK, which only has 1 queue. */
  int handled_packet = 0;
  if( FD_UNLIKELY( route_loopback( ctx->src_ip_addr, sig ) ) ) {
    handled_packet = ctx->round_robin_id == 0;
  } else {
    handled_packet = (seq % ctx->round_robin_cnt) == ctx->round_robin_id;
  }

  if( FD_UNLIKELY( src_tile==SRC_TILE_NET || !handled_packet ) ) {
    *opt_filter = 1;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_net_tile_t * ctx = (fd_net_tile_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
  fd_memcpy( ctx->frame, src, sz ); // TODO: Change xsk_aio interface to eliminate this copy
}

static void
send_arp_probe( fd_net_tile_t * ctx,
                uint            dst_ip_addr,
                uint            ifindex ) {
  uchar          arp_buf[ FD_IP_ARP_SZ ];
  ulong          arp_len = 0UL;

  uint           src_ip_addr  = ctx->src_ip_addr;
  uchar *        src_mac_addr = ctx->src_mac_addr;

  /* prepare arp table */
  int arp_table_rtn = fd_ip_update_arp_table( ctx->ip, dst_ip_addr, ifindex );

  if( FD_UNLIKELY( arp_table_rtn==FD_IP_SUCCESS ) ) {
    /* generate a probe */
    fd_ip_arp_gen_arp_probe( arp_buf, FD_IP_ARP_SZ, &arp_len, dst_ip_addr, fd_uint_bswap( src_ip_addr ), src_mac_addr );

    /* send the probe */
    fd_aio_pkt_info_t aio_buf = { .buf = arp_buf, .buf_sz = (ushort)arp_len };
    ctx->tx->send_func( ctx->xsk_aio[ 0 ], &aio_buf, 1, NULL, 1 );
  }
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_tsorig;
  (void)opt_filter;
  (void)mux;

  fd_net_tile_t * ctx = (fd_net_tile_t *)_ctx;

  fd_aio_pkt_info_t aio_buf = { .buf = ctx->frame, .buf_sz = (ushort)*opt_sz };
  if( FD_UNLIKELY( route_loopback( ctx->src_ip_addr, *opt_sig ) ) ) {
    ctx->lo_tx->send_func( ctx->xsk_aio[ 1 ], &aio_buf, 1, NULL, 1 );
  } else {
    /* extract dst ip */
    uint dst_ip = fd_uint_bswap( fd_disco_netmux_sig_ip_addr( *opt_sig ) );

    uint  next_hop    = 0U;
    uchar dst_mac[6]  = {0};
    uint  if_idx      = 0;

    /* route the packet */
    /*
     * determine the destination:
     *   same host
     *   same subnet
     *   other
     * determine the next hop
     *   localhost
     *   gateway
     *   subnet local host
     * determine the mac address of the next hop address
     *   and the local ipv4 and eth addresses */
    int rtn = fd_ip_route_ip_addr( dst_mac, &next_hop, &if_idx, ctx->ip, dst_ip );
    if( FD_UNLIKELY( rtn == FD_IP_PROBE_RQD ) ) {
      /* another fd_net instance might have already resolved this address
         so simply try another fetch */
      fd_ip_arp_fetch( ctx->ip );
      rtn = fd_ip_route_ip_addr( dst_mac, &next_hop, &if_idx, ctx->ip, dst_ip );
    }

    long now;
    switch( rtn ) {
      case FD_IP_PROBE_RQD:
        /* TODO possibly buffer some data while waiting for ARPs to complete */
        /* TODO rate limit ARPs */
        /* TODO add caching of ip_dst -> routing info */
        send_arp_probe( ctx, next_hop, if_idx );

        /* refresh tables */
        now = fd_log_wallclock();
        ctx->ip_next_upd = now + (long)200e3;
        break;
      case FD_IP_NO_ROUTE:
        /* cannot make progress here */
        break;
      case FD_IP_SUCCESS:
        /* set destination mac address */
        memcpy( ctx->frame, dst_mac, 6UL );

        /* set source mac address */
        memcpy( ctx->frame + 6UL, ctx->src_mac_addr, 6UL );

        ctx->tx->send_func( ctx->xsk_aio[ 0 ], &aio_buf, 1, NULL, 1 );
        break;
      case FD_IP_RETRY:
        /* refresh tables */
        now = fd_log_wallclock();
        ctx->ip_next_upd = now + (long)200e3;
        /* TODO consider buffering */
        break;
      case FD_IP_MULTICAST:
      case FD_IP_BROADCAST:
      default:
        /* should not occur in current use cases */
        break;
    }
  }

  *opt_filter = 1;
}

void
fd_net_tile_join_privileged( void *                     shnet,
                        fd_net_tile_args_t const * args ) {
  FD_SCRATCH_ALLOC_INIT( l, shnet );
  FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_t ), sizeof( fd_net_tile_t ) );
  fd_net_tile_init_t * init_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_init_t ), sizeof( fd_net_tile_init_t ) );

  /* Initialize XSK and xsk_aio which requires being privileged. */
  void * xsk = fd_xsk_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_align(), fd_xsk_footprint( FD_NET_MTU, args->xdp_rx_queue_size, args->xdp_rx_queue_size, args->xdp_tx_queue_size, args->xdp_tx_queue_size ) ),
                           FD_NET_MTU,
                           args->xdp_rx_queue_size,
                           args->xdp_rx_queue_size,
                           args->xdp_tx_queue_size,
                           args->xdp_tx_queue_size );
  if( FD_UNLIKELY( !fd_xsk_bind( xsk, args->app_name, args->interface, (uint)args->tidx ) ) )
    FD_LOG_ERR(( "failed to bind xsk for net tile %lu", args->tidx ));

  init_ctx->xsk = fd_xsk_join( xsk );
  if( FD_UNLIKELY( !init_ctx->xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

  init_ctx->xsk_aio = fd_xsk_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_aio_align(), fd_xsk_aio_footprint( args->xdp_tx_queue_size, args->xdp_aio_depth ) ),
                                      args->xdp_tx_queue_size,
                                      args->xdp_aio_depth );
  if( FD_UNLIKELY( !init_ctx->xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_new failed" ));

  /* Networking tile at index 0 also binds to loopback (only queue 0 available on lo) */
  init_ctx->lo_xsk     = NULL;
  init_ctx->lo_xsk_aio = NULL;
  if( FD_UNLIKELY( strcmp( args->interface, "lo" ) && !args->tidx ) ) {
    void * lo_xsk = fd_xsk_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_align(), fd_xsk_footprint( FD_NET_MTU, args->xdp_rx_queue_size, args->xdp_rx_queue_size, args->xdp_tx_queue_size, args->xdp_tx_queue_size ) ),
                                FD_NET_MTU,
                                args->xdp_rx_queue_size,
                                args->xdp_rx_queue_size,
                                args->xdp_tx_queue_size,
                                args->xdp_tx_queue_size );
    if( FD_UNLIKELY( !fd_xsk_bind( lo_xsk, args->app_name, "lo", (uint)args->tidx ) ) )
      FD_LOG_ERR(( "failed to bind lo_xsk for net tile %lu", args->tidx ));

    init_ctx->lo_xsk = fd_xsk_join( lo_xsk );
    if( FD_UNLIKELY( !init_ctx->lo_xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

    init_ctx->lo_xsk_aio = fd_xsk_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_xsk_aio_align(), fd_xsk_aio_footprint( args->xdp_tx_queue_size, args->xdp_aio_depth ) ),
                                           args->xdp_tx_queue_size,
                                           args->xdp_aio_depth );
    if( FD_UNLIKELY( !init_ctx->lo_xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_new failed" ));
  }

  /* init fd_ip */
  init_ctx->ip = fd_ip_join( fd_ip_new( FD_SCRATCH_ALLOC_APPEND( l, fd_ip_align(), fd_ip_footprint( 0UL, 0UL ) ), 0UL, 0UL ) );
}

fd_net_tile_t *
fd_net_tile_join( void *                     shnet,
                  fd_net_tile_args_t const * args,
                  fd_net_tile_topo_t const * topo ) {
  FD_SCRATCH_ALLOC_INIT( l, shnet );
  fd_net_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_t ), sizeof( fd_net_tile_t ) );
  fd_net_tile_init_t * init_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_tile_init_t ), sizeof( fd_net_tile_init_t ) );
  fd_aio_t * net_rx_aio = fd_aio_join( fd_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_aio_align(), fd_aio_footprint() ), ctx, net_rx_aio_send ) );
  if( FD_UNLIKELY( !net_rx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  ctx->round_robin_cnt = args->round_robin_cnt;
  ctx->round_robin_id  = args->tidx;

  ctx->xsk_aio_cnt = 1;
  ctx->xsk_aio[ 0 ] = fd_xsk_aio_join( init_ctx->xsk_aio, init_ctx->xsk );
  if( FD_UNLIKELY( !ctx->xsk_aio[ 0 ] ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));
  fd_xsk_aio_set_rx( ctx->xsk_aio[ 0 ], net_rx_aio );
  ctx->tx = fd_xsk_aio_get_tx( init_ctx->xsk_aio );
  if( FD_UNLIKELY( init_ctx->lo_xsk ) ) {
    ctx->xsk_aio[ 1 ] = fd_xsk_aio_join( init_ctx->lo_xsk_aio, init_ctx->lo_xsk );
    if( FD_UNLIKELY( !ctx->xsk_aio[ 1 ] ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));
    fd_xsk_aio_set_rx( ctx->xsk_aio[ 1 ], net_rx_aio );
    ctx->lo_tx = fd_xsk_aio_get_tx( init_ctx->lo_xsk_aio );
    ctx->xsk_aio_cnt = 2;
  }

  ctx->src_ip_addr = args->src_ip_addr;
  memcpy( ctx->src_mac_addr, args->src_mac_addr, 6UL );

  for( ulong i=0UL; i<FD_NET_TILE_PORT_ALLOW_CNT; i++ ) {
    if( FD_UNLIKELY( !args->allow_ports[ i ] ) ) FD_LOG_ERR(( "net tile listen port %lu was 0", i ));
    ctx->allow_ports[ i ] = args->allow_ports[ i ];
  }

  /* Put a bound on chunks we read from the input, to make sure they
      are within in the data region of the workspace. */

  ctx->in_mem    = topo->in_wksp;
  ctx->in_chunk0 = fd_disco_compact_chunk0( ctx->in_mem );
  ctx->in_wmark  = fd_disco_compact_wmark ( ctx->in_mem, topo->in_mtu );

  ctx->out_mem    = topo->out_wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->out_dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->out_dcache, topo->out_mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ctx->ip = init_ctx->ip;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)ctx + fd_net_tile_footprint( args ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)ctx - fd_net_tile_footprint( args ), scratch_top, (ulong)ctx + fd_net_tile_footprint( args ) ));
  
  return ctx;
}

void
fd_net_tile_run( fd_net_tile_t *         ctx,
                 fd_cnc_t *              cnc,
                 ulong                   in_cnt,
                 fd_frag_meta_t const ** in_mcache,
                 ulong **                in_fseq,
                 fd_frag_meta_t *        mcache,
                 ulong                   out_cnt,
                 ulong **                out_fseq ) {
  fd_mux_callbacks_t callbacks = {
    .during_housekeeping = during_housekeeping,
    .before_credit       = before_credit,
    .before_frag         = before_frag,
    .during_frag         = during_frag,
    .after_frag          = after_frag,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}
