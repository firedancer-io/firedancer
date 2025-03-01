/* The net tile translates between AF_XDP and fd_tango
   traffic.  It is responsible for setting up the XDP and
   XSK socket configuration. */

#include <errno.h>
#include <sys/socket.h> /* MSG_DONTWAIT */
#include <unistd.h> /* close */

#include "fd_xdp_tile_private.h"
#include "generated/xdp_seccomp.h"

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t)                      );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),        tile->net.free_ring_depth * sizeof(ulong) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* net_xsk_bootstrap assigns UMEM frames to the FILL ring. */

static ulong
net_xsk_bootstrap( fd_net_ctx_t * ctx,
                   uint           xsk_idx,
                   ulong          frame_off ) {
  fd_xsk_t * xsk = &ctx->xsk[ xsk_idx ];

  ulong const frame_sz  = FD_NET_MTU;
  ulong const fr_depth  = ctx->xsk[ xsk_idx ].ring_fr.depth/2UL;

  fd_xdp_ring_t * fill      = &xsk->ring_fr;
  uint            fill_prod = fill->cached_prod;
  for( ulong j=0UL; j<fr_depth; j++ ) {
    fill->frame_ring[ j ] = frame_off;
    frame_off += frame_sz;
  }
  FD_VOLATILE( *fill->prod ) = fill->cached_prod = fill_prod + (uint)fr_depth;

  return frame_off;
}

/* privileged_init does the following initialization steps:

   - Create an AF_XDP socket
   - Map XDP metadata rings
   - Register UMEM data region with socket
   - Insert AF_XDP socket into xsk_map

   Net tile 0 also runs fd_xdp_install and repeats the above step for
   the loopback device.  (Unless the main interface is already loopback)

   Kernel object references:

     BPF_LINK file descriptor
      |
      +-> XDP program installation on NIC
      |    |
      |    +-> XDP program <-- BPF_PROG file descriptor (prog_fd)
      |
      +-> XSKMAP object <-- BPF_MAP file descriptor (xsk_map)
      |
      +-> BPF_MAP object <-- BPF_MAP file descriptor (udp_dsts) */

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );
  ulong *        free_tx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), tile->net.free_ring_depth * sizeof(ulong) );;

  fd_memset( ctx, 0, sizeof(fd_net_ctx_t) );

  uint if_idx = if_nametoindex( tile->net.interface );
  if( FD_UNLIKELY( !if_idx ) ) FD_LOG_ERR(( "if_nametoindex(%s) failed", tile->net.interface ));

  /* Load up dcache containing UMEM */

  void * const dcache_mem          = fd_topo_obj_laddr( topo, tile->net.umem_dcache_obj_id );
  void * const umem_dcache         = fd_dcache_join( dcache_mem );
  ulong  const umem_dcache_data_sz = fd_dcache_data_sz( umem_dcache );
  ulong  const umem_frame_sz       = 2048UL;

  /* Left shrink UMEM region to be 4096 byte aligned */

  void * const umem_frame0 = (void *)fd_ulong_align_up( (ulong)umem_dcache, 4096UL );
  ulong        umem_sz     = umem_dcache_data_sz - ((ulong)umem_frame0 - (ulong)umem_dcache);
  umem_sz = fd_ulong_align_dn( umem_sz, umem_frame_sz );

  /* Derive chunk bounds */

  void * const umem_base   = fd_wksp_containing( dcache_mem );
  ulong  const umem_chunk0 = ( (ulong)umem_frame0 - (ulong)umem_base )>>FD_CHUNK_LG_SZ;
  ulong  const umem_wmark  = umem_chunk0 + ( ( umem_sz-umem_frame_sz )>>FD_CHUNK_LG_SZ );
  if( FD_UNLIKELY( umem_chunk0>UINT_MAX || umem_wmark>UINT_MAX || umem_chunk0>umem_wmark ) ) {
    FD_LOG_ERR(( "Calculated invalid UMEM bounds [%lu,%lu]", umem_chunk0, umem_wmark ));
  }

  if( FD_UNLIKELY( !umem_base   ) ) FD_LOG_ERR(( "UMEM dcache is not in a workspace" ));
  if( FD_UNLIKELY( !umem_dcache ) ) FD_LOG_ERR(( "Failed to join UMEM dcache" ));

  ctx->umem_frame0 = umem_frame0;
  ctx->umem_sz     = umem_sz;
  ctx->umem_base   = dcache_mem;
  ctx->umem_chunk0 = (uint)umem_chunk0;
  ctx->umem_wmark  = (uint)umem_wmark;

  ctx->free_tx.queue = free_tx;
  ctx->free_tx.depth = tile->net.xdp_tx_queue_size;

  /* Create and install XSKs */

  fd_xsk_params_t params0 = {
    .if_idx      = if_idx,
    .if_queue_id = (uint)tile->kind_id,

    /* Some kernels produce EOPNOTSUP errors on sendto calls when
       starting up without either XDP_ZEROCOPY or XDP_COPY
       (e.g. 5.14.0-503.23.1.el9_5 with i40e) */
    .bind_flags  = tile->net.zero_copy ? XDP_ZEROCOPY : XDP_COPY,

    .fr_depth  = tile->net.xdp_rx_queue_size*2,
    .rx_depth  = tile->net.xdp_rx_queue_size,
    .cr_depth  = tile->net.xdp_tx_queue_size,
    .tx_depth  = tile->net.xdp_tx_queue_size,

    .umem_addr = umem_frame0,
    .frame_sz  = umem_frame_sz,
    .umem_sz   = umem_sz
  };

  if( tile->net.xdp_busy_poll ) {
    params0.busy_poll_usecs = (tile->net.napi_poll_duration + 999UL) / 1000UL;
  } else {
    params0.bind_flags |= XDP_USE_NEED_WAKEUP;
  }

  int xsk_map_fd = 123462;
  ctx->prog_link_fds[ 0 ] = 123463;
  /* Init XSK */
  if( FD_UNLIKELY( !fd_xsk_init( &ctx->xsk[ 0 ], &params0 ) ) ) {
    FD_LOG_ERR(( "failed to bind xsk for net tile %lu", tile->kind_id ));
  }
  if( FD_UNLIKELY( ctx->xsk[0].busy_poll && !ctx->xsk[0].napi_id )) {
    FD_LOG_WARNING((
      "The network driver of interface (%u-%s) does not support preferred busy polling.\n"
      "The kernel was unable to determine the NAPI ID of the RX queue.\n"
      "Please unset config option [tiles.net.busy_poll.enabled].\n",
      if_idx, tile->net.interface
    ));
  }
  if( FD_UNLIKELY( !fd_xsk_activate( &ctx->xsk[ 0 ], xsk_map_fd ) ) ) {
    FD_LOG_ERR(( "failed to activate xsk for net tile %lu", tile->kind_id ));
  }

  if( FD_UNLIKELY( fd_sandbox_gettid()==fd_sandbox_getpid() ) ) {
    /* Kind of gross.. in single threaded mode we don't want to close the xsk_map_fd
       since it's shared with other net tiles.  Just check for that by seeing if we
       are the only thread in the process. */
    if( FD_UNLIKELY( -1==close( xsk_map_fd ) ) )                     FD_LOG_ERR(( "close(%d) failed (%d-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));
  }

  /* Networking tile at index 0 also binds to loopback (only queue 0 available on lo) */

  if( FD_UNLIKELY( strcmp( tile->net.interface, "lo" ) && !tile->kind_id ) ) {
    ctx->xsk_cnt = 2;

    ushort udp_port_candidates[] = {
      (ushort)tile->net.legacy_transaction_listen_port,
      (ushort)tile->net.quic_transaction_listen_port,
      (ushort)tile->net.shred_listen_port,
      (ushort)tile->net.gossip_listen_port,
      (ushort)tile->net.repair_intake_listen_port,
      (ushort)tile->net.repair_serve_listen_port,
    };

    uint lo_idx = if_nametoindex( "lo" );
    if( FD_UNLIKELY( !lo_idx ) ) FD_LOG_ERR(( "if_nametoindex(lo) failed" ));

    /* FIXME move this to fd_topo_run */
    fd_xdp_fds_t lo_fds = fd_xdp_install( lo_idx,
                                          tile->net.src_ip_addr,
                                          sizeof(udp_port_candidates)/sizeof(udp_port_candidates[0]),
                                          udp_port_candidates,
                                          "skb" );

    ctx->prog_link_fds[ 1 ] = lo_fds.prog_link_fd;
    /* init xsk 1 */
    fd_xsk_params_t params1 = params0;
    params1.if_idx      = lo_idx; /* probably always 1 */
    params1.if_queue_id = 0;
    params1.bind_flags  = 0;
    if( FD_UNLIKELY( !fd_xsk_init( &ctx->xsk[ 1 ], &params1 ) ) )              FD_LOG_ERR(( "failed to bind lo_xsk" ));
    if( FD_UNLIKELY( !fd_xsk_activate( &ctx->xsk[ 1 ], lo_fds.xsk_map_fd ) ) ) FD_LOG_ERR(( "failed to activate lo_xsk" ));
    if( FD_UNLIKELY( -1==close( lo_fds.xsk_map_fd ) ) )                        FD_LOG_ERR(( "close(%d) failed (%d-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));
  }

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ctx->xdp_stats_interval_ticks = (long)( FD_XDP_STATS_INTERVAL_NS * tick_per_ns );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_net_ctx_t), sizeof(fd_net_ctx_t) );

  ctx->net_tile_id  = (uint)tile->kind_id;
  ctx->net_tile_cnt = (uint)fd_topo_tile_name_cnt( topo, tile->name );

  ctx->src_ip_addr = tile->net.src_ip_addr;
  memcpy( ctx->src_mac_addr, tile->net.src_mac_addr, 6UL );

  ctx->shred_listen_port              = tile->net.shred_listen_port;
  ctx->quic_transaction_listen_port   = tile->net.quic_transaction_listen_port;
  ctx->legacy_transaction_listen_port = tile->net.legacy_transaction_listen_port;
  ctx->gossip_listen_port             = tile->net.gossip_listen_port;
  ctx->repair_intake_listen_port      = tile->net.repair_intake_listen_port;
  ctx->repair_serve_listen_port       = tile->net.repair_serve_listen_port;

  /* Put a bound on chunks we read from the input, to make sure they
     are within in the data region of the workspace. */

  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "net tile in link cnt is zero" ));
  if( FD_UNLIKELY( tile->in_cnt>MAX_NET_INS ) ) FD_LOG_ERR(( "net tile in link cnt %lu exceeds MAX_NET_INS %lu", tile->in_cnt, MAX_NET_INS ));
  FD_TEST( tile->in_cnt<=32 );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( link->mtu!=FD_NET_MTU ) ) FD_LOG_ERR(( "net tile in link does not have a normal MTU" ));

    ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  for( ulong i = 0; i < tile->out_cnt; i++ ) {
    fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ i  ] ];
    if( strcmp( out_link->name, "net_quic" ) == 0 ) {
      fd_topo_link_t * quic_out = out_link;
      ctx->quic_out->mcache = quic_out->mcache;
      ctx->quic_out->sync   = fd_mcache_seq_laddr( ctx->quic_out->mcache );
      ctx->quic_out->depth  = fd_mcache_depth( ctx->quic_out->mcache );
      ctx->quic_out->seq    = fd_mcache_seq_query( ctx->quic_out->sync );
    } else if( strcmp( out_link->name, "net_shred" ) == 0 ) {
      fd_topo_link_t * shred_out = out_link;
      ctx->shred_out->mcache = shred_out->mcache;
      ctx->shred_out->sync   = fd_mcache_seq_laddr( ctx->shred_out->mcache );
      ctx->shred_out->depth  = fd_mcache_depth( ctx->shred_out->mcache );
      ctx->shred_out->seq    = fd_mcache_seq_query( ctx->shred_out->sync );
    } else if( strcmp( out_link->name, "net_gossip" ) == 0 ) {
      fd_topo_link_t * gossip_out = out_link;
      ctx->gossip_out->mcache = gossip_out->mcache;
      ctx->gossip_out->sync   = fd_mcache_seq_laddr( ctx->gossip_out->mcache );
      ctx->gossip_out->depth  = fd_mcache_depth( ctx->gossip_out->mcache );
      ctx->gossip_out->seq    = fd_mcache_seq_query( ctx->gossip_out->sync );
    } else if( strcmp( out_link->name, "net_repair" ) == 0 ) {
      fd_topo_link_t * repair_out = out_link;
      ctx->repair_out->mcache = repair_out->mcache;
      ctx->repair_out->sync   = fd_mcache_seq_laddr( ctx->repair_out->mcache );
      ctx->repair_out->depth  = fd_mcache_depth( ctx->repair_out->mcache );
      ctx->repair_out->seq    = fd_mcache_seq_query( ctx->repair_out->sync );
    } else if( strcmp( out_link->name, "net_netlnk" ) == 0 ) {
      fd_topo_link_t * netlink_out = out_link;
      ctx->neigh4_solicit->mcache = netlink_out->mcache;
      ctx->neigh4_solicit->depth  = fd_mcache_depth( ctx->neigh4_solicit->mcache );
      ctx->neigh4_solicit->seq    = fd_mcache_seq_query( fd_mcache_seq_laddr( ctx->neigh4_solicit->mcache ) );
    } else {
      FD_LOG_ERR(( "unrecognized out link `%s`", out_link->name ));
    }
  }

  /* Check if any of the tiles we set a listen port for do not have an outlink. */
  if( FD_UNLIKELY( ctx->shred_listen_port!=0 && ctx->shred_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "shred listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->quic_transaction_listen_port!=0 && ctx->quic_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "quic transaction listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->legacy_transaction_listen_port!=0 && ctx->quic_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "legacy transaction listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->gossip_listen_port!=0 && ctx->gossip_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "gossip listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->repair_intake_listen_port!=0 && ctx->repair_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "repair intake port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->repair_serve_listen_port!=0 && ctx->repair_out->mcache==NULL ) ) {
    FD_LOG_ERR(( "repair serve listen port set but no out link was found" ));
  } else if( FD_UNLIKELY( ctx->neigh4_solicit->mcache==NULL ) ) {
    FD_LOG_ERR(( "netlink request link not found" ));
  }

  for( uint j=0U; j<2U; j++ ) {
    ctx->tx_flusher[ j ].pending_wmark         = (ulong)( (double)tile->net.xdp_tx_queue_size * 0.7 );
    ctx->tx_flusher[ j ].tail_flush_backoff    = (long)( (double)tile->net.tx_flush_timeout_ns * fd_tempo_tick_per_ns( NULL ) );
    ctx->tx_flusher[ j ].next_tail_flush_ticks = 0L;
  }

  /* Join netbase objects */
  ctx->fib_local = fd_fib4_join( fd_topo_obj_laddr( topo, tile->net.fib4_local_obj_id ) );
  ctx->fib_main  = fd_fib4_join( fd_topo_obj_laddr( topo, tile->net.fib4_main_obj_id  ) );
  if( FD_UNLIKELY( !ctx->fib_local || !ctx->fib_main ) ) FD_LOG_ERR(( "fd_fib4_join failed" ));
  if( FD_UNLIKELY( !fd_neigh4_hmap_join(
      ctx->neigh4,
      fd_topo_obj_laddr( topo, tile->net.neigh4_obj_id ),
      fd_topo_obj_laddr( topo, tile->net.neigh4_ele_obj_id ) ) ) ) {
    FD_LOG_ERR(( "fd_neigh4_hmap_join failed" ));
  }

  /* Initialize TX free ring */

  ulong const frame_sz  = 2048UL;
  ulong       frame_off = 0UL;
  ulong const tx_depth  = ctx->free_tx.depth;
  for( ulong j=0; j<tx_depth; j++ ) {
    ctx->free_tx.queue[ j ] = (ulong)ctx->umem_frame0 + frame_off;
    frame_off += frame_sz;
  }
  ctx->free_tx.prod = tx_depth;

  /* Initialize RX mcache chunks */

  for( ulong i=0UL; i<(tile->out_cnt); i++ ) {
    fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ i  ] ];
    fd_frag_meta_t * mcache   = out_link->mcache;
    for( ulong j=0UL; j<fd_mcache_depth( mcache ); j++ ) {
      mcache[ j ].chunk = (uint)( ctx->umem_chunk0 + (frame_off>>FD_CHUNK_LG_SZ) );
      frame_off += frame_sz;
    }
  }

  /* Initialize FILL ring */

  for( uint j=0U; j<ctx->xsk_cnt; j++ ) {
    frame_off = net_xsk_bootstrap( ctx, j, frame_off );
  }

  if( FD_UNLIKELY( frame_off > ctx->umem_sz ) ) {
    FD_LOG_ERR(( "UMEM is too small" ));
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );

  /* A bit of a hack, if there is no loopback XSK for this tile, we still need to pass
     two "allow" FD arguments to the net policy, so we just make them both the same. */
  int allow_fd2 = ctx->xsk_cnt>1UL ? ctx->xsk[ 1 ].xsk_fd : ctx->xsk[ 0 ].xsk_fd;
  FD_TEST( ctx->xsk[ 0 ].xsk_fd >= 0 && allow_fd2 >= 0 );
  populate_sock_filter_policy_xdp( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->xsk[ 0 ].xsk_fd, (uint)allow_fd2 );
  return sock_filter_policy_xdp_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<6UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

                                      out_fds[ out_cnt++ ] = ctx->xsk[ 0 ].xsk_fd;
                                      out_fds[ out_cnt++ ] = ctx->prog_link_fds[ 0 ];
  if( FD_LIKELY( ctx->xsk_cnt>1UL ) ) out_fds[ out_cnt++ ] = ctx->xsk[ 1 ].xsk_fd;
  if( FD_LIKELY( ctx->xsk_cnt>1UL ) ) out_fds[ out_cnt++ ] = ctx->prog_link_fds[ 1 ];
  return out_cnt;
}

static void
stem_run( fd_topo_t *      topo,
          fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_net_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_net_ctx_t ), sizeof( fd_net_ctx_t ) );

  FD_TEST( ctx->xsk_cnt >= 1 );
  if( ctx->xsk[0].busy_poll ) {
    fd_xdp_tile_poll_run( topo, tile );
  } else {
    fd_xdp_tile_softirq_run( topo, tile );
  }
}

fd_topo_run_tile_t fd_tile_xdp = {
  .name                     = "net",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
