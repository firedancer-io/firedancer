/* Topology support routines for the net tile */

#include "fd_net_tile.h"
#include "../topo/fd_topob.h"
#include "../netlink/fd_netlink_tile.h"
#include "../../app/shared/fd_config.h" /* FIXME layering violation */
#include "../../util/pod/fd_pod_format.h"
#include "fd_linux_bond.h"

#include <errno.h>
#include <net/if.h>
#include <unistd.h>

static void
setup_xdp_tile( fd_topo_t *             topo,
                ulong                   tile_kind_id,
                fd_topo_tile_t *        netlink_tile,
                ulong const *           tile_to_cpu,
                fd_config_net_t const * net_cfg,
                char const *            if_phys,
                ulong                   if_queue,
                int                     xsk_core_dump ) {
  fd_topo_tile_t * tile = fd_topob_tile( topo, "net", "net", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  fd_topob_link( topo, "net_netlnk", "net_netlnk", 128UL, 0UL, 0UL );
  fd_topob_tile_in(  topo, "netlnk", 0UL, "metric_in", "net_netlnk", tile_kind_id, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "net",    tile_kind_id,                "net_netlnk", tile_kind_id );
  fd_netlink_topo_join( topo, netlink_tile, tile );

  fd_topo_obj_t * umem_obj = fd_topob_obj( topo, "dcache", "net_umem" );
  fd_topob_tile_uses( topo, tile, umem_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_pod_insertf_ulong( topo->props, umem_obj->id, "net.%lu.umem", tile_kind_id );

  FD_STATIC_ASSERT( sizeof(tile->xdp.if_virt)==IF_NAMESIZE, str_bounds );
  fd_cstr_ncpy( tile->xdp.if_virt, net_cfg->interface, IF_NAMESIZE );
  tile->net.bind_address = net_cfg->bind_address_parsed;

  FD_STATIC_ASSERT( sizeof(tile->xdp.if_phys)==IF_NAMESIZE, str_bounds );
  fd_cstr_ncpy( tile->xdp.if_phys, if_phys, IF_NAMESIZE );
  tile->xdp.if_queue = (uint)if_queue;

  tile->xdp.tx_flush_timeout_ns = (long)net_cfg->xdp.flush_timeout_micros * 1000L;
  tile->xdp.xdp_rx_queue_size   = net_cfg->xdp.xdp_rx_queue_size;
  tile->xdp.xdp_tx_queue_size   = net_cfg->xdp.xdp_tx_queue_size;
  tile->xdp.zero_copy           = net_cfg->xdp.xdp_zero_copy;
  fd_cstr_ncpy( tile->xdp.xdp_mode, net_cfg->xdp.xdp_mode, sizeof(tile->xdp.xdp_mode) );

  tile->xdp.net.umem_dcache_obj_id = umem_obj->id;
  tile->xdp.netdev_dbl_buf_obj_id  = netlink_tile->netlink.netdev_dbl_buf_obj_id;
  tile->xdp.fib4_main_obj_id       = netlink_tile->netlink.fib4_main_obj_id;
  tile->xdp.fib4_local_obj_id      = netlink_tile->netlink.fib4_local_obj_id;
  tile->xdp.neigh4_obj_id          = netlink_tile->netlink.neigh4_obj_id;

  tile->xdp.xsk_core_dump = xsk_core_dump;

  /* Allocate free ring */

  tile->xdp.free_ring_depth = tile->xdp.xdp_tx_queue_size;
  if( tile_kind_id==0 ) {
    /* Allocate additional frames for loopback */
    tile->xdp.free_ring_depth += 16384UL;
  }
}

static void
setup_sock_tile( fd_topo_t *             topo,
                 ulong const *           tile_to_cpu,
                 fd_config_net_t const * net_cfg ) {
  fd_topo_tile_t * tile = fd_topob_tile( topo, "sock", "sock", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  tile->sock.net.bind_address = net_cfg->bind_address_parsed;

  if( FD_UNLIKELY( net_cfg->socket.receive_buffer_size>INT_MAX ) ) FD_LOG_ERR(( "invalid [net.socket.receive_buffer_size]" ));
  if( FD_UNLIKELY( net_cfg->socket.send_buffer_size   >INT_MAX ) ) FD_LOG_ERR(( "invalid [net.socket.send_buffer_size]" ));
  tile->sock.so_rcvbuf = (int)net_cfg->socket.receive_buffer_size;
  tile->sock.so_sndbuf = (int)net_cfg->socket.send_buffer_size   ;
}

void
fd_topos_net_tiles( fd_topo_t *             topo,
                    ulong                   net_tile_cnt,
                    fd_config_net_t const * net_cfg,
                    ulong                   netlnk_max_routes,
                    ulong                   netlnk_max_peer_routes,
                    ulong                   netlnk_max_neighbors,
                    int                     xsk_core_dump,
                    ulong const             tile_to_cpu[ FD_TILE_MAX ] ) {
  /* net_umem: Packet buffers */
  fd_topob_wksp( topo, "net_umem" );

  /* Create workspaces */

  if( 0==strcmp( net_cfg->provider, "xdp" ) ) {

    /* net: private working memory of the net tiles */
    fd_topob_wksp( topo, "net" );
    /* netlnk: private working memory of the netlnk tile */
    fd_topob_wksp( topo, "netlnk" );
    /* netbase: shared network config (config plane) */
    fd_topob_wksp( topo, "netbase" );
    /* net_netlnk: net->netlnk ARP requests */
    fd_topob_wksp( topo, "net_netlnk" );

    fd_topo_tile_t * netlink_tile = fd_topob_tile( topo, "netlnk", "netlnk", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
    fd_netlink_topo_create( netlink_tile, topo, netlnk_max_routes, netlnk_max_peer_routes, netlnk_max_neighbors, net_cfg->interface );

    /* Enumerate network devices to attach to */
    uint devices[ FD_NET_BOND_SLAVE_MAX ] = {0};
    uint device_cnt = 1U;
    if( net_cfg->xdp.native_bond && fd_bonding_is_master( net_cfg->interface ) ) {
      fd_bonding_slave_iter_t iter_[1];
      fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, net_cfg->interface );
      uint slave_cnt;
      for( slave_cnt=0U;
           /*         */ !fd_bonding_slave_iter_done( iter );
           slave_cnt++,  fd_bonding_slave_iter_next( iter ) ) {
        uint if_idx = if_nametoindex( fd_bonding_slave_iter_ele( iter ) );
        if( FD_UNLIKELY( !if_idx ) ) FD_LOG_ERR(( "if_nametoindex(%s) failed", fd_bonding_slave_iter_ele( iter ) ));
        devices[ slave_cnt ] = if_idx;
      }
      if( slave_cnt==0 ) {
        FD_LOG_ERR(( "no bond slave devices detected on interface %s (see [net.xdp.native_bond])", net_cfg->interface ));
      }
      device_cnt = (uint)slave_cnt;
    } else {
      devices[ 0 ] = if_nametoindex( net_cfg->interface );
      if( FD_UNLIKELY( !devices[ 0 ] ) ) FD_LOG_ERR(( "unsupported [net.interface]: `%s`", net_cfg->interface ));
      device_cnt = 1U;
    }

    /* Verify that net_tile_cnt is a multiple of device_cnt */
    if( FD_UNLIKELY( net_tile_cnt%device_cnt!=0 ) ) {
      FD_LOG_ERR(( "net tile count %lu must be a multiple of the number of slave devices %u (incompatible settings [layout.net_tile_count] and [net.xdp.native_bond])", net_tile_cnt, device_cnt ));
    }
    uint dev_queue_cnt = (uint)net_tile_cnt/device_cnt;

    /* Assign XDP tiles to device queues */
    ulong tile_kind_id = 0UL;
    for( uint i=0UL; i<device_cnt; i++ ) {
      char if_name[ IF_NAMESIZE ];
      if( FD_UNLIKELY( !if_indextoname( devices[ i ], if_name ) ) ) {
        FD_LOG_ERR(( "error initializing network stack: if_indextoname(%u) failed (try disabling [net.xdp.native_bond]?)", i ));
      }
      for( ulong j=0UL; j<dev_queue_cnt; j++ ) {
        setup_xdp_tile( topo, tile_kind_id++, netlink_tile, tile_to_cpu, net_cfg, if_name, (uint)j, xsk_core_dump );
      }
    }
    FD_TEST( tile_kind_id==net_tile_cnt );

  } else if( 0==strcmp( net_cfg->provider, "socket" ) ) {

    /* sock: private working memory of the sock tiles */
    fd_topob_wksp( topo, "sock" );

    for( ulong i=0UL; i<net_tile_cnt; i++ ) {
      setup_sock_tile( topo, tile_to_cpu, net_cfg );
    }

  } else {
    FD_LOG_ERR(( "invalid `net.provider`" ));
  }
}

static int
topo_is_xdp( fd_topo_t * topo ) {
  /* FIXME hacky */
  for( ulong j=0UL; j<(topo->tile_cnt); j++ ) {
    if( 0==strcmp( topo->tiles[ j ].name, "net" ) ) {
      return 1;
    }
  }
  return 0;
}

static void
add_xdp_rx_link( fd_topo_t *  topo,
                 char const * link_name,
                 ulong        net_kind_id,
                 ulong        depth ) {
  if( FD_UNLIKELY( !topo || !link_name  ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( link_name )>=sizeof(topo->links[ topo->link_cnt ].name ) ) ) FD_LOG_ERR(( "link name too long: %s", link_name ));
  if( FD_UNLIKELY( topo->link_cnt>=FD_TOPO_MAX_LINKS ) ) FD_LOG_ERR(( "too many links" ));

  ulong kind_id = 0UL;
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    if( !strcmp( topo->links[ i ].name, link_name ) ) kind_id++;
  }

  fd_topo_link_t * link = &topo->links[ topo->link_cnt ];
  strncpy( link->name, link_name, sizeof(link->name) );
  link->id       = topo->link_cnt;
  link->kind_id  = kind_id;
  link->depth    = depth;
  link->mtu      = FD_NET_MTU;
  link->burst    = 0UL;

  fd_topo_obj_t * obj = fd_topob_obj( topo, "mcache", "net_umem" );
  link->mcache_obj_id = obj->id;
  FD_TEST( fd_pod_insertf_ulong( topo->props, depth, "obj.%lu.depth", obj->id ) );

  link->dcache_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "net.%lu.umem", net_kind_id );
  if( FD_UNLIKELY( link->dcache_obj_id==ULONG_MAX ) ) FD_LOG_ERR(( "umem dcache not found for net %lu", net_kind_id ));

  topo->link_cnt++;
}

void
fd_topos_net_rx_link( fd_topo_t *  topo,
                      char const * link_name,
                      ulong        net_kind_id,
                      ulong        depth ) {
  if( topo_is_xdp( topo ) ) {
    add_xdp_rx_link( topo, link_name, net_kind_id, depth );
    fd_topob_tile_out( topo, "net", net_kind_id, link_name, net_kind_id );
  } else {
    fd_topob_link( topo, link_name, "net_umem", depth, FD_NET_MTU, 64 );
    fd_topob_tile_out( topo, "sock", net_kind_id, link_name, net_kind_id );
  }
}

void
fd_topos_tile_in_net( fd_topo_t *  topo,
                      char const * fseq_wksp,
                      char const * link_name,
                      ulong        link_kind_id,
                      int          reliable,
                      int          polled ) {
  for( ulong j=0UL; j<(topo->tile_cnt); j++ ) {
    if( 0==strcmp( topo->tiles[ j ].name, "net"  ) ||
        0==strcmp( topo->tiles[ j ].name, "sock" ) ) {
      fd_topob_tile_in( topo, topo->tiles[ j ].name, topo->tiles[ j ].kind_id, fseq_wksp, link_name, link_kind_id, reliable, polled );
    }
  }
}

void
fd_topos_net_tile_finish( fd_topo_t * topo,
                          ulong       net_kind_id ) {
  if( !topo_is_xdp( topo ) ) return;

  fd_topo_tile_t * net_tile = &topo->tiles[ fd_topo_find_tile( topo, "net", net_kind_id ) ];

  ulong rx_depth = net_tile->xdp.xdp_rx_queue_size;
  ulong tx_depth = net_tile->xdp.xdp_tx_queue_size;
  rx_depth += (rx_depth/2UL);
  tx_depth += (tx_depth/2UL);

  if( net_kind_id==0 ) {
    /* Double it for loopback XSK */
    rx_depth *= 2UL;
    tx_depth *= 2UL;
  }

  ulong cum_frame_cnt = rx_depth + tx_depth;

  /* Count up the depth of all RX mcaches */

  for( ulong j=0UL; j<(net_tile->out_cnt); j++ ) {
    ulong link_id       = net_tile->out_link_id[ j ];
    ulong mcache_obj_id = topo->links[ link_id ].mcache_obj_id;
    ulong depth = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.depth", mcache_obj_id );
    if( FD_UNLIKELY( depth==ULONG_MAX ) ) FD_LOG_ERR(( "Didn't find depth for mcache %s", topo->links[ link_id ].name ));
    cum_frame_cnt += depth + 1UL;
  }

  /* Create a dcache object */

  ulong umem_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "net.%lu.umem", net_kind_id );
  FD_TEST( umem_obj_id!=ULONG_MAX );

  FD_TEST( net_tile->net.umem_dcache_obj_id > 0 );
  fd_pod_insertf_ulong( topo->props, cum_frame_cnt, "obj.%lu.depth", umem_obj_id );
  fd_pod_insertf_ulong( topo->props, 2UL,           "obj.%lu.burst", umem_obj_id ); /* 4096 byte padding */
  fd_pod_insertf_ulong( topo->props, 2048UL,        "obj.%lu.mtu",   umem_obj_id );
}

void
fd_topo_install_xdp( fd_topo_t const * topo,
                     fd_xdp_fds_t *    fds,
                     uint *            fds_cnt,
                     uint              bind_addr,
                     int               dry_run ) {
  uint fds_max = *fds_cnt;
  memset( fds, 0, fds_max*sizeof(fd_xdp_fds_t) );

  uint if_cnt = 0U;
# define ADD_IF_IDX( idx_ ) do {                      \
    uint idx = (idx_);                                \
    int found = 0;                                    \
    for( uint i=0U; i<if_cnt; i++ ) {                 \
      if( fds[ i ].if_idx==idx ) {                    \
        found = 1;                                    \
        break;                                        \
      }                                               \
    }                                                 \
    if( !found ) {                                    \
      FD_TEST( if_cnt<FD_NET_BOND_SLAVE_MAX+1 );      \
      fds[ if_cnt++ ].if_idx = idx;                   \
    }                                                 \
  } while(0)

  /* Create a list of unique fds */

  ulong net_tile_cnt = fd_topo_tile_name_cnt( topo, "net" );
  for( ulong tile_kind_id=0UL; tile_kind_id<net_tile_cnt; tile_kind_id++ ) {
    ulong net_tile_id = fd_topo_find_tile( topo, "net", tile_kind_id );
    FD_TEST( net_tile_id!=ULONG_MAX );
    fd_topo_tile_t const * tile = &topo->tiles[ net_tile_id ];
    uint if_idx = if_nametoindex( tile->xdp.if_phys ); FD_TEST( if_idx );
    ADD_IF_IDX( if_idx );
  }

  /* Add loopback unless found */

  uint lo_idx = if_nametoindex( "lo" ); FD_TEST( lo_idx );
  ADD_IF_IDX( lo_idx );

  /* Done with config discovery */

  *fds_cnt = if_cnt;
  int next_fd = 123462;
  for( uint i=0U; i<if_cnt; i++ ) {
    fds[ i ].xsk_map_fd   = next_fd++;
    fds[ i ].prog_link_fd = next_fd++;
  }
  if( dry_run ) return;

  /* Install */

  ulong net0_tile_idx = fd_topo_find_tile( topo, "net", 0UL );
  FD_TEST( net0_tile_idx!=ULONG_MAX );
  fd_topo_tile_t const * net0_tile = &topo->tiles[ net0_tile_idx ];

  ushort udp_port_candidates[] = {
    (ushort)net0_tile->xdp.net.legacy_transaction_listen_port,
    (ushort)net0_tile->xdp.net.quic_transaction_listen_port,
    (ushort)net0_tile->xdp.net.shred_listen_port,
    (ushort)net0_tile->xdp.net.gossip_listen_port,
    (ushort)net0_tile->xdp.net.repair_intake_listen_port,
    (ushort)net0_tile->xdp.net.repair_serve_listen_port,
    (ushort)net0_tile->xdp.net.txsend_src_port,
  };

  for( uint i=0U; i<if_cnt; i++ ) {
    /* Override XDP mode for loopback */
    char const * xdp_mode = net0_tile->xdp.xdp_mode;
    if( fds[ i ].if_idx==1U ) xdp_mode = "skb";

    fd_xdp_fds_t xdp_fds = fd_xdp_install(
        fds[ i ].if_idx,
        bind_addr,
        sizeof(udp_port_candidates)/sizeof(udp_port_candidates[0]),
        udp_port_candidates,
        xdp_mode );
    if( FD_UNLIKELY( -1==dup2( xdp_fds.xsk_map_fd, fds[ i ].xsk_map_fd ) ) ) {
      FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( -1==close( xdp_fds.xsk_map_fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( -1==dup2( xdp_fds.prog_link_fd, fds[ i ].prog_link_fd ) ) ) {
      FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( -1==close( xdp_fds.prog_link_fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

# undef ADD_IF_IDX
}
