/* Topology support routines for the net tile */

#include "fd_net_tile.h"
#include "../topo/fd_topob.h"
#include "../netlink/fd_netlink_tile.h"
#include "../../app/shared/fd_config.h" /* FIXME layering violation */
#include "../../util/pod/fd_pod_format.h"

#include <net/if.h>

static void
setup_xdp_tile( fd_topo_t *             topo,
                ulong                   i,
                fd_topo_tile_t *        netlink_tile,
                ulong const *           tile_to_cpu,
                fd_config_net_t const * net_cfg ) {
  fd_topo_tile_t * tile = fd_topob_tile( topo, "net", "net", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  fd_netlink_topo_join( topo, netlink_tile, tile );

  fd_topo_obj_t * umem_obj = fd_topob_obj( topo, "dcache", "net_umem" );
  fd_topob_tile_uses( topo, tile, umem_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_pod_insertf_ulong( topo->props, umem_obj->id, "net.%lu.umem", i );

  FD_STATIC_ASSERT( sizeof(tile->xdp.interface)==IF_NAMESIZE, str_bounds );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( tile->xdp.interface ), net_cfg->interface, IF_NAMESIZE-1 ) );
  tile->net.bind_address = net_cfg->bind_address_parsed;

  tile->xdp.tx_flush_timeout_ns = (long)net_cfg->xdp.flush_timeout_micros * 1000L;
  tile->xdp.xdp_rx_queue_size = net_cfg->xdp.xdp_rx_queue_size;
  tile->xdp.xdp_tx_queue_size = net_cfg->xdp.xdp_tx_queue_size;
  tile->xdp.zero_copy         = net_cfg->xdp.xdp_zero_copy;
  fd_memset( tile->xdp.xdp_mode, 0, 4 );
  fd_memcpy( tile->xdp.xdp_mode, net_cfg->xdp.xdp_mode, strnlen( net_cfg->xdp.xdp_mode, 3 ) );  /* GCC complains about strncpy */

  tile->xdp.net.umem_dcache_obj_id= umem_obj->id;
  tile->xdp.netdev_dbl_buf_obj_id = netlink_tile->netlink.netdev_dbl_buf_obj_id;
  tile->xdp.fib4_main_obj_id      = netlink_tile->netlink.fib4_main_obj_id;
  tile->xdp.fib4_local_obj_id     = netlink_tile->netlink.fib4_local_obj_id;
  tile->xdp.neigh4_obj_id         = netlink_tile->netlink.neigh4_obj_id;
  tile->xdp.neigh4_ele_obj_id     = netlink_tile->netlink.neigh4_ele_obj_id;

  /* Allocate free ring */

  tile->xdp.free_ring_depth = tile->xdp.xdp_tx_queue_size;
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
                    ulong const             tile_to_cpu[ FD_TILE_MAX ] ) {
  /* net_umem: Packet buffers */
  fd_topob_wksp( topo, "net_umem" );

  /* Create workspaces */

  fd_pod_insert_cstr( topo->props, "net.provider", net_cfg->provider );
  if( 0==strcmp( net_cfg->provider, "xdp" ) ) {

    /* net: private working memory of the net tiles */
    fd_topob_wksp( topo, "net" );
    /* netlnk: private working memory of the netlnk tile */
    fd_topob_wksp( topo, "netlnk" );
    /* netbase: shared network config (config plane) */
    fd_topob_wksp( topo, "netbase" );
    /* sock: private working memory of the fallback sock tile */
    fd_topob_wksp( topo, "sock" );
    /* net_sock: net->sock link for TX fallback */
    fd_topob_wksp( topo, "net_sock" );

    fd_topo_tile_t * netlink_tile = fd_topob_tile( topo, "netlnk", "netlnk", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
    fd_netlink_topo_create( netlink_tile, topo, netlnk_max_routes, netlnk_max_peer_routes, netlnk_max_neighbors, net_cfg->interface );

    setup_sock_tile( topo, tile_to_cpu, net_cfg );
    for( ulong i=0UL; i<net_tile_cnt; i++ ) {
      setup_xdp_tile( topo, i, netlink_tile, tile_to_cpu, net_cfg );
      fd_topob_link( topo, "net_sock", "net_sock", 1024UL, FD_NET_MTU, 1UL );
      fd_topob_tile_out( topo, "net", i, "net_sock", i );
      fd_topob_tile_in( topo, "sock", 0UL, "metric_in", "net_sock", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }

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

static void
fd_topos_xdp_tile_finish( fd_topo_t *      topo,
                          fd_topo_tile_t * net_tile ) {
  ulong rx_depth = net_tile->xdp.xdp_rx_queue_size;
  ulong tx_depth = net_tile->xdp.xdp_tx_queue_size;
  rx_depth += (rx_depth/2UL);
  tx_depth += (tx_depth/2UL);

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

  ulong umem_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "net.%lu.umem", net_tile->kind_id );
  FD_TEST( umem_obj_id!=ULONG_MAX );

  FD_TEST( net_tile->net.umem_dcache_obj_id > 0 );
  fd_pod_insertf_ulong( topo->props, cum_frame_cnt, "obj.%lu.depth", umem_obj_id );
  fd_pod_insertf_ulong( topo->props, 2UL,           "obj.%lu.burst", umem_obj_id ); /* 4096 byte padding */
  fd_pod_insertf_ulong( topo->props, 2048UL,        "obj.%lu.mtu",   umem_obj_id );
}

void
fd_topos_net_tile_finish( fd_topo_t * topo ) {
  for( ulong i=0UL; i<(topo->tile_cnt); i++ ) {
    if( 0==strcmp( topo->tiles[ i ].name, "net" ) ) {
      fd_topos_xdp_tile_finish( topo, &topo->tiles[ i ] );
    }
  }

  /* All net providers except "socket" use the sock tile as a fallback.
     This means that the sock tile should steer all packets it receives
     back to the high-performance tile. */
}
