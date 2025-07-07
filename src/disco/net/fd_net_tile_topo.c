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
  fd_topob_link( topo, "net_netlnk", "net_netlnk", 128UL, 0UL, 0UL );
  fd_topob_tile_in(  topo, "netlnk", 0UL, "metric_in", "net_netlnk", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "net",    i,                "net_netlnk", i );
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
  if( i==0 ) {
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

#if FD_HAS_IBVERBS

static void
setup_ibeth_tile( fd_topo_t *             topo,
                  fd_topo_tile_t *        netlink_tile,
                  ulong const *           tile_to_cpu,
                  fd_config_net_t const * net_cfg ) {
  fd_topo_tile_t * tile = fd_topob_tile( topo, "ibeth", "ibeth", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  fd_topob_link( topo, "net_netlnk", "net_netlnk", 128UL, 0UL, 0UL );
  fd_topob_tile_in(  topo, "netlnk", 0UL, "metric_in", "net_netlnk", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "ibeth",  0UL,              "net_netlnk", 0UL );
  fd_netlink_topo_join( topo, netlink_tile, tile );

  fd_topo_obj_t * umem_obj = fd_topob_obj( topo, "dcache", "net_umem" );
  fd_topob_tile_uses( topo, tile, umem_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_pod_insertf_ulong( topo->props, umem_obj->id, "net.%lu.umem", 0UL ); /* FIXME multi queue support */

  fd_cstr_fini( fd_cstr_append_cstr_safe(
      fd_cstr_init( tile->ibeth.if_name ),
      net_cfg->interface,
      IF_NAMESIZE-1UL ) );
  tile->ibeth.rx_queue_size = 1024U; /* FIXME */
  tile->ibeth.tx_queue_size = 1024U; /* FIXME */

  tile->ibeth.umem_dcache_obj_id    = umem_obj->id;
  tile->ibeth.netdev_dbl_buf_obj_id = netlink_tile->netlink.netdev_dbl_buf_obj_id;
  tile->ibeth.fib4_main_obj_id      = netlink_tile->netlink.fib4_main_obj_id;
  tile->ibeth.fib4_local_obj_id     = netlink_tile->netlink.fib4_local_obj_id;
  tile->ibeth.neigh4_obj_id         = netlink_tile->netlink.neigh4_obj_id;
  tile->ibeth.neigh4_ele_obj_id     = netlink_tile->netlink.neigh4_ele_obj_id;
}

#endif

void
fd_topos_net_tiles( fd_topo_t *             topo,
                    ulong                   net_tile_cnt,
                    fd_config_net_t const * net_cfg,
                    ulong                   netlnk_max_routes,
                    ulong                   netlnk_max_neighbors,
                    ulong const             tile_to_cpu[ FD_TILE_MAX ] ) {
  /* net_umem: Packet buffers */
  fd_topob_wksp( topo, "net_umem" );

  fd_pod_insert_cstr( topo->props, "net.provider",  net_cfg->provider );

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
    fd_netlink_topo_create( netlink_tile, topo, netlnk_max_routes, netlnk_max_neighbors, net_cfg->interface );

    for( ulong i=0UL; i<net_tile_cnt; i++ ) {
      setup_xdp_tile( topo, i, netlink_tile, tile_to_cpu, net_cfg );
    }

  } else if( 0==strcmp( net_cfg->provider, "socket" ) ) {

    /* sock: private working memory of the sock tiles */
    fd_topob_wksp( topo, "sock" );

    for( ulong i=0UL; i<net_tile_cnt; i++ ) {
      setup_sock_tile( topo, tile_to_cpu, net_cfg );
    }

  } else if( 0==strcmp( net_cfg->provider, "ibverbs" ) ) {

# if !FD_HAS_IBVERBS
    FD_LOG_ERR(( "[net.provider] is 'ibverbs', but Firedancer was built without ibverbs support.\n"
                 "Please do a clean rebuild with 'make EXTRAS=ibverbs'." ));
# else

    /* ibeth: private working memory of the ibeth tiles */
    fd_topob_wksp( topo, "ibeth" );
    /* netlnk: private working memory of the netlnk tile */
    fd_topob_wksp( topo, "netlnk" );
    /* netbase: shared network config (config plane) */
    fd_topob_wksp( topo, "netbase" );
    /* net_netlnk: net->netlnk ARP requests */
    fd_topob_wksp( topo, "net_netlnk" );

    fd_topo_tile_t * netlink_tile = fd_topob_tile( topo, "netlnk", "netlnk", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
    fd_netlink_topo_create( netlink_tile, topo, netlnk_max_routes, netlnk_max_neighbors, net_cfg->interface );

    setup_ibeth_tile( topo, netlink_tile, tile_to_cpu, net_cfg );

# endif

  } else {
    FD_LOG_ERR(( "invalid `net.provider`" ));
  }
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
  char const * provider = fd_pod_query_cstr( topo->props, "net.provider", "" );
  if( 0==strcmp( provider, "xdp" ) ) {
    add_xdp_rx_link( topo, link_name, net_kind_id, depth );
    fd_topob_tile_out( topo, "net", net_kind_id, link_name, net_kind_id );
  } else if( 0==strcmp( provider, "socket" ) ) {
    fd_topob_link( topo, link_name, "net_umem", depth, FD_NET_MTU, 64 );
    fd_topob_tile_out( topo, "sock", net_kind_id, link_name, net_kind_id );
  } else if( 0==strcmp( provider, "ibverbs" ) ) {
    fd_topob_link( topo, link_name, "net_umem", depth, FD_NET_MTU, 64 );
    fd_topob_tile_out( topo, "ibeth", net_kind_id, link_name, net_kind_id );
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
    if( 0==strcmp( topo->tiles[ j ].name, "net"   ) ||
        0==strcmp( topo->tiles[ j ].name, "sock"  ) ||
        0==strcmp( topo->tiles[ j ].name, "ibeth" ) ) {
      fd_topob_tile_in( topo, topo->tiles[ j ].name, topo->tiles[ j ].kind_id, fseq_wksp, link_name, link_kind_id, reliable, polled );
    }
  }
}

static void
fd_topos_xdp_setup_mem( fd_topo_t *      topo,
                        fd_topo_tile_t * net_tile ) {
  ulong rx_depth = net_tile->xdp.xdp_rx_queue_size;
  ulong tx_depth = net_tile->xdp.xdp_tx_queue_size;
  rx_depth += (rx_depth/2UL);
  tx_depth += (tx_depth/2UL);

  if( net_tile->kind_id==0 ) {
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

  ulong umem_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "net.%lu.umem", net_tile->kind_id );
  FD_TEST( umem_obj_id!=ULONG_MAX );

  FD_TEST( net_tile->net.umem_dcache_obj_id > 0 );
  fd_pod_insertf_ulong( topo->props, cum_frame_cnt, "obj.%lu.depth", umem_obj_id );
  fd_pod_insertf_ulong( topo->props, 2UL,           "obj.%lu.burst", umem_obj_id ); /* 4096 byte padding */
  fd_pod_insertf_ulong( topo->props, 2048UL,        "obj.%lu.mtu",   umem_obj_id );
}

static void
fd_topos_ibeth_setup_mem( fd_topo_t *      topo,
                          fd_topo_tile_t * ibeth_tile ) {
  ulong cum_frame_cnt = 0UL;

  ulong const rx_depth = ibeth_tile->ibeth.rx_queue_size;
  ulong const tx_depth = ibeth_tile->ibeth.tx_queue_size;
  cum_frame_cnt += rx_depth + tx_depth;

  /* Count up the depth of all RX mcaches */

  for( ulong j=0UL; j<(ibeth_tile->out_cnt); j++ ) {
    ulong link_id       = ibeth_tile->out_link_id[ j ];
    ulong mcache_obj_id = topo->links[ link_id ].mcache_obj_id;
    ulong depth = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.depth", mcache_obj_id );
    if( FD_UNLIKELY( depth==ULONG_MAX ) ) FD_LOG_ERR(( "Didn't find depth for mcache %s", topo->links[ link_id ].name ));
    cum_frame_cnt += depth + 1UL;
  }

  /* Create a dcache object */

  ulong umem_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "net.%lu.umem", ibeth_tile->kind_id );
  FD_TEST( umem_obj_id!=ULONG_MAX );

  FD_TEST( ibeth_tile->ibeth.umem_dcache_obj_id > 0 );
  fd_pod_insertf_ulong( topo->props, cum_frame_cnt, "obj.%lu.depth", umem_obj_id );
  fd_pod_insertf_ulong( topo->props, 2UL,           "obj.%lu.burst", umem_obj_id ); /* 4096 byte padding */
  fd_pod_insertf_ulong( topo->props, FD_NET_MTU,    "obj.%lu.mtu",   umem_obj_id );
}

void
fd_topos_net_tile_finish( fd_topo_t * topo,
                          ulong       net_kind_id ) {
  char const * provider = fd_pod_query_cstr( topo->props, "net.provider", "" );
  if( 0==strcmp( provider, "xdp" ) ) {
    ulong tile_id = fd_topo_find_tile( topo, "net", net_kind_id );
    if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) {
      FD_LOG_ERR(( "tile net:%lu not found", net_kind_id ));
    }
    fd_topos_xdp_setup_mem( topo, &topo->tiles[ tile_id ] );
  } else if( 0==strcmp( provider, "ibverbs" ) ) {
    ulong tile_id = fd_topo_find_tile( topo, "ibeth", net_kind_id );
    if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) {
      FD_LOG_ERR(( "tile ibeth:%lu not found", net_kind_id ));
    }
    fd_topos_ibeth_setup_mem( topo, &topo->tiles[ tile_id ] );
  } else {
    return;
  }
}
