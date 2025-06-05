/* Topology support routines for the net tile */

#include "fd_net_tile.h"
#include "../topo/fd_topob.h"
#include "../netlink/fd_netlink_tile.h"
#include "../../app/shared/fd_config.h" /* FIXME layering violation */
#include "../../util/pod/fd_pod_format.h"

#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if.h> /* struct ifreq */
#include <sys/ioctl.h>

/* interface_addrs queries the MAC address and first IPv4 address of an
   interface, given an interface name. */

static void
interface_addrs( char const * interface,
                 uchar *      mac,
                 uint *       ip4_addr ) {
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  struct ifreq ifr = {0};
  ifr.ifr_addr.sa_family = AF_INET;

  strncpy( ifr.ifr_name, interface, IFNAMSIZ );
  if( FD_UNLIKELY( ioctl( fd, SIOCGIFHWADDR, &ifr ) ) ) {
    FD_LOG_ERR(( "Failed to get MAC address of interface `%s`: (%i-%s)", interface, errno, fd_io_strerror( errno ) ));
  }
  fd_memcpy( mac, ifr.ifr_hwaddr.sa_data, 6 );

  if( FD_UNLIKELY( ioctl( fd, SIOCGIFADDR, &ifr ) ) ) {
    FD_LOG_ERR(( "Failed to get IP address of interface `%s`: (%i-%s)", interface, errno, fd_io_strerror( errno ) ));
  }
  *ip4_addr = ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;

  if( FD_UNLIKELY( close(fd) ) ) {
    FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

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
  fd_pod_insert_uint( topo->props, "net.queue_cnt", net_cfg->ethtool_queue_count );

  /* Create workspaces */
  if( 0==strcmp( net_cfg->provider, "xdp" ) ) {

    fd_pod_insert_cstr( topo->props, "net.if_name", net_cfg->interface );
    fd_pod_insert_uint( topo->props, "net.if_idx",  if_nametoindex( net_cfg->interface ) );

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
  if( 0==strcmp( fd_pod_query_cstr( topo->props, "net.provider", "" ), "xdp" ) ) {
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

static fd_topo_tile_t *
prepare_xdp_queue_assign( fd_topo_t * topo,
                          ulong       xdp_tile_idx ) {
  ulong tile_id = fd_topo_find_tile( topo, "net", xdp_tile_idx );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "tile net:%lu not found", xdp_tile_idx ));
  }
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  if( FD_UNLIKELY( tile->xdp.queue_cnt >= FD_TOPO_XDP_TILE_QUEUES_MAX ) ) {
    FD_LOG_ERR(( "Cannot start, net:%lu exceeds the max of %u network queues.\n"
                  "Consider increasing [layout.net_tile_count] or decreasing [net.ethtool_queue_count]",
                  xdp_tile_idx, FD_TOPO_XDP_TILE_QUEUES_MAX ));
  }
  return tile;
}

static void
fd_topos_xdp_assign_queues( fd_topo_t * topo ) {

  /* Reverse round robin assign interface queues to net tiles */

  ulong const net_tile_cnt = fd_topo_tile_name_cnt( topo, "net" );
  ulong       net_tile_idx = net_tile_cnt-1UL;
  uint const  queue_cnt    = fd_pod_query_uint( topo->props, "net.queue_cnt", 0U );
  if( FD_UNLIKELY( !queue_cnt ) ) FD_LOG_ERR(( "net.queue_cnt not set" ));

  for( uint queue_idx=0UL; queue_idx<queue_cnt; queue_idx++ ) {
    fd_topo_tile_t *      tile  = prepare_xdp_queue_assign( topo, net_tile_idx );
    fd_topo_xdp_queue_t * queue = &tile->xdp.queues[ tile->xdp.queue_cnt ];
    queue->queue_id = queue_idx;

    fd_cstr_fini( fd_cstr_append_cstr_safe(
        fd_cstr_init( queue->if_name ),
        fd_pod_query_cstr( topo->props, "net.if_name", "" ),
        IF_NAMESIZE-1UL ) );
    queue->if_idx = fd_pod_query_uint( topo->props, "net.if_idx", 0U );

    interface_addrs( queue->if_name, queue->mac_addr, &queue->ip4_addr );
    queue->xsk_map_fd = -1; /* placeholder */

    /* Next queue */
    tile->xdp.queue_cnt++;
    net_tile_idx = fd_ulong_if( net_tile_idx==0UL, net_tile_cnt-1UL, net_tile_idx-1UL );
  }

  /* Assign loopback queue */

  do {
    fd_topo_tile_t *      tile  = prepare_xdp_queue_assign( topo, net_tile_idx );
    fd_topo_xdp_queue_t * queue = &tile->xdp.queues[ tile->xdp.queue_cnt ];

    fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( queue->if_name ), "lo" ) );
    queue->if_idx   = 1U;
    queue->queue_id = 0U;

    interface_addrs( queue->if_name, queue->mac_addr, &queue->ip4_addr );
    queue->xsk_map_fd = -1; /* placeholder */

    /* Next queue */
    tile->xdp.queue_cnt++;
    net_tile_idx = fd_ulong_if( net_tile_idx==0UL, net_tile_cnt-1UL, net_tile_idx-1UL );
  } while(0);

}

static void
fd_topos_xdp_setup_mem( fd_topo_t *      topo,
                        fd_topo_tile_t * net_tile ) {
  ulong cum_frame_cnt = 0UL;

  /* Round robin assign channels */

  ulong rx_depth = net_tile->xdp.xdp_rx_queue_size;
  ulong tx_depth = net_tile->xdp.xdp_tx_queue_size;
  rx_depth += (rx_depth/2UL);
  tx_depth += (tx_depth/2UL);
  ulong const queue_frame_cnt = rx_depth + tx_depth;
  cum_frame_cnt += queue_frame_cnt * net_tile->xdp.queue_cnt;

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
  if( 0!=strcmp( fd_pod_query_cstr( topo->props, "net.provider", "" ), "xdp" ) ) return;

  fd_topos_xdp_assign_queues( topo );

  ulong const net_tile_cnt = fd_topo_tile_name_cnt( topo, "net" );
  for( ulong net_kind_id=0UL; net_kind_id<net_tile_cnt; net_kind_id++ ) {
    ulong tile_id = fd_topo_find_tile( topo, "net", net_kind_id );
    if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) {
      FD_LOG_ERR(( "tile net:%lu not found", net_kind_id ));
    }
    fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
    fd_topos_xdp_setup_mem( topo, tile );
  }
}
