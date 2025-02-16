/* Topology support routines for the net tile */

#include "fd_net_tile.h"
#include "../topo/fd_topob.h"
#include "../netlink/fd_netlink_tile.h"
#include "../../app/fdctl/config.h"

void
fd_topos_net_tiles( fd_topo_t *      topo,
                    config_t const * config,
                    ulong const      tile_to_cpu[ FD_TILE_MAX ] ) {
  ulong net_tile_cnt = config->layout.net_tile_count;

  /* Create workspaces */

  /* net: private working memory of the net tiles */
  fd_topob_wksp( topo, "net" );
  /* netlnk: private working memory of the netlnk tile */
  fd_topob_wksp( topo, "netlnk" );
  /* netbase: shared network config (config plane) */
  fd_topob_wksp( topo, "netbase" );
  /* net_netlnk: net->netlnk ARP requests */
  fd_topob_wksp( topo, "net_netlnk" );

  /* Create topology */

  fd_topob_link( topo, "net_netlnk", "net_netlnk", 128UL, 0UL, 0UL );

  fd_topo_tile_t * netlink_tile = fd_topob_tile( topo, "netlnk", "netlnk", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  fd_netlink_topo_create( netlink_tile, topo, config );

  for( ulong i=0UL; i<net_tile_cnt; i++ ) {

    fd_topo_tile_t * tile = fd_topob_tile( topo, "net", "net", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
    fd_topob_tile_in(  topo, "netlnk", 0UL, "metric_in", "net_netlnk", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "net",    i,                "net_netlnk", i );
    fd_netlink_topo_join( topo, netlink_tile, tile );

    strncpy( tile->net.interface,    config->tiles.net.interface, sizeof(tile->net.interface) );
    memcpy(  tile->net.src_mac_addr, config->tiles.net.mac_addr,  6UL );

    tile->net.tx_flush_timeout_ns = (long)config->tiles.net.flush_timeout_micros * 1000L;
    tile->net.xdp_rx_queue_size = config->tiles.net.xdp_rx_queue_size;
    tile->net.xdp_tx_queue_size = config->tiles.net.xdp_tx_queue_size;
    tile->net.src_ip_addr       = config->tiles.net.ip_addr;
    tile->net.zero_copy         = !!strcmp( config->tiles.net.xdp_mode, "skb" ); /* disable zc for skb */
    fd_memset( tile->net.xdp_mode, 0, 4 );
    fd_memcpy( tile->net.xdp_mode, config->tiles.net.xdp_mode, strnlen( config->tiles.net.xdp_mode, 3 ) );  /* GCC complains about strncpy */

    tile->net.netdev_dbl_buf_obj_id = netlink_tile->netlink.netdev_dbl_buf_obj_id;
    tile->net.fib4_main_obj_id      = netlink_tile->netlink.fib4_main_obj_id;
    tile->net.fib4_local_obj_id     = netlink_tile->netlink.fib4_local_obj_id;
    tile->net.neigh4_obj_id         = netlink_tile->netlink.neigh4_obj_id;
    tile->net.neigh4_ele_obj_id     = netlink_tile->netlink.neigh4_ele_obj_id;

  }
}
