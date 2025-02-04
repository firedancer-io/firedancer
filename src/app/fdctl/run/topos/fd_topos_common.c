#include "topos.h"
#include "../../fdctl.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/netlink/fd_netlink_tile.h" /* fd_netlink_topo_create */
#include "../../../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */
#include "../../../../util/shmem/fd_shmem_private.h" /* fd_numa_cpu_cnt() */

void
fd_topos_affinity( fd_topos_affinity_t * affinity,
                   char const *          affinity_str ) {
  memset( affinity, 0, sizeof(fd_topos_affinity_t) );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  affinity->is_auto = !strcmp( affinity_str, "auto" );

  affinity->tile_cnt = 0UL;
  if( FD_LIKELY( !affinity->is_auto ) ) affinity->tile_cnt = fd_tile_private_cpus_parse( affinity_str, parsed_tile_to_cpu );

  for( ulong i=0UL; i<affinity->tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=fd_numa_cpu_cnt() ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], fd_numa_cpu_cnt() ));
    affinity->tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }
}

void
fd_topos_detect_affinity_mismatch( fd_topo_t const *           topo,
                                   fd_topos_affinity_t const * affinity ) {
  if( FD_LIKELY( !affinity->is_auto ) ) {
    if( FD_UNLIKELY( affinity->tile_cnt<topo->tile_cnt ) )
      FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                   "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                   "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                   topo->tile_cnt, affinity->tile_cnt ));
    if( FD_UNLIKELY( affinity->tile_cnt>topo->tile_cnt ) )
      FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                       "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                       "individual tile counts in the [layout] section of the configuration file.",
                       topo->tile_cnt, affinity->tile_cnt ));
  }
}

void
fd_topos_seal( fd_topo_t *                 topo,
               fd_topos_affinity_t const * affinity ) {
  if( FD_UNLIKELY( affinity->is_auto ) ) fd_topob_auto_layout( topo );
  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
}


void
fd_topos_add_net_tile( fd_topo_t *      topo,
                       config_t const * config,
                       ulong const      tile_to_cpu[ FD_TILE_MAX ] ) {
  ulong net_tile_cnt = config->layout.net_tile_count;

  fd_topob_wksp( topo, "net"          );
  fd_topob_wksp( topo, "netlnk"       );
  fd_topob_wksp( topo, "netbase"      );
  fd_topob_wksp( topo, "net_netlink"  );

  fd_topob_link( topo, "net_netlink", "net_netlink", 128UL, 0UL, 0UL );

  fd_topo_tile_t * netlink_tile = fd_topob_tile( topo, "netlnk", "netlnk", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0 );
  fd_netlink_topo_create( netlink_tile, topo, config );

  for( ulong i=0UL; i<net_tile_cnt; i++ ) {

    fd_topo_tile_t * tile = fd_topob_tile( topo, "net", "net", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0 );
    fd_topob_tile_in(  topo, "netlnk", 0UL, "metric_in", "net_netlink", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "net",    i,                "net_netlink", i );
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
