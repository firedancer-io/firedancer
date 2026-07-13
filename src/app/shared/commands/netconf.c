#include "../fd_config.h"
#include "../fd_action.h"
#include "../fd_bootinfo.h"

#include "../../../waltz/ip/fd_fib4.h"
#include "../../../disco/net/fd_net_tile.h"
#include "../../../waltz/mib/fd_netdev_tbl.h"
#include "../../../waltz/neigh/fd_neigh4_map.h"
#include "../../../util/pod/fd_pod_format.h"

#include <net/if.h>
#include <stdio.h>

void
netconf_cmd_fn( args_t *   args,
                config_t * config ) {
  fd_bootinfo_adopt( config );
  (void)args;

  fd_topo_t * topo = &config->topo;
  ulong wksp_id = fd_topo_find_wksp( topo, "netbase" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "netbase workspace not found" ));
  }
  fd_topo_wksp_t * netbase = &topo->workspaces[ wksp_id ];
  ulong net_wksp_id = fd_topo_find_wksp( topo, "net" );
  if( FD_UNLIKELY( net_wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "net workspace not found" ));
  fd_topo_wksp_t * net_wksp = &topo->workspaces[ net_wksp_id ];

  ulong tile_id = fd_topo_find_tile( topo, "netlnk", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "netlnk tile not found" ));
  }
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  ulong net_tile_id = fd_topo_find_tile( topo, "net", 0UL );
  if( FD_UNLIKELY( net_tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "net tile not found" ));
  fd_topo_tile_t * net_tile = &topo->tiles[ net_tile_id ];

  fd_bootinfo_check_layout( config );
  fd_topo_join_workspace( topo, netbase,  FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_join_workspace( topo, net_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  puts( "\nINTERFACES\n" );
  fd_netdev_tbl_join_t netdev[1];
  FD_TEST( fd_netdev_tbl_join( netdev, fd_topo_obj_laddr( topo, tile->netlink.netdev_tbl_obj_id ) ) );
  fd_netdev_tbl_fprintf( netdev, stdout );
  fd_netdev_tbl_leave( netdev );

  puts( "\nIPv4 ROUTES (main)\n" );
  fd_fib4_t fib4_main[1];
  FD_TEST( fd_net_tile_fib4_join( fib4_main, topo, net_tile, 1 ) );
  fd_fib4_fprintf( fib4_main, stdout );
  fd_fib4_leave( fib4_main );

  puts( "\nIPv4 ROUTES (local)\n" );
  fd_fib4_t fib4_local[1];
  FD_TEST( fd_net_tile_fib4_join( fib4_local, topo, net_tile, 0 ) );
  fd_fib4_fprintf( fib4_local, stdout );
  fd_fib4_leave( fib4_local );

  printf( "\nNEIGHBOR TABLE (%.16s)\n\n", tile->netlink.neigh_if );
  fd_neigh4_hmap_t neigh4[1];
  ulong neigh4_obj_id = tile->netlink.neigh4_obj_id;
  ulong ele_max   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong probe_max = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong seed      = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  FD_TEST( (ele_max!=ULONG_MAX) & (probe_max!=ULONG_MAX) & (seed!=ULONG_MAX) );
  FD_TEST( fd_neigh4_hmap_join( neigh4, fd_topo_obj_laddr( topo, neigh4_obj_id ), ele_max, probe_max, seed ) );
  fd_neigh4_hmap_fprintf( neigh4, stdout );
  fd_neigh4_hmap_leave( neigh4 );

  puts( "" );
}

action_t fd_action_netconf = {
  .name           = "netconf",
  .args           = NULL,
  .fn             = netconf_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .description    = "Print network configuration",
  .detail         = "Connects to a running validator and prints the networking state its\n"
                    "net tiles have discovered, including the routing (FIB), interface (MIB), and\n"
                    "neighbor (ARP) tables.",
};
