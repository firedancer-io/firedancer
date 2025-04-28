#include "../fd_config.h"
#include "../fd_action.h"

#include "../../../waltz/ip/fd_fib4.h"
#include "../../../waltz/mib/fd_dbl_buf.h"
#include "../../../waltz/mib/fd_netdev_tbl.h"
#include "../../../waltz/neigh/fd_neigh4_map.h"

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h> /* aligned_alloc */

void
netconf_cmd_fn( args_t *   args,
                config_t * config ) {
  (void)args;

  fd_topo_t * topo = &config->topo;
  ulong wksp_id = fd_topo_find_wksp( topo, "netbase" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "netbase workspace not found" ));
  }
  fd_topo_wksp_t * netbase = &topo->workspaces[ wksp_id ];

  ulong tile_id = fd_topo_find_tile( topo, "netlnk", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "netlnk tile not found" ));
  }
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  fd_topo_join_workspace( topo, netbase, FD_SHMEM_JOIN_MODE_READ_ONLY );

  puts( "\nINTERFACES\n" );
  fd_dbl_buf_t * netdev_buf = fd_dbl_buf_join( fd_topo_obj_laddr( topo, tile->netlink.netdev_dbl_buf_obj_id ) );
  FD_TEST( netdev_buf );
  void * netdev_copy = aligned_alloc( fd_netdev_tbl_align(), fd_dbl_buf_obj_mtu( netdev_buf ) );
  fd_dbl_buf_read( netdev_buf, netdev_copy, NULL );
  fd_netdev_tbl_join_t netdev[1];
  FD_TEST( fd_netdev_tbl_join( netdev, netdev_copy ) );
  fd_netdev_tbl_fprintf( netdev, stdout );
  fd_netdev_tbl_leave( netdev );
  free( netdev_copy );
  fd_dbl_buf_leave( netdev_buf );

  puts( "\nIPv4 ROUTES (main)\n" );
  fd_fib4_t * fib4_main = fd_fib4_join( fd_topo_obj_laddr( topo, tile->netlink.fib4_main_obj_id ) );
  FD_TEST( fib4_main );
  fd_fib4_fprintf( fib4_main, stdout );
  fd_fib4_leave( fib4_main );

  puts( "\nIPv4 ROUTES (local)\n" );
  fd_fib4_t * fib4_local = fd_fib4_join( fd_topo_obj_laddr( topo, tile->netlink.fib4_local_obj_id ) );
  FD_TEST( fib4_local );
  fd_fib4_fprintf( fib4_local, stdout );
  fd_fib4_leave( fib4_local );

  printf( "\nNEIGHBOR TABLE (%.16s)\n\n", tile->netlink.neigh_if );
  fd_neigh4_hmap_t neigh4[1];
  FD_TEST( fd_neigh4_hmap_join( neigh4, fd_topo_obj_laddr( topo, tile->netlink.neigh4_obj_id ), fd_topo_obj_laddr( topo, tile->netlink.neigh4_ele_obj_id ) ) );
  fd_neigh4_hmap_fprintf( neigh4, stdout );
  fd_neigh4_hmap_leave( neigh4 );

  puts( "" );
}

action_t fd_action_netconf = {
  .name        = "netconf",
  .args        = NULL,
  .fn          = netconf_cmd_fn,
  .perm        = NULL,
  .description = "Print network configuration",
};
