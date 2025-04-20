#include "../fd_config.h"

#include "../../../waltz/dns/fd_dns_cache.h"
#include "../../../waltz/ip/fd_fib4.h"
#include "../../../waltz/mib/fd_dbl_buf.h"
#include "../../../waltz/mib/fd_netdev_tbl.h"
#include "../../../waltz/neigh/fd_neigh4_map.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h> /* aligned_alloc */

void
netconf_cmd_fn( args_t *   args,
                config_t * config ) {
  (void)args;

  fd_topo_t * topo = &config->topo;
  ulong const netbase_wksp_id = fd_topo_find_wksp( topo, "netbase" );
  if( FD_UNLIKELY( netbase_wksp_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "netbase workspace not found" ));
  }
  fd_topo_wksp_t * const netbase = &topo->workspaces[ netbase_wksp_id ];

  ulong const netlnk_tile_id = fd_topo_find_tile( topo, "netlnk", 0UL );
  if( FD_UNLIKELY( netlnk_tile_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "netlnk tile not found" ));
  }
  fd_topo_tile_t * netlnk_tile = &topo->tiles[ netlnk_tile_id ];

  fd_topo_wksp_t * dns_cache = NULL;
  ulong dns_cache_wksp_id = fd_topo_find_wksp( topo, "dns_cache" );
  if( FD_UNLIKELY( dns_cache_wksp_id!=ULONG_MAX ) ) {
    dns_cache = &topo->workspaces[ dns_cache_wksp_id ];
  }

  fd_topo_tile_t * dns_tile = NULL;
  ulong const dns_tile_id = fd_topo_find_tile( topo, "dns", 0UL );
  if( FD_UNLIKELY( dns_tile_id!=ULONG_MAX ) ) {
    dns_tile = &topo->tiles[ dns_tile_id ];
  }

  fd_topo_join_workspace( topo, netbase, FD_SHMEM_JOIN_MODE_READ_ONLY );

  puts( "\nINTERFACES\n" );
  fd_dbl_buf_t * netdev_buf = fd_dbl_buf_join( fd_topo_obj_laddr( topo, netlnk_tile->netlink.netdev_dbl_buf_obj_id ) );
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
  fd_fib4_t * fib4_main = fd_fib4_join( fd_topo_obj_laddr( topo, netlnk_tile->netlink.fib4_main_obj_id ) );
  FD_TEST( fib4_main );
  fd_fib4_fprintf( fib4_main, stdout );
  fd_fib4_leave( fib4_main );

  puts( "\nIPv4 ROUTES (local)\n" );
  fd_fib4_t * fib4_local = fd_fib4_join( fd_topo_obj_laddr( topo, netlnk_tile->netlink.fib4_local_obj_id ) );
  FD_TEST( fib4_local );
  fd_fib4_fprintf( fib4_local, stdout );
  fd_fib4_leave( fib4_local );

  printf( "\nNEIGHBOR TABLE (%.16s)\n\n", netlnk_tile->netlink.neigh_if );
  fd_neigh4_hmap_t neigh4[1];
  FD_TEST( fd_neigh4_hmap_join( neigh4, fd_topo_obj_laddr( topo, netlnk_tile->netlink.neigh4_obj_id ), fd_topo_obj_laddr( topo, netlnk_tile->netlink.neigh4_ele_obj_id ) ) );
  fd_neigh4_hmap_fprintf( neigh4, stdout );
  fd_neigh4_hmap_leave( neigh4 );

  if( dns_tile && dns_cache ) {
    fd_topo_join_workspace( topo, dns_cache, FD_SHMEM_JOIN_MODE_READ_ONLY );
    puts( "\nDNS CACHE\n" );
    fd_dns_cache_join_t ljoin[1];
    FD_TEST( fd_dns_cache_join( fd_topo_obj_laddr( topo, dns_tile->dns.dns_cache_obj_id ), ljoin ) );
    fd_dns_cache_query_t query[1];
    fd_dns_cache_addr_t * addr = fd_dns_cache_query_start( ljoin, query, dns_tile->dns.bundle_domain, dns_tile->dns.bundle_domain_len );
    printf( "- %.*s:", (int)dns_tile->dns.bundle_domain_len, dns_tile->dns.bundle_domain );
    if( FD_UNLIKELY( !addr ) ) {
      puts( " not found" );
    } else {
      puts( "" );
      do {
        char addr_str[ INET6_ADDRSTRLEN ];
        if( FD_UNLIKELY( !inet_ntop( AF_INET6, addr->ip6, addr_str, sizeof(addr_str) ) ) ) FD_LOG_ERR(( "inet_ntop failed" ));
        printf( "  - %s\n", addr_str );
        addr = fd_dns_cache_query_next( ljoin, query );
      } while( addr );
    }
    fd_dns_cache_leave( ljoin );
  }

  puts( "" );
}

action_t fd_action_netconf = {
  .name        = "netconf",
  .args        = NULL,
  .fn          = netconf_cmd_fn,
  .perm        = NULL,
  .description = "Print network configuration",
};
