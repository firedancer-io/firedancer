#ifndef CORE_SUBTOPO_H
#define CORE_SUBTOPO_H

#include "../../shared/fd_config.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */

extern fd_topo_obj_callbacks_t * CALLBACKS[];

/* core_subtopo creates the 'core' subtopo: net, metrics, and sign tiles.
   and the links between them.
   Other tiles and links can be attached to these after it returns.
   Therefore, it does not call finish (neither net nor topo )

   ALL SUBTOPOS should be disjoint! */
FD_FN_UNUSED static void
fd_core_subtopo( config_t * config, ulong tile_to_cpu[ FD_TILE_MAX ] ) {
  fd_topo_t * topo = &config->topo;

  static char* const tiles_to_add[] = {
    "metric",
    "net",
    "sign",
  };
  for( int i=0; i<3; ++i) FD_TEST( fd_topo_find_tile( topo, tiles_to_add[i], 0UL ) == ULONG_MAX );

  ulong net_tile_cnt  = config->layout.net_tile_count;
  ulong sign_tile_cnt = config->firedancer.layout.sign_tile_count;

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topo_tile_t * metric_tile = fd_topob_tile( topo, "metric", "metric", "metric_in", ULONG_MAX, 0, 0 );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  fd_topos_net_tiles( topo, net_tile_cnt, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );
  ulong net_tile_id = fd_topo_find_tile( topo, "net", 0UL );
  if( net_tile_id==ULONG_MAX ) net_tile_id = fd_topo_find_tile( topo, "sock", 0UL );
  if( FD_UNLIKELY( net_tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "net tile not found" ));
  fd_topo_tile_t * net_tile = &topo->tiles[ net_tile_id ];
  net_tile->net.gossip_listen_port = config->gossip.port;

  fd_topob_wksp( topo, "sign" );
  for( ulong i=0UL; i<sign_tile_cnt; i++ ) {
    fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );
  }
}


/* Use fd_link_permit_no_producers with links that do not have any
   producers.  This may be required in sub-topologies used for
   development and testing. */
FD_FN_UNUSED static ulong
fd_link_permit_no_producers( fd_topo_t * topo, char * link_name ) {
  ulong found = 0UL;
  for( ulong link_i = 0UL; link_i < topo->link_cnt; link_i++ ) {
    if( !strcmp( topo->links[ link_i ].name, link_name ) ) {
      topo->links[ link_i ].permit_no_producers = 1;
      found++;
    }
  }
  return found;
}

/* Use fd_link_permit_no_consumers with links that do not have any
   consumers.  This may be required in sub-topologies used for
   development and testing. */
FD_FN_UNUSED static ulong
fd_link_permit_no_consumers( fd_topo_t * topo, char * link_name ) {
  ulong found = 0UL;
  for( ulong link_i = 0UL; link_i < topo->link_cnt; link_i++ ) {
    if( !strcmp( topo->links[ link_i ].name, link_name ) ) {
      topo->links[ link_i ].permit_no_consumers = 1;
      found++;
    }
  }
  return found;
}

#endif /* CORE_SUBTOPO_H */
