#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../disco/topo/fd_topo.h"
#include "../../../discof/ipecho/fd_ipecho_client.h"

#include <unistd.h>

void
shred_version_cmd_fn( args_t *   args,
                      config_t * config ) {
  (void)args;

  void * _client = aligned_alloc( FD_IPECHO_CLIENT_ALIGN, fd_ipecho_client_footprint() );
  FD_TEST( _client );
  fd_ipecho_client_t * client = fd_ipecho_client_join( fd_ipecho_client_new( _client ) );
  FD_TEST( client );

  ulong tile_idx = fd_topo_find_tile( &config->topo, "gossip", 0UL );
  FD_TEST( tile_idx!=ULONG_MAX );

  fd_topo_tile_t * tile = &config->topo.tiles[ tile_idx ];
  fd_ipecho_client_init( client, tile->gossip.entrypoints, tile->gossip.entrypoints_cnt );

  for(;;) {
    ushort shred_version = 0;
    int _charge_busy;
    int err = fd_ipecho_client_poll( client, &shred_version, &_charge_busy );
    if( FD_UNLIKELY( -1==err ) ) FD_LOG_ERR(( "couldn't get shred version" ));
    if( FD_UNLIKELY( !err) ) {
      FD_LOG_STDOUT(( "%hu\n", shred_version ));
      break;
    }
  }
}

action_t fd_action_shred_version = {
  .name        = "shred-version",
  .fn          = shred_version_cmd_fn,
  .description = "Retrieve the current shred version from the entrypoints",
};
