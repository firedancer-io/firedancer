#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../disco/topo/fd_topo.h"
#include "../../../disco/topo/fd_dns_resolve.h"
#include "../../../discof/ipecho/fd_ipecho_client.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
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

  fd_ip4_port_t entrypoints[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];
  fd_dns_resolve_peers( tile->gossip.entrypoints[ 0 ], sizeof(tile->gossip.entrypoints[ 0 ]), tile->gossip.entrypoints_cnt, "gossip.entrypoints", entrypoints );
  int epoll_fd = epoll_create1( 0 );
  if( FD_UNLIKELY( -1==epoll_fd ) ) FD_LOG_ERR(( "epoll_create1 failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_ipecho_client_init( client, entrypoints, tile->gossip.entrypoints_cnt, epoll_fd );

  for(;;) {
    ushort shred_version = 0;
    int _charge_busy;
    int err = fd_ipecho_client_poll( client, fd_log_wallclock(), &shred_version, &_charge_busy );
    if( FD_UNLIKELY( -1==err ) ) FD_LOG_ERR(( "couldn't get shred version" ));
    if( FD_UNLIKELY( !err) ) {
      FD_LOG_STDOUT(( "%hu\n", shred_version ));
      break;
    }
    struct epoll_event ev;
    if( FD_UNLIKELY( -1==epoll_wait( epoll_fd, &ev, 1, 100 ) && errno!=EINTR ) ) FD_LOG_ERR(( "epoll_wait failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

action_t fd_action_shred_version = {
  .name        = "shred-version",
  .fn          = shred_version_cmd_fn,
  .description = "Retrieve the current shred version from the entrypoints",
  .detail      = "Connects to the gossip entrypoints listed in the configuration file using the\n"
                 "IP echo protocol, prints the cluster's current shred version to stdout, and\n"
                 "exits.  Useful for filling in [consensus.expected_shred_version].  Does not\n"
                 "require a running validator, but the entrypoints must be reachable.",
  .usage       = "shred-version",
};
