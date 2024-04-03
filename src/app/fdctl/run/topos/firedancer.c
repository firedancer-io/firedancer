#include "../../config.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "topo_util.h"

#ifdef FD_GOSSIP_DEMO
#define FD_GOSSIP_TILES 3
#else
#define FD_GOSSIP_TILES 1
#endif


void
fd_topo_firedancer( config_t * config ) {
  fd_topo_t * topo = &config->topo;

  /* Static configuration of all workspaces in the topology.  Workspace
     sizing will be determined dynamically at runtime based on how much
     space will be allocated from it. */
  ulong wksp_cnt = 0;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NETMUX_INOUT }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_STAKE_OUT    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_METRIC_IN    }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SHRED_STORE  }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_POH_SHRED    }; wksp_cnt++;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_STORE_REPAIR }; wksp_cnt++;

  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NET          }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_NETMUX       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_STORE        }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_SIGN         }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_METRIC       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_GOSSIP       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_REPAIR       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_BLOCKSTORE   }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_REPLAY       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_GOSSIP_VERIFY       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_GOSSIP_DEDUP       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_VERIFY_DEDUP       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_DEDUP_PACK       }; wksp_cnt++;
  topo->workspaces[ wksp_cnt ] = (fd_topo_wksp_t){ .id = wksp_cnt, .kind = FD_TOPO_WKSP_KIND_GOSSIP_PRE_DEDUP       }; wksp_cnt++;


  topo->wksp_cnt = wksp_cnt;

  /* Static listing of all links in the topology. */
  ulong link_cnt = 0;

  LINK( config->layout.net_tile_count,    FD_TOPO_LINK_KIND_NET_TO_NETMUX,   FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( 1,                                FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );

  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  LINK( FD_GOSSIP_TILES,                        FD_TOPO_LINK_KIND_GOSSIP_TO_NETMUX, FD_TOPO_WKSP_KIND_NETMUX_INOUT, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( config->layout.verify_tile_count,       FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP,  FD_TOPO_WKSP_KIND_GOSSIP_VERIFY, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( config->layout.gossip_dedup_tile_count, FD_TOPO_LINK_KIND_DEDUP_TO_GOSSIP,  FD_TOPO_WKSP_KIND_GOSSIP_DEDUP,  config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  LINK( config->layout.gossip_pre_dedup_tile_count, FD_TOPO_LINK_KIND_PRE_DEDUP_TO_VERIFY,  FD_TOPO_WKSP_KIND_GOSSIP_DEDUP, config->tiles.net.send_buffer_size,       FD_NET_MTU,             1UL );
  topo->link_cnt = link_cnt;

  ulong tile_cnt = 0UL;

  TILE( config->layout.net_tile_count,    FD_TOPO_TILE_KIND_NET,        FD_TOPO_WKSP_KIND_NET,        fd_topo_find_link( topo, FD_TOPO_LINK_KIND_NET_TO_NETMUX,   i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_NETMUX,     FD_TOPO_WKSP_KIND_NETMUX,     fd_topo_find_link( topo, FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   i ) );
  TILE( 1,                                FD_TOPO_TILE_KIND_SIGN,       FD_TOPO_WKSP_KIND_SIGN,       ULONG_MAX                                                       );
  TILE( 1,                                FD_TOPO_TILE_KIND_METRIC,     FD_TOPO_WKSP_KIND_METRIC,     ULONG_MAX                                                       );
  TILE( FD_GOSSIP_TILES,                                FD_TOPO_TILE_KIND_GOSSIP,     FD_TOPO_WKSP_KIND_GOSSIP,     fd_topo_find_link( topo, FD_TOPO_LINK_KIND_GOSSIP_TO_NETMUX,   i )                                                       );
  TILE( config->layout.gossip_pre_dedup_tile_count,  FD_TOPO_TILE_KIND_GOSSIP_PRE_DEDUP, FD_TOPO_WKSP_KIND_GOSSIP_PRE_DEDUP, fd_topo_find_link( topo, FD_TOPO_LINK_KIND_PRE_DEDUP_TO_VERIFY, i) );
  TILE( config->layout.verify_tile_count,        FD_TOPO_TILE_KIND_GOSSIP_VERIFY, FD_TOPO_WKSP_KIND_GOSSIP_VERIFY, fd_topo_find_link( topo, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP, i) );
  TILE( config->layout.gossip_dedup_tile_count,  FD_TOPO_TILE_KIND_GOSSIP_DEDUP, FD_TOPO_WKSP_KIND_GOSSIP_DEDUP, fd_topo_find_link( topo, FD_TOPO_LINK_KIND_DEDUP_TO_GOSSIP, i) );

  topo->tile_cnt = tile_cnt;

  for( ulong i=0; i<config->layout.net_tile_count; i++ )    TILE_IN(  FD_TOPO_TILE_KIND_NET,    i,   FD_TOPO_LINK_KIND_NETMUX_TO_OUT,   0UL, 0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.net_tile_count; i++ )    TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_NET_TO_NETMUX,   i,   0, 1 ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong i=0; i<config->layout.gossip_pre_dedup_tile_count; i++ ) TILE_IN( FD_TOPO_TILE_KIND_GOSSIP_PRE_DEDUP, i, FD_TOPO_LINK_KIND_NETMUX_TO_OUT,     0UL, 0, 1 );
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
    for( ulong j=0; j<config->layout.gossip_pre_dedup_tile_count; j++ ) {
      TILE_IN(  FD_TOPO_TILE_KIND_GOSSIP_VERIFY, i, FD_TOPO_LINK_KIND_PRE_DEDUP_TO_VERIFY,     j, 0, 1 );
    }
  }
  for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
    for( ulong j=0; j<config->layout.gossip_dedup_tile_count; j++ ) {
      TILE_IN(  FD_TOPO_TILE_KIND_GOSSIP_DEDUP, j, FD_TOPO_LINK_KIND_VERIFY_TO_DEDUP,     i, 0, 1 );
    }
  }
  for( ulong i=0; i<config->layout.gossip_dedup_tile_count; i++ ) {
    for( ulong j=0; j<FD_GOSSIP_TILES; j++ ) {
      TILE_IN(  FD_TOPO_TILE_KIND_GOSSIP, j, FD_TOPO_LINK_KIND_DEDUP_TO_GOSSIP,   i, 0, 1 );
    }
  }
  for( ulong i=0; i<FD_GOSSIP_TILES; i++ ) {
    TILE_IN(  FD_TOPO_TILE_KIND_NETMUX, 0UL, FD_TOPO_LINK_KIND_GOSSIP_TO_NETMUX,  i, 0, 1 );
  }
}
