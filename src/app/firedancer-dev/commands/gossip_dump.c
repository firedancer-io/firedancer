#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../discof/gossip/fd_gossip_tile.h"
#include "../../../util/net/fd_ip4.h"

#include <stdio.h>

void
gossip_dump_cmd_fn( args_t *   args,
                    config_t * config ) {
  (void)args;

  fd_topo_t * topo = &config->topo;

  ulong tile_id = fd_topo_find_tile( topo, "gossip", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "gossip tile not found" ));
  }
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  ulong tile_obj_id = tile->tile_obj_id;
  FD_TEST( tile_obj_id!=ULONG_MAX );
  ulong wksp_id = topo->objs[ tile_obj_id ].wksp_id;
  FD_TEST( wksp_id!=ULONG_MAX );
  fd_topo_wksp_t * wksp = &topo->workspaces[ wksp_id ];

  fd_topo_join_workspace( topo, wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  fd_gossip_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile_obj_id );

  fd_contact_info_t my_ci[1];
  *my_ci = FD_VOLATILE_CONST( *ctx->my_contact_info );

  puts( "" );
  puts( "my_contact_info:" );
  FD_BASE58_ENCODE_32_BYTES( my_ci->pubkey.uc, pubkey_b58 );
  printf( "  pubkey: %s\n", pubkey_b58 );
  printf( "  shred_version: %u\n", my_ci->shred_version );
  puts( "  sockets:" );
  for( uint i=0UL; i<FD_CONTACT_INFO_SOCKET_CNT; i++ ) {
    fd_ip4_port_t const * ele = &my_ci->sockets[ i ];
    if( ele->addr==0 && ele->port==0 ) continue;
    printf( "    proto_%02u: " FD_IP4_ADDR_FMT ":%hu\n",
            i,
            FD_IP4_ADDR_FMT_ARGS( ele->addr ),
            fd_ushort_bswap( ele->port ) );
  }
  puts( "" );

  /* TODO dump further information */
}

action_t fd_action_gossip_dump = {
  .name           = "gossip-dump",
  .args           = NULL,
  .fn             = gossip_dump_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Dump gossip tile state",
};
