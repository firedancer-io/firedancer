#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus */
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */
#include "../../../util/pod/fd_pod_format.h"
#include "../../../util/net/fd_ip4.h" /* fd_cstr_to_ip4_addr */

#include <stdio.h> /* printf */
#include <unistd.h> /* isatty */
#include <sys/ioctl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
gossip_topo( config_t * config ) {
  static const ulong tile_to_cpu[ FD_TILE_MAX ] = {0}; /* TODO */

  config->layout.net_tile_count = 1;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topo_tile_t * metric_tile = fd_topob_tile( topo, "metric", "metric", "metric_in", ULONG_MAX, 0, 0 );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  fd_topos_net_tiles( topo, 1UL, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );
  ulong net_tile_id = fd_topo_find_tile( topo, "net", 0UL );
  if( net_tile_id==ULONG_MAX ) net_tile_id = fd_topo_find_tile( topo, "sock", 0UL );
  if( FD_UNLIKELY( net_tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "net tile not found" ));
  fd_topo_tile_t * net_tile = &topo->tiles[ net_tile_id ];
  net_tile->net.gossip_listen_port = config->gossip.port;

  fd_topob_wksp( topo, "gossip" );
  fd_topo_tile_t * gossip_tile = fd_topob_tile( topo, "gossip", "gossip", "metric_in", 0UL, 0, 0 );

  strncpy( gossip_tile->gossip.identity_key_path, config->paths.identity_key, sizeof(gossip_tile->gossip.identity_key_path) );
  gossip_tile->gossip.gossip_listen_port     = config->gossip.port;
  gossip_tile->gossip.ip_addr                = config->net.ip_addr;
  gossip_tile->gossip.expected_shred_version = config->consensus.expected_shred_version;
  gossip_tile->gossip.entrypoints_cnt = fd_ulong_min( config->gossip.resolved_entrypoints_cnt, FD_TOPO_GOSSIP_ENTRYPOINTS_MAX );
  fd_memcpy( gossip_tile->gossip.entrypoints, config->gossip.resolved_entrypoints, gossip_tile->gossip.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  if( FD_UNLIKELY( !gossip_tile->gossip.entrypoints_cnt ) ) {
    FD_LOG_ERR(( "Missing [tiles.gossip.entrypoints]" ));
  }
  if( FD_UNLIKELY( !gossip_tile->gossip.expected_shred_version ) ) {
    FD_LOG_ERR(( "Missing [consensus.expected_shred_version]" ));
  }

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", 0UL, 0, 1 );
  strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );
  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_link( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp( topo, "sign_gossip"  );
  fd_topob_link( topo, "sign_gossip", "sign_gossip", 128UL,   64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );

  fd_topob_wksp( topo, "gossip_net" );
  fd_topob_link( topo, "gossip_net", "gossip_net", config->net.ingress_buffer_size, FD_NET_MTU, 1UL );

  fd_topos_net_rx_link( topo, "net_gossip", 0UL, config->net.ingress_buffer_size );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "net_gossip",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "sign_gossip",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topos_tile_in_net( topo, "metric_in", "gossip_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_net", 0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign", 0UL );

  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "gossip" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  fd_topob_tile_uses( topo, gossip_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topos_net_tile_finish( topo, 0UL );
  fd_topob_auto_layout( topo, 0 );
  topo->agave_affinity_cnt = 0;
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
gossip_cmd_args( int *    pargc FD_PARAM_UNUSED,
                 char *** pargv FD_PARAM_UNUSED,
                 args_t * args  FD_PARAM_UNUSED ) {}

static void
gossip_cmd_fn( args_t *   args FD_PARAM_UNUSED,
               config_t * config ) {
  gossip_topo( config );
  fd_topo_t * topo = &config->topo;

  configure_stage( &fd_cfg_stage_sysctl,           CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_hugetlbfs,        CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_channels, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_gro,      CONFIGURE_CMD_INIT, config );

  initialize_workspaces( config );
  initialize_stacks( config );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_topo_install_xdp( topo, config->net.bind_address_parsed );
  }
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  for(;;) pause();
}

static void
configure_stage_perm( configure_stage_t const * stage,
                      fd_cap_chk_t *            chk,
                      config_t const *          config ) {
  int enabled = !stage->enabled || stage->enabled( config );
  if( enabled && stage->check( config ).result != CONFIGURE_OK )
    if( stage->init_perm ) stage->init_perm( chk, config );
}

static void
gossip_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                 fd_cap_chk_t *   chk,
                 config_t const * config ) {
  configure_stage_perm( &fd_cfg_stage_sysctl,           chk, config );
  configure_stage_perm( &fd_cfg_stage_hugetlbfs,        chk, config );
  configure_stage_perm( &fd_cfg_stage_ethtool_channels, chk, config );
  configure_stage_perm( &fd_cfg_stage_ethtool_gro,      chk, config );
}

action_t fd_action_gossip = {
  .name        = "gossip",
  .description = "Run the gossip tile (peer discovery)",
  .args        = gossip_cmd_args,
  .fn          = gossip_cmd_fn,
  .perm        = gossip_cmd_perm,
};
