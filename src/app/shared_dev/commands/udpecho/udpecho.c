#include "../../fd_shared_dev.h"
#include "../dev.h"
#include "../../../shared/commands/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../../../shared/commands/run/run.h" /* fdctl_check_configure */
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */

#include <unistd.h> /* pause */

static void
udpecho_topo( config_t * config ) {
  char const * affinity = config->development.udpecho.affinity;
  int is_auto_affinity = !strcmp( affinity, "auto" );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [development.udpecho.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }
  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt!=4UL ) )
      FD_LOG_ERR(( "Invalid [development.udpecho.affinity]: must include exactly three CPUs" ));
  }

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topos_net_tiles( topo, config->layout.net_tile_count, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

  fd_topob_wksp( topo, "l4swap" );
  fd_topob_tile( topo, "l4swap", "l4swap", "l4swap", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

  fd_topob_link( topo, "quic_net", "l4swap", 2048UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "l4swap", 0UL, "quic_net", 0UL );
  fd_topob_tile_in( topo, "net", 0UL, "metric_in", "quic_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topos_net_rx_link( topo, "net_quic", 0UL, config->net.ingress_buffer_size );
  fd_topob_tile_in( topo, "l4swap", 0UL, "metric_in", "net_quic", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topos_net_tile_finish( topo, 0UL );
  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );
  topo->agave_affinity_cnt = 0;
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

void
udpecho_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  ushort port_l = fd_env_strip_cmdline_ushort( pargc, pargv, "--port", NULL, 0 );
  ushort port_s = fd_env_strip_cmdline_ushort( pargc, pargv, "-p",     NULL, 0 );
  ushort port   = port_s ? port_s : port_l;
  if( FD_UNLIKELY( !port ) ) FD_LOG_ERR(( "Missing --port argument" ));
  args->udpecho.listen_port = port;
}

void
udpecho_cmd_fn( args_t *   args,
                config_t * config ) {
  udpecho_topo( config );
  fd_topo_t *      topo        = &config->topo;
  fd_topo_tile_t * net_tile    = &topo->tiles[ fd_topo_find_tile( topo, "net",    0UL ) ];
  fd_topo_tile_t * metric_tile = &topo->tiles[ fd_topo_find_tile( topo, "metric", 0UL ) ];

  net_tile->net.legacy_transaction_listen_port = args->udpecho.listen_port;

  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  configure_stage( &fd_cfg_stage_sysctl,           CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_hugetlbfs,        CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_channels, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_gro,      CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_loopback, CONFIGURE_CMD_INIT, config );

  fdctl_check_configure( config );
  /* FIXME this allocates lots of memory unnecessarily */
  initialize_workspaces( config );
  initialize_stacks( config );
  fdctl_setup_netns( config, 1 );
  (void)fd_topo_install_xdp( topo, config->net.bind_address_parsed );
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );
  for(;;) pause();
}

action_t fd_action_udpecho = {
  .name        = "udpecho",
  .args        = udpecho_cmd_args,
  .fn          = udpecho_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Run a UDP echo server"
};
