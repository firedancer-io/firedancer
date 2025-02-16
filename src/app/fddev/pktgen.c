#include "fddev.h"
#include "../fdctl/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../fdctl/run/run.h" /* fdctl_check_configure */
#include "../fdctl/run/topos/topos.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/topo/fd_topob.h"

void
pktgen_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  /* FIXME add config options here */
  (void)pargc; (void)pargv; (void)args;
}

void
pktgen_cmd_topo( args_t *   args FD_PARAM_UNUSED,
                 config_t * config ) {

  uint fake_dst_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.pktgen.fake_dst_ip, &fake_dst_ip ) ) ) {
    FD_LOG_ERR(( "Invalid [development.pktgen.fake_dst_ip]" ));
  }

  fd_topo_t * topo = &config->topo;
  fd_topob_wksp( topo, "pktgen" );
  fd_topob_wksp( topo, "metric_in" );

  fd_topos_affinity_t affinity[1]; fd_topos_affinity( affinity, config->development.pktgen.affinity, "development.pktgen.affinity" );
  fd_topos_net_tiles( topo, config, affinity->tile_to_cpu );

  fd_topo_tile_t * pktgen_tile = fd_topob_tile( topo, "pktgen", "pktgen", "pktgen", affinity->tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  pktgen_tile->pktgen.fake_dst_ip = fake_dst_ip;

  fd_topob_link( topo, "pktgen_out", "pktgen", 2048UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "pktgen", 0UL, "pktgen_out", 0UL );
  fd_topob_tile_in( topo, "net", 0UL, "metric_in", "pktgen_out", 0UL, 0, 1 );

  if( FD_UNLIKELY( affinity->is_auto ) ) fd_topob_auto_layout( topo );
  fd_topos_seal( topo );

  if( FD_LIKELY( !affinity->is_auto ) ) {
    if( FD_UNLIKELY( affinity->tile_cnt<topo->tile_cnt ) )
      FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [development.pktgen.affinity] only provides for %lu cores. "
                   "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                   "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                   topo->tile_cnt, affinity->tile_cnt ));
    if( FD_UNLIKELY( affinity->tile_cnt>topo->tile_cnt ) )
      FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [development.pktgen.affinity] provides for %lu cores. "
                       "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                       "individual tile counts in the [layout] section of the configuration file.",
                       topo->tile_cnt, affinity->tile_cnt ));
  }

}

void
pktgen_cmd_fn( args_t *         args,
               config_t * const config ) {
  if( FD_LIKELY( !args->dev.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    configure_args.configure.stages[ 0 ] = &fd_cfg_stage_hugetlbfs;
    configure_args.configure.stages[ 1 ] = &fd_cfg_stage_sysctl;
    configure_args.configure.stages[ 2 ] = &fd_cfg_stage_ethtool_channels;
    configure_args.configure.stages[ 3 ] = &fd_cfg_stage_ethtool_gro;
    configure_args.configure.stages[ 4 ] = &fd_cfg_stage_ethtool_loopback;
    configure_cmd_fn( &configure_args, config );
  }

  fdctl_check_configure( config );
  /* FIXME this allocates lots of memory unnecessarily */
  initialize_workspaces( config );
  initialize_stacks( config );
  fdctl_setup_netns( config );
  (void)fd_topo_install_xdp( &config->topo );;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  for(;;) pause();
}
