#include "fddev.h"
#include "../fdctl/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../fdctl/run/run.h" /* fdctl_check_configure */
#include "../fdctl/run/topos/topos.h"
#include "../../disco/topo/fd_topob.h"

static void
add_pktgen_topo( fd_topo_t *           topo,
                 fd_topos_affinity_t * affinity,
                 uint                  fake_dst_ip ) {
  fd_topob_wksp( topo, "pktgen" );

  fd_topo_tile_t * pktgen_tile = fd_topob_tile( topo, "pktgen", "pktgen", "pktgen", affinity->tile_to_cpu[ topo->tile_cnt ], 0 );
  pktgen_tile->pktgen.fake_dst_ip = fake_dst_ip;

  fd_topob_link( topo, "pktgen_out", "pktgen", 2048UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "pktgen", 0UL, "pktgen_out", 0UL );
  fd_topob_tile_in( topo, "net", 0UL, "metric_in", "pktgen_out", 0UL, 0, 1 );
}

void
pktgen_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  /* FIXME add config options here */
  (void)pargc; (void)pargv; (void)args;
}

void
pktgen_cmd_fn( args_t *         args,
               config_t * const config ) {
  uint fake_dst_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.pktgen.fake_dst_ip, &fake_dst_ip ) ) ) {
    FD_LOG_ERR(( "Invalid [development.pktgen.fake_dst_ip]" ));
  }

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name, fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size ) ) };
  fd_topos_affinity_t affinity[1]; fd_topos_affinity( affinity, config->development.pktgen.affinity );
  fd_topob_wksp( topo, "metric_in" );
  fd_topos_add_net_tile( topo, config, affinity->tile_to_cpu );
  add_pktgen_topo( &config->topo, affinity, fake_dst_ip );
  fd_topos_detect_affinity_mismatch( topo, affinity );
  fd_topos_seal( topo, affinity );

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
  (void)fd_topo_install_xdp( &config->topo );;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  for(;;) pause();
}
