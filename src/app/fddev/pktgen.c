#include "fddev.h"
#include "../fdctl/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../fdctl/run/run.h" /* fdctl_check_configure */
#include "../../disco/topo/fd_topob.h"
#include "../../util/shmem/fd_shmem_private.h" /* fd_numa_cpu_cnt */
#include "../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */

static void
add_pktgen_topo( fd_topo_t *  topo,
                 char const * affinity,
                 uint         fake_dst_ip ) {
  fd_topob_wksp( topo, "pktgen" );

  int is_auto_affinity = !strcmp( affinity, "auto" );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=fd_numa_cpu_cnt() ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [development.pktgen.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], fd_numa_cpu_cnt() ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }
  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt<1UL ) )
      FD_LOG_ERR(( "Invalid [development.pktgen.affinity]" ));
    else if( FD_UNLIKELY( affinity_tile_cnt>1UL ) )
      FD_LOG_WARNING(( "The pktgen topology you are using has 1 tile, but the CPU affinity specified "
                       "in the [development.pktgen.affinity] provides for %lu cores. The extra cores will be unused.",
                       affinity_tile_cnt ));
  }

  fd_topo_tile_t * pktgen_tile = fd_topob_tile( topo, "pktgen", "pktgen", "pktgen", tile_to_cpu[ 0 ], 0, 0 );
  pktgen_tile->pktgen.fake_dst_ip = fake_dst_ip;

  fd_topob_link( topo, "pktgen_out", "pktgen", 2048UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "pktgen", 0UL, "pktgen_out", 0UL );
  fd_topob_tile_in( topo, "net", 0UL, "metric_in", "pktgen_out", 0UL, 0, 1 );

  /* This will blow away previous auto topology layouts and recompute an auto topology. */
  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo );
  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
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

  add_pktgen_topo( &config->topo,
                   config->development.pktgen.affinity,
                   fake_dst_ip );

  if( FD_LIKELY( !args->dev.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
      configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_fn( &configure_args, config );
  }

  update_config_for_dev( config );
  fdctl_check_configure( config );
  /* FIXME this allocates lots of memory unnecessarily */
  initialize_workspaces( config );
  initialize_stacks( config );
  (void)fd_topo_install_xdp( &config->topo );;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  for(;;) pause();
}
