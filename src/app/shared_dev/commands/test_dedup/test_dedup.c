#include "../../../shared/commands/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../../../shared/commands/run/run.h" /* fdctl_check_configure */
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */

#include <unistd.h> /* pause */

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
test_dedup_topo( config_t *   config,
                 char const * affinity ) {
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
      FD_LOG_ERR(( "The --affinity flag specifies a CPU index of %hu, but the system only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }
  if( FD_LIKELY( !is_auto_affinity ) ) {
    FD_LOG_NOTICE(( "Using --affinity %s", affinity ));
    FD_LOG_NOTICE(( "affinity_tile_cnt %lu", affinity_tile_cnt ));
    if( FD_UNLIKELY( affinity_tile_cnt!=3UL ) )
      FD_LOG_ERR(( "Invalid --affinity: must include exactly 3 CPUs" ));
  }

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "test_dedup" );
  fd_topob_wksp( topo, "metric_in"  );
  fd_topo_tile_t * dedup_tile  = fd_topob_tile( topo, "dedup",  "test_dedup", "metric_in", tile_to_cpu[ 0 ], 0, 0 );
  fd_topo_tile_t * tduptx_tile = fd_topob_tile( topo, "TDupTx", "test_dedup", "metric_in", tile_to_cpu[ 1 ], 0, 0 );
  fd_topo_tile_t * tduprx_tile = fd_topob_tile( topo, "TDupRx", "test_dedup", "metric_in", tile_to_cpu[ 2 ], 0, 0 );

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

void
test_dedup_cmd_args( int *    pargc,
                     char *** pargv,
                     args_t * args ) {
  char const * affinity           = fd_env_strip_cmdline_cstr ( pargc, pargv, "--affinity",       NULL, "auto"                     );
  args->test_dedup.tx_cnt         = fd_env_strip_cmdline_ulong( pargc, pargv, "--tx-cnt",         NULL, 2UL                        );
  args->test_dedup.tx_depth       = fd_env_strip_cmdline_ulong( pargc, pargv, "--tx-depth",       NULL, 32768UL                    );
  args->test_dedup.tx_mtu         = fd_env_strip_cmdline_ulong( pargc, pargv, "--tx-mtu",         NULL, 1472UL                     );
  args->test_dedup.tcache_depth   = fd_env_strip_cmdline_ulong( pargc, pargv, "--tcache-depth",   NULL, 4194302UL                  );
  args->test_dedup.tcache_map_cnt = fd_env_strip_cmdline_ulong( pargc, pargv, "--tcache-map-cnt", NULL, 0UL /* use default */      );
  args->test_dedup.dedup_depth    = fd_env_strip_cmdline_ulong( pargc, pargv, "--dedup-depth",    NULL, 32768UL                    );
  args->test_dedup.dedup_cr_max   = fd_env_strip_cmdline_ulong( pargc, pargv, "--dedup-cr-max",   NULL, 0UL /* use default */      );
  args->test_dedup.dedup_lazy     = fd_env_strip_cmdline_long ( pargc, pargv, "--dedup-lazy",     NULL, 0L /* use default */       );
  args->test_dedup.rx_cnt         = fd_env_strip_cmdline_ulong( pargc, pargv, "--rx-cnt",         NULL, 2UL                        );
  args->test_dedup.test_depth     = fd_env_strip_cmdline_ulong( pargc, pargv, "--test-depth",     NULL, 2046UL                     );
  args->test_dedup.test_map_cnt   = fd_env_strip_cmdline_ulong( pargc, pargv, "--test-map-cnt",   NULL, 0UL /* use default */      );

  args->test_dedup.burst_avg       = fd_env_strip_cmdline_float( pargc, pargv, "--burst-avg",       NULL, 1472.f );
  args->test_dedup.pkt_payload_max = fd_env_strip_cmdline_ulong( pargc, pargv, "--pkt-payload-max", NULL, 1472UL );
  args->test_dedup.pkt_framing     = fd_env_strip_cmdline_ulong( pargc, pargv, "--pkt-framing",     NULL,   70UL );
  args->test_dedup.pkt_bw          = fd_env_strip_cmdline_float( pargc, pargv, "--pkt-bw",          NULL,  25e9f );
  args->test_dedup.dup_frac        = fd_env_strip_cmdline_float( pargc, pargv, "--dup-frac",        NULL,   0.9f );
  args->test_dedup.dup_avg_age     = fd_env_strip_cmdline_float( pargc, pargv, "--dup-avg-age",     NULL, 1e-3f*(float)args->test_dedup.tcache_depth );

  FD_TEST( strlen( affinity )<sizeof(args->test_dedup.affinity) );
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( args->test_dedup.affinity ), affinity ) );

  if( FD_UNLIKELY( !args->test_dedup.tx_cnt ) ) FD_LOG_ERR(( "tx_cnt should be positive" ));
  if( FD_UNLIKELY( !args->test_dedup.rx_cnt ) ) FD_LOG_ERR(( "rx_cnt should be positive" ));

  if( FD_UNLIKELY( args->test_dedup.test_depth>args->test_dedup.tcache_depth ) ) {
    FD_LOG_ERR(( "--test-depth should be at most --tcache-depth" ));
  }
}

void
test_dedup_cmd_fn( args_t *   args,
                config_t * config ) {
  test_dedup_topo( config, args->test_dedup.affinity );
  fd_topo_t * topo = &config->topo;

  configure_stage( &fd_cfg_stage_hugetlbfs, CONFIGURE_CMD_INIT, config );

  fdctl_check_configure( config );
  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );
  for(;;) pause();
}

action_t fd_action_test_dedup = {
  .name        = "test-dedup",
  .args        = test_dedup_cmd_args,
  .fn          = test_dedup_cmd_fn,
  .description = "Test the dedup tile"
};
