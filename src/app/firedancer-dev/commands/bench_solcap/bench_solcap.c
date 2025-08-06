#include "../../../shared_dev/fd_shared_dev.h"
#include "../../../shared/commands/run/run.h"
#include "../../../shared/commands/configure/configure.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include <unistd.h>

/* Publisher tile (generates test packets) */

extern fd_topo_run_tile_t bench_solcap_producer_tile;

/* Topology */

static void
bench_solcap_cmd_args( int *    pargc,
                       char *** pargv,
                       args_t * args ) {
  (void)pargc; (void)pargv; (void)args;
}

static void
bench_solcap_topo( config_t * config,
                   args_t *   args ) {
  (void)args;
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "solcap" );
  fd_topo_tile_t * tile_solcap = fd_topob_tile( topo, "solcap", "solcap", "solcap", 0UL, 0, 0 );
  tile_solcap->solcap.block_cnt =   256UL;
  tile_solcap->solcap.block_sz  = 65536UL;
  tile_solcap->solcap.use_uring = 1;

  fd_topob_tile( topo, "pktgn1", "solcap", "solcap", 0UL, 0, 0 );

  fd_topob_link( topo, "pktgn1_out", "solcap", 4096UL, 256UL, 1UL );
  fd_topob_tile_out( topo, "pktgn1", 0UL, "pktgn1_out", 0UL );
  fd_topob_tile_in( topo, "solcap", 0UL, "solcap", "pktgn1_out", 0UL, 1, 1 );

  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

/* Command-line */

static void
bench_solcap_cmd_fn( args_t *   args,
                     config_t * config ) {
  strcpy( config->hugetlbfs.max_page_size, "huge" );
  bench_solcap_topo( config, args );

  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong            solcap_tile_idx = fd_topo_find_tile( topo, "solcap", 0UL );
  ulong            gen_tile_idx    = fd_topo_find_tile( topo, "pktgn1", 0UL );
  fd_topo_tile_t * solcap_tile     = &topo->tiles[ solcap_tile_idx ];
  fd_topo_tile_t * gen_tile        = &topo->tiles[ gen_tile_idx    ];
  ulong volatile * solcap_metrics  = fd_metrics_tile( solcap_tile->metrics );
  ulong volatile * gen_metrics     = fd_metrics_tile( gen_tile->metrics    );

  double ns_per_tick = 1.0/fd_tempo_tick_per_ns( NULL );
  long  now        = fd_log_wallclock();
  long  then       = now+(long)1e9;
  ulong sz_last    = 0UL;
  ulong backp_last = FD_VOLATILE_CONST( gen_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] );
  for(;;) {
    if( now>then ) {
      ulong sz    = FD_VOLATILE_CONST( solcap_metrics[ MIDX( COUNTER, SOLCAP, FILE_SIZE_BYTES ) ] );
      ulong backp = FD_VOLATILE_CONST( gen_metrics   [ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] );
      FD_LOG_NOTICE(( "Rate: %g bytes/s (backp=%3.0f%%)",
                      (double)( sz-sz_last ),
                      (double)( backp-backp_last )*ns_per_tick/1e7 ));
      sz_last = sz;
      backp_last = backp;
      then = now+(long)1e9;
    }
    now = fd_log_wallclock();
  }
}

static void
bench_solcap_cmd_perm( args_t *         args,
                       fd_cap_chk_t *   chk    FD_PARAM_UNUSED,
                       config_t const * config FD_PARAM_UNUSED ) {
  args->configure.command = CONFIGURE_CMD_INIT;
  ulong stage_idx = 0UL;
  args->configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args->configure.stages[ stage_idx++ ] = NULL;
  configure_cmd_perm( args, chk, config );
  run_cmd_perm( NULL, chk, config );
}

action_t fd_action_bench_solcap = {
  .name        = "bench-solcap",
  .args        = bench_solcap_cmd_args,
  .fn          = bench_solcap_cmd_fn,
  .perm        = bench_solcap_cmd_perm,
  .description = "Benchmark solcap logger"
};
