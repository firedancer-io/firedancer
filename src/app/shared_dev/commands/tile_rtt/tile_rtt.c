#include "../../../shared/commands/run/run.h" /* fdctl_check_configure */
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */
#include "fd_trtt_tile.h"

#include <stdio.h> /* fputs */
#include <stdlib.h> /* exit */
#include <unistd.h> /* pause */

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
tile_rtt_topo( config_t * config ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );

  fd_topob_wksp( topo, "tile_rtt" );
  fd_topob_tile( topo, "trtt", "tile_rtt", "tile_rtt", 0UL, 0, 0 );
  fd_topob_tile( topo, "echo", "tile_rtt", "tile_rtt", 1UL, 0, 0 );

  ulong const link_depth = 1024;
  fd_topob_link( topo, "trtt_echo", "tile_rtt", link_depth, 0UL, 0UL );
  fd_topob_link( topo, "echo_trtt", "tile_rtt", link_depth, 0UL, 0UL );
  fd_topob_tile_out( topo, "trtt", 0UL, "trtt_echo", 0UL );
  fd_topob_tile_out( topo, "echo", 0UL, "echo_trtt", 0UL );
  fd_topob_tile_in ( topo, "echo", 0UL, "tile_rtt", "trtt_echo", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "trtt", 0UL, "tile_rtt", "echo_trtt", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
tile_rtt_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  int help = fd_env_strip_cmdline_contains( pargc, pargv, "--help" );
  if( help ) {
    fputs( "Usage: tile-rtt [options]\n"
           "Options:\n"
           "  --help          Show this help message\n"
           "  --config <file> Path to the configuration file\n"
           "  --tile-cpus ... CPU affinity for [trtt, echo] tiles\n",
           stderr );
    fflush( stderr );
    exit( 0 );
  }
  char const * tile_cpus = fd_env_strip_cmdline_cstr( pargc, pargv, "--tile-cpus", "FD_TILE_CPUS", NULL );
  if( tile_cpus ) {
    ulong cpu_cnt = fd_tile_private_cpus_parse( tile_cpus, args->tile_rtt.tile_cpus, 2UL );
    if( FD_UNLIKELY( cpu_cnt!=2UL ) ) FD_LOG_ERR(( "--tile-cpus specifies %lu CPUs, but need exactly 2", cpu_cnt ));
  }
}

static void
tile_rtt_cmd_fn( args_t *   args,
                 config_t * config ) {
  fd_topo_t * topo = &config->topo;
  topo->tiles[ 0 ].cpu_idx = args->tile_rtt.tile_cpus[ 0 ];
  topo->tiles[ 1 ].cpu_idx = args->tile_rtt.tile_cpus[ 1 ];

  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  ulong            trtt_idx  = fd_topo_find_tile( topo, "trtt", 0UL );
  FD_TEST( trtt_idx!=ULONG_MAX );
  fd_topo_tile_t * trtt_tile = &topo->tiles[ trtt_idx ];
  fd_trtt_tile_t * trtt_ctx  = fd_topo_obj_laddr( topo, trtt_tile->tile_obj_id );
  fd_histf_t *     rtt_hist_ = trtt_ctx->rtt_hist;
  fd_histf_join( rtt_hist_ );
  FD_LOG_NOTICE(( "trtt_ctx is at %p", (void *)trtt_ctx ));

  fd_histf_t const * rtt_hist_ro_init = fd_type_pun( rtt_hist_ );
  fd_histf_t prev_hist[ 1 ];
  *prev_hist = *rtt_hist_ro_init;

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );
  double ns_per_tick = 1.0/fd_tempo_tick_per_ns( NULL );
  for(;;) {
    fd_log_sleep( (long)1e9 );
    /* FIXME is this data race safe? */
    fd_histf_t const * rtt_hist_ro = fd_type_pun( rtt_hist_ );

    fd_histf_t delta_hist[ 1 ];
    fd_histf_subtract( rtt_hist_ro, prev_hist, delta_hist );

    ulong p10 = fd_histf_percentile( delta_hist, 10, (ulong)1e9 );
    ulong p50 = fd_histf_percentile( delta_hist, 50, (ulong)1e9 );
    ulong p99 = fd_histf_percentile( delta_hist, 99, (ulong)1e9 );
    FD_LOG_NOTICE(( "tile_rtt/sec: p10=%5.1f p50=%5.1f p99=%5.1f",
                    (double)p10*ns_per_tick,
                    (double)p50*ns_per_tick,
                    (double)p99*ns_per_tick ));

    *prev_hist = *rtt_hist_ro;
  }
}

action_t fd_action_tile_rtt = {
  .name        = "tile-rtt",
  .description = "Measure tile-to-tile latency",
  .args        = tile_rtt_cmd_args,
  .fn          = tile_rtt_cmd_fn,
  .topo        = tile_rtt_topo
};
