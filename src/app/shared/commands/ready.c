#include "run/run.h"

#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/metrics/generated/fd_metrics_replay.h"

void
ready_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  args->ready.ready_slot = fd_env_strip_cmdline_ulong( pargc, pargv, "--ready-slot", NULL, 0UL );
}

void
ready_cmd_fn( args_t *   args,
              config_t * config ) {
  ulong wksp_id = fd_topo_find_wksp( &config->topo, "metric_in" );
  FD_TEST( wksp_id!=ULONG_MAX );

  fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ wksp_id ], FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_workspace_fill( &config->topo, &config->topo.workspaces[ wksp_id ] );

  for( ulong i=0; i<config->topo.tile_cnt; i++) {
    fd_topo_tile_t * tile = &config->topo.tiles[i];

    /* Don't wait for agave hosted tiles yet, they will take a
       long time, and aren't needed to start sending transactions
       anyway. */
    if( FD_UNLIKELY( tile->is_agave ) ) continue;

    long start = fd_log_wallclock();
    int printed = 0;
    do {
      ulong status = fd_metrics_tile( tile->metrics )[ FD_METRICS_GAUGE_TILE_STATUS_OFF ];

      if( FD_LIKELY( status==1UL ) ) break;
      else if( FD_UNLIKELY( tile->allow_shutdown && status==2UL ) ) break;
      else if( FD_UNLIKELY( status ) )
        FD_LOG_ERR(( "status for tile %s:%lu is in bad state %lu", tile->name, tile->kind_id, status ));

      if( FD_UNLIKELY( !printed && (fd_log_wallclock()-start) > 2L*1000*1000*1000L ) ) {
        FD_LOG_NOTICE(( "waiting for tile %s:%lu to be ready", tile->name, tile->kind_id ));
        printed = 1;
      }
    } while(1);
  }

  /* Optionally wait for the replay tile to reach a certain slot */
  if( FD_UNLIKELY( args->ready.ready_slot ) ) {
    ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
    if( FD_UNLIKELY( replay_idx==ULONG_MAX ) ) {
      FD_LOG_ERR(( "--ready-slot specified but no replay tile found" ));
    }
    fd_topo_tile_t * replay_tile = &config->topo.tiles[ replay_idx ];

    long start = fd_log_wallclock();
    int printed = 0;
    do {
      ulong reset_slot = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_RESET_SLOT_OFF ];

      if( FD_LIKELY( reset_slot>=args->ready.ready_slot ) ) break;

      if( FD_UNLIKELY( !printed && (fd_log_wallclock()-start) > 4e9L ) ) {
        FD_LOG_NOTICE(( "waiting for reset slot to reach %lu (currently %lu)", args->ready.ready_slot, reset_slot ));
        printed = 1;
      }
    } while(1);
  }

  fd_topo_leave_workspaces( &config->topo );
  FD_LOG_NOTICE(( "all tiles ready" ));
}

action_t fd_action_ready = {
  .name           = "ready",
  .args           = ready_cmd_args,
  .fn             = ready_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Wait for all tiles to be running",
};
