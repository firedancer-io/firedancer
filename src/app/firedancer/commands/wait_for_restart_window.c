#include "../../shared/fd_config.h"
#include "../../shared/fd_bootinfo.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/metrics/generated/fd_metrics_replay.h"
#include "../../../disco/metrics/generated/fd_metrics_snapmk.h"

#include <errno.h>
#include <signal.h>

static volatile int g_running = 1;

static void
signal_handler( int sig FD_PARAM_UNUSED ) {
  g_running = 0;
}

static void
wait_for_restart_window_cmd_args( int *    pargc,
                                  char *** pargv,
                                  args_t * args ) {
  args->wait_for_restart_window.min_idle_time        = fd_env_strip_cmdline_ulong( pargc, pargv, "--min-idle-time",          NULL, 10UL );
  args->wait_for_restart_window.max_delinquent_stake = fd_env_strip_cmdline_ulong( pargc, pargv, "--max-delinquent-stake",   NULL, 5UL  );
  args->wait_for_restart_window.skip_snapshot_check  = fd_env_strip_cmdline_contains( pargc, pargv, "--skip-new-snapshot-check" );
  args->wait_for_restart_window.skip_health_check    = fd_env_strip_cmdline_contains( pargc, pargv, "--skip-health-check"       );
  args->wait_for_restart_window.skip_delinquent_check = !fd_env_strip_cmdline_contains( pargc, pargv, "--delinquent-check"      );
}

static void
wait_for_restart_window_cmd_fn( args_t *   args,
                                config_t * config ) {

  /* Install signal handlers for clean shutdown. */

  struct sigaction sa = { .sa_handler = signal_handler };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)",  errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( !args->wait_for_restart_window.skip_delinquent_check ) ) {
    FD_LOG_ERR(( "--delinquent-check is not yet implemented.  "
                 "Omit --delinquent-check to skip delinquent stake checking (the default)." ));
  }

  ulong min_idle_time = args->wait_for_restart_window.min_idle_time;
  int   skip_snapshot  = args->wait_for_restart_window.skip_snapshot_check;
  int   skip_health    = args->wait_for_restart_window.skip_health_check;

  /* Convert min_idle_time (minutes) to slots.
     Solana targets ~400ms per slot, so 150 slots/min. */

  ulong const slots_per_min = 150UL;
  ulong min_idle_slots = min_idle_time * slots_per_min;

  FD_LOG_NOTICE(( "waiting for a safe restart window  "
                  "(min-idle-time=%lu min, min-idle-slots=%lu, skip-snapshot=%s, skip-health=%s)",
                  min_idle_time, min_idle_slots,
                  skip_snapshot ? "yes" : "no",
                  skip_health  ? "yes" : "no" ));

  /* Attach to the running validator's shared memory (read-only). */

  fd_bootinfo_adopt( config );
  ulong wksp_id = fd_topo_find_wksp( &config->topo, "metric_in" );
  FD_TEST( wksp_id!=ULONG_MAX );

  fd_bootinfo_check_layout( config );
  fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ wksp_id ], FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_workspace_fill( &config->topo, &config->topo.workspaces[ wksp_id ] );

  /* Locate the replay tile. */

  ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
  if( FD_UNLIKELY( replay_idx==ULONG_MAX ) ) FD_LOG_ERR(( "no replay tile found in topology" ));
  fd_topo_tile_t * replay_tile = &config->topo.tiles[ replay_idx ];

  /* Locate the snapmk tile (optional — may not exist if snapshots are
     disabled). */

  ulong snapmk_idx = fd_topo_find_tile( &config->topo, "snapmk", 0UL );
  fd_topo_tile_t * snapmk_tile = ( snapmk_idx!=ULONG_MAX ) ? &config->topo.tiles[ snapmk_idx ] : NULL;

  if( FD_UNLIKELY( !skip_snapshot && !snapmk_tile ) ) {
    FD_LOG_WARNING(( "no snapmk tile found — snapshot freshness check will be skipped" ));
    skip_snapshot = 1;
  }

  /* Snapshot baseline tracking.  When we enter an idle window we record
     the current finished snapshot slots.  A "fresh" snapshot means a new
     full snapshot completed after we entered the idle window. */

  int   in_idle_window            = 0;
  ulong idle_window_full_baseline = 0UL;

  /* Poll every 5 seconds. */

  long const poll_interval_ns = 5L * 1000L * 1000L * 1000L;

  while( FD_LIKELY( g_running ) ) {

    char ts_buf[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    fd_log_wallclock_cstr( fd_log_wallclock(), ts_buf );

    /* 1. Health check: replay tile status must be 1 (running). */

    if( FD_UNLIKELY( !skip_health ) ) {
      ulong status = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_TILE_STATUS_OFF ];
      if( FD_UNLIKELY( status!=1UL ) ) {
        FD_LOG_NOTICE(( "%s  replay tile not healthy (status=%lu), waiting...", ts_buf, status ));
        in_idle_window = 0;
        goto sleep;
      }
    }

    /* 2. Leader-slot idle gap check. */

    ulong reset_slot       = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_RESET_SLOT_OFF ];
    ulong next_leader_slot = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_NEXT_LEADER_SLOT_OFF ];

    ulong idle_gap;
    if( FD_UNLIKELY( next_leader_slot==0UL ) ) {
      ulong active_stake = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_ACTIVE_STAKE_LAMPORTS_OFF ];
      if( FD_LIKELY( active_stake==0UL ) ) {
        idle_gap = ULONG_MAX;  /* no stake -> genuinely no leader slots */
      } else {
        /* Have stake but no known upcoming leader slot.  Near epoch end
           and next epoch's schedule may not be computed yet. */
        FD_LOG_NOTICE(( "%s  no upcoming leader slots known (likely near epoch boundary), waiting...", ts_buf ));
        in_idle_window = 0;
        goto sleep;
      }
    } else if( FD_UNLIKELY( next_leader_slot<=reset_slot ) ) {
      /* Currently leading or just finished — no idle gap. */
      idle_gap = 0UL;
    } else {
      idle_gap = next_leader_slot - reset_slot;
    }

    if( FD_UNLIKELY( idle_gap<min_idle_slots ) ) {
      FD_LOG_NOTICE(( "%s  not enough idle time before next leader slot "
                      "(reset_slot=%lu, next_leader=%lu, idle_gap=%lu, need=%lu)",
                      ts_buf, reset_slot, next_leader_slot, idle_gap, min_idle_slots ));
      in_idle_window = 0;
      goto sleep;
    }

    /* We are in an idle window.  If we just entered, record snapshot
       baselines. */

    if( FD_UNLIKELY( !in_idle_window ) ) {
      in_idle_window = 1;
      if( !skip_snapshot && snapmk_tile ) {
        idle_window_full_baseline = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_FULL_OFF ];
      }
      FD_LOG_NOTICE(( "%s  entered idle window (reset_slot=%lu, next_leader=%lu, idle_gap=%lu)",
                      ts_buf, reset_slot, next_leader_slot, idle_gap ));
    }

    /* 3. Snapshot freshness check: a new full snapshot must have
       completed since we entered the idle window. */

    if( FD_LIKELY( !skip_snapshot && snapmk_tile ) ) {
      ulong full_finished = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_FULL_OFF ];

      if( FD_UNLIKELY( full_finished<=idle_window_full_baseline ) ) {
        FD_LOG_NOTICE(( "%s  waiting for a new full snapshot (last_full=%lu, baseline=%lu)",
                        ts_buf, full_finished, idle_window_full_baseline ));
        goto sleep;
      }

      /* Verify incremental snapshot is at least as recent as the full
         (i.e. based on the current full).  If incremental is 0 that
         just means none has been produced yet, which is fine. */

      ulong incr_finished = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_INCREMENTAL_OFF ];
      if( FD_UNLIKELY( incr_finished!=0UL && incr_finished<full_finished ) ) {
        FD_LOG_NOTICE(( "%s  incremental snapshot is stale (incr=%lu, full=%lu), waiting...",
                        ts_buf, incr_finished, full_finished ));
        goto sleep;
      }
    }

    /* All checks passed — safe to restart. */

    FD_LOG_NOTICE(( "%s  safe to restart (reset_slot=%lu, next_leader=%lu)",
                    ts_buf, reset_slot, next_leader_slot ));
    fd_topo_leave_workspaces( &config->topo );
    return;

sleep:
    fd_log_wait_until( fd_log_wallclock() + poll_interval_ns );
  }

  /* Interrupted by signal. */

  FD_LOG_WARNING(( "interrupted before finding a safe restart window" ));
  fd_topo_leave_workspaces( &config->topo );
  exit( 1 );
}

static void
wait_for_restart_window_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--min-idle-time",          "<minutes>", "Minimum idle time (in minutes) required before the next leader\n"
                                                                     "slot.  Converted to slots at 150 slots/min.  Default: 10" );
  fd_action_help_arg( help, "--max-delinquent-stake",   "<percent>", "Maximum percentage of delinquent stake allowed (stored for\n"
                                                                     "future use, not yet checked).  Default: 5" );
  fd_action_help_arg( help, "--skip-new-snapshot-check", NULL,       "Skip the snapshot freshness check" );
  fd_action_help_arg( help, "--skip-health-check",       NULL,       "Skip the replay tile health check" );
  fd_action_help_arg( help, "--delinquent-check",        NULL,       "Enable delinquent stake checking (not yet implemented;\n"
                                                                     "errors if used)" );
}

action_t fd_action_wait_for_restart_window = {
  .name           = "wait-for-restart-window",
  .args           = wait_for_restart_window_cmd_args,
  .fn             = wait_for_restart_window_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .description    = "Wait until it is safe to restart the validator",
  .detail         = "Attaches to a running validator and polls every 5 seconds until\n"
                    "all of the following are true:\n"
                    "\n"
                    "  - The replay tile is healthy\n"
                    "  - There is enough idle time before the next leader slot\n"
                    "  - A fresh full snapshot exists (produced during the idle window)\n"
                    "\n"
                    "When all conditions are met the command exits 0.  Interrupting\n"
                    "with SIGINT or SIGTERM exits non-zero.\n"
                    "\n"
                    "Delinquent stake checking is deferred to a future release and\n"
                    "must be explicitly opted in with --delinquent-check (which\n"
                    "currently errors).",
  .usage          = "wait-for-restart-window [OPTIONS]",
  .args_help      = wait_for_restart_window_args_help,
};
