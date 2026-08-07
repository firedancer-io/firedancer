#include "../../shared/fd_config.h"
#include "../../shared/fd_bootinfo.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/metrics/generated/fd_metrics_replay.h"
#include "../../../disco/metrics/generated/fd_metrics_snapmk.h"

#include <errno.h>
#include <signal.h>
#include <unistd.h>

/* ANSI escape codes for TUI rendering. */

#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_DIM     "\033[2m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_CLEARLN "\033[K"

/* Check result codes. */

#define CHECK_FAIL 0
#define CHECK_PASS 1
#define CHECK_SKIP 2

/* Frame buffer for atomic terminal writes (following watch.c pattern). */

static char  frame_buf[ 4096 ];
static ulong frame_len;

#define PRINT(...) do {                                                        \
    ulong _print_len;                                                          \
    FD_TEST( fd_cstr_printf_check( frame_buf+frame_len,                        \
                                   sizeof(frame_buf)-frame_len, &_print_len,   \
                                   __VA_ARGS__ ) );                            \
    frame_len += _print_len;                                                   \
  } while(0)

static void
flush_frame( void ) {
  ulong written = 0UL;
  while( written<frame_len ) {
    long w = write( STDOUT_FILENO, frame_buf+written, frame_len-written );
    if( FD_UNLIKELY( -1L==w && errno==EAGAIN ) ) continue;
    else if( FD_UNLIKELY( -1L==w ) ) break;
    else if( FD_UNLIKELY( 0L==w  ) ) break;
    written += (ulong)w;
  }
  frame_len = 0UL;
}

/* Number of lines rendered per frame (4 checks + blank + status). */

#define LINES_PER_FRAME 6UL

static void
render_check_line( char const * label,
                   int          result,
                   char const * desc ) {
  char const * icon;
  char const * desc_pre;
  char const * desc_post;

  switch( result ) {
  case CHECK_PASS:
    icon      = ANSI_GREEN "\xe2\x9c\x93" ANSI_RESET;  /* ✓ */
    desc_pre  = "";
    desc_post = "";
    break;
  case CHECK_FAIL:
    icon      = ANSI_RED "\xe2\x9c\x97" ANSI_RESET;    /* ✗ */
    desc_pre  = "";
    desc_post = "";
    break;
  default: /* CHECK_SKIP */
    icon      = ANSI_DIM "-" ANSI_RESET;
    desc_pre  = ANSI_DIM;
    desc_post = ANSI_RESET;
    break;
  }

  PRINT( "  %-13s%s %s%s%s" ANSI_CLEARLN "\n", label, icon, desc_pre, desc, desc_post );
}

static void
render_status( int          health_result,
               char const * health_desc,
               int          leader_result,
               char const * leader_desc,
               int          snapshot_result,
               char const * snapshot_desc,
               int          epoch_result,
               char const * epoch_desc,
               int          all_pass,
               long         elapsed_s,
               int          first_frame ) {
  frame_len = 0UL;

  /* Hide cursor and reposition if not the first frame. */

  PRINT( "\033[?25l" );
  if( FD_UNLIKELY( !first_frame ) ) {
    PRINT( "\033[%luA\r", LINES_PER_FRAME );
  }

  render_check_line( "health",     health_result,   health_desc   );
  render_check_line( "leader gap", leader_result,   leader_desc   );
  render_check_line( "snapshot",   snapshot_result,  snapshot_desc );
  render_check_line( "epoch",      epoch_result,     epoch_desc   );

  PRINT( ANSI_CLEARLN "\n" );

  if( FD_UNLIKELY( all_pass ) ) {
    PRINT( "  " ANSI_GREEN ANSI_BOLD "safe to restart" ANSI_RESET ANSI_CLEARLN "\n" );
  } else {
    PRINT( "  waiting... (%lds elapsed)" ANSI_CLEARLN "\n", elapsed_s );
  }

  /* Clear any leftover lines below and restore cursor. */

  PRINT( "\033[0J\033[?25h" );

  flush_frame();
}

static void
restore_cursor( void ) {
  frame_len = 0UL;
  PRINT( "\033[?25h" );
  flush_frame();
}

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
  long start_time  = fd_log_wallclock();
  int  first_frame = 1;

  while( FD_LIKELY( g_running ) ) {

    /* 1. Health check: replay tile status must be 1 (running). */

    int  health_result;
    char health_desc[ 128 ];

    if( FD_UNLIKELY( skip_health ) ) {
      health_result = CHECK_SKIP;
      fd_cstr_printf_check( health_desc, sizeof(health_desc), NULL, "skipped" );
    } else {
      ulong status = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_TILE_STATUS_OFF ];
      if( FD_LIKELY( status==1UL ) ) {
        health_result = CHECK_PASS;
        fd_cstr_printf_check( health_desc, sizeof(health_desc), NULL, "healthy" );
      } else {
        health_result = CHECK_FAIL;
        fd_cstr_printf_check( health_desc, sizeof(health_desc), NULL, "not healthy (status=%lu)", status );
      }
    }

    /* 2. Leader-slot idle gap and epoch boundary checks. */

    int  leader_result = CHECK_SKIP;
    int  epoch_result  = CHECK_PASS;
    char leader_desc[ 256 ];
    char epoch_desc[ 128 ];

    ulong reset_slot       = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_RESET_SLOT_OFF ];
    ulong next_leader_slot = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_NEXT_LEADER_SLOT_OFF ];
    ulong idle_gap         = 0UL;

    if( FD_UNLIKELY( next_leader_slot==0UL ) ) {
      ulong active_stake = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_ACTIVE_STAKE_LAMPORTS_OFF ];
      if( FD_LIKELY( active_stake==0UL ) ) {
        idle_gap = ULONG_MAX;
        epoch_result = CHECK_PASS;
        fd_cstr_printf_check( epoch_desc, sizeof(epoch_desc), NULL, "ok (no stake)" );
      } else {
        epoch_result = CHECK_FAIL;
        fd_cstr_printf_check( epoch_desc, sizeof(epoch_desc), NULL, "near epoch boundary, schedule unknown" );
        leader_result = CHECK_SKIP;
        fd_cstr_printf_check( leader_desc, sizeof(leader_desc), NULL, "waiting for epoch" );
      }
    } else {
      epoch_result = CHECK_PASS;
      fd_cstr_printf_check( epoch_desc, sizeof(epoch_desc), NULL, "ok" );
      if( FD_UNLIKELY( next_leader_slot<=reset_slot ) ) {
        idle_gap = 0UL;
      } else {
        idle_gap = next_leader_slot - reset_slot;
      }
    }

    if( FD_LIKELY( epoch_result!=CHECK_FAIL ) ) {
      if( FD_LIKELY( idle_gap>=min_idle_slots ) ) {
        leader_result = CHECK_PASS;
        if( FD_UNLIKELY( idle_gap==ULONG_MAX ) ) {
          fd_cstr_printf_check( leader_desc, sizeof(leader_desc), NULL, "idle (no upcoming leader slots)" );
        } else {
          fd_cstr_printf_check( leader_desc, sizeof(leader_desc), NULL, "idle %lu slots (need %lu)", idle_gap, min_idle_slots );
        }
      } else {
        leader_result = CHECK_FAIL;
        fd_cstr_printf_check( leader_desc, sizeof(leader_desc), NULL, "next leader in %lu slots (need %lu)", idle_gap, min_idle_slots );
      }
    }

    /* Update idle window state.  Reset if any pre-snapshot check
       failed; enter if all pass and we weren't already in one. */

    int idle_checks_pass = ( health_result!=CHECK_FAIL ) &&
                           ( leader_result!=CHECK_FAIL ) &&
                           ( epoch_result!=CHECK_FAIL );

    if( FD_UNLIKELY( !idle_checks_pass ) ) {
      in_idle_window = 0;
    } else if( FD_UNLIKELY( !in_idle_window ) ) {
      in_idle_window = 1;
      if( !skip_snapshot && snapmk_tile ) {
        idle_window_full_baseline = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_FULL_OFF ];
      }
    }

    /* 3. Snapshot freshness check: a new full snapshot must have
       completed since we entered the idle window. */

    int  snapshot_result;
    char snapshot_desc[ 256 ];

    if( FD_UNLIKELY( skip_snapshot ) ) {
      snapshot_result = CHECK_SKIP;
      fd_cstr_printf_check( snapshot_desc, sizeof(snapshot_desc), NULL, "skipped" );
    } else if( FD_UNLIKELY( !in_idle_window ) ) {
      snapshot_result = CHECK_SKIP;
      fd_cstr_printf_check( snapshot_desc, sizeof(snapshot_desc), NULL, "waiting for idle window" );
    } else {
      ulong full_finished = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_FULL_OFF ];

      if( FD_UNLIKELY( full_finished<=idle_window_full_baseline ) ) {
        snapshot_result = CHECK_FAIL;
        fd_cstr_printf_check( snapshot_desc, sizeof(snapshot_desc), NULL,
                              "waiting for new full snapshot (last=%lu, baseline=%lu)",
                              full_finished, idle_window_full_baseline );
      } else {
        /* Verify incremental snapshot is at least as recent as the full
           (i.e. based on the current full).  If incremental is 0 that
           just means none has been produced yet, which is fine. */

        ulong incr_finished = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_INCREMENTAL_OFF ];
        if( FD_UNLIKELY( incr_finished!=0UL && incr_finished<full_finished ) ) {
          snapshot_result = CHECK_FAIL;
          fd_cstr_printf_check( snapshot_desc, sizeof(snapshot_desc), NULL,
                                "incremental stale (incr=%lu, full=%lu)", incr_finished, full_finished );
        } else {
          snapshot_result = CHECK_PASS;
          fd_cstr_printf_check( snapshot_desc, sizeof(snapshot_desc), NULL, "ok (slot=%lu)", full_finished );
        }
      }
    }

    /* Check if all conditions are met (pass or skip). */

    int all_pass = ( health_result!=CHECK_FAIL ) &&
                   ( leader_result!=CHECK_FAIL ) &&
                   ( epoch_result!=CHECK_FAIL ) &&
                   ( snapshot_result!=CHECK_FAIL );

    long elapsed_s = (fd_log_wallclock() - start_time) / (1000L * 1000L * 1000L);

    /* Render the TUI panel. */

    render_status( health_result, health_desc,
                   leader_result, leader_desc,
                   snapshot_result, snapshot_desc,
                   epoch_result, epoch_desc,
                   all_pass, elapsed_s, first_frame );
    first_frame = 0;

    if( FD_UNLIKELY( all_pass ) ) {
      FD_LOG_NOTICE(( "safe to restart (reset_slot=%lu, next_leader=%lu)", reset_slot, next_leader_slot ));
      fd_topo_leave_workspaces( &config->topo );
      return;
    }

    fd_log_wait_until( fd_log_wallclock() + poll_interval_ns );
  }

  /* Interrupted by signal — restore cursor and exit. */

  restore_cursor();
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
