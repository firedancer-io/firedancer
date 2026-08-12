#include "../../shared/fd_config.h"
#include "../../shared/fd_bootinfo.h"
#include "../../shared/fd_action.h"
#include "adminctl_client.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/metrics/generated/fd_metrics_replay.h"
#include "../../../disco/metrics/generated/fd_metrics_diag.h"
#include "../../../disco/diag/fd_diag_tile.h"

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

/* Number of lines rendered per frame (3 checks + status). */

#define LINES_PER_FRAME 4UL

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
  render_check_line( "epoch",      epoch_result,     epoch_desc   );

  if( FD_UNLIKELY( all_pass ) ) {
    PRINT( "  " ANSI_GREEN ANSI_BOLD "safe to exit" ANSI_RESET ANSI_CLEARLN "\n" );
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

/* wait_for_safe_window polls the running validator until all exit
   safety checks pass.  Returns normally on success.  Calls exit(1) if
   interrupted by a signal. */

static void
wait_for_safe_window( config_t * config,
                      ulong      min_idle_slots,
                      int        skip_health ) {

  /* Install signal handlers for clean shutdown. */

  struct sigaction sa = { .sa_handler = signal_handler };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)",  errno, fd_io_strerror( errno ) ));

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

  /* Locate the diag tile (for the health check). */

  fd_topo_tile_t * diag_tile = NULL;
  if( FD_LIKELY( !skip_health ) ) {
    ulong diag_idx = fd_topo_find_tile( &config->topo, "diag", 0UL );
    if( FD_UNLIKELY( diag_idx==ULONG_MAX ) ) {
      FD_LOG_WARNING(( "no diag tile found — health check will be skipped" ));
      skip_health = 1;
    } else {
      diag_tile = &config->topo.tiles[ diag_idx ];
    }
  }

  /* Poll every 5 seconds. */

  long const poll_interval_ns = 5L * 1000L * 1000L * 1000L;
  long start_time  = fd_log_wallclock();
  int  first_frame = 1;

  while( FD_LIKELY( g_running ) ) {

    /* 0. Fail-fast: if the maximum idle window for the remaining epoch
       is known and smaller than min_idle_slots, there is no possible
       exit window and we can exit immediately. */

    ulong max_idle_window = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_MAX_IDLE_WINDOW_SLOTS_OFF ];
    if( FD_UNLIKELY( max_idle_window>0UL && max_idle_window<min_idle_slots ) ) {
      FD_LOG_ERR(( "Validator has no idle window of at least %lu slots. "
                   "Largest idle window is %lu slots",
                   min_idle_slots, max_idle_window ));
    }

    /* 1. Health check: diag replay status must be RUNNING (caught up). */

    int  health_result;
    char health_desc[ 128 ];

    if( FD_UNLIKELY( skip_health ) ) {
      health_result = CHECK_SKIP;
      fd_cstr_printf_check( health_desc, sizeof(health_desc), NULL, "skipped" );
    } else {
      ulong replay_status = fd_metrics_tile( diag_tile->metrics )[ FD_METRICS_GAUGE_DIAG_REPLAY_STATUS_OFF ];
      if( FD_LIKELY( replay_status==FD_DIAG_REPLAY_STATUS_RUNNING ) ) {
        health_result = CHECK_PASS;
        fd_cstr_printf_check( health_desc, sizeof(health_desc), NULL, "caught up" );
      } else if( FD_UNLIKELY( replay_status==FD_DIAG_REPLAY_STATUS_BEHIND ) ) {
        health_result = CHECK_FAIL;
        fd_cstr_printf_check( health_desc, sizeof(health_desc), NULL, "behind" );
      } else {
        health_result = CHECK_FAIL;
        fd_cstr_printf_check( health_desc, sizeof(health_desc), NULL, "not ready (status=%lu)", replay_status );
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

    /* Check if all conditions are met (pass or skip). */

    int all_pass = ( health_result!=CHECK_FAIL ) &&
                   ( leader_result!=CHECK_FAIL ) &&
                   ( epoch_result!=CHECK_FAIL );

    long elapsed_s = (fd_log_wallclock() - start_time) / (1000L * 1000L * 1000L);

    /* Render the TUI panel. */

    render_status( health_result, health_desc,
                   leader_result, leader_desc,
                   epoch_result, epoch_desc,
                   all_pass, elapsed_s, first_frame );
    first_frame = 0;

    if( FD_UNLIKELY( all_pass ) ) {
      FD_LOG_NOTICE(( "safe to exit (reset_slot=%lu, next_leader=%lu)", reset_slot, next_leader_slot ));
      /* Metric workspace stays joined — caller leaves after drain. */
      return;
    }

    fd_log_wait_until( fd_log_wallclock() + poll_interval_ns );
  }

  /* Interrupted by signal — restore cursor and exit. */

  restore_cursor();
  FD_LOG_WARNING(( "interrupted before finding a safe exit window" ));
  fd_topo_leave_workspaces( &config->topo );
  exit( 1 );
}

static void
exit_cmd_fn( args_t *   args,
             config_t * config ) {
  int force       = args->exit.force;
  int skip_health = args->exit.skip_health_check;
  int query_only  = args->exit.query_only;

  if( FD_UNLIKELY( force && query_only ) ) {
    FD_LOG_ERR(( "--force and --query-only are mutually exclusive" ));
  }

  if( FD_LIKELY( !force ) ) {
    ulong min_idle_time = args->exit.min_idle_time;

    ulong const slots_per_min = 150UL;
    ulong min_idle_slots = min_idle_time * slots_per_min;

    FD_LOG_NOTICE(( "waiting for a safe exit window  "
                    "(min-idle-time=%lu min, min-idle-slots=%lu, skip-health=%s)",
                    min_idle_time, min_idle_slots,
                    skip_health ? "yes" : "no" ));

    wait_for_safe_window( config, min_idle_slots, skip_health );
  } else {
    FD_LOG_NOTICE(( "--force specified, skipping safe exit window check" ));

    /* Still need to adopt the config for bootinfo access below. */
    fd_bootinfo_adopt( config );
  }

  if( FD_UNLIKELY( query_only ) ) {
    FD_LOG_NOTICE(( "--query-only specified, not sending SIGTERM" ));
    fd_topo_leave_workspaces( &config->topo );
    return;
  }

  /* Drain phase: tell the replay tile to stop accepting new work and
     drain in-flight state.  Skip if --force was given. */

  if( FD_LIKELY( !force ) ) {
    fd_adminctl_t * adminctl = adminctl_client_attach( config, NULL );

    void * payload;
    ulong  payload_max;
    ulong  slot = fd_adminctl_reserve( adminctl, &payload, &payload_max );
    if( FD_UNLIKELY( slot==ULONG_MAX ) ) FD_LOG_ERR(( "adminctl reserve failed" ));
    fd_adminctl_publish( adminctl, slot, FD_ADMINCTL_CMD_DRAIN, 0UL );
    ulong result = fd_adminctl_wait( adminctl, slot );
    if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) )
      FD_LOG_WARNING(( "drain command returned %lu, proceeding with SIGTERM", result ));

    /* Poll drain metric until drained or timeout. */

    ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
    if( FD_UNLIKELY( replay_idx==ULONG_MAX ) ) FD_LOG_ERR(( "no replay tile found in topology" ));
    fd_topo_tile_t * replay_tile = &config->topo.tiles[ replay_idx ];

    long drain_start      = fd_log_wallclock();
    long drain_timeout_ns = 30L * 1000L * 1000L * 1000L;

    FD_LOG_NOTICE(( "draining replay tile..." ));

    for(;;) {
      ulong drain_status = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_DRAIN_STATUS_OFF ];
      if( FD_LIKELY( drain_status==2UL ) ) {
        FD_LOG_NOTICE(( "replay tile drained successfully" ));
        break;
      }
      long now = fd_log_wallclock();
      if( FD_UNLIKELY( now - drain_start > drain_timeout_ns ) ) {
        FD_LOG_WARNING(( "drain timed out after 30s, proceeding with SIGTERM" ));
        break;
      }
      fd_log_wait_until( now + 500L*1000L*1000L );
    }
  }

  if( FD_LIKELY( !force ) ) fd_topo_leave_workspaces( &config->topo );

  /* Discover the validator PID via bootinfo and send SIGTERM. */

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s.bootinfo",
                                 config->hugetlbfs.mount_path, config->name ) );

  fd_bootinfo_t info;
  if( FD_UNLIKELY( -1==fd_bootinfo_path_read( path, &info ) ) )
    FD_LOG_ERR(( "failed to read bootinfo at %s", path ));

  if( FD_UNLIKELY( !fd_bootinfo_live( &info ) ) )
    FD_LOG_ERR(( "validator is no longer running (pid %lu)", info.pid ));

  if( FD_UNLIKELY( kill( (pid_t)info.pid, SIGTERM ) ) )
    FD_LOG_ERR(( "kill(%lu, SIGTERM) failed (%i-%s)", info.pid, errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "sent SIGTERM to validator pid %lu", info.pid ));

  /* Wait for the validator to terminate. */

  long const poll_ns = 500L * 1000L * 1000L; /* 500 ms */

  while( FD_LIKELY( fd_bootinfo_live( &info ) ) ) {
    fd_log_wait_until( fd_log_wallclock() + poll_ns );

    /* Re-read bootinfo in case pid_start_time changed (pid reuse). */
    if( FD_UNLIKELY( -1==fd_bootinfo_path_read( path, &info ) ) ) break;
  }

  FD_LOG_NOTICE(( "validator (pid %lu) has terminated", info.pid ));
}

static void
exit_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args ) {
  args->exit.min_idle_time     = fd_env_strip_cmdline_ulong( pargc, pargv, "--min-idle-time", NULL, 10UL );
  args->exit.skip_health_check = fd_env_strip_cmdline_contains( pargc, pargv, "--skip-health-check" );
  args->exit.query_only        = fd_env_strip_cmdline_contains( pargc, pargv, "--query-only" );
  args->exit.force             = fd_env_strip_cmdline_contains( pargc, pargv, "--force" )
                               | fd_env_strip_cmdline_contains( pargc, pargv, "-f" );
}

static void
exit_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--min-idle-time",      "<minutes>", "Minimum idle time (in minutes) required before the next leader\n"
                                                                "slot.  Converted to slots at 150 slots/min.  Default: 10" );
  fd_action_help_arg( help, "--skip-health-check",  NULL,       "Skip the health check (replay caught-up status)" );
  fd_action_help_arg( help, "--query-only",         NULL,       "Wait for the safe window but do not send SIGTERM.\n"
                                                                "The validator keeps running.  Useful for scripting" );
  fd_action_help_arg( help, "--force / -f",         NULL,       "Skip the safe exit window check and send SIGTERM immediately" );
}

action_t fd_action_exit = {
  .name           = "exit",
  .args           = exit_cmd_args,
  .fn             = exit_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .description    = "Gracefully stop the validator after waiting for a safe exit window",
  .detail         = "Attaches to a running validator and polls every 5 seconds until\n"
                    "all of the following are true:\n"
                    "\n"
                    "  - The validator is caught up (diag replay status)\n"
                    "  - There is enough idle time before the next leader slot\n"
                    "\n"
                    "Once safe, sends SIGTERM to the validator supervisor and polls\n"
                    "until the process terminates (exit 0).\n"
                    "\n"
                    "Use --skip-health-check to bypass the caught-up check.\n"
                    "Use --query-only to wait for the safe window without sending\n"
                    "SIGTERM (useful for scripting).\n"
                    "Use --force to skip all checks and send SIGTERM immediately.",
  .usage          = "exit [OPTIONS]",
  .args_help      = exit_args_help,
};
