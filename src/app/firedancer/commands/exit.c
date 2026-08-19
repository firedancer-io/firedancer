#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_bootinfo.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/metrics/generated/fd_metrics_replay.h"
#include "../../../disco/metrics/generated/fd_metrics_diag.h"
#include "../../../disco/metrics/generated/fd_metrics_snapmk.h"
#include "../../../disco/diag/fd_diag_tile.h"
#include "generated/exit_seccomp.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/capability.h>

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

/* When the replay tile finishes a leader slot, next_leader_slot is
   briefly ULONG_MAX (published as 0 in metrics) until the tower tile
   responds.  Require a re-confirmation pass to avoid a false positive
   in this window. */

#define MIN_CONSECUTIVE_PASSES 2UL

/* Frame buffer for atomic terminal writes (following watch.c pattern). */

static char  frame_buf[ 8192 ];
static ulong frame_len;

#define PRINT(...) do {                                                      \
    ulong _print_len;                                                        \
    FD_TEST( fd_cstr_printf_check( frame_buf+frame_len,                      \
                                   sizeof(frame_buf)-frame_len, &_print_len, \
                                   __VA_ARGS__ ) );                          \
    frame_len += _print_len;                                                 \
  } while(0)

static void
flush_frame( void ) {
  ulong written = 0UL;
  while( written<frame_len ) {
    long w = write( STDOUT_FILENO, frame_buf+written, frame_len-written );
    if( FD_UNLIKELY( -1L==w && (errno==EAGAIN || errno==EINTR) ) ) continue;
    else if( FD_UNLIKELY( -1L==w ) ) break;
    else if( FD_UNLIKELY( 0L==w  ) ) break;
    written += (ulong)w;
  }
  frame_len = 0UL;
}

/* Number of lines rendered per frame (4 checks + status). */

#define LINES_PER_FRAME 5UL

/* Aggregated check results passed to render_status. */

struct exit_check {
  int  result;
  char desc[ 256 ];
};

typedef struct exit_check exit_check_t;

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
render_status( exit_check_t const * health,
               exit_check_t const * leader,
               exit_check_t const * metrics,
               exit_check_t const * snap,
               int                  all_pass,
               long                 elapsed_s,
               int                  first_frame ) {
  frame_len = 0UL;

  /* Hide cursor and reposition if not the first frame. */

  PRINT( "\033[?25l" );
  if( FD_UNLIKELY( !first_frame ) ) {
    PRINT( "\033[%luA\r", LINES_PER_FRAME );
  }

  render_check_line( "health",     health->result,  health->desc );
  render_check_line( "leader gap", leader->result,  leader->desc );
  render_check_line( "metrics",    metrics->result, metrics->desc );
  render_check_line( "snapshot",   snap->result,    snap->desc );

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

static volatile sig_atomic_t g_running = 1;

static void
signal_handler( int sig FD_PARAM_UNUSED ) {
  /* Restore cursor visibility (write is async-signal-safe). */
  (void)!write( STDOUT_FILENO, "\033[?25h", 6 );
  g_running = 0;
}

/* wait_for_safe_window polls the running validator until all exit
   safety checks pass.  Returns normally on success.  Calls exit(1) if
   interrupted by a signal.

   The caller must have already: joined the metric_in workspace,
   called fd_topo_workspace_fill, and installed signal handlers.
   pidfd is a file descriptor obtained from pidfd_open() before
   entering the sandbox — it refers to the exact process incarnation
   and is immune to PID reuse.  target_pid is retained for log
   messages only. */

static void
wait_for_safe_window( config_t * config,
                      ulong      min_idle_slots,
                      int        skip_health,
                      pid_t      target_pid,
                      int        pidfd ) {

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

  /* Locate the snapmk tile (for snapshot-in-progress check). */

  fd_topo_tile_t * snapmk_tile = NULL;
  ulong snapmk_idx = fd_topo_find_tile( &config->topo, "snapmk", 0UL );
  if( FD_UNLIKELY( snapmk_idx!=ULONG_MAX ) ) {
    snapmk_tile = &config->topo.tiles[ snapmk_idx ];
  }

  /* Poll every second. */

  long const poll_interval_ns    = 1000L * 1000L * 1000L;  /* 1 s    */
  long const confirm_interval_ns =  200L * 1000L * 1000L;  /* 200 ms */
  long  start_time  = fd_log_wallclock();
  int   first_frame = 1;
  ulong pass_cnt    = 0UL;

  while( FD_LIKELY( g_running ) ) {

    /* 0. Verify the validator is still alive (pidfd becomes readable
       when the process exits). */

    struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
    struct timespec zero_ts = { .tv_sec = 0, .tv_nsec = 0 };
    int pret = (int)ppoll( &pfd, 1, &zero_ts, NULL );
    if( FD_UNLIKELY( pret>0 ) ) {
      restore_cursor();
      FD_LOG_ERR(( "validator (pid %d) exited while waiting for safe exit window", target_pid ));
    }

    /* 1. Health check: diag replay status must be RUNNING (caught up). */

    exit_check_t health;

    if( FD_UNLIKELY( skip_health ) ) {
      health.result = CHECK_SKIP;
      fd_cstr_printf_check( health.desc, sizeof(health.desc), NULL, "skipped" );
    } else {
      ulong replay_status = fd_metrics_tile( diag_tile->metrics )[ FD_METRICS_GAUGE_DIAG_REPLAY_STATUS_OFF ];
      if( FD_LIKELY( replay_status==FD_DIAG_REPLAY_STATUS_RUNNING ) ) {
        health.result = CHECK_PASS;
        fd_cstr_printf_check( health.desc, sizeof(health.desc), NULL, "caught up" );
      } else if( FD_UNLIKELY( replay_status==FD_DIAG_REPLAY_STATUS_BEHIND ) ) {
        health.result = CHECK_FAIL;
        fd_cstr_printf_check( health.desc, sizeof(health.desc), NULL, "behind" );
      } else {
        health.result = CHECK_FAIL;
        fd_cstr_printf_check( health.desc, sizeof(health.desc), NULL, "not ready (status=%lu)", replay_status );
      }
    }

    /* 2. Leader-slot idle gap check.  The "metrics" gate ensures the
       replay tile has written at least one update before we trust the
       leader-slot values (both default to zero). */

    exit_check_t leader  = { .result = CHECK_SKIP };
    exit_check_t metrics = { .result = CHECK_PASS };

    ulong reset_slot       = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_RESET_SLOT_OFF ];
    ulong next_leader_slot = fd_metrics_tile( replay_tile->metrics )[ FD_METRICS_GAUGE_REPLAY_NEXT_LEADER_SLOT_OFF ];
    ulong idle_gap         = 0UL;

    if( FD_UNLIKELY( reset_slot==0UL ) ) {
      /* reset_slot==0 means the replay tile hasn't published a valid
         reset slot yet (gauge default).  Block until the replay tile
         is initialized to avoid trusting a stale next_leader_slot
         that was written first (no atomicity between the two). */
      metrics.result = CHECK_FAIL;
      fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "not ready" );
      leader.result  = CHECK_SKIP;
      fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "waiting for metrics" );
    } else if( FD_UNLIKELY( next_leader_slot==0UL ) ) {
      /* reset_slot>0 but next_leader_slot==0 means the replay tile
         mapped ULONG_MAX to 0 — no upcoming leader slots (e.g. no
         stake or past all leader slots in the epoch). */
      metrics.result = CHECK_PASS;
      fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "ok" );
      idle_gap = ULONG_MAX;
    } else {
      metrics.result = CHECK_PASS;
      fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "ok" );
      if( FD_UNLIKELY( next_leader_slot<=reset_slot ) ) {
        idle_gap = 0UL;
      } else {
        idle_gap = next_leader_slot - reset_slot;
      }
    }

    if( FD_LIKELY( metrics.result!=CHECK_FAIL ) ) {
      if( FD_LIKELY( idle_gap>=min_idle_slots ) ) {
        leader.result = CHECK_PASS;
        if( FD_UNLIKELY( idle_gap==ULONG_MAX ) ) {
          fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "idle (no upcoming leader slots)" );
        } else {
          fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "idle %lu slots (need %lu)", idle_gap, min_idle_slots );
        }
      } else {
        leader.result = CHECK_FAIL;
        fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "next leader in %lu slots (need %lu)", idle_gap, min_idle_slots );
      }
    }

    /* 3. Snapshot check: no snapshot currently being written. */

    exit_check_t snap;

    if( FD_UNLIKELY( !snapmk_tile ) ) {
      snap.result = CHECK_SKIP;
      fd_cstr_printf_check( snap.desc, sizeof(snap.desc), NULL, "skipped" );
    } else {
      ulong started_full  = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_STARTED_FULL_OFF ];
      ulong finished_full = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_FULL_OFF ];
      ulong started_incr  = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_STARTED_INCREMENTAL_OFF ];
      ulong finished_incr = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_INCREMENTAL_OFF ];

      /* These are slot numbers that increase monotonically. */

      if( FD_LIKELY( started_full<=finished_full && started_incr<=finished_incr ) ) {
        snap.result = CHECK_PASS;
        fd_cstr_printf_check( snap.desc, sizeof(snap.desc), NULL, "idle" );
      } else {
        snap.result = CHECK_FAIL;
        fd_cstr_printf_check( snap.desc, sizeof(snap.desc), NULL, "snapshot in progress" );
      }
    }

    /* Check if all conditions are met (pass or skip). */

    int all_pass = ( health.result!=CHECK_FAIL ) &&
                   ( leader.result!=CHECK_FAIL ) &&
                   ( metrics.result!=CHECK_FAIL ) &&
                   ( snap.result!=CHECK_FAIL );

    if( FD_UNLIKELY( all_pass ) ) pass_cnt++;
    else                          pass_cnt = 0UL;

    int confirmed = pass_cnt>=MIN_CONSECUTIVE_PASSES;

    long elapsed_s = (fd_log_wallclock() - start_time) / (1000L * 1000L * 1000L);

    /* Render the TUI panel. */

    render_status( &health, &leader, &metrics, &snap,
                   confirmed, elapsed_s, first_frame );
    first_frame = 0;

    if( FD_UNLIKELY( confirmed ) ) {
      FD_LOG_NOTICE(( "safe to exit (reset_slot=%lu, next_leader=%lu)", reset_slot, next_leader_slot ));
      return;
    }

    fd_log_wait_until( fd_log_wallclock() + (pass_cnt ? confirm_interval_ns : poll_interval_ns) );
  }

  /* Interrupted by signal — restore cursor and exit. */

  restore_cursor();
  FD_LOG_WARNING(( "interrupted before finding a safe exit window" ));
  exit( 1 );
}

static void
exit_cmd_perm( args_t *         args FD_PARAM_UNUSED,
               fd_cap_chk_t *   chk,
               config_t const * config ) {
  ulong mlock_limit = fd_topo_mlock( &config->topo );

  fd_cap_chk_raise_rlimit( chk, "exit", RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );

  if( fd_sandbox_requires_cap_sys_admin( config->uid, config->gid ) )
    fd_cap_chk_cap( chk, "exit", CAP_SYS_ADMIN, "call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_cap_chk_cap( chk, "exit", CAP_SETUID,    "call `setresuid(2)` to switch uid to the sandbox user" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_cap_chk_cap( chk, "exit", CAP_SETGID,    "call `setresgid(2)` to switch gid to the sandbox user" );
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

  /* Attach to the running validator's config (once). */

  fd_bootinfo_adopt_named( config, args->exit.name );

  /* Read the validator PID before sandboxing (requires filesystem). */

  char bootinfo_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( bootinfo_path, sizeof(bootinfo_path), NULL, "%s/%s.bootinfo",
                                 config->hugetlbfs.mount_path, config->name ) );

  fd_bootinfo_t info;
  if( FD_UNLIKELY( -1==fd_bootinfo_path_read( bootinfo_path, &info ) ) )
    FD_LOG_ERR(( "failed to read bootinfo at %s", bootinfo_path ));

  if( FD_UNLIKELY( !fd_bootinfo_live( &info ) ) )
    FD_LOG_ERR(( "validator is no longer running (pid %lu)", info.pid ));

  pid_t target_pid = (pid_t)info.pid;
  if( FD_UNLIKELY( target_pid<=0 || (ulong)target_pid!=info.pid ) )
    FD_LOG_ERR(( "invalid validator pid %lu", info.pid ));

  /* Open a pidfd for the target process before entering the sandbox.
     The pidfd refers to this exact process incarnation and is immune
     to PID reuse — all liveness probes and signal delivery inside
     the sandbox use this fd instead of kill(). */

  int pidfd = (int)syscall( SYS_pidfd_open, target_pid, 0U );
  if( FD_UNLIKELY( pidfd<0 ) )
    FD_LOG_ERR(( "pidfd_open(%d) failed (%i-%s); kernel 5.3+ required",
                 target_pid, errno, fd_io_strerror( errno ) ));

  /* Verify topology layout and join the metrics workspace before
     sandboxing (requires filesystem access and mlock). */

  fd_bootinfo_check_layout( config );

  ulong wksp_id = fd_topo_find_wksp( &config->topo, "metric_in" );
  FD_TEST( wksp_id!=ULONG_MAX );

  fd_topo_wksp_t * metric_wksp = &config->topo.workspaces[ wksp_id ];
  fd_topo_join_workspace( &config->topo, metric_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Install signal handlers before entering the sandbox. */

  struct sigaction sa = { .sa_handler = signal_handler };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)",  errno, fd_io_strerror( errno ) ));

  /* Enter the seccomp sandbox. */

  int allow_fds[ 5 ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 0; /* stdin */
  allow_fds[ allow_fds_cnt++ ] = 1; /* stdout */
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd();
  allow_fds[ allow_fds_cnt++ ] = pidfd;

  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_exit( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd(), (uint)pidfd );

  if( FD_LIKELY( config->development.sandbox ) ) {
    fd_sandbox_enter( config->uid,
                      config->gid,
                      0,
                      0,
                      0,
                      1, /* Keep controlling terminal for Ctrl+C */
                      0,
                      0UL,
                      0UL,
                      0UL,
                      0UL,
                      allow_fds_cnt,
                      allow_fds,
                      sock_filter_policy_exit_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  /* Resolve pointers in mmap'd workspace memory (safe inside sandbox). */

  fd_topo_workspace_fill( &config->topo, metric_wksp );

  if( FD_LIKELY( !force ) ) {
    ulong min_idle_slots = args->exit.min_idle_slots;

    FD_LOG_NOTICE(( "waiting for a safe exit window  "
                    "(min-idle-slots=%lu, skip-health=%s)",
                    min_idle_slots,
                    skip_health ? "yes" : "no" ));

    wait_for_safe_window( config, min_idle_slots, skip_health, target_pid, pidfd );
  } else {
    FD_LOG_NOTICE(( "--force specified, skipping safe exit window check" ));
  }

  if( FD_UNLIKELY( query_only ) ) {
    FD_LOG_NOTICE(( "--query-only specified, not sending SIGTERM" ));
    return;
  }

  /* Restore default signal disposition so that Ctrl+C during the
     SIGTERM wait phase terminates the exit command immediately.  With
     SIG_DFL the kernel handles SIGINT; no flag polling latency. */

  struct sigaction sa_dfl = { .sa_handler = SIG_DFL };
  sigaction( SIGINT,  &sa_dfl, NULL );
  sigaction( SIGTERM, &sa_dfl, NULL );

  /* Send SIGTERM to the validator via pidfd (immune to PID reuse). */

  if( FD_UNLIKELY( syscall( SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 0U ) ) ) {
    if( FD_LIKELY( errno==ESRCH ) ) {
      FD_LOG_NOTICE(( "validator (pid %d) already exited", target_pid ));
      return;
    }
    if( FD_LIKELY( errno==EPERM ) )
      FD_LOG_ERR(( "permission denied signaling validator pid %d — run as the validator's user or root", target_pid ));
    FD_LOG_ERR(( "pidfd_send_signal(%d, SIGTERM) failed (%i-%s)", target_pid, errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "sent SIGTERM to validator pid %d", target_pid ));

  /* Wait for the validator to terminate by polling the pidfd.  The
     pidfd becomes readable (POLLIN) when the process exits, so ppoll
     wakes immediately on termination rather than sleeping the full
     interval.  No SIGKILL escalation on purpose — the operator should
     decide whether to force-kill.  Ctrl+C terminates the exit command
     (SIG_DFL restored above). */

  long const warn_s  = 15L;
  long const warn_ns = warn_s * 1000L * 1000L * 1000L;
  long       sigterm_time = fd_log_wallclock();
  int        warned       = 0;

  struct timespec poll_ts = { .tv_sec = 0, .tv_nsec = 500L * 1000L * 1000L };  /* 500 ms */

  for(;;) {
    struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
    int pret = (int)ppoll( &pfd, 1, &poll_ts, NULL );
    if( FD_UNLIKELY( pret>0 ) ) break;  /* pidfd readable → process exited */

    long now     = fd_log_wallclock();
    long elapsed = now - sigterm_time;

    if( FD_UNLIKELY( !warned && elapsed>=warn_ns ) ) {
      FD_LOG_WARNING(( "validator pid %d still running after %lds of SIGTERM", target_pid, warn_s ));
      warned = 1;
    }
  }

  FD_LOG_NOTICE(( "validator (pid %d) has terminated", target_pid ));
}

static void
exit_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args ) {
  args->exit.min_idle_slots    = fd_env_strip_cmdline_ulong( pargc, pargv, "--min-idle-slots", NULL, 1500UL );
  args->exit.skip_health_check = fd_env_strip_cmdline_contains( pargc, pargv, "--skip-health-check" );
  args->exit.query_only        = fd_env_strip_cmdline_contains( pargc, pargv, "--query-only" );
  args->exit.force             = fd_env_strip_cmdline_contains( pargc, pargv, "--force" )
                               | fd_env_strip_cmdline_contains( pargc, pargv, "-f" );
  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) {
    if( FD_UNLIKELY( !name[ 0 ] ) )
      FD_LOG_ERR(( "--name must not be empty" ));
    if( FD_UNLIKELY( strlen( name )>=sizeof(args->exit.name) ) )
      FD_LOG_ERR(( "--name too long (max %lu characters)", sizeof(args->exit.name)-1UL ));
    fd_cstr_ncpy( args->exit.name, name, sizeof(args->exit.name) );
  }
}

static void
exit_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--min-idle-slots",     "<slots>",   "Minimum number of idle slots required before the next leader\n"
                                                                "slot.  Default: 1500" );
  fd_action_help_arg( help, "--skip-health-check",  NULL,       "Skip the health check (replay caught-up status)" );
  fd_action_help_arg( help, "--query-only",         NULL,       "Wait for the safe window but do not send SIGTERM.\n"
                                                                "The validator keeps running.  Useful for scripting" );
  fd_action_help_arg( help, "--force / -f",         NULL,       "Skip the safe exit window check and send SIGTERM immediately" );
  fd_action_help_arg( help, "--name",               "<name>",   "Select a specific validator by name when multiple are running" );
}

action_t fd_action_exit = {
  .name           = "exit",
  .args           = exit_cmd_args,
  .fn             = exit_cmd_fn,
  .require_config = 0, /* fd_bootinfo_adopt_named replaces config with the running validator's published config */
  .perm           = exit_cmd_perm,
  .description    = "Stop the validator at a safe time.",
  .detail         = "Attaches to a running validator and polls every second until\n"
                    "all of the following are true:\n"
                    "\n"
                    "  - The validator is caught up (diag replay status)\n"
                    "  - There are enough idle slots before the next leader slot\n"
                    "  - No snapshot is currently being written\n"
                    "\n"
                    "Once safe, sends SIGTERM to the validator supervisor and polls\n"
                    "until the process terminates (exit 0).\n"
                    "\n"
                    "Use --skip-health-check to bypass the caught-up check.\n"
                    "Use --query-only to wait for the safe window without sending\n"
                    "  SIGTERM (useful for scripting).\n"
                    "Use --force to skip all checks and send SIGTERM immediately.",
  .usage          = "exit [OPTIONS]",
  .args_help      = exit_args_help,
};
