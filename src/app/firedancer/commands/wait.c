#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_bootinfo.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/metrics/generated/fd_metrics_replay.h"
#include "../../../disco/metrics/generated/fd_metrics_diag.h"
#include "../../../disco/metrics/generated/fd_metrics_snapmk.h"
#include "../../../disco/diag/fd_diag_tile.h"
#include "../../../flamenco/rewards/fd_rewards_base.h"
#include "generated/wait_seccomp.h"

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
   in this window (the tower responds well within 200ms). */

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

/* Number of lines rendered per frame.  Must equal the number of
   render_check_line calls in render_status (currently 5: health,
   leader gap, metrics, snapshot, delinquent) plus 1 status line. */

#define WAIT_CHECK_CNT  5UL
#define LINES_PER_FRAME (WAIT_CHECK_CNT + 1UL)

/* Aggregated check results passed to render_status. */

struct wait_check {
  int  result;
  char desc[ 256 ];
};

typedef struct wait_check wait_check_t;

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
render_status( wait_check_t const * health,
               wait_check_t const * leader,
               wait_check_t const * metrics,
               wait_check_t const * snap,
               wait_check_t const * delinquent,
               int                  all_pass,
               long                 elapsed_s,
               int                  first_frame ) {
  frame_len = 0UL;

  /* Hide cursor and reposition if not the first frame. */

  PRINT( "\033[?25l" );
  if( FD_UNLIKELY( !first_frame ) ) {
    PRINT( "\033[%luA\r", LINES_PER_FRAME );
  }

  render_check_line( "health",     health->result,     health->desc     );
  render_check_line( "leader gap", leader->result,     leader->desc     );
  render_check_line( "metrics",    metrics->result,    metrics->desc    );
  render_check_line( "snapshot",   snap->result,       snap->desc       );
  render_check_line( "delinquent", delinquent->result, delinquent->desc );

  if( FD_UNLIKELY( all_pass ) ) {
    PRINT( "  " ANSI_GREEN ANSI_BOLD "safe to stop" ANSI_RESET ANSI_CLEARLN "\n" );
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

/* wait_for_safe_window polls the running validator until all safety
   checks pass.  Returns normally on success.  Calls exit(1) if
   interrupted by a signal.

   The caller must have already: joined the metric_in workspace,
   called fd_topo_workspace_fill, and installed signal handlers.
   pidfd is a file descriptor obtained from pidfd_open() before
   entering the sandbox; it refers to the exact process incarnation
   and is immune to PID reuse.  target_pid is retained for log
   messages only. */

static void
wait_for_safe_window( config_t * config,
                      ulong      min_idle_slots,
                      ulong      min_idle_time_ns,
                      ulong      max_delinquent_stake_pct,
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
      FD_LOG_WARNING(( "no diag tile found; health check will be skipped" ));
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
      FD_LOG_ERR(( "validator (pid %d) exited while waiting for safe window", target_pid ));
    }

    /* 1. Health check: diag replay status must be RUNNING (caught up). */

    wait_check_t health;

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

    /* 2. Leader-slot idle gap check.  Use a seqlock to guarantee a
       consistent snapshot of the replay tile gauges.  The replay tile
       increments MetricsSeqno to odd before writing and to even after.
       On x86-64 TSO, volatile loads are ordered so no explicit fences
       are needed on the consumer side. */

    wait_check_t leader  = { .result = CHECK_SKIP };
    wait_check_t metrics = { .result = CHECK_PASS };

    volatile ulong * replay_metrics = fd_metrics_tile( replay_tile->metrics );

    ulong seqno_before     = replay_metrics[ FD_METRICS_GAUGE_REPLAY_METRICS_SEQNO_OFF ];
    ulong reset_slot       = replay_metrics[ FD_METRICS_GAUGE_REPLAY_RESET_SLOT_OFF ];
    ulong next_leader_slot = replay_metrics[ FD_METRICS_GAUGE_REPLAY_NEXT_LEADER_SLOT_OFF ];
    ulong leader_slot_val  = replay_metrics[ FD_METRICS_GAUGE_REPLAY_LEADER_SLOT_OFF ];
    ulong epoch_end_slot   = replay_metrics[ FD_METRICS_GAUGE_REPLAY_EPOCH_END_SLOT_OFF ];
    ulong ns_per_slot_val  = replay_metrics[ FD_METRICS_GAUGE_REPLAY_NS_PER_SLOT_OFF ];
    ulong seqno_after      = replay_metrics[ FD_METRICS_GAUGE_REPLAY_METRICS_SEQNO_OFF ];

    ulong idle_gap = 0UL;

    if( FD_UNLIKELY( (seqno_before & 1UL) || seqno_before!=seqno_after ) ) {
      /* metrics_write is in progress; the gauge values may be torn.
         Skip this iteration; the next poll will almost certainly see
         a consistent snapshot. */
      metrics.result = CHECK_FAIL;
      fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "metrics in flux" );
      leader.result  = CHECK_SKIP;
      fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "waiting for metrics" );
      goto skip_leader_check;
    }

    /* When --min-idle-time-secs is used, convert the time threshold to
       slots using the live ns_per_slot metric from the replay tile. */

    ulong effective_min_idle_slots = min_idle_slots;
    if( FD_UNLIKELY( min_idle_time_ns ) ) {
      if( FD_UNLIKELY( !ns_per_slot_val ) ) {
        metrics.result = CHECK_FAIL;
        fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "not ready (ns_per_slot unknown)" );
        leader.result  = CHECK_SKIP;
        fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "waiting for metrics" );
        goto skip_leader_check;
      }
      effective_min_idle_slots = (min_idle_time_ns + ns_per_slot_val - 1UL) / ns_per_slot_val;
    }

    if( FD_UNLIKELY( reset_slot==0UL || epoch_end_slot==0UL ) ) {
      /* reset_slot==0 or epoch_end_slot==0 means the replay tile
         hasn't published valid metrics yet (gauge defaults).  Block
         until the replay tile is initialized to avoid trusting stale
         leader-slot values. */
      metrics.result = CHECK_FAIL;
      fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "not ready" );
      leader.result  = CHECK_SKIP;
      fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "waiting for metrics" );
    } else if( FD_UNLIKELY( epoch_end_slot<reset_slot ) ) {
      /* epoch_end_slot is behind reset_slot; the validator crossed an
         epoch boundary but epoch_end_slot hasn't been refreshed yet.
         The leader schedule for the new epoch may not be loaded, so
         the leader gap check cannot be trusted. */
      metrics.result = CHECK_FAIL;
      fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "epoch boundary crossed, waiting for update" );
      leader.result  = CHECK_SKIP;
      fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "waiting for metrics" );
    } else if( FD_UNLIKELY( leader_slot_val ) ) {
      /* The validator is currently leading a slot. */
      metrics.result = CHECK_PASS;
      fd_cstr_printf_check( metrics.desc, sizeof(metrics.desc), NULL, "ok" );
      leader.result  = CHECK_FAIL;
      fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "leading slot %lu", leader_slot_val );
    } else if( FD_UNLIKELY( next_leader_slot==0UL ) ) {
      /* reset_slot>0 but next_leader_slot==0 means the replay tile
         mapped ULONG_MAX to 0; no upcoming leader slots (e.g. no
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

    if( FD_LIKELY( metrics.result!=CHECK_FAIL && leader.result!=CHECK_FAIL ) ) {
      /* Epoch boundary guard: if we are too close to the end of the
         epoch, the next epoch's leader schedule may not be loaded yet,
         which could cause a false positive on the leader gap check.
         Mirrors the Agave guard:
         https://github.com/anza-xyz/agave/blob/v4.2.1/validator/src/commands/wait_for_restart_window/mod.rs#L290-L293 */

      ulong epoch_boundary_slots = epoch_end_slot - reset_slot;

      if( FD_UNLIKELY( epoch_boundary_slots<effective_min_idle_slots ) ) {
        leader.result = CHECK_FAIL;
        fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "epoch boundary in %lu slots (need %lu)", epoch_boundary_slots, effective_min_idle_slots );
      } else if( FD_LIKELY( idle_gap>=effective_min_idle_slots ) ) {
        leader.result = CHECK_PASS;
        if( FD_UNLIKELY( idle_gap==ULONG_MAX ) ) {
          fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "idle (no upcoming leader slots)" );
        } else {
          fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "idle %lu slots (need %lu)", idle_gap, effective_min_idle_slots );
        }
      } else {
        leader.result = CHECK_FAIL;
        fd_cstr_printf_check( leader.desc, sizeof(leader.desc), NULL, "next leader in %lu slots (need %lu)", idle_gap, effective_min_idle_slots );
      }
    }

skip_leader_check:;
    /* 3. Snapshot check: no snapshot currently being written. */

    wait_check_t snap;

    if( FD_UNLIKELY( !snapmk_tile ) ) {
      snap.result = CHECK_SKIP;
      fd_cstr_printf_check( snap.desc, sizeof(snap.desc), NULL, "skipped" );
    } else {
      ulong started_full  = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_STARTED_FULL_OFF ];
      ulong finished_full = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_FULL_OFF ];
      ulong started_incr  = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_STARTED_INCREMENTAL_OFF ];
      ulong finished_incr = fd_metrics_tile( snapmk_tile->metrics )[ FD_METRICS_GAUGE_SNAPMK_LAST_SNAPSHOT_SLOT_FINISHED_INCREMENTAL_OFF ];

      /* These are slot numbers that increase monotonically within a
         single validator lifetime.  The pidfd liveness check ensures
         we are tracking a single process incarnation, so no wrap. */

      if( FD_LIKELY( started_full<=finished_full && started_incr<=finished_incr ) ) {
        snap.result = CHECK_PASS;
        fd_cstr_printf_check( snap.desc, sizeof(snap.desc), NULL, "idle" );
      } else {
        snap.result = CHECK_FAIL;
        fd_cstr_printf_check( snap.desc, sizeof(snap.desc), NULL, "snapshot in progress" );
      }
    }

    /* 4. Delinquent stake check. */

    wait_check_t delinquent;

    if( FD_UNLIKELY( metrics.result==CHECK_FAIL ) ) {
      delinquent.result = CHECK_SKIP;
      fd_cstr_printf_check( delinquent.desc, sizeof(delinquent.desc), NULL, "waiting for metrics" );
    } else {
      ulong delinquent_lamports = replay_metrics[ FD_METRICS_GAUGE_REPLAY_DELINQUENT_STAKE_LAMPORTS_OFF ];
      ulong total_lamports      = replay_metrics[ FD_METRICS_GAUGE_REPLAY_CLUSTER_ACTIVE_STAKE_LAMPORTS_OFF ];

      /* Divide out lamports to keep delinquent*100 well within
         ulong.  Precision loss is negligible for this rough
         estimate. */

      ulong delinquent_stake = delinquent_lamports / LAMPORTS_PER_SOL;
      ulong total_stake      = total_lamports      / LAMPORTS_PER_SOL;

      if( FD_UNLIKELY( !total_stake ) ) {
        delinquent.result = CHECK_SKIP;
        fd_cstr_printf_check( delinquent.desc, sizeof(delinquent.desc), NULL, "waiting for stake data" );
      } else {
        ulong pct = delinquent_stake * 100UL / total_stake;
        if( FD_LIKELY( pct<=max_delinquent_stake_pct ) ) {
          delinquent.result = CHECK_PASS;
          fd_cstr_printf_check( delinquent.desc, sizeof(delinquent.desc), NULL, "%lu%% delinquent (max %lu%%)", pct, max_delinquent_stake_pct );
        } else {
          delinquent.result = CHECK_FAIL;
          fd_cstr_printf_check( delinquent.desc, sizeof(delinquent.desc), NULL, "%lu%% delinquent (max %lu%%)", pct, max_delinquent_stake_pct );
        }
      }
    }

    /* Check if all conditions are met (pass or skip). */

    int all_pass = ( health.result!=CHECK_FAIL ) &&
                   ( leader.result!=CHECK_FAIL ) &&
                   ( metrics.result!=CHECK_FAIL ) &&
                   ( snap.result!=CHECK_FAIL ) &&
                   ( delinquent.result!=CHECK_FAIL );

    if( FD_UNLIKELY( all_pass ) ) pass_cnt++;
    else                          pass_cnt = 0UL;

    int confirmed = pass_cnt>=MIN_CONSECUTIVE_PASSES;

    long elapsed_s = (fd_log_wallclock() - start_time) / (1000L * 1000L * 1000L);

    /* Render the TUI panel. */

    render_status( &health, &leader, &metrics, &snap, &delinquent,
                   confirmed, elapsed_s, first_frame );
    first_frame = 0;

    if( FD_UNLIKELY( confirmed ) ) {
      FD_LOG_NOTICE(( "safe to stop (reset_slot=%lu, next_leader=%lu)", reset_slot, next_leader_slot ));
      return;
    }

    fd_log_wait_until( fd_log_wallclock() + (pass_cnt ? confirm_interval_ns : poll_interval_ns) );
  }

  /* Interrupted by signal; restore cursor and exit. */

  restore_cursor();
  FD_LOG_WARNING(( "interrupted before finding a safe window" ));
  exit( 1 );
}

static void
wait_cmd_perm( args_t *         args FD_PARAM_UNUSED,
               fd_cap_chk_t *   chk,
               config_t const * config ) {
  ulong mlock_limit = fd_topo_mlock( &config->topo );

  fd_cap_chk_raise_rlimit( chk, "wait", RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );

  if( fd_sandbox_requires_cap_sys_admin( config->uid, config->gid ) )
    fd_cap_chk_cap( chk, "wait", CAP_SYS_ADMIN, "call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_cap_chk_cap( chk, "wait", CAP_SETUID,    "call `setresuid(2)` to switch uid to the sandbox user" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_cap_chk_cap( chk, "wait", CAP_SETGID,    "call `setresgid(2)` to switch gid to the sandbox user" );
}

static void
wait_cmd_fn( args_t *   args,
             config_t * config ) {
  int skip_health = args->wait.skip_health_check;

  /* Attach to the running validator's config (once). */

  fd_bootinfo_adopt_named( config, args->wait.name );

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
     to PID reuse; all liveness probes inside the sandbox use this
     fd instead of kill(). */

  int pidfd = (int)syscall( SYS_pidfd_open, target_pid, 0U );
  if( FD_UNLIKELY( pidfd<0 ) )
    FD_LOG_ERR(( "pidfd_open(%d) failed (%i-%s); kernel 5.3+ required",
                 target_pid, errno, fd_io_strerror( errno ) ));

  /* Re-verify the validator is still running with the same incarnation.
     Closes the TOCTOU window between the initial fd_bootinfo_live
     check and pidfd_open; if the validator exited and the PID was
     reused, fd_bootinfo_live detects the start-time mismatch. */

  if( FD_UNLIKELY( -1==fd_bootinfo_path_read( bootinfo_path, &info ) || !fd_bootinfo_live( &info ) ) )
    FD_LOG_ERR(( "validator (pid %d) exited during wait setup", target_pid ));

  /* Verify topology layout and join the metrics workspace before
     sandboxing (requires filesystem access and mlock). */

  fd_bootinfo_check_layout( config );

  ulong wksp_id = fd_topo_find_wksp( &config->topo, "metric_in" );
  FD_TEST( wksp_id!=ULONG_MAX );

  fd_topo_wksp_t * metric_wksp = &config->topo.workspaces[ wksp_id ];
  fd_topo_join_workspace( &config->topo, metric_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Install signal handlers before entering the sandbox.  SIGPIPE is
     ignored so that writing to a closed pipe (e.g. firedancer wait |
     head) doesn't kill the process without restoring the cursor. */

  struct sigaction sa = { .sa_handler = signal_handler };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)",  errno, fd_io_strerror( errno ) ));

  struct sigaction sa_ign = { .sa_handler = SIG_IGN };
  if( FD_UNLIKELY( sigaction( SIGPIPE, &sa_ign, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGPIPE) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

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
  populate_sock_filter_policy_wait( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd() );

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
                      sock_filter_policy_wait_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  /* Resolve pointers in mmap'd workspace memory (safe inside sandbox). */

  fd_topo_workspace_fill( &config->topo, metric_wksp );

  ulong min_idle_slots           = args->wait.min_idle_slots;
  ulong min_idle_time_ns         = args->wait.min_idle_time_ns;
  ulong max_delinquent_stake_pct = args->wait.max_delinquent_stake_pct;

  if( FD_UNLIKELY( min_idle_time_ns ) ) {
    ulong min_idle_time_s = min_idle_time_ns / 1000000000UL;
    FD_LOG_NOTICE(( "waiting for a safe window  "
                    "(min-idle-time-secs=%lus, max-delinquent-stake=%lu%%, skip-health=%s)",
                    min_idle_time_s,
                    max_delinquent_stake_pct,
                    skip_health ? "yes" : "no" ));
  } else {
    FD_LOG_NOTICE(( "waiting for a safe window  "
                    "(min-idle-slots=%lu, max-delinquent-stake=%lu%%, skip-health=%s)",
                    min_idle_slots,
                    max_delinquent_stake_pct,
                    skip_health ? "yes" : "no" ));
  }

  wait_for_safe_window( config, min_idle_slots, min_idle_time_ns, max_delinquent_stake_pct, skip_health, target_pid, pidfd );
}

static void
wait_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args ) {
  ulong min_idle_slots_raw = fd_env_strip_cmdline_ulong( pargc, pargv, "--min-idle-slots", NULL, ULONG_MAX );
  ulong min_idle_time_s    = fd_env_strip_cmdline_ulong( pargc, pargv, "--min-idle-time-secs",  NULL, ULONG_MAX );

  if( FD_UNLIKELY( min_idle_slots_raw!=ULONG_MAX && min_idle_time_s!=ULONG_MAX ) ) {
    FD_LOG_ERR(( "--min-idle-slots and --min-idle-time-secs are mutually exclusive" ));
  }

  if( FD_UNLIKELY( min_idle_time_s!=ULONG_MAX ) ) {
    /* Convert seconds to nanoseconds. */
    if( FD_UNLIKELY( min_idle_time_s > ULONG_MAX/1000000000UL ) )
      FD_LOG_ERR(( "--min-idle-time-secs value too large" ));
    if( FD_UNLIKELY( !min_idle_time_s ) )
      FD_LOG_NOTICE(( "--min-idle-time-secs 0 disables the leader slot gap and epoch boundary checks" ));
    args->wait.min_idle_time_ns = min_idle_time_s * 1000000000UL;
    args->wait.min_idle_slots   = 0UL; /* will be computed at runtime */
  } else {
    args->wait.min_idle_time_ns = 0UL;
    args->wait.min_idle_slots   = ( min_idle_slots_raw==ULONG_MAX ) ? 1500UL : min_idle_slots_raw;
    if( FD_UNLIKELY( !args->wait.min_idle_slots ) )
      FD_LOG_NOTICE(( "--min-idle-slots 0 disables the leader slot gap and epoch boundary checks" ));
  }

  ulong max_delinquent = fd_env_strip_cmdline_ulong( pargc, pargv, "--max-delinquent-stake", NULL, 5UL );
  if( FD_UNLIKELY( max_delinquent>100UL ) )
    FD_LOG_ERR(( "--max-delinquent-stake must be 0-100" ));
  args->wait.max_delinquent_stake_pct = max_delinquent;

  args->wait.skip_health_check = fd_env_strip_cmdline_contains( pargc, pargv, "--skip-health-check" );
  args->wait.name[ 0 ] = '\0';
  char const * name = fd_env_strip_cmdline_cstr( pargc, pargv, "--name", NULL, NULL );
  if( FD_UNLIKELY( name ) ) {
    if( FD_UNLIKELY( !name[ 0 ] ) )
      FD_LOG_ERR(( "--name must not be empty" ));
    if( FD_UNLIKELY( strlen( name )>=sizeof(args->wait.name) ) )
      FD_LOG_ERR(( "--name too long (max %lu characters)", sizeof(args->wait.name)-1UL ));
    fd_cstr_ncpy( args->wait.name, name, sizeof(args->wait.name) );
  }
}

static void
wait_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--min-idle-slots",     "<slots>",     "Minimum number of idle slots required before the next leader\n"
                                                                   "slot.  Default: 1500" );
  fd_action_help_arg( help, "--min-idle-time-secs", "<seconds>",   "Minimum idle time in seconds before the next leader slot.\n"
                                                                   "Converted to slots using the live slot duration.\n"
                                                                   "Mutually exclusive with --min-idle-slots" );
  fd_action_help_arg( help, "--max-delinquent-stake", "<percent>", "Maximum percentage of delinquent stake allowed.\n"
                                                                   "Default: 5 (matching Agave)" );
  fd_action_help_arg( help, "--skip-health-check",  NULL,          "Skip the health check (replay caught-up status)" );
  fd_action_help_arg( help, "--name",               "<name>",      "Select a specific validator by name when multiple are running.\n"
                                                                   "Tip: set [name] to the identity pubkey in the TOML config" );
}

action_t fd_action_wait = {
  .name           = "wait",
  .args           = wait_cmd_args,
  .fn             = wait_cmd_fn,
  .require_config = 0, /* fd_bootinfo_adopt_named replaces config with the running validator's published config */
  .perm           = wait_cmd_perm,
  .description    = "Wait for a safe window to stop the validator.",
  .detail         = "Attaches to a running validator and polls every second until\n"
                    "all of the following are true:\n"
                    "\n"
                    "  - The validator is caught up (diag replay status)\n"
                    "  - There are enough idle slots before the next leader slot\n"
                    "  - No snapshot is currently being written\n"
                    "  - Cluster delinquent stake is below the threshold\n"
                    "    (sampled at optimistic confirmation cadence)\n"
                    "\n"
                    "Once safe, returns (exit 0).  The validator keeps running.\n"
                    "\n"
                    "Use --skip-health-check to bypass the caught-up check.",
  .usage          = "wait [OPTIONS]",
  .args_help      = wait_args_help,
};
