#include "monitor_gossip.h"
#include "gossip_diag.h"
#include "generated/monitor_gossip_seccomp.h"

#include "../../../shared/commands/monitor/monitor.h" /* reconstruct_topo */
#include "../../../../util/clock/fd_clock.h"

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <linux/capability.h>

void
monitor_gossip_cmd_args( int *    pargc,
                         char *** pargv,
                         args_t * args ) {
  if( FD_UNLIKELY( fd_env_strip_cmdline_contains( pargc, pargv, "--help" ) ) ) {
    fputs(
      "\nUsage: firedancer monitor-gossip [GLOBAL FLAGS] [FLAGS]\n"
      "\n"
      "  Monitor gossip diagnostics on a running Firedancer\n"
      "  instance.  Attaches read-only to the validator's\n"
      "  shared memory and prints CRDS tables, message\n"
      "  statistics, and tile performance.\n"
      "\n"
      "Global Flags:\n"
      "  --mainnet            Use Solana mainnet-beta defaults\n"
      "  --testnet            Use Solana testnet defaults\n"
      "  --devnet             Use Solana devnet defaults\n"
      "\n"
      "Flags:\n"
      "  --topo <name>        Reconstruct topology from a named\n"
      "                       action (e.g. gossip). Default uses\n"
      "                       the production topology.\n"
      "  --compact            Use compact output format\n"
      "\n",
      stderr );
    exit( EXIT_SUCCESS );
  }

  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );
  ulong topo_name_len = strlen( topo_name );
  if( FD_UNLIKELY( topo_name_len > sizeof(args->monitor_gossip.topo)-1 ) ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->monitor_gossip.topo ), topo_name, topo_name_len ) );

  args->monitor_gossip.compact_mode = fd_env_strip_cmdline_contains( pargc, pargv, "--compact" );
}

static void
signal_handler( int sig ) {
  (void)sig;
  exit( 0 );
}

void
monitor_gossip_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                         fd_cap_chk_t *   chk,
                         config_t const * config ) {
  ulong mlock_limit = fd_topo_mlock( &config->topo );

  fd_cap_chk_raise_rlimit( chk, "monitor-gossip", RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );

  if( fd_sandbox_requires_cap_sys_admin( config->uid, config->gid ) )
    fd_cap_chk_cap( chk, "monitor-gossip", CAP_SYS_ADMIN, "call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_cap_chk_cap( chk, "monitor-gossip", CAP_SETUID,    "call `setresuid(2)` to switch uid to the sandbox user" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_cap_chk_cap( chk, "monitor-gossip", CAP_SETGID,    "call `setresgid(2)` to switch gid to the sandbox user" );
}

void
monitor_gossip_cmd_fn( args_t *   args,
                       config_t * config ) {
  reconstruct_topo( config, args->monitor_gossip.topo );

  struct sigaction sa = {
    .sa_handler = signal_handler,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int allow_fds[ 4 ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 0; /* stdin */
  allow_fds[ allow_fds_cnt++ ] = 1; /* stdout */
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd();

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_monitor_gossip( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd() );

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
                      sock_filter_policy_monitor_gossip_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  fd_topo_fill( &config->topo );

  fd_gossip_diag_ctx_t diag_ctx[1];
  if( FD_UNLIKELY( fd_gossip_diag_init( diag_ctx, &config->topo, config ) ) ) {
    FD_LOG_ERR(( "Failed to initialize gossip diagnostics. "
                 "Is a Firedancer instance running with gossip tiles?" ));
  }

  printf( "Found %lu gossvf tiles\n", diag_ctx->gossvf.tile_count );

  fd_clock_t   clock_lmem[1];
  void       * clock_mem = aligned_alloc( FD_CLOCK_ALIGN, FD_CLOCK_FOOTPRINT );
  FD_TEST( clock_mem );
  fd_clock_default_init( clock_lmem, clock_mem );

  long next_report_time = fd_clock_now( clock_lmem ) + 1000000000L;

  for(;;) {
    long current_time = fd_clock_now( clock_lmem );
    if( FD_LIKELY( current_time < next_report_time ) ) continue;
    next_report_time += 1000000000L;

    fd_gossip_diag_render( diag_ctx, args->monitor_gossip.compact_mode );
  }
}

action_t fd_action_monitor_gossip = {
  .name           = "monitor-gossip",
  .args           = monitor_gossip_cmd_args,
  .fn             = monitor_gossip_cmd_fn,
  .require_config = 1,
  .perm           = monitor_gossip_cmd_perm,
  .is_diagnostic  = 1,
  .description    = "Monitor gossip diagnostics on a running Firedancer instance",
};
