#define _GNU_SOURCE
#include "fddev.h"

#include "../shared/commands/configure/configure.h"
#include "../shared/fd_file_util.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

extern configure_stage_t fd_cfg_stage_kill;
extern configure_stage_t fd_cfg_stage_netns;
extern configure_stage_t fd_cfg_stage_genesis;
extern configure_stage_t fd_cfg_stage_blockstore;
extern configure_stage_t fd_cfg_stage_keys;

configure_stage_t * STAGES[ CONFIGURE_STAGE_COUNT ] = {
  &fd_cfg_stage_kill,
  &fd_cfg_stage_netns,
  &fd_cfg_stage_hugetlbfs,
  &fd_cfg_stage_sysctl,
  &fd_cfg_stage_hyperthreads,
  &fd_cfg_stage_ethtool_channels,
  &fd_cfg_stage_ethtool_gro,
  &fd_cfg_stage_ethtool_loopback,
  &fd_cfg_stage_keys,
  &fd_cfg_stage_genesis,
#ifdef FD_HAS_NO_AGAVE
  NULL,
#else
  &fd_cfg_stage_blockstore,
#endif
  NULL,
};

extern fd_topo_run_tile_t fd_tile_net;
extern fd_topo_run_tile_t fd_tile_netlnk;
extern fd_topo_run_tile_t fd_tile_sock;
extern fd_topo_run_tile_t fd_tile_quic;
extern fd_topo_run_tile_t fd_tile_bundle;
extern fd_topo_run_tile_t fd_tile_verify;
extern fd_topo_run_tile_t fd_tile_dedup;
extern fd_topo_run_tile_t fd_tile_pack;
extern fd_topo_run_tile_t fd_tile_shred;
extern fd_topo_run_tile_t fd_tile_sign;
extern fd_topo_run_tile_t fd_tile_metric;
extern fd_topo_run_tile_t fd_tile_cswtch;
extern fd_topo_run_tile_t fd_tile_gui;
extern fd_topo_run_tile_t fd_tile_plugin;
extern fd_topo_run_tile_t fd_tile_bencho;
extern fd_topo_run_tile_t fd_tile_benchg;
extern fd_topo_run_tile_t fd_tile_benchs;
extern fd_topo_run_tile_t fd_tile_pktgen;

#ifdef FD_HAS_NO_AGAVE
extern fd_topo_run_tile_t fd_tile_gossip;
extern fd_topo_run_tile_t fd_tile_repair;
extern fd_topo_run_tile_t fd_tile_store_int;
extern fd_topo_run_tile_t fd_tile_replay;
extern fd_topo_run_tile_t fd_tile_execor;
extern fd_topo_run_tile_t fd_tile_replay_thread;
extern fd_topo_run_tile_t fd_tile_batch;
extern fd_topo_run_tile_t fd_tile_batch_thread;
extern fd_topo_run_tile_t fd_tile_poh_int;
extern fd_topo_run_tile_t fd_tile_sender;
extern fd_topo_run_tile_t fd_tile_eqvoc;
extern fd_topo_run_tile_t fd_tile_rpcserv;
extern fd_topo_run_tile_t fd_tile_restart;
extern fd_topo_run_tile_t fd_tile_blackhole;
#else
extern fd_topo_run_tile_t fd_tile_resolv;
extern fd_topo_run_tile_t fd_tile_poh;
extern fd_topo_run_tile_t fd_tile_bank;
extern fd_topo_run_tile_t fd_tile_store;
#endif

fd_topo_run_tile_t * TILES[] = {
  &fd_tile_net,
  &fd_tile_netlnk,
  &fd_tile_sock,
  &fd_tile_quic,
  &fd_tile_bundle,
  &fd_tile_verify,
  &fd_tile_dedup,
  &fd_tile_pack,
  &fd_tile_shred,
  &fd_tile_sign,
  &fd_tile_metric,
  &fd_tile_cswtch,
  &fd_tile_gui,
  &fd_tile_plugin,
  &fd_tile_bencho,
  &fd_tile_benchg,
  &fd_tile_benchs,
  &fd_tile_pktgen,
#ifdef FD_HAS_NO_AGAVE
  &fd_tile_gossip,
  &fd_tile_repair,
  &fd_tile_store_int,
  &fd_tile_replay,
  &fd_tile_replay_thread,
  &fd_tile_execor,
  &fd_tile_batch,
  &fd_tile_batch_thread,
  &fd_tile_poh_int,
  &fd_tile_sender,
  &fd_tile_eqvoc,
  &fd_tile_rpcserv,
  &fd_tile_restart,
  &fd_tile_blackhole,
#else
  &fd_tile_resolv,
  &fd_tile_poh,
  &fd_tile_bank,
  &fd_tile_store,
#endif
  NULL,
};

action_t DEV_ACTIONS[] = {
  { .name = "bench",      .args = bench_cmd_args,      .fn = bench_cmd_fn,      .perm = dev_cmd_perm,   .description = "Test validator TPS benchmark" },
  { .name = "dev",        .args = dev_cmd_args,        .fn = dev_cmd_fn,        .perm = dev_cmd_perm,   .description = "Start up a test validator" },
  { .name = "dev1",       .args = dev1_cmd_args,       .fn = dev1_cmd_fn,       .perm = dev_cmd_perm,   .description = "Start up a single tile" },
  { .name = "dump",       .args = dump_cmd_args,       .fn = dump_cmd_fn,       .perm = NULL,           .description = "Dump tango links to pcap", .is_diagnostic=1 },
  { .name = "flame",      .args = flame_cmd_args,      .fn = flame_cmd_fn,      .perm = flame_cmd_perm, .description = "Capture a perf flamegraph", .is_diagnostic=1 },
  { .name = "help",       .args = NULL,                .fn = dev_help_cmd_fn,   .perm = NULL,           .description = "Print this help message", .is_diagnostic=1 },
  { .name = "load",       .args = load_cmd_args,       .fn = load_cmd_fn,       .perm = load_cmd_perm,  .description = "Load test an external validator" },
  { .name = "pktgen",     .args = pktgen_cmd_args,     .fn = pktgen_cmd_fn,     .perm = dev_cmd_perm,   .description = "Flood interface with invalid Ethernet frames" },
  { .name = "quic-trace", .args = quic_trace_cmd_args, .fn = quic_trace_cmd_fn, .perm = NULL,           .description = "Trace quic tile", .is_diagnostic=1 },
  { .name = "txn",        .args = txn_cmd_args,        .fn = txn_cmd_fn,        .perm = txn_cmd_perm,   .description = "Send a transaction to an fddev instance" },
  { .name = "wksp",       .args = NULL,                .fn = wksp_cmd_fn,       .perm = wksp_cmd_perm,  .description = "Initialize workspaces" },
# if FD_HAS_NO_AGAVE
  { .name = "gossip",     .args = gossip_cmd_args,     .fn = gossip_cmd_fn,     .perm = gossip_cmd_perm,.description = "Run a standalone gossip node" },
# endif
  {0}
};

extern char fd_log_private_path[ 1024 ];

#define MAX_ARGC 32

/* Rerun the currently executing process as root. This will never return,
   instead it replaces the currently executing process with a new one. */
static void
execve_as_root( int     argc,
                char ** argv ) {
  char _current_executable_path[ PATH_MAX ];
  FD_TEST( -1!=fd_file_util_self_exe( _current_executable_path ) );

  char * args[ MAX_ARGC+4 ];
  for( int i=1; i<argc; i++ ) args[i+2] = argv[i];
  args[ 0 ]      = "sudo";
  args[ 1 ]      = "-E";
  args[ 2 ]      = _current_executable_path;
  /* always override the log path to use the same one we just opened for ourselves */
  args[ argc+2 ] = "--log-path";
  args[ argc+3 ] = fd_log_private_path;
  args[ argc+4 ] = NULL;

  /* ok to leak these dynamic strings because we are about to execve anyway */
  char * envp[ 3 ] = {0};
  char * env;
  int    idx = 0;
  if( FD_LIKELY(( env = getenv( "FIREDANCER_CONFIG_TOML" ) )) ) {
    if( FD_UNLIKELY( asprintf( &envp[ idx++ ], "FIREDANCER_CONFIG_TOML=%s", env ) == -1 ) )
      FD_LOG_ERR(( "asprintf() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY(( env = getenv( "TERM" ) )) ) {
    if( FD_UNLIKELY( asprintf( &envp[ idx++ ], "TERM=%s", env ) == -1 ) )
      FD_LOG_ERR(( "asprintf() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  execve( "/usr/bin/sudo", args, envp );
  FD_LOG_ERR(( "execve(sudo) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static config_t config;

int
fddev_main( int     argc,
            char ** _argv ) {
  /* save original arguments list in case we need to respawn the process
     as privileged */
  int    orig_argc = argc;
  char * orig_argv[ MAX_ARGC+1 ] = {0};
  for( int i=0; i<fd_int_min( MAX_ARGC, argc ); i++ ) orig_argv[ i ] = _argv[ i ];

  if( FD_UNLIKELY( argc >= MAX_ARGC ) ) FD_LOG_ERR(( "too many arguments (%i)", argc ));
  char ** argv = _argv;

  argc--; argv++;

  fd_env_strip_cmdline_cstr( &argc, &argv, "--log-level-stderr", NULL, NULL );
  char const * log_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--log-path", NULL, NULL );

  fdctl_boot( &argc, &argv, &config, log_path );

  int no_sandbox = fd_env_strip_cmdline_contains( &argc, &argv, "--no-sandbox" );
  int no_clone = fd_env_strip_cmdline_contains( &argc, &argv, "--no-clone" );
  config.development.no_clone = config.development.no_clone || no_clone;
  config.development.sandbox = config.development.sandbox && !no_sandbox && !no_clone;

  const char * action_name = "dev";
  if( FD_UNLIKELY( argc > 0 && argv[ 0 ][ 0 ] != '-' ) ) {
    action_name = argv[ 0 ];
    argc--; argv++;
  }

  action_t * action = NULL;
  for( ulong i=0; ACTIONS[ i ].name; i++ ) {
    if( FD_UNLIKELY( !strcmp( action_name, ACTIONS[ i ].name ) ) ) {
      action = &ACTIONS[ i ];
      break;
    }
  }
  for( ulong i=0; DEV_ACTIONS[ i ].name; i++ ) {
    if( FD_UNLIKELY( !strcmp( action_name, DEV_ACTIONS[ i ].name ) ) ) {
      action = &DEV_ACTIONS[ i ];
      break;
    }
  }

  if( FD_UNLIKELY( !action ) ) FD_LOG_ERR(( "unknown subcommand `%s`", action_name ));

  int is_allowed_live = action->is_diagnostic==1;
  if( FD_UNLIKELY( config.is_live_cluster && !is_allowed_live ) )
    FD_LOG_ERR(( "The `fddev` command is for development and test environments but your "
                 "configuration targets a live cluster. Use `fdctl` if this is a "
                 "production environment" ));

  args_t args = {0};
  if( FD_LIKELY( action->args ) ) action->args( &argc, &argv, &args );
  if( FD_UNLIKELY( argc ) ) FD_LOG_ERR(( "unknown argument `%s`", argv[ 0 ] ));

  /* Check if we are appropriately permissioned to run the desired
     command. */
  if( FD_LIKELY( action->perm ) ) {
    fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
    action->perm( &args, chk, &config );
    ulong err_cnt = fd_cap_chk_err_cnt( chk );
    if( FD_UNLIKELY( err_cnt ) ) {
      if( FD_UNLIKELY( !geteuid() ) ) {
        for( ulong i=0UL; i<err_cnt; i++ ) FD_LOG_WARNING(( "%s", fd_cap_chk_err( chk, i ) ));
        FD_LOG_ERR(( "insufficient permissions to execute command `%s` when running as root. "
                     "fddev is likely being run with a reduced capability bounding set.", action_name ));
      }
      execve_as_root( orig_argc, orig_argv );
    }
  }

  /* run the command */
  action->fn( &args, &config );
  return 0;
}
