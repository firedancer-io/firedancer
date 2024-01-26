#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

extern configure_stage_t _kill;
extern configure_stage_t netns;
extern configure_stage_t genesis;
extern configure_stage_t keys;

configure_stage_t * STAGES[ CONFIGURE_STAGE_COUNT ] = {
  &_kill,
  &netns,
  &large_pages,
  &shmem,
  &sysctl,
  &xdp,
  &xdp_leftover,
  &ethtool,
  &keys,
  &workspace_leftover,
  &workspace,
  &genesis,
  NULL,
};

static action_t DEV_ACTIONS[] = {
  { .name = "dev",   .args = dev_cmd_args,   .fn = dev_cmd_fn,   .perm = dev_cmd_perm },
  { .name = "dev1",  .args = dev1_cmd_args,  .fn = dev1_cmd_fn,  .perm = dev_cmd_perm },
  { .name = "txn",   .args = txn_cmd_args,   .fn = txn_cmd_fn,   .perm = txn_cmd_perm },
  { .name = "bench", .args = bench_cmd_args, .fn = bench_cmd_fn, .perm = bench_cmd_perm },
};

#define MAX_ARGC 32

extern char fd_log_private_path[ 1024 ];

/* Rerun the currently executing process as root. This will never return,
   instead it replaces the currently executing process with a new one. */
static void
execve_as_root( int     argc,
                char ** argv ) {
  char _current_executable_path[ PATH_MAX ];
  current_executable_path( _current_executable_path );

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
main( int     argc,
      char ** _argv ) {
  /* save original arguments list in case we need to respawn the process
     as privileged */
  int    orig_argc = argc;
  char * orig_argv[ MAX_ARGC+1 ] = {0};
  for( int i=0; i<fd_int_min( MAX_ARGC, argc ); i++ ) orig_argv[ i ] = _argv[ i ];

  if( FD_UNLIKELY( argc >= MAX_ARGC ) ) FD_LOG_ERR(( "too many arguments (%i)", argc ));
  char ** argv = _argv;

  argc--; argv++;

  char const * log_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--log-path", NULL, NULL );

  fdctl_boot( &argc, &argv, &config, log_path );

  /* load configuration and command line parsing */
  if( FD_UNLIKELY( config.is_live_cluster ) )
    FD_LOG_ERR(( "The `fddev` command is for development and test environments but your "
                 "configuration targets a live cluster. Use `fdctl` if this is a "
                 "production environment" ));

  int no_sandbox = fd_env_strip_cmdline_contains( &argc, &argv, "--no-sandbox" );
  config.development.sandbox = config.development.sandbox && !no_sandbox;

  const char * action_name = "dev";
  if( FD_UNLIKELY( argc > 0 && argv[ 0 ][ 0 ] != '-' ) ) {
    action_name = argv[ 0 ];
    argc--; argv++;
  }

  action_t * action = NULL;
  for( ulong i=0; i<sizeof(ACTIONS)/sizeof(ACTIONS[ 0 ]); i++ ) {
    if( FD_UNLIKELY( !strcmp( action_name, ACTIONS[ i ].name ) ) ) {
      action = &ACTIONS[ i ];
      break;
    }
  }
  for( ulong i=0; i<sizeof(DEV_ACTIONS)/sizeof(DEV_ACTIONS[ 0 ]); i++ ) {
    if( FD_UNLIKELY( !strcmp( action_name, DEV_ACTIONS[ i ].name ) ) ) {
      action = &DEV_ACTIONS[ i ];
      break;
    }
  }

  if( FD_UNLIKELY( !action ) ) FD_LOG_ERR(( "unknown subcommand `%s`", action_name ));

  args_t args;
  if( FD_LIKELY( action->args ) ) action->args( &argc, &argv, &args );
  if( FD_UNLIKELY( argc ) ) FD_LOG_ERR(( "unknown argument `%s`", argv[ 0 ] ));

  /* check if we are appropriate permissioned to run the desired command */
  if( FD_LIKELY( action->perm ) ) {
    fd_caps_ctx_t caps = {0};
    action->perm( &args, &caps, &config );
    if( FD_UNLIKELY( caps.err_cnt ) ) {
      execve_as_root( orig_argc, orig_argv );
    }
  }

  /* run the command */
  action->fn( &args, &config );

  return 0;
}
