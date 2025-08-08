#define _GNU_SOURCE
#include "fd_dev_boot.h"

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../shared/boot/fd_boot.h"
#include "../../platform/fd_file_util.h"

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

extern char fd_log_private_path[ 1024 ];

extern action_t * ACTIONS[];

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

config_t config;

int
fd_dev_main( int                        argc,
             char **                    _argv,
             int                        is_firedancer,
             fd_config_file_t * const * configs,
             void (* topo_init )( config_t * config ) ) {
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

  int no_sandbox = fd_env_strip_cmdline_contains( &argc, &argv, "--no-sandbox" );
  int no_clone = fd_env_strip_cmdline_contains( &argc, &argv, "--no-clone" );

  const char * opt_user_config_path = fd_env_strip_cmdline_cstr(
    &argc,
    &argv,
    "--config",
    "FIREDANCER_CONFIG_TOML",
    NULL );

  const char * action_name = "dev";
  if( FD_LIKELY( argc > 0 && !strcmp( argv[ 0 ], "--version" ) ) ) {
    action_name = "version";
    argc--; argv++;
  } else if( FD_LIKELY( argc > 0 && !strcmp( argv[ 0 ], "--help" ) ) ) {
    action_name = "help";
    argc--; argv++;
  } else if( FD_UNLIKELY( argc > 0 && argv[ 0 ][ 0 ] != '-' ) ) {
    action_name = argv[ 0 ];
    argc--; argv++;
  }

  action_t * action = NULL;
  for( ulong i=0UL; ACTIONS[ i ]; i++ ) {
    if( FD_UNLIKELY( !strcmp( action_name, ACTIONS[ i ]->name ) ) ) {
      action = ACTIONS[ i ];
      if( FD_UNLIKELY( action->is_immediate ) ) {
        action->fn( NULL, NULL );
        return 0;
      }
      break;
    }
  }

  if( FD_UNLIKELY( !action ) ) {
    fprintf( stderr, "unknown subcommand `%s`\n", action_name );
    exit( 1 );
  }

  fd_main_init( &argc, &argv, &config, opt_user_config_path, is_firedancer, action->is_local_cluster, log_path, configs, topo_init );

  config.development.no_clone = config.development.no_clone || no_clone;
  config.development.sandbox = config.development.sandbox && !no_sandbox && !no_clone;

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
