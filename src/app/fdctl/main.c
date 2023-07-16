#define _GNU_SOURCE
#include "fdctl.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    const char * name;
    void       (*args)( int * pargc, char *** pargv, args_t * args );
    void       (*perm)( args_t * args, security_t * security, config_t * const config );
    void       (*fn  )( args_t * args, config_t * const config );
} action_t;

/* available command line programs */
static action_t ACTIONS[] = {
  { .name = "run",       .args = run_cmd_args,       .fn = run_cmd_fn,       .perm = run_cmd_perm },
  { .name = "configure", .args = configure_cmd_args, .fn = configure_cmd_fn, .perm = configure_cmd_perm },
  { .name = "monitor",   .args = monitor_cmd_args,   .fn = monitor_cmd_fn,   .perm = monitor_cmd_perm },
};

#define MAX_ARGC 32

/* Rerun the currently executing process as root. This will never return,
   instead it replaces the currently executing process with a new one. */
static void
execve_as_root( int     argc,
                char ** argv ) {
  char self_exe[ PATH_MAX ] = {0};
  long count = readlink( "/proc/self/exe", self_exe, PATH_MAX );
  if( FD_UNLIKELY( count < 0 ) ) FD_LOG_ERR(( "readlink(/proc/self/exe) failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( count >= PATH_MAX ) ) FD_LOG_ERR(( "readlink(/proc/self/exe) returned truncated path" ));

  char * args[ MAX_ARGC+1 ];
  for( int i=2; i<=argc; i++ ) args[i] = argv[i-1];
  args[0]      = "sudo";
  args[1]      = self_exe;
  args[argc+1] = NULL;

  /* ok to leak these dynamic strings because we are about to execve anyway */
  char * envp[ 3 ] = {0};
  char * env;
  int    idx = 0;
  if( FD_LIKELY(( env = getenv( "FIREDANCER_CONFIG_TOML" ) )) ) {
    if( FD_UNLIKELY( asprintf( &envp[ idx++ ], "FIREDANCER_CONFIG_TOML=%s", env ) == -1 ) )
      FD_LOG_ERR(( "asprintf() failed (%i-%s)", errno, strerror( errno ) ));
  }
  if( FD_LIKELY(( env = getenv( "TERM" ) )) ) {
    if( FD_UNLIKELY( asprintf( &envp[ idx++ ], "TERM=%s", env ) == -1 ) )
      FD_LOG_ERR(( "asprintf() failed (%i-%s)", errno, strerror( errno ) ));
  }

  execve( "/usr/bin/sudo", args, envp );
  FD_LOG_ERR(( "execve(sudo) failed (%i-%s)", errno, strerror( errno ) ));
}

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

  /* initialize logging */
  fd_boot_secure1( &argc, &argv );

  /* load configuration and command line parsing */
  config_t config = config_parse( &argc, &argv );

  const char * action_name = "run";
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

  if( FD_UNLIKELY( !action ) ) FD_LOG_ERR(( "unknown argument `%s`", action_name ));

  int    sudo = fd_env_strip_cmdline_contains( &argc, &argv, "--sudo" );
  args_t args;
  action->args( &argc, &argv, &args );

  if( FD_UNLIKELY( argc ) ) FD_LOG_ERR(( "unknown argument `%s`", argv[ 0 ] ));

  /* check if we are appropriate permissioned to run the desired command */
  if( FD_LIKELY( action->perm ) ) {
    security_t security;
    action->perm( &args, &security, &config );
    if( FD_UNLIKELY( security.idx ) ) {
      if( FD_LIKELY( sudo || config.development.sudo ) ) {
        execve_as_root( orig_argc, orig_argv );
      } else {
        for( ulong i=0; i<security.idx; i++ ) FD_LOG_WARNING(( "%s", security.errors[ i ] ));
        FD_LOG_ERR(( "insufficient permissions to execute command `%s`", action_name ));
      }
    }
  }

  /* run the command */
  action->fn( &args, &config );

  return 0;
}
