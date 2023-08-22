#define _GNU_SOURCE
#include "fdctl.h"

#include <sys/mman.h>

action_t ACTIONS[ 4 ] = {
  { .name = "run",       .args = NULL,               .fn = run_cmd_fn,       .perm = run_cmd_perm },
  { .name = "configure", .args = configure_cmd_args, .fn = configure_cmd_fn, .perm = configure_cmd_perm },
  { .name = "monitor",   .args = monitor_cmd_args,   .fn = monitor_cmd_fn,   .perm = monitor_cmd_perm },
  { .name = "keygen",    .args = NULL,               .fn = keygen_cmd_fn,    .perm = NULL },
};

extern int * fd_log_private_shared_lock;

int
main1( int     argc,
      char ** _argv ) {
  fd_log_private_shared_lock = (int*)mmap( NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, (off_t)0 );
  if( FD_UNLIKELY( !fd_log_private_shared_lock ) ) exit(1);

  fd_boot( &argc, &_argv );
  fd_log_thread_set( "main" );

  char ** argv = _argv;
  argc--; argv++;

  /* load configuration and command line parsing */
  config_t config = config_parse( &argc, &argv );

  if( FD_UNLIKELY( !argc ) ) FD_LOG_ERR(( "no subcommand specified" ));

  action_t * action = NULL;
  for( ulong i=0; i<sizeof(ACTIONS)/sizeof(ACTIONS[ 0 ]); i++ ) {
    if( FD_UNLIKELY( !strcmp( argv[ 0 ], ACTIONS[ i ].name ) ) ) {
      action = &ACTIONS[ i ];
      break;
    }
  }
  if( FD_UNLIKELY( !action ) ) FD_LOG_ERR(( "unknown subcommand `%s`", argv[ 0 ] ));

  argc--; argv++;

  args_t args;
  if( FD_LIKELY( action->args ) ) action->args( &argc, &argv, &args );
  if( FD_UNLIKELY( argc ) ) FD_LOG_ERR(( "unknown argument `%s`", argv[ 0 ] ));

  /* check if we are appropriate permissioned to run the desired command */
  if( FD_LIKELY( action->perm ) ) {
    security_t security = {
      .idx = 0,
    };
    action->perm( &args, &security, &config );
    if( FD_UNLIKELY( security.idx ) ) {
      for( ulong i=0; i<security.idx; i++ ) FD_LOG_WARNING(( "%s", security.errors[ i ] ));
      FD_LOG_ERR(( "insufficient permissions to execute command `%s`", argv[ 0 ] ));
    }
  }

  /* run the command */
  action->fn( &args, &config );

  return 0;
}
