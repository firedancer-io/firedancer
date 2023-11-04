#include "fdctl.h"

action_t ACTIONS[ ACTIONS_CNT ] = {
  { .name = "run",       .args = NULL,               .fn = run_cmd_fn,       .perm = run_cmd_perm,        .description = "Start up a Firedancer validator" },
  { .name = "configure", .args = configure_cmd_args, .fn = configure_cmd_fn, .perm = configure_cmd_perm,  .description = "Configure the local host so it can run Firedancer correctly" },
  { .name = "monitor",   .args = monitor_cmd_args,   .fn = monitor_cmd_fn,   .perm = monitor_cmd_perm,    .description = "Monitor a locally running Firedancer instance with a terminal GUI" },
  { .name = "keygen",    .args = keygen_cmd_args,    .fn = keygen_cmd_fn,    .perm = NULL,                .description = "Generate new keypairs for use with the validator" },
  { .name = "ready",     .args = NULL,               .fn = ready_cmd_fn,     .perm = NULL,                .description = "Wait for all tiles to be running" },
  { .name = "mem",       .args = NULL,               .fn = mem_cmd_fn,       .perm = NULL,                .description = "Print workspace memory and tile topology information" },
  { .name = "help",      .args = NULL,               .fn = help_cmd_fn,      .perm = NULL,                .description = "Print this help message" },
};

struct action_alias {
  const char * name;
  const char * alias;
};

struct action_alias ALIASES[] = {
  { .name = "info", .alias = "mem" },
  { .name = "topo", .alias = "mem" },
};

int
main1( int     argc,
      char ** _argv ) {
  fd_boot( &argc, &_argv );
  fd_log_thread_set( "main" );

  char ** argv = _argv;
  argc--; argv++;

  /* load configuration and command line parsing */
  config_t config = config_parse( &argc, &argv );

  if( FD_UNLIKELY( !argc ) ) {
    help_cmd_fn( NULL, &config );
    FD_LOG_ERR(( "no subcommand specified" ));
  }

  const char * command = argv[ 0 ];
  for ( ulong i=0; i <sizeof(ALIASES)/sizeof(ALIASES[ 0 ]); i++ ) {
    if( FD_UNLIKELY( !strcmp( argv[ 0 ], ALIASES[ i ].name ) ) ) {
      command = ALIASES[ i ].alias;
      break;
    }
  }

  action_t * action = NULL;
  for( ulong i=0; i<ACTIONS_CNT; i++ ) {
    if( FD_UNLIKELY( !strcmp( command, ACTIONS[ i ].name ) ) ) {
      action = &ACTIONS[ i ];
      break;
    }
  }
  if( FD_UNLIKELY( !action ) ) {
    help_cmd_fn( NULL, &config );
    FD_LOG_ERR(( "unknown subcommand `%s`", argv[ 0 ] ));
  }

  argc--; argv++;

  args_t args;
  if( FD_LIKELY( action->args ) ) action->args( &argc, &argv, &args );
  if( FD_UNLIKELY( argc ) ) FD_LOG_ERR(( "unknown argument `%s`", argv[ 0 ] ));

  /* check if we are appropriate permissioned to run the desired command */
  if( FD_LIKELY( action->perm ) ) {
    fd_caps_ctx_t caps[1] = {0};
    action->perm( &args, caps, &config );
    if( FD_UNLIKELY( caps->err_cnt ) ) {
      for( ulong i=0; i<caps->err_cnt; i++ ) FD_LOG_WARNING(( "%s", caps->err[ i ] ));
      if( FD_LIKELY( !strcmp( action->name, "run" ) ) ) {
        FD_LOG_ERR(( "insufficient permissions to execute command `%s`. It is recommended "
                     "to start Firedancer as the root user, but you can also start it "
                     "with the missing capabilities listed above. The program only needs "
                     "to start with elevated permissions to do privileged operations at "
                     "boot, and will immediately drop permissions and switch to the user "
                     "specified in your configuration file once they are complete. Firedancer "
                     "will not execute outside of the boot process as root, and will refuse "
                     "to start if it cannot drop privileges. Firedancer needs to be started "
                     "privileged to configure high performance networking with XDP.", action->name ));
      } else if( FD_LIKELY( !strcmp( action->name, "configure" ) ) ) {
        FD_LOG_ERR(( "insufficient permissions to execute command `%s`. It is recommended "
                     "to configure Firedancer as the root user. Firedancer configuration requires "
                     "root because it does privileged operating system actions like setting up XDP. "
                     "Configuration is a local action that does not access the network, and the process "
                     "exits immedaitely once configuration completes. The user that Firedancer runs "
                     "as is specified in your configuration file, and although configuration runs as root "
                     "it will permission the relevant resources for the user in your configuration file, "
                     "which can be an anonymous maximally restrictive account with no privileges.", action->name ));
      } else {
        FD_LOG_ERR(( "insufficient permissions to execute command `%s`", action->name ));
      }
    }
  }

  /* run the command */
  action->fn( &args, &config );

  return 0;
}
