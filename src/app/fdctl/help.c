#include "fdctl.h"

void
help_cmd_fn( args_t *         args,
             config_t * const config ) {
  (void)args;
  (void)config;

  FD_LOG_STDOUT(( "Firedancer control binary\n\n" ));
  FD_LOG_STDOUT(( "Usage: fdctl [OPTIONS] <SUBCOMMAND>\n\n" ));
  FD_LOG_STDOUT(( "\nOPTIONS:\n" ));
  /* fdctl does not have many flag arguments so we hard-code the
     --config parameter. */
  FD_LOG_STDOUT(( "        --config <PATH>    Path to config TOML file\n\n" ));
  FD_LOG_STDOUT(( "SUBCOMMANDS:\n" ));
  for( ulong i=0; i<ACTIONS_CNT ; i++ ) {
    FD_LOG_STDOUT(( "    %9s    %s\n", ACTIONS[ i ].name, ACTIONS[ i ].description ));
  }
}
