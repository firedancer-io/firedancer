#include "../fd_config.h"

#include <unistd.h>

extern action_t * ACTIONS;

void
help_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
             config_t * config FD_PARAM_UNUSED ) {
  FD_LOG_STDOUT(( "Firedancer control binary\n\n" ));
  FD_LOG_STDOUT(( "Usage: fdctl [OPTIONS] <SUBCOMMAND>\n\n" ));
  FD_LOG_STDOUT(( "\nOPTIONS:\n" ));
  /* fdctl does not have many flag arguments so we hard-code the
     --config parameter. */
  FD_LOG_STDOUT(( "        --config <PATH>    Path to config TOML file\n\n" ));
  FD_LOG_STDOUT(( "SUBCOMMANDS:\n" ));
  for( ulong i=0; ACTIONS[ i ].name; i++ ) {
    FD_LOG_STDOUT(( "    %9s    %s\n", ACTIONS[ i ].name, ACTIONS[ i ].description ));
  }
}
