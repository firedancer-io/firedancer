#include "../fd_config.h"
#include "../fd_action.h"

#include <unistd.h>

extern char const * FD_APP_NAME;
extern char const * FD_BINARY_NAME;

extern action_t * ACTIONS[];

void
help_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
             config_t * config FD_PARAM_UNUSED ) {
  FD_LOG_STDOUT(( "%s control binary\n\n", FD_APP_NAME ));
  FD_LOG_STDOUT(( "Usage: %s <SUBCOMMAND> [OPTIONS]\n\n", FD_BINARY_NAME ));
  FD_LOG_STDOUT(( "\nOPTIONS:\n" ));
  /* fdctl does not have many flag arguments so we hard-code the
     --config parameter. */
  FD_LOG_STDOUT(( "        --config <PATH>    Path to config TOML file\n" ));
  FD_LOG_STDOUT(( "        --version          Show the current software version\n" ));
  FD_LOG_STDOUT(( "        --help             Print this help message\n\n" ));
  FD_LOG_STDOUT(( "SUBCOMMANDS:\n" ));
  for( ulong i=0UL; ACTIONS[ i ]; i++ ) {
    FD_LOG_STDOUT(( "   %13s    %s\n", ACTIONS[ i ]->name, ACTIONS[ i ]->description ));
  }
}

action_t fd_action_help = {
  .name          = "help",
  .args          = NULL,
  .fn            = help_cmd_fn,
  .perm          = NULL,
  .description   = "Print this help message",
  .is_help       = 1,
  .is_immediate  = 1,
  .is_diagnostic = 1,
};
