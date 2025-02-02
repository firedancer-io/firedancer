#include "fddev.h"

void
dev_help_cmd_fn( args_t *         args   FD_FN_UNUSED,
                 config_t * const config FD_FN_UNUSED ) {
  FD_LOG_STDOUT(( "Firedancer development binary\n\n" ));
  FD_LOG_STDOUT(( "Usage: fddev [OPTIONS] <SUBCOMMAND>\n\n" ));
  FD_LOG_STDOUT(( "\nOPTIONS:\n" ));
  /* fddev does not have many flag arguments so we hard-code the
     --config parameter. */
  FD_LOG_STDOUT(( "        --config <PATH>    Path to config TOML file\n\n" ));

  FD_LOG_STDOUT(( "SUBCOMMANDS (fddev):\n" ));
  for( ulong i=0; DEV_ACTIONS[ i ].name; i++ ) {
    FD_LOG_STDOUT(( "    %10s    %s\n", DEV_ACTIONS[ i ].name, DEV_ACTIONS[ i ].description ));
  }

  FD_LOG_STDOUT(( "\nSUBCOMMANDS (fdctl):\n" ));
  for( ulong i=0; ACTIONS[ i ].name; i++ ) {
    for( ulong j=0; DEV_ACTIONS[ j ].name; j++ ) {
      if( 0==strcmp( ACTIONS[ i ].name, DEV_ACTIONS[ j ].name ) ) break;
    }
    FD_LOG_STDOUT(( "    %10s    %s\n", ACTIONS[ i ].name, ACTIONS[ i ].description ));
  }
}
