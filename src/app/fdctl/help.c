#include "fdctl.h"

#include <stdio.h>

#define MAX_LENGTH 4096

#define PRINT_HELP( ... ) do {                                                \
    int n = snprintf( cur, rem, __VA_ARGS__ );                                \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf failed" ));             \
    if( FD_UNLIKELY( (ulong)n >= rem ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    rem -= (ulong)n;                                                          \
    cur += n;                                                                 \
  } while( 0 )

void
help_cmd_fn( args_t *         args,
             config_t * const config ) {
  (void)args;
  (void)config;

  char help[ MAX_LENGTH ] = {0};
  char * cur = help;
  ulong rem = MAX_LENGTH-1; /* Leave one character to NUL terminate string */

  PRINT_HELP( "Firedancer control binary\n\n" );
  PRINT_HELP( "Usage: fdctl [OPTIONS] <SUBCOMMAND>\n\n" );
  PRINT_HELP( "\nOPTIONS:\n" );
  /* fdctl does not have many flag arguments so we hard-code the
     --config parameter. */
  PRINT_HELP( "        --config <PATH>    Path to config TOML file\n\n" );
  PRINT_HELP( "SUBCOMMANDS:\n" );
  for( ulong i=0; i<ACTIONS_CNT ; i++ ) {
    PRINT_HELP( "    %9s    %s\n", ACTIONS[ i ].name, ACTIONS[ i ].description );
  }
  fd_log_private_fprintf_0( STDOUT_FILENO, "%s", help );
}
