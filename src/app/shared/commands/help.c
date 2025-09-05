#include "../fd_config.h"
#include "../fd_action.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern char const * FD_APP_NAME;
extern char const * FD_BINARY_NAME;

extern action_t * ACTIONS[];

static int
action_compare( void const * a, void const * b ) {
  action_t const * action_a = *(action_t const * const *)a;
  action_t const * action_b = *(action_t const * const *)b;
  return strcmp( action_a->name, action_b->name );
}

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
  

  ulong action_count = 0UL;
  while( ACTIONS[ action_count ] ) action_count++;
  
  action_t ** sorted_actions = (action_t **)malloc( action_count * sizeof(action_t *) );
  if( FD_UNLIKELY( !sorted_actions ) ) FD_LOG_ERR(( "malloc failed" ));
  
  for( ulong i=0UL; i<action_count; i++ ) {
    sorted_actions[ i ] = ACTIONS[ i ];
  }
  
  qsort( sorted_actions, action_count, sizeof(action_t *), action_compare );
  
  /* Print the sorted actions */
  for( ulong i=0UL; i<action_count; i++ ) {
    FD_LOG_STDOUT(( "   %13s    %s\n", sorted_actions[ i ]->name, sorted_actions[ i ]->description ));
  }
  
  free( sorted_actions );
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
