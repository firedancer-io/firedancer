#include "../fd_config.h"
#include "../fd_action.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char const * FD_APP_NAME;
extern char const * FD_BINARY_NAME;

extern action_t * ACTIONS[];

#define SORT_NAME        sort_action_name
#define SORT_KEY_T       action_t *
#define SORT_BEFORE(a,b) (strcmp( (a)->name, (b)->name )<0)
#include "../../../util/tmpl/fd_sort.c"

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

  ulong       action_cnt = 0UL;
  while( ACTIONS[ action_cnt ] ) action_cnt++;

  if( FD_LIKELY( action_cnt ) ) {
    action_t ** sorted = malloc( action_cnt * sizeof(action_t *) );
    if( FD_UNLIKELY( !sorted ) ) {
      FD_LOG_ERR(( "malloc failed for help sorted actions (count %lu, elem_sz %lu, total %lu)",
                   action_cnt,
                   (ulong)sizeof( action_t * ),
                   action_cnt * (ulong)sizeof( action_t * ) ));
      }

    for( ulong i=0UL; i<action_cnt; i++ ) {
      sorted[ i ] = ACTIONS[ i ];
    }

    sort_action_name_inplace( sorted, action_cnt );

    for( ulong i=0UL; i<action_cnt; i++ ) {
      char const * desc = sorted[ i ]->description;
      if( FD_UNLIKELY( !desc ) ) desc = "";
      FD_LOG_STDOUT(( "   %13s    %s\n", sorted[ i ]->name, desc ));
    }

    free( sorted );
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
