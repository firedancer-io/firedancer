#define _GNU_SOURCE
#include "fddev.h"

void
initialize_workspaces( config_t * const config );

void
wksp_cmd_fn( args_t *         args,
             config_t * const config ) {
  (void)args;

  initialize_workspaces( config );
  exit_group( 0 );
}
