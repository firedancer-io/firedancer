#include "fdctl.h"

void
mem_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;

  fd_topo_print( config->pod, 1 );
}
