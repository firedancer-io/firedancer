#include "fdctl.h"

void
info_cmd_fn( args_t *         args,
             config_t * const config ) {
  (void)args;

  fd_topo_fill( &config->topo, FD_TOPO_FILL_MODE_FOOTPRINT );
  fd_topo_print_log( &config->topo );
}
