#include "../fd_config.h"

void
mem_cmd_fn( args_t *   args FD_PARAM_UNUSED,
            config_t * config ) {
  fd_topo_print_log( 1, &config->topo );
}
