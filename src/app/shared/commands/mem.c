#include "../fd_config.h"

void
mem_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;

  fd_topo_print_log( 1, &config->topo );
}
