#include "../fd_config.h"
#include "../fd_action.h"

void
mem_cmd_fn( args_t *   args FD_PARAM_UNUSED,
            config_t * config ) {
  fd_topo_print_log( 1, &config->topo );
}

action_t fd_action_mem = {
  .name           = "mem",
  .args           = NULL,
  .fn             = mem_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Print workspace memory and tile topology information",
};
