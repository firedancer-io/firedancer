#include "../../shared_dev/commands/dev.h"

void
firedancer_dev_dev_cmd_fn( args_t *   args,
                           config_t * config ) {
  dev_cmd_fn( args, config, NULL );
}

action_t fd_action_dev = {
  .name             = "dev",
  .args             = dev_cmd_args,
  .fn               = firedancer_dev_dev_cmd_fn,
  .perm             = dev_cmd_perm,
  .is_local_cluster = 1,
  .description      = "Start up a development validator"
};
