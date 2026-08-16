#include "../../shared_dev/commands/dev.h"
#include "votor_monitor.h"

void
firedancer_dev_dev_cmd_fn( args_t *   args,
                           config_t * config ) {
  dev_cmd_fn( args, config, NULL, votor_monitor_child );
}

/* dev also accepts the consensus monitor's own flags (--fps, --frames,
   --rows, --cols, --ascii, --no-color); strip them here so
   --votor-monitor can be tuned the same way the standalone command is. */

static void
firedancer_dev_dev_cmd_args( int *    pargc,
                             char *** pargv,
                             args_t * args ) {
  dev_cmd_args( pargc, pargv, args );
  votor_monitor_args( pargc, pargv );
}

action_t fd_action_dev = {
  .name             = "dev",
  .args             = firedancer_dev_dev_cmd_args,
  .fn               = firedancer_dev_dev_cmd_fn,
  .perm             = dev_cmd_perm,
  .is_local_cluster = 1,
  .description      = "Start up a development validator"
};
