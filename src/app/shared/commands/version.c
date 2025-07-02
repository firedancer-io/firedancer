#include "../fd_config.h"
#include "../fd_action.h"

#include <unistd.h>

extern char const fdctl_version_string[];
extern char const fdctl_commit_ref_string[];

void
version_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
                config_t * config FD_PARAM_UNUSED ) {
  FD_LOG_STDOUT(( "%s (%s)\n", fdctl_version_string, fdctl_commit_ref_string ));
}

action_t fd_action_version = {
  .name        = "version",
  .args        = NULL,
  .fn          = version_cmd_fn,
  .perm        = NULL,
  .is_immediate= 1,
  .description = "Show the current software version",
};
