#include "../fd_config.h"
#include "../fd_action.h"

#include <unistd.h>

void
version_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
                config_t * config FD_PARAM_UNUSED ) {
  FD_LOG_STDOUT(( "%s (%s)\n", fd_version_cstr, fd_commit_ref_cstr ));
}

action_t fd_action_version = {
  .name        = "version",
  .args        = NULL,
  .fn          = version_cmd_fn,
  .perm        = NULL,
  .is_immediate= 1,
  .description = "Show the current software version",
};
