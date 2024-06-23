#include "fdctl.h"

#include "version.h"

void
version_cmd_fn( args_t *         args,
                config_t * const config ) {
  (void)args;
  (void)config;

  // FD_LOG_STDOUT(( "%lu.%lu.%lu\n", FDCTL_MAJOR_VERSION, FDCTL_MINOR_VERSION, FDCTL_PATCH_VERSION ));
}
