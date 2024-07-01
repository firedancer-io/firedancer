#include "fdctl.h"

#include "version.h"

void
version_cmd_fn( args_t *         args,
                config_t * const config ) {
  (void)args;
  (void)config;

  FD_LOG_STDOUT(( "%u.%u.%u\n", FD_VERSION_MAJOR, FD_VERSION_MINOR, FD_VERSION_PATCH ));
}
