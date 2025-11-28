#include "../../shared_dev/commands/bench/bench.h"
#include "../../shared_dev/commands/dev.h"

#include <unistd.h>

static void
bench_cmd_topo( config_t * config ) {
  config->development.sandbox  = 0;
  config->development.no_clone = 1;
}

void
firedancer_dev_bench_cmd_fn( args_t *   args,
                             config_t * config ) {
  bench_cmd_fn( args, config, 1 );

  /* Sleep parent thread forever, Ctrl+C will terminate. */
  for(;;) pause();
}

action_t fd_action_bench = {
  .name             = "bench",
  .args             = bench_cmd_args,
  .fn               = firedancer_dev_bench_cmd_fn,
  .perm             = dev_cmd_perm,
  .topo             = bench_cmd_topo,
  .is_local_cluster = 1,
  .description      = "Test validator TPS benchmark"
};
