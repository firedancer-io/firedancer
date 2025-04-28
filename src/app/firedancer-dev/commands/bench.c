#include "../../shared_dev/commands/bench/bench.h"
#include "../../shared_dev/commands/dev.h"

#include <unistd.h>

void
firedancer_dev_bench_cmd_fn( args_t *   args,
                             config_t * config ) {
  bench_cmd_fn( args, config );

  /* Sleep parent thread forever, Ctrl+C will terminate. */
  for(;;) pause();
}

action_t fd_action_bench = {
  .name             = "bench",
  .args             = bench_cmd_args,
  .fn               = firedancer_dev_bench_cmd_fn,
  .perm             = dev_cmd_perm,
  .is_local_cluster = 1,
  .description      = "Test validator TPS benchmark"
};
