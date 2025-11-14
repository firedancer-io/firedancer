#include "../../shared_dev/commands/bench/bench.h"
#include "../../shared_dev/commands/dev.h"

#include <unistd.h>
#include <pthread.h>

void
agave_boot( config_t const * config );

static void *
agave_thread_main( void * _args ) {
  config_t * config = _args;
  agave_boot( config );

  /* Agave will never exit, we never set exit flag to true */
  FD_LOG_ERR(( "agave_boot() exited" ));
  return NULL;
}

void
fddev_bench_cmd_fn( args_t *   args,
                    config_t * config ) {
  bench_cmd_fn( args, config, 0 );

  pthread_t agave;
  pthread_create( &agave, NULL, agave_thread_main, (void *)config );

  /* Sleep parent thread forever, Ctrl+C will terminate. */
  for(;;) pause();
}

action_t fd_action_bench = {
  .name             = "bench",
  .args             = bench_cmd_args,
  .fn               = fddev_bench_cmd_fn,
  .perm             = dev_cmd_perm,
  .is_local_cluster = 1,
  .description      = "Test validator TPS benchmark"
};
