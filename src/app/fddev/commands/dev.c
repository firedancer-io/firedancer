#define _GNU_SOURCE
#include "../../shared_dev/commands/dev.h"

#include <pthread.h>

void
agave_boot( config_t const * config );

static void *
agave_main1( void * args ) {
  agave_boot( args );
  return NULL;
}

void
spawn_agave( config_t const * config ) {
  pthread_t pthread;
  int err = pthread_create( &pthread, NULL, agave_main1, (void *)config );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "pthread_create() failed (%i-%s)", err, fd_io_strerror( err ) ));
  err = pthread_setname_np( pthread, "fdSolMain" );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "pthread_setname_np() failed (%i-%s)", err, fd_io_strerror( err ) ));
}

void
fddev_dev_cmd_fn( args_t *   args,
                           config_t * config ) {
  dev_cmd_fn( args, config, spawn_agave );
}

action_t fd_action_dev = {
  .name             = "dev",
  .args             = dev_cmd_args,
  .fn               = fddev_dev_cmd_fn,
  .perm             = dev_cmd_perm,
  .is_local_cluster = 1,
  .description      = "Start up a development validator"
};
