#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run.h"

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

void
dev_cmd_perm( args_t *         args,
              security_t *     security,
              config_t * const config ) {
  (void)args;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  configure_args.configure.stages[ 0 ] = &netns;
  for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
    configure_args.configure.stages[ i + 1 ] = STAGES[ i ];
  configure_args.configure.stages[ CONFIGURE_STAGE_COUNT+1 ] = &cluster;
  configure_cmd_perm( &configure_args, security, config );

  run_cmd_perm( NULL, security, config );
}

void
dev_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  /* cluster and netns stages are not accessible from regular configure command,
     but perform them here. netns is first, as other stages might depend on it */
  /* netns is the first stage, others might depend on it */
  configure_args.configure.stages[ 0 ] = &netns;
  for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
    configure_args.configure.stages[ i + 1 ] = STAGES[ i ];
  configure_args.configure.stages[ CONFIGURE_STAGE_COUNT ] = &cluster;
  configure_cmd_fn( &configure_args, config );

  /* when starting from a new genesis block, this needs to be off else the
     validator will get stuck forever. */
  config->consensus.wait_for_vote_to_start_leader = 0;

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    /* if we entered a network namespace during configuration, leave it
       so that `run_firedancer` starts from a clean namespace */
    leave_network_namespace();
  }

  run_firedancer( config );
}
