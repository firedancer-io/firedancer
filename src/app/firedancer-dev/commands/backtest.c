/* The backtest command spawns a smaller topology for replaying shreds from
   rocksdb (or other sources TBD) and reproduce the behavior of replay tile.

   The smaller topology is:
           repair_repla         replay_exec       exec_writer
   backtest-------------->replay------------->exec------------->writer
     ^                    |^ | |                                   ^
     |____________________|| | |___________________________________|
          replay_notif     | |
                           | |------------------------------>no consumer
    no producer-------------  stake_out, send_out, poh_out
                store_replay,
                pack_replay,

*/

#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/replay/fd_replay_notif.h"

#include <unistd.h> /* pause */

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

extern int * fd_log_private_shared_lock;

static void
backtest_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                config_t * config ) {
  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  for( ulong i=0UL; STAGES[ i ]; i++ )
    configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_fn( &configure_args, config );

  run_firedancer_init( config, 1 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );
  for(;;) pause();
}

action_t fd_action_backtest = {
  .name = "backtest",
  .args = NULL,
  .fn   = backtest_cmd_fn,
  .perm = dev_cmd_perm,
};
