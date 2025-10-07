/* The eqvoc_test command spawns a smaller topology for replaying shreds and testing equivocation.

   The smaller topology is:
           shred_out             replay_exec
   eqvoc_test-------------->replay------------->exec
     ^                     |^ | ^                |
     |_____________________|| | |________________|
          replay_out        | |   exec_replay
                            | |------------------------------>no consumer
     no producer-------------  stake_out, send_out, poh_out
                store_replay

*/
#define _GNU_SOURCE
#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/tower/fd_tower_tile.h"
#include "../../../discof/replay/fd_exec.h" /* FD_RUNTIME_PUBLIC_ACCOUNT_UPDATE_MSG_MTU */

#include "../main.h"

#include <unistd.h>
#include <fcntl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

static void
eqvoctest_topo( config_t * config ) {

  config->development.sandbox  = 0;
  config->development.no_clone = 1;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong cpu_idx = 0;

  fd_topob_wksp( topo, "metric_in" );

  /**********************************************************************/
  /* Add the eqvoc tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "eqvoct" );
  fd_topo_tile_t * eqvoct_tile = fd_topob_tile( topo, "eqvoct", "eqvoct", "metric_in", cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Add the tower tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "tower" );
  fd_topo_tile_t * tower_tile = fd_topob_tile( topo, "tower", "tower", "metric_in", cpu_idx++, 0, 0 );
  (void)tower_tile;

  /**********************************************************************/
  /* Add the repair tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "repair" );
  fd_topo_tile_t * repair_tile = fd_topob_tile( topo, "repair", "repair", "metric_in", cpu_idx++, 0, 0 );
  (void)repair_tile;

  /**********************************************************************/
  /* Add the genesis tiles to topo                                       */
  /**********************************************************************/

  fd_topob_wksp( topo, "genesi" );
  fd_topo_tile_t * genesi_tile = fd_topob_tile( topo, "genesi",  "genesi",  "metric_in",  cpu_idx++, 0, 0 );
  genesi_tile->allow_shutdown = 1;

  /**********************************************************************/
  /* Setup eqvoctest->replay link (shred_out) in topo                 */
  /**********************************************************************/

  /* The repair tile is replaced by the backtest tile for the repair to
     replay link.  The frag interface is a "slice", ie. entry batch,
     which is provided by the backtest tile, which reads in the entry
     batches from the CLI-specified source (eg. RocksDB). */

  fd_topob_wksp( topo, "replay_out" );
  fd_topob_link( topo, "replay_out", "replay_out", 65536UL, FD_SHRED_OUT_MTU, 2UL );
  fd_topob_tile_out( topo, "eqvoct", 0UL, "replay_out", 0UL );

  /**********************************************************************/
  /* Setup snapshot links in topo                                       */
  /**********************************************************************/
  fd_topob_wksp( topo, "genesi_out" );
  fd_topob_link( topo, "genesi_out", "genesi_out", 2UL, 10UL*1024UL*1024UL+32UL+sizeof(fd_lthash_value_t), 1UL );
  fd_topob_tile_out( topo, "genesi", 0UL, "genesi_out", 0UL );

  /**********************************************************************/
  /* More backtest->replay links in topo                                */
  /**********************************************************************/

  fd_topob_wksp( topo, "tower_out" );
  fd_topob_link( topo, "tower_out", "tower_out", 1024UL, sizeof(fd_tower_slot_done_t), 1UL );
  fd_topob_tile_out( topo, "tower", 0UL, "tower_out", 0UL );

  /**********************************************************************/
  /* Setup replay->backtest link (replay_notif) in topo                 */
  /**********************************************************************/

  fd_topob_tile_in ( topo, "tower",  0UL, "metric_in", "replay_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "tower",  0UL, "metric_in", "genesi_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "eqvoct", 0UL, "metric_in", "genesi_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "repair", 0UL, "metric_in", "tower_out",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED  );

  /**********************************************************************/
  /* Setup the shared objs                                              */
  /**********************************************************************/

  fd_topob_wksp( topo, "store" );
  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.store.max_completed_shred_sets, 1 );
  fd_topob_tile_uses( topo, eqvoct_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib,
      config->firedancer.funk.lock_pages );
  fd_topob_tile_uses( topo, genesi_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );


  /**********************************************************************/
  /* Finish and print out the topo information                          */
  /**********************************************************************/
  fd_topob_finish( topo, CALLBACKS );
}

extern int * fd_log_private_shared_lock;

static void
eqvoctest_cmd_topo( config_t * config ) {
  eqvoctest_topo( config );
}

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_normalpage;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_snapshots;
  args.configure.stages[ stage_idx++ ] = NULL;

  return args;
}

void
eqvoctest_cmd_args( int *    pargc,
                    char *** pargv,
                    args_t * args ) {
  (void)pargc;
  (void)pargv;
  (void)args;
}

void
eqvoctest_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                   fd_cap_chk_t *   chk,
                   config_t const * config ) {
  args_t c_args = configure_args();
  configure_cmd_perm( &c_args, chk, config );
  run_cmd_perm( NULL, chk, config );
}

static void
eqvoctest_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                 config_t * config ) {
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  run_firedancer_init( config, 1, 0 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( &config->topo );

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );
  for(;;) pause();
}

action_t fd_action_eqvoctest = {
  .name = "eqvoctest",
  .args = eqvoctest_cmd_args,
  .fn   = eqvoctest_cmd_fn,
  .perm = eqvoctest_cmd_perm,
  .topo = eqvoctest_cmd_topo,
};
