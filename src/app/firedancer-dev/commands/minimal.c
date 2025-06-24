#include "../../firedancer/topology.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include <unistd.h> /* pause */
#include "../../../disco/topo/fd_topob.h"

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

/* Function to create the minimal topology */
static void
minimal_topo( config_t * config ) {
  FD_LOG_NOTICE(("Creating minimal topology top of function"));
  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );

  /* Assuming default page size and thresholds */
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong cpu_idx = 0;

  // metric tile just to pass it in?
  FD_LOG_NOTICE(("Creating minimal topology before metric tile"));
  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_tile( topo, "metric", "metric", "metric_in", cpu_idx++, 0, 0 );
  FD_LOG_NOTICE(("Creating minimal topology after metric tile"));
  fd_topob_wksp( topo, "metric" );
  /**********************************************************************/
  /* Create and add the first tile                                      */
  /**********************************************************************/
  fd_topob_wksp( topo, "tile1" ); /* Create workspace for tile1 */
  fd_topob_tile( topo, "tile1", "tile1", "metric_in", cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Create and add the second tile                                     */
  /**********************************************************************/
  fd_topob_wksp( topo, "tile2" ); /* Create workspace for tile2 */
  fd_topob_tile( topo, "tile2", "tile2", "metric_in", cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Create the link connecting tile1 to tile2                          */
  /**********************************************************************/
  fd_topob_wksp( topo, "tile1_to_2" ); /* Shared workspace for link */
  fd_topob_link( topo, "tile1_to_2", "tile1_to_2", 128UL, 1024UL, 1UL ); /* Depth = 128, MTU = 1024 */

  FD_LOG_NOTICE(("made the link"));
  /* Connect tile1's output to tile2's input */
  fd_topob_tile_out( topo, "tile1", 0UL, "tile1_to_2", 0UL );
  fd_topob_tile_in( topo, "tile2",  0UL, "metric_in", "tile1_to_2", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /**********************************************************************/
  /* Set up any shared objects if necessary                             */
  /**********************************************************************/
  /* Add code here if tile1 and tile2 need to share runtime objects such as execution buffers or memory pools. */

  /**********************************************************************/
  /* Finalize the topology                                              */
  /**********************************************************************/
  FD_LOG_NOTICE(("before finalize"));
  fd_topob_finish( topo, NULL ); /* NULL can be replaced with callbacks if needed */
  FD_LOG_NOTICE(("afterfinalize"));
  fd_topo_print_log( /* stdout */ 1, topo );
  FD_LOG_NOTICE(("after print log"));

}

/* Define the custom command for running this simple topology */
static void
minimal_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
                config_t * config ) {
  minimal_topo( config );
  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  for(;;) pause();
}

static void 
minimal_cmd_perm( args_t *         args   FD_PARAM_UNUSED,
                  fd_cap_chk_t *   chk    FD_PARAM_UNUSED,
                  config_t const * config FD_PARAM_UNUSED ) {}

static void 
minimal_cmd_args( int *    pargc FD_PARAM_UNUSED,
                  char *** pargv FD_PARAM_UNUSED,
                  args_t * args  FD_PARAM_UNUSED ) {}

/* Register the new action */
action_t fd_action_minimal = {
  .name = "minimal",
  .args = minimal_cmd_args,
  .fn   = minimal_cmd_fn,
  .perm = minimal_cmd_perm,
};