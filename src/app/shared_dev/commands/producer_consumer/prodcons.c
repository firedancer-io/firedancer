#include "../dev.h"
#include "../../../shared/commands/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../../../shared/commands/run/run.h" /* fdctl_check_configure */
#include "../../../../disco/topo/fd_topob.h"

#include <stdio.h> /* printf */
#include <unistd.h> /* isatty */

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
prodcons_topo( config_t * config ) {
  // Reset topology from scratch
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  
  // Create workspaces
  fd_topob_wksp( topo, "prod_wksp" );
  fd_topob_wksp( topo, "cons_wksp" );

  // TESTING BELow
  fd_topob_wksp( topo, "metric_in" );
  
  // Create tiles with simple CPU assignment (CPU 0 and 1)
  fd_topob_tile( topo, "produc", "prod_wksp", "prod_wksp", 0, 0, 1, 0 );
  fd_topob_tile( topo, "consum", "cons_wksp", "cons_wksp", 1, 0, 1, 0 );
  
  // Create single link between them
  // fd_topob_wksp( topo, "data_link" );
  fd_topob_link( topo, "data_link", "prod_wksp", 1024UL, 256UL, 1UL );
  
  // Connect producer output to link
  fd_topob_tile_out( topo, "produc", 0UL, "data_link", 0UL );
  
  // Connect consumer input to link  
  // TODO: make reliable, cuz unreliable getting overrun
  fd_topob_tile_in( topo, "consum", 0UL, "metric_in", "data_link", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( 1, topo );
}

void
prodcons_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  /* FIXME add config options here */
  (void)pargc; (void)pargv; (void)args;
}

void
prodcons_cmd_fn( args_t *   args FD_PARAM_UNUSED,
               config_t * config ) {
  prodcons_topo( config );

  // Add the missing configuration steps to clean up and initialize properly
  configure_stage( &fd_cfg_stage_sysctl,    CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_hugetlbfs, CONFIGURE_CMD_INIT, config );
  
  fdctl_check_configure( config );
  
  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  for(;;) pause();
}

action_t fd_action_prodcons = {
  .name        = "prodcons",
  .args        = prodcons_cmd_args,
  .fn          = prodcons_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Producer-consumer topology"
};
