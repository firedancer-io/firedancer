#ifndef HEADER_fd_src_app_shared_boot_fd_boot_h
#define HEADER_fd_src_app_shared_boot_fd_boot_h

#include "../fd_config.h"
#include "../fd_config_file.h"

FD_PROTOTYPES_BEGIN

/* fd_app_tile_run returns the run descriptor of the tile with the same
   name as the given tile, looked up in the application's TILES list.
   Logs an error and exits if no such tile exists. */

fd_topo_run_tile_t
fd_app_tile_run( fd_topo_tile_t const * tile );

int
fd_main( int                        argc,
         char **                    _argv,
         fd_config_file_t * const * configs,
         void (* topo_init )( config_t * config ) );

int
fd_main_init( int *                      pargc,
              char ***                   pargv,
              config_t   *               config,
              const char *               opt_user_config_path,
              int                        is_local_cluster,
              char const *               log_path,
              fd_config_file_t * const * configs,
              int                        dev );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_boot_fd_boot_h */
