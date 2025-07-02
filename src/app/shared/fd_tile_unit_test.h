#ifndef HEADER_fd_src_app_shared_fd_tile_unit_test_h
#define HEADER_fd_src_app_shared_fd_tile_unit_test_h

#include "../../app/shared/fd_config.h"

/* fd_tile_unit_test_init provides the skeleton initialization steps.
   From the three config paths, only default_topo_config_path is
   required, whereas the other two (override_topo_config_path and
   user_topo_config_path) are optional.  These inputs, together with
   netns, is_firedancer and is_local_cluster are passed to
   fd_config_load() (Refer to the functions documentation for further
   details).  fd_topo_initialize_ is a pointer to the initialization
   function inside the chosen topology (e.g. firedancer or fdctl).
   topo_run_tile is typically declared and defined inside the tile
   under test.  out_config is populated as part of the initialization
   process.  On error, the function logs a warning and returns NULL.
   On success, it return a (fd_topo_tile_t *) pointer, which is
   typically required by (un)priviliged_init. */

fd_topo_tile_t *
fd_tile_unit_test_init( char const *         default_topo_config_path,
                        char const *         override_topo_config_path,
                        char const *         user_topo_config_path,
                        int                  netns,
                        int                  is_firedancer,
                        int                  is_local_cluster,
                        void (*fd_topo_initialize_)(config_t *),
                        fd_topo_run_tile_t * topo_run_tile,
                        config_t *           out_config );

#endif /* HEADER_fd_src_app_shared_fd_tile_unit_test_h */
