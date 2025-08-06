#ifndef HEADER_fd_src_app_shared_dev_fd_shared_dev_h
#define HEADER_fd_src_app_shared_dev_fd_shared_dev_h

#include "../../disco/topo/fd_topo.h"

FD_PROTOTYPES_BEGIN

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_dev_fd_shared_dev_h */
