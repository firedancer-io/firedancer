#ifndef HEADER_fd_src_discof_fd_accdb_topo_h
#define HEADER_fd_src_discof_fd_accdb_topo_h

/* fd_accdb_topo.h provides an API to join a tile to the accounts DB. */

#include "../disco/topo/fd_topo.h"
#include "../flamenco/accdb/fd_accdb_base.h"

FD_PROTOTYPES_BEGIN

void
fd_accdb_init_from_topo( fd_accdb_user_t *      accdb,
                         fd_topo_t const *      topo,
                         fd_topo_tile_t const * tile );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_fd_accdb_topo_h */
