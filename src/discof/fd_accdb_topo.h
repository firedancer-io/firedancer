#ifndef HEADER_fd_src_discof_fd_accdb_topo_h
#define HEADER_fd_src_discof_fd_accdb_topo_h

/* fd_accdb_topo.h provides an API to join a tile to the accounts DB. */

#include "../disco/topo/fd_topo.h"

FD_PROTOTYPES_BEGIN

void
fd_progcache_init_from_topo( fd_progcache_t *  progcache,
                             fd_topo_t const * topo,
                             uchar *           scratch,
                             ulong             scratch_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_fd_accdb_topo_h */
