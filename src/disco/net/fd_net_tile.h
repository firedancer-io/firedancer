#ifndef HEADER_fd_src_disco_net_fd_net_tile_h
#define HEADER_fd_src_disco_net_fd_net_tile_h

/* fd_net_tile.h contains APIs for providing XDP networking to a
   Firedancer topology using the 'net' tile. */

#include "../topo/fd_topob.h"

struct fdctl_config;
typedef struct fdctl_config config_t;

FD_PROTOTYPES_BEGIN

/* fd_topos_net_tiles appends the net and netlnk tiles to the
   topology.  These tiles provide fast XDP networking. */

void
fd_topos_net_tiles( fd_topo_t *      topo,
                    config_t const * config,
                    ulong const      tile_to_cpu[ FD_TILE_MAX ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_tile_h */
