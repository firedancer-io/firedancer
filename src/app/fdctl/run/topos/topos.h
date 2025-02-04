#ifndef HEADER_fd_src_app_fdctl_run_topos_h
#define HEADER_fd_src_app_fdctl_run_topos_h

#include "../../config.h"

struct fd_topos_affinity {
  ulong tile_to_cpu[ FD_TILE_MAX ];
  ulong tile_cnt;
  int   is_auto;
};

typedef struct fd_topos_affinity fd_topos_affinity_t;

FD_PROTOTYPES_BEGIN

void
fd_topos_affinity( fd_topos_affinity_t * affinity,
                   char const *          affinity_str );

void
fd_topos_create_validator( fd_topo_t *                 topo,
                           config_t *                  config,
                           fd_topos_affinity_t const * affinity );

void
fd_topos_add_net_tile( fd_topo_t *      topo,
                       config_t const * config,
                       ulong const      tile_to_cpu[ FD_TILE_MAX ] );

void
fd_topos_detect_affinity_mismatch( fd_topo_t const *           topo,
                                   fd_topos_affinity_t const * affinity );

void
fd_topos_seal( fd_topo_t *                 topo,
               fd_topos_affinity_t const * affinity );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_fdctl_run_topos_h */
