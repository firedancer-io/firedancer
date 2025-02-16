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

/* fd_topos_affinity parses an affinity string. */

void
fd_topos_affinity( fd_topos_affinity_t * affinity,
                   char const *          affinity_str,
                   char const *          config_option );

/* fd_topos_create_validator creates all base validator tiles. */

void
fd_topos_create_validator( fd_topo_t * topo,
                           config_t *  config );

void
fd_topos_seal( fd_topo_t * topo );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_fdctl_run_topos_h */
