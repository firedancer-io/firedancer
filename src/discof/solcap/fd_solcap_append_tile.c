#include "../../disco/topo/fd_topo.h"

static ulong
scratch_align( void ) {
  return 1UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return 1UL;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;
}

static void
run( fd_topo_t *      topo,
     fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;
}

fd_topo_run_tile_t fd_tile_solcap_append = {
  .name              = "solcap",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = run
};
