/* This is the 'main' solcap tile implementation.
   Under the hood, just calls one of the underlying backend tiles. */

#include "../../disco/topo/fd_topo.h"

extern fd_topo_run_tile_t fd_tile_solcap_uring;
extern fd_topo_run_tile_t fd_tile_solcap_append;

static ulong
scratch_align( void ) {
  return fd_ulong_max( fd_tile_solcap_uring.scratch_align(), fd_tile_solcap_append.scratch_align() );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  if( tile->solcap.use_uring ) {
    return fd_tile_solcap_uring.scratch_footprint( tile );
  } else {
    return fd_tile_solcap_append.scratch_footprint( tile );
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  if( tile->solcap.use_uring ) {
    fd_tile_solcap_uring.privileged_init( topo, tile );
  } else {
    fd_tile_solcap_append.privileged_init( topo, tile );
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  if( tile->solcap.use_uring ) {
    fd_tile_solcap_uring.unprivileged_init( topo, tile );
  } else {
    fd_tile_solcap_append.unprivileged_init( topo, tile );
  }
}

static void
run( fd_topo_t *      topo,
          fd_topo_tile_t * tile ) {
  if( tile->solcap.use_uring ) {
    fd_tile_solcap_uring.run( topo, tile );
  } else {
    fd_tile_solcap_append.run( topo, tile );
  }
}

fd_topo_run_tile_t fd_tile_solcap = {
  .name              = "solcap",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = run
};
