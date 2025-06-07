/* The ibeth tile translates Ethernet frames between InfiniBand devices
   in 'raw packet' mode and fd_tango traffic.  Works best on Mellanox
   ConnectX. */

#include "../../topo/fd_topo.h"
#include <errno.h>
#include <infiniband/verbs.h>

/* fd_ibeth_open_device attempts to open an ibv_context for the device
   specified by tile configuration. */

struct ibv_context *
fd_ibeth_open_device( fd_topo_tile_t const * tile ) {
  int device_cnt = 0;
  struct ibv_device ** dev_list = ibv_get_device_list( &device_cnt );
  if( FD_UNLIKELY( !dev_list ) ) {
    FD_LOG_ERR(( "ibv_get_device_list_failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( !device_cnt ) ) {
    FD_LOG_ERR(( "No ibverbs devices found" ));
  }
  FD_LOG_DEBUG(( "Found %i ibverbs devices", device_cnt ));

  /* Scan device list for interface */
  for( int i=0; i<device_cnt; i++ ) {
    struct ibv_device * dev = dev_list[ i ];
    if( FD_UNLIKELY( !dev ) ) break;
    FD_LOG_NOTICE(( "name=%s dev_name=%s", dev->name, dev->dev_name ));
  }
  (void)tile;

  FD_LOG_ERR(( "TODO" ));
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  (void)topo;
  if( FD_UNLIKELY( tile->kind_id!=0 ) ) {
    /* FIXME support receive side scaling using ibv_create_rwq_ind_table
             and ibv_rx_hash_conf. */
    FD_LOG_ERR(( "Sorry, net.provider='ibeth' only supports layout.net_tile_count=1" ));
  }

  struct ibv_context * ibv_context = fd_ibeth_open_device( tile );
  (void)ibv_context;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;
}

static ulong
scratch_align( void ) {
  return 1UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return 0UL;
}

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_ibeth = {
  .name                     = "ibeth",
  //.populate_allowed_seccomp = populate_allowed_seccomp,
  //.populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init
};
#endif
