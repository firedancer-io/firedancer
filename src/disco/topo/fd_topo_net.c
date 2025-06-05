#include "fd_topo_net.h"
#include <errno.h>
#include <unistd.h>

static int
fd_xdp_multi_fds_if_idx_exists( fd_xdp_multi_fds_t const * fds,
                                uint                       if_idx ) {
  for( ulong i=0UL; i<fds->device_cnt; i++ ) {
    if( fds->device[ i ].if_idx==if_idx ) return 1;
  }
  return 0;
}

static int
fd_xdp_multi_fds_if_idx_add( fd_xdp_multi_fds_t * fds,
                             uint                 if_idx,
                             char const           if_name[ 16 ] ) {
  uint idx = fds->device_cnt;
  if( FD_UNLIKELY( idx>=FD_TOPO_XDP_DEVICES_MAX ) ) {
    return 0;
  }
  memcpy( fds->device[ idx ].if_name, if_name, 16 );
  fds->device[ idx ].if_idx = if_idx;
  fds->device_cnt++;
  return 1;
}

fd_xdp_multi_fds_t
fd_topo_install_xdp( fd_topo_t * topo,
                     uint        bind_addr ) {
  ulong net0_tile_idx = fd_topo_find_tile( topo, "net", 0UL );
  FD_TEST( net0_tile_idx!=ULONG_MAX );
  fd_topo_tile_t const * net0_tile = &topo->tiles[ net0_tile_idx ];
  ushort const udp_port_candidates[] = {
    (ushort)net0_tile->xdp.net.legacy_transaction_listen_port,
    (ushort)net0_tile->xdp.net.quic_transaction_listen_port,
    (ushort)net0_tile->xdp.net.shred_listen_port,
    (ushort)net0_tile->xdp.net.gossip_listen_port,
    (ushort)net0_tile->xdp.net.repair_intake_listen_port,
    (ushort)net0_tile->xdp.net.repair_serve_listen_port,
  };

  /* Gather array of unique interface indices */

  fd_xdp_multi_fds_t fds = {0};
  for( ulong tile_idx=0UL; tile_idx<(topo->tile_cnt); tile_idx++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ tile_idx ];
    if( 0!=strcmp( tile->name, "net" ) ) continue;
    for( ulong j=0UL; j<(tile->xdp.queue_cnt); j++ ) {
      uint if_idx = tile->xdp.queues[ j ].if_idx;
      if( !fd_xdp_multi_fds_if_idx_exists( &fds, if_idx ) ) {
        if( FD_UNLIKELY( !fd_xdp_multi_fds_if_idx_add( &fds, if_idx, tile->xdp.queues[ j ].if_name ) ) ) {
          FD_LOG_ERR(( "Topology contains more than %d interfaces (too many bond device slaves?)",
                       FD_TOPO_XDP_DEVICES_MAX ));
        }
      }
    }
  }

  /* Install XDP interfaces */

  int dup_fd = FD_TOPO_XDP_INHERIT_FD_MIN;
  for( ulong i=0UL; i<(fds.device_cnt); i++ ) {
    fd_xdp_fds_t xdp_fds = fd_xdp_install(
        fds.device[ i ].if_idx,
        bind_addr,
        sizeof(udp_port_candidates)/sizeof(udp_port_candidates[0]),
        udp_port_candidates,
        net0_tile->xdp.xdp_mode
    );

    if( FD_UNLIKELY( -1==dup2( xdp_fds.xsk_map_fd, dup_fd++   ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)",  errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( xdp_fds.xsk_map_fd            ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==dup2( xdp_fds.prog_link_fd, dup_fd++ ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)" , errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( xdp_fds.prog_link_fd          ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    fds.device[ i ].fds = (fd_xdp_fds_t) {
      .xsk_map_fd   = dup_fd - 2,
      .prog_link_fd = dup_fd - 1,
    };
  }

  /* Fill in file descriptors in net tiles */

  for( ulong tile_idx=0UL; tile_idx<(topo->tile_cnt); tile_idx++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ tile_idx ];
    if( 0!=strcmp( tile->name, "net" ) ) continue;

    for( ulong j=0UL; j<(tile->xdp.queue_cnt); j++ ) {
      uint if_idx = tile->xdp.queues[ j ].if_idx;
      for( ulong k=0UL; k<(fds.device_cnt); k++ ) {
        if( fds.device[ k ].if_idx==if_idx ) {
          tile->xdp.queues[ j ].xsk_map_fd = fds.device[ k ].fds.xsk_map_fd;
          FD_LOG_DEBUG(( "net:%lu interface/queue %u:%u assigned XSK map fd %d",
                          tile->kind_id, if_idx, tile->xdp.queues[ j ].queue_id, tile->xdp.queues[ j ].xsk_map_fd ));
          break;
        }
      }
      if( FD_UNLIKELY( tile->xdp.queues[ j ].xsk_map_fd<0 ) ) {
        FD_LOG_ERR(( "Failed to assign XSK map fd for net:%lu interface/queue %u:%u (programming bug?)",
                     tile->kind_id, if_idx, tile->xdp.queues[ j ].queue_id ));
      }
    }

    for( ulong k=0UL; k<(fds.device_cnt); k++ ) {
      int const prog_link_fd = fds.device[ k ].fds.prog_link_fd;
      if( FD_UNLIKELY( tile->xdp.prog_link_fd_cnt>=FD_TOPO_XDP_TILE_QUEUES_MAX ) ) {
        FD_LOG_ERR(( "Too many XDP program link FDs for net tile %lu", tile->kind_id ));
      }
      tile->xdp.prog_link_fds[ tile->xdp.prog_link_fd_cnt++ ] = prog_link_fd;
    }
  }

  return fds;
}
