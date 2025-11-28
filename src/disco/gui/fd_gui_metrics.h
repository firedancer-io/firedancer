#ifndef HEADER_fd_src_disco_gui_fd_gui_metrics_h
#define HEADER_fd_src_disco_gui_fd_gui_metrics_h

#include "../../util/fd_util_base.h"
#include "../topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"

static inline ulong
fd_gui_metrics_sum_tiles_counter( fd_topo_t const *    topo,
                                  char const *         name,
                                  ulong                tile_cnt,
                                  ulong                metric_idx ) {
  ulong total = 0UL;
  for( ulong i = 0UL; i < topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( topo->tiles[ i ].name, name ) ) ) {
      FD_TEST( topo->tiles[ i ].kind_id < tile_cnt );
      fd_topo_tile_t const * tile = &topo->tiles[ i ];
      volatile ulong const * tile_metrics = fd_metrics_tile( tile->metrics );
      total += tile_metrics[ metric_idx ];
    }
  }
  return total;
}

static inline ulong
fd_gui_metrics_gossip_total_ingress_bytes( fd_topo_t const * topo, ulong gossvf_tile_cnt ) {
  return fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_UNPARSEABLE) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_LOOPBACK) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_INACTIVE) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_WALLCLOCK) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SIGNATURE) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SHRED_VERSION) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_DESTINATION) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_WALLCLOCK) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_SIGNATURE) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PUSH_NO_VALID_CRDS) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_RESPONSE_NO_VALID_CRDS) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PING_SIGNATURE) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PONG_SIGNATURE) );
}

static inline ulong
fd_gui_metrics_gosip_total_egress_bytes( fd_topo_t const * topo, ulong gossip_tile_cnt ) {
  return fd_gui_metrics_sum_tiles_counter( topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) )
       + fd_gui_metrics_sum_tiles_counter( topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) );
}

#endif /* HEADER_fd_src_disco_gui_fd_gui_metrics_h */
