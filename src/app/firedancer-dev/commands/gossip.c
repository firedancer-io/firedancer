#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus */
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../discof/gossip/fd_gossip_tile.h"
#include "../../../flamenco/gossip/fd_gossip_private.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../util/net/fd_ip4.h" /* fd_cstr_to_ip4_addr */

#include "core_subtopo.h"
#include "gossip.h"

#include <stdio.h> /* printf */
#include <stdlib.h>
#include <unistd.h> /* isatty */
#include <sys/ioctl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
gossip_cmd_topo( config_t * config ) {
  static ulong tile_to_cpu[ FD_TILE_MAX ] = {0}; /* TODO */

  ulong net_tile_cnt = config->layout.net_tile_count;

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_core_subtopo(   config, tile_to_cpu );
  fd_gossip_subtopo( config, tile_to_cpu );

  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "sign_gossip",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  for( ulong i=0UL; i<net_tile_cnt; i++ ) fd_topos_net_tile_finish( topo, i );
  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

void
fd_gossip_subtopo( config_t * config, ulong tile_to_cpu[ FD_TILE_MAX ] FD_PARAM_UNUSED ) {
  fd_topo_t * topo = &config->topo;

  ulong gossvf_tile_count = config->firedancer.layout.gossvf_tile_count;
  ulong net_tile_cnt = config->layout.net_tile_count;

  static char* const tiles_to_add[] = {
    "gossvf",
    "ipecho",
    "gossip",
  };
  for( int i=0; i<3; ++i) FD_TEST( fd_topo_find_tile( topo, tiles_to_add[i], 0UL ) == ULONG_MAX );

  ulong net_tile_id = fd_topo_find_tile( topo, "net", 0UL );
  if( net_tile_id==ULONG_MAX ) net_tile_id = fd_topo_find_tile( topo, "sock", 0UL );
  if( FD_UNLIKELY( net_tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "net tile not found" ));
  fd_topo_tile_t * net_tile = &topo->tiles[ net_tile_id ];
  net_tile->net.gossip_listen_port = config->gossip.port;

  fd_topob_wksp( topo, "gossip" );
  fd_topo_tile_t * gossip_tile = fd_topob_tile( topo, "gossip", "gossip", "metric_in", 0UL, 0, 1 /* uses_keyswitch */ );
  strncpy( gossip_tile->gossip.identity_key_path, config->paths.identity_key, sizeof(gossip_tile->gossip.identity_key_path) );
  gossip_tile->gossip.entrypoints_cnt        = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ ) {
    gossip_tile->gossip.entrypoints[ i ] = config->gossip.resolved_entrypoints[ i ];
  }
  gossip_tile->gossip.ip_addr              = config->net.ip_addr;
  gossip_tile->gossip.shred_version        = config->consensus.expected_shred_version;
  gossip_tile->gossip.max_entries          = config->tiles.gossip.max_entries;
  gossip_tile->gossip.ports.gossip         = config->gossip.port;
  gossip_tile->gossip.ports.repair         = 0;
  gossip_tile->gossip.ports.tpu            = 0;
  gossip_tile->gossip.ports.tpu_quic       = 0;
  gossip_tile->gossip.ports.tvu            = 0;
  gossip_tile->gossip.ports.tvu_quic       = 0;
  gossip_tile->gossip.boot_timestamp_nanos = config->boot_timestamp_nanos;

  fd_topob_wksp( topo, "gossvf" );
  for( ulong i=0UL; i<gossvf_tile_count; i++ ) {
    fd_topo_tile_t * gossvf_tile = fd_topob_tile( topo, "gossvf", "gossvf", "metric_in", 0UL, 0, 1 );
    strncpy( gossvf_tile->gossvf.identity_key_path, config->paths.identity_key, sizeof(gossvf_tile->gossvf.identity_key_path) );
    gossvf_tile->gossvf.tcache_depth = 1UL<<22UL;
    gossvf_tile->gossvf.shred_version = 0;
    gossvf_tile->gossvf.allow_private_address = 0;
    gossvf_tile->gossvf.entrypoints_cnt = config->gossip.entrypoints_cnt;
    gossvf_tile->gossvf.boot_timestamp_nanos = config->boot_timestamp_nanos;
    for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ ) {
      gossvf_tile->gossvf.entrypoints[ i ] = config->gossip.resolved_entrypoints[ i ];
    }
  }
  for( ulong i=0UL; i<net_tile_cnt; i++ ) {
    fd_topos_net_rx_link( topo, "net_gossvf", i, config->net.ingress_buffer_size );
  }
  for( ulong i=0UL; i<gossvf_tile_count; i++ ) {
    for( ulong j=0UL; j<net_tile_cnt; j++ ) {
      fd_topob_tile_in( topo, "gossvf", i, "metric_in", "net_gossvf", j, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }
  }

  fd_topob_wksp( topo, "gossip_net" );
  fd_topob_link( topo, "gossip_net", "gossip_net", 65536*4UL, FD_NET_MTU, 1UL );
  fd_topos_tile_in_net( topo, "metric_in", "gossip_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_net", 0UL );

  fd_topob_wksp( topo, "ipecho" );
  fd_topo_tile_t * ipecho_tile = fd_topob_tile( topo, "ipecho", "ipecho", "metric_in", 0UL, 0, 0 );
  ipecho_tile->ipecho.expected_shred_version = config->consensus.expected_shred_version;
  ipecho_tile->ipecho.bind_address = config->net.ip_addr;
  ipecho_tile->ipecho.bind_port = config->gossip.port;
  ipecho_tile->ipecho.entrypoints_cnt = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ ) {
    ipecho_tile->ipecho.entrypoints[ i ] = config->gossip.resolved_entrypoints[ i ];
  }

  fd_topob_wksp( topo, "ipecho_out" );
  fd_topob_link( topo, "ipecho_out", "ipecho_out", 4UL, 0UL, 1UL );
  fd_topob_tile_out( topo, "ipecho", 0UL, "ipecho_out", 0UL );

  for( ulong i=0UL; i<gossvf_tile_count; i++ ) {
    fd_topob_tile_in( topo, "gossvf", i, "metric_in", "ipecho_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "ipecho_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp( topo, "gossvf_gossi" );
  fd_topob_wksp( topo, "gossip_gossv" );
  fd_topob_wksp( topo, "gossip_out" );

  fd_topob_link(     topo, "gossip_gossv", "gossip_gossv", 65536UL*4, sizeof(fd_gossip_ping_update_t), 1UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_gossv", 0UL );

  fd_topob_link( topo, "gossip_out", "gossip_out", 65536UL*4, sizeof(fd_gossip_update_message_t), 1UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_out", 0UL );
  for( ulong i=0UL; i<gossvf_tile_count; i++ ) {
    fd_topob_link(     topo, "gossvf_gossi", "gossvf_gossi", 65536UL*4, sizeof(fd_gossip_view_t)+FD_NET_MTU, 1UL );
    fd_topob_tile_out( topo, "gossvf", i, "gossvf_gossi", i );
    fd_topob_tile_in(  topo, "gossip", 0UL, "metric_in", "gossvf_gossi", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    /* Only one link_kind for gossip_out broadcast link */
    fd_topob_tile_in( topo, "gossvf", i, "metric_in", "gossip_gossv", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "gossvf", i, "metric_in", "gossip_out",   0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_link( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp( topo, "sign_gossip"  );
  fd_topob_link( topo, "sign_gossip", "sign_gossip", 128UL, 64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign", 0UL );
}

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_sysctl;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_ethtool_channels;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_ethtool_gro;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_ethtool_loopback;
  args.configure.stages[ stage_idx++ ] = NULL;

  return args;
}

void
gossip_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                 fd_cap_chk_t *   chk,
                 config_t const * config ) {
  args_t c_args = configure_args();
  configure_cmd_perm( &c_args, chk, config );
  run_cmd_perm( NULL, chk, config );
}

static char *
fmt_count( char buf[ static 64 ], ulong count ) {
  char tmp[ 64 ];
  if( FD_LIKELY( count<1000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%lu", count ) );
  else if( FD_LIKELY( count<1000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f K", (double)count/1000.0 ) );
  else if( FD_LIKELY( count<1000000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f M", (double)count/1000000.0 ) );

  FD_TEST( fd_cstr_printf_check( buf, 64UL, NULL, "%12s", tmp ) );
  return buf;
}

static char *
fmt_bytes( char buf[ static 64 ], ulong bytes ) {
  char tmp[ 64 ];
  if( FD_LIKELY( 8UL*bytes<1000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%lu bits", 8UL*bytes ) );
  else if( FD_LIKELY( 8UL*bytes<1000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f Kbit", (double)(8UL*bytes)/1000.0 ) );
  else if( FD_LIKELY( 8UL*bytes<1000000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f Mbit", (double)(8UL*bytes)/1000000.0 ) );
  else FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f Gbit", (double)(8UL*bytes)/1000000000.0 ) );

  FD_TEST( fd_cstr_printf_check( buf, 64UL, NULL, "%12s", tmp ) );
  return buf;
}

static char *
fmt_pct( char buf[ static 64 ], double pct ) {
  char tmp[ 64 ];
  FD_TEST( fd_cstr_printf_check( tmp, 64UL, NULL, "%.1f", pct ) );
  FD_TEST( fd_cstr_printf_check( buf, 64UL, NULL, "%12s", tmp ) );
  return buf;
}

struct rx_deltas {
  ulong pull_request_rx;
  ulong pull_request_rx_drop;
  ulong pull_request_rx_bytes;
  ulong pull_request_tx;
  ulong pull_request_tx_bytes;

  ulong pull_response_rx;
  ulong pull_response_rx_drop;
  ulong pull_response_rx_bytes;
  ulong pull_response_tx;
  ulong pull_response_tx_bytes;

  ulong push_rx;
  ulong push_rx_drop;
  ulong push_rx_bytes;
  ulong push_tx;
  ulong push_tx_bytes;

  ulong prune_rx;
  ulong prune_rx_drop;
  ulong prune_rx_bytes;
  ulong prune_tx;
  ulong prune_tx_bytes;

  ulong ping_rx;
  ulong ping_rx_drop;
  ulong ping_rx_bytes;
  ulong ping_tx;
  ulong ping_tx_bytes;

  ulong pong_rx;
  ulong pong_rx_drop;
  ulong pong_rx_bytes;
  ulong pong_tx;
  ulong pong_tx_bytes;
};

typedef struct rx_deltas rx_deltas_t;

/* Data structures for handling multiple gossvf tiles */
typedef struct {
  ulong                tile_count;
  fd_topo_tile_t **    tiles;
  volatile ulong **    metrics;
  ulong **             prev_metrics;
  volatile ulong **    net_links;
} gossvf_tiles_t;

/* Collect all gossvf tiles from topology */
static gossvf_tiles_t
collect_gossvf_tiles( fd_topo_t * topo ) {
  gossvf_tiles_t tiles = {0};
  tiles.tile_count = fd_topo_tile_name_cnt( topo, "gossvf" );

  if( FD_UNLIKELY( tiles.tile_count == 0UL ) ) {
    FD_LOG_ERR(( "No gossvf tiles found in topology" ));
  }

  /* Allocate arrays for all tiles */
  tiles.tiles = aligned_alloc( 8UL, tiles.tile_count * sizeof(fd_topo_tile_t*) );
  FD_TEST( tiles.tiles );
  tiles.metrics = aligned_alloc( 8UL, tiles.tile_count * sizeof(volatile ulong*) );
  FD_TEST( tiles.metrics );
  tiles.prev_metrics = aligned_alloc( 8UL, tiles.tile_count * sizeof(ulong*) );
  FD_TEST( tiles.prev_metrics );
  tiles.net_links = aligned_alloc( 8UL, tiles.tile_count * sizeof(volatile ulong*) );
  FD_TEST( tiles.net_links );

  /* Find and populate all gossvf tiles */
  for( ulong i = 0UL; i < tiles.tile_count; i++ ) {
    ulong tile_idx = fd_topo_find_tile( topo, "gossvf", i );
    FD_TEST( tile_idx != ULONG_MAX );

    tiles.tiles[i] = &topo->tiles[ tile_idx ];
    tiles.metrics[i] = fd_metrics_tile( tiles.tiles[i]->metrics );
    FD_TEST( tiles.metrics[i] );

    tiles.prev_metrics[i] = aligned_alloc( 8UL, FD_METRICS_TOTAL_SZ );
    FD_TEST( tiles.prev_metrics[i] );
    memset( tiles.prev_metrics[i], 0, FD_METRICS_TOTAL_SZ );

    tiles.net_links[i] = fd_metrics_link_in( tiles.tiles[i]->metrics, 0UL );
    FD_TEST( tiles.net_links[i] );
  }

  return tiles;
}

/* Aggregate specific GOSSVF counter metrics that make sense to sum */
static ulong
aggregate_gossvf_counter( gossvf_tiles_t * tiles, ulong metric_idx ) {
  ulong total = 0UL;
  for( ulong i = 0UL; i < tiles->tile_count; i++ ) {
    total += tiles->metrics[i][metric_idx];
  }
  return total;
}

/* Aggregate specific GOSSVF previous counter metrics */
static ulong
aggregate_gossvf_prev_counter( gossvf_tiles_t * tiles, ulong metric_idx ) {
  ulong total = 0UL;
  for( ulong i = 0UL; i < tiles->tile_count; i++ ) {
    total += tiles->prev_metrics[i][metric_idx];
  }
  return total;
}

/* Enhanced rx_deltas function that works with multiple gossvf tiles */
static rx_deltas_t
rx_deltas_aggregated( volatile ulong * gossip_metrics,
                     ulong *          gossip_prev,
                     gossvf_tiles_t * gossvf_tiles ) {
  rx_deltas_t deltas;

  /* Aggregate pull request metrics across all gossvf tiles */
  ulong pull_request_rx_current =
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_REQUEST ) ) +
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ) +
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ) +
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ) +
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ) +
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ) +
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) );

  ulong pull_request_rx_prev =
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_REQUEST ) ) +
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ) +
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ) +
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ) +
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ) +
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ) +
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) );

  deltas.pull_request_rx = pull_request_rx_current - pull_request_rx_prev;

  /* Continue with other metrics... (truncated for brevity, but same pattern) */
  deltas.pull_request_rx_drop =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) ));

  /* TX metrics come from gossip tile (unchanged) */
  deltas.pull_request_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_REQUEST ) ] -
                           gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_REQUEST ) ];
  deltas.pull_request_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) ] -
                                 gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) ];

  /* RX bytes aggregated across tiles */
  deltas.pull_request_rx_bytes =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_LOOPBACK ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_INACTIVE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_WALLCLOCK ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SIGNATURE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SHRED_VERSION ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_LOOPBACK ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_INACTIVE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_WALLCLOCK ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SIGNATURE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SHRED_VERSION ) ));

  /* For brevity, I'll implement the remaining metrics with the same pattern */
  /* Pull response metrics */
  deltas.pull_response_rx =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ));

  deltas.pull_response_rx_drop =
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ) -
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) );

  deltas.pull_response_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_RESPONSE ) ] -
                            gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_RESPONSE ) ];
  deltas.pull_response_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) ] -
                                  gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) ];
  deltas.pull_response_rx_bytes =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ));

  /* Push metrics */
  deltas.push_rx =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ));

  deltas.push_rx_drop =
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ) -
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) );

  deltas.push_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PUSH ) ] -
                   gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PUSH ) ];
  deltas.push_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) ] -
                         gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) ];
  deltas.push_rx_bytes =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PUSH_NO_VALID_CRDS ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PUSH_NO_VALID_CRDS ) ));

  /* Prune metrics */
  deltas.prune_rx =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ));

  deltas.prune_rx_drop =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ));

  deltas.prune_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PRUNE ) ] -
                    gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PRUNE ) ];
  deltas.prune_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) ] -
                          gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) ];
  deltas.prune_rx_bytes =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_DESTINATION ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_WALLCLOCK ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_SIGNATURE ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_DESTINATION ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_WALLCLOCK ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_SIGNATURE ) ));

  /* Ping metrics */
  deltas.ping_rx =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PING ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PING ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ));

  deltas.ping_rx_drop =
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ) -
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) );

  deltas.ping_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PING ) ] -
                   gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PING ) ];
  deltas.ping_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) ] -
                         gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) ];
  deltas.ping_rx_bytes =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PING_SIGNATURE ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PING_SIGNATURE ) ));

  /* Pong metrics */
  deltas.pong_rx =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PONG ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PONG ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ));

  deltas.pong_rx_drop =
    aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ) -
    aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) );

  deltas.pong_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PONG ) ] -
                   gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PONG ) ];
  deltas.pong_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) ] -
                         gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) ];
  deltas.pong_rx_bytes =
    (aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG ) ) +
     aggregate_gossvf_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PONG_SIGNATURE ) )) -
    (aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG ) ) +
     aggregate_gossvf_prev_counter( gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PONG_SIGNATURE ) ));

  return deltas;
}
/* Display detailed per-tile gossvf metrics */
FD_FN_UNUSED static void
display_gossvf_detailed( gossvf_tiles_t * tiles ) {
  printf("\n=== Detailed Per-Tile Gossvf Metrics ===\n");

  for( ulong i = 0UL; i < tiles->tile_count; i++ ) {
    printf("\n--- Gossvf Tile %lu ---\n", i);

    volatile ulong * metrics = tiles->metrics[i];
    ulong * prev_metrics = tiles->prev_metrics[i];

    /* Performance metrics for this tile */
#define DIFFX(METRIC) metrics[ MIDX( COUNTER, TILE, METRIC ) ] - prev_metrics[ MIDX( COUNTER, TILE, METRIC ) ]
    ulong hkeep_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING) +
                        DIFFX(REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING) +
                        DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING);
    ulong busy_ticks = DIFFX(REGIME_DURATION_NANOS_PROCESSING_PREFRAG) +
                       DIFFX(REGIME_DURATION_NANOS_PROCESSING_POSTFRAG);
    ulong caught_up_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG) +
                            DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG);
    ulong backpressure_ticks = DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG);
    ulong total_ticks = hkeep_ticks + busy_ticks + caught_up_ticks + backpressure_ticks;
#undef DIFFX

    if( total_ticks > 0UL ) {
      printf("  Performance: Hkeep: %.1f %%  Busy: %.1f %%  Idle: %.1f %%  Backp: %.1f %%\n",
             (double)hkeep_ticks/(double)total_ticks*100.0,
             (double)busy_ticks/(double)total_ticks*100.0,
             (double)caught_up_ticks/(double)total_ticks*100.0,
             (double)backpressure_ticks/(double)total_ticks*100.0);
    }

    /* Message counts for this tile */
    printf("  Pull Request RX: %lu (Success: %lu, Drops: %lu)\n",
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_REQUEST ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_REQUEST ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) ]);

    printf("  Pull Response RX: %lu (Success: %lu, Drops: %lu)\n",
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ]);

    printf("  Push RX: %lu (Success: %lu, Drops: %lu)\n",
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ]);

    printf("  Prune RX: %lu (Success: %lu, Drops: %lu)\n",
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ]);

    printf("  Ping RX: %lu (Success: %lu, Drops: %lu)\n",
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PING ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PING ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ]);

    printf("  Pong RX: %lu (Success: %lu, Drops: %lu)\n",
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PONG ) ] +
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PONG ) ],
           metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ]);
  }

  printf("\n=== End Detailed View ===\n");
}


FD_FN_UNUSED static rx_deltas_t
rx_deltas( volatile ulong * gossip_metrics,
           ulong *          gossip_prev,
           volatile ulong * gossvf_metrics,
           ulong *          gossvf_prev ) {
  rx_deltas_t deltas;

  deltas.pull_request_rx = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_REQUEST ) ] +
                           gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] +
                           gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ] +
                           gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ] +
                           gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ] +
                           gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ] +
                           gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) ] -
                           gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_REQUEST ) ] -
                           gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] -
                           gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ] -
                           gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ] -
                           gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ] -
                           gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ] -
                           gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) ];
  deltas.pull_request_rx_drop = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] +
                                gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ] +
                                gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ] +
                                gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ] +
                                gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ] +
                                gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) ] -
                                gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] -
                                gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_LOOPBACK ) ] -
                                gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_INACTIVE ) ] -
                                gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_WALLCLOCK ) ] -
                                gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SIGNATURE ) ] -
                                gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_REQUEST_SHRED_VERSION ) ];
  deltas.pull_request_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_REQUEST ) ] -
                           gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_REQUEST ) ];
  deltas.pull_request_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) ] -
                                 gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) ];
  deltas.pull_request_rx_bytes = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST ) ] +
                                 gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] +
                                 gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_LOOPBACK ) ] +
                                 gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_INACTIVE ) ] +
                                 gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_WALLCLOCK ) ] +
                                 gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SIGNATURE ) ] +
                                 gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SHRED_VERSION ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_LOOPBACK ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_INACTIVE ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_WALLCLOCK ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SIGNATURE ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_REQUEST_SHRED_VERSION ) ];

  deltas.pull_response_rx = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] +
                            gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ] -
                            gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] -
                            gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ];
  deltas.pull_response_rx_drop = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ] -
                                 gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ];
  deltas.pull_response_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_RESPONSE ) ] -
                            gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PULL_RESPONSE ) ];
  deltas.pull_response_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) ] -
                                  gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) ];
  deltas.pull_response_rx_bytes = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE ) ] +
                                  gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ] -
                                  gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE ) ] -
                                  gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ];

  deltas.push_rx = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) ] +
                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ] -
                   gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) ] -
                   gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ];
  deltas.push_rx_drop = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ] -
                        gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) ];
  deltas.push_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PUSH ) ] -
                   gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PUSH ) ];
  deltas.push_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) ] -
                         gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) ];
  deltas.push_rx_bytes = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH ) ] +
                         gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PUSH_NO_VALID_CRDS ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PUSH_NO_VALID_CRDS ) ];

  deltas.prune_rx = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) ] +
                    gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] +
                    gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] +
                    gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ];
  deltas.prune_rx_drop = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] +
                         gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] +
                         gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ];
  deltas.prune_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PRUNE ) ] -
                    gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PRUNE ) ];
  deltas.prune_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) ] -
                          gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) ];
  deltas.prune_rx_bytes = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) ] +
                          gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] +
                          gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_WALLCLOCK ) ] +
                          gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_SIGNATURE ) ] -
                          gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) ] -
                          gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_DESTINATION ) ] -
                          gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_WALLCLOCK ) ] -
                          gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_SIGNATURE ) ];

  deltas.ping_rx = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PING ) ] +
                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ] -
                   gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PING ) ] -
                   gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ];
  deltas.ping_rx_drop = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ] -
                        gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PING_SIGNATURE ) ];
  deltas.ping_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PING ) ] -
                   gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PING ) ];
  deltas.ping_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) ] -
                         gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) ];
  deltas.ping_rx_bytes = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING ) ] +
                         gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PING_SIGNATURE ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PING_SIGNATURE ) ];

  deltas.pong_rx = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PONG ) ] +
                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ] -
                   gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PONG ) ] -
                   gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ];
  deltas.pong_rx_drop = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ] -
                        gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PONG_SIGNATURE ) ];
  deltas.pong_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PONG ) ] -
                   gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PONG ) ];
  deltas.pong_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) ] -
                         gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) ];
  deltas.pong_rx_bytes = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG ) ] +
                         gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PONG_SIGNATURE ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PONG_SIGNATURE ) ];

  return deltas;
}

void
gossip_cmd_fn( args_t *   args,
               config_t * config ) {
  (void)args;

  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  run_firedancer_init( config, 1, 1 );

  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_topo_install_xdp( &config->topo, config->net.bind_address_parsed );
  }
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( &config->topo );

  ulong gossip_tile_idx = fd_topo_find_tile( &config->topo, "gossip", 0UL );
  FD_TEST( gossip_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * gossip_tile = &config->topo.tiles[ gossip_tile_idx ];

  /* Collect all gossvf tiles instead of just the first one */
  gossvf_tiles_t gossvf_tiles = collect_gossvf_tiles( &config->topo );
  printf("Found %lu gossvf tiles\n", gossvf_tiles.tile_count);

  ulong net_tile_idx = fd_topo_find_tile( &config->topo, "net", 0UL );
  FD_TEST( net_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * net_tile = &config->topo.tiles[ net_tile_idx ];

  volatile ulong * gossip_metrics = fd_metrics_tile( gossip_tile->metrics );
  FD_TEST( gossip_metrics );

  volatile ulong * net_metrics = fd_metrics_tile( net_tile->metrics );
  FD_TEST( net_metrics );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );

  /* Use the first gossvf tile's net link for overrun monitoring */
  volatile ulong * net_link = gossvf_tiles.net_links[0];
  FD_TEST( net_link );

  ulong * gossip_prev = aligned_alloc( 8UL, FD_METRICS_TOTAL_SZ );
  FD_TEST( gossip_prev );
  memset( gossip_prev, 0, FD_METRICS_TOTAL_SZ );

  ulong prev_net_tx1_bytes = 0UL;
  ulong prev_net_rx1_bytes = 0UL;
  ulong prev_net_rx_bytes = 0UL;

  for(;;) {
#define DIFFC(buf, METRIC) fmt_count( buf, gossip_metrics[ MIDX( COUNTER, GOSSIP, METRIC ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, METRIC ) ] )
#define DIFFB(buf, METRIC) fmt_bytes( buf, gossip_metrics[ MIDX( COUNTER, GOSSIP, METRIC ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, METRIC ) ] )

  char buf1[ 64 ], buf2[ 64 ], buf3[ 64 ], buf4[ 64 ], buf5[ 64 ];

  ulong total_overrun = 0UL;
  for( ulong i = 0UL; i < gossvf_tiles.tile_count; i++ ) {
    volatile ulong * net_vf_link = gossvf_tiles.net_links[i];

    ulong overrun_count = net_vf_link[ MIDX( COUNTER, LINK, OVERRUN_POLLING_FRAG_COUNT ) ] +
                            net_vf_link[ MIDX( COUNTER, LINK, OVERRUN_READING_FRAG_COUNT ) ];
    // printf(" Vf Tile %lu: Overrun: %s\n", i, fmt_count( buf1, overrun_count ) );
    total_overrun += overrun_count;
  }
  printf(" Total Overrun: %s\n", fmt_count( buf1, total_overrun ) );
  printf(" Total ping tracked: %lu\n", gossip_metrics[ MIDX( COUNTER, GOSSIP, PING_TRACKED_COUNT ) ] );

  printf(" Net RX bw %s, TX bw %s .. %s %s\n", fmt_bytes( buf1, net_metrics[ MIDX( COUNTER, NET, RX_BYTES_TOTAL ) ] - prev_net_rx1_bytes ),
                                      fmt_bytes( buf2, net_metrics[ MIDX( COUNTER, NET, TX_BYTES_TOTAL ) ] - prev_net_tx1_bytes ),
                                      fmt_count( buf3, net_metrics[ MIDX( COUNTER, NET, RX_FILL_BLOCKED_CNT ) ] ),
                                      fmt_count( buf3, net_metrics[ MIDX( COUNTER, NET, RX_BACKPRESSURE_CNT ) ] ) );

  printf(" Single Tile RX bw %s\n", fmt_bytes( buf1, net_link[ MIDX( COUNTER, LINK, CONSUMED_SIZE_BYTES ) ] - prev_net_rx_bytes ) );
  prev_net_rx_bytes = net_link[ MIDX( COUNTER, LINK, CONSUMED_SIZE_BYTES ) ];
  prev_net_rx1_bytes = net_metrics[ MIDX( COUNTER, NET, RX_BYTES_TOTAL ) ];
  prev_net_tx1_bytes = net_metrics[ MIDX( COUNTER, NET, TX_BYTES_TOTAL ) ];

  ulong pull_response_drops = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) );
  ulong pull_response_success = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) );
  printf(" Pull response drops: %lu/%lu\n", pull_response_drops, pull_response_drops + pull_response_success);

  ulong crds_success = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) );
  ulong crds_duplicate = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) );
  ulong crds_signature = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) );
  ulong crds_relayer_shred = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) );
  ulong crds_origin_no_contact = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) );
  ulong crds_origin_shred = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) );
  ulong crds_inactive = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) );

  ulong pull_response_crds_total = crds_success + crds_duplicate + crds_signature + crds_relayer_shred + crds_origin_no_contact + crds_origin_shred + crds_inactive;

  ulong prev_crds_success = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) );
  ulong prev_crds_duplicate = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) );
  ulong prev_crds_signature = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) );
  ulong prev_crds_relayer_shred = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) );
  ulong prev_crds_origin_no_contact = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) );
  ulong prev_crds_origin_shred = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) );
  ulong prev_crds_inactive = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) );

  ulong prev_pull_response_crds_total = prev_crds_success + prev_crds_duplicate + prev_crds_signature + prev_crds_relayer_shred + prev_crds_origin_no_contact + prev_crds_origin_shred + prev_crds_inactive;

  printf(" Pull response CRDS drops: (%lu/%lu) %.1f %% (%.1f %% duplicate, %.1f %% signature, %.1f %% relayer shred version, %.1f %% origin no contact info, %.1f %% origin shred version %.1f, %% inactive)\n",
          pull_response_crds_total - crds_success,
          pull_response_crds_total,
          ((double)pull_response_crds_total - (double)crds_success ) / (double)pull_response_crds_total * 100.0,
          (double)crds_duplicate / (double)pull_response_crds_total * 100.0,
          (double)crds_signature / (double)pull_response_crds_total * 100.0,
          (double)crds_relayer_shred / (double)pull_response_crds_total * 100.0,
          (double)crds_origin_no_contact / (double)pull_response_crds_total * 100.0,
          (double)crds_origin_shred / (double)pull_response_crds_total * 100.0,
          (double)crds_inactive / (double)pull_response_crds_total * 100.0 );


  printf( " Pull response CRDS inc drops: (%lu/%lu) %1.f %% (%.1f %% duplicate, %.1f %% signature, %.1f %% relayer shred version, %.1f %% origin no contact info, %.1f %% origin shred version, %.1f %% inactive)\n\n",
          (pull_response_crds_total - prev_pull_response_crds_total) - (crds_success - prev_crds_success),
          pull_response_crds_total - prev_pull_response_crds_total,
          ((double)(pull_response_crds_total - prev_pull_response_crds_total) - (double)(crds_success - prev_crds_success) ) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(crds_duplicate - prev_crds_duplicate) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(crds_signature - prev_crds_signature) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(crds_relayer_shred - prev_crds_relayer_shred) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(crds_origin_no_contact - prev_crds_origin_no_contact) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(crds_origin_shred - prev_crds_origin_shred) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(crds_inactive - prev_crds_inactive) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0 );

 ulong pull_response_insertion_total = gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ] +
                                       gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_STALE ) ] +
                                       gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_WALLCLOCK ) ] +
                                       gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ];
 ulong prev_pull_response_insertion_total = gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ] +
                                            gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_STALE ) ] +
                                            gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_WALLCLOCK ) ] +
                                            gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ];

 printf(" Pull response CRDS insertion drops: (%lu/%lu) %.1f %% (%.1f %% no override, %.1f %% old, %.1f %% hash duplicate)\n",
         pull_response_insertion_total - gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ],
         pull_response_insertion_total,
         ((double)pull_response_insertion_total - (double)gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ] ) / (double)pull_response_insertion_total * 100.0,
         (double)gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_STALE ) ] / (double)pull_response_insertion_total * 100.0,
         (double)gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_WALLCLOCK ) ] / (double)pull_response_insertion_total * 100.0,
         (double)gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ] / (double)pull_response_insertion_total * 100.0 );
 printf( " Pull response CRDS insertion inc drops: (%lu/%lu) %.1f %% (%.1f %% no override, %.1f %% old, %.1f %% hash duplicate)\n\n",
         (pull_response_insertion_total - prev_pull_response_insertion_total) - (gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ]),
         pull_response_insertion_total - prev_pull_response_insertion_total,
         ((double)(pull_response_insertion_total - prev_pull_response_insertion_total) - (double)(gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PULL_RESPONSE ) ]) ) / (double)(pull_response_insertion_total - prev_pull_response_insertion_total) * 100.0,
         (double)(gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_STALE ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_STALE ) ]) / (double)(pull_response_insertion_total - prev_pull_response_insertion_total) * 100.0,
         (double)(gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_WALLCLOCK ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_WALLCLOCK ) ]) / (double)(pull_response_insertion_total - prev_pull_response_insertion_total) * 100.0,
         (double)(gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ]) / (double)(pull_response_insertion_total - prev_pull_response_insertion_total) * 100.0 );

 /* Push message statistics - similar to pull response pattern */
 ulong push_drops = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PUSH_NO_VALID_CRDS ) );
 ulong push_success = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PUSH ) );
 printf(" Push drops: %lu/%lu\n", push_drops, push_drops + push_success);

 ulong push_crds_success = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PUSH ) );
 ulong push_crds_signature = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_SIGNATURE ) );
 ulong push_crds_relayer_no_contact = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_RELAYER_NO_CONTACT_INFO ) );
 ulong push_crds_relayer_shred = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_RELAYER_SHRED_VERSION ) );
 ulong push_crds_origin_no_contact = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_ORIGIN_NO_CONTACT_INFO ) );
 ulong push_crds_origin_shred = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_ORIGIN_SHRED_VERSION ) );
 ulong push_crds_inactive = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_INACTIVE ) );
 ulong push_crds_wallclock = aggregate_gossvf_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_WALLCLOCK ) );

 ulong push_crds_total = push_crds_success + push_crds_signature + push_crds_relayer_no_contact + push_crds_relayer_shred + push_crds_origin_no_contact + push_crds_origin_shred + push_crds_inactive + push_crds_wallclock;

 ulong prev_push_crds_success = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PUSH ) );
 ulong prev_push_crds_signature = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_SIGNATURE ) );
 ulong prev_push_crds_relayer_no_contact = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_RELAYER_NO_CONTACT_INFO ) );
 ulong prev_push_crds_relayer_shred = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_RELAYER_SHRED_VERSION ) );
 ulong prev_push_crds_origin_no_contact = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_ORIGIN_NO_CONTACT_INFO ) );
 ulong prev_push_crds_origin_shred = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_ORIGIN_SHRED_VERSION ) );
 ulong prev_push_crds_inactive = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_INACTIVE ) );
 ulong prev_push_crds_wallclock = aggregate_gossvf_prev_counter( &gossvf_tiles, MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PUSH_WALLCLOCK ) );

 ulong prev_push_crds_total = prev_push_crds_success + prev_push_crds_signature + prev_push_crds_relayer_no_contact + prev_push_crds_relayer_shred + prev_push_crds_origin_no_contact + prev_push_crds_origin_shred + prev_push_crds_inactive + prev_push_crds_wallclock;

 printf(" Push CRDS drops: (%lu/%lu) %.1f %% (%.1f %% signature, %.1f %% relayer no contact info, %.1f %% relayer shred version, %.1f %% origin no contact info, %.1f %% origin shred version, %.1f %% inactive, %.1f %% wallclock)\n",
         push_crds_total - push_crds_success,
         push_crds_total,
         ((double)push_crds_total - (double)push_crds_success ) / (double)push_crds_total * 100.0,
         (double)push_crds_signature / (double)push_crds_total * 100.0,
         (double)push_crds_relayer_no_contact / (double)push_crds_total * 100.0,
         (double)push_crds_relayer_shred / (double)push_crds_total * 100.0,
         (double)push_crds_origin_no_contact / (double)push_crds_total * 100.0,
         (double)push_crds_origin_shred / (double)push_crds_total * 100.0,
         (double)push_crds_inactive / (double)push_crds_total * 100.0,
         (double)push_crds_wallclock / (double)push_crds_total * 100.0 );


 printf( " Push CRDS inc drops: (%lu/%lu) %.1f %% (%.1f %% signature, %.1f %% relayer no contact info, %.1f %% relayer shred version, %.1f %% origin no contact info, %.1f %% origin shred version, %.1f %% inactive, %.1f %% wallclock)\n\n",
         (push_crds_total - prev_push_crds_total) - (push_crds_success - prev_push_crds_success),
         push_crds_total - prev_push_crds_total,
         ((double)(push_crds_total - prev_push_crds_total) - (double)(push_crds_success - prev_push_crds_success) ) / (double)(push_crds_total - prev_push_crds_total) * 100.0,
         (double)(push_crds_signature - prev_push_crds_signature) / (double)(push_crds_total - prev_push_crds_total) * 100.0,
         (double)(push_crds_relayer_no_contact - prev_push_crds_relayer_no_contact) / (double)(push_crds_total - prev_push_crds_total) * 100.0,
         (double)(push_crds_relayer_shred - prev_push_crds_relayer_shred) / (double)(push_crds_total - prev_push_crds_total) * 100.0,
         (double)(push_crds_origin_no_contact - prev_push_crds_origin_no_contact) / (double)(push_crds_total - prev_push_crds_total) * 100.0,
         (double)(push_crds_origin_shred - prev_push_crds_origin_shred) / (double)(push_crds_total - prev_push_crds_total) * 100.0,
         (double)(push_crds_inactive - prev_push_crds_inactive) / (double)(push_crds_total - prev_push_crds_total) * 100.0,
         (double)(push_crds_wallclock - prev_push_crds_wallclock) / (double)(push_crds_total - prev_push_crds_total) * 100.0 );

 ulong push_insertion_total = gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ] +
                              gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_STALE ) ] +
                              gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_DUPLICATE ) ];
 ulong prev_push_insertion_total = gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ] +
                                   gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_STALE ) ] +
                                   gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_DUPLICATE ) ];

 printf(" Push CRDS insertion drops: (%lu/%lu) %.1f %% (%.1f %% no override, %.1f %% hash duplicate)\n",
         push_insertion_total - gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ],
         push_insertion_total,
         ((double)push_insertion_total - (double)gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ] ) / (double)push_insertion_total * 100.0,
         (double)gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_STALE ) ] / (double)push_insertion_total * 100.0,
         (double)gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_DUPLICATE ) ] / (double)push_insertion_total * 100.0 );
 printf( " Push CRDS insertion inc drops: (%lu/%lu) %.1f %% (%.1f %% no override, %.1f %% hash duplicate)\n\n",
         (push_insertion_total - prev_push_insertion_total) - (gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ]),
         push_insertion_total - prev_push_insertion_total,
         ((double)(push_insertion_total - prev_push_insertion_total) - (double)(gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_UPSERTED_PUSH ) ]) ) / (double)(push_insertion_total - prev_push_insertion_total) * 100.0,
         (double)(gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_STALE ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_STALE ) ]) / (double)(push_insertion_total - prev_push_insertion_total) * 100.0,
         (double)(gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_DUPLICATE ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, CRDS_RX_COUNT_DROPPED_PUSH_DUPLICATE ) ]) / (double)(push_insertion_total - prev_push_insertion_total) * 100.0 );

  printf( " +------------------------+--------------+  +------------+--------------+\n" );
  printf( " | CRDS Type              | Count        |  | Ping Type  | Count        |\n" );
  printf( " +------------------------+--------------+  +------------+--------------+\n" );
  printf( " | Contact Info V1        | %s |"        "  | Unpinged   | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V1 ) ] ), fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_UNPINGED ) ] ) );
  printf( " | Contact Info V2        | %s |"        "  | Invalid    | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V2 ) ] ), fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_INVALID ) ] ) );
  printf( " | Vote                   | %s |"        "  | Valid      | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_VOTE ) ] ),            fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_VALID ) ] ) );
  printf( " | Lowest Slot            | %s |"        "  | Refreshing | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_LOWEST_SLOT ) ] ),     fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_VALID_REFRESHING ) ] ) );
  printf( " | Snapshot Hashes        | %s |"        "  +------------+--------------+\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_SNAPSHOT_HASHES ) ] ) );
  printf( " | Accounts Hashes        | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_ACCOUNTS_HASHES ) ] ) );
  printf( " | Inc Snapshot Hashes    | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_INCREMENTAL_SNAPSHOT_HASHES ) ] ) );
  printf( " | Epoch Slots            | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_EPOCH_SLOTS ) ] ) );
  printf( " | Version V1             | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_VERSION_V1 ) ] ) );
  printf( " | Version V2             | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_VERSION_V2 ) ] ) );
  printf( " | Node Instance          | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_NODE_INSTANCE ) ] ) );
  printf( " | Duplicate Shred        | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_DUPLICATE_SHRED ) ] ) );
  printf( " | Restart Last Voted     | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_RESTART_LAST_VOTED_FORK_SLOTS ) ] ) );
  printf( " | Restart Heaviest       | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_RESTART_HEAVIEST_FORK ) ] ) );
  printf( " +------------------------+--------------+\n\n" );

#define DIFFX(METRIC) gossip_metrics[ MIDX( COUNTER, TILE, METRIC ) ] - gossip_prev[ MIDX( COUNTER, TILE, METRIC ) ]
    ulong hkeep_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING);
    ulong busy_ticks = DIFFX(REGIME_DURATION_NANOS_PROCESSING_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_POSTFRAG ) + DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG);
    ulong caught_up_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG);
    ulong backpressure_ticks = DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG);
    ulong total_ticks = hkeep_ticks + busy_ticks + caught_up_ticks + backpressure_ticks;

    printf( " Gossip Hkeep: %.1f %%  Busy: %.1f %%  Idle: %.1f %%  Backp: %0.1f %%\n",
            (double)hkeep_ticks/(double)total_ticks*100.0,
            (double)busy_ticks/(double)total_ticks*100.0,
            (double)caught_up_ticks/(double)total_ticks*100.0,
            (double)backpressure_ticks/(double)total_ticks*100.0 );
#undef DIFFX
    /* Aggregate gossvf performance metrics across all tiles */
    ulong gossvf_hkeep_ticks = 0UL, gossvf_busy_ticks = 0UL, gossvf_caught_up_ticks = 0UL, gossvf_backpressure_ticks = 0UL;

    for( ulong i = 0UL; i < gossvf_tiles.tile_count; i++ ) {
      volatile ulong * metrics = gossvf_tiles.metrics[i];
      ulong * prev_metrics = gossvf_tiles.prev_metrics[i];

#define DIFFX(METRIC) metrics[ MIDX( COUNTER, TILE, METRIC ) ] - prev_metrics[ MIDX( COUNTER, TILE, METRIC ) ]
      gossvf_hkeep_ticks += DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING);
      gossvf_busy_ticks += DIFFX(REGIME_DURATION_NANOS_PROCESSING_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_POSTFRAG );
      gossvf_caught_up_ticks += DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG);
      gossvf_backpressure_ticks += DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG);
#undef DIFFX
    }

    ulong gossvf_total_ticks = gossvf_hkeep_ticks + gossvf_busy_ticks + gossvf_caught_up_ticks + gossvf_backpressure_ticks;

    printf( " Gossvf Hkeep: %.1f %%  Busy: %.1f %%  Idle: %.1f %%  Backp: %0.1f %% (%lu tiles)\n\n",
            gossvf_total_ticks > 0UL ? (double)gossvf_hkeep_ticks/(double)gossvf_total_ticks*100.0 : 0.0,
            gossvf_total_ticks > 0UL ? (double)gossvf_busy_ticks/(double)gossvf_total_ticks*100.0 : 0.0,
            gossvf_total_ticks > 0UL ? (double)gossvf_caught_up_ticks/(double)gossvf_total_ticks*100.0 : 0.0,
            gossvf_total_ticks > 0UL ? (double)gossvf_backpressure_ticks/(double)gossvf_total_ticks*100.0 : 0.0,
            gossvf_tiles.tile_count );

    // display_gossvf_detailed( &gossvf_tiles );

    ulong total_crds = 0UL;
    for( ulong i=0UL; i<FD_METRICS_ENUM_CRDS_VALUE_CNT; i++ ) total_crds += gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT )+i ];

    printf( " +--------------+--------------+--------------+--------------+--------------+--------------+\n" );
    printf( " |              | Entries      | Capacity     | Utilization  | Evicted      | Expired      |\n" );
    printf( " +--------------+--------------+--------------+--------------+--------------+--------------+\n" );
    printf( " | Table Size   | %s | %s | %s | %s | %s |\n",
      fmt_count( buf1, total_crds ),
      fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_CAPACITY ) ] ),
      fmt_pct( buf3, (double)total_crds / (double)gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_CAPACITY ) ] ),
      fmt_count( buf4, gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_EVICTED_COUNT ) ] ),
      fmt_count( buf5, gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_EXPIRED_COUNT ) ] ) );
    printf( " | Contact Info | %s | %s | %s | %s |          n/a |\n",
      fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V2 ) ] ),
      fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_PEER_CAPACITY ) ] ),
      fmt_pct( buf3, (double)gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V2 ) ] / (double)gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_PEER_CAPACITY ) ] ),
      fmt_count( buf4, gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_PEER_EVICTED_COUNT ) ] ) );
    printf( " | Purged       | %s | %s | %s | %s | %s |\n",
      fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_PURGED_COUNT ) ] ),
      fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_PURGED_CAPACITY ) ] ),
      fmt_pct( buf3, (double)gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_PURGED_COUNT ) ] / (double)gossip_metrics[ MIDX( GAUGE, GOSSIP, CRDS_PURGED_CAPACITY ) ] ),
      fmt_count( buf4, gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_PURGED_EVICTED_COUNT ) ] ),
      fmt_count( buf5, gossip_metrics[ MIDX( COUNTER, GOSSIP, CRDS_PURGED_EXPIRED_COUNT ) ] ) );
    printf( " +--------------+--------------+--------------+--------------+--------------+--------------+\n\n" );

    rx_deltas_t deltas = rx_deltas_aggregated( gossip_metrics, gossip_prev, &gossvf_tiles );

    printf( " +--------------------------------------------------------------------------+--------------+\n" );
    printf( " |              | RX count     | RX drops     | TX count     | RX bits      | TX bits      |\n" );
    printf( " +--------------+--------------+--------------+--------------+--------------+--------------+\n" );
    printf( " | Pull Request | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.pull_request_rx ), fmt_count( buf2, deltas.pull_request_rx_drop ),  fmt_count( buf3, deltas.pull_request_tx ),  fmt_bytes( buf4, deltas.pull_request_rx_bytes ),  fmt_bytes( buf5, deltas.pull_request_tx_bytes ) );
    printf( " | Pull Response| %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.pull_response_rx), fmt_count( buf2, deltas.pull_response_rx_drop ), fmt_count( buf3, deltas.pull_response_tx ), fmt_bytes( buf4, deltas.pull_response_rx_bytes ), fmt_bytes( buf5, deltas.pull_response_tx_bytes ) );
    printf( " | Push         | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.push_rx ),         fmt_count( buf2, deltas.push_rx_drop ),          fmt_count( buf3, deltas.push_tx ),          fmt_bytes( buf4, deltas.push_rx_bytes ),          fmt_bytes( buf5, deltas.push_tx_bytes ) );
    printf( " | Prune        | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.prune_rx ),        fmt_count( buf2, deltas.prune_rx_drop ),         fmt_count( buf3, deltas.prune_tx ),         fmt_bytes( buf4, deltas.prune_rx_bytes ),         fmt_bytes( buf5, deltas.prune_tx_bytes ) );
    printf( " | Ping         | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.ping_rx ),         fmt_count( buf2, deltas.ping_rx_drop ),          fmt_count( buf3, deltas.ping_tx ),          fmt_bytes( buf4, deltas.ping_rx_bytes ),          fmt_bytes( buf5, deltas.ping_tx_bytes ) );
    printf( " | Pong         | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.pong_rx ),         fmt_count( buf2, deltas.pong_rx_drop ),          fmt_count( buf3, deltas.pong_tx ),          fmt_bytes( buf4, deltas.pong_rx_bytes ),          fmt_bytes( buf5, deltas.pong_tx_bytes ) );
    printf( " +--------------+--------------+--------------+--------------+--------------+--------------+\n\n" );

    // printf( " +--------------------------------------------------------------------------+\n" );
    // printf( " |              | RX count     | TX count     | RX bytes     | TX bytes     |\n" );
    // printf( " +--------------+--------------+--------------+--------------+--------------+\n" );
    // printf( " | Pull Request | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PULL_REQUEST ), DIFFC( buf2, MESSAGE_TX_COUNT_PULL_REQUEST ), DIFFB( buf3, MESSAGE_RX_BYTES_PULL_REQUEST ), DIFFB( buf4, MESSAGE_TX_BYTES_PULL_REQUEST ) );
    // printf( " | Pull Response| %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PULL_RESPONSE ), DIFFC( buf2, MESSAGE_TX_COUNT_PULL_RESPONSE ), DIFFB( buf3, MESSAGE_RX_BYTES_PULL_RESPONSE ), DIFFB( buf4, MESSAGE_TX_BYTES_PULL_RESPONSE ) );
    // printf( " | Push         | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PUSH ), DIFFC( buf2, MESSAGE_TX_COUNT_PUSH ), DIFFB( buf3, MESSAGE_RX_BYTES_PUSH ), DIFFB( buf4, MESSAGE_TX_BYTES_PUSH ) );
    // printf( " | Prune        | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PRUNE ), DIFFC( buf2, MESSAGE_TX_COUNT_PRUNE ), DIFFB( buf3, MESSAGE_RX_BYTES_PRUNE ), DIFFB( buf4, MESSAGE_TX_BYTES_PRUNE ) );
    // printf( " | Ping         | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PING ), DIFFC( buf2, MESSAGE_TX_COUNT_PING ), DIFFB( buf3, MESSAGE_RX_BYTES_PING ), DIFFB( buf4, MESSAGE_TX_BYTES_PING ) );
    // printf( " | Pong         | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PONG ), DIFFC( buf2, MESSAGE_TX_COUNT_PONG ), DIFFB( buf3, MESSAGE_RX_BYTES_PONG ), DIFFB( buf4, MESSAGE_TX_BYTES_PONG ) );
    // printf( " +--------------------------------------------------------------------------+\n\n" );

    for( ulong i=0UL; i<FD_METRICS_TOTAL_SZ/sizeof(ulong); i++ ) gossip_prev[ i ] = gossip_metrics[ i ];

    /* Update previous metrics for all gossvf tiles */
    for( ulong tile_idx = 0UL; tile_idx < gossvf_tiles.tile_count; tile_idx++ ) {
      for( ulong i=0UL; i<FD_METRICS_TOTAL_SZ/sizeof(ulong); i++ ) {
        gossvf_tiles.prev_metrics[tile_idx][ i ] = gossvf_tiles.metrics[tile_idx][ i ];
      }
    }
    sleep( 1 );
  }
}

action_t fd_action_gossip = {
  .name = "gossip",
  .args = NULL,
  .fn   = gossip_cmd_fn,
  .perm = gossip_cmd_perm,
  .topo = gossip_cmd_topo,
};
