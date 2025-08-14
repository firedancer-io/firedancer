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

#include <stdio.h> /* printf */
#include <stdlib.h>
#include <unistd.h> /* isatty */
#include <sys/ioctl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
gossip_cmd_topo( config_t * config ) {
  static const ulong tile_to_cpu[ FD_TILE_MAX ] = {0}; /* TODO */

  config->layout.net_tile_count = 1;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topo_tile_t * metric_tile = fd_topob_tile( topo, "metric", "metric", "metric_in", ULONG_MAX, 0, 0 );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  fd_topos_net_tiles( topo, 1UL, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );
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
  gossip_tile->gossip.ip_addr       = config->net.ip_addr;
  gossip_tile->gossip.shred_version = config->consensus.expected_shred_version;
  gossip_tile->gossip.max_entries  = config->tiles.gossip.max_entries;
  gossip_tile->gossip.ports.gossip = config->gossip.port;
  gossip_tile->gossip.boot_timesamp_nanos = fd_log_wallclock();

  fd_topob_wksp( topo, "gossvf" );
  fd_topo_tile_t * gossvf_tile = fd_topob_tile( topo, "gossvf", "gossvf", "metric_in", 0UL, 0, 1 );
  strncpy( gossvf_tile->gossvf.identity_key_path, config->paths.identity_key, sizeof(gossvf_tile->gossvf.identity_key_path) );
  gossvf_tile->gossvf.tcache_depth = 1UL<<22UL;
  gossvf_tile->gossvf.shred_version = 0;
  gossvf_tile->gossvf.allow_private_address = 0;
  gossvf_tile->gossvf.entrypoints_cnt = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ ) {
    gossvf_tile->gossvf.entrypoints[ i ] = config->gossip.resolved_entrypoints[ i ];
  }
  gossvf_tile->gossvf.boot_timesamp_nanos = gossip_tile->gossip.boot_timesamp_nanos;

  fd_topob_wksp( topo, "gossip_net" );
  fd_topob_link( topo, "gossip_net", "gossip_net", config->net.ingress_buffer_size, FD_NET_MTU, 1UL );

  fd_topos_net_rx_link( topo, "net_gossvf", 0UL, config->net.ingress_buffer_size );
  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "net_gossvf",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topos_tile_in_net( topo, "metric_in", "gossip_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_net", 0UL );

  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "gossip" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  fd_topob_tile_uses( topo, gossip_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topos_net_tile_finish( topo, 0UL );

  fd_topob_wksp( topo, "ipecho" );
  fd_topo_tile_t * ipecho_tile = fd_topob_tile( topo, "ipecho", "ipecho", "metric_in", 0UL, 0, 0 );
  ipecho_tile->ipecho.expected_shred_version = config->consensus.expected_shred_version;
  ipecho_tile->ipecho.bind_address = config->net.ip_addr;
  ipecho_tile->ipecho.bind_port = config->gossip.port;
  ipecho_tile->ipecho.entrypoints_cnt = config->gossip.entrypoints_cnt;
  FD_LOG_WARNING(( "IPECHO entrypoints: %lu", ipecho_tile->ipecho.entrypoints_cnt ));
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ ) {
    ipecho_tile->ipecho.entrypoints[ i ] = config->gossip.resolved_entrypoints[ i ];
  }

  fd_topob_wksp( topo, "ipecho_out" );
  fd_topob_link( topo, "ipecho_out", "ipecho_out", 4UL, 0UL, 1UL );
  fd_topob_tile_out( topo, "ipecho", 0UL, "ipecho_out", 0UL );
  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "ipecho_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "ipecho_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp( topo, "gossvf_gossi" );
  fd_topob_link( topo, "gossvf_gossi", "gossvf_gossi", config->net.ingress_buffer_size, sizeof(fd_gossip_view_t)+FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "gossvf", 0UL, "gossvf_gossi", 0UL );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "gossvf_gossi", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp( topo, "gossip_gossv" );
  fd_topob_link( topo, "gossip_gossv", "gossip_gossv", 4096UL, sizeof(fd_gossip_ping_update_t), 1UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_gossv", 0UL );
  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "gossip_gossv", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp( topo, "gossip_out" );
  fd_topob_link( topo, "gossip_out", "gossip_out", 65536UL, sizeof(fd_gossip_update_message_t), 1UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_out", 0UL );
  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "gossip_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", 0UL, 0, 1 );
  strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );
  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_link( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp( topo, "sign_gossip"  );
  fd_topob_link( topo, "sign_gossip", "sign_gossip", 128UL, 64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign", 0UL );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "sign_gossip",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
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

static rx_deltas_t
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
                    gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_LOOPBACK ) ] +
                    gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] +
                    gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PRUNE ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_LOOPBACK ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] -
                    gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ];
  deltas.prune_rx_drop = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_LOOPBACK ) ] +
                         gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] +
                         gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_LOOPBACK ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_WALLCLOCK ) ] -
                         gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PRUNE_SIGNATURE ) ];
  deltas.prune_tx = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PRUNE ) ] -
                    gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_COUNT_PRUNE ) ];
  deltas.prune_tx_bytes = gossip_metrics[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) ] -
                          gossip_prev[ MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) ];
  deltas.prune_rx_bytes = gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) ] +
                          gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_LOOPBACK ) ] +
                          gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_WALLCLOCK ) ] +
                          gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_SIGNATURE ) ] -
                          gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) ] -
                          gossvf_prev[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_DROPPED_PRUNE_LOOPBACK ) ] -
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

  ulong gossvf_tile_idx = fd_topo_find_tile( &config->topo, "gossvf", 0UL );
  FD_TEST( gossvf_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * gossvf_tile = &config->topo.tiles[ gossvf_tile_idx ];

  ulong net_tile_idx = fd_topo_find_tile( &config->topo, "net", 0UL );
  FD_TEST( net_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * net_tile = &config->topo.tiles[ net_tile_idx ];

  volatile ulong * gossip_metrics = fd_metrics_tile( gossip_tile->metrics );
  FD_TEST( gossip_metrics );

  volatile ulong * gossvf_metrics = fd_metrics_tile( gossvf_tile->metrics );
  FD_TEST( gossvf_metrics );

  volatile ulong * net_metrics = fd_metrics_tile( net_tile->metrics );
  FD_TEST( net_metrics );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );

  volatile ulong * net_link = fd_metrics_link_in( gossvf_tile->metrics, 0UL );
  FD_TEST( net_link );

  ulong * gossip_prev = aligned_alloc( 8UL, FD_METRICS_TOTAL_SZ );
  FD_TEST( gossip_prev );
  memset( gossip_prev, 0, FD_METRICS_TOTAL_SZ );

  ulong * gossvf_prev = aligned_alloc( 8UL, FD_METRICS_TOTAL_SZ );
  FD_TEST( gossvf_prev );
  memset( gossvf_prev, 0, FD_METRICS_TOTAL_SZ );

  ulong prev_net_tx1_bytes = 0UL;
  ulong prev_net_rx1_bytes = 0UL;
  ulong prev_net_rx_bytes = 0UL;

  for(;;) {
#define DIFFC(buf, METRIC) fmt_count( buf, gossip_metrics[ MIDX( COUNTER, GOSSIP, METRIC ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, METRIC ) ] )
#define DIFFB(buf, METRIC) fmt_bytes( buf, gossip_metrics[ MIDX( COUNTER, GOSSIP, METRIC ) ] - gossip_prev[ MIDX( COUNTER, GOSSIP, METRIC ) ] )

  char buf1[ 64 ], buf2[ 64 ], buf3[ 64 ], buf4[ 64 ], buf5[ 64 ];

  printf(" Overrun: %lu\n", net_link[ MIDX( COUNTER, LINK, OVERRUN_POLLING_FRAG_COUNT ) ] +
                            net_link[ MIDX( COUNTER, LINK, OVERRUN_READING_FRAG_COUNT ) ] );
  printf(" Net RX bw %s, TX bw %s .. %s %s\n", fmt_bytes( buf1, net_metrics[ MIDX( COUNTER, NET, RX_BYTES_TOTAL ) ] - prev_net_rx1_bytes ),
                                      fmt_bytes( buf2, net_metrics[ MIDX( COUNTER, NET, TX_BYTES_TOTAL ) ] - prev_net_tx1_bytes ),
                                      fmt_count( buf3, net_metrics[ MIDX( COUNTER, NET, RX_FILL_BLOCKED_CNT ) ] ),
                                      fmt_count( buf3, net_metrics[ MIDX( COUNTER, NET, RX_BACKPRESSURE_CNT ) ] ) );

  printf(" Tile RX bw %s\n", fmt_bytes( buf1, net_link[ MIDX( COUNTER, LINK, CONSUMED_SIZE_BYTES ) ] - prev_net_rx_bytes ) );
  prev_net_rx_bytes = net_link[ MIDX( COUNTER, LINK, CONSUMED_SIZE_BYTES ) ];
  prev_net_rx1_bytes = net_metrics[ MIDX( COUNTER, NET, RX_BYTES_TOTAL ) ];
  prev_net_tx1_bytes = net_metrics[ MIDX( COUNTER, NET, TX_BYTES_TOTAL ) ];

  printf(" Pull response drops: %lu/%lu\n", gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ],
                                            gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) ] +
                                            gossvf_metrics[ MIDX( COUNTER, GOSSVF, MESSAGE_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] );

  ulong pull_response_crds_total = gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] +
                                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ] +
                                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) ] +
                                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) ] +
                                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) ] +
                                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) ] +
                                   gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) ];
  ulong prev_pull_response_crds_total = gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] +
                                        gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ] +
                                        gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) ] +
                                        gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) ] +
                                        gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) ] +
                                        gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) ] +
                                        gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) ];
  printf(" Pull response CRDS drops: (%lu/%lu) %.1f %% (%.1f %% duplicate, %.1f %% signature, %.1f %% relayer shred version, %.1f %% origin no contact info, %.1f %% origin shred version %.1f, %% inactive)\n",
          pull_response_crds_total - gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ],
          pull_response_crds_total,
          ((double)pull_response_crds_total - (double)gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] ) / (double)pull_response_crds_total * 100.0,
          (double)gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ] / (double)pull_response_crds_total * 100.0,
          (double)gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) ] / (double)pull_response_crds_total * 100.0,
          (double)gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) ] / (double)pull_response_crds_total * 100.0,
          (double)gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) ] / (double)pull_response_crds_total * 100.0,
          (double)gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) ] / (double)pull_response_crds_total * 100.0,
          (double)gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) ] / (double)pull_response_crds_total * 100.0 );
  printf( " Pull response CRDS inc drops: (%lu/%lu) %1.f %% (%.1f %% duplicate, %.1f %% signature, %.1f %% relayer shred version, %.1f %% origin no contact info, %.1f %% origin shred version, %.1f %% inactive)\n\n",
          (pull_response_crds_total - prev_pull_response_crds_total) - (gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ]),
          pull_response_crds_total - prev_pull_response_crds_total,
          ((double)(pull_response_crds_total - prev_pull_response_crds_total) - (double)(gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_SUCCESS_PULL_RESPONSE ) ]) ) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_DUPLICATE ) ]) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_SIGNATURE ) ]) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_RELAYER_SHRED_VERSION ) ]) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_NO_CONTACT_INFO ) ]) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_ORIGIN_SHRED_VERSION ) ]) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0,
          (double)(gossvf_metrics[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) ] - gossvf_prev[ MIDX( COUNTER, GOSSVF, CRDS_RX_COUNT_DROPPED_PULL_RESPONSE_INACTIVE ) ]) / (double)(pull_response_crds_total - prev_pull_response_crds_total) * 100.0 );

  printf( " +------------------------+--------------+  +------------+--------------+\n" );
  printf( " | CRDS Type              | Count        |  | Ping Type  | Count        |\n" );
  printf( " +------------------------+--------------+  +------------+--------------+\n" );
  printf( " | Contact Info V1        | %s |"        "  | Unpinged   | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_CONTACT_INFO_V1 ) ] ), fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_UNPINGED ) ] ) );
  printf( " | Contact Info V2        | %s |"        "  | Invalid    | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_CONTACT_INFO_V2 ) ] ), fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_INVALID ) ] ) );
  printf( " | Vote                   | %s |"        "  | Valid      | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_VOTE ) ] ),            fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_VALID ) ] ) );
  printf( " | Lowest Slot            | %s |"        "  | Refreshing | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_LOWEST_SLOT ) ] ),     fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, PING_TRACKER_COUNT_VALID_REFRESHING ) ] ) );
  printf( " | Snapshot Hashes        | %s |"        "  +------------+--------------+\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_SNAPSHOT_HASHES ) ] ) );
  printf( " | Accounts Hashes        | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_ACCOUNTS_HASHES ) ] ) );
  printf( " | Inc Snapshot Hashes    | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_INCREMENTAL_SNAPSHOT_HASHES ) ] ) );
  printf( " | Epoch Slots            | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_EPOCH_SLOTS ) ] ) );
  printf( " | Version V1             | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_VERSION_V1 ) ] ) );
  printf( " | Version V2             | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_VERSION_V2 ) ] ) );
  printf( " | Node Instance          | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_NODE_INSTANCE ) ] ) );
  printf( " | Duplicate Shred        | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_DUPLICATE_SHRED ) ] ) );
  printf( " | Restart Last Voted     | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_RESTART_LAST_VOTED_FORK_SLOTS ) ] ) );
  printf( " | Restart Heaviest       | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CRDS_COUNTS_RESTART_HEAVIEST_FORK ) ] ) );
  printf( " +------------------------+--------------+\n\n" );

#define DIFFX(METRIC) gossip_metrics[ MIDX( COUNTER, TILE, METRIC ) ] - gossip_prev[ MIDX( COUNTER, TILE, METRIC ) ]
    ulong hkeep_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING);
    ulong busy_ticks = DIFFX(REGIME_DURATION_NANOS_PROCESSING_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_POSTFRAG );
    ulong caught_up_ticks1 = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG);
    ulong caught_up_ticks2 = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG);
    ulong backpressure_ticks = DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG);
    ulong total_ticks = hkeep_ticks + busy_ticks + caught_up_ticks1 + caught_up_ticks2 + backpressure_ticks;

    printf( " Gossip Hkeep: %.1f %%  Busy: %.1f %%  Idle1: %.1f %%  Idle2: %.1f %%  Backp: %0.1f %%\n",
            (double)hkeep_ticks/(double)total_ticks*100.0,
            (double)busy_ticks/(double)total_ticks*100.0,
            (double)caught_up_ticks1/(double)total_ticks*100.0,
            (double)caught_up_ticks2/(double)total_ticks*100.0,
            (double)backpressure_ticks/(double)total_ticks*100.0 );
#undef DIFFX
#define DIFFX(METRIC) gossvf_metrics[ MIDX( COUNTER, TILE, METRIC ) ] - gossvf_prev[ MIDX( COUNTER, TILE, METRIC ) ]
    ulong gossvf_hkeep_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING);
    ulong gossvf_busy_ticks = DIFFX(REGIME_DURATION_NANOS_PROCESSING_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_POSTFRAG );
    ulong gossvf_caught_up_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG);
    ulong gossvf_backpressure_ticks = DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG);
    ulong gossvf_total_ticks = gossvf_hkeep_ticks + gossvf_busy_ticks + gossvf_caught_up_ticks + gossvf_backpressure_ticks;

    printf( " Gossvf Hkeep: %.1f %%  Busy: %.1f %%  Idle: %.1f %%  Backp: %0.1f %%\n\n",
            (double)gossvf_hkeep_ticks/(double)gossvf_total_ticks*100.0,
            (double)gossvf_busy_ticks/(double)gossvf_total_ticks*100.0,
            (double)gossvf_caught_up_ticks/(double)gossvf_total_ticks*100.0,
            (double)gossvf_backpressure_ticks/(double)gossvf_total_ticks*100.0 );
#undef DIFFX

    printf( " +------------+--------------+--------------+--------------+--------------+\n" );
    printf( " |            | Entries      | Capacity     | Utilization  | Dropped      |\n" );
    printf( " +------------+--------------+--------------+--------------+--------------+\n" );
    printf( " | Table Size | %s | %s | %s | %s |\n", fmt_count( buf1, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_SIZE ) ] ),
                                                     fmt_count( buf2, gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CAPACITY ) ] ),
                                                     fmt_pct( buf3, (double)gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_SIZE ) ] / (double)gossip_metrics[ MIDX( GAUGE, GOSSIP, TABLE_CAPACITY ) ] ),
                                                     "        TODO" );
    printf( " +------------+--------------+--------------+--------------+--------------+\n\n" );

    rx_deltas_t deltas = rx_deltas( gossip_metrics, gossip_prev, gossvf_metrics, gossvf_prev );

    printf( " +--------------------------------------------------------------------------+--------------+\n" );
    printf( " |              | RX count     | RX drops     | TX count     | RX bits      | TX bits      |\n" );
    printf( " +--------------+--------------+--------------+--------------+--------------+--------------+\n" );
    printf( " | Pull Request | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.pull_request_rx ), fmt_count( buf2, deltas.pull_request_rx_drop ),  fmt_count( buf3, deltas.pull_request_tx ),  fmt_bytes( buf4, deltas.pull_request_rx_bytes ),  fmt_bytes( buf5, deltas.pull_request_tx_bytes ) );
    printf( " | Pull Response| %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.pull_response_rx), fmt_count( buf2, deltas.pull_response_rx_drop ), fmt_count( buf3, deltas.pull_response_tx ), fmt_bytes( buf4, deltas.pull_response_rx_bytes ), fmt_bytes( buf5, deltas.pull_response_tx_bytes ) );
    printf( " | Push         | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.push_rx ),         fmt_count( buf2, deltas.push_rx_drop ),          fmt_count( buf3, deltas.push_tx ),          fmt_bytes( buf4, deltas.push_rx_bytes ),          fmt_bytes( buf5, deltas.push_tx_bytes ) );
    printf( " | Prune        | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.prune_rx ),        fmt_count( buf2, deltas.prune_rx_drop ),         fmt_count( buf3, deltas.prune_tx ),         fmt_bytes( buf4, deltas.prune_rx_bytes ),         fmt_bytes( buf5, deltas.prune_tx_bytes ) );
    printf( " | Ping         | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.ping_rx ),         fmt_count( buf2, deltas.ping_rx_drop ),          fmt_count( buf3, deltas.ping_tx ),          fmt_bytes( buf4, deltas.ping_rx_bytes ),          fmt_bytes( buf5, deltas.ping_tx_bytes ) );
    printf( " | Pong         | %s | %s | %s | %s | %s |\n", fmt_count( buf1, deltas.pong_rx ),         fmt_count( buf2, deltas.pong_rx_drop ),          fmt_count( buf3, deltas.pong_tx ),          fmt_bytes( buf4, deltas.pong_rx_bytes ),          fmt_bytes( buf5, deltas.pong_tx_bytes ) );
    printf( " +--------------------------------------------------------------------------+--------------+\n\n" );

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
    for( ulong i=0UL; i<FD_METRICS_TOTAL_SZ/sizeof(ulong); i++ ) gossvf_prev[ i ] = gossvf_metrics[ i ];
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
