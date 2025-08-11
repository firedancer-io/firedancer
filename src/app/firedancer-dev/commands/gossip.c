#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus */
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */
#include "../../../disco/metrics/fd_metrics.h"
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

  gossip_tile->gossip.ip_addr                    = config->net.ip_addr;
  gossip_tile->gossip.has_expected_shred_version = !!config->consensus.expected_shred_version;
  gossip_tile->gossip.expected_shred_version     = config->consensus.expected_shred_version;

  gossip_tile->gossip.max_entries                = config->tiles.gossip.max_entries;
  gossip_tile->gossip.ports.gossip               = config->gossip.port;

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", 0UL, 0, 1 );
  strncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );
  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_link( topo, "gossip_sign", "gossip_sign", 128UL, 2048UL, 1UL );
  fd_topob_tile_in( topo, "sign", 0UL, "metric_in", "gossip_sign", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_wksp( topo, "sign_gossip"  );
  fd_topob_link( topo, "sign_gossip", "sign_gossip", 128UL,   64UL, 1UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_gossip", 0UL );

  fd_topob_wksp( topo, "gossip_net" );
  fd_topob_link( topo, "gossip_net", "gossip_net", config->net.ingress_buffer_size, FD_NET_MTU, 1UL );

  fd_topos_net_rx_link( topo, "net_gossip", 0UL, config->net.ingress_buffer_size );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "net_gossip",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "sign_gossip",  0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topos_tile_in_net( topo, "metric_in", "gossip_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_net", 0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign", 0UL );

  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "gossip" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  fd_topob_tile_uses( topo, gossip_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topos_net_tile_finish( topo, 0UL );

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

void
gossip_cmd_fn( args_t *   args,
               config_t * config ) {
  (void)args;

  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  run_firedancer_init( config, 1 );

  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_topo_install_xdp( &config->topo, config->net.bind_address_parsed );
  }
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( &config->topo );

  ulong gossip_tile_idx = fd_topo_find_tile( &config->topo, "gossip", 0UL );
  FD_TEST( gossip_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * gossip_tile = &config->topo.tiles[ gossip_tile_idx ];

  volatile ulong * metrics = fd_metrics_tile( gossip_tile->metrics );
  FD_TEST( metrics );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );

  volatile ulong * net_link = fd_metrics_link_in( gossip_tile->metrics, 0UL );
  FD_TEST( net_link );

  ulong * prev = aligned_alloc( 8UL, FD_METRICS_TOTAL_SZ );
  FD_TEST( prev );
  memset( prev, 0, FD_METRICS_TOTAL_SZ );

  for(;;) {
#define DIFFC(buf, METRIC) fmt_count( buf, metrics[ MIDX( COUNTER, GOSSIP, METRIC ) ] - prev[ MIDX( COUNTER, GOSSIP, METRIC ) ] )
#define DIFFB(buf, METRIC) fmt_bytes( buf, metrics[ MIDX( COUNTER, GOSSIP, METRIC ) ] - prev[ MIDX( COUNTER, GOSSIP, METRIC ) ] )

    char buf1[ 64 ], buf2[ 64 ], buf3[ 64 ], buf4[ 64 ];

    printf(" Overrun: %lu\n", net_link[ MIDX( COUNTER, LINK, OVERRUN_POLLING_FRAG_COUNT ) ] + 
                              net_link[ MIDX( COUNTER, LINK, OVERRUN_READING_FRAG_COUNT ) ] );

#define DIFFX(METRIC) metrics[ MIDX( COUNTER, TILE, METRIC ) ] - prev[ MIDX( COUNTER, TILE, METRIC ) ]
    ulong hkeep_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING) + DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING);
    ulong busy_ticks = DIFFX(REGIME_DURATION_NANOS_PROCESSING_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_PROCESSING_POSTFRAG );
    ulong caught_up_ticks = DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG) + DIFFX(REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG);
    ulong backpressure_ticks = DIFFX(REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG);
    ulong total_ticks = hkeep_ticks + busy_ticks + caught_up_ticks + backpressure_ticks;

    printf( " Hkeep: %.1f %%  Busy: %.1f %%  Idle: %.1f %%  Backp: %0.1f %%\n\n",
            (double)hkeep_ticks/(double)total_ticks*100.0,
            (double)busy_ticks/(double)total_ticks*100.0,
            (double)caught_up_ticks/(double)total_ticks*100.0,
            (double)backpressure_ticks/(double)total_ticks*100.0 );

    printf( " +------------+--------------+--------------+--------------+--------------+\n" );
    printf( " |            | Entries      | Capacity     | Utilization  | Dropped      |\n" );
    printf( " +------------+--------------+--------------+--------------+--------------+\n" );
    printf( " | Table Size | %s | %s | %s | %s |\n", fmt_count( buf1, metrics[ MIDX( GAUGE, GOSSIP, TABLE_SIZE ) ] ),
                                                     fmt_count( buf2, metrics[ MIDX( GAUGE, GOSSIP, TABLE_CAPACITY ) ] ),
                                                     fmt_pct( buf3, (double)metrics[ MIDX( GAUGE, GOSSIP, TABLE_SIZE ) ] / (double)metrics[ MIDX( GAUGE, GOSSIP, TABLE_CAPACITY ) ] ),
                                                     "        TODO" );
    printf( " +------------+--------------+--------------+--------------+--------------+\n\n" );

    printf( " +--------------------------------------------------------------------------+\n" );
    printf( " |              | RX count     | TX count     | RX bytes     | TX bytes     |\n" );
    printf( " +--------------+--------------+--------------+--------------+--------------+\n" );
    printf( " | Pull Request | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PULL_REQUEST ), DIFFC( buf2, MESSAGE_TX_COUNT_PULL_REQUEST ), DIFFB( buf3, MESSAGE_RX_BYTES_PULL_REQUEST ), DIFFB( buf4, MESSAGE_TX_BYTES_PULL_REQUEST ) );
    printf( " | Pull Response| %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PULL_RESPONSE ), DIFFC( buf2, MESSAGE_TX_COUNT_PULL_RESPONSE ), DIFFB( buf3, MESSAGE_RX_BYTES_PULL_RESPONSE ), DIFFB( buf4, MESSAGE_TX_BYTES_PULL_RESPONSE ) );
    printf( " | Push         | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PUSH ), DIFFC( buf2, MESSAGE_TX_COUNT_PUSH ), DIFFB( buf3, MESSAGE_RX_BYTES_PUSH ), DIFFB( buf4, MESSAGE_TX_BYTES_PUSH ) );
    printf( " | Prune        | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PRUNE ), DIFFC( buf2, MESSAGE_TX_COUNT_PRUNE ), DIFFB( buf3, MESSAGE_RX_BYTES_PRUNE ), DIFFB( buf4, MESSAGE_TX_BYTES_PRUNE ) );
    printf( " | Ping         | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PING ), DIFFC( buf2, MESSAGE_TX_COUNT_PING ), DIFFB( buf3, MESSAGE_RX_BYTES_PING ), DIFFB( buf4, MESSAGE_TX_BYTES_PING ) );
    printf( " | Pong         | %s | %s | %s | %s |\n", DIFFC( buf1, MESSAGE_RX_COUNT_PONG ), DIFFC( buf2, MESSAGE_TX_COUNT_PONG ), DIFFB( buf3, MESSAGE_RX_BYTES_PONG ), DIFFB( buf4, MESSAGE_TX_BYTES_PONG ) );
    printf( " +--------------------------------------------------------------------------+\n\n" );

    for( ulong i=0UL; i<FD_METRICS_TOTAL_SZ/sizeof(ulong); i++ ) prev[ i ] = metrics[ i ];
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
