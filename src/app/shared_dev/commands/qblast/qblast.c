#include "../dev.h"
#include "../../../shared/commands/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../../../shared/commands/run/run.h" /* fdctl_check_configure */
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */

#include <unistd.h> /* pause */

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
qblast_topo( config_t * config, args_t const * args ) {
  /* affinity handling */
  char const * affinity = config->development.qblast.affinity;
  int is_auto_affinity = fd_memeq( affinity, "auto", 4 );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( !is_auto_affinity ) {
    affinity_tile_cnt = fd_tile_private_cpus_parse( affinity, parsed_tile_to_cpu );
    if( affinity_tile_cnt!=4UL )
      FD_LOG_ERR(( "Invalid [development.qblast.affinity]: must include exactly four CPUs" ));
  }

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [development.qblast.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "metric"    );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "qblast"    );

  fd_topos_net_tiles( topo, config->layout.net_tile_count, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );
  fd_topob_tile( topo, "qblast", "qblast", "qblast",    tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  fd_topob_tile( topo, "metric", "metric", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

  /* uses 'quic_net' and 'net_quic' to minimize changes */
  fd_topob_link( topo, "quic_net", "qblast", 2048UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "qblast", 0UL, "quic_net", 0UL );
  fd_topos_tile_in_net( topo, "metric_in", "quic_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topos_net_rx_link( topo, "net_quic", 0UL, config->net.ingress_buffer_size );
  fd_topob_tile_in( topo, "qblast", 0UL, "metric_in", "net_quic", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  /* Setup config values */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( FD_UNLIKELY( !strcmp( tile->name, "net" ) || !strcmp( tile->name, "sock" ) ) ) {
      tile->net.legacy_transaction_listen_port = config->development.qblast.src_port;
    }
  }
  fd_topo_tile_t * qblast_tile = &topo->tiles[ fd_topo_find_tile( topo, "qblast", 0UL ) ];
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( args->qblast.server_ip, &qblast_tile->qblast.dst_ip ) ) ) {
    FD_LOG_ERR(( "Invalid server IP address: %s", args->qblast.server_ip ));
  }
  qblast_tile->qblast.dst_port    = args->qblast.server_port;
  qblast_tile->qblast.src_ip      = config->net.ip_addr;
  qblast_tile->qblast.src_port    = config->development.qblast.src_port;
  qblast_tile->qblast.conn_target = args->qblast.conn_cnt;

  fd_topos_net_tile_finish( topo, 0UL );
  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );
  topo->agave_affinity_cnt = 0;
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

void
qblast_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  int     argc = *pargc;
  char ** argv = *pargv;

  /* Parse arguments using fd_env_strip_cmdline_* functions */
  char const * server_str  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--server",      NULL, NULL );
  ulong        conn_cnt    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--conn-cnt",    NULL, 1UL );

  /* Validate and parse server argument */
  if( FD_UNLIKELY( !server_str ) ) {
    FD_LOG_ERR(( "Missing required --server IP:PORT argument" ));
  }

  char const * colon = NULL;
  for( char const * c=server_str; c<server_str+strlen(server_str); c++ ) {
    if( *c == ':' ) {
      colon = c;
      break;
    }
  }
  if( FD_UNLIKELY( !colon ) ) {
    FD_LOG_ERR(( "--server argument must be in IP:PORT format" ));
  }

  char const * server_ip = server_str;
  ushort server_port = fd_cstr_to_ushort( colon + 1 );
  if( FD_UNLIKELY( server_port == 0 ) ) {
    FD_LOG_ERR(( "Invalid server port in --server argument" ));
  }

  /* Store parsed arguments in the args structure */
  fd_memcpy( args->qblast.server_ip, server_ip, (ulong)(colon-server_str) );
  args->qblast.server_port = server_port;
  args->qblast.conn_cnt    = conn_cnt;

  /* Update argc/argv - fd_env_strip_cmdline_* functions already removed processed args */
  *pargc = argc;
  *pargv = argv;
}

void
qblast_cmd_fn( args_t *   args,
               config_t * config ) {
  qblast_topo( config, args );
  fd_topo_t * topo   = &config->topo;

  ulong xdp_tile_idx = fd_topo_find_tile( topo, "net", 0UL );
  ulong net_tile_idx = fd_ulong_if( xdp_tile_idx!=ULONG_MAX, xdp_tile_idx, fd_topo_find_tile( topo, "sock", 0UL ) );
  FD_TEST( net_tile_idx != ULONG_MAX );
  fd_topo_tile_t * net_tile    = &topo->tiles[ net_tile_idx ];
  fd_topo_tile_t * metric_tile = &topo->tiles[ fd_topo_find_tile( topo, "metric", 0UL ) ];

  net_tile->net.legacy_transaction_listen_port = config->development.qblast.src_port;

  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  configure_stage( &fd_cfg_stage_sysctl,           CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_hugetlbfs,        CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_channels, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_gro,      CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_loopback, CONFIGURE_CMD_INIT, config );

  fdctl_check_configure( config );
  initialize_workspaces( config );
  initialize_stacks( config );
  fdctl_setup_netns( config, 1 );
  if( !strcmp( config->net.provider, "xdp" ) ) {
    (void)fd_topo_install_xdp( topo, config->net.bind_address_parsed );
  }
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  FD_LOG_NOTICE(( "Starting qblast: server=%s:%u, conn_cnt=%lu, src_ip=%u.%u.%u.%u:%u",
                  args->qblast.server_ip, args->qblast.server_port, args->qblast.conn_cnt,
                  config->net.ip_addr&0xFF, (config->net.ip_addr>>8)&0xFF, (config->net.ip_addr>>16)&0xFF, (config->net.ip_addr>>24)&0xFF,
                  config->development.qblast.src_port ));

  /* Run indefinitely */
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  for(;;) pause();
}

action_t fd_action_qblast = {
  .name        = "qblast",
  .args        = qblast_cmd_args,
  .fn          = qblast_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Create and service multiple QUIC connections for stress testing\n"
                 "Usage: --server IP:PORT [--conn-cnt N]"
};
