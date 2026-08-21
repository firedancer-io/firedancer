#include "../dev.h"
#include "../../../shared/commands/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../../../shared/commands/run/run.h" /* fdctl_check_configure */
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/net/fd_ip4.h"

#include <stdio.h> /* printf */
#include <unistd.h> /* isatty */
#include <sys/ioctl.h>
#include <poll.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
pktgen_topo( config_t * config ) {
  ulong net_tile_cnt = config->layout.net_tile_count;

  char const * affinity = config->development.pktgen.affinity;
  int is_auto_affinity = !strcmp( affinity, "auto" );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  ulong required_tile_cnt = 3UL+net_tile_cnt;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_topob_parse_affinity_cstr( affinity, parsed_tile_to_cpu, 0 );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [development.pktgen.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }
  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt!=required_tile_cnt ) )
      FD_LOG_ERR(( "Invalid [development.pktgen.affinity]: must include exactly %lu CPUs", required_tile_cnt ));
  }

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topos_net_tiles( topo, net_tile_cnt, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, 0, tile_to_cpu );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0, 0 );

  char const * net_tile_name = fd_net_tile_name( config->net.provider );

  fd_topob_wksp( topo, "pktgen" );
  fd_topo_tile_t * pktgen_tile = fd_topob_tile( topo, "pktgen", "pktgen", "pktgen", tile_to_cpu[ topo->tile_cnt ], 0, 0, 0 );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.pktgen.fake_dst_ip, &pktgen_tile->pktgen.fake_dst_ip ) ) ) {
    FD_LOG_ERR(( "Invalid [development.pktgen.fake_dst_ip]" ));
  }
  fd_topob_link( topo, "pktgen_out", "pktgen", 32768UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "pktgen", 0UL, "pktgen_out", 0UL );
  for( ulong i=0UL; i<net_tile_cnt; i++ ) {
    fd_topob_tile_in( topo, net_tile_name, i, "metric_in", "pktgen_out", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

    /* Create dummy RX link */
    fd_topos_net_rx_link( topo, "net_quic", i, config->net.ingress_buffer_size );
    fd_topob_tile_in( topo, "pktgen", 0UL, "metric_in", "net_quic", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

    fd_topos_net_tile_finish( topo, i );
  }


  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );
  topo->agave_affinity_cnt = 0;
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

void
pktgen_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  /* FIXME add config options here */
  (void)pargc; (void)pargv; (void)args;
}

/* Hacky: Since the pktgen runs in the same process, use globals to
   share state */
extern uint fd_pktgen_active;

/* fd_net_stats stores the stats for a single net tile. */

struct fd_net_stats {
  double busy_r;
  double rx_ok_pps;
  double rx_bps;
  double rx_drop_pps;
  double tx_ok_pps;
  double tx_bps;

  ulong  rx_bufs_idle;
  ulong  rx_bufs_busy;
  ulong  tx_bufs_idle;
  ulong  tx_bufs_busy;
};
typedef struct fd_net_stats fd_net_stats_t;

/* fd_net_metrics_last stores recent key metrics for a single net
   tile, used to calculate the next net_stats. */

struct fd_net_metrics_last {
  long  ts;
  ulong cum_idle;
  ulong cum_tick;
  ulong rx_ok;
  ulong rx_byte;
  ulong rx_drop;
  ulong tx_ok;
  ulong tx_byte;
};
typedef struct fd_net_metrics_last fd_net_metrics_last_t;

/* get_net_stats computes and returns per net tile stats. */

static fd_net_stats_t const *
get_net_stats( ulong volatile const * net_metrics[ FD_TOPO_MAX_TILES ],
               ulong                  net_tile_cnt,
               char const *           provider ) {

  static fd_net_stats_t        net_stats       [ FD_TOPO_MAX_TILES ];
  static fd_net_metrics_last_t net_metrics_last[ FD_TOPO_MAX_TILES ];

  long now = fd_log_wallclock();

  for( ulong kind_id=0UL; kind_id<net_tile_cnt; kind_id++ ) {
    ulong volatile const *  metrics = net_metrics      [ kind_id ];
    fd_net_metrics_last_t * last    = &net_metrics_last[ kind_id ];
    fd_net_stats_t *        stats   = &net_stats       [ kind_id ];

    if( FD_UNLIKELY( last->ts==0L ) ) last->ts = now;

    long dt = now-last->ts;
    if( dt<=(long)10e6 ) continue;

    ulong cum_idle_now  = metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG        ) ];
    ulong cum_tick_now  = cum_idle_now;
    /* */ cum_tick_now += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING    ) ];
    /* */ cum_tick_now += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING   ) ];
    /* */ cum_tick_now += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING ) ];
    /* */ cum_tick_now += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG         ) ];
    /* */ cum_tick_now += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_PREFRAG        ) ];
    /* */ cum_tick_now += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG      ) ];
    /* */ cum_tick_now += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_POSTFRAG       ) ];

    ulong rx_ok_now   = 0;
    ulong rx_byte_now = 0;
    ulong rx_drop_now = 0;
    ulong tx_ok_now   = 0;
    ulong tx_byte_now = 0;

    if( 0==strcmp( provider, "xdp" ) ) {
      stats->rx_bufs_idle = metrics[ MIDX( GAUGE, NET, RX_BUFFER_IDLE ) ];
      stats->rx_bufs_busy = metrics[ MIDX( GAUGE, NET, RX_BUFFER_BUSY ) ];
      stats->tx_bufs_idle = metrics[ MIDX( GAUGE, NET, TX_BUFFER_IDLE ) ];
      stats->tx_bufs_busy = metrics[ MIDX( GAUGE, NET, TX_BUFFER_BUSY ) ];

      rx_ok_now     = metrics[ MIDX( COUNTER, NET, PKT_RX                    ) ];
      rx_byte_now   = metrics[ MIDX( COUNTER, NET, PKT_RX_BYTES              ) ];
      rx_drop_now   = metrics[ MIDX( COUNTER, NET, PKT_RX_FILL_RING_FULL     ) ];
      /* */ rx_drop_now  += metrics[ MIDX( COUNTER, NET, PKT_RX_BACKPRESSURE       ) ];
      /* */ rx_drop_now  += metrics[ MIDX( COUNTER, NET, XDP_RX_OTHER_DROPPED      ) ];
      /* */ rx_drop_now  += metrics[ MIDX( COUNTER, NET, XDP_RX_INVALID_DESCRIPTOR ) ];
      /* */ rx_drop_now  += metrics[ MIDX( COUNTER, NET, XDP_RX_RING_FULL          ) ];
      tx_ok_now     = metrics[ MIDX( COUNTER, NET, PKT_TX_COMPLETED          ) ];
      tx_byte_now   = metrics[ MIDX( COUNTER, NET, PKT_TX_BYTES              ) ];

    } else if( 0==strcmp( provider, "mlx5" ) ) {
      stats->rx_bufs_idle = metrics[ MIDX( GAUGE, MLX5, RX_BUFFER_IDLE ) ];
      stats->rx_bufs_busy = metrics[ MIDX( GAUGE, MLX5, RX_BUFFER_BUSY ) ];
      stats->tx_bufs_idle = metrics[ MIDX( GAUGE, MLX5, TX_BUFFER_IDLE ) ];
      stats->tx_bufs_busy = metrics[ MIDX( GAUGE, MLX5, TX_BUFFER_BUSY ) ];

      rx_ok_now     = metrics[ MIDX( COUNTER, MLX5, PKT_RX       ) ];
      rx_byte_now   = metrics[ MIDX( COUNTER, MLX5, PKT_RX_BYTES ) ];
      rx_drop_now   = metrics[ MIDX( COUNTER, MLX5, RX_OUT_OF_BUFFER  ) ];
      /* */ rx_drop_now += metrics[ MIDX( COUNTER, MLX5, PKT_RX_MALFORMED  ) ];
      /* */ rx_drop_now += metrics[ MIDX( COUNTER, MLX5, PKT_RX_ROUTE_FAIL ) ];
      tx_ok_now     = metrics[ MIDX( COUNTER, MLX5, PKT_TX_COMPLETED ) ];
      tx_byte_now   = metrics[ MIDX( COUNTER, MLX5, PKT_TX_BYTES     ) ];
    }


    ulong cum_idle_delta = cum_idle_now-last->cum_idle;
    ulong cum_tick_delta = cum_tick_now-last->cum_tick;
    ulong rx_ok_delta    = rx_ok_now   -last->rx_ok;
    ulong rx_byte_delta  = rx_byte_now -last->rx_byte;
    ulong rx_drop_delta  = rx_drop_now -last->rx_drop;
    ulong tx_ok_delta    = tx_ok_now   -last->tx_ok;
    ulong tx_byte_delta  = tx_byte_now -last->tx_byte;

    stats->busy_r      = 1.0 - ( (double)cum_idle_delta / (double)cum_tick_delta );
    stats->rx_ok_pps   = 1e9*( (double)rx_ok_delta  /(double)dt );
    stats->rx_bps      = 8e9*( (double)rx_byte_delta/(double)dt );
    stats->rx_drop_pps = 1e9*( (double)rx_drop_delta/(double)dt );
    stats->tx_ok_pps   = 1e9*( (double)tx_ok_delta  /(double)dt );
    stats->tx_bps      = 8e9*( (double)tx_byte_delta/(double)dt );

    last->ts       = now;
    last->cum_idle = cum_idle_now;
    last->cum_tick = cum_tick_now;
    last->rx_ok    = rx_ok_now;
    last->rx_byte  = rx_byte_now;
    last->rx_drop  = rx_drop_now;
    last->tx_ok    = tx_ok_now;
    last->tx_byte  = tx_byte_now;
  }

  return net_stats;
}

/* render_status prints statistics at the top of the screen.
   Should be called at a low rate (~500ms). */

static void
render_status( ulong volatile const * net_metrics[ FD_TOPO_MAX_TILES ],
               ulong                  net_tile_cnt,
               char const *           provider ) {
  fputs( "\0337"      /* save cursor position */
         "\033[H"     /* move cursor to (0,0) */
         "\033[2K\n", /* create an empty line to avoid spamming look back buffer */
         stdout );
  printf( "\033[2K" "[Firedancer pktgen] mode=%s\n",
          FD_VOLATILE_CONST( fd_pktgen_active ) ? "send+recv" : "recv" );

  fd_net_stats_t const * stats = get_net_stats( net_metrics, net_tile_cnt, provider );

  fd_net_stats_t summary = {0};
  for( ulong i=0UL; i<net_tile_cnt; i++ ) {
    summary.busy_r       += stats[ i ].busy_r;
    summary.rx_ok_pps    += stats[ i ].rx_ok_pps;
    summary.rx_bps       += stats[ i ].rx_bps;
    summary.rx_drop_pps  += stats[ i ].rx_drop_pps;
    summary.tx_ok_pps    += stats[ i ].tx_ok_pps;
    summary.tx_bps       += stats[ i ].tx_bps;
    summary.rx_bufs_idle += stats[ i ].rx_bufs_idle;
    summary.rx_bufs_busy += stats[ i ].rx_bufs_busy;
    summary.tx_bufs_idle += stats[ i ].tx_bufs_idle;
    summary.tx_bufs_busy += stats[ i ].tx_bufs_busy;
  }
  summary.busy_r /= (double)net_tile_cnt;

  printf( "\033[2K" "Overall stats:\n" );

  /* Render packet per second rates */
  printf( "\033[2K" "  Net busy: %.2f%%\n"
          "\033[2K" "  RX ok:   %10.3e pps %10.3e bps\n"
          "\033[2K" "  RX drop: %10.3e pps\n"
          "\033[2K" "  TX ok:   %10.3e pps %10.3e bps\n"
          "\033[2K" "  RX bufs: %6lu idle %6lu busy\n"
          "\033[2K" "  TX bufs: %6lu idle %6lu busy\n",
          100.*summary.busy_r,
          summary.rx_ok_pps,    summary.rx_bps,
          summary.rx_drop_pps,
          summary.tx_ok_pps,    summary.tx_bps,
          summary.rx_bufs_idle, summary.rx_bufs_busy,
          summary.tx_bufs_idle, summary.tx_bufs_busy );

  printf( "\033[2K" "Individual net tiles:\n" );

  for( ulong i=0UL; i<net_tile_cnt; i++ ) {
    printf( "\033[2K" "  net:%-3lu busy %6.2f%% | RX(ok) %10.3e pps | TX(ok) %10.3e pps\n",
            i,
            100.*stats[ i ].busy_r,
            stats[ i ].rx_ok_pps,
            stats[ i ].tx_ok_pps );
  }

  fputs( "\0338", stdout ); /* restore cursor position */
  fflush( stdout );
}

/* FIXME fixup screen on window size changes */

void
pktgen_cmd_fn( args_t *   args FD_PARAM_UNUSED,
               config_t * config ) {
  fd_topo_t *      topo         = &config->topo;
  ulong            net_tile_cnt = config->layout.net_tile_count;
  if( FD_UNLIKELY( net_tile_cnt>FD_TOPO_MAX_TILES ) ) {
    FD_LOG_ERR(( "more net tiles (%lu) than max num tiles allowed (%lu)", net_tile_cnt, FD_TOPO_MAX_TILES ));
  }

  fd_topo_tile_t * metric_tile  = &topo->tiles[ fd_topo_find_tile( topo, "metric", 0UL ) ];

  fd_topo_tile_t       * net_tiles  [ FD_TOPO_MAX_TILES ];
  ulong volatile const * net_metrics[ FD_TOPO_MAX_TILES ];

  ushort const listen_port = 9000;
  config->tiles.quic.regular_transaction_listen_port = listen_port;
  for( ulong kind_id=0UL; kind_id<net_tile_cnt; kind_id++ ) {
    net_tiles[ kind_id ] = &topo->tiles[ fd_topo_find_tile( topo, fd_net_tile_name( config->net.provider ), kind_id ) ];
    net_tiles[ kind_id ]->net.legacy_transaction_listen_port = listen_port;
  }

  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  configure_stage( &fd_cfg_stage_sysctl,           CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_hugetlbfs,        CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_bonding,          CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_channels, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_offloads, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_sysfs_poll,       CONFIGURE_CMD_INIT, config );

  fdctl_check_configure( config );
  /* FIXME this allocates lots of memory unnecessarily */
  initialize_workspaces( config );
  initialize_stacks( config );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_topo_install_xdp_simple( &config->topo, config->net.bind_address_parsed );
  }
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  for( ulong kind_id=0UL; kind_id<net_tile_cnt; kind_id++ ) {
    net_metrics[ kind_id ] = fd_metrics_tile( net_tiles[ kind_id ]->metrics );
  }

  /* Don't attempt to render TTY */
  if( !isatty( STDOUT_FILENO ) ) {
    puts( "stdout is not a tty, not taking commands" );
    FD_VOLATILE( fd_pktgen_active ) = 1;
    for(;;) pause();
    return;
  }

  /* Clear screen */
  struct winsize w;
  if( FD_UNLIKELY( 0!=ioctl( STDOUT_FILENO, TIOCGWINSZ, &w ) ) ) {
    FD_LOG_WARNING(( "ioctl(STDOUT_FILENO,TIOCGWINSZ) failed" ));
  } else {
    for( ulong i=0UL; i<w.ws_row; i++ ) putc( '\n', stdout );
  }

  /* Simple REPL loop */
  puts( "Running fddev pktgen" );
  printf( "%s socket listening on port %u\n", config->net.provider, (uint)listen_port );
  puts( "Available commands: start, stop, quit" );
  puts( "" );
  char input[ 256 ] = {0};
  for(;;) {
    render_status( net_metrics, net_tile_cnt, config->net.provider );
    fputs( "pktgen> ", stdout );
    fflush( stdout );

    for(;;) {
      struct pollfd fds[1] = {{ .fd=STDIN_FILENO, .events=POLLIN }};
      int poll_res = poll( fds, 1, 500 );
      if( poll_res==0 ) {
        render_status( net_metrics, net_tile_cnt, config->net.provider );
        continue;
      } else if( poll_res>0 ) {
        break;
      } else {
        FD_LOG_ERR(( "poll(STDIN_FILENO) failed" ));
        break;
      }
    }

    if( fgets( input, sizeof(input), stdin )==NULL ) {
      putc( '\n', stdout );
      break;
    }
    input[ strcspn( input, "\n" ) ] = '\0';
    input[ sizeof(input)-1        ] = '\0';

    if( !input[0] ) {
      /* No command */
    } else if( !strcmp( input, "exit" ) || !strcmp( input, "quit" ) ) {
      break;
    } else if( !strcmp( input, "start" ) ) {
      FD_VOLATILE( fd_pktgen_active ) = 1U;
    } else if( !strcmp( input, "stop" ) ) {
      FD_VOLATILE( fd_pktgen_active ) = 0U;
    } else {
      fputs( "Unknown command\n", stdout );
    }
  }
  puts( "Exiting" );
}

action_t fd_action_pktgen = {
  .name        = "pktgen",
  .topo        = pktgen_topo,
  .args        = pktgen_cmd_args,
  .fn          = pktgen_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Flood interface with invalid Ethernet frames"
};
