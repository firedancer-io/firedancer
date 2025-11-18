#include "../dev.h"
#include "../../../shared/commands/configure/configure.h" /* CONFIGURE_CMD_INIT */
#include "../../../shared/commands/run/run.h" /* fdctl_check_configure */
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */

#include <stdio.h> /* printf */
#include <unistd.h> /* isatty */
#include <sys/ioctl.h>
#include <poll.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
pktgen_topo( config_t * config ) {
  char const * affinity = config->development.pktgen.affinity;
  int is_auto_affinity = !strcmp( affinity, "auto" );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( affinity, parsed_tile_to_cpu );

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
    if( FD_UNLIKELY( affinity_tile_cnt!=4UL ) )
      FD_LOG_ERR(( "Invalid [development.pktgen.affinity]: must include exactly three CPUs" ));
  }

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topos_net_tiles( topo, config->layout.net_tile_count, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

  fd_topob_wksp( topo, "pktgen" );
  fd_topo_tile_t * pktgen_tile = fd_topob_tile( topo, "pktgen", "pktgen", "pktgen", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.pktgen.fake_dst_ip, &pktgen_tile->pktgen.fake_dst_ip ) ) ) {
    FD_LOG_ERR(( "Invalid [development.pktgen.fake_dst_ip]" ));
  }
  fd_topob_link( topo, "pktgen_out", "pktgen", 2048UL, FD_NET_MTU, 1UL );
  fd_topob_tile_out( topo, "pktgen", 0UL, "pktgen_out", 0UL );
  fd_topob_tile_in( topo, "net", 0UL, "metric_in", "pktgen_out", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  /* Create dummy RX link */
  fd_topos_net_rx_link( topo, "net_quic", 0UL, config->net.ingress_buffer_size );
  fd_topob_tile_in( topo, "pktgen", 0UL, "metric_in", "net_quic", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topos_net_tile_finish( topo, 0UL );
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

/* render_status prints statistics at the top of the screen.
   Should be called at a low rate (~500ms). */

static void
render_status( ulong volatile const * net_metrics ) {
  fputs( "\0337"      /* save cursor position */
         "\033[H"     /* move cursor to (0,0) */
         "\033[2K\n", /* create an empty line to avoid spamming look back buffer */
         stdout );
  printf( "\033[2K" "[Firedancer pktgen] mode=%s\n",
          FD_VOLATILE_CONST( fd_pktgen_active ) ? "send+recv" : "recv" );

  /* Render packet per second rates */
  static long   ts_last       = -1L;
  static ulong  cum_idle_last = 0UL;
  static ulong  cum_tick_last = 0UL;
  static ulong  rx_ok_last    = 0UL;
  static ulong  rx_byte_last  = 0UL;
  static ulong  rx_drop_last  = 0UL;
  static ulong  tx_ok_last    = 0UL;
  static ulong  tx_byte_last  = 0UL;

  static double busy_r       = 0.0;
  static double rx_ok_pps    = 0.0;
  static double rx_bps       = 0.0;
  static double rx_drop_pps  = 0.0;
  static double tx_ok_pps    = 0.0;
  static double tx_bps       = 0.0;

  if( FD_UNLIKELY( ts_last==-1 ) ) ts_last = fd_log_wallclock();
  long now = fd_log_wallclock();
  long dt  = now-ts_last;
  if( dt>(long)10e6 ) {
    ulong cum_idle_now  = net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG  ) ];
    ulong cum_tick_now  = cum_idle_now;
    /* */ cum_tick_now += net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING    ) ];
    /* */ cum_tick_now += net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING   ) ];
    /* */ cum_tick_now += net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING ) ];
    /* */ cum_tick_now += net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG         ) ];
    /* */ cum_tick_now += net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_PREFRAG        ) ];
    /* */ cum_tick_now += net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG      ) ];
    /* */ cum_tick_now += net_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_PROCESSING_POSTFRAG       ) ];
    ulong rx_ok_now     = net_metrics[ MIDX( COUNTER, NET, RX_PKT_CNT           ) ];
    ulong rx_byte_now   = net_metrics[ MIDX( COUNTER, NET, RX_BYTES_TOTAL       ) ];
    ulong rx_drop_now   = net_metrics[ MIDX( COUNTER, NET, RX_FILL_BLOCKED_CNT  ) ];
    /* */ rx_drop_now  += net_metrics[ MIDX( COUNTER, NET, RX_BACKPRESSURE_CNT  ) ];
    /* */ rx_drop_now  += net_metrics[ MIDX( COUNTER, NET, XDP_RX_DROPPED_OTHER ) ];
    /* */ rx_drop_now  += net_metrics[ MIDX( COUNTER, NET, XDP_RX_INVALID_DESCS ) ];
    /* */ rx_drop_now  += net_metrics[ MIDX( COUNTER, NET, XDP_RX_RING_FULL     ) ];
    ulong tx_ok_now     = net_metrics[ MIDX( COUNTER, NET, TX_COMPLETE_CNT      ) ];
    ulong tx_byte_now   = net_metrics[ MIDX( COUNTER, NET, TX_BYTES_TOTAL       ) ];

    ulong cum_idle_delta = cum_idle_now-cum_idle_last;
    ulong cum_tick_delta = cum_tick_now-cum_tick_last;
    ulong rx_ok_delta    = rx_ok_now   -rx_ok_last;
    ulong rx_byte_delta  = rx_byte_now -rx_byte_last;
    ulong rx_drop_delta  = rx_drop_now -rx_drop_last;
    ulong tx_ok_delta    = tx_ok_now   -tx_ok_last;
    ulong tx_byte_delta  = tx_byte_now -tx_byte_last;

    busy_r               = 1.0 - ( (double)cum_idle_delta / (double)cum_tick_delta );
    rx_ok_pps            = 1e9*( (double)rx_ok_delta  /(double)dt );
    rx_bps               = 8e9*( (double)rx_byte_delta/(double)dt );
    rx_drop_pps          = 1e9*( (double)rx_drop_delta/(double)dt );
    tx_ok_pps            = 1e9*( (double)tx_ok_delta  /(double)dt );
    tx_bps               = 8e9*( (double)tx_byte_delta/(double)dt );

    ts_last              = now;
    cum_idle_last        = cum_idle_now;
    cum_tick_last        = cum_tick_now;
    rx_ok_last           = rx_ok_now;
    rx_byte_last         = rx_byte_now;
    rx_drop_last         = rx_drop_now;
    tx_ok_last           = tx_ok_now;
    tx_byte_last         = tx_byte_now;
  }

  ulong rx_idle = net_metrics[ MIDX( GAUGE, NET, RX_IDLE_CNT ) ];
  ulong rx_busy = net_metrics[ MIDX( GAUGE, NET, RX_BUSY_CNT ) ];
  ulong tx_idle = net_metrics[ MIDX( GAUGE, NET, TX_IDLE_CNT ) ];
  ulong tx_busy = net_metrics[ MIDX( GAUGE, NET, TX_BUSY_CNT ) ];
  printf( "\033[2K" "  Net busy: %.2f%%\n"
          "\033[2K" "  RX ok:   %10.3e pps %10.3e bps\n"
          "\033[2K" "  RX drop: %10.3e pps\n"
          "\033[2K" "  TX ok:   %10.3e pps %10.3e bps\n"
          "\033[2K" "  RX bufs: %6lu idle %6lu busy\n"
          "\033[2K" "  TX bufs: %6lu idle %6lu busy\n",
          100.*busy_r,
          rx_ok_pps,   rx_bps,
          rx_drop_pps,
          tx_ok_pps,   tx_bps,
          rx_idle,     rx_busy,
          tx_idle,     tx_busy );

  fputs( "\0338", stdout ); /* restore cursor position */
  fflush( stdout );
}

/* FIXME fixup screen on window size changes */

void
pktgen_cmd_fn( args_t *   args FD_PARAM_UNUSED,
               config_t * config ) {
  pktgen_topo( config );
  fd_topo_t *      topo        = &config->topo;
  fd_topo_tile_t * net_tile    = &topo->tiles[ fd_topo_find_tile( topo, "net",    0UL ) ];
  fd_topo_tile_t * metric_tile = &topo->tiles[ fd_topo_find_tile( topo, "metric", 0UL ) ];

  ushort const listen_port = 9000;
  net_tile->net.legacy_transaction_listen_port = listen_port;

  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  configure_stage( &fd_cfg_stage_sysctl,           CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_hugetlbfs,        CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_bonding,          CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_channels, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_offloads, CONFIGURE_CMD_INIT, config );

  fdctl_check_configure( config );
  /* FIXME this allocates lots of memory unnecessarily */
  initialize_workspaces( config );
  initialize_stacks( config );
  fdctl_setup_netns( config, 1 );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_topo_install_xdp_simple( &config->topo, config->net.bind_address_parsed );
  }
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong volatile const * net_metrics = fd_metrics_tile( net_tile->metrics );

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
  printf( "XDP socket listening on port %u\n", (uint)listen_port );
  puts( "Available commands: start, stop, quit" );
  puts( "" );
  char input[ 256 ] = {0};
  for(;;) {
    render_status( net_metrics );
    fputs( "pktgen> ", stdout );
    fflush( stdout );

    for(;;) {
      struct pollfd fds[1] = {{ .fd=STDIN_FILENO, .events=POLLIN }};
      int poll_res = poll( fds, 1, 500 );
      if( poll_res==0 ) {
        render_status( net_metrics );
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
  .args        = pktgen_cmd_args,
  .fn          = pktgen_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Flood interface with invalid Ethernet frames"
};
