/* The repair_stress command sends dummy repair requests at a configurable
   rate through the net tile. This is useful for testing packet drop rates
   and determining when the net tile begins to drop packets. */

   #include "../../../disco/net/fd_net_tile.h"
   #include "../../../disco/topo/fd_topob.h"
   #include "../../../disco/topo/fd_cpu_topo.h"
   #include "../../../util/tile/fd_tile_private.h"

   /* topology.c not needed - we build our own minimal topology */
   #include "../../firedancer/topology.h"
   #include "../../shared/commands/configure/configure.h"
   #include "../../shared/commands/run/run.h" /* initialize_workspaces */
   #include "../../shared/fd_config.h" /* config_t */
   #include "../../shared_dev/commands/dev.h"
   #include "../../../disco/topo/fd_topob.h"
   #include "../../../disco/metrics/fd_metrics.h"
   #include "../../../discof/repair/fd_repair.h" /* for fd_repair_shred_req_t */

   #include "core_subtopo.h"

   #include <unistd.h> /* pause */
   #include <fcntl.h>
   #include <stdio.h>
   #include <termios.h>

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

/* Simple topology with just net tiles and repair_net link for stress testing */
static void
repair_stress_topo( config_t * config ) {
  ulong net_tile_cnt = config->layout.net_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                  "only has %lu CPUs.",
                  parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  fd_core_subtopo( config, tile_to_cpu );

  /* Workspaces */
  fd_topob_wksp( topo, "net_repair" );

  /* Links - repair_net is an input link to net tiles */
  fd_topob_link( topo, "repair_net", "net_repair", config->net.ingress_buffer_size, FD_NET_MTU, 1UL );
  for( ulong i=0UL; i<net_tile_cnt; i++ ) fd_topos_net_rx_link( topo, "net_repair", i, config->net.ingress_buffer_size );
  for( ulong i=0UL; i<net_tile_cnt; i++ ) fd_topos_tile_in_net(  topo, "metric_in", "repair_net",   i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  //for( ulong i=0UL; i<net_tile_cnt; i++ ) fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "net_repair",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */


  /* No repair tile needed - we'll inject directly */

  FD_TEST( fd_link_permit_no_producers( topo, "repair_net" ) == 1UL );
  FD_TEST( fd_link_permit_no_consumers( topo, "net_repair" ) == net_tile_cnt );

  config->tiles.send.send_src_port = 0; /* disable send */
  config->tiles.shred.shred_listen_port = 0; /* disable shred listen */
  config->tiles.quic.quic_transaction_listen_port = 0; /* disable quic listen */
  config->tiles.quic.regular_transaction_listen_port = 0; /* disable regular listen */
  config->gossip.port = 0; /* disable gossip */
  config->tiles.repair.repair_serve_listen_port = 0; /* disable repair intake listen */

  for( ulong i=0UL; i<net_tile_cnt; i++ ) fd_topos_net_tile_finish( topo, i );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );

  fd_topob_finish( topo, CALLBACKS );

  config->topo = *topo;
}

void
repair_stress_cmd_args( int *    pargc,
                        char *** pargv,
                        args_t * args ) {
  if( FD_UNLIKELY( !*pargc ) )
    FD_LOG_ERR(( "\n \
usage: repair_stress --rate <packets_per_second> [--dst-ip <ip>] [--dst-port <port>] \n\n \
       --rate: Number of packets per second to send (required) \n \
       --dst-ip: Destination IP address (default: 127.0.0.1) \n \
       --dst-port: Destination UDP port (default: 8000) \n" ));

  char const * rate_str = fd_env_strip_cmdline_cstr( pargc, pargv, "--rate", NULL, NULL );
  if( FD_UNLIKELY( !rate_str ) ) FD_LOG_ERR(( "--rate is required" ));

  args->repair_stress.rate = strtoul( rate_str, NULL, 10 );
  if( FD_UNLIKELY( args->repair_stress.rate == 0UL ) ) FD_LOG_ERR(( "Invalid rate: %s", rate_str ));

  char const * dst_ip = fd_env_strip_cmdline_cstr( pargc, pargv, "--dst-ip", NULL, NULL );
  if( FD_LIKELY( dst_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( dst_ip, &args->repair_stress.dst_ip ) ) )
      FD_LOG_ERR(( "Invalid destination IP: %s", dst_ip ));
  } else {
    args->repair_stress.dst_ip = 607617600U; /* 64.130.55.36  */
  }

  char const * dst_port_str = fd_env_strip_cmdline_cstr( pargc, pargv, "--dst-port", NULL, NULL );
  if( FD_LIKELY( dst_port_str ) ) {
    ulong port = strtoul( dst_port_str, NULL, 10 );
    if( FD_UNLIKELY( port == 0UL || port > 65535UL ) ) FD_LOG_ERR(( "Invalid destination port: %s", dst_port_str ));
    args->repair_stress.dst_port = (ushort)port;
  } else {
    args->repair_stress.dst_port = 8000U;
  }
}

static void
repair_stress_cmd_fn( args_t *   args,
                     config_t * config ) {
  FD_LOG_NOTICE(( "Repair stress test topology" ));

  memset( &config->topo, 0, sizeof(config->topo) );
  repair_stress_topo( config );

  FD_LOG_NOTICE(( "Repair stress init" ));
  fd_topo_print_log( 1, &config->topo );

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  for( ulong i=0UL; STAGES[ i ]; i++ ) {
    configure_args.configure.stages[ i ] = STAGES[ i ];
  }
  configure_cmd_fn( &configure_args, config );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_xdp_fds_t fds = fd_topo_install_xdp( &config->topo, config->net.bind_address_parsed );
    (void)fds;
  }

  run_firedancer_init( config, 1, 0 );

  extern int * fd_log_private_shared_lock;
  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_fill( &config->topo );

  ulong net_tile_cnt = config->layout.net_tile_count;
  volatile ulong ** repair_net_links = aligned_alloc( 8UL, net_tile_cnt * sizeof(volatile ulong*) );
  FD_TEST( repair_net_links );

  for( ulong i = 0UL; i < net_tile_cnt; i++ ) {
    ulong tile_idx = fd_topo_find_tile( &config->topo, "net", i );
    if( FD_UNLIKELY( tile_idx == ULONG_MAX ) ) FD_LOG_ERR(( "net tile %lu not found", i ));
    fd_topo_tile_t * tile = &config->topo.tiles[ tile_idx ];

    ulong repair_net_in_idx = fd_topo_find_tile_in_link( &config->topo, tile, "repair_net", 0UL );
    if( FD_UNLIKELY( repair_net_in_idx == ULONG_MAX ) ) {
      FD_LOG_ERR(( "repair_net link not found for net tile %lu", i ));
    }
    repair_net_links[i] = fd_metrics_link_in( tile->metrics, repair_net_in_idx );
    FD_TEST( repair_net_links[i] );
  }
  /* Find the repair_net link - this is an input to net tiles */
  ulong repair_net_link_idx = fd_topo_find_link( &config->topo, "repair_net", 0UL );
  FD_TEST( repair_net_link_idx!=ULONG_MAX );
  fd_topo_link_t * repair_net_link = &config->topo.links[ repair_net_link_idx ];

  /* Get dcache and mcache for repair_net link */
  fd_wksp_t * dcache_wksp = config->topo.workspaces[ config->topo.objs[ repair_net_link->dcache_obj_id ].wksp_id ].wksp;
  void * dcache = repair_net_link->dcache;
  void * mcache = repair_net_link->mcache;

  ulong dcache_chunk0 = fd_dcache_compact_chunk0( dcache_wksp, dcache );
  ulong dcache_wmark  = fd_dcache_compact_wmark( dcache_wksp, dcache, repair_net_link->mtu );
  ulong dcache_chunk  = dcache_chunk0;

  ulong mcache_depth = fd_mcache_depth( mcache );
  ulong * mcache_sync = fd_mcache_seq_laddr( mcache );
  ulong mcache_seq   = fd_mcache_seq_query( mcache_sync );

  /* Create a dummy repair request message (zeroed out as requested) */
  uchar dummy_repair_payload[ 256 ];
  fd_memset( dummy_repair_payload, 0, sizeof(dummy_repair_payload) );

  /* Minimum repair request size is roughly the size of a repair message */
  ulong payload_sz = sizeof(fd_repair_shred_req_t); /* Use shred request size as baseline */

  /* Calculate sleep time between packets */
  long double ns_per_packet = 1e9L / (long)args->repair_stress.rate; /* nanoseconds per packet */
  (void)ns_per_packet;

  FD_LOG_NOTICE(( "Starting repair stress test: %lu pps to %u.%u.%u.%u:%u on %lu net tiles",
                  args->repair_stress.rate,
                  args->repair_stress.dst_ip & 0xffU,
                  (args->repair_stress.dst_ip >> 8) & 0xffU,
                  (args->repair_stress.dst_ip >> 16) & 0xffU,
                  (args->repair_stress.dst_ip >> 24) & 0xffU,
                  args->repair_stress.dst_port,
                  net_tile_cnt ));

  /* Start the topology */
  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run );

  /* Send packets in a loop */
  ulong pkt_count = 0UL;
  long last_stats = fd_log_wallclock();
  long last_sent = fd_log_wallclock();
  ulong last_count = 0UL;

  fd_ip4_udp_hdrs_t intake_hdr[1];
  fd_ip4_udp_hdr_init(intake_hdr, 1232, 0, 8000 );
  ushort net_id = 0;

  for(;;) {
    long now = fd_log_wallclock();
    /* Maintain rate by skipping if necessary */
    if( now - last_sent < ns_per_packet ) continue;

    /* Write packet to dcache */
    uchar * packet = fd_chunk_to_laddr( dcache_wksp, dcache_chunk );
    fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;

    /* Initialize Ethernet header */
    *hdr = *intake_hdr;

    /* Initialize IP header */
    fd_ip4_hdr_t * ip4 = hdr->ip4;
    ip4->saddr       = 0;
    ip4->daddr       = args->repair_stress.dst_ip;
    ip4->net_id      = fd_ushort_bswap( net_id++ );
    ip4->check       = 0U;
    ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
    ip4->check       = fd_ip4_hdr_check_fast( ip4 );
    /* Initialize UDP header */
    fd_udp_hdr_t * udp = hdr->udp;
    udp->net_dport = ( args->repair_stress.dst_port );
    udp->net_len   = fd_ushort_bswap( (ushort)(sizeof(fd_udp_hdr_t)+payload_sz) );
    udp->check     = 0U;

    /* Copy payload */
    fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), dummy_repair_payload, payload_sz );

    ulong packet_sz = sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t) + payload_sz;
    ulong sig = fd_disco_netmux_sig( args->repair_stress.dst_ip, args->repair_stress.dst_port,
                                     args->repair_stress.dst_ip, DST_PROTO_OUTGOING, sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( mcache, mcache_depth, mcache_seq, sig, dcache_chunk, packet_sz, 0UL, 0UL, tspub );
    mcache_seq = fd_seq_inc( mcache_seq, 1UL );

    /* Advance dcache chunk */
    dcache_chunk = fd_dcache_compact_next( dcache_chunk, packet_sz, dcache_chunk0, dcache_wmark );
    last_sent = now;

    pkt_count++;

    /* Print stats every second */
    if( now - last_stats > 1e9L ) {
      ulong pps = pkt_count - last_count;
      FD_LOG_NOTICE(( "Sent %lu packets (%.2f pps)", pkt_count, (double)pps ));
      last_stats = now;
      last_count = pkt_count;

      /* Sum overrun across all net tiles connected to repair_net */
      ulong total_overrun = repair_net_links[0][ MIDX( COUNTER, LINK, OVERRUN_POLLING_FRAG_COUNT ) ]; /* coarse double counting prevention */
      ulong total_consumed = 0UL;
      for( ulong i = 0UL; i < net_tile_cnt; i++ ) {
        volatile ulong * ovar_net_metrics = repair_net_links[i];
        total_overrun  += ovar_net_metrics[ MIDX( COUNTER, LINK, OVERRUN_READING_FRAG_COUNT ) ];
        total_consumed += ovar_net_metrics[ MIDX( COUNTER, LINK, CONSUMED_COUNT ) ];
      }
      printf( " Total overrun: %lu\n", total_overrun );
      printf( " Net consumed:  %lu\n", total_consumed );

    }
  }
}

action_t fd_action_repair_stress = {
  .name = "repair_stress",
  .args = repair_stress_cmd_args,
  .fn   = repair_stress_cmd_fn,
  .perm = dev_cmd_perm,
};

