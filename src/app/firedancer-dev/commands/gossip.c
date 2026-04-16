#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../discof/gossip/fd_gossip_tile.h"
#include "../../../util/clock/fd_clock.h"

#include "../../firedancer/commands/monitor_gossip/gossip_diag.h"

#include "core_subtopo.h"
#include "gossip.h"

#include <stdio.h> /* printf */
#include <stdlib.h>
#include <unistd.h> /* isatty */
#include <sys/ioctl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

void
resolve_gossip_entrypoints( config_t * config );

static void
gossip_cmd_topo( config_t * config ) {
  resolve_gossip_entrypoints( config );

  /* Disable non-gossip listen ports */
  config->tiles.shred.shred_listen_port = 0U;
  config->tiles.quic.quic_transaction_listen_port = 0U;
  config->tiles.quic.regular_transaction_listen_port = 0U;
  config->tiles.repair.repair_intake_listen_port = 0U;
  config->tiles.repair.repair_serve_listen_port = 0U;
  config->tiles.txsend.txsend_src_port = 0U;

  static ulong tile_to_cpu[ FD_TILE_MAX ] = {0}; /* TODO */

  ulong net_tile_cnt = config->layout.net_tile_count;

  /* Reset topology from scratch */
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->lazy_paging = config->development.lazy_paging;

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

  fd_topob_wksp( topo, "gossip" );
  fd_topo_tile_t * gossip_tile = fd_topob_tile( topo, "gossip", "gossip", "metric_in", 0UL, 0, 1, 0 );
  fd_cstr_ncpy( gossip_tile->gossip.identity_key_path, config->paths.identity_key, sizeof(gossip_tile->gossip.identity_key_path) );
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
    fd_topo_tile_t * gossvf_tile = fd_topob_tile( topo, "gossvf", "gossvf", "metric_in", 0UL, 0, 1, 0 );
    fd_cstr_ncpy( gossvf_tile->gossvf.identity_key_path, config->paths.identity_key, sizeof(gossvf_tile->gossvf.identity_key_path) );
    gossvf_tile->gossvf.tcache_depth = 1UL<<22UL;
    gossvf_tile->gossvf.shred_version = config->consensus.expected_shred_version;
    gossvf_tile->gossvf.allow_private_address = config->development.gossip.allow_private_address;
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
  fd_topo_tile_t * ipecho_tile = fd_topob_tile( topo, "ipecho", "ipecho", "metric_in", 0UL, 0, 0, 0 );
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

  fd_topob_wksp( topo, "gossvf_gossip" );
  fd_topob_wksp( topo, "gossip_gossvf" );
  fd_topob_wksp( topo, "gossip_out" );

  fd_topob_link(     topo, "gossip_gossvf", "gossip_gossvf", 65536UL*4, sizeof(fd_gossip_ping_update_t), 1UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_gossvf", 0UL );

  fd_topob_link( topo, "gossip_out", "gossip_out", 65536UL*4, sizeof(fd_gossip_update_message_t), 1UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_out", 0UL );
  for( ulong i=0UL; i<gossvf_tile_count; i++ ) {
    fd_topob_link(     topo, "gossvf_gossip", "gossvf_gossip", 65536UL*4, sizeof(fd_gossip_message_t)+FD_GOSSIP_MESSAGE_MAX_CRDS+FD_NET_MTU, 1UL );
    fd_topob_tile_out( topo, "gossvf", i, "gossvf_gossip", i );
    fd_topob_tile_in(  topo, "gossip", 0UL, "metric_in", "gossvf_gossip", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    /* Only one link_kind for gossip_out broadcast link */
    fd_topob_tile_in( topo, "gossvf", i, "metric_in", "gossip_gossvf", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "gossvf", i, "metric_in", "gossip_out",    0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
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
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_bonding;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_ethtool_channels;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_ethtool_offloads;
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

/* Display helper functions and types have been extracted to
   gossip_diag.h / gossip_diag.c in the shared commands directory. */

static void
gossip_args( int *    pargc,
             char *** pargv,
             args_t * args  ) {
  if( FD_UNLIKELY( fd_env_strip_cmdline_contains( pargc, pargv, "--help" ) ) ) {
    fputs(
      "\nUsage: firedancer-dev gossip [GLOBAL FLAGS] [FLAGS]\n"
      "\n"
      "Global Flags:\n"
      "  --mainnet            Use Solana mainnet-beta defaults\n"
      "  --testnet            Use Solana testnet defaults\n"
      "  --devnet             Use Solana devnet defaults\n"
      "\n"
      "Flags:\n"
      "  --max-entries <num>         Exit once we see <num> CRDS entries in table\n"
      "  --max-contact-infos <num>   Exit once we see <num> contact infos in table\n"
      "  --compact                   Use compact output format\n"
      "\n",
      stderr );
    exit( EXIT_SUCCESS );
  }

  args->gossip.max_entries  = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--max-entries", NULL, ULONG_MAX );
  args->gossip.max_contact  = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--max-contact-infos", NULL, ULONG_MAX );
  args->gossip.compact_mode = fd_env_strip_cmdline_contains( pargc, pargv, "--compact" );
}

void
gossip_cmd_fn( args_t *   args,
               config_t * config ) {
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  run_firedancer_init( config, 1, 1 );

  int const is_xdp = ( 0==strcmp( config->net.provider, "xdp" ) );
  if( is_xdp ) fd_topo_install_xdp_simple( &config->topo, config->net.bind_address_parsed );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );

  fd_gossip_diag_ctx_t diag_ctx[1];
  if( FD_UNLIKELY( fd_gossip_diag_init( diag_ctx, &config->topo, config ) ) )
    FD_LOG_ERR(( "Failed to initialize gossip diagnostics" ));

  fd_clock_t   clock_lmem[1];
  void       * clock_mem = aligned_alloc( FD_CLOCK_ALIGN, FD_CLOCK_FOOTPRINT );
  FD_TEST( clock_mem );
  fd_clock_default_init( clock_lmem, clock_mem );

  long start_time       = fd_clock_now( clock_lmem );
  long next_report_time = start_time + 1000000000L;

  for(;;) {
    long current_time = fd_clock_now( clock_lmem );

    if( FD_LIKELY( current_time < next_report_time ) ) {
      continue;
    }
    next_report_time += 1000000000L;

    fd_gossip_diag_render( diag_ctx, args->gossip.compact_mode );

    if( FD_UNLIKELY( diag_ctx->last_total_crds >= args->gossip.max_entries ||
                     diag_ctx->last_total_contact_infos >= args->gossip.max_contact ) ) {
      long elapsed = current_time - start_time;
      double elapsed_secs = (double)elapsed / 1000000000.0;
      printf( "User defined thresholds reached in %.2fs\n"
              "  Table Size   : %lu\n"
              "  Contact Infos: %lu\n",
              elapsed_secs, diag_ctx->last_total_crds, diag_ctx->last_total_contact_infos );
      break;
    }
  }
}

action_t fd_action_gossip = {
  .name = "gossip",
  .args = gossip_args,
  .fn   = gossip_cmd_fn,
  .perm = gossip_cmd_perm,
  .topo = gossip_cmd_topo,
};
