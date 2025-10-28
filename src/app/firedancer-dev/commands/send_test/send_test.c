/*
send_test is a firedancer-dev command that tests the send tile.
It uses the net, send, metrics, and sign tiles, just like in prod.
The main test function writes contact info to the gossip_out link,
stake info to the stake_out link, and triggers mock votes on the
tower_out link.

It takes two required arguments:
--gossip-file: the path to the gossip file
--stake-file: the path to the stake file
These two files should include lines from the 'solana gossip' and
'solana validators' commands, respectively. It is recommended to run
with a known good subset of nodes while tuning the send tile.

send_test can also run with live gossip, if --gossip-file is set to "live".
This will populate contact info from the live cluster, and requires the
config's gossip section populated appropriately. 'live' mode will spin
up the entire gossip subtopo.
*/
#include "../../../shared/commands/configure/configure.h"
#include "../../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../../shared/fd_config.h" /* config_t */
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus_t */
#include "../../../../util/tile/fd_tile_private.h"
#include "../../../../disco/net/fd_net_tile.h" /* fd_topos_net_tiles */
#include "../../../../discof/tower/fd_tower_tile.h"
#include "../../../../flamenco/leaders/fd_leaders_base.h" /* FD_STAKE_OUT_MTU */
#include "../../../../app/firedancer/topology.h" /* fd_topo_configure_tile */
#include "../../../../disco/keyguard/fd_keyload.h"

#include "../core_subtopo.h"
#include "../gossip.h"
#include "send_test_helpers.c"

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

struct {
  char gossip_file[256];
  char stake_file[256];
} send_test_args = {0};

static void
send_test_topo( config_t * config ) {

  ulong const net_tile_cnt = config->layout.net_tile_count;
  ulong const ingress_buf_sz = config->net.ingress_buffer_size;

  /* Setup topology */
  fd_topo_t * topo    = fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( strcmp( config->layout.affinity, "auto" ) ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                    "in the system.",
                    parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  /* Check if we should use live gossip or mock gossip */
  int use_live_gossip = !strcmp( send_test_args.gossip_file, "live" );

  fd_core_subtopo( config, tile_to_cpu );
  if( use_live_gossip ) fd_gossip_subtopo( config, tile_to_cpu );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /* Add send tile */
  fd_topob_wksp( topo, "send" );
  fd_topob_tile( topo, "send", "send", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

  /* wksps for send links */
  fd_topob_wksp( topo, "send_net" );
  fd_topob_wksp( topo, "sign_send" );
  fd_topob_wksp( topo, "send_sign" );

  /* real links for send */
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_send", i, ingress_buf_sz );

  FOR(net_tile_cnt) fd_topob_link( topo, "send_net",  "send_net",  ingress_buf_sz, FD_NET_MTU, 1UL  );
  /**/              fd_topob_link( topo, "send_sign", "send_sign", 128UL,          FD_TXN_MTU, 1UL  );
  /**/              fd_topob_link( topo, "sign_send", "sign_send", 128UL,          64UL,       1UL  );

  /* mock links */
  /* braces shut up clang's 'misleading identation' warning */
  if( !use_live_gossip ) {fd_topob_wksp( topo, "gossip_out" ); }
  /**/                    fd_topob_wksp( topo, "replay_stake"  );
  /**/                    fd_topob_wksp( topo, "tower_out" );
  /**/                    fd_topob_wksp( topo, "send_out"  );

  if( !use_live_gossip ) {fd_topob_link( topo, "gossip_out",   "gossip_out",   65536UL*4UL, sizeof(fd_gossip_update_message_t), 1UL ); }
  /**/                    fd_topob_link( topo, "replay_stake", "replay_stake", 128UL,       FD_STAKE_OUT_MTU,                   1UL );
  /**/                    fd_topob_link( topo, "tower_out",    "tower_out",    1024UL,      sizeof(fd_tower_slot_done_t),       1UL );
  /**/                    fd_topob_link( topo, "send_out",     "send_out",     128UL,       40200UL * 38UL,                     1UL );

  if( !use_live_gossip ) {fd_link_permit_no_producers( topo, "gossip_out" ); }
  if( !use_live_gossip ) {fd_link_permit_no_consumers( topo, "send_out"   ); }
  /**/                    fd_link_permit_no_producers( topo, "replay_stake"  );
  /**/                    fd_link_permit_no_producers( topo, "tower_out" );

  if( use_live_gossip ) {
    /* finish off gossip in_links */
    fd_topob_tile_in( topo, "gossip",  0UL, "metric_in", "send_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "gossip",  0UL, "metric_in", "sign_gossip", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  }

  /* attach send in links */
  fd_topos_tile_in_net( topo, /* ***** */  "metric_in", "send_net",     0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in (    topo, "send", 0UL, "metric_in", "net_send",     0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_in(     topo, "send", 0UL, "metric_in", "gossip_out",   0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in(     topo, "send", 0UL, "metric_in", "replay_stake", 0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in(     topo, "send", 0UL, "metric_in", "tower_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /* attach out links */
  fd_topob_tile_out( topo, "send", 0UL, "send_net", 0UL );
  fd_topob_tile_out( topo, "send", 0UL, "send_out", 0UL );

  /* unpolled links have to be last! */
  fd_topob_tile_in ( topo, "sign", 0UL, "metric_in", "send_sign", 0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_in ( topo, "send", 0UL, "metric_in", "sign_send", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "send", 0UL, "send_sign", 0UL );
  fd_topob_tile_out( topo, "sign", 0UL, "sign_send", 0UL );

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  /* Finish topology setup */
  if( FD_UNLIKELY( !strcmp( config->layout.affinity, "auto" ) ) ) fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static void
send_test_cmd_args( int *    pargc,
                    char *** pargv,
                    args_t * args  FD_PARAM_UNUSED ) {
  char ** _pargv = *pargv;
  int     _pargc = *pargc;
  int     found_gossip = 0;
  int     found_stake = 0;

  /* Extract our arguments */
  for( int i = 0; i < _pargc - 1; i++ ) {
    if( !strcmp( _pargv[i], "--gossip-file" ) ) {
      strncpy( send_test_args.gossip_file, _pargv[i+1], sizeof(send_test_args.gossip_file) - 1 );
      found_gossip = 1;
    } else if( !strcmp( _pargv[i], "--stake-file" ) ) {
      strncpy( send_test_args.stake_file, _pargv[i+1], sizeof(send_test_args.stake_file) - 1 );
      found_stake = 1;
    }
  }

  /* Remove our arguments from argv */
  int write_idx = 0;
  for( int read_idx = 0; read_idx < _pargc; read_idx++ ) {
    if( read_idx < _pargc - 1 &&
        (!strcmp( _pargv[read_idx], "--gossip-file" ) || !strcmp( _pargv[read_idx], "--stake-file" )) ) {
      read_idx++; /* Skip the argument value too */
    } else {
      _pargv[write_idx++] = _pargv[read_idx];
    }
  }
  *pargc = write_idx;

  if( !found_gossip ) FD_LOG_ERR(( "--gossip-file is required" ));
  if( !found_stake ) FD_LOG_ERR(( "--stake-file is required" ));
}


static void
init( send_test_ctx_t * ctx, config_t * config ) {
  fd_topo_t * topo = &config->topo;
  ctx->topo = topo;
  ctx->config = config;

  /* Copy file paths from send_test_args */
  fd_memcpy( ctx->gossip_file, send_test_args.gossip_file, sizeof(ctx->gossip_file) );
  fd_memcpy( ctx->stake_file,  send_test_args.stake_file,  sizeof(ctx->stake_file ) );

  int live_gossip = !strcmp( send_test_args.gossip_file, "live" );

  ctx->identity_key  [ 0 ] = *(fd_pubkey_t const *)(fd_keyload_load( config->paths.identity_key, /* pubkey only: */ 1 ) );
  ctx->vote_acct_addr[ 0 ] = *(fd_pubkey_t const *)(fd_keyload_load( config->paths.vote_account, /* pubkey only: */ 1 ) );

  ctx->out_links[    MOCK_CI_IDX   ] = setup_test_out_link( topo, "gossip_out" );
  ctx->out_links[  MOCK_STAKE_IDX  ] = setup_test_out_link( topo, "replay_stake" );
  ctx->out_links[ MOCK_TRIGGER_IDX ] = setup_test_out_link( topo, "tower_out" );

  ctx->out_fns  [    MOCK_CI_IDX   ] = send_test_ci;
  ctx->out_fns  [  MOCK_STAKE_IDX  ] = send_test_stake;
  ctx->out_fns  [ MOCK_TRIGGER_IDX ] = send_test_trigger;

  ctx->last_evt [    MOCK_CI_IDX   ] = 0;
  ctx->last_evt [  MOCK_STAKE_IDX  ] = 0;
  ctx->last_evt [ MOCK_TRIGGER_IDX ] = 0;

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ctx->delay    [    MOCK_CI_IDX   ] = (long)(tick_per_ns * 5e9);
  ctx->delay    [  MOCK_STAKE_IDX  ] = (long)(tick_per_ns * 400e6 * MAX_SLOTS_PER_EPOCH);
  ctx->delay    [ MOCK_TRIGGER_IDX ] = (long)(tick_per_ns * 400e6); /* 400ms */
  if( live_gossip ) {
    ctx->delay[ MOCK_CI_IDX ] = LONG_MAX;
  }

  encode_vote( ctx, ctx->twr_buf );

  /* send first epoch of stake info */
  send_test_stake( ctx, &ctx->out_links[ MOCK_STAKE_IDX ] );
}
static void
send_test_main_loop( send_test_ctx_t * ctx ) {
  for(;;) {
    long now = fd_tickcount();
    for( ulong i=0UL; i<MOCK_CNT; i++ ) {
      if( ctx->last_evt[ i ] + ctx->delay[ i ] <= now ) {
        send_test_out_t * out = &ctx->out_links[ i ];
        ctx->out_fns [ i ]( ctx, out );
        ctx->last_evt[ i ] = now;
      }
    }
  }
}

static void
send_test_cmd_fn( args_t *   args ,
                  config_t * config ) {
  send_test_topo( config );

  configure_stage( &fd_cfg_stage_sysctl,           CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_hugetlbfs,        CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_channels, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_offloads, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_ethtool_loopback, CONFIGURE_CMD_INIT, config );

  fd_topo_print_log( 0, &config->topo );

  run_firedancer_init( config, !args->dev.no_init_workspaces, 1 );
  fdctl_setup_netns( config, 1 );

  if( 0==strcmp( config->net.provider, "xdp" ) ) fd_topo_install_xdp( &config->topo, config->net.bind_address_parsed );

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );

  send_test_ctx_t ctx = {0};
  init( &ctx, config );
  send_test_main_loop( &ctx );
}

static void
configure_stage_perm( configure_stage_t const * stage,
                      fd_cap_chk_t *            chk,
                      config_t const *          config ) {
  int enabled = !stage->enabled || stage->enabled( config );
  if( enabled && stage->check( config ).result != CONFIGURE_OK )
    if( stage->init_perm ) stage->init_perm( chk, config );
}

static void
send_test_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                    fd_cap_chk_t *   chk,
                    config_t const * config ) {
  configure_stage_perm( &fd_cfg_stage_sysctl,           chk, config );
  configure_stage_perm( &fd_cfg_stage_hugetlbfs,        chk, config );
  configure_stage_perm( &fd_cfg_stage_ethtool_channels, chk, config );
  configure_stage_perm( &fd_cfg_stage_ethtool_offloads, chk, config );
  configure_stage_perm( &fd_cfg_stage_ethtool_loopback, chk, config );
}

action_t fd_action_send_test = {
  .name = "send_test",
  .args = send_test_cmd_args,
  .fn   = send_test_cmd_fn,
  .perm = send_test_cmd_perm,
};
