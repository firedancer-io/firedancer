#define _GNU_SOURCE

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/events/fd_event_report.h"
#include "../../../disco/net/fd_net_tile.h"
#include "../../../disco/keyguard/fd_keyguard.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../discof/replay/fd_replay_tile.h"
#include "../../../discof/votor/fd_votor_tile.h"
#include "../../../flamenco/gossip/fd_gossip_message.h"
#include "../../../util/env/fd_env.h"
#include "../../../util/net/fd_ip4.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
extern configure_stage_t fd_cfg_stage_keys;

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

#define VOTEST_OUT_GOSSIP (0UL)
#define VOTEST_OUT_REPLAY (1UL)
#define VOTEST_OUT_EPOCH  (2UL)
#define VOTEST_OUT_IPECHO (3UL)
#define VOTEST_OUT_CNT    (4UL)

struct votest_out {
  void * mem;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;
  ulong  mtu;
};
typedef struct votest_out votest_out_t;

struct votest_ctx {
  votest_out_t out[ VOTEST_OUT_CNT ];
  uint         target_ip;
  ushort       target_port;
  int          sent_contact;
  int          sent_ipecho;
  ulong        slot;
  fd_hash_t    parent_hash;
  long         next_contact_ts;
  long         next_slot_ts;
};
typedef struct votest_ctx votest_ctx_t;

static uint   votest_target_ip;
static ushort votest_target_port;

FD_FN_CONST static inline ulong
votest_scratch_align( void ) {
  return alignof(votest_ctx_t);
}

FD_FN_PURE static inline ulong
votest_scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(votest_ctx_t);
}

static void
votest_out_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile,
                 votest_ctx_t *         ctx,
                 ulong                  out_idx,
                 char const *           name ) {
  fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ out_idx ] ];
  if( FD_UNLIKELY( strcmp( link->name, name ) ) )
    FD_LOG_ERR(( "votest output %lu expected %s, got %s", out_idx, name, link->name ));
  ctx->out[ out_idx ].mtu = link->mtu;
  if( FD_LIKELY( link->mtu ) ) {
    ctx->out[ out_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->out[ out_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->out[ out_idx ].mem, link->dcache );
    ctx->out[ out_idx ].wmark  = fd_dcache_compact_wmark ( ctx->out[ out_idx ].mem, link->dcache, link->mtu );
    ctx->out[ out_idx ].chunk  = ctx->out[ out_idx ].chunk0;
  }
}

static void
votest_unprivileged_init( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile ) {
  votest_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(votest_ctx_t) );
  FD_TEST( tile->out_cnt==VOTEST_OUT_CNT );

  votest_out_init( topo, tile, ctx, VOTEST_OUT_GOSSIP, "gossip_out"   );
  votest_out_init( topo, tile, ctx, VOTEST_OUT_REPLAY, "replay_out"   );
  votest_out_init( topo, tile, ctx, VOTEST_OUT_EPOCH,  "replay_epoch" );
  votest_out_init( topo, tile, ctx, VOTEST_OUT_IPECHO, "ipecho_out"   );

  ctx->target_ip   = votest_target_ip;
  ctx->target_port = votest_target_port;
  ctx->slot        = 1UL;
}

static void
votest_publish( votest_ctx_t *      ctx,
                fd_stem_context_t * stem,
                ulong               out_idx,
                ulong               sig,
                void const *        msg,
                ulong               sz ) {
  votest_out_t * out = &ctx->out[ out_idx ];
  ulong ts = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong chunk = 0UL;
  if( FD_LIKELY( sz ) ) {
    chunk = out->chunk;
    fd_memcpy( fd_chunk_to_laddr( out->mem, chunk ), msg, sz );
  }
  fd_stem_publish( stem, out_idx, sig, chunk, sz, 0UL, ts, ts );
  if( FD_LIKELY( out->mtu ) ) out->chunk = fd_dcache_compact_next( out->chunk, out->mtu, out->chunk0, out->wmark );
}

static void
votest_publish_contact( votest_ctx_t *      ctx,
                        fd_stem_context_t * stem ) {
  fd_gossip_update_message_t msg[1];
  memset( msg, 0, sizeof(msg) );
  msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  memset( msg->origin, 0x42, sizeof(msg->origin) );
  msg->wallclock = (ulong)fd_log_wallclock();
  msg->contact_info->idx = 0UL;
  msg->contact_info->value->version.client = FD_GOSSIP_CONTACT_INFO_CLIENT_FIREDANCER;
  msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ] = (fd_gossip_socket_t){
    .is_ipv6 = 0,
    .ip4     = ctx->target_ip,
    .port    = fd_ushort_bswap( ctx->target_port )
  };
  votest_publish( ctx, stem, VOTEST_OUT_GOSSIP, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, msg, FD_GOSSIP_UPDATE_SZ_CONTACT_INFO );
}

static void
votest_publish_slot( votest_ctx_t *      ctx,
                     fd_stem_context_t * stem ) {
  fd_replay_slot_completed_t msg[1];
  memset( msg, 0, sizeof(msg) );
  msg->slot            = ctx->slot;
  msg->parent_slot     = ctx->slot-1UL;
  msg->parent_block_id = ctx->parent_hash;
  memset( msg->block_id.uc, (int)( ctx->slot & 255UL ), sizeof(fd_hash_t) );
  msg->bank_idx        = ctx->slot;

  ctx->parent_hash = msg->block_id;
  ctx->slot++;
  votest_publish( ctx, stem, VOTEST_OUT_REPLAY, REPLAY_SIG_SLOT_COMPLETED, msg, sizeof(fd_replay_slot_completed_t) );
}

static void
votest_after_credit( votest_ctx_t *      ctx,
                     fd_stem_context_t * stem,
                     int *               opt_poll_in,
                     int *               charge_busy ) {
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( !ctx->sent_contact ) ) {
    votest_publish_contact( ctx, stem );
    ctx->sent_contact = 1;
    ctx->next_contact_ts = now + (long)2000000000L;
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( !ctx->sent_ipecho ) ) {
    votest_publish( ctx, stem, VOTEST_OUT_IPECHO, 1UL, NULL, 0UL );
    ctx->sent_ipecho = 1;
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( now>=ctx->next_contact_ts ) ) {
    votest_publish_contact( ctx, stem );
    ctx->next_contact_ts = now + (long)2000000000L;
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( !ctx->next_slot_ts ) ) ctx->next_slot_ts = now;
  if( FD_LIKELY( now<ctx->next_slot_ts ) ) return;

  votest_publish_slot( ctx, stem );
  ctx->next_slot_ts = now + (long)200000000L;
  *opt_poll_in = 0;
  *charge_busy = 1;
}

static int
votest_returnable_frag( votest_ctx_t *      ctx FD_PARAM_UNUSED,
                        ulong              in_idx FD_PARAM_UNUSED,
                        ulong              seq FD_PARAM_UNUSED,
                        ulong              sig FD_PARAM_UNUSED,
                        ulong              chunk FD_PARAM_UNUSED,
                        ulong              sz FD_PARAM_UNUSED,
                        ulong              ctl FD_PARAM_UNUSED,
                        ulong              tsorig FD_PARAM_UNUSED,
                        ulong              tspub FD_PARAM_UNUSED,
                        fd_stem_context_t * stem FD_PARAM_UNUSED ) {
  return 0;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1000000L)

#define STEM_CALLBACK_CONTEXT_TYPE    votest_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(votest_ctx_t)
#define STEM_CALLBACK_AFTER_CREDIT    votest_after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG votest_returnable_frag

#include "../../../disco/stem/fd_stem.c"

static fd_topo_tile_t const *
votest_tile_for_obj( fd_topo_t const *     topo,
                     fd_topo_obj_t const * obj ) {
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( FD_LIKELY( tile->tile_obj_id==obj->id ) ) return tile;
  }

  FD_LOG_ERR(( "tile object %lu has no tile", obj->id ));
  return NULL;
}

static ulong
votest_tile_footprint( fd_topo_t const *     topo,
                       fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = votest_tile_for_obj( topo, obj );
  if( FD_UNLIKELY( !strcmp( tile->name, "votest" ) ) ) return votest_scratch_footprint( tile );

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_LIKELY( runner.scratch_footprint ) ) return runner.scratch_footprint( tile );
  return 0UL;
}

static ulong
votest_tile_align( fd_topo_t const *     topo,
                   fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = votest_tile_for_obj( topo, obj );
  if( FD_UNLIKELY( !strcmp( tile->name, "votest" ) ) ) return votest_scratch_align();

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_LIKELY( runner.scratch_align ) ) return runner.scratch_align();
  return 1UL;
}

static ulong
votest_tile_loose( fd_topo_t const *     topo,
                   fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = votest_tile_for_obj( topo, obj );
  if( FD_UNLIKELY( !strcmp( tile->name, "votest" ) ) ) return 0UL;

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_UNLIKELY( runner.loose_footprint ) ) return runner.loose_footprint( tile );
  return 0UL;
}

static fd_topo_obj_callbacks_t fd_obj_cb_votest_tile = {
  .name      = "tile",
  .footprint = votest_tile_footprint,
  .align     = votest_tile_align,
  .loose     = votest_tile_loose,
  .new       = NULL,
};

static void
votest_callbacks( fd_topo_obj_callbacks_t ** callbacks,
                  ulong                       callbacks_cnt ) {
  ulong i;
  for( i=0UL; CALLBACKS[ i ]; i++ ) {
    if( FD_UNLIKELY( i+1UL>=callbacks_cnt ) ) FD_LOG_ERR(( "too many topology callbacks" ));
    callbacks[ i ] = CALLBACKS[ i ];
    if( FD_UNLIKELY( !strcmp( CALLBACKS[ i ]->name, "tile" ) ) ) callbacks[ i ] = &fd_obj_cb_votest_tile;
  }
  callbacks[ i ] = NULL;
}

static void
votest_run_main( fd_topo_t * topo ) {
  ulong tile_id = fd_topo_find_tile( topo, "votest", 0UL );
  FD_TEST( tile_id!=ULONG_MAX );

  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  fd_topo_fill_tile( topo, tile );

  FD_TEST( tile->metrics );
  fd_metrics_register( tile->metrics );
  fd_event_register( topo, tile );

  votest_unprivileged_init( topo, tile );
  stem_run( topo, tile );
  FD_LOG_ERR(( "votest stem_run returned" ));
}

static void
parse_ip4_port( char const * s,
                uint *       ip,
                ushort *     port ) {
  char buf[ IP4_PORT_STR_MAX ];
  fd_cstr_ncpy( buf, s, sizeof(buf) );
  char * colon = strrchr( buf, ':' );
  if( FD_UNLIKELY( !colon ) ) FD_LOG_ERR(( "invalid --target `%s`, expected ip:port", s ));
  *colon = '\0';
  char const * port_cstr = colon+1;
  char * end = NULL;
  errno = 0;
  ulong port_ulong = strtoul( port_cstr, &end, 10 );
  if( FD_UNLIKELY( errno || !end || *end || port_ulong>USHORT_MAX || !port_ulong ) )
    FD_LOG_ERR(( "invalid --target port `%s`", port_cstr ));
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( buf, ip ) ) ) FD_LOG_ERR(( "invalid --target ip `%s`", buf ));
  *port = (ushort)port_ulong;
}

static void
votor_test_cmd_args( int *    pargc,
                     char *** pargv,
                     args_t * args ) {
  char const * target = fd_env_strip_cmdline_cstr( pargc, pargv, "--target", NULL, "64.130.37.11:9011" );
  fd_cstr_ncpy( args->votor_test.target, target, sizeof(args->votor_test.target) );
  ulong local_port = fd_env_strip_cmdline_ulong( pargc, pargv, "--local-port", NULL, 9011UL );
  if( FD_UNLIKELY( local_port>USHORT_MAX || !local_port ) ) FD_LOG_ERR(( "invalid --local-port `%lu`", local_port ));
  args->votor_test.local_port = (ushort)local_port;
}

static void
votor_test_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                     fd_cap_chk_t *   chk,
                     config_t const * config ) {
  args_t configure_args = { .configure.command = CONFIGURE_CMD_INIT };
  configure_args.configure.stages[ 0 ] = &fd_cfg_stage_hugetlbfs;
  configure_args.configure.stages[ 1 ] = &fd_cfg_stage_keys;
  configure_args.configure.stages[ 2 ] = NULL;
  configure_cmd_perm( &configure_args, chk, config );
  run_cmd_perm( NULL, chk, config );
}

static void
votor_test_topo( config_t * config,
                 uint       target_ip,
                 ushort     target_port,
                 ushort     local_port ) {
  config->development.sandbox  = 0;
  config->development.no_clone = 1;
  fd_cstr_ncpy( config->net.provider, "socket", sizeof(config->net.provider) );
  config->layout.net_tile_count = 1U;

  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );
  topo->max_page_size           = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) tile_to_cpu[ i ] = ULONG_MAX;

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "votor" );
  fd_topob_wksp( topo, "votest" );
  fd_topob_wksp( topo, "gossip_out" );
  fd_topob_wksp( topo, "replay_out" );
  fd_topob_wksp( topo, "replay_epoch" );
  fd_topob_wksp( topo, "ipecho_out" );
  fd_topob_wksp( topo, "votor_out" );
  fd_topob_wksp( topo, "net_votor" );
  fd_topob_wksp( topo, "sign" );
  fd_topob_wksp( topo, "votor_sign" );
  fd_topob_wksp( topo, "sign_votor" );

  fd_topos_net_tiles( topo, 1UL, &config->net, config->tiles.netlink.max_routes,
                      config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors,
                      0, tile_to_cpu );

  fd_topob_link( topo, "gossip_out",   "gossip_out",   1024UL, sizeof(fd_gossip_update_message_t), 1UL );
  fd_topob_link( topo, "replay_out",   "replay_out",   1024UL, sizeof(fd_replay_message_t),        1UL );
  fd_topob_link( topo, "replay_epoch", "replay_epoch", 2UL,    FD_EPOCH_OUT_MTU,                   1UL );
  fd_topob_link( topo, "ipecho_out",   "ipecho_out",   2UL,    0UL,                                1UL );
  fd_topob_link( topo, "votor_out",    "votor_out",    1024UL, 1024UL,                             2UL );
  fd_topob_link( topo, "votor_net",    "net_votor",    config->net.ingress_buffer_size, FD_NET_MTU, 1UL );
  fd_topob_link( topo, "votor_sign",   "votor_sign",   128UL, FD_KEYGUARD_SIGN_REQ_MTU,             1UL );
  fd_topob_link( topo, "sign_votor",   "sign_votor",   128UL, sizeof(fd_ed25519_sig_t),             1UL );
  fd_topos_net_rx_link( topo, "net_alpenglow", 0UL, config->net.ingress_buffer_size );

  fd_topob_tile( topo, "metric", "metric", "metric_in", ULONG_MAX, 0, 0, 0 );
  fd_topob_tile( topo, "votest", "votest", "metric_in", ULONG_MAX, 1, 0, 0 );
  votest_target_ip   = target_ip;
  votest_target_port = target_port;

  fd_topo_tile_t * votor = fd_topob_tile( topo, "votor", "votor", "metric_in", ULONG_MAX, 0, 1, 0 );
  votor->tower.max_live_slots = 1024UL;
  votor->tower.skip_own_vote_ingest = 1;
  fd_cstr_ncpy( votor->tower.identity_key, config->paths.identity_key, sizeof(votor->tower.identity_key) );
  votor->quic.max_concurrent_connections = config->tiles.quic.max_concurrent_connections;
  votor->quic.max_concurrent_handshakes  = config->tiles.quic.max_concurrent_handshakes;
  votor->quic.idle_timeout_millis        = config->tiles.quic.idle_timeout_millis;
  votor->quic.ack_delay_millis           = config->tiles.quic.ack_delay_millis;
  votor->quic.retry                      = 0;
  votor->quic.alpenglow_ip_addr          = config->net.ip_addr;
  votor->quic.alpenglow_listen_port      = local_port;
  fd_cstr_ncpy( votor->quic.key_log_path, config->firedancer.development.votor.ssl_key_log_file, sizeof(votor->quic.key_log_path) );

  fd_topo_tile_t * sign = fd_topob_tile( topo, "sign", "sign", "metric_in", ULONG_MAX, 0, 1, 0 );
  fd_cstr_ncpy( sign->sign.identity_key_path, config->paths.identity_key, sizeof(sign->sign.identity_key_path) );

  ulong sock_id = fd_topo_find_tile( topo, "sock", 0UL );
  if( FD_LIKELY( sock_id!=ULONG_MAX ) ) topo->tiles[ sock_id ].sock.net.alpenglow_listen_port = local_port;
  ulong net_id = fd_topo_find_tile( topo, "net", 0UL );
  if( FD_LIKELY( net_id!=ULONG_MAX ) ) topo->tiles[ net_id ].net.alpenglow_listen_port = local_port;

  fd_topob_tile_out( topo, "votest", 0UL, "gossip_out",   0UL );
  fd_topob_tile_out( topo, "votest", 0UL, "replay_out",   0UL );
  fd_topob_tile_out( topo, "votest", 0UL, "replay_epoch", 0UL );
  fd_topob_tile_out( topo, "votest", 0UL, "ipecho_out",   0UL );
  fd_topob_tile_in ( topo, "votest", 0UL, "metric_in", "votor_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "net_alpenglow", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "replay_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "gossip_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "replay_epoch",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "ipecho_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "votor", 0UL, "votor_out",     0UL );
  fd_topob_tile_out( topo, "votor", 0UL, "votor_net",     0UL );
  fd_topos_tile_in_net( topo, "metric_in", "votor_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_in ( topo, "sign",  0UL, "metric_in", "votor_sign", 0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_out( topo, "votor", 0UL,              "votor_sign", 0UL );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "sign_votor", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  fd_topob_tile_out( topo, "sign",  0UL,              "sign_votor", 0UL );

  fd_topos_net_tile_finish( topo, 0UL );
  fd_topo_obj_callbacks_t * callbacks[ 64 ];
  votest_callbacks( callbacks, sizeof(callbacks)/sizeof(callbacks[ 0 ]) );
  fd_topob_finish( topo, callbacks );
  fd_topo_print_log( 1, topo );
}

static void
votor_test_cmd_fn( args_t *   args,
                   config_t * config ) {
  uint   target_ip;
  ushort target_port;
  parse_ip4_port( args->votor_test.target, &target_ip, &target_port );

  ushort local_port = args->votor_test.local_port ? args->votor_test.local_port : config->tiles.alpenglow.listen_port;
  if( FD_UNLIKELY( !local_port ) ) local_port = 9011U;

  votor_test_topo( config, target_ip, target_port, local_port );

  configure_stage( &fd_cfg_stage_hugetlbfs, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_keys,      CONFIGURE_CMD_INIT, config );
  fdctl_check_configure( config );
  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  FD_LOG_NOTICE(( "votor-test target " FD_IP4_ADDR_FMT ":%u local_port=%u",
                  FD_IP4_ADDR_FMT_ARGS( target_ip ), (uint)target_port, (uint)local_port ));
  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run );
  votest_run_main( &config->topo );
}

static void
votor_test_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--target",     "<ip:port>", "Alpenglow QUIC peer to connect to. Defaults to 64.130.37.11:9011" );
  fd_action_help_arg( help, "--local-port", "<port>",    "Local Alpenglow UDP port. Defaults to 9011" );
}

action_t fd_action_votor_test = {
  .name        = "votor-test",
  .args        = votor_test_cmd_args,
  .fn          = votor_test_cmd_fn,
  .perm        = votor_test_cmd_perm,
  .description = "Run a mocked Votor QUIC smoke topology",
  .usage       = "votor-test [--target <ip:port>] [--local-port <port>]",
  .args_help   = votor_test_args_help
};
