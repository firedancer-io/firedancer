/* firedancer-dev votor -- minimal topology that ingests Alpenglow votes
   from the live cluster and builds certificates, logging them.

   Tiles: metric net sign | gossvf gossip ipecho | epoch | votor

   gossip is not optional: peers only open an Alpenglow QUIC connection to
   us if our identity is in their epoch staked-node map AND our gossip
   ContactInfo advertises an alpenglow socket (agave
   StakedValidatorsCache::refresh_cache_entry).  Without a gossip tile
   nothing is ever sent to us.

   The votor tile's consensus path is gated on an epoch validator set,
   which in production only the replay tile publishes.  The epoch tile stands in
   for it: it loads a dumped set (stakes + compressed BLS pubkeys) from a
   file and publishes it on replay_epoch, plus a synthetic replayed tip on
   replay_out -- update_epoch_vtrs installs a set but never activates it;
   only set_active_epoch does, driven from the replayed tip.

   This thread draws the live view: it polls votor_out and renders the
   per-slot stake aggregation, the certs that form and the notarized /
   finalized / rooted verdicts.  The votor tile is told to echo the votes
   and certs it RECEIVES onto votor_out as well
   (quic.alpenglow_publish_rx), which is dev-only -- in production that
   link's consumers are reliable, so the extra frags would backpressure
   consensus.

   Keys: [space] pause  [q] quit
   --frames N renders N frames and exits, for capturing into a log. */

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
#include "../../../flamenco/leaders/fd_leaders_base.h"
#include "../../../flamenco/stakes/fd_stake_weight.h"
#include "../../../util/env/fd_env.h"
#include "../../../util/net/fd_ip4.h"

#include "core_subtopo.h"
#include "votor_monitor.h"
#include "gossip.h"

#include "../../../alpenglow/consensus/ag_pool.h"
#include "../../../alpenglow/consensus/ag_votor.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../discof/votor/fd_votor_tile.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
extern configure_stage_t fd_cfg_stage_keys;

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

void
resolve_gossip_entrypoints( config_t * config );

/* Epoch dump file, written by contrib/alpenglow/dump_epoch.py.  Little
   endian, header followed by voter_cnt records ordered arbitrarily (the
   votor re-ranks with ag_epoch_info_rank).  Dev tool: the two files are
   expected to move together, so a mismatch just fails to parse. */

struct __attribute__((packed)) hdr {
  ulong               epoch;
  ulong               start_slot;
  ulong               slot_cnt;
  ulong               tip_slot;   /* slot to start the synthetic tip from */
  ulong               voter_cnt;
  fd_epoch_schedule_t epoch_schedule;
};
typedef struct hdr hdr_t;

struct __attribute__((packed)) voter {
  fd_pubkey_t vote_key;
  fd_pubkey_t id_key;
  ulong       stake;
  uchar       bls[ FD_EPOCH_INFO_BLS_PUBKEY_SZ ];
};
typedef struct voter voter_t;

/* Locked against contrib/alpenglow/dump_epoch.py. */
FD_STATIC_ASSERT( sizeof(hdr_t)==73UL,    hdr_sz   );
FD_STATIC_ASSERT( sizeof(voter_t)==120UL, voter_sz );

#define OUT_EPOCH  (0UL)
#define OUT_REPLAY (1UL)
#define OUT_CNT    (2UL)

struct out {
  void * mem;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;
  ulong  mtu;
};
typedef struct out out_t;

struct ctx {
  out_t     out[ OUT_CNT ];
  hdr_t     hdr;
  voter_t   voters[ FD_EPOCH_INFO_MAX_VOTERS ];

  ulong     slot;
  fd_hash_t parent_block_id;
  long      next_epoch_ts;
  long      next_slot_ts;
  long      slot_period_ns;
};
typedef struct ctx ctx_t;

static char  epoch_file[ PATH_MAX ];
static ulong slot_period_ns;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(ctx_t);
}

static void
out_init( fd_topo_t const *      topo,
          fd_topo_tile_t const * tile,
          ctx_t *                ctx,
          ulong                  out_idx,
          char const *           name ) {
  fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ out_idx ] ];
  if( FD_UNLIKELY( strcmp( link->name, name ) ) )
    FD_LOG_ERR(( "epoch output %lu expected %s, got %s", out_idx, name, link->name ));
  ctx->out[ out_idx ].mtu    = link->mtu;
  ctx->out[ out_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out[ out_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->out[ out_idx ].mem, link->dcache );
  ctx->out[ out_idx ].wmark  = fd_dcache_compact_wmark ( ctx->out[ out_idx ].mem, link->dcache, link->mtu );
  ctx->out[ out_idx ].chunk  = ctx->out[ out_idx ].chunk0;
}

static void
load_epoch( ctx_t * ctx ) {
  FILE * f = fopen( epoch_file, "rb" );
  if( FD_UNLIKELY( !f ) )
    FD_LOG_ERR(( "fopen(%s) failed (%i-%s); generate it with contrib/alpenglow/dump_epoch.py",
                 epoch_file, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( 1UL!=fread( &ctx->hdr, sizeof(hdr_t), 1UL, f ) ) )
    FD_LOG_ERR(( "%s: truncated header", epoch_file ));
  if( FD_UNLIKELY( !ctx->hdr.voter_cnt || ctx->hdr.voter_cnt>FD_EPOCH_INFO_MAX_VOTERS ) )
    FD_LOG_ERR(( "%s: voter_cnt %lu out of range", epoch_file, ctx->hdr.voter_cnt ));

  if( FD_UNLIKELY( ctx->hdr.voter_cnt!=fread( ctx->voters, sizeof(voter_t), ctx->hdr.voter_cnt, f ) ) )
    FD_LOG_ERR(( "%s: truncated voter records", epoch_file ));
  fclose( f );

  FD_LOG_NOTICE(( "epoch loaded %s: epoch %lu, %lu voters, start_slot %lu, tip_slot %lu",
                  epoch_file, ctx->hdr.epoch, ctx->hdr.voter_cnt, ctx->hdr.start_slot, ctx->hdr.tip_slot ));
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(ctx_t) );
  FD_TEST( tile->out_cnt==OUT_CNT );

  out_init( topo, tile, ctx, OUT_EPOCH,  "replay_epoch" );
  out_init( topo, tile, ctx, OUT_REPLAY, "replay_out"   );

  load_epoch( ctx );
  ctx->slot           = ctx->hdr.tip_slot;
  ctx->slot_period_ns = (long)slot_period_ns;
}

/* publish_epoch emits the loaded validator set.  Republished
   periodically: update_epoch_vtrs re-ranks the same epoch in place, so it
   is idempotent, and it covers the votor joining the link late. */

static void
publish_epoch( ctx_t *             ctx,
               fd_stem_context_t * stem ) {
  out_t *               out = &ctx->out[ OUT_EPOCH ];
  fd_epoch_info_msg_t * msg = fd_chunk_to_laddr( out->mem, out->chunk );

  msg->epoch             = ctx->hdr.epoch;
  msg->staked_vote_cnt   = ctx->hdr.voter_cnt;
  msg->staked_id_cnt     = 0UL; /* votor reads stake weights + BLS keys only */
  msg->start_slot        = ctx->hdr.start_slot;
  msg->slot_cnt          = ctx->hdr.slot_cnt;
  msg->excluded_id_stake = 0UL;
  msg->epoch_schedule    = ctx->hdr.epoch_schedule;
  memset( &msg->features, 0, sizeof(msg->features) );

  fd_vote_stake_weight_t * sw  = fd_epoch_info_msg_stake_weights( msg );
  uchar *                  bls = fd_epoch_info_msg_bls_pubkeys  ( msg );
  for( ulong i=0UL; i<ctx->hdr.voter_cnt; i++ ) {
    voter_t const * v = &ctx->voters[ i ];
    sw[ i ].vote_key = v->vote_key;
    sw[ i ].id_key   = v->id_key;
    sw[ i ].stake    = v->stake;
    fd_memcpy( bls + i*FD_EPOCH_INFO_BLS_PUBKEY_SZ, v->bls, FD_EPOCH_INFO_BLS_PUBKEY_SZ );
  }

  ulong sz = fd_epoch_info_msg_sz( ctx->hdr.voter_cnt, 0UL );
  ulong ts = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, OUT_EPOCH, 0UL, out->chunk, sz, 0UL, ts, ts );
  out->chunk = fd_dcache_compact_next( out->chunk, out->mtu, out->chunk0, out->wmark );
}

/* publish_slot emits a synthetic replayed tip.  The votor needs a
   tip in the dumped epoch to activate its validator set; the block ids are
   fabricated, so notarization of these slots is meaningless -- what is
   under test is ingest, signature verification and cert aggregation of the
   real votes arriving over QUIC. */

static void
publish_slot( ctx_t *             ctx,
              fd_stem_context_t * stem ) {
  out_t *                      out = &ctx->out[ OUT_REPLAY ];
  fd_replay_slot_completed_t * msg = fd_chunk_to_laddr( out->mem, out->chunk );

  ulong slots_per_epoch = ctx->hdr.epoch_schedule.slots_per_epoch;
  memset( msg, 0, sizeof(fd_replay_slot_completed_t) );
  msg->slot            = ctx->slot;
  msg->parent_slot     = ctx->slot-1UL;
  msg->root_slot       = ctx->hdr.start_slot;
  msg->epoch           = ctx->hdr.epoch;
  msg->slots_per_epoch = slots_per_epoch;
  msg->slot_in_epoch   = ctx->slot - ctx->hdr.start_slot;
  msg->parent_block_id = ctx->parent_block_id;
  memset( msg->block_id.uc, (int)( ctx->slot & 255UL ), sizeof(fd_hash_t) );

  ctx->parent_block_id = msg->block_id;
  ctx->slot++;

  ulong ts = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, OUT_REPLAY, REPLAY_SIG_SLOT_COMPLETED, out->chunk,
                   sizeof(fd_replay_slot_completed_t), 0UL, ts, ts );
  out->chunk = fd_dcache_compact_next( out->chunk, out->mtu, out->chunk0, out->wmark );
}

static void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  long now = fd_log_wallclock();

  if( FD_UNLIKELY( now>=ctx->next_epoch_ts ) ) {
    publish_epoch( ctx, stem );
    ctx->next_epoch_ts = now + (long)5e9;
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( !ctx->next_slot_ts ) ) ctx->next_slot_ts = now;
  if( FD_LIKELY( now<ctx->next_slot_ts ) ) return;

  publish_slot( ctx, stem );
  ctx->next_slot_ts = now + ctx->slot_period_ns;
  *opt_poll_in = 0;
  *charge_busy = 1;
}

static int
returnable_frag( ctx_t *             ctx  FD_PARAM_UNUSED,
                 ulong               in_idx FD_PARAM_UNUSED,
                 ulong               seq  FD_PARAM_UNUSED,
                 ulong               sig  FD_PARAM_UNUSED,
                 ulong               chunk FD_PARAM_UNUSED,
                 ulong               sz   FD_PARAM_UNUSED,
                 ulong               ctl  FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem FD_PARAM_UNUSED ) {
  return 0;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1000000L)

#define STEM_CALLBACK_CONTEXT_TYPE    ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(ctx_t)
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../../disco/stem/fd_stem.c"

static fd_topo_tile_t const *
tile_for_obj( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( FD_LIKELY( tile->tile_obj_id==obj->id ) ) return tile;
  }
  FD_LOG_ERR(( "tile object %lu has no tile", obj->id ));
  return NULL;
}

static ulong
obj_footprint( fd_topo_t const *     topo,
               fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = tile_for_obj( topo, obj );
  if( FD_UNLIKELY( !strcmp( tile->name, "epoch" ) ) ) return scratch_footprint( tile );

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_LIKELY( runner.scratch_footprint ) ) return runner.scratch_footprint( tile );
  return 0UL;
}

static ulong
obj_align( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = tile_for_obj( topo, obj );
  if( FD_UNLIKELY( !strcmp( tile->name, "epoch" ) ) ) return scratch_align();

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_LIKELY( runner.scratch_align ) ) return runner.scratch_align();
  return 1UL;
}

static ulong
obj_loose( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = tile_for_obj( topo, obj );
  if( FD_UNLIKELY( !strcmp( tile->name, "epoch" ) ) ) return 0UL;

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_UNLIKELY( runner.loose_footprint ) ) return runner.loose_footprint( tile );
  return 0UL;
}

static fd_topo_obj_callbacks_t obj_cb_tile = {
  .name      = "tile",
  .footprint = obj_footprint,
  .align     = obj_align,
  .loose     = obj_loose,
  .new       = NULL,
};

static void
install_callbacks( fd_topo_obj_callbacks_t ** callbacks,
                   ulong                      callbacks_cnt ) {
  ulong i;
  for( i=0UL; CALLBACKS[ i ]; i++ ) {
    if( FD_UNLIKELY( i+1UL>=callbacks_cnt ) ) FD_LOG_ERR(( "too many topology callbacks" ));
    callbacks[ i ] = CALLBACKS[ i ];
    if( FD_UNLIKELY( !strcmp( CALLBACKS[ i ]->name, "tile" ) ) ) callbacks[ i ] = &obj_cb_tile;
  }
  callbacks[ i ] = NULL;
}

static void
votor_topo( config_t * config ) {
  resolve_gossip_entrypoints( config );

  /* Socket provider: this command only runs the hugetlbfs / keys
     configure stages, not the XDP ones, and vote traffic is far below
     what XDP is for. */
  fd_cstr_ncpy( config->net.provider, "socket", sizeof(config->net.provider) );
  config->development.sandbox  = 0;
  config->development.no_clone = 1;

  /* One net tile only.  The sock tile assigns its receive sockets to
     absolute file descriptors starting at RX_SOCK_FD_MIN with no kind_id
     offset, so a second sock tile in this single-process topology races to
     dup3 onto the same fds ("file descriptor N already exists"). */
  config->layout.net_tile_count = 1U;

  /* Only gossip and alpenglow listen; everything else is off. */
  config->tiles.shred.shred_listen_port             = 0U;
  config->tiles.quic.quic_transaction_listen_port   = 0U;
  config->tiles.quic.regular_transaction_listen_port= 0U;
  config->tiles.repair.repair_client_listen_port    = 0U;
  config->tiles.rserve.repair_serve_listen_port     = 0U;
  config->tiles.txsend.txsend_src_port              = 0U;

  static ulong tile_to_cpu[ FD_TILE_MAX ] = {0};

  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size           = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  fd_core_subtopo  ( config, tile_to_cpu );
  fd_gossip_subtopo( config, tile_to_cpu );

  ushort listen_port = config->tiles.alpenglow.listen_port;
  ushort client_port = config->tiles.alpenglow.client_port;

  /* Advertise the alpenglow socket in our ContactInfo -- without it no
     peer will ever dial us (fd_gossip_subtopo does not set this; the
     production topology does). */
  ulong gossip_id = fd_topo_find_tile( topo, "gossip", 0UL );
  FD_TEST( gossip_id!=ULONG_MAX );
  topo->tiles[ gossip_id ].gossip.ports.alpen = listen_port;

  for( ulong i=0UL; i<config->layout.net_tile_count; i++ ) {
    ulong net_id = fd_topo_find_tile( topo, "net", i );
    if( net_id==ULONG_MAX ) net_id = fd_topo_find_tile( topo, "sock", i );
    FD_TEST( net_id!=ULONG_MAX );
    topo->tiles[ net_id ].net.alpenglow_listen_port        = listen_port;
    topo->tiles[ net_id ].net.alpenglow_client_listen_port = client_port;
  }

  /* epoch: stands in for replay's epoch / tip publications. */
  fd_topob_wksp( topo, "epoch"      );
  fd_topob_wksp( topo, "replay_epoch" );
  fd_topob_wksp( topo, "replay_out"   );
  fd_topob_link( topo, "replay_epoch", "replay_epoch", 128UL,  FD_EPOCH_OUT_MTU,            1UL );
  fd_topob_link( topo, "replay_out",   "replay_out",   1024UL, sizeof(fd_replay_message_t), 1UL );

  /* is_agave=1 so fd_topo_run_single_process( .., 0, .. ) skips it: the
     epoch tile is command-local and is not in the fdctl tile registry, so
     main runs it itself (votor_run_epoch). */
  fd_topob_tile   ( topo, "epoch", "epoch", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0, 0 );
  fd_topob_tile_out( topo, "epoch", 0UL, "replay_epoch", 0UL );
  fd_topob_tile_out( topo, "epoch", 0UL, "replay_out",   0UL );

  /* votor */
  fd_topob_wksp( topo, "votor"      );
  fd_topob_wksp( topo, "votor_out"  );
  fd_topob_wksp( topo, "net_votor"  );
  fd_topob_wksp( topo, "votor_sign" );
  fd_topob_wksp( topo, "sign_votor" );

  fd_topob_link( topo, "votor_out",  "votor_out",  16384UL, 1024UL,                   2UL )->permit_no_consumers = 1;
  fd_topob_link( topo, "votor_net",  "net_votor",  config->net.ingress_buffer_size, FD_NET_MTU, 1UL );
  fd_topob_link( topo, "votor_sign", "votor_sign", 128UL,   FD_KEYGUARD_SIGN_REQ_MTU, 1UL );
  fd_topob_link( topo, "sign_votor", "sign_votor", 128UL,   192UL,                    1UL );
  for( ulong i=0UL; i<config->layout.net_tile_count; i++ )
    fd_topos_net_rx_link( topo, "net_alpenglow", i, config->net.ingress_buffer_size );

  fd_topo_tile_t * votor = fd_topob_tile( topo, "votor", "votor", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 1, 0 );
  votor->quic.alpenglow_publish_rx = 1; /* dev: let the viewer see peer votes/certs */
  votor->tower.max_live_slots = 1024UL;
  fd_cstr_ncpy( votor->tower.identity_key, config->paths.identity_key, sizeof(votor->tower.identity_key) );
  votor->quic.max_concurrent_connections = config->tiles.quic.max_concurrent_connections;
  votor->quic.max_concurrent_handshakes  = config->tiles.quic.max_concurrent_handshakes;
  votor->quic.idle_timeout_millis        = config->tiles.quic.idle_timeout_millis;
  votor->quic.ack_delay_millis           = config->tiles.quic.ack_delay_millis;
  votor->quic.retry                      = 0;
  votor->quic.alpenglow_ip_addr            = config->net.ip_addr;
  votor->quic.alpenglow_listen_port        = listen_port;
  votor->quic.alpenglow_client_listen_port = client_port;
  fd_cstr_ncpy( votor->quic.key_log_path, config->firedancer.development.votor.ssl_key_log_file, sizeof(votor->quic.key_log_path) );

  for( ulong i=0UL; i<config->layout.net_tile_count; i++ )
    fd_topob_tile_in( topo, "votor", 0UL, "metric_in", "net_alpenglow", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "replay_out",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "gossip_out",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "replay_epoch", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "ipecho_out",   0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "votor", 0UL,              "votor_out",    0UL );
  fd_topob_tile_out( topo, "votor", 0UL,              "votor_net",    0UL );
  fd_topos_tile_in_net( topo, "metric_in", "votor_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_in ( topo, "sign",  0UL, "metric_in", "votor_sign", 0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_out( topo, "votor", 0UL,              "votor_sign", 0UL );
  fd_topob_tile_out( topo, "sign",  0UL,              "sign_votor", 0UL );
  fd_topob_tile_in ( topo, "votor", 0UL, "metric_in", "sign_votor", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );

  /* gossip.h contract: sign_gossip must be gossip's last in_link. */
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "sign_gossip", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );

  for( ulong i=0UL; i<config->layout.net_tile_count; i++ ) fd_topos_net_tile_finish( topo, i );

  fd_topo_obj_callbacks_t * callbacks[ 64 ];
  install_callbacks( callbacks, sizeof(callbacks)/sizeof(callbacks[ 0 ]) );
  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, callbacks );
}

static fd_topo_run_tile_t epoch_run_tile = {
  .name              = "epoch",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

/* votor_tile_run resolves the local epoch tile; everything else is a
   normal firedancer tile. */

static fd_topo_run_tile_t
votor_tile_run( fd_topo_tile_t const * tile ) {
  if( FD_UNLIKELY( !strcmp( tile->name, "epoch" ) ) ) return epoch_run_tile;
  return fdctl_tile_run( tile );
}

static void FD_FN_UNUSED
votor_run_epoch( fd_topo_t * topo ) {
  ulong tile_id = fd_topo_find_tile( topo, "epoch", 0UL );
  FD_TEST( tile_id!=ULONG_MAX );

  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  fd_topo_fill_tile( topo, tile );

  FD_TEST( tile->metrics );
  fd_metrics_register( tile->metrics );
  fd_event_register( topo, tile );

  unprivileged_init( topo, tile );
  stem_run( topo, tile );
  FD_LOG_ERR(( "epoch stem_run returned" ));
}

static void
votor_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args FD_PARAM_UNUSED ) {
  char const * file = fd_env_strip_cmdline_cstr( pargc, pargv, "--epoch-file", NULL, "epoch.bin" );
  fd_cstr_ncpy( epoch_file, file, sizeof(epoch_file) );
  slot_period_ns = fd_env_strip_cmdline_ulong( pargc, pargv, "--slot-period-ns", NULL, 216000000UL );

  votor_monitor_args( pargc, pargv );
}

static void
votor_cmd_perm( args_t *         args FD_PARAM_UNUSED,
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
votor_cmd_fn( args_t *   args FD_PARAM_UNUSED,
              config_t * config ) {
  votor_topo( config );

  configure_stage( &fd_cfg_stage_hugetlbfs, CONFIGURE_CMD_INIT, config );
  configure_stage( &fd_cfg_stage_keys,      CONFIGURE_CMD_INIT, config );
  fdctl_check_configure( config );
  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  FD_LOG_NOTICE(( "votor ingest topology: alpenglow port %u, epoch file %s",
                  (uint)config->tiles.alpenglow.listen_port, epoch_file ));

  /* Every tile, including the local epoch tile, runs under the topology
     runner; this thread draws the live view off votor_out. */
  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, votor_tile_run );
  votor_monitor_run( config );
}

static void
votor_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--epoch-file",     "<path>", "Epoch validator-set dump from contrib/alpenglow/dump_epoch.py. Defaults to epoch.bin" );
  fd_action_help_arg( help, "--slot-period-ns", "<ns>",   "Synthetic tip advance period. Defaults to 216000000 (216ms)" );
}

action_t fd_action_votor = {
  .name        = "votor",
  .args        = votor_cmd_args,
  .fn          = votor_cmd_fn,
  .perm        = votor_cmd_perm,
  .description = "Ingest Alpenglow votes and build certs with a minimal topology",
  .usage       = "votor [--epoch-file <path>] [--slot-period-ns <ns>]",
  .args_help   = votor_args_help
};

