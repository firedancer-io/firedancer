#include "fd_gossip_tile.h"
#include "../../disco/metrics/fd_metrics.h"
#include "generated/fd_gossip_tile_seccomp.h"

#include "../../flamenco/gossip/crds/fd_crds.h"
#include "../../flamenco/gossip/fd_gossip_out.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../disco/fd_txn_m.h"

#define IN_KIND_GOSSVF        (0)
#define IN_KIND_SHRED_VERSION (1)
#define IN_KIND_SIGN          (2)
#define IN_KIND_SEND          (3)
#define IN_KIND_STAKE         (4)

/* Symbols exported by version.c */
extern ulong const firedancer_major_version;
extern ulong const firedancer_minor_version;
extern ulong const firedancer_patch_version;
extern uint  const firedancer_commit_ref;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t)                                                  );
  l = FD_LAYOUT_APPEND( l, fd_gossip_align(),             fd_gossip_footprint( tile->gossip.max_entries, tile->gossip.entrypoints_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t),    MAX_STAKED_LEADERS*sizeof(fd_stake_weight_t)                                  );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
gossip_send_fn( void *                ctx,
                fd_stem_context_t *   stem,
                uchar const *         payload,
                ulong                 payload_sz,
                fd_ip4_port_t const * peer_address,
                ulong                 tsorig ) {
  fd_gossip_tile_ctx_t * gossip_ctx = (fd_gossip_tile_ctx_t *)ctx;

  uchar * packet          = (uchar *)fd_chunk_to_laddr( gossip_ctx->net_out->mem, gossip_ctx->net_out->chunk );
  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *gossip_ctx->net_out_hdr;

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  fd_udp_hdr_t * udp = hdr->udp;

  ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t) + sizeof(fd_ip4_hdr_t)) );
  udp->net_len     = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  ip4->daddr       = peer_address->addr;
  udp->net_dport   = peer_address->port;
  ip4->net_id      = fd_ushort_bswap( gossip_ctx->net_id++ );
  ip4->check       = fd_ip4_hdr_check_fast( ip4 );
  udp->check       = 0;

  /* TODO: Construct payload in place to avoid memcpy here. */
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );

  ulong tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig       = fd_disco_netmux_sig( peer_address->addr, peer_address->port, peer_address->addr, DST_PROTO_OUTGOING, 0UL /* ignored */ );
  ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);

  fd_stem_publish( stem, gossip_ctx->net_out->idx, sig, gossip_ctx->net_out->chunk, packet_sz, 0UL, tspub, tsorig );
  gossip_ctx->net_out->chunk = fd_dcache_compact_next( gossip_ctx->net_out->chunk, packet_sz, gossip_ctx->net_out->chunk0, gossip_ctx->net_out->wmark );
}

static void
gossip_sign_fn( void *        ctx,
                uchar const * data,
                ulong         data_sz,
                int           sign_type,
                uchar *       out_signature ) {
  fd_gossip_tile_ctx_t * gossip_ctx = (fd_gossip_tile_ctx_t *)ctx;
  fd_keyguard_client_sign( gossip_ctx->keyguard_client, out_signature, data, data_sz, sign_type );
}

static void
gossip_ping_tracker_change_fn( void *        _ctx,
                               uchar const * peer_pubkey,
                               fd_ip4_port_t peer_address,
                               long          now,
                               int           change_type ) {
  (void)now;

  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;

  fd_gossip_ping_update_t * ping_update = (fd_gossip_ping_update_t *)fd_chunk_to_laddr( ctx->gossvf_out->mem, ctx->gossvf_out->chunk );
  fd_memcpy( ping_update->pubkey.uc, peer_pubkey, 32UL );
  ping_update->gossip_addr.l = peer_address.l;
  ping_update->remove = change_type!=FD_PING_TRACKER_CHANGE_TYPE_ACTIVE;

  fd_stem_publish( ctx->stem, ctx->gossvf_out->idx, 0UL, ctx->gossvf_out->chunk, sizeof(fd_gossip_ping_update_t), 0UL, 0UL, 0UL );
  ctx->gossvf_out->chunk = fd_dcache_compact_next( ctx->gossvf_out->chunk, sizeof(fd_gossip_ping_update_t), ctx->gossvf_out->chunk0, ctx->gossvf_out->wmark );
}

static inline void
during_housekeeping( fd_gossip_tile_ctx_t * ctx ) {
  ctx->last_wallclock = fd_log_wallclock();
  ctx->last_tickcount = fd_tickcount();
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    /* TODO: Need some kind of state machine here, to ensure we switch
       in sync with the signing tile.  Currently, we might send out a
       badly signed message before the signing tile has switched. */
    fd_memcpy( ctx->my_contact_info->pubkey.uc, ctx->keyswitch->bytes, 32UL );
    fd_gossip_set_my_contact_info( ctx->gossip, ctx->my_contact_info, ctx->last_wallclock );

    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_gossip_tile_ctx_t * ctx ) {
  fd_ping_tracker_metrics_t const * ping_tracker_metrics = fd_gossip_ping_tracker_metrics( ctx->gossip );

  FD_MGAUGE_SET( GOSSIP, PING_TRACKER_COUNT_UNPINGED,         ping_tracker_metrics->unpinged_cnt );
  FD_MGAUGE_SET( GOSSIP, PING_TRACKER_COUNT_INVALID,          ping_tracker_metrics->invalid_cnt );
  FD_MGAUGE_SET( GOSSIP, PING_TRACKER_COUNT_VALID,            ping_tracker_metrics->valid_cnt );
  FD_MGAUGE_SET( GOSSIP, PING_TRACKER_COUNT_VALID_REFRESHING, ping_tracker_metrics->refreshing_cnt );

  FD_MCNT_SET( GOSSIP, PING_TRACKER_PONG_RESULT_STAKED,     ping_tracker_metrics->pong_result[ 0UL ] );
  FD_MCNT_SET( GOSSIP, PING_TRACKER_PONG_RESULT_ENTRYPOINT, ping_tracker_metrics->pong_result[ 1UL ] );
  FD_MCNT_SET( GOSSIP, PING_TRACKER_PONG_RESULT_UNTRACKED,  ping_tracker_metrics->pong_result[ 2UL ] );
  FD_MCNT_SET( GOSSIP, PING_TRACKER_PONG_RESULT_ADDRESS,    ping_tracker_metrics->pong_result[ 3UL ] );
  FD_MCNT_SET( GOSSIP, PING_TRACKER_PONG_RESULT_TOKEN,      ping_tracker_metrics->pong_result[ 4UL ] );
  FD_MCNT_SET( GOSSIP, PING_TRACKER_PONG_RESULT_SUCCESS,    ping_tracker_metrics->pong_result[ 5UL ] );

  FD_MCNT_SET( GOSSIP, PING_TRACKER_EVICTED_COUNT,         ping_tracker_metrics->peers_evicted );
  FD_MCNT_SET( GOSSIP, PING_TRACKED_COUNT,                 ping_tracker_metrics->tracked_cnt );
  FD_MCNT_SET( GOSSIP, PING_TRACKER_STAKE_CHANGED_COUNT,   ping_tracker_metrics->stake_changed_cnt );
  FD_MCNT_SET( GOSSIP, PING_TRACKER_ADDRESS_CHANGED_COUNT, ping_tracker_metrics->address_changed_cnt );

  fd_crds_metrics_t const * crds_metrics = fd_gossip_crds_metrics( ctx->gossip );

  FD_MGAUGE_ENUM_COPY( GOSSIP, CRDS_COUNT,          crds_metrics->count );
  FD_MCNT_SET(         GOSSIP, CRDS_EXPIRED_COUNT,  crds_metrics->expired_cnt );
  FD_MCNT_SET(         GOSSIP, CRDS_EVICTED_COUNT,  crds_metrics->evicted_cnt );

  FD_MGAUGE_SET( GOSSIP, CRDS_PEER_STAKED_COUNT,   crds_metrics->peer_staked_cnt );
  FD_MGAUGE_SET( GOSSIP, CRDS_PEER_UNSTAKED_COUNT, crds_metrics->peer_unstaked_cnt );
  FD_MGAUGE_SET( GOSSIP, CRDS_PEER_TOTAL_STAKE,    crds_metrics->peer_visible_stake );
  FD_MCNT_SET(   GOSSIP, CRDS_PEER_EVICTED_COUNT,  crds_metrics->peer_evicted_cnt );

  FD_MGAUGE_SET( GOSSIP, CRDS_PURGED_COUNT,         crds_metrics->purged_cnt );
  FD_MCNT_SET(   GOSSIP, CRDS_PURGED_EVICTED_COUNT, crds_metrics->purged_evicted_cnt );
  FD_MCNT_SET(   GOSSIP, CRDS_PURGED_EXPIRED_COUNT, crds_metrics->purged_expired_cnt );

  fd_gossip_metrics_t const * metrics = fd_gossip_metrics( ctx->gossip );

  FD_MCNT_ENUM_COPY( GOSSIP, MESSAGE_TX_COUNT,            metrics->message_tx );
  FD_MCNT_ENUM_COPY( GOSSIP, MESSAGE_TX_BYTES,            metrics->message_tx_bytes );

  FD_MCNT_ENUM_COPY( GOSSIP, CRDS_TX_PUSH_COUNT,          metrics->crds_tx_push );
  FD_MCNT_ENUM_COPY( GOSSIP, CRDS_TX_PUSH_BYTES,          metrics->crds_tx_push_bytes );
  FD_MCNT_ENUM_COPY( GOSSIP, CRDS_TX_PULL_RESPONSE_COUNT, metrics->crds_tx_pull_response );
  FD_MCNT_ENUM_COPY( GOSSIP, CRDS_TX_PULL_RESPONSE_BYTES, metrics->crds_tx_pull_response_bytes );

  FD_MCNT_ENUM_COPY( GOSSIP, CRDS_RX_COUNT,               metrics->crds_rx_count );

  FD_MCNT_SET( GOSSIP, CONTACT_INFO_UNRECOGNIZED_SOCKET_TAGS, metrics->ci_rx_unrecognized_socket_tag_cnt );
  FD_MCNT_SET( GOSSIP, CONTACT_INFO_IPV6,                     metrics->ci_rx_ipv6_address_cnt );

  FD_MCNT_SET( GOSSIP, CRDS_INSERTED_COUNT,       metrics->crds_inserted_count );
  FD_MCNT_SET( GOSSIP, CRDS_INSERTED_FRESH_COUNT, metrics->crds_inserted_fresh_count );
}

void
after_credit( fd_gossip_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy FD_PARAM_UNUSED ) {
  ctx->stem = stem;

  if( FD_UNLIKELY( !ctx->my_contact_info->shred_version ) ) return;

  long now = ctx->last_wallclock + (long)((double)(fd_tickcount()-ctx->last_tickcount)/ctx->ticks_per_ns);
  fd_gossip_advance( ctx->gossip, now, stem );
}

static void
handle_shred_version( fd_gossip_tile_ctx_t * ctx,
                       ulong                 sig ) {
  long now = ctx->last_wallclock + (long)((double)(fd_tickcount()-ctx->last_tickcount)/ctx->ticks_per_ns);
  ctx->my_contact_info->shred_version = (ushort)sig;
  fd_gossip_set_my_contact_info( ctx->gossip, ctx->my_contact_info, now );
}

static void
handle_local_vote( fd_gossip_tile_ctx_t * ctx,
                   fd_txn_m_t const *     txn_m,
                   fd_stem_context_t *    stem ) {
  long now = ctx->last_wallclock + (long)((double)(fd_tickcount()-ctx->last_tickcount)/ctx->ticks_per_ns);
  fd_gossip_push_vote( ctx->gossip, fd_txn_m_payload_const( txn_m ), txn_m->payload_sz, stem, now );
}

static void
handle_stakes( fd_gossip_tile_ctx_t *        ctx,
               fd_stake_weight_msg_t const * msg ) {
  ulong stakes_cnt = compute_id_weights_from_vote_weights( ctx->stake_weights_converted, msg->weights, msg->staked_cnt );
  fd_gossip_stakes_update( ctx->gossip, ctx->stake_weights_converted, stakes_cnt );
}

static void
handle_packet( fd_gossip_tile_ctx_t * ctx,
               ulong                  sig,
               uchar const *          payload,
               ulong                  payload_sz,
               fd_stem_context_t *    stem ) {
  long now = ctx->last_wallclock + (long)((double)(fd_tickcount()-ctx->last_tickcount)/ctx->ticks_per_ns);

  fd_ip4_port_t peer = (fd_ip4_port_t){
    .addr = fd_gossvf_sig_addr( sig ),
    .port = fd_gossvf_sig_port( sig )
  };

  switch( fd_gossvf_sig_kind( sig ) ) {
    case 0: {
      fd_gossip_rx( ctx->gossip, peer, payload, payload_sz, now, stem );
      fd_gossip_advance( ctx->gossip, now, stem );
      break;
    }
    case 1: {
      fd_gossip_pingreq_t * pingreq = (fd_gossip_pingreq_t *)payload;
      fd_gossip_ping_tracker_track( ctx->gossip, pingreq->pubkey.uc, peer, now );
    }
  }
}

static inline int
returnable_frag( fd_gossip_tile_ctx_t * ctx,
                 ulong                  in_idx,
                 ulong                  seq,
                 ulong                  sig,
                 ulong                  chunk,
                 ulong                  sz,
                 ulong                  ctl,
                 ulong                  tsorig,
                 ulong                  tspub,
                 fd_stem_context_t *    stem ) {
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  if( FD_UNLIKELY( !ctx->my_contact_info->shred_version && ctx->in[ in_idx ].kind!=IN_KIND_SHRED_VERSION ) ) return 1;

  switch( ctx->in[ in_idx ].kind ) {
    case IN_KIND_SHRED_VERSION: handle_shred_version( ctx, sig ); break;
    case IN_KIND_SEND:          handle_local_vote( ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), stem ); break;
    case IN_KIND_STAKE:         handle_stakes( ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) ); break;
    case IN_KIND_GOSSVF:        handle_packet( ctx, sig, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sz, stem ); break;
  }

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->gossip.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  fd_memcpy( ctx->my_contact_info->pubkey.uc, fd_type_pun_const( fd_keyload_load( tile->gossip.identity_key_path, /* pubkey only: */ 1 ) ), 32UL );
  FD_TEST( fd_rng_secure( &ctx->rng_seed, 4UL ) );
  FD_TEST( fd_rng_secure( &ctx->rng_idx,  8UL ) );
}

static inline fd_gossip_out_ctx_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had no output link named %s", tile->name, tile->kind_id, name ));

  void * mem   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_gossip_out_ctx_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  void * _gossip             = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_align(),             fd_gossip_footprint( tile->gossip.max_entries, tile->gossip.entrypoints_cnt ) );
  void * _stake_weights      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),    MAX_STAKED_LEADERS*sizeof(fd_stake_weight_t) );

  ctx->stake_weights_converted = (fd_stake_weight_t *)_stake_weights;

  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, ctx->rng_seed, ctx->rng_idx ) ) );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]) );
  ulong sign_in_tile_idx = ULONG_MAX;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    if( FD_LIKELY( link->mtu ) ) {
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    } else {
      ctx->in[ i ].chunk0 = 0UL;
      ctx->in[ i ].wmark  = 0UL;
    }
    ctx->in[ i ].mtu    = link->mtu;

    if( FD_UNLIKELY( !strcmp( link->name, "ipecho_out" ) ) ) {
      ctx->in[ i ].kind = IN_KIND_SHRED_VERSION;
    } else if( FD_UNLIKELY( !strcmp( link->name, "gossvf_gossi" ) ) ) {
      ctx->in[ i ].kind = IN_KIND_GOSSVF;
    } else if( FD_UNLIKELY( !strcmp( link->name, "sign_gossip" ) ) ) {
      ctx->in[ i ].kind = IN_KIND_SIGN;
      sign_in_tile_idx = i;
    } else if( FD_UNLIKELY( !strcmp( link->name, "send_txns" ) ) ) {
      ctx->in[ i ].kind = IN_KIND_SEND;
    } else if( FD_UNLIKELY( !strcmp( link->name, "replay_stake" ) ) ) {
      ctx->in[ i ].kind = IN_KIND_STAKE;
    } else {
      FD_LOG_ERR(( "unexpected input link name %s", link->name ));
    }
  }

  if( FD_UNLIKELY( sign_in_tile_idx==ULONG_MAX ) )
    FD_LOG_ERR(( "tile %s:%lu had no input link named sign_gossip", tile->name, tile->kind_id ));

  *ctx->net_out    = out1( topo, tile, "gossip_net"   );
  *ctx->sign_out   = out1( topo, tile, "gossip_sign"  );
  *ctx->gossip_out = out1( topo, tile, "gossip_out"   );
  *ctx->gossvf_out = out1( topo, tile, "gossip_gossv" );

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id [ sign_in_tile_idx  ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->sign_out->idx ] ];

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  if( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                       sign_out->mcache,
                                                       sign_out->dcache,
                                                       sign_in->mcache,
                                                       sign_in->dcache,
                                                       sign_out->mtu ) )==NULL ) {
    FD_LOG_ERR(( "failed to join keyguard client" ));
  }

  ctx->ticks_per_ns   = fd_tempo_tick_per_ns( NULL );
  ctx->last_wallclock = fd_log_wallclock();
  ctx->last_tickcount = fd_tickcount();

  ctx->my_contact_info->shred_version = tile->gossip.shred_version;

  ctx->my_contact_info->wallclock_nanos                   = ctx->last_wallclock;
  ctx->my_contact_info->instance_creation_wallclock_nanos = tile->gossip.boot_timestamp_nanos;

  ctx->my_contact_info->version.client      = FD_CONTACT_INFO_VERSION_CLIENT_FIREDANCER;
  ctx->my_contact_info->version.major       = (ushort)firedancer_major_version;
  ctx->my_contact_info->version.minor       = (ushort)firedancer_minor_version;
  ctx->my_contact_info->version.patch       = (ushort)firedancer_patch_version;
  ctx->my_contact_info->version.commit      = firedancer_commit_ref;
  ctx->my_contact_info->version.feature_set = UINT_MAX; /* TODO ... */

  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ]            = (fd_ip4_port_t){ .addr = tile->gossip.ports.gossip   ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.gossip )   };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TVU ]               = (fd_ip4_port_t){ .addr = tile->gossip.ports.tvu      ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.tvu )      };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TPU ]               = (fd_ip4_port_t){ .addr = tile->gossip.ports.tpu      ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.tpu )      };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TPU_FORWARDS ]      = (fd_ip4_port_t){ .addr = tile->gossip.ports.tpu      ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.tpu )      };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TPU_QUIC ]          = (fd_ip4_port_t){ .addr = tile->gossip.ports.tpu_quic ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.tpu_quic ) };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC ]     = (fd_ip4_port_t){ .addr = tile->gossip.ports.tpu_quic ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.tpu_quic ) };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TPU_FORWARDS_QUIC ] = (fd_ip4_port_t){ .addr = tile->gossip.ports.tpu_quic ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.tpu_quic ) };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TPU_VOTE ]          = (fd_ip4_port_t){ .addr = tile->gossip.ports.tpu      ? tile->gossip.ip_addr : 0, .port = fd_ushort_bswap( tile->gossip.ports.tpu )      };

  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TVU_QUIC ]          = (fd_ip4_port_t){ .addr = 0, .port = 0 };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_SERVE_REPAIR ]      = (fd_ip4_port_t){ .addr = 0, .port = 0 };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_SERVE_REPAIR_QUIC ] = (fd_ip4_port_t){ .addr = 0, .port = 0 };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_RPC ]               = (fd_ip4_port_t){ .addr = 0, .port = 0 };
  ctx->my_contact_info->sockets[ FD_CONTACT_INFO_SOCKET_RPC_PUBSUB ]        = (fd_ip4_port_t){ .addr = 0, .port = 0 };

  ctx->gossip = fd_gossip_join( fd_gossip_new( _gossip,
                                               ctx->rng,
                                               tile->gossip.max_entries,
                                               tile->gossip.entrypoints_cnt,
                                               tile->gossip.entrypoints,
                                               ctx->my_contact_info,
                                               ctx->last_wallclock,
                                               gossip_send_fn,
                                               ctx,
                                               gossip_sign_fn,
                                               ctx,
                                               gossip_ping_tracker_change_fn,
                                               ctx,
                                               ctx->gossip_out,
                                               ctx->net_out ) );
  FD_TEST( ctx->gossip );

  FD_MGAUGE_SET( GOSSIP, CRDS_CAPACITY,        tile->gossip.max_entries     );
  FD_MGAUGE_SET( GOSSIP, CRDS_PEER_CAPACITY,   FD_CONTACT_INFO_TABLE_SIZE   );
  FD_MGAUGE_SET( GOSSIP, CRDS_PURGED_CAPACITY, 4UL*tile->gossip.max_entries );

  fd_ip4_udp_hdr_init( ctx->net_out_hdr, FD_GOSSIP_MTU, tile->gossip.ip_addr, tile->gossip.ports.gossip );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_gossip_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_gossip_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

/* Account for worst case in fd_gossip_rx and fd_gossip_advance, which
   are both called in returnable_frag.

   fd_gossip_rx: Gossip updates are sent out via the gossip_out link for
    specific CRDS messages received, and when a contact info is dropped.
    Worst case is when:
    - all incoming CRDS messages are broadcasted as updates, and
    - CRDS table is full, and all entries dropped to make way for new
      ones are contact infos

    Ping tracker track also publishes a status change on the
    gossip_gossv link if an incoming pong changes an inactive or
    unpinged peer to active. There is only one pong processed per
    after_frag loop.

    This leaves us with a worst case of FD_GOSSIP_MSG_MAX_CRDS*2 on
    gossip_out, and 1 on gossip_gossv.

   fd_gossip_advance: two links we need to look at: the gossip_gossv
    link that publishes fd_ping_tracker changes and the gossip_out link
    for when contact infos are dropped during expiry.

    fd_ping_tracker publishes a ping status change message when a peer
     becomes inactive. In the worst case, all peers can become inactive
     in one loop. So there would be FD_PING_TRACKER_MAX ping status
     changes.

    During the expire loop, all contact infos might be dropped in one
    iteration, which would result in CRDS_MAX_CONTACT_INFO gossip
    updates

   We find the worst case burst by taking the maximum burst of the two
   links in fd_gossip_rx and fd_gossip_advance. That would be:
                        gossip_out link                    gossip_gossv link
   max( FD_GOSSIP_MSG_CRDS_MAX*2+CRDS_MAX_CONTACT_INFO, 1+FD_PING_TRACKER_MAX)

   */

FD_STATIC_ASSERT( CRDS_MAX_CONTACT_INFO+FD_GOSSIP_MSG_MAX_CRDS*2UL<=FD_PING_TRACKER_MAX+1UL,
                  "Gossip stem burst needs recalculating" );
#define STEM_BURST ( FD_PING_TRACKER_MAX+1UL )

#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gossip_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gossip_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_gossip = {
  .name                     = "gossip",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
