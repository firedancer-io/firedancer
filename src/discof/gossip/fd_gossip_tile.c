#include "fd_gossip_tile.h"
#include "../../disco/metrics/fd_metrics.h"
#include "generated/fd_gossip_tile_seccomp.h"

#include "../../flamenco/gossip/fd_gossip.h"
#include "../../flamenco/gossip/fd_gossip_out.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/shred/fd_stake_ci.h"

#include <sys/random.h>

#define IN_KIND_NET           (0)
#define IN_KIND_SHRED_VERSION (1)
#define IN_KIND_SIGN          (2)
#define IN_KIND_SEND          (3)
#define IN_KIND_VOTER         (4)
#define IN_KIND_RSTART        (5)
#define IN_KIND_STAKE         (6)

/* Symbols exported by version.c */
extern ulong const firedancer_major_version;
extern ulong const firedancer_minor_version;
extern ulong const firedancer_patch_version;
extern uint  const firedancer_commit_ref;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_gossip_in_ctx_t;

struct fd_gossip_tile_ctx {
  fd_gossip_t *             gossip;
  ulong                     gossip_max_entries;
  fd_contact_info_t         my_contact_info[1];

  uint                      rng_seed;
  ulong                     rng_idx;

  double                    ticks_per_ns;
  long                      last_wallclock;
  long                      last_tickcount;

  ulong                     vote_stake_weights_cnt;
  fd_vote_stake_weight_t *  vote_stake_weights;

  fd_stake_weight_t *       stake_weights_converted;

  uchar                     buffer[ FD_NET_MTU ];

  fd_gossip_in_ctx_t        in[ 32UL ];
  int                       in_kind[ 32UL ];

  fd_gossip_out_ctx_t       net_out[ 1 ];

  fd_gossip_out_ctx_t       gossip_out[ 1 ];
  fd_gossip_out_ctx_t       sign_out[ 1 ];

  fd_keyguard_client_t      keyguard_client[ 1 ];
  fd_keyswitch_t *          keyswitch;

  fd_ip4_udp_hdrs_t         net_out_hdr[ 1 ];
  ushort                    net_id;
};

typedef struct fd_gossip_tile_ctx fd_gossip_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_tile_ctx_t),   sizeof(fd_gossip_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_gossip_align(),               fd_gossip_footprint( tile->gossip.max_entries ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vote_stake_weight_t), MAX_STAKED_LEADERS*sizeof(fd_vote_stake_weight_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t),      MAX_STAKED_LEADERS*sizeof(fd_stake_weight_t) );
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
  fd_gossip_metrics_t const * metrics = fd_gossip_metrics( ctx->gossip );
  /* CRDS Table */
  FD_MGAUGE_SET(       GOSSIP, TABLE_SIZE,          metrics->crds_table->total_ele_cnt );
  FD_MGAUGE_ENUM_COPY( GOSSIP, TABLE_CRDS_COUNTS,   metrics->crds_table->ele_cnt.crd );
  FD_MGAUGE_SET(       GOSSIP, PURGED_SIZE,         metrics->crds_table->table_purged_cnt );
  FD_MGAUGE_SET(       GOSSIP, VISIBLE_STAKE,       metrics->crds_table->visible_stake );
  FD_MGAUGE_SET(       GOSSIP, STAKED_PEER_COUNT,   metrics->crds_table->staked_peer_cnt );
  FD_MGAUGE_SET(       GOSSIP, UNSTAKED_PEER_COUNT, metrics->crds_table->unstaked_peer_cnt );
  FD_MCNT_ENUM_COPY(   GOSSIP, UNDETERMINED_CRDS,   metrics->crds_table->undetermined.crd );

  #define COPY_MSG_RX( name, msg_traffic ) \
    FD_MCNT_ENUM_COPY( GOSSIP, name##_COUNT, msg_traffic->count.msg ); \
    FD_MCNT_ENUM_COPY( GOSSIP, name##_BYTES, msg_traffic->bytes.msg );

  COPY_MSG_RX( MESSAGE_RX, metrics->rx );
  COPY_MSG_RX( MESSAGE_TX,     metrics->tx );

  #define COPY_CRDS_TRAFFIC( route, traffic ) \
    FD_MCNT_ENUM_COPY( GOSSIP, CRDS_##route##_COUNT,    traffic.count.crd ); \
    FD_MCNT_ENUM_COPY( GOSSIP, CRDS_##route##_BYTES,    traffic.bytes.crd );

  #define COPY_CRDS_INSERT( route, insert ) \
    COPY_CRDS_TRAFFIC( route##_RX, insert->rx ); \
    FD_MCNT_ENUM_COPY( GOSSIP, CRDS_##route##_UPSERTED, insert->upserted.crd ); \
    FD_MCNT_ENUM_COPY( GOSSIP, CRDS_##route##_DUPLICATES, insert->duplicates.crd ); \
    FD_MCNT_ENUM_COPY( GOSSIP, CRDS_##route##_OLD, insert->too_old.crd );


  COPY_CRDS_INSERT( PUSH, metrics->push_rx );
  COPY_CRDS_INSERT( PULL, metrics->pull_rx );

  /* TX */
  COPY_CRDS_TRAFFIC( PUSH_TX, metrics->push_tx[0] );
  COPY_CRDS_TRAFFIC( PULL_TX, metrics->pull_tx[0] );
}

void
after_credit( fd_gossip_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy FD_PARAM_UNUSED ) {
  ctx->last_wallclock = fd_log_wallclock();
  fd_gossip_advance( ctx->gossip, ctx->last_wallclock, stem );
}

static inline void
during_frag( fd_gossip_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET || ctx->in_kind[ in_idx ]==IN_KIND_SEND ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

    uchar const * dcache_entry = (uchar const *)fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_memcpy( ctx->buffer, dcache_entry, sz );
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED_VERSION ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=0UL ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    fd_gossip_in_ctx_t const * in_ctx = &ctx->in[ in_idx ];
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    uchar const * dcache_entry             = (uchar const *)fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    fd_stake_weight_msg_t const *  msg     = fd_type_pun_const( dcache_entry );
    fd_vote_stake_weight_t const * weights = msg->weights;
    fd_memcpy( ctx->vote_stake_weights, weights, msg->staked_cnt*sizeof(fd_vote_stake_weight_t) );
    ctx->vote_stake_weights_cnt = msg->staked_cnt;
  } else {
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
after_frag( fd_gossip_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq    FD_PARAM_UNUSED,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *    stem ) {
  long now = ctx->last_wallclock + (long)((double)(fd_tickcount()-ctx->last_tickcount)/ctx->ticks_per_ns);
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    fd_gossip_advance( ctx->gossip, now, stem );
    fd_gossip_rx( ctx->gossip, ctx->buffer, sz, now, stem );
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED_VERSION ) ) {
    FD_MGAUGE_SET( GOSSIP, SHRED_VERSION, (ushort)sig );
    ctx->my_contact_info->shred_version   = (ushort)sig;
    ctx->my_contact_info->wallclock_nanos = now;
    fd_gossip_set_my_contact_info( ctx->gossip, ctx->my_contact_info, now );
  } else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SEND ) ) {
    fd_gossip_push_vote( ctx->gossip, ctx->buffer, sz, stem, now );
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    ulong stakes_cnt = compute_id_weights_from_vote_weights( ctx->stake_weights_converted, ctx->vote_stake_weights, ctx->vote_stake_weights_cnt );
    fd_gossip_stakes_update( ctx->gossip, ctx->stake_weights_converted, stakes_cnt );
  } else {
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
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
  FD_TEST( 4UL==getrandom( &ctx->rng_seed, 4UL, 0 ) );
  FD_TEST( 8UL==getrandom( &ctx->rng_idx,  8UL, 0 ) );
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
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t),      sizeof(fd_gossip_tile_ctx_t) );
  void * gossip              = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_align(),                  fd_gossip_footprint( tile->gossip.max_entries ) );
  void * _vote_stake_weights = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t),    MAX_STAKED_LEADERS*sizeof(fd_vote_stake_weight_t) );
  void * _stake_weights      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),         MAX_STAKED_LEADERS*sizeof(fd_stake_weight_t) );


  ctx->gossip_max_entries      = tile->gossip.max_entries;
  ctx->vote_stake_weights      = (fd_vote_stake_weight_t *)_vote_stake_weights;
  ctx->stake_weights_converted = (fd_stake_weight_t *)_stake_weights;
  fd_rng_t rng[ 1 ];
  FD_TEST( fd_rng_join( fd_rng_new( rng, ctx->rng_seed, ctx->rng_idx ) ) );

  FD_MGAUGE_SET( GOSSIP, SHRED_VERSION, tile->gossip.expected_shred_version );
  FD_MGAUGE_SET( GOSSIP, TABLE_CAPACITY,  tile->gossip.max_entries );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong sign_in_tile_idx = ULONG_MAX;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );

    if( FD_UNLIKELY( !strcmp( link->name, "ipecho_gossip" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_SHRED_VERSION;
    } else if( FD_UNLIKELY( !strcmp( link->name, "net_gossip" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET;
    } else if( FD_UNLIKELY( !strcmp( link->name, "sign_gossip" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_SIGN;
      sign_in_tile_idx = i;
    } else if( FD_UNLIKELY( !strcmp( link->name, "voter_gossip" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_VOTER;
    } else if( FD_UNLIKELY( !strcmp( link->name, "rstart_gossi" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_RSTART;
    } else if( FD_UNLIKELY( !strcmp( link->name, "send_txns" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_SEND;
    } else if( FD_UNLIKELY( !strcmp( link->name, "stake_out" ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_STAKE;
    } else {
      FD_LOG_ERR(( "unexpected input link name %s", link->name ));
    }
  }

  if( FD_UNLIKELY( sign_in_tile_idx==ULONG_MAX ) )
    FD_LOG_ERR(( "tile %s:%lu had no input link named sign_gossip", tile->name, tile->kind_id ));

  *ctx->net_out    = out1( topo, tile, "gossip_net" );
  *ctx->sign_out   = out1( topo, tile, "gossip_sign" );

  /* Optional out links (?) */
  uchar has_gossip_out = 0;
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ i ] ];
    if( FD_UNLIKELY( !strcmp( link->name, "gossip_out" ) ) ) {
      *ctx->gossip_out = out1( topo, tile, "gossip_out" );
      has_gossip_out = 1;
    }
  }

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id [ sign_in_tile_idx  ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->sign_out->idx ] ];

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

  /* TODO setup my_contact_info */
  if( tile->gossip.has_expected_shred_version ) {
    ctx->my_contact_info->shred_version = tile->gossip.expected_shred_version;
  } else {
    ctx->my_contact_info->shred_version = 0;
  }
  uchar * pubkey = fd_keyload_load( tile->gossip.identity_key_path, /* pubkey only: */ 1 );

  fd_contact_info_t * ci                = ctx->my_contact_info;
  fd_memcpy( ci->pubkey.uc, pubkey, 32UL );
  ci->wallclock_nanos                   = ctx->last_wallclock;
  ci->version.client                    = FD_CONTACT_INFO_VERSION_CLIENT_FIREDANCER;
  ci->version.major                     = (ushort)firedancer_major_version;
  ci->version.minor                     = (ushort)firedancer_minor_version;
  ci->version.patch                     = (ushort)firedancer_patch_version;
  ci->version.commit                    = firedancer_commit_ref;
  ci->version.feature_set               = UINT_MAX;
  ci->instance_creation_wallclock_nanos = ctx->last_wallclock;

  uint ip_addr = tile->gossip.ip_addr;

  fd_ip4_port_t * gossip_port = &ci->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];
  gossip_port->addr = ip_addr;
  gossip_port->port = fd_ushort_bswap( tile->gossip.ports.gossip );

  fd_ip4_port_t * shred = &ci->sockets[ FD_CONTACT_INFO_SOCKET_TVU ];
  shred->addr = ip_addr;
  shred->port = fd_ushort_bswap( tile->gossip.ports.tvu );

  fd_ip4_port_t * tpu = &ci->sockets[ FD_CONTACT_INFO_SOCKET_TPU ];
  tpu->addr = ip_addr;
  tpu->port = fd_ushort_bswap( tile->gossip.ports.tpu );

  fd_ip4_port_t * tpu_quic = &ci->sockets[ FD_CONTACT_INFO_SOCKET_TPU_QUIC ];
  tpu_quic->addr = ip_addr;
  tpu_quic->port = fd_ushort_bswap( tile->gossip.ports.tpu_quic );

  fd_ip4_port_t * vote = &ci->sockets[ FD_CONTACT_INFO_SOCKET_TPU_VOTE ];
  vote->addr = ip_addr;
  vote->port = fd_ushort_bswap( tile->gossip.ports.vote );

  // fd_ip4_port_t * repair = &ci->sockets[ FD_CONTACT_INFO_SOCKET_SERVE_REPAIR ];
  // repair->addr = ip_addr;
  // repair->port = fd_ushort_bswap( tile->gossip.ports.repair );



  ctx->gossip = fd_gossip_join( fd_gossip_new( gossip,
                                               rng,
                                               ctx->gossip_max_entries,
                                               tile->gossip.entrypoints_cnt,
                                               tile->gossip.entrypoints,
                                               ctx->my_contact_info,
                                               ctx->last_wallclock,

                                               gossip_send_fn,
                                               (void*)ctx,
                                               gossip_sign_fn,
                                               (void*)ctx,
                                               has_gossip_out ? ctx->gossip_out : NULL,
                                               ctx->net_out ) );
  FD_TEST( ctx->gossip );

  fd_ip4_udp_hdr_init( ctx->net_out_hdr,
                       FD_GOSSIP_MTU,
                       tile->gossip.ip_addr,
                       tile->gossip.ports.gossip );

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

/* TODO: Size for the worst case ... 16k contact info updates + max crds in a pull request or push, all generating a frag */
#define STEM_BURST (1<<5)

#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gossip_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gossip_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

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
