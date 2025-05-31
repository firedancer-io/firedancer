#include "fd_gossip_tile.h"
#include "../../disco/metrics/fd_metrics.h"
#include "generated/fd_gossip_tile_seccomp.h"

#include "../../flamenco/gossip/fd_gossip.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"

#include <sys/random.h>

#define IN_KIND_NET           (0)
#define IN_KIND_SHRED_VERSION (1)
#define IN_KIND_SIGN          (2)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_gossip_in_ctx_t;

typedef struct {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_gossip_out_ctx_t;

struct fd_gossip_tile_ctx {
  fd_gossip_t * gossip;

  fd_pubkey_t   identity_key[1]; /* Just the public key */

  uint          rng_seed;
  ulong         rng_idx;

  double        ticks_per_ns;
  long          last_wallclock;
  long          last_tickcount;

  uchar         buffer[ FD_NET_MTU ];

  fd_gossip_in_ctx_t in[ 32UL ];
  int                in_kind[ 32UL ];

  fd_gossip_out_ctx_t net_out[ 1 ];
  fd_gossip_out_ctx_t gossip_out[ 1 ];
  fd_gossip_out_ctx_t sign_out[ 1 ];

  fd_keyguard_client_t keyguard_client[ 1 ];
  fd_keyswitch_t *     keyswitch;

  fd_ip4_udp_hdrs_t net_out_hdr[ 1 ]; /* Used to construct outgoing network packets */
  fd_stem_context_t * stem; /* This is ugly! */
};

typedef struct fd_gossip_tile_ctx fd_gossip_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_gossip_align(),             fd_gossip_footprint( tile->gossip.max_entries ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
gossip_send_fn( void *                ctx,
                uchar const *         payload,
                ulong                 payload_sz,
                fd_ip4_port_t const * peer_address,
                ulong                 tsorig ) {
  fd_gossip_tile_ctx_t * gossip_ctx = (fd_gossip_tile_ctx_t *)ctx;

  ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);
  gossip_ctx->net_out->chunk = fd_dcache_compact_next( gossip_ctx->net_out->chunk, packet_sz, gossip_ctx->net_out->chunk0, gossip_ctx->net_out->wmark );

  uchar * packet          = (uchar *)fd_chunk_to_laddr( gossip_ctx->net_out->mem, gossip_ctx->net_out->chunk );
  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *gossip_ctx->net_out_hdr;

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  fd_udp_hdr_t * udp = hdr->udp;

  /* Update payload size in headers */
  ip4->net_tot_len = fd_ushort_bswap( (ushort)(packet_sz + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t)) );
  udp->net_len     = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );

  /* Fill in destination info */
  ip4->daddr     = peer_address->addr;
  udp->net_dport =  peer_address->port;

  /* IP Checksum calculation */
  ip4->check = fd_ip4_hdr_check_fast( ip4 );
  /* TODO: ip4 net_id? */

  /* Inject payload */
  fd_memcpy( packet + sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );

  /* Publish fragment */
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig   = fd_disco_netmux_sig( peer_address->addr, peer_address->port, peer_address->addr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  fd_stem_publish( gossip_ctx->stem, 0UL, 0UL, gossip_ctx->net_out->chunk, packet_sz, sig, tsorig, tspub );
}

static void
gossip_sign_fn( void *        ctx,
                uchar const * data,
                ulong         sz,
                uchar *       signature ) {
  fd_gossip_tile_ctx_t * gossip_ctx = (fd_gossip_tile_ctx_t *)ctx;
  fd_keyguard_client_sign( gossip_ctx->keyguard_client, signature, data, sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

static inline void
during_housekeeping( fd_gossip_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    /* TODO: Need some kind of state machine here, to ensure we switch
       in sync with the signing tile.  Currently, we might send out a
       badly signed message before the signing tile has switched. */
    fd_gossip_set_identity( ctx->gossip, ctx->keyswitch->bytes );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  ctx->last_wallclock = fd_log_wallclock();
  ctx->last_tickcount = fd_tickcount();
  fd_gossip_advance( ctx->gossip, ctx->last_wallclock );
}

static inline void
metrics_write( fd_gossip_tile_ctx_t * ctx ) {
  fd_gossip_metrics_t const * metrics = fd_gossip_metrics( ctx->gossip );

  FD_MGAUGE_SET( GOSSIP, TABLE_SIZE,    metrics->table_size    );
  FD_MGAUGE_SET( GOSSIP, TABLE_EXPIRED, metrics->table_expired );
  FD_MGAUGE_SET( GOSSIP, TABLE_EVICTED, metrics->table_evicted );

  FD_MGAUGE_SET( GOSSIP, PURGED_SIZE,   metrics->purged_size   );

  FD_MGAUGE_SET( GOSSIP, FAILED_SIZE,   metrics->failed_size   );
}

static inline void
during_frag( fd_gossip_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

    uchar const * dcache_entry = (uchar const *)fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_memcpy( ctx->buffer, dcache_entry, sz );
  } else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED_VERSION ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=0UL ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));
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
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    long now = ctx->last_wallclock + (long)((double)(fd_tickcount()-ctx->last_tickcount)/ctx->ticks_per_ns);

    fd_gossip_advance( ctx->gossip, now );
    fd_gossip_rx( ctx->gossip, ctx->buffer, sz, now );
    ctx->stem = stem;
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED_VERSION ) ) {
    FD_MGAUGE_SET( GOSSIP, SHRED_VERSION, (ushort)sig );
    fd_gossip_set_expected_shred_version( ctx->gossip, 1, (ushort)sig );
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

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->gossip.identity_key_path, /* pubkey only: */ 1 ) );
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
  void * gossip              = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_align(),             fd_gossip_footprint( tile->gossip.max_entries ) );

  ctx->ticks_per_ns   = fd_tempo_tick_per_ns( NULL );
  ctx->last_wallclock = fd_log_wallclock();
  ctx->last_tickcount = fd_tickcount();

  fd_rng_t rng[ 1 ];
  FD_TEST( fd_rng_join( fd_rng_new( rng, ctx->rng_seed, ctx->rng_idx ) ) );
  ctx->gossip = fd_gossip_join( fd_gossip_new( gossip,
                                               rng,
                                               tile->gossip.max_entries,
                                               tile->gossip.has_expected_shred_version,
                                               tile->gossip.expected_shred_version,
                                               tile->gossip.entrypoints_cnt,
                                               tile->gossip.entrypoints,
                                               ctx->identity_key->uc,

                                               gossip_send_fn,
                                               (void*)ctx,
                                               gossip_sign_fn,
                                               (void*)ctx,

                                               ctx->last_wallclock ) );
  FD_TEST( ctx->gossip );

  FD_MGAUGE_SET( GOSSIP, SHRED_VERSION, tile->gossip.expected_shred_version );

  FD_MGAUGE_SET( GOSSIP, TABLE_CAPACITY,  tile->gossip.max_entries );
  FD_MGAUGE_SET( GOSSIP, PURGED_CAPACITY, tile->gossip.max_purged  );
  FD_MGAUGE_SET( GOSSIP, FAILED_CAPACITY, tile->gossip.max_failed  );

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
    } else {
      FD_LOG_ERR(( "unexpected input link name %s", link->name ));
    }
  }

  if( FD_UNLIKELY( sign_in_tile_idx==ULONG_MAX ) )
    FD_LOG_ERR(( "tile %s:%lu had no input link named sign_gossip", tile->name, tile->kind_id ));

  *ctx->net_out    = out1( topo, tile, "gossip_net" );
  *ctx->gossip_out = out1( topo, tile, "gossip_out" );
  *ctx->sign_out   = out1( topo, tile, "gossip_sign" );

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id [ sign_in_tile_idx  ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->sign_out->idx ] ];

  if( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                       sign_out->mcache,
                                                       sign_out->dcache,
                                                       sign_in->mcache,
                                                       sign_in->dcache ) ) ) {
    FD_LOG_ERR(( "failed to join keyguard client" ));
  }

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

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gossip_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gossip_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
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
