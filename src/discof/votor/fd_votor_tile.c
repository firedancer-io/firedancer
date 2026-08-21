#include "fd_votor_tile.h"
#include "generated/fd_votor_tile_seccomp.h"

#include "../../ballet/bls/fd_bls12_381.h"
#include "../../choreo/votor/ag_cert_serde.h"
#include "../../choreo/votor/ag_pool.h"
#include "../../choreo/votor/ag_vote_serde.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/stakes/fd_stake_weight.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../waltz/quic/tls/fd_quic_tls.h"
#include "../replay/fd_replay_tile.h"

#define IN_KIND_REPLAY (0)
#define IN_KIND_EPOCH  (1)
#define IN_KIND_IPECHO (2)
#define IN_KIND_NET    (3)

#define OUT_IDX_NET (1UL)

#define FD_VOTOR_CONN_CNT (AG_VAT_MAX * 2) /* each voter is given 1 conn + 1 backup conn */

/* https://github.com/anza-xyz/agave/blob/4ee3222695/votor-messages/src/wire.rs#L164-L190 */

#define DATAGRAM_KIND_NOTAR_VOTE          ( 1)
#define DATAGRAM_KIND_FINALIZE_VOTE       ( 2)
#define DATAGRAM_KIND_SKIP_VOTE           ( 3)
#define DATAGRAM_KIND_NOTAR_FALLBACK_VOTE ( 4)
#define DATAGRAM_KIND_SKIP_FALLBACK_VOTE  ( 5)
#define DATAGRAM_KIND_GENESIS_VOTE        ( 6)
#define DATAGRAM_KIND_FINALIZE_CERT       ( 7)
#define DATAGRAM_KIND_FAST_FINALIZE_CERT  ( 8)
#define DATAGRAM_KIND_NOTAR_CERT          ( 9)
#define DATAGRAM_KIND_NOTAR_FALLBACK_CERT (10)
#define DATAGRAM_KIND_SKIP_CERT           (11)
#define DATAGRAM_KIND_GENESIS_CERT        (12)

static char const * const datagram_kind_name[] = {
  "unknown",
  "notar_vote",
  "finalize_vote",
  "skip_vote",
  "notar_fallback_vote",
  "skip_fallback_vote",
  "genesis_vote",
  "finalize_cert",
  "fast_finalize_cert",
  "notar_cert",
  "notar_fallback_cert",
  "skip_cert",
  "genesis_cert",
};

static fd_quic_limits_t quic_limits = {
  .conn_cnt                    = FD_VOTOR_CONN_CNT,
  .handshake_cnt               = 1024UL,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 64UL * FD_VOTOR_CONN_CNT,
  .min_inflight_frame_cnt_conn = 32UL,
};

struct fd_votor_tile {
  int in_kind[ 32 ];

  fd_quic_t * quic;
  uchar       quic_tx_aio[ 128 ] __attribute__((aligned(alignof(fd_aio_t))));

  uchar const * identity_keypair;

  uchar sha512[ FD_SHA512_FOOTPRINT ] __attribute__((aligned(FD_SHA512_ALIGN)));

  ushort shred_version;

  uchar net_buf[ FD_NET_MTU ];

  fd_net_rx_bounds_t net_in_bounds[ 32 ];

  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in[ 32 ];

  void * net_out_mem;
  ulong  net_out_chunk0;
  ulong  net_out_wmark;
  ulong  net_out_chunk;

  fd_stem_context_t * stem;

  fd_replay_message_t replay_msg[ 1 ];

  ag_pool_t * pool;

  union {
    ag_vote_t vote;
    ag_cert_t cert;
  } msg;
};
typedef struct fd_votor_tile fd_votor_tile_t;

struct vtr_rank { ulong stake; uchar const * bls; ulong idx; };
typedef struct vtr_rank vtr_rank_t;

#define SORT_NAME        vtr_rank_sort
#define SORT_KEY_T       vtr_rank_t
#define SORT_BEFORE(a,b) ( (a).stake >(b).stake ||                                                                  \
                         ( (a).stake==(b).stake && memcmp((a).bls,(b).bls,AG_BLS_PUB_COMPRESSED_SZ)<0 ) )
#include "../../util/tmpl/fd_sort.c"

FD_STATIC_ASSERT( sizeof( ((fd_vote_stake_weight_t *)NULL)->bls_key )==AG_BLS_PUB_COMPRESSED_SZ, bls_pubkey_sz );

FD_FN_UNUSED static ulong
rank_validators( ag_validator_info_t *          out,
                 ulong                          out_max,
                 fd_vote_stake_weight_t const * stakes,
                 ulong                          stake_cnt ) {
  ulong in_cnt = fd_ulong_min( stake_cnt, AG_VAT_MAX );

  ag_bls_pub_t pk  [ AG_VAT_MAX ];
  uchar        cand[ AG_VAT_MAX ]; /* 1 if non-zero stake and BLS key is in G1 */
  for( ulong i=0UL; i<in_cnt; i++ ) {
    cand[ i ] = (uchar)( stakes[ i ].stake!=0UL && !fd_bls12_381_g1_decompress_syscall( pk[ i ], stakes[ i ].bls_key, 1 /* big endian */ ) );
  }

  vtr_rank_t rank[ AG_VAT_MAX ];
  ulong      m = 0UL;
  for( ulong i=0UL; i<in_cnt; i++ ) {
    if( FD_UNLIKELY( !cand[ i ] ) ) continue;
    ulong bls_dup = 0UL;
    ulong id_dup  = 0UL;
    for( ulong j=0UL; j<in_cnt; j++ ) {
      if( FD_UNLIKELY( !cand[ j ] ) ) continue;
      if( FD_UNLIKELY( !memcmp( stakes[ i ].bls_key,   stakes[ j ].bls_key,   AG_BLS_PUB_COMPRESSED_SZ ) ) ) bls_dup++;
      if( FD_UNLIKELY( !memcmp( stakes[ i ].id_key.uc, stakes[ j ].id_key.uc, sizeof(fd_pubkey_t)             ) ) ) id_dup++;
    }
    if( FD_UNLIKELY( bls_dup!=1UL || id_dup!=1UL ) ) continue;
    rank[ m ].stake = stakes[ i ].stake;
    rank[ m ].bls   = stakes[ i ].bls_key;
    rank[ m ].idx   = i;
    m++;
  }

  vtr_rank_sort_inplace( rank, m );

  ulong cnt = fd_ulong_min( m, out_max );
  for( ulong r=0UL; r<cnt; r++ ) {
    ulong                 idx = rank[ r ].idx;
    ag_validator_info_t * vi  = out + r;
    memset( vi, 0, sizeof(ag_validator_info_t) );
    vi->id    = r;
    vi->stake = stakes[ idx ].stake;
    fd_memcpy( vi->id_key,        stakes[ idx ].id_key.uc,   sizeof(ag_id_key_t)   );
    fd_memcpy( vi->vote_key,      stakes[ idx ].vote_key.uc, sizeof(ag_vote_key_t) );
    fd_memcpy( vi->bls_key, pk[ idx ],                 AG_BLS_PUB_SZ         );
  }
  return cnt;
}

static int
quic_aio_tx( void *                    _ctx,
             fd_aio_pkt_info_t const * batch,
             ulong                     batch_cnt,
             ulong *                   opt_batch_idx,
             int                       flush ) {
  (void)flush;

  fd_votor_tile_t * ctx = _ctx;

  for( ulong i=0UL; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;

    uint const ip_dst = FD_LOAD( uint, batch[ i ].buf+offsetof( fd_ip4_hdr_t, daddr_c ) );
    uchar * packet_l2 = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
    memset( packet_l2, 0, 12 );
    FD_STORE( ushort, packet_l2+offsetof( fd_eth_hdr_t, net_type ), fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    fd_memcpy( packet_l3, batch[ i ].buf, batch[ i ].buf_sz );
    ulong sz_l2 = sizeof(fd_eth_hdr_t) + batch[ i ].buf_sz;

    ulong sig   = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
    ulong chunk = ctx->net_out_chunk;
    ulong ctl   = fd_frag_meta_ctl( 0UL, 1, 1, 0 );
    fd_stem_publish( ctx->stem, OUT_IDX_NET, sig, chunk, sz_l2, ctl, 0L, 0L );

    ctx->net_out_chunk = fd_dcache_compact_next( chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) *opt_batch_idx = batch_cnt;

  return FD_AIO_SUCCESS;
}

static void
quic_sign( void *      signer_ctx,
           uchar       signature[ static 64 ],
           uchar const payload[ static 130 ] ) {
  fd_votor_tile_t * ctx = signer_ctx;

  fd_sha512_t * sha = fd_sha512_join( ctx->sha512 );
  fd_ed25519_sign( signature, payload, 130UL, ctx->identity_keypair+32UL, ctx->identity_keypair, sha );
  fd_sha512_leave( sha );
}

static void
quic_conn_new( fd_quic_conn_t * conn,
               void *           _ctx ) {
  (void)_ctx;

  /* tls_hs is released as soon as the handshake completes, so this is the
     only callback in which the peer's attested identity is readable. */
  uchar const * peer = conn->tls_hs ? conn->tls_hs->hs.srv.client_pubkey : NULL;
  FD_BASE58_ENCODE_32_BYTES( peer, peer_b58 );

  FD_LOG_NOTICE(( "votor peer connected %s " FD_IP4_ADDR_FMT ":%hu",
                  peer_b58,
                  FD_IP4_ADDR_FMT_ARGS( conn->peer->ip_addr ),
                  conn->peer->udp_port ));
}

static void
quic_datagram_rx( fd_quic_conn_t * conn,
                  uchar const *    data,
                  ulong            data_sz,
                  void *           _ctx ) {
  fd_votor_tile_t * ctx = _ctx;

  if( FD_UNLIKELY( data_sz<2UL ) ) return;

  switch( data[ 1 ] ) {
  case DATAGRAM_KIND_NOTAR_VOTE:
  case DATAGRAM_KIND_FINALIZE_VOTE:
  case DATAGRAM_KIND_SKIP_VOTE:
  case DATAGRAM_KIND_NOTAR_FALLBACK_VOTE:
  case DATAGRAM_KIND_SKIP_FALLBACK_VOTE:
  case DATAGRAM_KIND_GENESIS_VOTE:
    if( FD_UNLIKELY( ag_vote_de( &ctx->msg.vote, ctx->shred_version, data, data_sz, NULL ) ) ) return;
    FD_LOG_NOTICE(( "votor rx %s slot %lu from " FD_IP4_ADDR_FMT ":%hu",
                    datagram_kind_name[ data[ 1 ] ],
                    ag_vote_slot( &ctx->msg.vote ),
                    FD_IP4_ADDR_FMT_ARGS( conn->peer->ip_addr ),
                    conn->peer->udp_port ));
    return;
  case DATAGRAM_KIND_FINALIZE_CERT:
  case DATAGRAM_KIND_FAST_FINALIZE_CERT:
  case DATAGRAM_KIND_NOTAR_CERT:
  case DATAGRAM_KIND_NOTAR_FALLBACK_CERT:
  case DATAGRAM_KIND_SKIP_CERT:
  case DATAGRAM_KIND_GENESIS_CERT:
    if( FD_UNLIKELY( ag_cert_de( &ctx->msg.cert, ctx->shred_version, data, data_sz, NULL ) ) ) return;
    FD_LOG_NOTICE(( "votor rx %s slot %lu from " FD_IP4_ADDR_FMT ":%hu",
                    datagram_kind_name[ data[ 1 ] ],
                    ag_cert_slot( &ctx->msg.cert ),
                    FD_IP4_ADDR_FMT_ARGS( conn->peer->ip_addr ),
                    conn->peer->udp_port ));
    return;
  default:
    return;
  }
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_votor_tile_t), fd_quic_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t)                         );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),          fd_quic_footprint( &quic_limits )               );
  l = FD_LAYOUT_APPEND( l, ag_pool_align(),          ag_pool_footprint( tile->votor.max_live_slots ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static int
before_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)seq;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_VOTOR;
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY && sig!=REPLAY_SIG_SLOT_COMPLETED ) ) return 1;
  return 0;
}

static void
during_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz,
             ulong             ctl ) {
  (void)seq; (void)sig;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_NET: {
    void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz );
    fd_memcpy( ctx->net_buf, src, sz );
    break;
  }
  case IN_KIND_REPLAY: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>sizeof(ctx->replay_msg) ) ) {
      FD_LOG_ERR(( "chunk %lu sz %lu from replay out of bounds, chunk0 %lu wmark %lu",
                   chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    }
    fd_memcpy( ctx->replay_msg, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sz );
    break;
  }
  case IN_KIND_EPOCH:  break;
  case IN_KIND_IPECHO: break;
  default:             break;
  }
}

static void
after_frag( fd_votor_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)tsorig; (void)tspub;

  ctx->stem = stem;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_NET:
    if( FD_UNLIKELY( sz<sizeof(fd_eth_hdr_t) ) ) break;
    fd_quic_process_packet( ctx->quic,
                            ctx->net_buf+sizeof(fd_eth_hdr_t),
                            sz-sizeof(fd_eth_hdr_t),
                            fd_log_wallclock() );
    break;
  case IN_KIND_REPLAY: {
    fd_replay_slot_completed_t const * slot_completed  = &ctx->replay_msg->slot_completed;
    ag_block_id_t                      block_id        = ag_block_id( slot_completed->slot,        slot_completed->block_id.uc        );
    ag_block_id_t                      parent_block_id = ag_block_id( slot_completed->parent_slot, slot_completed->parent_block_id.uc );
    ag_pool_add_block( ctx->pool, &block_id, &parent_block_id );
    break;
  }
  case IN_KIND_IPECHO:
    FD_TEST( sig && sig<=USHORT_MAX );
    ctx->shred_version = (ushort)sig;
    break;
  case IN_KIND_EPOCH:  break;
  default:             break;
  }
}

static inline void
after_credit( fd_votor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  ctx->stem = stem;

  *charge_busy = fd_quic_service( ctx->quic, fd_log_wallclock() );
  *opt_poll_in = !*charge_busy;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->votor.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_keypair = fd_keyload_load( tile->votor.identity_key_path, 0 );

  fd_log_wallclock();
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t)                         );
  void *            _quic = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),          fd_quic_footprint( &quic_limits )               );
  void *            pool  = FD_SCRATCH_ALLOC_APPEND( l, ag_pool_align(),          ag_pool_footprint( tile->votor.max_live_slots ) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->shred_version = (ushort)0;

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );

  ulong seed;
  FD_TEST( fd_rng_secure( &seed, sizeof(seed) ) );

  ctx->pool = ag_pool_join( ag_pool_new( pool, tile->votor.max_live_slots, seed ) );
  FD_TEST( ctx->pool );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch" ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "net_votor"    ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
    }
    else FD_LOG_ERR(( "votor tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( link->mtu ) ) {
      ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
      ctx->in[ i ].mtu    = link->mtu;
    }
  }

  FD_TEST( tile->out_cnt>OUT_IDX_NET );
  fd_topo_link_t const * net_out = &topo->links[ tile->out_link_id[ OUT_IDX_NET ] ];
  FD_TEST( !strcmp( net_out->name, "votor_net" ) );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  ctx->quic = fd_quic_join( fd_quic_new( _quic, &quic_limits ) );
  FD_TEST( ctx->quic );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_aio_tx ) );
  FD_TEST( quic_tx_aio );
  fd_quic_set_aio_net_tx( ctx->quic, quic_tx_aio );

  ctx->quic->config.role         = FD_QUIC_ROLE_SERVER;
  ctx->quic->config.retry        = 0;
  ctx->quic->config.idle_timeout = 5L*1000L*1000L*1000L; /* TODO */
  ctx->quic->config.ack_delay    = 2L*1000L*1000L;       /* TODO */
  fd_memcpy( ctx->quic->config.identity_public_key, ctx->identity_keypair+32UL, 32UL );
  ctx->quic->config.sign        = quic_sign;
  ctx->quic->config.sign_ctx    = ctx;
  ctx->quic->config.alpn[ 0 ]   = 0x0c;
  fd_memcpy( ctx->quic->config.alpn+1, "alpenglow-v1", 12UL );
  ctx->quic->config.alpn_sz     = 13UL;
  ctx->quic->config.initial_rx_max_stream_data = 0UL;
  ctx->quic->config.max_datagram_frame_size    = 1280UL; /* IPv6 MTU */

  ctx->quic->cb.quic_ctx    = ctx;
  ctx->quic->cb.conn_new    = quic_conn_new;
  ctx->quic->cb.datagram_rx = quic_datagram_rx;

  FD_TEST( fd_quic_init( ctx->quic ) );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_votor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_votor_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_votor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_votor_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_votor = {
  .name                     = "votor",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
