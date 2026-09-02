#include "fd_votor_tile.h"
#include <linux/futex.h>
#include "generated/fd_votor_tile_seccomp.h"

#include "../../ballet/bls/fd_bls12_381.h"
#include "../../choreo/votor/ag_cert_serde.h"
#include "../../choreo/votor/ag_pool.h"
#include "../../choreo/votor/ag_vote_serde.h"
#include "../../choreo/votor/ag_votor.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../util/net/fd_net_headers.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../waltz/quic/fd_quic_conn.h"
#include "../../waltz/quic/tls/fd_quic_tls.h"
#include "../replay/fd_replay_tile.h"

#define IN_KIND_EPOCH  (0)
#define IN_KIND_GOSSIP (1)
#define IN_KIND_IPECHO (2)
#define IN_KIND_NET    (3)
#define IN_KIND_REPLAY (4)

#define OUT_IDX_VOTOR (0UL)
#define OUT_IDX_NET   (1UL)

#define QUIC_CONN_MAX (AG_VAT_MAX * 2)

#define CLOSE_CODE_INVALID_IDENTITY (2U)
#define CLOSE_CODE_NOT_ADMITTED     (3U)

static fd_quic_limits_t quic_client_limits = {
  .conn_cnt                    = AG_VAT_MAX,
  .handshake_cnt               = 1024UL,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 16UL * AG_VAT_MAX,
  .min_inflight_frame_cnt_conn = 8UL,
};

static fd_quic_limits_t quic_server_limits = {
  .conn_cnt                    = QUIC_CONN_MAX,
  .handshake_cnt               = 1024UL,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 64UL * QUIC_CONN_MAX,
  .min_inflight_frame_cnt_conn = 32UL,
};

#define STACK_NAME rooted
#define STACK_T    ag_block_id_t
#include "../../util/tmpl/fd_stack.c"

struct replayed {
  ag_block_id_t block_id;
  ag_block_id_t parent_block_id;
};
typedef struct replayed replayed_t;

#define MAP_NAME               replayed
#define MAP_T                  replayed_t
#define MAP_KEY                block_id
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_NULL           ((ag_block_id_t){ .slot = ULONG_MAX })
#define MAP_KEY_INVAL(k)       ((k).slot==ULONG_MAX)
#define MAP_KEY_EQUAL(k0,k1)   (!memcmp( &(k0), &(k1), sizeof(ag_block_id_t) ))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(key,seed) ((uint)fd_hash( (seed), &(key), sizeof(ag_block_id_t) ))
#define MAP_MEMOIZE            0
#include "../../util/tmpl/fd_map_dynamic.c"

/* The footer of a block we produce declares the highest finalization
   cert we hold, and the notarization and skip votes that earned rewards
   FD_NUM_SLOTS_FOR_REWARD slots back.  ag_pool will not hand a cert
   back after the fact, so the tile keeps what a footer needs as certs
   go past.

   reward_slot caches, per slot, the widest notarization and skip
   aggregate seen for it.  Only the plain notar and skip aggregates are
   eligible: a reward cert is one compressed signature over one base2
   bitmap, and the fallback aggregates of a skip or notar-fallback cert
   sign a different vote message, so they cannot be folded in.

   Publishing a leader window reads the reward slots of the whole window
   while skip certs for the window itself can already be arriving, so
   the live span is
   [ W-FD_NUM_SLOTS_FOR_REWARD, W+AG_SLOTS_PER_WINDOW-1 ], and one more
   keeps the next slot from aliasing onto the oldest. */

#define REWARD_SLOT_MAX (64UL) /* >= FD_NUM_SLOTS_FOR_REWARD+AG_SLOTS_PER_WINDOW+1 = 13 */
FD_STATIC_ASSERT( REWARD_SLOT_MAX>FD_NUM_SLOTS_FOR_REWARD+AG_SLOTS_PER_WINDOW, reward_slot_max );

struct reward_slot {
  ulong           slot; /* ULONG_MAX when the entry holds no slot */
  int             has_notar;
  ag_block_hash_t notar_block_hash;
  ag_bls_agg_t    notar_agg;
  int             has_skip;
  ag_bls_agg_t    skip_agg;
};
typedef struct reward_slot reward_slot_t;

struct publish {
  ulong          sig;
  fd_votor_msg_t msg;
};
typedef struct publish publish_t;

#define QUEUE_NAME publishes
#define QUEUE_T    publish_t
#include "../../util/tmpl/fd_queue_dynamic.c"

#define CONTACT_INFOS_LG_SLOT_CNT (16) /* FD_CONTACT_INFO_TABLE_SIZE keys, fill ratio 0.5 */
FD_STATIC_ASSERT( (1UL<<CONTACT_INFOS_LG_SLOT_CNT)==2UL*FD_CONTACT_INFO_TABLE_SIZE, contact_infos );

struct contact_info {
  fd_pubkey_t id_key;
  uint        ip4;
  ushort      port;
};
typedef struct contact_info contact_info_t;

#define MAP_NAME              contact_infos
#define MAP_T                 contact_info_t
#define MAP_LG_SLOT_CNT       CONTACT_INFOS_LG_SLOT_CNT
#define MAP_KEY               id_key
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          ((fd_pubkey_t){ .ul = {0} }) /* no validator identity is the zero pubkey */
#define MAP_KEY_INVAL(k)      (!((k).ul[0]|(k).ul[1]|(k).ul[2]|(k).ul[3]))
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( &(k0), &(k1), sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_hash( 0UL, &(key), sizeof(fd_pubkey_t) ))
#define MAP_MEMOIZE           0
#include "../../util/tmpl/fd_map.c"

#define PEERS_LG_SLOT_CNT (13) /* 2*AG_VAT_MAX keys, fill ratio 0.5 */
FD_STATIC_ASSERT( (1UL<<PEERS_LG_SLOT_CNT)>=4UL*AG_VAT_MAX, peers );

struct peer {
  fd_pubkey_t      id_key;
  ushort           curr_rank;
  ushort           next_rank;
  fd_quic_conn_t * conn;
};
typedef struct peer peer_t;

#define MAP_NAME              peers
#define MAP_T                 peer_t
#define MAP_LG_SLOT_CNT       PEERS_LG_SLOT_CNT
#define MAP_KEY               id_key
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          ((fd_pubkey_t){ .ul = {0} }) /* no validator identity is the zero pubkey */
#define MAP_KEY_INVAL(k)      (!((k).ul[0]|(k).ul[1]|(k).ul[2]|(k).ul[3]))
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( &(k0), &(k1), sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_hash( 0UL, &(key), sizeof(fd_pubkey_t) ))
#define MAP_MEMOIZE           0
#include "../../util/tmpl/fd_map.c"

struct fd_votor_tile {

  /* Metadata */

  uchar const * identity_keypair; /* FIXME keyguard */
  fd_pubkey_t   id_key;
  ag_bls_sec_t  bls_key;
  uchar         sha512[ FD_SHA512_FOOTPRINT ] __attribute__((aligned(FD_SHA512_ALIGN)));
  ushort        shred_version;

  /* Data */

  int               init;
  ag_block_id_t     rooted_block_id;
  ag_epoch_info_t * curr_epoch_info;
  ulong             curr_epoch_slot;
  ushort            curr_epoch_rank;
  ag_epoch_info_t * next_epoch_info;
  ulong             next_epoch_slot;
  ushort            next_epoch_rank;
  contact_info_t *  contact_infos;
  peer_t *          peers;
  ag_pool_t *       pool;
  ag_votor_t *      votor;
  replayed_t *      replayed;
  ag_block_id_t *   rooted;
  publish_t *       publishes;

  /* Leader */

  fd_multi_epoch_leaders_t * mleaders;
  ulong                      next_leader_slot;

  /* Certs */

  int                  has_fast_final_cert;
  int                  has_final_cert;
  ag_cert_fast_final_t fast_final_cert;
  ag_cert_final_t      final_cert;
  ag_cert_notar_t      notar_cert;
  reward_slot_t        reward_slots[ REWARD_SLOT_MAX ];

  /* Networking */

  fd_pubkey_t        client_peer_id_keys[ QUIC_CONN_MAX ];
  fd_pubkey_t        server_peer_id_keys[ QUIC_CONN_MAX ];
  fd_net_rx_bounds_t net_in_bounds[ 32 ];
  uchar              net_buf[ FD_NET_MTU ];
  fd_quic_t *        quic_client;
  fd_quic_t *        quic_server;
  uchar              quic_tx_aio[ 128 ] __attribute__((aligned(alignof(fd_aio_t))));
  ushort             quic_client_listen_port;
  ushort             quic_server_listen_port;
  uint               src_ip_addr;
  fd_ip4_udp_hdrs_t  hdr[ 1 ];
  ushort             net_id;

  /* Links */

  int in_kind[ 32 ];
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

  void * votor_out_mem;
  ulong  votor_out_chunk0;
  ulong  votor_out_wmark;
  ulong  votor_out_chunk;

  fd_stem_context_t * stem;

  /* Scratch */

  struct {
    union {
      ag_vote_t           vote;
      ag_cert_t           cert;
      ag_event_pool_t     pool_event;
      ag_event_repair_t   repair_event;
      ag_event_timeout_t  timeout_event;
      ag_event_vote_t     vote_event;
      ag_event_cert_t     cert_event;
    };
    ag_epoch_info_t curr_epoch_info;
    ag_epoch_info_t next_epoch_info;

    uchar ser[ AG_VOTE_SER_SZ( 1 ) > AG_CERT_SER_MAX ? AG_VOTE_SER_SZ( 1 ) : AG_CERT_SER_MAX ];
  } scratch;
};
typedef struct fd_votor_tile fd_votor_tile_t;

static void
record_final_cert( fd_votor_tile_t * ctx,
                   ag_cert_t const * cert ) {
  ulong                 slot       = ag_cert_slot( cert );
  reward_slot_t const * rs         = &ctx->reward_slots[ slot%REWARD_SLOT_MAX ];
  int                   have_notar = rs->slot==slot && rs->has_notar;

  int   have_final = ctx->has_fast_final_cert || ctx->has_final_cert;
  ulong final_slot = ctx->has_fast_final_cert ? ctx->fast_final_cert.slot : ctx->final_cert.slot;

  if( cert->kind==AG_CERT_KIND_FAST_FINAL ) {
    if( !have_final || slot>final_slot || ( slot==final_slot && ctx->has_final_cert ) ) {
      ctx->has_fast_final_cert = 1;
      ctx->has_final_cert      = 0;
      ctx->fast_final_cert     = cert->fast_final;
    }
  } else if( cert->kind==AG_CERT_KIND_FINAL ) {
    if( ( !have_final || slot>final_slot ) && have_notar ) {
      ctx->has_fast_final_cert = 0;
      ctx->has_final_cert      = 1;
      ctx->final_cert          = cert->final;
      fd_memset( &ctx->notar_cert, 0, sizeof(ag_cert_notar_t) );
      ctx->notar_cert.slot     = slot;
      ctx->notar_cert.agg_sig  = rs->notar_agg;
      memcpy( ctx->notar_cert.block_hash, rs->notar_block_hash, sizeof(ag_block_hash_t) );
    }
  }
}

static void
record_reward_cert( fd_votor_tile_t * ctx,
                    ag_cert_t const * cert ) {
  /* TODO naively implemented to just pass along certs */

  ulong           slot = ag_cert_slot( cert );
  reward_slot_t * rs   = &ctx->reward_slots[ slot%REWARD_SLOT_MAX ];

  if( FD_UNLIKELY( rs->slot!=slot ) ) {
    rs->slot      = slot;
    rs->has_notar = 0;
    rs->has_skip  = 0;
  }

  if( cert->kind==AG_CERT_KIND_NOTAR && ( !rs->has_notar || ag_bls_agg_signer_cnt( &cert->notar.agg_sig )>ag_bls_agg_signer_cnt( &rs->notar_agg ) ) ) {
    rs->has_notar = 1;
    rs->notar_agg = cert->notar.agg_sig;
    memcpy( rs->notar_block_hash, cert->notar.block_hash, sizeof(ag_block_hash_t) );
  } else if( cert->kind==AG_CERT_KIND_SKIP && ( !rs->has_skip || ag_bls_agg_signer_cnt( &cert->skip.agg_sig_skip )>ag_bls_agg_signer_cnt( &rs->skip_agg ) ) ) {
    rs->has_skip = 1;
    rs->skip_agg = cert->skip.agg_sig_skip;
  }
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
quic_client_conn_final( fd_quic_conn_t * conn,
                        void *           _ctx ) {
  fd_votor_tile_t *   ctx    = _ctx;
  fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
  if( FD_UNLIKELY( !id_key ) ) return;
  peer_t * peer = peers_query( ctx->peers, *id_key, NULL );
  if( FD_LIKELY( peer ) ) peer->conn = NULL;
}

static void
quic_client_conn_hs_complete( fd_quic_conn_t * conn,
                              void *           _ctx ) {
  (void)_ctx;
  fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
  if( FD_UNLIKELY( !id_key ) ) return;

  if( FD_LIKELY( !conn->tls_hs || memcmp( conn->tls_hs->hs.cli.server_pubkey, id_key->uc, sizeof(fd_pubkey_t) ) ) ) {
    fd_quic_conn_close( conn, CLOSE_CODE_INVALID_IDENTITY );
  }
}

static void
quic_client_datagram_tx( fd_votor_tile_t * ctx,
                         fd_quic_conn_t *  conn,
                         uchar const *     buf,
                         ulong             buf_sz ) {
  uchar * packet_l2 = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
  uchar * payload   = packet_l2 + sizeof(fd_ip4_udp_hdrs_t);

  ulong pkt_sz = fd_quic_conn_tx_dgram( conn, payload, FD_NET_MTU-sizeof(fd_ip4_udp_hdrs_t), buf, buf_sz );
  if( FD_UNLIKELY( !pkt_sz ) ) return;

  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)fd_type_pun( packet_l2 );
  *hdr = *ctx->hdr;

  hdr->ip4->daddr       = conn->peer[ 0 ].ip_addr;
  hdr->ip4->net_tot_len = fd_ushort_bswap( (ushort)( pkt_sz+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) );
  hdr->ip4->net_id      = fd_ushort_bswap( ctx->net_id++ );
  hdr->ip4->check       = 0;
  hdr->ip4->check       = fd_ip4_hdr_check_fast( hdr->ip4 );

  hdr->udp->net_dport = fd_ushort_bswap( conn->peer[ 0 ].udp_port );
  hdr->udp->net_len   = fd_ushort_bswap( (ushort)( pkt_sz+sizeof(fd_udp_hdr_t) ) );
  hdr->udp->check     = (ushort)0;

  uint  ip_dst = hdr->ip4->daddr;
  ulong sig    = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
  ulong sz_l2  = sizeof(fd_ip4_udp_hdrs_t) + pkt_sz;
  fd_stem_publish( ctx->stem, OUT_IDX_NET, sig, ctx->net_out_chunk, sz_l2, fd_frag_meta_ctl( 0UL, 1, 1, 0 ), 0L, 0L );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void
quic_server_conn_new( fd_quic_conn_t * conn,
                      void *           _ctx ) {
  if( FD_UNLIKELY( !conn->tls_hs ) ) return; /* no authenticated identity, so no votes will be attributed */
  fd_pubkey_t const * id_key = (fd_pubkey_t const *)fd_type_pun_const( conn->tls_hs->hs.srv.client_pubkey );

  fd_votor_tile_t * ctx = _ctx;
  if( FD_LIKELY( ctx->curr_epoch_info ) && FD_UNLIKELY( !peers_query( ctx->peers, *id_key, NULL ) ) ) {
    fd_quic_conn_close( conn, 0U );
    return;
  }
  ctx->server_peer_id_keys[ conn->conn_idx ] = *id_key;
  fd_quic_conn_set_context( conn, &ctx->server_peer_id_keys[ conn->conn_idx ] );
}

static void
quic_server_datagram_rx( fd_quic_conn_t * conn,
                         uchar const *    data,
                         ulong            data_sz,
                         void *           _ctx ) {

  fd_votor_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( !ctx->init  ) ) return;
  if( FD_UNLIKELY( data_sz<2UL ) ) return;
  uchar kind = data[ 1 ];

  switch( kind ) {
  case AG_VOTE_SERDE_TAG_NOTAR:
  case AG_VOTE_SERDE_TAG_FINAL:
  case AG_VOTE_SERDE_TAG_SKIP:
  case AG_VOTE_SERDE_TAG_NOTAR_FALLBACK:
  case AG_VOTE_SERDE_TAG_SKIP_FALLBACK:
  case AG_VOTE_SERDE_TAG_GENESIS: {
    if( FD_UNLIKELY( ag_vote_de( &ctx->scratch.vote, ctx->shred_version, data, data_sz ) ) ) return;

    fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
    if( FD_UNLIKELY( !id_key ) ) return;
    peer_t const * peer = peers_query( ctx->peers, *id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) return;

    ulong                   vote_slot  = ag_vote_slot( &ctx->scratch.vote );
    ushort                  rank       = fd_ushort_if( vote_slot>=ctx->next_epoch_slot, peer->next_rank, peer->curr_rank );
    if( FD_UNLIKELY( rank==USHORT_MAX ) ) return; /* peer is not ranked in their vote slot's epoch */
    ag_vote_set_rank( &ctx->scratch.vote, rank );
    // if( FD_UNLIKELY( !ag_vote_verify( &ctx->scratch.vote, epoch_info->validators[ rank ].bls_key, ctx->shred_version ) ) ) return; /* FIXME BLS is too expensive */
    ag_pool_add_vote( ctx->pool, &ctx->scratch.vote );
    return;
  }
  case AG_CERT_SERDE_TAG_FINAL:
  case AG_CERT_SERDE_TAG_FAST_FINAL:
  case AG_CERT_SERDE_TAG_NOTAR:
  case AG_CERT_SERDE_TAG_NOTAR_FALLBACK:
  case AG_CERT_SERDE_TAG_SKIP:
  case AG_CERT_SERDE_TAG_GENESIS: {
    if( FD_UNLIKELY( ag_cert_de( &ctx->scratch.cert, ctx->shred_version, data, data_sz ) ) ) return;

    fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
    if( FD_UNLIKELY( !id_key ) ) return;
    peer_t const * peer = peers_query( ctx->peers, *id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) return;

    ulong                   cert_slot = ag_cert_slot( &ctx->scratch.cert );
    ushort                  rank      = fd_ushort_if( cert_slot>=ctx->next_epoch_slot, peer->next_rank, peer->curr_rank );
    if( FD_UNLIKELY( rank==USHORT_MAX ) ) return; /* peer is not ranked in this cert slot's epoch */

    // if( FD_UNLIKELY( !ag_cert_verify( &ctx->scratch.cert, epoch_info, ctx->shred_version ) ) ) return; /* FIXME BLS is too expensive, 35x duplicate certs each cost a pairing */
    ag_pool_add_cert( ctx->pool, &ctx->scratch.cert );
    return;
  }
  default:
    return;
  }
}

static void
quic_sign( void *      signer_ctx,
           uchar       signature[ static 64 ],
           uchar const payload[ static 130 ] ) {
  fd_votor_tile_t * ctx = signer_ctx;

  fd_sha512_t * sha = fd_sha512_join( ctx->sha512 );
  fd_ed25519_sign( signature, payload, 130UL, ctx->identity_keypair+32UL, ctx->identity_keypair, sha ); /* TODO keyguard */
  fd_sha512_leave( sha );
}

static void
handle_epoch( fd_votor_tile_t *           ctx,
              fd_epoch_info_msg_t const * msg ) {

  ag_epoch_info_t * epoch_info;
  if     ( FD_UNLIKELY( !ctx->curr_epoch_info ) ) epoch_info = &ctx->scratch.curr_epoch_info;
  else if( FD_UNLIKELY( !ctx->next_epoch_info ) ) epoch_info = &ctx->scratch.next_epoch_info;
  else                                            epoch_info = ctx->curr_epoch_info;
  ag_epoch_info_rank( epoch_info, fd_epoch_info_msg_stake_weights( msg ), msg->staked_vote_cnt );

  /* swap pointers */

  if( FD_UNLIKELY( !ctx->curr_epoch_info ) ) {
    ctx->curr_epoch_info = epoch_info;
    ctx->curr_epoch_slot = msg->start_slot;
  } else {
    if( FD_LIKELY( ctx->next_epoch_info ) ) {
      ctx->curr_epoch_info = ctx->next_epoch_info;
      ctx->curr_epoch_slot = ctx->next_epoch_slot;
    }
    ctx->next_epoch_info = epoch_info;
    ctx->next_epoch_slot = msg->start_slot;
  }

  /* mark all for deletion */

  for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
    peer_t * peer = &ctx->peers[ slot ];
    if( FD_LIKELY( peers_key_inval( peer->id_key ) ) ) continue;
    peer->curr_rank = USHORT_MAX;
    peer->next_rank = USHORT_MAX;
  }

  /* unmark all ranked in curr epoch */

  for( ulong rank=0UL; rank<ctx->curr_epoch_info->validator_cnt; rank++ ) {
    fd_pubkey_t id_key;
    memcpy( id_key.uc, ctx->curr_epoch_info->validators[ rank ].id_key, sizeof(ag_id_key_t) );

    peer_t * peer = peers_query( ctx->peers, id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) {
      peer            = peers_insert( ctx->peers, id_key );
      peer->next_rank = USHORT_MAX;
      peer->conn      = NULL;
    }
    peer->curr_rank = (ushort)rank;
  }

  /* unmark all ranked in next epoch */

  /* Not fd_ulong_if: it is a function, so it would load validator_cnt
     through next_epoch_info before selecting.  On the first epoch
     message the swap above leaves next_epoch_info NULL. */

  ulong next_cnt = ctx->next_epoch_info ? ctx->next_epoch_info->validator_cnt : 0UL;
  for( ulong rank=0UL; rank<next_cnt; rank++ ) {
    fd_pubkey_t id_key;
    memcpy( id_key.uc, ctx->next_epoch_info->validators[ rank ].id_key, sizeof(ag_id_key_t) );

    peer_t * peer = peers_query( ctx->peers, id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) {
      peer            = peers_insert( ctx->peers, id_key );
      peer->curr_rank = USHORT_MAX;
      peer->conn      = NULL;
    }
    peer->next_rank = (ushort)rank;
  }

  /* quic_connect new peers */

  long now = fd_log_wallclock();
  for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
    peer_t * peer = &ctx->peers[ slot ];
    if( FD_LIKELY( peers_key_inval( peer->id_key ) ) ) continue;
    if( FD_LIKELY( peers_query( ctx->peers, peer->id_key, NULL ) ) ) {
      contact_info_t * ci = contact_infos_query( ctx->contact_infos, peer->id_key, NULL );
      if( FD_LIKELY( ci && !peer->conn ) ) {
        fd_quic_conn_t * conn = fd_quic_connect( ctx->quic_client, ci->ip4, ci->port, ctx->src_ip_addr, ctx->quic_client_listen_port, now );
        if( FD_LIKELY( conn ) ) {
          ctx->client_peer_id_keys[ conn->conn_idx ] = peer->id_key;
          fd_quic_conn_set_context( conn, &ctx->client_peer_id_keys[ conn->conn_idx ] );
          peer->conn = conn;
        }
      }
    }
  }

  /* quic_conn_close evicted peers */

  for( ulong slot=0UL; slot<peers_slot_cnt(); ) {
    peer_t * peer = &ctx->peers[ slot ];
    if( FD_LIKELY( peers_key_inval( peer->id_key ) ) )                            { slot++; continue; }
    if( FD_LIKELY( peer->curr_rank!=USHORT_MAX || peer->next_rank!=USHORT_MAX ) ) { slot++; continue; }
    if( FD_LIKELY( peer->conn ) ) {
      fd_quic_conn_set_context( peer->conn, NULL );
      fd_quic_conn_close( peer->conn, CLOSE_CODE_NOT_ADMITTED );
      peer->conn = NULL;
    }
    peers_remove( ctx->peers, peer ); /* relocates, so reconsider the freed slot */
  }

  /* update our own rank */

  peer_t const * self = peers_query( ctx->peers, ctx->id_key, NULL );
  ctx->curr_epoch_rank = self ? self->curr_rank : USHORT_MAX;
  ctx->next_epoch_rank = self ? self->next_rank : USHORT_MAX;

  /* update structures */

  ushort epoch_rank = fd_ushort_if( !!ctx->next_epoch_info, ctx->next_epoch_rank, ctx->curr_epoch_rank );
  ag_pool_advance_epoch( ctx->pool, epoch_info, epoch_rank, msg->start_slot );
  ag_votor_advance_epoch( ctx->votor, epoch_rank, msg->start_slot );

  /* update our leader schedule.  msg only points into the epoch dcache
     for this callback, so it must be consumed here. */

  fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, msg );
  fd_multi_epoch_leaders_epoch_msg_fini( ctx->mleaders );
  if( FD_UNLIKELY( ctx->next_leader_slot==ULONG_MAX ) ) ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, msg->start_slot, &ctx->id_key );

  ctx->init = ctx->rooted_block_id.slot!=ULONG_MAX && !!ctx->shred_version;
}

static void
handle_gossip( fd_votor_tile_t *                  ctx,
               ulong                              sig,
               fd_gossip_update_message_t const * msg ) {

  fd_pubkey_t id_key;
  memcpy( id_key.uc, msg->origin, sizeof(fd_pubkey_t) );
  if( FD_UNLIKELY( peers_key_inval( id_key ) ) ) return;

  contact_info_t contact_info = {0}; /* dummy 0:0 address for removal */
  switch( sig ) {
  case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
    fd_gossip_socket_t const * socket = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ];
    contact_info.ip4  = fd_uint_if  ( !socket->is_ipv6, socket->ip4,                     0U        );
    contact_info.port = fd_ushort_if( !socket->is_ipv6, fd_ushort_bswap( socket->port ), (ushort)0 );
    break;
  }
  case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE:
    break;
  default:
    FD_LOG_ERR(( "unexpected gossip sig %lu", sig ));
  }

  contact_info_t * ci   = contact_infos_query( ctx->contact_infos, id_key, NULL );
  peer_t *         peer = peers_query        ( ctx->peers,         id_key, NULL );

  if( FD_UNLIKELY( !contact_info.port ) ) { /* nowhere left to reach it */
    if( FD_LIKELY( ci ) ) contact_infos_remove( ctx->contact_infos, ci );
    if( FD_UNLIKELY( peer && peer->conn ) ) {
      fd_quic_conn_set_context( peer->conn, NULL );
      fd_quic_conn_close( peer->conn, 0U );
      peer->conn = NULL;
    }
    return;
  }

  if( FD_UNLIKELY( !ci ) ) {
    ci       = contact_infos_insert( ctx->contact_infos, id_key );
    ci->ip4  = contact_info.ip4;
    ci->port = contact_info.port;
  } else if( FD_UNLIKELY( ci->ip4 !=contact_info.ip4 || ci->port!=contact_info.port ) ) {
    ci->ip4  = contact_info.ip4;
    ci->port = contact_info.port;
    if( FD_UNLIKELY( peer && peer->conn ) ) { /* our conn is to the old address */
      fd_quic_conn_set_context( peer->conn, NULL );
      fd_quic_conn_close( peer->conn, 0U );
      peer->conn = NULL;
    }
  }

  if( FD_LIKELY( peer && !peer->conn ) ) {
    fd_quic_conn_t * conn = fd_quic_connect( ctx->quic_client, ci->ip4, ci->port, ctx->src_ip_addr, ctx->quic_client_listen_port, fd_log_wallclock() );
    if( FD_LIKELY( conn ) ) {
      ctx->client_peer_id_keys[ conn->conn_idx ] = peer->id_key;
      fd_quic_conn_set_context( conn, &ctx->client_peer_id_keys[ conn->conn_idx ] );
      peer->conn = conn;
    }
  }
}

static void
handle_replay( fd_votor_tile_t *           ctx,
               ulong                       sig,
               fd_replay_message_t const * replay ) {

  switch( sig ) {
  case REPLAY_SIG_SLOT_COMPLETED: {
    fd_replay_slot_completed_t const * slot_completed  = &replay->slot_completed;
    ag_block_id_t                      block_id        = ag_block_id( slot_completed->slot,        slot_completed->block_id.uc        );
    ag_block_id_t                      parent_block_id = ag_block_id( slot_completed->parent_slot, slot_completed->parent_block_id.uc );
    if( FD_LIKELY( !replayed_query( ctx->replayed, block_id, NULL ) ) ) replayed_insert( ctx->replayed, block_id )->parent_block_id = parent_block_id;
    if( FD_UNLIKELY( ctx->rooted_block_id.slot==ULONG_MAX ) ) {
      ctx->rooted_block_id = block_id;
      ag_pool_init ( ctx->pool,  block_id.slot );
      ag_votor_init( ctx->votor, block_id.slot, fd_log_wallclock() );
      ctx->init = !!ctx->curr_epoch_info && !!ctx->shred_version;
    } else if( FD_UNLIKELY( block_id.slot!=0 ) ) {
      ag_pool_add_block( ctx->pool, &block_id, &parent_block_id );
    }
    ag_event_replay_t completed = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = block_id.slot, .block_info = { .parent = parent_block_id } };
    memcpy( completed.block_info.hash, block_id.hash, sizeof(ag_block_hash_t) );
    ag_votor_handle_replay_event( ctx->votor, &completed );
    break;
  }
  case REPLAY_SIG_SLOT_DEAD: {
    fd_replay_slot_dead_t const * slot_dead = &replay->slot_dead;
    ag_event_replay_t             dead      = { .kind = AG_EVENT_REPLAY_DEAD, .slot = slot_dead->slot };
    ag_votor_handle_replay_event( ctx->votor, &dead );
    break;
  }
  default:
    FD_LOG_ERR(( "unexpected replay sig %lu", sig ));
  }
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_votor_tile_t), fd_quic_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( AG_EQVOC_BLOCK_HASH_MAX*tile->votor.max_live_slots ) ) + 1;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_votor_tile_t),       sizeof(fd_votor_tile_t)                           );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_client_limits )          );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_server_limits )          );
  l = FD_LAYOUT_APPEND( l, ag_pool_align(),                ag_pool_footprint( tile->votor.max_live_slots )   );
  l = FD_LAYOUT_APPEND( l, ag_votor_align(),               ag_votor_footprint( tile->votor.max_live_slots )  );
  l = FD_LAYOUT_APPEND( l, replayed_align(),               replayed_footprint( lg_blk_max )                  );
  l = FD_LAYOUT_APPEND( l, rooted_align(),                 rooted_footprint( tile->votor.max_live_slots )    );
  l = FD_LAYOUT_APPEND( l, publishes_align(),              publishes_footprint( tile->votor.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, peers_align(),                  peers_footprint()                                 );
  l = FD_LAYOUT_APPEND( l, contact_infos_align(),          contact_infos_footprint()                         );
  l = FD_LAYOUT_APPEND( l, fd_multi_epoch_leaders_align(), fd_multi_epoch_leaders_footprint()                );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
after_credit( fd_votor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {

  long now     = fd_log_wallclock();
  ctx->stem    = stem;
  *charge_busy = fd_quic_service( ctx->quic_client, now ) | fd_quic_service( ctx->quic_server, now );

  if( FD_LIKELY( !publishes_empty( ctx->publishes ) ) ) {
    publish_t pub = publishes_pop( ctx->publishes );
    memcpy( fd_chunk_to_laddr( ctx->votor_out_mem, ctx->votor_out_chunk ), &pub.msg, sizeof(fd_votor_msg_t) );
    fd_stem_publish( stem, OUT_IDX_VOTOR, pub.sig, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
    *opt_poll_in         = 0; /* drain the publishes */
    *charge_busy         = 1;
    return;
  }

  if( FD_UNLIKELY( !ctx->init ) ) return;

  if( FD_UNLIKELY( ag_pool_poll_pool_event( ctx->pool, &ctx->scratch.pool_event ) ) ) {
    ag_votor_handle_pool_event( ctx->votor, &ctx->scratch.pool_event, now );
    ag_cert_t const * cert = &ctx->scratch.pool_event.cert_created;
    if( FD_UNLIKELY( ctx->scratch.pool_event.kind==AG_EVENT_POOL_CERT_CREATED ) ) {
      publish_t pub;
      switch( cert->kind ) {
      case AG_CERT_KIND_FINAL:          pub.sig = FD_VOTOR_SIG_FINAL;          pub.msg.final.slot          = cert->final.slot;          ag_pool_finalized_block_hash( ctx->pool, cert->final.slot, pub.msg.final.block_id.uc ); break; /* names only the slot */
      case AG_CERT_KIND_FAST_FINAL:     pub.sig = FD_VOTOR_SIG_FAST_FINAL;     pub.msg.fast_final.slot     = cert->fast_final.slot;     memcpy( pub.msg.fast_final.block_id.uc,     cert->fast_final.block_hash,     sizeof(fd_hash_t) ); break;
      case AG_CERT_KIND_NOTAR:          pub.sig = FD_VOTOR_SIG_NOTAR;          pub.msg.notar.slot          = cert->notar.slot;          memcpy( pub.msg.notar.block_id.uc,          cert->notar.block_hash,          sizeof(fd_hash_t) ); break;
      case AG_CERT_KIND_NOTAR_FALLBACK: pub.sig = FD_VOTOR_SIG_NOTAR_FALLBACK; pub.msg.notar_fallback.slot = cert->notar_fallback.slot; memcpy( pub.msg.notar_fallback.block_id.uc, cert->notar_fallback.block_hash, sizeof(fd_hash_t) ); break;
      case AG_CERT_KIND_SKIP:           pub.sig = FD_VOTOR_SIG_SKIP;           pub.msg.skip.slot           = cert->skip.slot;           break;
      default:                          FD_LOG_ERR(( "unexpected certificate kind %u", cert->kind ));
      }
      FD_TEST( !publishes_full( ctx->publishes ) );
      publishes_push( ctx->publishes, pub );
    }
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_pool_poll_repair_event( ctx->pool, &ctx->scratch.repair_event ) ) ) {
    publish_t pub = { .sig = FD_VOTOR_SIG_REPAIR };
    pub.msg.repair.slot = ctx->scratch.repair_event.block.slot;
    memcpy( &pub.msg.repair.block_id, ctx->scratch.repair_event.block.hash, sizeof(fd_hash_t) );
    FD_TEST( !publishes_full( ctx->publishes ) );
    publishes_push( ctx->publishes, pub );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_votor_poll_timeout_event( ctx->votor, now, &ctx->scratch.timeout_event ) ) ) { /* a timeout we set on ParentReady */
    ag_votor_handle_timeout_event( ctx->votor, &ctx->scratch.timeout_event );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_votor_poll_vote_event( ctx->votor, &ctx->scratch.vote_event ) ) ) { /* our own vote */
    ulong                   vote_slot  = ag_vote_slot( &ctx->scratch.vote_event.vote );
    ag_epoch_info_t const * epoch_info = fd_ptr_if( vote_slot>=ctx->next_epoch_slot, ctx->next_epoch_info, ctx->curr_epoch_info );
    ulong                   rank       = ag_vote_rank( &ctx->scratch.vote_event.vote );
    if( FD_LIKELY( vote_slot>=ctx->curr_epoch_slot && epoch_info && rank<epoch_info->validator_cnt ) ) {
      ag_pool_add_vote( ctx->pool, &ctx->scratch.vote_event.vote );

      ulong ser_sz = ag_vote_ser( &ctx->scratch.vote_event.vote, ctx->shred_version, ctx->scratch.ser );
      for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
        peer_t const * peer = &ctx->peers[ slot ];
        if( FD_LIKELY( peers_key_inval( peer->id_key ) || !peer->conn || peer->conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) continue;
        quic_client_datagram_tx( ctx, peer->conn, ctx->scratch.ser, ser_sz );
      }

      *charge_busy = 1;
    }
  }

  if( FD_UNLIKELY( ag_votor_poll_cert_event( ctx->votor, &ctx->scratch.cert_event ) ) ) { /* a cert the pool accepted, or a standstill re-broadcast */
    ag_pool_add_cert( ctx->pool, &ctx->scratch.cert_event.cert );

    ulong ser_sz = ag_cert_ser( &ctx->scratch.cert_event.cert, ctx->shred_version, ctx->scratch.ser );
    for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
      peer_t const * peer = &ctx->peers[ slot ];
      if( FD_LIKELY( peers_key_inval( peer->id_key ) || !peer->conn || peer->conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) continue;
      quic_client_datagram_tx( ctx, peer->conn, ctx->scratch.ser, ser_sz );
    }

    record_reward_cert( ctx, &ctx->scratch.cert_event.cert );
    record_final_cert ( ctx, &ctx->scratch.cert_event.cert );

    uint            kind           = ctx->scratch.cert_event.cert.kind;
    ulong           finalized_slot = ag_pool_finalized_slot( ctx->pool );
    ag_block_hash_t finalized_hash;
    if( FD_LIKELY( ( kind==AG_CERT_KIND_FINAL || kind==AG_CERT_KIND_FAST_FINAL ) && ag_pool_finalized_block_hash( ctx->pool, finalized_slot, finalized_hash ) ) ) {
      ag_block_id_t ancestor_block_id = ag_block_id( finalized_slot, finalized_hash );
      replayed_t *  replayed          = NULL;

      while( FD_LIKELY( ancestor_block_id.slot>ctx->rooted_block_id.slot && ( replayed = replayed_query( ctx->replayed, ancestor_block_id, NULL ) ) ) ) {
        FD_TEST( !rooted_full( ctx->rooted ) );
        rooted_push( ctx->rooted, ancestor_block_id );
        ancestor_block_id = replayed->parent_block_id;
      }

      if( FD_UNLIKELY( !ag_block_id_eq( &ancestor_block_id, &ctx->rooted_block_id ) ) ) rooted_remove_all( ctx->rooted );

      while( FD_UNLIKELY( !rooted_empty( ctx->rooted ) ) ) {
        ag_block_id_t rooted_block_id = rooted_pop( ctx->rooted );

        publish_t pub = { .sig = FD_VOTOR_SIG_ROOTED };
        pub.msg.rooted.slot = rooted_block_id.slot;
        memcpy( pub.msg.rooted.block_id.uc, rooted_block_id.hash, sizeof(fd_hash_t) );
        FD_TEST( !publishes_full( ctx->publishes ) );
        publishes_push( ctx->publishes, pub );

        replayed = replayed_query( ctx->replayed, rooted_block_id, NULL );
        if( FD_LIKELY( replayed ) ) replayed_remove( ctx->replayed, replayed );

        ctx->rooted_block_id = rooted_block_id;
      }
    }
    *charge_busy = 1;
  }

  if( FD_LIKELY( ctx->next_leader_slot==ULONG_MAX ) ) return; /* never will be leader */

  /* Check if it's time to become leader. */

  ulong finalized_slot = ag_pool_finalized_slot( ctx->pool );
  while( FD_UNLIKELY( ctx->next_leader_slot<=finalized_slot ) ) {
    ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, ctx->next_leader_slot+AG_SLOTS_PER_WINDOW, &ctx->id_key );
    if( FD_UNLIKELY( ctx->next_leader_slot==ULONG_MAX ) ) return; /* schedule exhausted */
  }

  ag_block_id_t parent = ag_pool_wait_for_parent_ready( ctx->pool, ctx->next_leader_slot );
  if( FD_UNLIKELY( parent.slot==ULONG_MAX ) ) return; /* the pool has not granted parent ready yet */

  publish_t pub = { .sig = FD_VOTOR_SIG_LEADER };
  pub.msg.leader.start_slot  = ctx->next_leader_slot;
  pub.msg.leader.parent_slot = parent.slot;
  memcpy( pub.msg.leader.parent_block_id.uc, parent.hash, sizeof(fd_hash_t) );

  /* The footer compresses every aggregate it carries and cannot encode a
     rank past AG_VAT_MAX, so a cert failing either is dropped instead of
     being allowed to make our block unencodable.  A slow finalization
     carries the notarization aggregate too, so both are checked. */

  ag_bls_agg_t const * agg[ 2 ] = {
    fd_ptr_if( ctx->has_fast_final_cert, &ctx->fast_final_cert.agg_sig,
    fd_ptr_if( ctx->has_final_cert,      &ctx->final_cert.agg_sig, NULL ) ),
    fd_ptr_if( ctx->has_final_cert,      &ctx->notar_cert.agg_sig, NULL )
  };

  int final_ready = !!agg[ 0 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    if( !agg[ i ] ) continue;
    uchar csig[ AG_BLS_SIG_COMPRESSED_SZ ];
    ulong last = signer_set_last( agg[ i ]->bitmask );
    if( FD_UNLIKELY( ( last<AG_BLS_SIGNERS_MAX && last>=AG_VAT_MAX ) ||
                     fd_bls12_381_g2_compress( csig, agg[ i ]->sig, 1 ) ) ) final_ready = 0;
  }
  pub.msg.leader.has_fast_final_cert = ctx->has_fast_final_cert && final_ready;
  pub.msg.leader.has_final_cert      = ctx->has_final_cert      && final_ready;
  pub.msg.leader.fast_final_cert     = ctx->fast_final_cert;
  pub.msg.leader.final_cert          = ctx->final_cert;
  pub.msg.leader.notar_cert          = ctx->notar_cert;

  /* One reward cert pair per slot of the window: the runtime only
     accepts the slot FD_NUM_SLOTS_FOR_REWARD before the block. */
  for( ulong i=0UL; i<AG_SLOTS_PER_WINDOW; i++ ) {
    ulong leader_slot = ctx->next_leader_slot+i;
    if( FD_UNLIKELY( leader_slot<FD_NUM_SLOTS_FOR_REWARD ) ) continue;
    ulong                 reward_slot = leader_slot-FD_NUM_SLOTS_FOR_REWARD;
    reward_slot_t const * rs          = &ctx->reward_slots[ reward_slot%REWARD_SLOT_MAX ];
    if( FD_UNLIKELY( rs->slot!=reward_slot ) ) continue;
    if( rs->has_skip  ) pub.msg.leader.has_skip_reward_cert [ i ] = fd_reward_cert_from_agg( &pub.msg.leader.skip_reward_cert [ i ], reward_slot, NULL,                 &rs->skip_agg  );
    if( rs->has_notar ) pub.msg.leader.has_notar_reward_cert[ i ] = fd_reward_cert_from_agg( &pub.msg.leader.notar_reward_cert[ i ], reward_slot, rs->notar_block_hash, &rs->notar_agg );
  }

  FD_TEST( !publishes_full( ctx->publishes ) );
  publishes_push( ctx->publishes, pub );

  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, ctx->next_leader_slot+AG_SLOTS_PER_WINDOW, &ctx->id_key );
  *charge_busy = 1;
}

static int
before_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)seq;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_EPOCH:
    return 0;
  case IN_KIND_GOSSIP:
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  case IN_KIND_IPECHO:
    return 0;
  case IN_KIND_NET:
    if( FD_UNLIKELY( !ctx->curr_epoch_info ) ) return 1;
    return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_VOTOR;
  case IN_KIND_REPLAY:
    if( FD_UNLIKELY( !ctx->curr_epoch_info ) ) return 1;
    return sig!=REPLAY_SIG_SLOT_COMPLETED && sig!=REPLAY_SIG_SLOT_DEAD;
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
during_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz,
             ulong             ctl ) {
  (void)seq;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_EPOCH:
    handle_epoch( ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
    break;
  case IN_KIND_GOSSIP: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) {
      FD_LOG_ERR(( "chunk %lu sz %lu from gossip out of bounds, chunk0 %lu wmark %lu",
                   chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    }
    handle_gossip( ctx, sig, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
    break;
  }
  case IN_KIND_IPECHO:
    /* unreliable link, handled in after_frag */
    break;
  case IN_KIND_NET:
    fd_memcpy( ctx->net_buf, fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz ), sz );
    break;
  case IN_KIND_REPLAY: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>sizeof(fd_replay_message_t) ) ) {
      FD_LOG_ERR(( "chunk %lu sz %lu from replay out of bounds, chunk0 %lu wmark %lu",
                   chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    }
    handle_replay( ctx, sig, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ) );
    break;
  }
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
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
  case IN_KIND_EPOCH:
    /* reliable link, handled in during_frag */
    break;
  case IN_KIND_GOSSIP:
    /* reliable link, handled in during_frag */
    break;
  case IN_KIND_IPECHO:
    FD_TEST( sig && sig<=USHORT_MAX );
    ctx->shred_version = (ushort)sig;
    ag_votor_set_shred_version( ctx->votor, ctx->shred_version );
    ctx->init = !!ctx->curr_epoch_info && ctx->rooted_block_id.slot!=ULONG_MAX;
    break;
  case IN_KIND_NET: {
    if( FD_UNLIKELY( sz<sizeof(fd_eth_hdr_t)+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) ) break;
    fd_ip4_hdr_t const * ip4   = (fd_ip4_hdr_t const *)fd_type_pun_const( ctx->net_buf+sizeof(fd_eth_hdr_t) );
    ulong                iplen = FD_IP4_GET_LEN( *ip4 );
    if( FD_UNLIKELY( iplen<sizeof(fd_ip4_hdr_t) || sz<sizeof(fd_eth_hdr_t)+iplen+sizeof(fd_udp_hdr_t) ) ) break;
    fd_udp_hdr_t const * udp   = (fd_udp_hdr_t const *)fd_type_pun_const( ctx->net_buf+sizeof(fd_eth_hdr_t)+iplen );
    ushort               dport = fd_ushort_bswap( udp->net_dport );
    if( FD_UNLIKELY( dport!=ctx->quic_client_listen_port && dport!=ctx->quic_server_listen_port ) ) break;
    fd_quic_t * quic = fd_ptr_if( dport==ctx->quic_client_listen_port, ctx->quic_client, ctx->quic_server );
    fd_quic_process_packet( quic, ctx->net_buf+sizeof(fd_eth_hdr_t), sz-sizeof(fd_eth_hdr_t), fd_log_wallclock() );
    break;
  }
  case IN_KIND_REPLAY:
    /* reliable link, handled in during_frag */
    break;
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
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
  memcpy( ctx->id_key.uc, ctx->identity_keypair+32UL, sizeof(fd_pubkey_t) );

  char const derive_msg[] = "bls-key-derive-alpenglow";
  uchar         ikm[ 64 ];
  fd_sha512_t   _sha[ 1 ];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL, ctx->identity_keypair+32UL, ctx->identity_keypair, sha );
  fd_sha512_leave( sha );
  ag_bls_sec_derive( ctx->bls_key, ikm, sizeof(ikm) );
  fd_memzero_explicit( ikm, sizeof(ikm) );

  fd_log_wallclock();
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {

  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( AG_EQVOC_BLOCK_HASH_MAX*tile->votor.max_live_slots ) ) + 1;
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t),       sizeof(fd_votor_tile_t)                           );
  void *            quic_client   = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_client_limits )          );
  void *            quic_server   = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_server_limits )          );
  void *            pool          = FD_SCRATCH_ALLOC_APPEND( l, ag_pool_align(),                ag_pool_footprint( tile->votor.max_live_slots )   );
  void *            votor         = FD_SCRATCH_ALLOC_APPEND( l, ag_votor_align(),               ag_votor_footprint( tile->votor.max_live_slots )  );
  void *            replayed      = FD_SCRATCH_ALLOC_APPEND( l, replayed_align(),               replayed_footprint( lg_blk_max )                  );
  void *            rooted        = FD_SCRATCH_ALLOC_APPEND( l, rooted_align(),                 rooted_footprint( tile->votor.max_live_slots )    );
  void *            publishes     = FD_SCRATCH_ALLOC_APPEND( l, publishes_align(),              publishes_footprint( tile->votor.max_live_slots ) );
  void *            peers         = FD_SCRATCH_ALLOC_APPEND( l, peers_align(),                  peers_footprint()                                 );
  void *            contact_infos = FD_SCRATCH_ALLOC_APPEND( l, contact_infos_align(),          contact_infos_footprint()                         );
  void *            mleaders      = FD_SCRATCH_ALLOC_APPEND( l, fd_multi_epoch_leaders_align(), fd_multi_epoch_leaders_footprint()                );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->shred_version = (ushort)0;

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );

  ulong seed;
  FD_TEST( fd_rng_secure( &seed, sizeof(seed) ) );

  ctx->pool = ag_pool_join( ag_pool_new( pool, tile->votor.max_live_slots, seed ) );
  FD_TEST( ctx->pool );

  ctx->votor = ag_votor_join( ag_votor_new( votor, tile->votor.max_live_slots, seed ) );
  FD_TEST( ctx->votor );
  ag_votor_set_bls_key( ctx->votor, ctx->bls_key );

  ctx->curr_epoch_info = NULL;
  ctx->curr_epoch_slot = ULONG_MAX;
  ctx->curr_epoch_rank = USHORT_MAX;
  ctx->next_epoch_info = NULL;
  ctx->next_epoch_slot = ULONG_MAX;
  ctx->next_epoch_rank = USHORT_MAX;
  fd_memset( ctx->client_peer_id_keys, 0, sizeof(ctx->client_peer_id_keys) );
  fd_memset( ctx->server_peer_id_keys, 0, sizeof(ctx->server_peer_id_keys) );

  if( FD_UNLIKELY( !tile->votor.quic_client_listen_port ) )
    FD_LOG_ERR(( "[development.votor.quic_client_listen_port] must be non-zero when alpenglow is enabled" ));
  if( FD_UNLIKELY( tile->votor.quic_client_listen_port==tile->votor.quic_server_listen_port ) )
    FD_LOG_ERR(( "[development.votor.quic_client_listen_port] %hu must differ from [development.votor.quic_server_listen_port]",
                 tile->votor.quic_client_listen_port ));

  ctx->quic_client_listen_port = tile->votor.quic_client_listen_port;
  ctx->quic_server_listen_port = tile->votor.quic_server_listen_port;
  ctx->src_ip_addr             = tile->votor.ip_addr;
  ctx->net_id                  = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->hdr, FD_NET_MTU, ctx->src_ip_addr, ctx->quic_client_listen_port );

  ctx->rooted_block_id = (ag_block_id_t){ .slot = ULONG_MAX };

  ctx->replayed = replayed_join( replayed_new( replayed, lg_blk_max, seed ) );
  FD_TEST( ctx->replayed );

  ctx->rooted = rooted_join( rooted_new( rooted, tile->votor.max_live_slots ) );
  FD_TEST( ctx->rooted );

  ctx->publishes = publishes_join( publishes_new( publishes, tile->votor.max_live_slots ) );
  FD_TEST( ctx->publishes );

  ctx->peers = peers_join( peers_new( peers ) );
  FD_TEST( ctx->peers );

  ctx->contact_infos = contact_infos_join( contact_infos_new( contact_infos ) );
  FD_TEST( ctx->contact_infos );

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders ) );
  FD_TEST( ctx->mleaders );

  ctx->init                = 0;
  ctx->next_leader_slot    = ULONG_MAX;
  ctx->has_fast_final_cert = 0;
  ctx->has_final_cert      = 0;
  fd_memset( &ctx->fast_final_cert, 0, sizeof(ag_cert_fast_final_t) );
  fd_memset( &ctx->final_cert,      0, sizeof(ag_cert_final_t)      );
  fd_memset( &ctx->notar_cert,      0, sizeof(ag_cert_notar_t)      );
  for( ulong i=0UL; i<REWARD_SLOT_MAX; i++ ) ctx->reward_slots[ i ].slot = ULONG_MAX;

  FD_TEST( tile->in_cnt<=sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_epoch" ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "net_votor"    ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
    }
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else FD_LOG_ERR(( "votor tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( link->mtu ) ) {
      ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
      ctx->in[ i ].mtu    = link->mtu;
    }
  }

  FD_TEST( tile->out_cnt>OUT_IDX_NET );
  fd_topo_link_t const * votor_out = &topo->links[ tile->out_link_id[ OUT_IDX_VOTOR ] ];
  FD_TEST( !strcmp( votor_out->name, "votor_out" ) );
  ctx->votor_out_mem    = topo->workspaces[ topo->objs[ votor_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->votor_out_chunk0 = fd_dcache_compact_chunk0( ctx->votor_out_mem, votor_out->dcache );
  ctx->votor_out_wmark  = fd_dcache_compact_wmark ( ctx->votor_out_mem, votor_out->dcache, votor_out->mtu );
  ctx->votor_out_chunk  = ctx->votor_out_chunk0;

  fd_topo_link_t const * net_out = &topo->links[ tile->out_link_id[ OUT_IDX_NET ] ];
  FD_TEST( !strcmp( net_out->name, "votor_net" ) );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_aio_tx ) );
  FD_TEST( quic_tx_aio );

  ctx->quic_client = fd_quic_join( fd_quic_new( quic_client, &quic_client_limits ) );
  FD_TEST( ctx->quic_client );
  fd_quic_set_aio_net_tx( ctx->quic_client, quic_tx_aio );

  ctx->quic_client->config.role                       = FD_QUIC_ROLE_CLIENT;
  ctx->quic_client->config.retry                      = 0;
  ctx->quic_client->config.keep_alive                 = 1;
  ctx->quic_client->config.idle_timeout               = 5L*1000L*1000L*1000L;
  ctx->quic_client->config.ack_delay                  = 2L*1000L*1000L;
  memcpy( ctx->quic_client->config.identity_public_key, ctx->id_key.uc, 32UL );
  ctx->quic_client->config.sign                       = quic_sign;
  ctx->quic_client->config.sign_ctx                   = ctx;
  ctx->quic_client->config.alpn[ 0 ]                  = 0x0c;
  memcpy( ctx->quic_client->config.alpn+1, "alpenglow-v1", 12UL );
  ctx->quic_client->config.alpn_sz                    = 13UL;
  ctx->quic_client->config.initial_rx_max_stream_data = 0UL;

  ctx->quic_client->cb.quic_ctx         = ctx;
  ctx->quic_client->cb.conn_hs_complete = quic_client_conn_hs_complete;
  ctx->quic_client->cb.conn_final       = quic_client_conn_final;

  FD_TEST( fd_quic_init( ctx->quic_client ) );

  ctx->quic_server = fd_quic_join( fd_quic_new( quic_server, &quic_server_limits ) );
  FD_TEST( ctx->quic_server );
  fd_quic_set_aio_net_tx( ctx->quic_server, quic_tx_aio );

  ctx->quic_server->config.role                       = FD_QUIC_ROLE_SERVER;
  ctx->quic_server->config.retry                      = 0;
  ctx->quic_server->config.idle_timeout               = 5L*1000L*1000L*1000L;
  ctx->quic_server->config.ack_delay                  = 2L*1000L*1000L;
  memcpy( ctx->quic_server->config.identity_public_key, ctx->id_key.uc, 32UL );
  ctx->quic_server->config.sign                       = quic_sign;
  ctx->quic_server->config.sign_ctx                   = ctx;
  ctx->quic_server->config.alpn[ 0 ]                  = 0x0c;
  memcpy( ctx->quic_server->config.alpn+1, "alpenglow-v1", 12UL );
  ctx->quic_server->config.alpn_sz                    = 13UL;
  ctx->quic_server->config.initial_rx_max_stream_data = 0UL;
  ctx->quic_server->config.max_datagram_frame_size    = 1280UL;

  ctx->quic_server->cb.quic_ctx    = ctx;
  ctx->quic_server->cb.conn_new    = quic_server_conn_new;
  ctx->quic_server->cb.datagram_rx = quic_server_datagram_rx;

  FD_TEST( fd_quic_init( ctx->quic_server ) );
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
  out_fds[ out_cnt++ ] = 2;
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  return out_cnt;
}

#define STEM_BURST (2UL)
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
