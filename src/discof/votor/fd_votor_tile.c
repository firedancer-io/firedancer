#include "fd_votor_tile.h"
#include <linux/futex.h>
#include "generated/fd_votor_tile_seccomp.h"

#include "../../choreo/votor/ag_cert_serde.h"
#include "../../choreo/votor/ag_pool.h"
#include "../../choreo/votor/ag_slot_state.h"
#include "../../choreo/votor/ag_vote_serde.h"
#include "../../choreo/votor/ag_votor.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_clock_tile.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/stakes/fd_stake_weight.h"
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
#define IN_KIND_SIGN   (5)

#define OUT_IDX_VOTOR (0UL)
#define OUT_IDX_NET   (1UL)

#define VOTE_LOOKAHEAD_MAX (40UL) /* lookahead at most 40 slots from highest ParentReady (matches Agave) */

#define QUIC_BAN_TIMEOUT_NS     (10L*1000L*1000L*1000L) /* 10 seconds */
#define QUIC_CLOSE_CODE_UNKNOWN (2U)
#define QUIC_CLOSE_CODE_EVICTED (3U)
#define QUIC_CLOSE_CODE_BANNED  (4U)
#define QUIC_CONN_MAX           (AG_VAT_MAX * 2) /* each validator is alloted 2 concurrent conns */

#define SER_MAX (AG_VOTE_SER_MAX>AG_CERT_SER_MAX ? AG_VOTE_SER_MAX : AG_CERT_SER_MAX)

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

#define PEERS_LG_SLOT_CNT (13) /* 3*AG_VAT_MAX keys, fill ratio 0.73 */
FD_STATIC_ASSERT( (1UL<<PEERS_LG_SLOT_CNT)>=4UL*AG_VAT_MAX, peers );

struct peer {
  fd_pubkey_t      id_key;
  ushort           prev_rank;
  ushort           curr_rank;
  ushort           next_rank;
  fd_quic_conn_t * tx_conn;
  fd_quic_conn_t * rx_conn;
  long             ban_ts;
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

struct sort_voter {
  uchar const * bls;
  uchar const * id;
  ulong         stake;
  fd_bls_pub_t  pub;
  ulong         idx;
  int           dup;
};
typedef struct sort_voter sort_voter_t;

#define SORT_NAME        sort_voter_bls
#define SORT_KEY_T       sort_voter_t
#define SORT_BEFORE(a,b) ( memcmp( (a).bls, (b).bls, FD_BLS_PUB_COMPRESSED_SZ )<0 )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        sort_voter_id
#define SORT_KEY_T       sort_voter_t
#define SORT_BEFORE(a,b) ( memcmp( (a).id, (b).id, sizeof(fd_pubkey_t) )<0 )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        sort_voter_stake
#define SORT_KEY_T       sort_voter_t
#define SORT_BEFORE(a,b) ( (a).stake> (b).stake ||                                  \
                         ( (a).stake==(b).stake &&                                  \
                           memcmp( (a).bls, (b).bls, FD_BLS_PUB_COMPRESSED_SZ )<0 ) )
#include "../../util/tmpl/fd_sort.c"

struct fd_votor_tile {

  /* Signing */

  fd_pubkey_t          id_key;
  fd_keyguard_client_t keyguard_client[1];

  /* Initialization */

  int init;

  /* Cluster metadata */

  ushort shred_version;
  long   ns_per_slot;

  /* Epoch metadata */

  ag_epoch_info_t *          prev_epoch_info;
  ulong                      prev_epoch_slot;
  ag_epoch_info_t *          curr_epoch_info;
  ulong                      curr_epoch_slot;
  ag_epoch_info_t *          next_epoch_info;
  ulong                      next_epoch_slot;
  fd_multi_epoch_leaders_t * mleaders;
  ulong                      next_leader_slot;
  ulong                      highest_parent_ready_slot;
  ulong                      highest_unotar_final_slot; /* highest slot for which we have a final cert that we have not paired with a notar  */

  /* Alpenglow data structures */

  ag_pool_t *  pool;
  ag_votor_t * votor;

  /* Networking */

  contact_info_t *   contact_infos;
  peer_t *           peers;
  fd_pubkey_t        client_peer_id_keys[ QUIC_CONN_MAX ];
  fd_pubkey_t        server_peer_id_keys[ QUIC_CONN_MAX ];
  fd_net_rx_bounds_t net_in_bounds[ 32 ];
  uchar              net_buf[ FD_NET_MTU ];
  fd_quic_t *        quic_client;
  fd_quic_t *        quic_server;
  fd_clock_tile_t    clock[1];
  fd_aio_t           quic_tx_aio[ 1 ];
  ushort             quic_client_listen_port;
  ushort             quic_server_listen_port;
  uint               src_ip_addr;
  fd_ip4_udp_hdrs_t  hdr[ 1 ];
  ushort             net_id;

  /* Links */

  int                 in_kind[ 32 ];
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

  ulong                                        net_tx_cnt;
  struct { ulong chunk; ulong sz; ulong sig; } net_tx[ FD_VOTOR_NET_BURST ];

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
    ag_epoch_info_t prev_epoch_info;
    ag_epoch_info_t curr_epoch_info;
    ag_epoch_info_t next_epoch_info;
    uchar           ser[ SER_MAX ];
    fd_bls_set_t    bad[ fd_bls_set_word_cnt ];
  } scratch;

  /* Metrics */

  struct {
    ulong datagram_rx[ FD_METRICS_ENUM_DATAGRAM_RX_RESULT_CNT ];
    ulong vote_rx    [ FD_METRICS_ENUM_VOTE_RX_RESULT_CNT     ];
    ulong cert_rx    [ FD_METRICS_ENUM_CERT_RX_RESULT_CNT     ];
  } metrics;
};
typedef struct fd_votor_tile fd_votor_tile_t;

static void
ban_peer( peer_t * peer,
          long     now ) {
  FD_BASE58_ENCODE_32_BYTES( peer->id_key.uc, id_key_b58 );
  FD_LOG_WARNING(( "banning peer %s", id_key_b58 ));
  if( FD_LIKELY( peer->rx_conn ) ) {
    fd_quic_conn_set_context( peer->rx_conn, NULL );
    fd_quic_conn_close( peer->rx_conn, QUIC_CLOSE_CODE_BANNED );
    peer->rx_conn = NULL;
  }
  if( FD_LIKELY( peer->tx_conn ) ) {
    fd_quic_conn_set_context( peer->tx_conn, NULL );
    fd_quic_conn_close( peer->tx_conn, QUIC_CLOSE_CODE_BANNED );
    peer->tx_conn = NULL;
  }
  peer->ban_ts = now;
}

static void
ban_bad_ranks( fd_votor_tile_t *    ctx,
               fd_bls_set_t const * bad,
               ulong                slot_as_of ) {
  ag_epoch_info_t const * epoch_info = fd_ptr_if( slot_as_of>=ctx->next_epoch_slot, ctx->next_epoch_info, fd_ptr_if( slot_as_of>=ctx->curr_epoch_slot, ctx->curr_epoch_info, ctx->prev_epoch_info ) );
  if( FD_UNLIKELY( !epoch_info ) ) return;
  long now = fd_clock_tile_now( ctx->clock );
  for( ulong rank = fd_bls_set_const_iter_init( bad );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( bad, rank ) ) {
    fd_pubkey_t id_key; memcpy( id_key.uc, epoch_info->validators[ rank ].id_key, sizeof(ag_id_key_t) );
    peer_t * peer = peers_query( ctx->peers, id_key, NULL );
    if( FD_UNLIKELY( !peer || now<peer->ban_ts+QUIC_BAN_TIMEOUT_NS ) ) continue;
    ban_peer( peer, now );
  }
}

/* For telemetry events, not to be confused with ag_event.h representing
   state transition events. */

static void
report_alpenglow_vote( fd_votor_tile_t * ctx,
                       fd_quic_conn_t *  conn,
                       ag_vote_t const * vote,
                       uchar             tag,
                       int               result,
                       uchar             quorum_reached,
                       int               reason,
                       long              aggregation_start_time,
                       long              broadcast_start_time ) {
  fd_event_alpenglow_vote_t ev;
  fd_memset( &ev, 0, FD_EVENT_ALPENGLOW_VOTE_PREFIX_SZ );
  ev.kind       = FD_EVENT_ALPENGLOW_VOTE_KIND_NOTAR+tag-AG_VOTE_SERDE_TAG_NOTAR;
  ev.voter_rank = USHORT_MAX;

  ag_epoch_info_t const * epoch_info = NULL;
  if( FD_LIKELY( vote ) ) {
    ev.slot       = ag_vote_slot( vote );
    ev.voter_rank = ag_vote_rank( vote );
    epoch_info    = fd_ptr_if( ev.slot>=ctx->next_epoch_slot, ctx->next_epoch_info, fd_ptr_if( ev.slot>=ctx->curr_epoch_slot, ctx->curr_epoch_info, ctx->prev_epoch_info ) );
    uchar const * block_hash = ag_vote_block_hash( vote );
    if( FD_LIKELY( block_hash                                            ) ) memcpy( ev.block_id,       block_hash,                                  sizeof(ag_block_hash_t) );
    if( FD_LIKELY( epoch_info && ev.voter_rank<epoch_info->validator_cnt ) ) memcpy( ev.voter_identity, epoch_info->validators[ ev.voter_rank ].id_key, sizeof(ag_id_key_t)     );
  }

  fd_pubkey_t const * id_key = conn ? fd_quic_conn_get_context( conn ) : &ctx->id_key;
  FD_STORE( ushort, ev.received_from_ip+10, (ushort)0xffff );
  FD_STORE( uint,   ev.received_from_ip+12, conn ? conn->peer[ 0 ].ip_addr : ctx->src_ip_addr );
  if( FD_LIKELY( id_key ) ) memcpy( ev.received_from_identity, id_key->uc, sizeof(fd_pubkey_t) );

  ev.our_vote                           = !conn;
  ev.reason                            = reason;
  ev.processing_result                  = result;
  ev.quorum_reached_safe_to_notar       = fd_uchar_extract_bit( quorum_reached, AG_POOL_QUORUM_REACHED_SAFE_TO_NOTAR  );
  ev.quorum_reached_safe_to_skip        = fd_uchar_extract_bit( quorum_reached, AG_POOL_QUORUM_REACHED_SAFE_TO_SKIP   );
  ev.quorum_reached_final_cert          = fd_uchar_extract_bit( quorum_reached, AG_POOL_QUORUM_REACHED_FINAL          );
  ev.quorum_reached_fast_final_cert     = fd_uchar_extract_bit( quorum_reached, AG_POOL_QUORUM_REACHED_FAST_FINAL     );
  ev.quorum_reached_notar_cert          = fd_uchar_extract_bit( quorum_reached, AG_POOL_QUORUM_REACHED_NOTAR          );
  ev.quorum_reached_notar_fallback_cert = fd_uchar_extract_bit( quorum_reached, AG_POOL_QUORUM_REACHED_NOTAR_FALLBACK );
  ev.quorum_reached_skip_cert           = fd_uchar_extract_bit( quorum_reached, AG_POOL_QUORUM_REACHED_SKIP           );
  ev.aggregation_start_time             = (ulong)fd_long_if( result==FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_ACCEPTED, aggregation_start_time, 0L );
  ev.broadcast_start_time               = (ulong)broadcast_start_time;
  ev.done_time                          = (ulong)fd_clock_tile_now( ctx->clock );

  if( FD_UNLIKELY( !conn ) ) {
    ulong cnt = epoch_info ? epoch_info->validator_cnt : 0UL;
    fd_memset( ev.broadcast_to, 0, cnt*sizeof(fd_event_alpenglow_vote_broadcast_to_t) );
    for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
      peer_t const * peer = &ctx->peers[ slot ];
      if( FD_LIKELY( peers_key_inval( peer->id_key ) || !peer->tx_conn || peer->tx_conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) continue;
      ushort rank = fd_ushort_if( ev.slot>=ctx->next_epoch_slot, peer->next_rank, fd_ushort_if( ev.slot>=ctx->curr_epoch_slot, peer->curr_rank, peer->prev_rank ) );
      if( FD_UNLIKELY( rank>=cnt ) ) continue;
      memcpy( ev.broadcast_to[ rank ].identity, peer->id_key.uc, sizeof(fd_pubkey_t) );
      FD_STORE( ushort, ev.broadcast_to[ rank ].ip+10, (ushort)0xffff );
      FD_STORE( uint,   ev.broadcast_to[ rank ].ip+12, peer->tx_conn->peer[ 0 ].ip_addr );
      ev.broadcast_to[ rank ].port = peer->tx_conn->peer[ 0 ].udp_port;
    }
    ev.broadcast_to_cnt = cnt;
  }

  fd_event_report_alpenglow_vote( &ev );
}

static void
report_alpenglow_cert( fd_votor_tile_t * ctx,
                       fd_quic_conn_t *  conn,
                       ag_cert_t const * cert,
                       uchar             tag,
                       int               result,
                       long              verify_start_time,
                       long              broadcast_start_time ) {
  fd_event_alpenglow_cert_t ev;
  fd_memset( &ev, 0, FD_EVENT_ALPENGLOW_CERT_PREFIX_SZ );
  ev.kind = FD_EVENT_ALPENGLOW_CERT_KIND_FINAL+tag-AG_CERT_SERDE_TAG_FINAL;

  if( FD_LIKELY( cert ) ) {
    ev.slot = ag_cert_slot( cert );
    uchar const * block_hash = ag_cert_block_hash( cert );
    if( FD_LIKELY( block_hash ) ) memcpy( ev.block_id, block_hash, sizeof(ag_block_hash_t) );
    fd_bls_agg_t const * agg;
    fd_bls_agg_t const * agg2 = NULL;
    switch( cert->kind ) {
    case AG_CERT_KIND_FINAL:          agg = &cert->final.agg;                                                                 break;
    case AG_CERT_KIND_FAST_FINAL:     agg = &cert->fast_final.agg;                                                            break;
    case AG_CERT_KIND_NOTAR:          agg = &cert->notar.agg;                                                                 break;
    case AG_CERT_KIND_NOTAR_FALLBACK: agg = &cert->notar_fallback.agg_notar; agg2 = &cert->notar_fallback.agg_notar_fallback; break;
    case AG_CERT_KIND_SKIP:           agg = &cert->skip.agg_skip;            agg2 = &cert->skip.agg_skip_fallback;            break;
    default:                          FD_LOG_CRIT(( "unreachable" ));
    }
    for( ulong rank = fd_bls_set_const_iter_init( agg->set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( agg->set, rank ) ) {
      ev.voters[ rank>>3 ] = (uchar)( ev.voters[ rank>>3 ] | (1U<<(rank&7UL)) );
      ev.voters_len        = (rank>>3)+1UL;
    }
    if( FD_UNLIKELY( agg2 ) ) {
      for( ulong rank = fd_bls_set_const_iter_init( agg2->set );
                       !fd_bls_set_const_iter_done( rank );
                 rank = fd_bls_set_const_iter_next( agg2->set, rank ) ) {
        ev.fallback_voters[ rank>>3 ] = (uchar)( ev.fallback_voters[ rank>>3 ] | (1U<<(rank&7UL)) );
        ev.fallback_voters_len        = (rank>>3)+1UL;
      }
    }
  }

  fd_pubkey_t const * id_key = conn ? fd_quic_conn_get_context( conn ) : &ctx->id_key;
  FD_STORE( ushort, ev.relayer_ip+10, (ushort)0xffff );
  FD_STORE( uint,   ev.relayer_ip+12, conn ? conn->peer[ 0 ].ip_addr : ctx->src_ip_addr );
  if( FD_LIKELY( id_key ) ) memcpy( ev.relayer_identity, id_key->uc, sizeof(fd_pubkey_t) );

  ev.our_cert             = !conn;
  ev.processing_result    = result;
  ev.verify_start_time    = (ulong)verify_start_time;
  ev.broadcast_start_time = (ulong)broadcast_start_time;
  ev.done_time            = (ulong)fd_clock_tile_now( ctx->clock );

  if( FD_UNLIKELY( !conn ) ) {
    ag_epoch_info_t const * epoch_info = fd_ptr_if( ev.slot>=ctx->next_epoch_slot, ctx->next_epoch_info, fd_ptr_if( ev.slot>=ctx->curr_epoch_slot, ctx->curr_epoch_info, ctx->prev_epoch_info ) );
    ulong                   cnt        = epoch_info ? epoch_info->validator_cnt : 0UL;
    fd_memset( ev.broadcast_to, 0, cnt*sizeof(fd_event_alpenglow_cert_broadcast_to_t) );
    for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
      peer_t const * peer = &ctx->peers[ slot ];
      if( FD_LIKELY( peers_key_inval( peer->id_key ) || !peer->tx_conn || peer->tx_conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) continue;
      ushort rank = fd_ushort_if( ev.slot>=ctx->next_epoch_slot, peer->next_rank, fd_ushort_if( ev.slot>=ctx->curr_epoch_slot, peer->curr_rank, peer->prev_rank ) );
      if( FD_UNLIKELY( rank>=cnt ) ) continue;
      memcpy( ev.broadcast_to[ rank ].identity, peer->id_key.uc, sizeof(fd_pubkey_t) );
      FD_STORE( ushort, ev.broadcast_to[ rank ].ip+10, (ushort)0xffff );
      FD_STORE( uint,   ev.broadcast_to[ rank ].ip+12, peer->tx_conn->peer[ 0 ].ip_addr );
      ev.broadcast_to[ rank ].port = peer->tx_conn->peer[ 0 ].udp_port;
    }
    ev.broadcast_to_cnt = cnt;
  }

  fd_event_report_alpenglow_cert( &ev );
}

static void
publish_reward_certs( fd_votor_tile_t *   ctx,
                      fd_stem_context_t * stem,
                      ulong               reward_slot ) {
  fd_votor_msg_t *    chunk  = fd_chunk_to_laddr( ctx->votor_out_mem, ctx->votor_out_chunk );
  fd_votor_reward_t * reward = &chunk->reward;

  reward->slot     = reward_slot;
  reward->block_id = (fd_hash_t){ 0 };
  fd_bls_agg_null( &reward->agg_notar );
  fd_bls_agg_null( &reward->agg_skip );

  ag_slot_state_t const * state = ag_pool_slot_state( ctx->pool, reward_slot );
  if( FD_UNLIKELY( !state ) ) { /* no notar or skip votes for this slot: send a frag with empty reward certs */
    fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_REWARD, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
    return;
  }
  ag_epoch_info_t const * epoch_info = state->epoch_info;
  ag_slot_votes_t const * votes      = &state->votes;

  uchar msg[ AG_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz;
  int   err;

  uchar const *        hash  = votes->top_notar_hash;
  fd_bls_agg_t const * notar = ag_slot_state_notar_reward_agg( state );
  if( FD_LIKELY( notar ) ) {
    reward->agg_notar = *notar;
    msg_sz = ag_vote_signing_ser( AG_VOTE_KIND_NOTAR, reward_slot, hash, ctx->shred_version, msg );
    err    = fd_bls_agg_verify_subtract( &reward->agg_notar, msg, msg_sz, epoch_info->pubkeys, votes->notar_sig, ctx->scratch.bad );
    ban_bad_ranks( ctx, ctx->scratch.bad, reward_slot );
    if( FD_UNLIKELY( err ) ) fd_bls_agg_null( &reward->agg_notar );
    else                     memcpy( reward->block_id.uc, hash, sizeof(fd_hash_t) );
  }

  fd_bls_agg_t const * skip = ag_slot_state_skip_reward_agg( state );
  if( FD_LIKELY( skip ) ) {
    reward->agg_skip = *skip;
    msg_sz = ag_vote_signing_ser( AG_VOTE_KIND_SKIP, reward_slot, NULL, ctx->shred_version, msg );
    err    = fd_bls_agg_verify_subtract( &reward->agg_skip, msg, msg_sz, epoch_info->pubkeys, votes->skip_sig, ctx->scratch.bad );
    ban_bad_ranks( ctx, ctx->scratch.bad, reward_slot );
    if( FD_UNLIKELY( err ) ) fd_bls_agg_null( &reward->agg_skip );
  }

  fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_REWARD, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
}

static void
sign_ed25519( void *      signer_ctx,
              uchar       sig[ static FD_ED25519_SIG_SZ ],
              uchar const msg[ static FD_TLS_CV_SIGN_SZ ] ) {
  fd_votor_tile_t * ctx = signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, sig, msg, FD_TLS_CV_SIGN_SZ, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

FD_STATIC_ASSERT( FD_BLS_SIG_SZ==FD_KEYGUARD_BLS_SIG_SZ, bls_sig_sz );

static void
sign_bls( void *         signer_ctx,
          fd_bls_sig_t * sig,
          uchar const *  payload,
          ulong          payload_sz ) {
  fd_votor_tile_t * ctx = signer_ctx;
  uchar sig_bytes[ FD_BLS_SIG_SZ ];
  fd_keyguard_client_sign( ctx->keyguard_client, sig_bytes, payload, payload_sz, FD_KEYGUARD_SIGN_TYPE_BLS );
  if( FD_UNLIKELY( fd_bls_sig_de( sig, sig_bytes ) ) ) FD_LOG_CRIT(( "sign tile returned an invalid BLS signature" ));
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
    if( FD_UNLIKELY( ctx->net_tx_cnt==FD_VOTOR_NET_BURST ) ) {
      if( FD_LIKELY( opt_batch_idx ) ) *opt_batch_idx = i;
      return FD_AIO_ERR_AGAIN;
    }
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;

    ulong const sz_l2 = sizeof(fd_eth_hdr_t) + batch[ i ].buf_sz;
    if( FD_UNLIKELY( sz_l2>FD_ETH_PAYLOAD_MAX ) ) continue;

    uint const ip_dst = FD_LOAD( uint, batch[ i ].buf+offsetof( fd_ip4_hdr_t, daddr_c ) );
    uchar * packet_l2 = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
    memset( packet_l2, 0, 12 );
    FD_STORE( ushort, packet_l2+offsetof( fd_eth_hdr_t, net_type ), fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    fd_memcpy( packet_l3, batch[ i ].buf, batch[ i ].buf_sz );

    ctx->net_tx[ ctx->net_tx_cnt ].chunk = ctx->net_out_chunk;
    ctx->net_tx[ ctx->net_tx_cnt ].sz    = sz_l2;
    ctx->net_tx[ ctx->net_tx_cnt ].sig   = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
    ctx->net_tx_cnt++;

    ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) *opt_batch_idx = batch_cnt;

  return FD_AIO_SUCCESS;
}

static void
quic_client_conn_final( fd_quic_conn_t * conn,
                        void *           quic_ctx ) {
  fd_votor_tile_t *   ctx    = quic_ctx;
  fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
  if( FD_UNLIKELY( !id_key ) ) return;
  peer_t * peer = peers_query( ctx->peers, *id_key, NULL );
  if( FD_LIKELY( peer ) ) peer->tx_conn = NULL;
}

static void
quic_client_conn_hs_complete( fd_quic_conn_t * conn,
                              void *           quic_ctx ) {
  (void)quic_ctx;
  fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
  if( FD_UNLIKELY( !id_key ) ) return;

  if( FD_LIKELY( !conn->tls_hs || memcmp( conn->tls_hs->hs.cli.server_pubkey, id_key->uc, sizeof(fd_pubkey_t) ) ) ) {
    fd_quic_conn_close( conn, QUIC_CLOSE_CODE_UNKNOWN );
  }
}

static void
quic_client_datagram_tx( fd_votor_tile_t *   ctx,
                         fd_stem_context_t * stem,
                         fd_quic_conn_t *    conn,
                         uchar const *       buf,
                         ulong               buf_sz ) {
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
  fd_stem_publish( stem, OUT_IDX_NET, sig, ctx->net_out_chunk, sz_l2, fd_frag_meta_ctl( 0UL, 1, 1, 0 ), 0L, 0L );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void
quic_server_conn_new( fd_quic_conn_t * conn,
                      void *           _ctx ) {
  if( FD_UNLIKELY( !conn->tls_hs ) ) return; /* no authenticated identity, so no votes will be attributed */
  fd_pubkey_t const * id_key = (fd_pubkey_t const *)fd_type_pun_const( conn->tls_hs->hs.srv.client_pubkey );

  fd_votor_tile_t * ctx  = _ctx;
  peer_t *          peer = peers_query( ctx->peers, *id_key, NULL );
  if( FD_LIKELY( ctx->curr_epoch_info ) && FD_UNLIKELY( !peer ) ) {
    fd_quic_conn_close( conn, 0U );
    return;
  }
  if( FD_UNLIKELY( peer && fd_clock_tile_now( ctx->clock )<peer->ban_ts+QUIC_BAN_TIMEOUT_NS ) ) {
    fd_quic_conn_close( conn, QUIC_CLOSE_CODE_BANNED );
    return;
  }
  ctx->server_peer_id_keys[ conn->conn_idx ] = *id_key;
  fd_quic_conn_set_context( conn, &ctx->server_peer_id_keys[ conn->conn_idx ] );
  if( FD_LIKELY( peer ) ) {
    if( FD_UNLIKELY( peer->rx_conn ) ) {
      fd_quic_conn_set_context( peer->rx_conn, NULL );
      fd_quic_conn_close( peer->rx_conn, 0U );
    }
    peer->rx_conn = conn;
  }
}

static void
quic_server_conn_final( fd_quic_conn_t * conn,
                        void *           _ctx ) {
  fd_votor_tile_t *   ctx    = _ctx;
  fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
  if( FD_UNLIKELY( !id_key ) ) return;
  peer_t * peer = peers_query( ctx->peers, *id_key, NULL );
  if( FD_LIKELY( peer && peer->rx_conn==conn ) ) peer->rx_conn = NULL;
}

static void
quic_server_datagram_rx( fd_quic_conn_t * conn,
                         uchar const *    data,
                         ulong            data_sz,
                         void *           _ctx ) {

  fd_votor_tile_t * ctx = _ctx;
  if( FD_UNLIKELY( !ctx->init  ) ) { ctx->metrics.datagram_rx[ FD_METRICS_ENUM_DATAGRAM_RX_RESULT_V_NOT_READY_IDX ]++; return; }
  if( FD_UNLIKELY( data_sz<2UL ) ) { ctx->metrics.datagram_rx[ FD_METRICS_ENUM_DATAGRAM_RX_RESULT_V_TOO_SMALL_IDX ]++; return; }
  uchar kind = data[ 1 ];

  switch( kind ) {
  case AG_VOTE_SERDE_TAG_NOTAR:
  case AG_VOTE_SERDE_TAG_FINAL:
  case AG_VOTE_SERDE_TAG_SKIP:
  case AG_VOTE_SERDE_TAG_NOTAR_FALLBACK:
  case AG_VOTE_SERDE_TAG_SKIP_FALLBACK: {
    ctx->metrics.datagram_rx[ FD_METRICS_ENUM_DATAGRAM_RX_RESULT_V_VOTE_IDX ]++;
    fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
    if( FD_UNLIKELY( !id_key ) ) { ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_UNKNOWN_SIGNER_IDX ]++; report_alpenglow_vote( ctx, conn, NULL, kind, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_UNKNOWN_PEER, 0, FD_EVENT_ALPENGLOW_VOTE_REASON_NOT_OUR_VOTE, 0L, 0L ); return; }
    peer_t * peer = peers_query( ctx->peers, *id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) { ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_NOT_A_PEER_IDX ]++; report_alpenglow_vote( ctx, conn, NULL, kind, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_UNKNOWN_PEER, 0, FD_EVENT_ALPENGLOW_VOTE_REASON_NOT_OUR_VOTE, 0L, 0L ); return; }
    if( FD_UNLIKELY( fd_clock_tile_now( ctx->clock )<peer->ban_ts+QUIC_BAN_TIMEOUT_NS ) ) {
      ctx->metrics.vote_rx[FD_METRICS_ENUM_VOTE_RX_RESULT_V_BANNED_IDX]++;
      report_alpenglow_vote( ctx, conn, NULL, kind, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_BANNED_PEER, 0, FD_EVENT_ALPENGLOW_VOTE_REASON_NOT_OUR_VOTE, 0L, 0L );
      fd_quic_conn_close( conn, QUIC_CLOSE_CODE_BANNED );
      return;
    }

    int err = ag_vote_de( &ctx->scratch.vote, data, data_sz );
    if( FD_UNLIKELY( err ) ) {
      ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_SIZE_IDX     ] += (ulong)(err==AG_VOTE_DE_ERR_SZ   );
      ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_ENCODING_IDX ] += (ulong)(err==AG_VOTE_DE_ERR_INVAL);
      return;
    }
    ag_vote_t * vote      = &ctx->scratch.vote;
    ulong       vote_slot = ag_vote_slot( vote );
    ushort      rank      = fd_ushort_if( vote_slot>=ctx->next_epoch_slot, peer->next_rank, fd_ushort_if( vote_slot>=ctx->curr_epoch_slot, peer->curr_rank, peer->prev_rank ) );
    switch( vote->kind ) {
    case AG_VOTE_KIND_NOTAR:          vote->notar.rank          = rank; break;
    case AG_VOTE_KIND_FINAL:          vote->final.rank          = rank; break;
    case AG_VOTE_KIND_SKIP:           vote->skip.rank           = rank; break;
    case AG_VOTE_KIND_NOTAR_FALLBACK: vote->notar_fallback.rank = rank; break;
    case AG_VOTE_KIND_SKIP_FALLBACK:  vote->skip_fallback.rank  = rank; break;
    default:                          FD_LOG_CRIT(( "unreachable" ));
    }
    if( FD_UNLIKELY( ag_vote_shred_version( vote )!=ctx->shred_version ) ) { ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_SHRED_VERSION_IDX ]++; report_alpenglow_vote( ctx, conn, vote, kind, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SHRED_VERSION_MISMATCH, 0, FD_EVENT_ALPENGLOW_VOTE_REASON_NOT_OUR_VOTE, 0L, 0L ); return; }

    if( FD_UNLIKELY( blst_p2_is_inf( ag_vote_sig( vote ) ) ) ) { ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_SIG_IDX ]++; ban_peer( peer, fd_clock_tile_now( ctx->clock ) ); return; } /* identity is never a valid vote signature */
    uchar const * block_hash = ag_vote_block_hash( vote );
    if( FD_UNLIKELY( block_hash && !memcmp( block_hash, ag_block_hash_null, sizeof(ag_block_hash_t) ) ) ) { ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_BLOCK_HASH_IDX ]++; return; } /* null is never a valid block hash */

    if( FD_UNLIKELY( rank==USHORT_MAX ) ) { ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_RANK_IDX ]++; report_alpenglow_vote( ctx, conn, vote, kind, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_UNRANKED_PEER, 0, FD_EVENT_ALPENGLOW_VOTE_REASON_NOT_OUR_VOTE, 0L, 0L ); return; } /* peer is not ranked in their vote slot's epoch */
    if( FD_UNLIKELY( vote_slot>fd_ulong_max( ag_pool_finalized_slot( ctx->pool ), ctx->highest_parent_ready_slot )+VOTE_LOOKAHEAD_MAX ) ) { ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_SLOT_IDX ]++; report_alpenglow_vote( ctx, conn, vote, kind, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SLOT_TOO_NEW, 0, FD_EVENT_ALPENGLOW_VOTE_REASON_NOT_OUR_VOTE, 0L, 0L ); return; }

    long  aggregation_start_time = fd_clock_tile_now( ctx->clock );
    uchar quorum_reached;
    err = ag_pool_add_vote( ctx->pool, &ctx->scratch.vote, ctx->scratch.bad, &quorum_reached );
    int result;
    switch( err ) {
    case AG_POOL_SUCCESS:                ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_SUCCESS_IDX   ]++; result = FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_ACCEPTED;                                                                                                                         break;
    case AG_POOL_ERR_SLOT_OUT_OF_BOUNDS: ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_BAD_SLOT_IDX  ]++; result = fd_int_if( vote_slot<ag_pool_finalized_slot( ctx->pool ), FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SLOT_TOO_OLD, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SLOT_TOO_NEW ); break;
    case AG_POOL_ERR_DUPLICATE:          ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_DUPLICATE_IDX ]++; result = FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_DUPLICATE;                                                                                                                        break;
    case AG_POOL_ERR_SLASHABLE:          ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_SLASHABLE_IDX ]++; result = FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SLASHABLE;                                                                                                                        break;
    default:
      FD_LOG_CRIT(( "unhandled kind" ));
    }
    report_alpenglow_vote( ctx, conn, vote, kind, result, quorum_reached, FD_EVENT_ALPENGLOW_VOTE_REASON_NOT_OUR_VOTE, aggregation_start_time, 0L );
    if( FD_UNLIKELY( !fd_bls_set_is_null( ctx->scratch.bad ) ) ) ban_bad_ranks( ctx, ctx->scratch.bad, vote_slot );
    return;
  }
  case AG_CERT_SERDE_TAG_FINAL:
  case AG_CERT_SERDE_TAG_FAST_FINAL:
  case AG_CERT_SERDE_TAG_NOTAR:
  case AG_CERT_SERDE_TAG_NOTAR_FALLBACK:
  case AG_CERT_SERDE_TAG_SKIP: {
    ctx->metrics.datagram_rx[ FD_METRICS_ENUM_DATAGRAM_RX_RESULT_V_CERT_IDX ]++;
    fd_pubkey_t const * id_key = fd_quic_conn_get_context( conn );
    if( FD_UNLIKELY( !id_key ) ) { ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_UNKNOWN_SIGNER_IDX ]++; report_alpenglow_cert( ctx, conn, NULL, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_UNKNOWN_PEER, 0L, 0L ); return; }
    peer_t * peer = peers_query( ctx->peers, *id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) { ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_NOT_A_PEER_IDX ]++; report_alpenglow_cert( ctx, conn, NULL, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_UNKNOWN_PEER, 0L, 0L ); return; }
    if( FD_UNLIKELY( fd_clock_tile_now( ctx->clock )<peer->ban_ts+QUIC_BAN_TIMEOUT_NS ) ) { ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_BANNED_IDX ]++; report_alpenglow_cert( ctx, conn, NULL, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_BANNED_PEER, 0L, 0L ); fd_quic_conn_close( conn, QUIC_CLOSE_CODE_BANNED ); return; }

    int err = ag_cert_de( &ctx->scratch.cert, data, data_sz );
    if( FD_UNLIKELY( err ) ) {
      ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_BAD_SIZE_IDX     ] += (ulong)(err==AG_CERT_DE_ERR_SZ   );
      ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_BAD_ENCODING_IDX ] += (ulong)(err==AG_CERT_DE_ERR_INVAL);
      return;
    }
    if( FD_UNLIKELY( ag_cert_shred_version( &ctx->scratch.cert )!=ctx->shred_version ) ) { ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_SHRED_VERSION_IDX ]++; report_alpenglow_cert( ctx, conn, &ctx->scratch.cert, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_SHRED_VERSION_MISMATCH, 0L, 0L ); return; }

    ulong  cert_slot = ag_cert_slot( &ctx->scratch.cert );
    ushort rank      = fd_ushort_if( cert_slot>=ctx->next_epoch_slot, peer->next_rank, fd_ushort_if( cert_slot>=ctx->curr_epoch_slot, peer->curr_rank, peer->prev_rank ) );
    if( FD_UNLIKELY( rank==USHORT_MAX ) ) { ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_NOT_RANKED_IDX ]++; report_alpenglow_cert( ctx, conn, &ctx->scratch.cert, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_UNRANKED_PEER, 0L, 0L ); return; } /* peer is not ranked in this cert slot's epoch */

    long verify_start_time = fd_clock_tile_now( ctx->clock );
    switch( ag_pool_add_cert( ctx->pool, &ctx->scratch.cert, ctx->scratch.bad ) ) {
    case AG_POOL_SUCCESS:
      ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_SUCCESS_IDX ]++;
      report_alpenglow_cert( ctx, conn, &ctx->scratch.cert, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_ACCEPTED, verify_start_time, 0L );
      break;
    case AG_POOL_ERR_SLOT_OUT_OF_BOUNDS: ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_SLOT_OUT_OF_BOUNDS_IDX ]++; break;
    case AG_POOL_ERR_DUPLICATE:
      ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_DUPLICATE_IDX ]++;
      if( FD_LIKELY( ctx->scratch.cert.kind==AG_CERT_KIND_NOTAR ) ) report_alpenglow_cert( ctx, conn, &ctx->scratch.cert, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_DUPLICATE, 0L, 0L );
      break;
    case AG_POOL_ERR_CERT_VERIFY:
      ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_FAILED_VERIFY_IDX ]++;
      report_alpenglow_cert( ctx, conn, &ctx->scratch.cert, kind, FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_FAILED_BLS_VERIFY, verify_start_time, 0L );
      ban_peer( peer, fd_clock_tile_now( ctx->clock ) );
      break;
    default:
      FD_LOG_CRIT(( "unhandled kind" ));
    }
    if( FD_UNLIKELY( !fd_bls_set_is_null( ctx->scratch.bad ) ) ) ban_bad_ranks( ctx, ctx->scratch.bad, cert_slot );
    return;
  }
  default:
    ctx->metrics.datagram_rx[FD_METRICS_ENUM_DATAGRAM_RX_RESULT_V_UNKNOWN_TAG_IDX]++;
    break;
  }
}

static ag_epoch_info_t *
rank_voters( ag_epoch_info_t *              epoch_info,
             fd_vote_stake_weight_t const * stakes,
             ulong                          stake_cnt ) {

  FD_TEST( stake_cnt<=AG_VAT_MAX );

  sort_voter_t keys[AG_VAT_MAX];
  ulong        key_cnt = 0UL;
  for( ulong i=0UL; i<stake_cnt; i++ ) {
    if( FD_UNLIKELY( !stakes[i].stake ) ) continue;
    if( FD_UNLIKELY( fd_bls_pub_de( &keys[key_cnt].pub, stakes[i].bls_key, FD_BLS_PUB_COMPRESSED_SZ ) ) ) continue;
    keys[key_cnt].bls   = stakes[i].bls_key;
    keys[key_cnt].id    = stakes[i].id_key.uc;
    keys[key_cnt].stake = stakes[i].stake;
    keys[key_cnt].idx   = i;
    keys[key_cnt].dup   = 0;
    key_cnt++;
  }

  sort_voter_bls_inplace( keys, key_cnt );
  for( ulong i=1UL; i<key_cnt; i++ ) if( FD_UNLIKELY( !memcmp( keys[i-1UL].bls, keys[i].bls, FD_BLS_PUB_COMPRESSED_SZ ) ) ) keys[i-1UL].dup = keys[i].dup = 1;
  sort_voter_id_inplace( keys, key_cnt );
  for( ulong i=1UL; i<key_cnt; i++ ) if( FD_UNLIKELY( !memcmp( keys[i-1UL].id,  keys[i].id,  sizeof(fd_pubkey_t)      ) ) ) keys[i-1UL].dup = keys[i].dup = 1;
  epoch_info->validator_cnt = 0;
  for( ulong i=0UL; i<key_cnt; i++ ) if( FD_LIKELY( !keys[i].dup ) ) keys[epoch_info->validator_cnt++] = keys[i];
  sort_voter_stake_inplace( keys, epoch_info->validator_cnt );

  epoch_info->total_stake = 0UL;
  for( ulong i=0UL; i<epoch_info->validator_cnt; i++ ) {
    ulong                 idx            = keys[i].idx;
    ag_validator_info_t * validator_info = epoch_info->validators + i;
    memset( validator_info, 0, sizeof(ag_validator_info_t) );
    validator_info->id    = i;
    validator_info->stake = stakes[idx].stake;
    memcpy( validator_info->id_key,   stakes[idx].id_key.uc,   sizeof(ag_id_key_t)   );
    memcpy( validator_info->vote_key, stakes[idx].vote_key.uc, sizeof(ag_vote_key_t) );
    validator_info->bls_key  = keys[i].pub;
    epoch_info->pubkeys[i]   = keys[i].pub;
    epoch_info->total_stake += validator_info->stake;
  }
  return epoch_info;
}

static void
handle_epoch( fd_votor_tile_t *           ctx,
              fd_epoch_info_msg_t const * msg ) {

  ag_epoch_info_t * epoch_info;
  if     ( FD_UNLIKELY( !ctx->curr_epoch_info ) ) epoch_info = &ctx->scratch.curr_epoch_info;
  else if( FD_UNLIKELY( !ctx->next_epoch_info ) ) epoch_info = &ctx->scratch.next_epoch_info;
  else if( FD_UNLIKELY( !ctx->prev_epoch_info ) ) epoch_info = &ctx->scratch.prev_epoch_info;
  else                                            epoch_info = ctx->prev_epoch_info;
  rank_voters( epoch_info, fd_epoch_info_msg_stake_weights( msg ), msg->staked_vote_cnt );

  /* swap pointers */

  if( FD_UNLIKELY( !ctx->curr_epoch_info ) ) {
    ctx->curr_epoch_info = epoch_info;
    ctx->curr_epoch_slot = msg->start_slot;
  } else {
    if( FD_LIKELY( ctx->next_epoch_info ) ) {
      ctx->prev_epoch_info = ctx->curr_epoch_info;
      ctx->prev_epoch_slot = ctx->curr_epoch_slot;
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
    peer->prev_rank = USHORT_MAX;
    peer->curr_rank = USHORT_MAX;
    peer->next_rank = USHORT_MAX;
  }

  /* unmark all ranked in prev epoch */

  ulong prev_cnt = ctx->prev_epoch_info ? ctx->prev_epoch_info->validator_cnt : 0UL;
  for( ulong rank=0UL; rank<prev_cnt; rank++ ) {
    fd_pubkey_t id_key;
    memcpy( id_key.uc, ctx->prev_epoch_info->validators[ rank ].id_key, sizeof(ag_id_key_t) );

    peer_t * peer = peers_query( ctx->peers, id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) {
      peer              = peers_insert( ctx->peers, id_key );
      peer->curr_rank   = USHORT_MAX;
      peer->next_rank   = USHORT_MAX;
      peer->tx_conn     = NULL;
      peer->rx_conn     = NULL;
      peer->ban_ts      = 0L;
    }
    peer->prev_rank = (ushort)rank;
  }

  /* unmark all ranked in curr epoch */

  ushort own_rank = USHORT_MAX; /* our own rank in the new epoch */
  for( ulong rank=0UL; rank<ctx->curr_epoch_info->validator_cnt; rank++ ) {
    fd_pubkey_t id_key;
    memcpy( id_key.uc, ctx->curr_epoch_info->validators[ rank ].id_key, sizeof(ag_id_key_t) );
    if( FD_UNLIKELY( ctx->curr_epoch_info==epoch_info && fd_pubkey_eq( &id_key, &ctx->id_key ) ) ) own_rank = (ushort)rank;

    peer_t * peer = peers_query( ctx->peers, id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) {
      peer              = peers_insert( ctx->peers, id_key );
      peer->prev_rank   = USHORT_MAX;
      peer->next_rank   = USHORT_MAX;
      peer->tx_conn     = NULL;
      peer->rx_conn     = NULL;
      peer->ban_ts      = 0L;
    }
    peer->curr_rank = (ushort)rank;
  }

  /* unmark all ranked in next epoch */

  ulong next_cnt = ctx->next_epoch_info ? ctx->next_epoch_info->validator_cnt : 0UL;
  for( ulong rank=0UL; rank<next_cnt; rank++ ) {
    fd_pubkey_t id_key;
    memcpy( id_key.uc, ctx->next_epoch_info->validators[ rank ].id_key, sizeof(ag_id_key_t) );
    if( FD_UNLIKELY( ctx->next_epoch_info==epoch_info && fd_pubkey_eq( &id_key, &ctx->id_key ) ) ) own_rank = (ushort)rank;

    peer_t * peer = peers_query( ctx->peers, id_key, NULL );
    if( FD_UNLIKELY( !peer ) ) {
      peer            = peers_insert( ctx->peers, id_key );
      peer->prev_rank = USHORT_MAX;
      peer->curr_rank = USHORT_MAX;
      peer->tx_conn   = NULL;
      peer->rx_conn   = NULL;
      peer->ban_ts    = 0L;
    }
    peer->next_rank = (ushort)rank;
  }

  /* quic_connect new peers */

  long now = fd_clock_tile_now( ctx->clock );
  for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
    peer_t * peer = &ctx->peers[ slot ];
    if( FD_LIKELY( peers_key_inval( peer->id_key ) ) ) continue;
    if( FD_LIKELY( peers_query( ctx->peers, peer->id_key, NULL ) ) ) {
      contact_info_t * ci = contact_infos_query( ctx->contact_infos, peer->id_key, NULL );
      if( FD_LIKELY( ci && !peer->tx_conn && now>=peer->ban_ts+QUIC_BAN_TIMEOUT_NS ) ) {
        fd_quic_conn_t * conn = fd_quic_connect( ctx->quic_client, ci->ip4, ci->port, ctx->src_ip_addr, ctx->quic_client_listen_port, now );
        if( FD_LIKELY( conn ) ) {
          ctx->client_peer_id_keys[ conn->conn_idx ] = peer->id_key;
          fd_quic_conn_set_context( conn, &ctx->client_peer_id_keys[ conn->conn_idx ] );
          peer->tx_conn = conn;
        }
      }
    }
  }

  /* quic_conn_close evicted peers */

  for( ulong slot=0UL; slot<peers_slot_cnt(); ) {
    peer_t * peer = &ctx->peers[ slot ];
    if( FD_LIKELY( peers_key_inval( peer->id_key ) ) )                            { slot++; continue; }
    if( FD_LIKELY( peer->prev_rank!=USHORT_MAX || peer->curr_rank!=USHORT_MAX || peer->next_rank!=USHORT_MAX ) ) { slot++; continue; }
    if( FD_LIKELY( peer->tx_conn ) ) {
      fd_quic_conn_set_context( peer->tx_conn, NULL );
      fd_quic_conn_close( peer->tx_conn, QUIC_CLOSE_CODE_EVICTED );
      peer->tx_conn = NULL;
    }
    if( FD_LIKELY( peer->rx_conn ) ) {
      fd_quic_conn_set_context( peer->rx_conn, NULL );
      fd_quic_conn_close( peer->rx_conn, QUIC_CLOSE_CODE_EVICTED );
      peer->rx_conn = NULL;
    }
    peers_remove( ctx->peers, peer ); /* relocates, so reconsider the freed slot */
  }

  /* update slot time.  It's ok if ns_per_slot is a little off around
     epoch boundaries (for example, a slot in the previous or next epoch
     becomes ParentReady and we need to set skip timers).

     We still vote skip regardless, just a little early or late, which
     is ok especially given network jitter. */

  ctx->ns_per_slot = (long)msg->ns_per_slot;

  /* update structures */

  ag_pool_advance_epoch ( ctx->pool,  epoch_info, own_rank, msg->start_slot );
  ag_votor_advance_epoch( ctx->votor, ctx->ns_per_slot, own_rank, msg->start_slot );

  /* update our leader schedule */

  fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, msg );
  fd_multi_epoch_leaders_epoch_msg_fini( ctx->mleaders );
  if( FD_UNLIKELY( ctx->next_leader_slot==ULONG_MAX ) ) ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, msg->start_slot, &ctx->id_key );

  ctx->init = ag_pool_finalized_slot( ctx->pool )!=ULONG_MAX && !!ctx->shred_version;
}

static void
handle_gossip( fd_votor_tile_t *                  ctx,
               ulong                              sig,
               fd_gossip_update_message_t const * msg ) {

  fd_pubkey_t id_key;
  memcpy( id_key.uc, msg->origin, sizeof(fd_pubkey_t) );
  if( FD_UNLIKELY( peers_key_inval( id_key ) ) ) return;

  contact_info_t new_ci = {0}; /* dummy 0:0 address for removal */
  switch( sig ) {
  case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
    fd_gossip_socket_t const * socket = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ];
    new_ci.ip4  = fd_uint_if  ( !socket->is_ipv6, socket->ip4,                     0U        );
    new_ci.port = fd_ushort_if( !socket->is_ipv6, fd_ushort_bswap( socket->port ), (ushort)0 );
    break;
  }
  case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE:
    break;
  default:
    FD_LOG_ERR(( "unexpected gossip sig %lu", sig ));
  }

  contact_info_t * ci   = contact_infos_query( ctx->contact_infos, id_key, NULL );
  peer_t *         peer = peers_query        ( ctx->peers,         id_key, NULL );

  if( FD_UNLIKELY( !new_ci.port ) ) { /* nowhere left to reach it */
    if( FD_LIKELY( ci ) ) contact_infos_remove( ctx->contact_infos, ci );
    if( FD_UNLIKELY( peer && peer->tx_conn ) ) {
      fd_quic_conn_set_context( peer->tx_conn, NULL );
      fd_quic_conn_close( peer->tx_conn, 0U );
      peer->tx_conn = NULL;
    }
    return;
  }

  if( FD_UNLIKELY( !ci ) ) {
    ci       = contact_infos_insert( ctx->contact_infos, id_key );
    ci->ip4  = new_ci.ip4;
    ci->port = new_ci.port;
  } else if( FD_UNLIKELY( ci->ip4 !=new_ci.ip4 || ci->port!=new_ci.port ) ) {
    ci->ip4  = new_ci.ip4;
    ci->port = new_ci.port;
    if( FD_UNLIKELY( peer && peer->tx_conn ) ) { /* our conn is to the old address */
      fd_quic_conn_set_context( peer->tx_conn, NULL );
      fd_quic_conn_close( peer->tx_conn, 0U );
      peer->tx_conn = NULL;
    }
  }

  long now = fd_clock_tile_now( ctx->clock );
  if( FD_LIKELY( peer && !peer->tx_conn && now>=peer->ban_ts+QUIC_BAN_TIMEOUT_NS ) ) {
    fd_quic_conn_t * conn = fd_quic_connect( ctx->quic_client, ci->ip4, ci->port, ctx->src_ip_addr, ctx->quic_client_listen_port, now );
    if( FD_LIKELY( conn ) ) {
      ctx->client_peer_id_keys[ conn->conn_idx ] = peer->id_key;
      fd_quic_conn_set_context( conn, &ctx->client_peer_id_keys[ conn->conn_idx ] );
      peer->tx_conn = conn;
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
    if( FD_UNLIKELY( ag_pool_finalized_slot( ctx->pool )==ULONG_MAX ) ) {
      ag_pool_init( ctx->pool, block_id.slot );
      if( FD_LIKELY( ctx->shred_version ) ) ag_votor_init( ctx->votor, block_id.slot, fd_clock_tile_now( ctx->clock ), ctx->ns_per_slot, ctx->shred_version, sign_bls, ctx );
      ctx->init = !!ctx->curr_epoch_info && !!ctx->shred_version;
    } else if( FD_UNLIKELY( block_id.slot!=0 ) ) {
      ag_pool_add_block( ctx->pool, &block_id, &parent_block_id, ctx->scratch.bad );
      if( FD_UNLIKELY( !fd_bls_set_is_null( ctx->scratch.bad ) ) ) ban_bad_ranks( ctx, ctx->scratch.bad, block_id.slot );
    }
    ag_event_replay_t completed = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = block_id.slot, .block_info = { .parent = parent_block_id } };
    memcpy( completed.block_info.hash, block_id.hash, sizeof(ag_block_hash_t) );
    ag_votor_handle_replay_event( ctx->votor, &completed );
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
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_votor_tile_t),       sizeof(fd_votor_tile_t)                           );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_client_limits )          );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_server_limits )          );
  l = FD_LAYOUT_APPEND( l, ag_pool_align(),                ag_pool_footprint( tile->votor.max_live_slots )   );
  l = FD_LAYOUT_APPEND( l, ag_votor_align(),               ag_votor_footprint( tile->votor.max_live_slots )  );
  l = FD_LAYOUT_APPEND( l, peers_align(),                  peers_footprint()                                 );
  l = FD_LAYOUT_APPEND( l, contact_infos_align(),          contact_infos_footprint()                         );
  l = FD_LAYOUT_APPEND( l, fd_multi_epoch_leaders_align(), fd_multi_epoch_leaders_footprint()                );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
during_housekeeping( fd_votor_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) fd_clock_tile_recal( ctx->clock );
}

static inline long
next_deadline( fd_votor_tile_t * ctx ) {
  long next = fd_long_min( fd_quic_get_next_wakeup( ctx->quic_client ), fd_quic_get_next_wakeup( ctx->quic_server ) );
  return next==LONG_MAX ? LONG_MAX : fd_clock_tile_wallclock_to_tickcount( ctx->clock, next );
}

static inline void
after_credit( fd_votor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {

  long now     = fd_clock_tile_now( ctx->clock );
  *charge_busy = fd_quic_service( ctx->quic_client, now ) | fd_quic_service( ctx->quic_server, now );
  for( ulong i=0UL; i<ctx->net_tx_cnt; i++ ) fd_stem_publish( stem, OUT_IDX_NET, ctx->net_tx[ i ].sig, ctx->net_tx[ i ].chunk, ctx->net_tx[ i ].sz, fd_frag_meta_ctl( 0UL, 1, 1, 0 ), 0L, 0L );
  ctx->net_tx_cnt = 0UL;

  if( FD_UNLIKELY( !ctx->init ) ) return;

  if( FD_UNLIKELY( ag_pool_poll_pool_event( ctx->pool, &ctx->scratch.pool_event ) ) ) {
    ag_votor_handle_pool_event( ctx->votor, &ctx->scratch.pool_event, now );
    if( FD_UNLIKELY( ctx->scratch.pool_event.kind==AG_EVENT_POOL_PARENT_READY ) ) ctx->highest_parent_ready_slot = fd_ulong_max( ctx->highest_parent_ready_slot, ctx->scratch.pool_event.parent_ready.slot );

    /* Notify other tiles that we have a cert indicating this slot has
       reached a new state.

       TODO also publish contiguous implicitly finalized and ensure no
       missed final certs? */

    ag_cert_t const * cert = &ctx->scratch.pool_event.cert_created;
    if( FD_UNLIKELY( ctx->scratch.pool_event.kind==AG_EVENT_POOL_CERT_CREATED ) ) {
      ulong                   slot  = ag_cert_slot( cert );
      ag_slot_state_t const * state = ag_pool_slot_state( ctx->pool, slot );
      fd_votor_msg_t *        chunk = fd_chunk_to_laddr( ctx->votor_out_mem, ctx->votor_out_chunk );
      fd_votor_certed_t *     certed = &chunk->certed;
      switch( cert->kind ) {
      case AG_CERT_KIND_FINAL:
        if( FD_LIKELY( state && state->certs.notar.slot != ULONG_MAX ) ) {
          *certed = (fd_votor_certed_t){ .kind = cert->kind, .slot = slot, .block_id = FD_LOAD( fd_hash_t, state->certs.notar.block_hash ), .agg = state->certs.finalize.agg, .agg2 = state->certs.notar.agg };
          fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_CERTED, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
          ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
        } else {
          ctx->highest_unotar_final_slot = slot;
        }
        break;
      case AG_CERT_KIND_FAST_FINAL:
        *certed = (fd_votor_certed_t){ .kind = cert->kind, .slot = slot, .block_id = FD_LOAD( fd_hash_t, cert->fast_final.block_hash ), .agg = cert->fast_final.agg };
        fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_CERTED, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
        ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
        break;
      case AG_CERT_KIND_NOTAR:
        *certed = (fd_votor_certed_t){ .kind = cert->kind, .slot = slot, .block_id = FD_LOAD( fd_hash_t, cert->notar.block_hash ), .agg = cert->notar.agg };
        fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_CERTED, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
        ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );


        if( FD_UNLIKELY( ctx->highest_unotar_final_slot==slot && state && state->certs.finalize.slot != ULONG_MAX ) ) {
          chunk   = fd_chunk_to_laddr( ctx->votor_out_mem, ctx->votor_out_chunk );
          certed  = &chunk->certed;
          *certed = (fd_votor_certed_t){ .kind = AG_CERT_KIND_FINAL, .slot = slot, .block_id = FD_LOAD( fd_hash_t, cert->notar.block_hash ), .agg = state->certs.finalize.agg, .agg2 = cert->notar.agg };
          fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_CERTED, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
          ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
        }
        break;
      case AG_CERT_KIND_NOTAR_FALLBACK:
        *certed = (fd_votor_certed_t){ .kind = cert->kind, .slot = slot, .block_id = FD_LOAD( fd_hash_t, cert->notar_fallback.block_hash ), .agg = cert->notar_fallback.agg_notar, .agg2 = cert->notar_fallback.agg_notar_fallback };
        fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_CERTED, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
        ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
        break;
      case AG_CERT_KIND_SKIP:
        *certed = (fd_votor_certed_t){ .kind = cert->kind, .slot = slot, .agg = cert->skip.agg_skip, .agg2 = cert->skip.agg_skip_fallback };
        fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_CERTED, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
        ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
        break;
      default:
        FD_LOG_CRIT(( "unreachable" ));
      }
    }
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_pool_poll_repair_event( ctx->pool, &ctx->scratch.repair_event ) ) ) {
    fd_votor_msg_t * chunk = fd_chunk_to_laddr( ctx->votor_out_mem, ctx->votor_out_chunk );
    chunk->repair = (fd_votor_repair_t){ .slot = ctx->scratch.repair_event.block.slot, .block_id = FD_LOAD( fd_hash_t, ctx->scratch.repair_event.block.hash ) };
    fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_REPAIR, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_votor_poll_timeout_event( ctx->votor, now, &ctx->scratch.timeout_event ) ) ) { /* a timeout we set on ParentReady */
    ag_votor_handle_timeout_event( ctx->votor, &ctx->scratch.timeout_event );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ag_votor_poll_vote_event( ctx->votor, &ctx->scratch.vote_event ) ) ) { /* our own vote */
    ulong                   vote_slot  = ag_vote_slot( &ctx->scratch.vote_event.vote );
    ag_epoch_info_t const * epoch_info = fd_ptr_if( vote_slot>=ctx->next_epoch_slot, ctx->next_epoch_info, fd_ptr_if( vote_slot>=ctx->curr_epoch_slot, ctx->curr_epoch_info, ctx->prev_epoch_info ) );
    ulong                   rank       = ag_vote_rank( &ctx->scratch.vote_event.vote );
    if( FD_LIKELY( epoch_info && rank<epoch_info->validator_cnt ) ) {
      long  aggregation_start_time = fd_clock_tile_now( ctx->clock );
      uchar quorum_reached;
      int   err = ag_pool_add_vote( ctx->pool, &ctx->scratch.vote_event.vote, ctx->scratch.bad, &quorum_reached );
      if( FD_UNLIKELY( !fd_bls_set_is_null( ctx->scratch.bad ) ) ) ban_bad_ranks( ctx, ctx->scratch.bad, vote_slot );

      ulong ser_sz               = ag_vote_ser( &ctx->scratch.vote_event.vote, ctx->scratch.ser );
      long  broadcast_start_time = fd_clock_tile_now( ctx->clock );
      for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
        peer_t const * peer = &ctx->peers[ slot ];
        if( FD_LIKELY( peers_key_inval( peer->id_key ) || !peer->tx_conn || peer->tx_conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) continue;
        quic_client_datagram_tx( ctx, stem, peer->tx_conn, ctx->scratch.ser, ser_sz );
      }

      int result;
      switch( err ) {
      case AG_POOL_SUCCESS:                result = FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_ACCEPTED;                                                                                                                         break;
      case AG_POOL_ERR_SLOT_OUT_OF_BOUNDS: result = fd_int_if( vote_slot<ag_pool_finalized_slot( ctx->pool ), FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SLOT_TOO_OLD, FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SLOT_TOO_NEW ); break;
      case AG_POOL_ERR_DUPLICATE:          result = FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_DUPLICATE;                                                                                                                        break;
      case AG_POOL_ERR_SLASHABLE:          result = FD_EVENT_ALPENGLOW_VOTE_PROCESSING_RESULT_SLASHABLE;                                                                                                                        break;
      default:
        FD_LOG_CRIT(( "unhandled kind" ));
      }
      if( FD_LIKELY( ctx->scratch.vote_event.reason!=UCHAR_MAX ) ) report_alpenglow_vote( ctx, NULL, &ctx->scratch.vote_event.vote, ctx->scratch.ser[ 1 ], result, quorum_reached, FD_EVENT_ALPENGLOW_VOTE_REASON_BLOCK_REPLAYED+ctx->scratch.vote_event.reason, aggregation_start_time, broadcast_start_time );

      *charge_busy = 1;
    }
  }

  if( FD_UNLIKELY( ag_votor_poll_cert_event( ctx->votor, &ctx->scratch.cert_event ) ) ) { /* a cert the pool accepted, or a standstill re-broadcast */
    ag_pool_add_cert( ctx->pool, &ctx->scratch.cert_event.cert, ctx->scratch.bad );
    if( FD_UNLIKELY( !fd_bls_set_is_null( ctx->scratch.bad ) ) ) ban_bad_ranks( ctx, ctx->scratch.bad, ag_cert_slot( &ctx->scratch.cert_event.cert ) );

    ulong ser_sz               = ag_cert_ser( &ctx->scratch.cert_event.cert, ctx->scratch.ser );
    long  broadcast_start_time = fd_clock_tile_now( ctx->clock );
    for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
      peer_t const * peer = &ctx->peers[ slot ];
      if( FD_LIKELY( peers_key_inval( peer->id_key ) || !peer->tx_conn || peer->tx_conn->state!=FD_QUIC_CONN_STATE_ACTIVE ) ) continue;
      quic_client_datagram_tx( ctx, stem, peer->tx_conn, ctx->scratch.ser, ser_sz );
    }

    ulong stake;
    switch( ctx->scratch.cert_event.cert.kind ) {
    case AG_CERT_KIND_FINAL:          stake = ctx->scratch.cert_event.cert.final.stake;          break;
    case AG_CERT_KIND_FAST_FINAL:     stake = ctx->scratch.cert_event.cert.fast_final.stake;     break;
    case AG_CERT_KIND_NOTAR:          stake = ctx->scratch.cert_event.cert.notar.stake;          break;
    case AG_CERT_KIND_NOTAR_FALLBACK: stake = ctx->scratch.cert_event.cert.notar_fallback.stake; break;
    case AG_CERT_KIND_SKIP:           stake = ctx->scratch.cert_event.cert.skip.stake;           break;
    default:                          FD_LOG_CRIT(( "unreachable" ));
    }
    if( FD_UNLIKELY( stake ) ) report_alpenglow_cert( ctx, NULL, &ctx->scratch.cert_event.cert, ctx->scratch.ser[ 1 ], FD_EVENT_ALPENGLOW_CERT_PROCESSING_RESULT_ACCEPTED, 0L, broadcast_start_time );
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ctx->next_leader_slot==ULONG_MAX ) ) return; /* never will be leader */

  /* Check if it's time to become leader. */

  ulong finalized_slot = ag_pool_finalized_slot( ctx->pool );
  while( FD_UNLIKELY( ctx->next_leader_slot<=finalized_slot ) ) {
    ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, ctx->next_leader_slot+AG_SLOTS_PER_WINDOW, &ctx->id_key );
    if( FD_UNLIKELY( ctx->next_leader_slot==ULONG_MAX ) ) return; /* schedule exhausted */
  }

  ag_block_id_t parent = ag_pool_wait_for_parent_ready( ctx->pool, ctx->next_leader_slot );
  if( FD_UNLIKELY( parent.slot==ULONG_MAX ) ) return; /* the pool has not granted parent ready yet */

  ulong reward_slot = fd_ulong_sat_sub( ctx->next_leader_slot, FD_NUM_SLOTS_FOR_REWARD );
  for( ulong i=0UL; i<AG_SLOTS_PER_WINDOW; i++ ) publish_reward_certs( ctx, stem, reward_slot+i );

  fd_votor_msg_t * chunk = fd_chunk_to_laddr( ctx->votor_out_mem, ctx->votor_out_chunk );
  chunk->leader = (fd_votor_leader_t){ .slot = ctx->next_leader_slot, .parent_slot = parent.slot, .parent_block_id = FD_LOAD( fd_hash_t, parent.hash ) };
  fd_stem_publish( stem, OUT_IDX_VOTOR, FD_VOTOR_SIG_LEADER, ctx->votor_out_chunk, sizeof(fd_votor_msg_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->votor_out_chunk = fd_dcache_compact_next( ctx->votor_out_chunk, sizeof(fd_votor_msg_t), ctx->votor_out_chunk0, ctx->votor_out_wmark );

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
    return sig!=REPLAY_SIG_SLOT_COMPLETED;
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

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_EPOCH:
    /* reliable link, handled in during_frag */
    break;
  case IN_KIND_GOSSIP:
    /* reliable link, handled in during_frag */
    break;
  case IN_KIND_IPECHO:
    FD_TEST( sig && sig<=USHORT_MAX );
    if( FD_UNLIKELY( !ctx->shred_version && ag_pool_finalized_slot( ctx->pool )!=ULONG_MAX ) ) ag_votor_init( ctx->votor, ag_pool_finalized_slot( ctx->pool ), fd_clock_tile_now( ctx->clock ), ctx->ns_per_slot, (ushort)sig, sign_bls, ctx );
    ctx->shred_version = (ushort)sig;
    ctx->init = !!ctx->curr_epoch_info && ag_pool_finalized_slot( ctx->pool )!=ULONG_MAX;
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
    fd_quic_process_packet( quic, ctx->net_buf+sizeof(fd_eth_hdr_t), sz-sizeof(fd_eth_hdr_t), fd_clock_tile_now( ctx->clock ) );
    for( ulong i=0UL; i<ctx->net_tx_cnt; i++ ) fd_stem_publish( stem, OUT_IDX_NET, ctx->net_tx[ i ].sig, ctx->net_tx[ i ].chunk, ctx->net_tx[ i ].sz, fd_frag_meta_ctl( 0UL, 1, 1, 0 ), 0L, 0L );
    ctx->net_tx_cnt = 0UL;
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

  ctx->id_key = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->votor.identity_key_path, /* pubkey only: */ 1 ) );

  fd_log_wallclock();
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t),       sizeof(fd_votor_tile_t)                           );
  void *            quic_client   = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_client_limits )          );
  void *            quic_server   = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),                fd_quic_footprint( &quic_server_limits )          );
  void *            pool          = FD_SCRATCH_ALLOC_APPEND( l, ag_pool_align(),                ag_pool_footprint( tile->votor.max_live_slots )   );
  void *            votor         = FD_SCRATCH_ALLOC_APPEND( l, ag_votor_align(),               ag_votor_footprint( tile->votor.max_live_slots )  );
  void *            peers         = FD_SCRATCH_ALLOC_APPEND( l, peers_align(),                  peers_footprint()                                 );
  void *            contact_infos = FD_SCRATCH_ALLOC_APPEND( l, contact_infos_align(),          contact_infos_footprint()                         );
  void *            mleaders      = FD_SCRATCH_ALLOC_APPEND( l, fd_multi_epoch_leaders_align(), fd_multi_epoch_leaders_footprint()                );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->shred_version = (ushort)0;

  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  ulong seed;
  FD_TEST( fd_rng_secure( &seed, sizeof(seed) ) );

  ctx->pool = ag_pool_join( ag_pool_new( pool, tile->votor.max_live_slots, seed ) );
  FD_TEST( ctx->pool );

  ctx->votor = ag_votor_join( ag_votor_new( votor, tile->votor.max_live_slots, seed ) );
  FD_TEST( ctx->votor );

  ctx->prev_epoch_info = NULL;
  ctx->prev_epoch_slot = ULONG_MAX;
  ctx->curr_epoch_info = NULL;
  ctx->curr_epoch_slot = ULONG_MAX;
  ctx->next_epoch_info = NULL;
  ctx->next_epoch_slot = ULONG_MAX;
  memset( ctx->client_peer_id_keys, 0, sizeof(ctx->client_peer_id_keys) );
  memset( ctx->server_peer_id_keys, 0, sizeof(ctx->server_peer_id_keys) );

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


  ctx->peers = peers_join( peers_new( peers ) );
  FD_TEST( ctx->peers );

  ctx->contact_infos = contact_infos_join( contact_infos_new( contact_infos ) );
  FD_TEST( ctx->contact_infos );

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders ) );
  FD_TEST( ctx->mleaders );

  ctx->init                      = 0;
  ctx->net_tx_cnt                = 0UL;
  ctx->next_leader_slot          = ULONG_MAX;
  ctx->ns_per_slot               = 400000000L; /* until epoch info */
  ctx->highest_parent_ready_slot = 0UL;
  ctx->highest_unotar_final_slot = ULONG_MAX;

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
    else if( FD_LIKELY( !strcmp( link->name, "sign_votor"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
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
  FD_TEST( net_out->burst>=FD_VOTOR_NET_BURST );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_votor", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "votor_sign", tile->kind_id );
  FD_TEST( sign_in_idx !=ULONG_MAX );
  FD_TEST( sign_out_idx!=ULONG_MAX );
  fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];

  fd_sleep_t * sleep = NULL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( sleep );
  }

  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
          sign_out->mcache,
          sign_out->dcache,
          sign_in->mcache,
          sign_in->dcache,
          sign_out->mtu,
          sign_in->mtu,
          sleep,
          sign_out->id,
          fd_topo_find_link_consumer( topo, sign_out ) ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard client" ));
  }

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
  ctx->quic_client->config.sign                       = sign_ed25519;
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
  fd_clock_tile_init( ctx->clock );
  fd_quic_set_aio_net_tx( ctx->quic_server, quic_tx_aio );

  ctx->quic_server->config.role                       = FD_QUIC_ROLE_SERVER;
  ctx->quic_server->config.retry                      = 0;
  ctx->quic_server->config.idle_timeout               = 5L*1000L*1000L*1000L;
  ctx->quic_server->config.ack_delay                  = 2L*1000L*1000L;
  memcpy( ctx->quic_server->config.identity_public_key, ctx->id_key.uc, 32UL );
  ctx->quic_server->config.sign                       = sign_ed25519;
  ctx->quic_server->config.sign_ctx                   = ctx;
  ctx->quic_server->config.alpn[ 0 ]                  = 0x0c;
  memcpy( ctx->quic_server->config.alpn+1, "alpenglow-v1", 12UL );
  ctx->quic_server->config.alpn_sz                    = 13UL;
  ctx->quic_server->config.initial_rx_max_stream_data = 0UL;
  ctx->quic_server->config.max_datagram_frame_size    = 1280UL;

  ctx->quic_server->cb.quic_ctx    = ctx;
  ctx->quic_server->cb.conn_new    = quic_server_conn_new;
  ctx->quic_server->cb.conn_final  = quic_server_conn_final;
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

static void
metrics_write( fd_votor_tile_t * ctx ) {
  FD_MCNT_ENUM_COPY( VOTOR, DATAGRAM_RX, ctx->metrics.datagram_rx );
  FD_MCNT_ENUM_COPY( VOTOR, VOTE_RX,     ctx->metrics.vote_rx     );
  FD_MCNT_ENUM_COPY( VOTOR, CERT_RX,     ctx->metrics.cert_rx     );
}

#define STEM_BURST FD_VOTOR_OUT_BURST /* votor_out only; EXCLUDES VOTOR_NET (has no reliable consumers) */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_votor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_votor_tile_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_NEXT_DEADLINE       next_deadline
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return fd_ulong_max( sizeof(fd_event_alpenglow_vote_t), sizeof(fd_event_alpenglow_cert_t) );
}

fd_topo_run_tile_t fd_tile_votor = {
  .name                     = "votor",
  .max_event_sz             = max_event_sz,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
