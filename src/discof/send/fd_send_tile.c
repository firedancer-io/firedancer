#include "fd_send_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "fd_target_slot.h"
#include "generated/fd_send_tile_seccomp.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../disco/pack/fd_microblock.h"

#include <sys/random.h>

/* 'Staleness' is currently just for debugging - we don't act on it */
#define CONTACT_INFO_STALE_NS (60e9L) /* ~60 seconds */

/* map leader pubkey to contact/conn info
   A map entry is created only for staked peers. On receiving contact info, we update
   the map entry with the following 4 sockets from the contact info:
    - QUIC_VOTE
    - QUIC_TPU
    - UDP_VOTE
    - UDP_TPU

   For the UDP ports, we simply send to that sockaddr when the leader is selected.
   For QUIC ports, we establish a quic connection just in time for the leader slot.
   We allow that connection to time out if it's going to be dormant for a while.
   This reduces the bandwidth consumed and the amount of work the fd_quic needs to do.
*/

#define MAP_NAME               fd_send_conn_map
#define MAP_T                  fd_send_conn_entry_t
#define MAP_LG_SLOT_CNT        17
#define MAP_KEY                pubkey
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(key)      ((key).ui[3])
#include "../../util/tmpl/fd_map.c"

fd_quic_limits_t quic_limits = {
  .conn_cnt                    = MAX_STAKED_LEADERS,
  .handshake_cnt               = MAX_STAKED_LEADERS,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 16UL * MAX_STAKED_LEADERS,
  .min_inflight_frame_cnt_conn = 4UL,
  .stream_id_cnt               = 64UL,
  .tx_buf_sz                   = 1UL<<11,
  .stream_pool_cnt             = 1UL<<13
};

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( 128UL, fd_quic_align() ), fd_send_conn_map_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(), fd_quic_footprint( &quic_limits ) );
  l = FD_LAYOUT_APPEND( l, fd_send_conn_map_align(), fd_send_conn_map_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* QUIC callbacks */

static void
quic_tls_cv_sign( void *      signer_ctx,
                  uchar       signature[ static 64 ],
                  uchar const payload[ static 130 ] ) {
  fd_send_tile_ctx_t * ctx = signer_ctx;
  long dt = -fd_clock_now( ctx->clock );
  fd_keyguard_client_sign( ctx->keyguard_client, signature, payload, 130UL, FD_KEYGUARD_SIGN_TYPE_ED25519 );
  dt += ( ctx->now = fd_clock_now( ctx->clock ) );
  fd_histf_sample( ctx->metrics.sign_duration, (ulong)dt );
}

/* quic_hs_complete is called when the QUIC handshake is complete
   It is currently used only for debug logging */
static void
quic_hs_complete( fd_quic_conn_t * conn,
                  void *           quic_ctx FD_PARAM_UNUSED ) {
  fd_send_tile_ctx_t * ctx = fd_type_pun( quic_ctx );
  fd_send_conn_entry_t * entry = fd_type_pun( fd_quic_conn_get_context( conn ) );
  if( FD_UNLIKELY( !entry ) ) return;

  for( ulong i=0; i<FD_SEND_PORT_QUIC_CNT; i++ ) {
    if( entry->conn[i] == conn ) { ctx->metrics.quic_hs_complete[i]++; break; }
  }
  FD_LOG_DEBUG(("send_tile: QUIC handshake complete for leader %s", FD_BASE58_ENC_32_ALLOCA( entry->pubkey.key )));
}

inline static int
port_idx_is_quic( ulong port_idx ) {
  return (port_idx==FD_SEND_PORT_QUIC_VOTE_IDX) | (port_idx==FD_SEND_PORT_QUIC_TPU_IDX);
}

/* quic_conn_final is called when the QUIC connection dies. */
static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           quic_ctx ) {
  fd_send_conn_entry_t * entry = fd_type_pun( fd_quic_conn_get_context( conn ) );
  if( FD_UNLIKELY( !entry ) ) {
    FD_LOG_CRIT(( "send_tile: Conn map entry not found in conn_final" ));
  }

  fd_send_tile_ctx_t * ctx = fd_type_pun( quic_ctx );

  ulong clr_idx = ~0UL;
  for( ulong i=0UL; i<FD_SEND_PORT_QUIC_CNT; i++ ) {
    if( entry->conn[i] == conn ) {
      entry->conn[i] = NULL;
      clr_idx = i;
      FD_LOG_DEBUG(("send_tile: Quic conn final: %p to peer " FD_IP4_ADDR_FMT ":%u", (void*)conn, FD_IP4_ADDR_FMT_ARGS(entry->ip4s[i]), entry->ports[i]));
      ctx->metrics.quic_conn_final[i]++;
      break;
    }
  }

  if( FD_UNLIKELY( clr_idx == ~0UL ) ) {
    FD_LOG_CRIT(( "conn not found in entry for peer %s", FD_BASE58_ENC_32_ALLOCA( entry->pubkey.key )));
  }
}

/* send_to_net sends a packet to the net tile.
   It takes pointers to the ip4 hdr, udp hdr, and the payload.
   Always uses the eth hdr from ctx->packet_hdr. */
static void
send_to_net( fd_send_tile_ctx_t * ctx,
             fd_ip4_hdr_t const * ip4_hdr,
             fd_udp_hdr_t const * udp_hdr,
             uchar        const * payload,
             ulong                payload_sz ) {

  uint  const ip_dst = FD_LOAD( uint, ip4_hdr->daddr_c );
  ulong const ip_sz  = FD_IP4_GET_LEN( *ip4_hdr );

  fd_send_link_out_t * net_out_link = ctx->net_out;
  uchar * packet_l2 = fd_chunk_to_laddr( net_out_link->mem, net_out_link->chunk );
  uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
  uchar * packet_l4 = packet_l3 + ip_sz;
  uchar * packet_l5 = packet_l4 + sizeof(fd_udp_hdr_t);

  fd_memcpy( packet_l2, ctx->packet_hdr->eth, sizeof(fd_eth_hdr_t) );
  fd_memcpy( packet_l3, ip4_hdr,              ip_sz                );
  fd_memcpy( packet_l4, udp_hdr,              sizeof(fd_udp_hdr_t) );
  fd_memcpy( packet_l5, payload,              payload_sz           );

  FD_LOG_DEBUG(("voting: sending packet to " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS(ip_dst), fd_ushort_bswap(udp_hdr->net_dport) ));
  ulong sig   = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
  ulong tspub = (ulong)ctx->now;
  ulong sz_l2 = sizeof(fd_eth_hdr_t) + ip_sz + sizeof(fd_udp_hdr_t) + payload_sz;

  fd_stem_publish( ctx->stem, net_out_link->idx, sig, net_out_link->chunk, sz_l2, 0UL, 0, tspub );
  net_out_link->chunk = fd_dcache_compact_next( net_out_link->chunk, sz_l2, net_out_link->chunk0, net_out_link->wmark );
}

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush FD_PARAM_UNUSED ) {
  fd_send_tile_ctx_t * ctx = _ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;
    uchar * buf = batch[ i ].buf;
    fd_ip4_hdr_t * ip4_hdr    = fd_type_pun( buf );
    fd_udp_hdr_t * udp_hdr    = fd_type_pun( buf + sizeof(fd_ip4_hdr_t) );
    uchar        * payload    = buf + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);
    ulong          payload_sz = batch[ i ].buf_sz - sizeof(fd_ip4_hdr_t) - sizeof(fd_udp_hdr_t);
    send_to_net( ctx, ip4_hdr, udp_hdr, payload, payload_sz );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

static void
during_housekeeping( fd_send_tile_ctx_t * ctx ) {
  ctx->housekeeping_ctr++;

  if( FD_UNLIKELY( ctx->recal_next <= ctx->now ) ) {
    ctx->recal_next = fd_clock_default_recal( ctx->clock );
  }

  #define MAP_STATS_PERIOD (32UL)
  if( ctx->housekeeping_ctr % MAP_STATS_PERIOD == 0UL ) {
    ulong const map_cnt = fd_send_conn_map_slot_cnt();
    ulong staked_no_ci = 0UL;
    ulong stale_ci = 0UL;
    ulong map_real_cnt = 0UL;
    for( ulong i=0UL; i<map_cnt; i++ ) {
      fd_send_conn_entry_t * entry = &ctx->conn_map[i];
      if( !fd_send_conn_map_key_equal( entry->pubkey, fd_send_conn_map_key_null() ) ) {
        map_real_cnt++;
        if( !entry->got_ci_msg ) {
          staked_no_ci++;
        } else if( ctx->now - entry->last_ci_ns > CONTACT_INFO_STALE_NS ) {
          stale_ci++;
        }
      }
    }
    ctx->metrics.staked_no_ci = staked_no_ci;
    ctx->metrics.stale_ci = stale_ci;
    FD_LOG_DEBUG(("send_tile map check: %lu no ci and %lu stale out of %lu staked", staked_no_ci, stale_ci, map_real_cnt ));
  }
  #undef MAP_STATS_PERIOD
}

/* quic_connect initiates quic connections for a given entry and port. It uses the
   contact info stored in entry, and points the conn and entry to each other.
   Returns a handle to the new connection, and NULL if creating it failed */

static fd_quic_conn_t *
quic_connect( fd_send_tile_ctx_t   * ctx,
              fd_send_conn_entry_t * entry,
              ulong                  port_idx ) {

  ulong  conn_idx = port_idx;
  uint   dst_ip   = entry->ip4s[port_idx];
  ushort dst_port = entry->ports[port_idx];

  FD_TEST( entry->conn[conn_idx] == NULL );

  fd_quic_conn_t * conn = fd_quic_connect( ctx->quic, dst_ip, dst_port, ctx->src_ip_addr, ctx->src_port, ctx->now );
  if( FD_UNLIKELY( !conn ) ) {
    FD_LOG_WARNING(( "send_tile: Failed to create QUIC connection to " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS(dst_ip), dst_port ));
    return NULL;
  }

  FD_LOG_DEBUG(("send_tile: Quic conn created: %p to peer " FD_IP4_ADDR_FMT ":%u", (void*)conn, FD_IP4_ADDR_FMT_ARGS(dst_ip), dst_port));

  entry->conn[conn_idx] = conn;
  fd_quic_conn_set_context( conn, entry );

  return conn;
}

/* ensure_conn_for_slot ensures a connection exists for the given pubkey if it's
   a leader for the target slot. Creates connection if needed. */
static void
ensure_conn_for_slot( fd_send_tile_ctx_t * ctx,
                      ulong                target_slot,
                      long                 lifespan ) {
  fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, target_slot );
  if( FD_UNLIKELY( !leader ) ) {
    /* Track NoLeader outcome for both QUIC ports */
    for( ulong i=0UL; i<FD_SEND_PORT_QUIC_CNT; i++ ) {
      ctx->metrics.ensure_conn_result[i][FD_METRICS_ENUM_SEND_ENSURE_CONN_RESULT_V_NO_LEADER_IDX]++;
    }
    return;
  }

  fd_send_conn_entry_t * entry = fd_send_conn_map_query( ctx->conn_map, *leader, NULL );
  if( FD_UNLIKELY( !entry ) ) FD_LOG_CRIT(( "Tried ensuring conn for unstaked pubkey"));

  for( ulong i=0UL; i<FD_SEND_PORT_QUIC_CNT; i++ ) {
    if( FD_UNLIKELY( !entry->ip4s[i] | !entry->ports[i] ) ) {
      ctx->metrics.ensure_conn_result[i][FD_METRICS_ENUM_SEND_ENSURE_CONN_RESULT_V_NO_CI_IDX]++;
      continue;
    }

    if( !entry->conn[i] ) {
      /* Attempting to create new connection */
      fd_quic_conn_t * conn  = quic_connect( ctx, entry, i );
      if( FD_UNLIKELY( !conn ) ) continue;
      ctx->metrics.ensure_conn_result[i][FD_METRICS_ENUM_SEND_ENSURE_CONN_RESULT_V_NEW_CONNECTION_IDX]++;
      fd_quic_service( ctx->quic, ctx->now );
    } else {
      /* Connection already exists */
      ctx->metrics.ensure_conn_result[i][FD_METRICS_ENUM_SEND_ENSURE_CONN_RESULT_V_CONNECTED_IDX]++;
      fd_quic_conn_let_die( entry->conn[i], lifespan );
    }
  }
}

/* leader_send sends a payload to 'pubkey' in all possible ways. For quic targets,
   it relies on quic connections that are already established. */
static void
leader_send( fd_send_tile_ctx_t * ctx,
             fd_pubkey_t const  * pubkey,
             uchar const        * payload,
             ulong                payload_sz ) {

  fd_send_conn_entry_t * entry = fd_send_conn_map_query( ctx->conn_map, *pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) {
    FD_LOG_CRIT(( "Tried looking up connection for an unstaked pubkey"));
  }

  for( ulong i=0UL; i<FD_SEND_PORT_CNT; i++ ) {
    /* skip unroutable */
    if( !entry->ip4s[i] | !entry->ports[i] ) {
      ctx->metrics.send_result_cnt[i][FD_METRICS_ENUM_TXN_SEND_RESULT_V_NO_CI_IDX]++;
      continue;
    }

    if( port_idx_is_quic( i ) ) {
      fd_quic_conn_t * conn = entry->conn[i];
      if( FD_UNLIKELY( !conn ) ) {
        FD_LOG_DEBUG(("no conn for %s at " FD_IP4_ADDR_FMT ":%u", FD_BASE58_ENC_32_ALLOCA( pubkey->key ), FD_IP4_ADDR_FMT_ARGS(entry->ip4s[i]), entry->ports[i] ));
        ctx->metrics.send_result_cnt[i][FD_METRICS_ENUM_TXN_SEND_RESULT_V_NO_CONN_IDX]++;
        continue;
      }

      fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
      if( FD_UNLIKELY( !stream ) ) {
        FD_LOG_DEBUG(("new_stream failed for %s at " FD_IP4_ADDR_FMT ":%u bc conn state was %u", FD_BASE58_ENC_32_ALLOCA( pubkey->key ), FD_IP4_ADDR_FMT_ARGS(entry->ip4s[i]), entry->ports[i], conn->state ));
        ctx->metrics.send_result_cnt[i][FD_METRICS_ENUM_TXN_SEND_RESULT_V_NO_STREAM_IDX]++;
        continue;
      }

      ctx->metrics.send_result_cnt[i][FD_METRICS_ENUM_TXN_SEND_RESULT_V_SUCCESS_IDX]++;

      fd_quic_stream_send( stream, payload, payload_sz, 1 );
      fd_quic_service( ctx->quic, ctx->now ); /* trigger send ASAP */
    } else {

      fd_ip4_hdr_t * ip4_hdr = ctx->packet_hdr->ip4;
      fd_udp_hdr_t * udp_hdr = ctx->packet_hdr->udp;

      ctx->metrics.send_result_cnt[i][FD_METRICS_ENUM_TXN_SEND_RESULT_V_SUCCESS_IDX]++;

      ip4_hdr->daddr       = entry->ip4s[i];
      ip4_hdr->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
      ip4_hdr->net_id      = fd_ushort_bswap( ctx->net_id++ );
      ip4_hdr->check       = 0;
      ip4_hdr->check       = fd_ip4_hdr_check_fast( ip4_hdr );

      udp_hdr->net_dport = fd_ushort_bswap( entry->ports[i] ); /* to net order */
      udp_hdr->net_len   = fd_ushort_bswap( (ushort)( payload_sz + sizeof(fd_udp_hdr_t) ) );
      send_to_net( ctx, ip4_hdr, udp_hdr, payload, payload_sz );
    }
  }
}

/* handle_contact_info_update handles a new contact. Validates contact info
   and starts/restarts a connection if necessary. */
static inline void
handle_contact_info_update( fd_send_tile_ctx_t *               ctx,
                            fd_gossip_update_message_t const * msg ) {
  static uint const socket_idx[FD_SEND_PORT_CNT] = {
    FD_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC,
    FD_CONTACT_INFO_SOCKET_TPU_QUIC,
    FD_CONTACT_INFO_SOCKET_TPU_VOTE,
    FD_CONTACT_INFO_SOCKET_TPU
  };

  fd_send_conn_entry_t * entry  = fd_send_conn_map_query( ctx->conn_map, *(fd_pubkey_t *)(msg->origin_pubkey), NULL );
  if( FD_UNLIKELY( !entry ) ) {
    /* Skip if UNSTAKED */
    // FD_LOG_DEBUG(("send_tile: Skipping unstaked pubkey %s", FD_BASE58_ENC_32_ALLOCA( msg->origin_pubkey )));
    ctx->metrics.unstaked_ci_rcvd++;
    return;
  }

  for( ulong i=0UL; i<FD_SEND_PORT_CNT; i++ ) {

    fd_ip4_port_t const * socket   = &msg->contact_info.contact_info->sockets[ socket_idx[i] ];
    uint                  new_ip   = socket->addr;
    ushort                new_port = fd_ushort_bswap( socket->port ); /* convert port to host order */
    uint                  old_ip   = entry->ip4s[i];
    ushort                old_port = entry->ports[i];

    if( FD_UNLIKELY( !new_ip || !new_port ) ) {
      FD_LOG_DEBUG(( "send_tile: Unroutable contact info for pubkey %s", FD_BASE58_ENC_32_ALLOCA( msg->origin_pubkey )));
      ctx->metrics.new_contact_info[i][FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_V_UNROUTABLE_IDX]++;
      continue;
    }

    int info_changed    = (old_ip != new_ip) | (old_port != new_port);
    entry->ip4s [i]  = new_ip;
    entry->ports[i] = new_port;

    ulong quic_conn_idx = i;
    if( port_idx_is_quic( i ) && info_changed && entry->conn[quic_conn_idx]!=NULL ) {
      /* Track connection finalization before closing */
      fd_quic_conn_close( entry->conn[i], 0 );
    }

    /* bc taking branches for just metrics would be sad */
    /* !info_changed -> NoChange, info_changed && old_port==0 -> Initialized, info_changed && old_port!=0 -> Changed */
    static ulong metric_idx_map[] = {
      FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_V_NO_CHANGE_IDX,
      FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_V_INITIALIZED_IDX,
      FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_V_CHANGED_IDX
    };
    ulong metric_idx = metric_idx_map[ !!info_changed<<(!!old_port) ];
    ctx->metrics.new_contact_info[i][metric_idx]++;
  }

  entry->got_ci_msg    = 1;
  entry->last_ci_ns    = ctx->now;
}

static inline void
handle_contact_info_removal( fd_send_tile_ctx_t *                ctx FD_PARAM_UNUSED,
                              fd_gossip_update_message_t const * msg FD_PARAM_UNUSED ) {
  fd_send_conn_entry_t * entry = fd_send_conn_map_query( ctx->conn_map, *(fd_pubkey_t *)(msg->origin_pubkey), NULL );
  if( FD_LIKELY( entry ) ) {
    for( ulong i=0UL; i<FD_SEND_PORT_QUIC_CNT; i++ ) {
      if( FD_UNLIKELY( entry->conn[i] ) ) fd_quic_conn_close( entry->conn[i], 0 );
      entry->ip4s[i]  = 0;
      entry->ports[i] = 0;
    }
    ctx->metrics.ci_removed++;
  }
}

/* Called during after_frag for stake messages. */
static void
finalize_stake_msg( fd_send_tile_ctx_t * ctx ) {

  fd_multi_epoch_leaders_stake_msg_fini( ctx->mleaders );

  /* Get the current stake destinations */
  fd_vote_stake_weight_t const * stakes = fd_multi_epoch_leaders_get_stake_weights( ctx->mleaders );
  ulong                       stake_cnt = fd_multi_epoch_leaders_get_stake_cnt( ctx->mleaders );
  if( FD_UNLIKELY( !stakes ) ) {
    FD_LOG_WARNING(( "No stake destinations available for current slot" ));
    return;
  }

  /* populate staked validators in connection map */
  for( ulong i=0UL; i<stake_cnt; i++ ) {
    fd_vote_stake_weight_t const * stake_info = &stakes[i];
    fd_pubkey_t            const   pubkey     = stake_info->id_key;

    fd_send_conn_entry_t * entry = fd_send_conn_map_query( ctx->conn_map, pubkey, NULL );
    /* UNSTAKED -> NO_CONN: create new entry in NO_CONN state */
    if( FD_UNLIKELY( !entry ) ) {
      // FD_LOG_DEBUG(("send_tile: creating new entry for pubkey %s", FD_BASE58_ENC_32_ALLOCA( pubkey.key )));
      /* insert and initialize entry */
      entry = fd_send_conn_map_insert( ctx->conn_map, pubkey );
      *entry = (fd_send_conn_entry_t){.pubkey = entry->pubkey, .hash = entry->hash };
    }
  }
}

static void
handle_vote_msg( fd_send_tile_ctx_t * ctx,
                 ulong                vote_slot,
                 uchar *              signed_vote_txn,
                 ulong                vote_txn_sz ) {
  uchar txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_txn_t * txn = (fd_txn_t *)txn_mem;
  FD_TEST( fd_txn_parse( signed_vote_txn, vote_txn_sz, txn_mem, NULL ) );

  /* sign the txn */
  uchar * signature = signed_vote_txn + txn->signature_off;
  uchar const * message   = signed_vote_txn + txn->message_off;
  ulong message_sz  = vote_txn_sz - txn->message_off;
  fd_keyguard_client_sign( ctx->keyguard_client, signature, message, message_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

  FD_LOG_INFO(("got vote for slot %lu", vote_slot));

  fd_target_slot_push( ctx->target_slot, FD_TARGET_SLOT_TYPE_VOTE, vote_slot );

  ulong const target_cnt = fd_target_slot_predict( ctx->target_slot );

  /* send to leader for next few slots */
  for( ulong i=0UL; i<target_cnt; i++ ) {
    ulong target_slot = ctx->target_slot->slots[i];
    fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, target_slot );
    if( FD_LIKELY( leader ) ) {
      leader_send( ctx, leader, signed_vote_txn, vote_txn_sz );
    } else {
      ctx->metrics.leader_not_found++;
      FD_LOG_DEBUG(("send_tile: Failed to get leader contact for slot %lu", target_slot));
    }
  }

  ulong const most_likely_slot = ctx->target_slot->slots[0];
  for( ulong i=0; i<FD_SEND_CONNECT_AHEAD_LEADER_CNT; i++ ) {
    /* FIXME: be smarter than just most likely slot ? */
    ulong connect_slot = most_likely_slot + i*FD_EPOCH_SLOTS_PER_ROTATION;
    /* keep alive for at least as long as needed */
    ensure_conn_for_slot( ctx, connect_slot, FD_SEND_QUIC_MIN_CONN_LIFETIME_SECONDS * (long)1e9 );
  }

  /* send to gossip and dedup */
  fd_send_link_out_t * gossip_verify_out = ctx->gossip_verify_out;
  uchar * msg_to_gossip = fd_chunk_to_laddr( gossip_verify_out->mem, gossip_verify_out->chunk );
  fd_txn_m_t * txnm = (fd_txn_m_t *)msg_to_gossip;
  *txnm = (fd_txn_m_t) { 0UL };
  txnm->payload_sz = (ushort)vote_txn_sz;
  txnm->source_ipv4 = ctx->src_ip_addr;
  txnm->source_tpu  = FD_TXN_M_TPU_SOURCE_SEND;
  fd_memcpy( msg_to_gossip+sizeof(fd_txn_m_t), signed_vote_txn, vote_txn_sz );
  ulong msg_sz = fd_txn_m_realized_footprint( txnm, 0, 0 );
  fd_stem_publish( ctx->stem, gossip_verify_out->idx, 1UL, gossip_verify_out->chunk, msg_sz, 0UL, 0, 0 );
  gossip_verify_out->chunk = fd_dcache_compact_next(
    gossip_verify_out->chunk,
    msg_sz,
    gossip_verify_out->chunk0,
    gossip_verify_out->wmark );
}

/* Stem callbacks */

static inline void
before_credit( fd_send_tile_ctx_t * ctx,
               fd_stem_context_t  * stem,
               int *                charge_busy ) {
  ctx->stem = stem;

  ctx->now = fd_clock_now( ctx->clock );
  /* Publishes to mcache via callbacks */
  *charge_busy = fd_quic_service( ctx->quic, ctx->now );
}

static inline int
before_frag( fd_send_tile_ctx_t * ctx,
             ulong                in_idx,
             ulong                seq FD_PARAM_UNUSED,
             ulong                sig ) {
  if( FD_UNLIKELY( ctx->in_links[in_idx].kind==IN_KIND_GOSSIP ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }

  if( FD_UNLIKELY( ctx->in_links[in_idx].kind==IN_KIND_POH ) ) {
    return fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_MICROBLOCK;
  }

  return 0;
}

static void
during_frag( fd_send_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {

  fd_send_link_in_t * in_link = &ctx->in_links[ in_idx ];
  if( FD_UNLIKELY( chunk<in_link->chunk0 || chunk>in_link->wmark ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu] on link %lu", chunk, sz, in_link->chunk0, in_link->wmark, in_idx ));
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( in_link->mem, chunk );
  ulong         kind         = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_NET ) ) {
    void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds, chunk, ctl, sz );
    fd_memcpy( ctx->quic_buf, src, sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_STAKE ) ) {
    if( sz>sizeof(fd_stake_weight_t)*(MAX_STAKED_LEADERS+1UL) ) {
      FD_LOG_ERR(( "sz %lu >= max expected stake update size %lu", sz, sizeof(fd_stake_weight_t) * (MAX_STAKED_LEADERS+1UL) ));
    }
    fd_multi_epoch_leaders_stake_msg_init( ctx->mleaders, fd_type_pun_const( dcache_entry ) );
  }

  if( FD_LIKELY( kind==IN_KIND_GOSSIP ) ) {
    fd_memcpy( ctx->contact_buf, dcache_entry, sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_TOWER ) ) {
    FD_TEST( sz==sizeof(fd_tower_slot_done_t) );

    fd_tower_slot_done_t const * slot_done = fd_type_pun_const( dcache_entry );

    ulong const vote_slot   = slot_done->vote_slot;
    ulong const vote_txn_sz = slot_done->vote_txn_sz;
    if( FD_UNLIKELY( vote_slot==ULONG_MAX ) ) return; /* no new vote to send */

    uchar vote_txn[ FD_TPU_MTU ];
    fd_memcpy( vote_txn, slot_done->vote_txn, vote_txn_sz );

    handle_vote_msg( ctx, vote_slot, vote_txn, vote_txn_sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_SHRED ) ) {
    fd_target_slot_push( ctx->target_slot, FD_TARGET_SLOT_TYPE_TURBINE, fd_disco_shred_out_shred_sig_slot( sig ) );
  }

  if( FD_UNLIKELY( kind==IN_KIND_POH ) ) {
    fd_entry_batch_meta_t const * meta = fd_type_pun_const( dcache_entry );
    if( FD_UNLIKELY( meta->block_complete ) ) {
      ulong poh_slot = fd_disco_poh_sig_slot( sig );
      fd_target_slot_push( ctx->target_slot, FD_TARGET_SLOT_TYPE_POH, poh_slot );
    }
  }
}

static void
after_frag( fd_send_tile_ctx_t * ctx,
            ulong                in_idx,
            ulong                seq FD_PARAM_UNUSED,
            ulong                sig FD_PARAM_UNUSED,
            ulong                sz,
            ulong                tsorig FD_PARAM_UNUSED,
            ulong                tspub FD_PARAM_UNUSED,
            fd_stem_context_t *  stem ) {

  ctx->stem = stem;

  fd_send_link_in_t * in_link = &ctx->in_links[ in_idx ];
  ulong                 kind  = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_NET ) ) {
    uchar     * ip_pkt = ctx->quic_buf + sizeof(fd_eth_hdr_t);
    ulong       ip_sz  = sz - sizeof(fd_eth_hdr_t);
    fd_quic_t * quic   = ctx->quic;

    fd_quic_process_packet( quic, ip_pkt, ip_sz, ctx->now );
  }

  if( FD_UNLIKELY( kind==IN_KIND_GOSSIP ) ) {
    fd_gossip_update_message_t const * msg = fd_type_pun_const( ctx->contact_buf );
    if( FD_LIKELY( msg->tag==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) ) {
      handle_contact_info_update( ctx, msg );
    } else if ( FD_UNLIKELY( msg->tag==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) ) {
      handle_contact_info_removal( ctx, msg );
    }
  }

  if( FD_UNLIKELY( kind==IN_KIND_STAKE ) ) {
    finalize_stake_msg( ctx );
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_send_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_send_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->send.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)(fd_keyload_load( tile->send.identity_key_path, /* pubkey only: */ 1 ) );
}

static fd_send_link_in_t *
setup_input_link( fd_send_tile_ctx_t * ctx,
                  fd_topo_t          * topo,
                  fd_topo_tile_t     * tile,
                  ulong                kind,
                  const char         * name ) {
  ulong in_idx = fd_topo_find_tile_in_link( topo, tile, name, 0 );
  FD_TEST( in_idx!=ULONG_MAX );
  fd_topo_link_t    * in_link      = &topo->links[ tile->in_link_id[ in_idx ] ];
  fd_send_link_in_t * in_link_desc = &ctx->in_links[ in_idx ];

  in_link_desc->mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
  in_link_desc->chunk0 = fd_dcache_compact_chunk0( in_link_desc->mem, in_link->dcache );
  in_link_desc->wmark  = fd_dcache_compact_wmark( in_link_desc->mem, in_link->dcache, in_link->mtu );
  in_link_desc->dcache = in_link->dcache;
  in_link_desc->kind   = kind;

  return in_link_desc;
}

static void
setup_output_link( fd_send_link_out_t * desc,
                   fd_topo_t           * topo,
                   fd_topo_tile_t      * tile,
                   const char          * name ) {
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, name, 0 );
  FD_TEST( out_idx!=ULONG_MAX );
  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ out_idx ] ];

  desc->idx    = out_idx;
  desc->mcache = out_link->mcache;
  desc->sync   = fd_mcache_seq_laddr( desc->mcache );
  desc->depth  = fd_mcache_depth( desc->mcache );
  desc->mem    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  desc->chunk0 = fd_dcache_compact_chunk0( desc->mem, out_link->dcache );
  desc->wmark  = fd_dcache_compact_wmark( desc->mem, out_link->dcache, out_link->mtu );
  desc->chunk  = desc->chunk0;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( !tile->out_cnt ) ) FD_LOG_ERR(( "send has no output link" ));

  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_send_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
  if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  fd_quic_t * quic = fd_quic_join( fd_quic_new( FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &quic_limits ) ), &quic_limits ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_new failed" ));

  quic->config.role          =  FD_QUIC_ROLE_CLIENT;
  quic->config.idle_timeout  =  FD_SEND_QUIC_IDLE_TIMEOUT_NS;
  quic->config.ack_delay     =  FD_SEND_QUIC_ACK_DELAY_NS;
  quic->config.keep_alive    =  1;
  quic->config.sign          =  quic_tls_cv_sign;
  quic->config.sign_ctx      =  ctx;
  fd_memcpy( quic->config.identity_public_key, ctx->identity_key, sizeof(ctx->identity_key) );

  quic->cb.conn_hs_complete  = quic_hs_complete;
  quic->cb.conn_final        = quic_conn_final;
  quic->cb.quic_ctx          = ctx;

  fd_quic_set_aio_net_tx( quic, quic_tx_aio );
  FD_TEST_CUSTOM( fd_quic_init( quic ), "fd_quic_init failed" );

  ctx->quic = quic;

  /* Initialize connection map */
  void * conn_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_send_conn_map_align(), fd_send_conn_map_footprint() );
  ctx->conn_map = fd_send_conn_map_join( fd_send_conn_map_new( conn_map_mem ) );
  if( FD_UNLIKELY( !ctx->conn_map ) ) FD_LOG_ERR(( "fd_send_conn_map_join failed" ));

  /* Initalize slot predictor */
  fd_target_slot_t * target_slot = fd_target_slot_new( ctx->target_slot_mem );
  if( FD_UNLIKELY( !target_slot ) ) FD_LOG_ERR(( "fd_target_slot_new failed" ));
  ctx->target_slot = target_slot;

  ctx->src_ip_addr = tile->send.ip_addr;
  ctx->src_port    = tile->send.send_src_port;
  fd_ip4_udp_hdr_init( ctx->packet_hdr, FD_TXN_MTU, ctx->src_ip_addr, ctx->src_port );

  setup_input_link( ctx, topo, tile, IN_KIND_GOSSIP, "gossip_out"   );
  setup_input_link( ctx, topo, tile, IN_KIND_STAKE,  "replay_stake" );
  setup_input_link( ctx, topo, tile, IN_KIND_TOWER,  "tower_out"    );
  setup_input_link( ctx, topo, tile, IN_KIND_SHRED,  "shred_out"    );
  setup_input_link( ctx, topo, tile, IN_KIND_POH,    "poh_replay"   );

  fd_send_link_in_t * net_in = setup_input_link( ctx, topo, tile, IN_KIND_NET, "net_send" );
  fd_net_rx_bounds_init( &ctx->net_in_bounds, net_in->dcache );

  setup_output_link( ctx->gossip_verify_out, topo, tile, "send_txns" );
  setup_output_link( ctx->net_out,           topo, tile, "send_net"  );

  /* Set up keyguard(s) */
  ulong             sign_in_idx  =  fd_topo_find_tile_in_link(  topo, tile, "sign_send", 0 );
  ulong             sign_out_idx =  fd_topo_find_tile_out_link( topo, tile, "send_sign", 0 );
  fd_topo_link_t  * sign_in      =  &topo->links[ tile->in_link_id[  sign_in_idx  ] ];
  fd_topo_link_t  * sign_out     =  &topo->links[ tile->out_link_id[ sign_out_idx ] ];

  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache,
                                                            sign_out->mtu ) )==NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

  /* init metrics */
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
  fd_histf_join( fd_histf_new( ctx->metrics.sign_duration,
                                  FD_MHIST_MIN( SEND, SIGN_DURATION_NANOS    ),
                                  FD_MHIST_MAX( SEND, SIGN_DURATION_NANOS    ) ) );

  /* Call new/join here rather than in fd_quic so min/max can differ across uses */
  fd_histf_join( fd_histf_new( quic->metrics.service_duration,
                                  FD_MHIST_SECONDS_MIN( SEND, SERVICE_DURATION_SECONDS ),
                                  FD_MHIST_SECONDS_MAX( SEND, SERVICE_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( quic->metrics.receive_duration,
                                  FD_MHIST_SECONDS_MIN( SEND, RECEIVE_DURATION_SECONDS ),
                                  FD_MHIST_SECONDS_MAX( SEND, RECEIVE_DURATION_SECONDS ) ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }

  fd_clock_t * clock = ctx->clock;
  fd_clock_default_init( clock, ctx->clock_mem );
  ctx->recal_next    = fd_clock_recal_next( clock );
  ctx->now           = fd_clock_now( clock );
}

static ulong
populate_allowed_seccomp( fd_topo_t      const * topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter   * out ) {

  populate_sock_filter_policy_fd_send_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_send_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

static void
metrics_write( fd_send_tile_ctx_t * ctx ) {

  /* Basic counters */
  FD_MCNT_SET(       SEND, LEADER_NOT_FOUND,             ctx->metrics.leader_not_found                             );
  FD_MCNT_SET(       SEND, UNSTAKED_CI,                  ctx->metrics.unstaked_ci_rcvd                             );
  FD_MCNT_SET(       SEND, CI_REMOVED,                   ctx->metrics.ci_removed                                   );

  /* Port-separated contact info metrics */
  FD_MCNT_ENUM_COPY( SEND, NEW_CONTACT_INFO_QUIC_VOTE,   ctx->metrics.new_contact_info[FD_SEND_PORT_QUIC_VOTE_IDX] );
  FD_MCNT_ENUM_COPY( SEND, NEW_CONTACT_INFO_QUIC_TPU,    ctx->metrics.new_contact_info[FD_SEND_PORT_QUIC_TPU_IDX]  );
  FD_MCNT_ENUM_COPY( SEND, NEW_CONTACT_INFO_UDP_VOTE,    ctx->metrics.new_contact_info[FD_SEND_PORT_UDP_VOTE_IDX]  );
  FD_MCNT_ENUM_COPY( SEND, NEW_CONTACT_INFO_UDP_TPU,     ctx->metrics.new_contact_info[FD_SEND_PORT_UDP_TPU_IDX]   );

  /* Port-separated send result metrics */
  FD_MCNT_ENUM_COPY( SEND, SEND_RESULT_QUIC_VOTE,        ctx->metrics.send_result_cnt[FD_SEND_PORT_QUIC_VOTE_IDX]  );
  FD_MCNT_ENUM_COPY( SEND, SEND_RESULT_QUIC_TPU,         ctx->metrics.send_result_cnt[FD_SEND_PORT_QUIC_TPU_IDX]   );
  FD_MCNT_ENUM_COPY( SEND, SEND_RESULT_UDP_VOTE,         ctx->metrics.send_result_cnt[FD_SEND_PORT_UDP_VOTE_IDX]   );
  FD_MCNT_ENUM_COPY( SEND, SEND_RESULT_UDP_TPU,          ctx->metrics.send_result_cnt[FD_SEND_PORT_UDP_TPU_IDX]    );

  /* Port-separated QUIC metrics */
  FD_MCNT_ENUM_COPY( SEND, HANDSHAKE_COMPLETE,           ctx->metrics.quic_hs_complete                             );
  FD_MCNT_ENUM_COPY( SEND, QUIC_CONN_FINAL,              ctx->metrics.quic_conn_final                              );
  FD_MCNT_ENUM_COPY( SEND, ENSURE_CONN_RESULT_QUIC_VOTE, ctx->metrics.ensure_conn_result[FD_METRICS_ENUM_SEND_QUIC_PORTS_V_QUIC_VOTE_IDX] );
  FD_MCNT_ENUM_COPY( SEND, ENSURE_CONN_RESULT_QUIC_TPU,  ctx->metrics.ensure_conn_result[FD_METRICS_ENUM_SEND_QUIC_PORTS_V_QUIC_TPU_IDX] );

  /* Gauges */
  FD_MGAUGE_SET(     SEND, STAKED_NO_CI,                 ctx->metrics.staked_no_ci                                 );
  FD_MGAUGE_SET(     SEND, STALE_CI,                     ctx->metrics.stale_ci                                     );

  FD_MHIST_COPY(     SEND, SIGN_DURATION_NANOS,          ctx->metrics.sign_duration                                );

  /* General QUIC metrics */
  FD_MCNT_SET(         SEND, RECEIVED_BYTES,              ctx->quic->metrics.net_rx_byte_cnt         );
  FD_MCNT_ENUM_COPY(   SEND, RECEIVED_FRAMES,             ctx->quic->metrics.frame_rx_cnt            );
  FD_MCNT_SET(         SEND, RECEIVED_PACKETS,            ctx->quic->metrics.net_rx_pkt_cnt          );
  FD_MCNT_SET(         SEND, STREAM_RECEIVED_BYTES,       ctx->quic->metrics.stream_rx_byte_cnt      );
  FD_MCNT_SET(         SEND, STREAM_RECEIVED_EVENTS,      ctx->quic->metrics.stream_rx_event_cnt     );

  FD_MCNT_SET(         SEND, SENT_PACKETS,                ctx->quic->metrics.net_tx_pkt_cnt          );
  FD_MCNT_SET(         SEND, SENT_BYTES,                  ctx->quic->metrics.net_tx_byte_cnt         );
  FD_MCNT_SET(         SEND, RETRY_SENT,                  ctx->quic->metrics.retry_tx_cnt            );
  FD_MCNT_ENUM_COPY(   SEND, ACK_TX,                      ctx->quic->metrics.ack_tx                  );

  FD_MGAUGE_ENUM_COPY( SEND, CONNECTIONS_STATE,           ctx->quic->metrics.conn_state_cnt          );
  FD_MGAUGE_SET(       SEND, CONNECTIONS_ALLOC,           ctx->quic->metrics.conn_alloc_cnt          );
  FD_MCNT_SET(         SEND, CONNECTIONS_CREATED,         ctx->quic->metrics.conn_created_cnt        );
  FD_MCNT_SET(         SEND, CONNECTIONS_CLOSED,          ctx->quic->metrics.conn_closed_cnt         );
  FD_MCNT_SET(         SEND, CONNECTIONS_ABORTED,         ctx->quic->metrics.conn_aborted_cnt        );
  FD_MCNT_SET(         SEND, CONNECTIONS_TIMED_OUT,       ctx->quic->metrics.conn_timeout_cnt        );
  FD_MCNT_SET(         SEND, CONNECTIONS_RETRIED,         ctx->quic->metrics.conn_retry_cnt          );
  FD_MCNT_SET(         SEND, CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt   );
  FD_MCNT_SET(         SEND, CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_ENUM_COPY(   SEND, PKT_CRYPTO_FAILED,           ctx->quic->metrics.pkt_decrypt_fail_cnt    );
  FD_MCNT_ENUM_COPY(   SEND, PKT_NO_KEY,                  ctx->quic->metrics.pkt_no_key_cnt          );
  FD_MCNT_ENUM_COPY(   SEND, PKT_NO_CONN,                 ctx->quic->metrics.pkt_no_conn_cnt         );
  FD_MCNT_ENUM_COPY(   SEND, FRAME_TX_ALLOC,              ctx->quic->metrics.frame_tx_alloc_cnt      );
  FD_MCNT_SET(         SEND, PKT_NET_HEADER_INVALID,      ctx->quic->metrics.pkt_net_hdr_err_cnt     );
  FD_MCNT_SET(         SEND, PKT_QUIC_HEADER_INVALID,     ctx->quic->metrics.pkt_quic_hdr_err_cnt    );
  FD_MCNT_SET(         SEND, PKT_UNDERSZ,                 ctx->quic->metrics.pkt_undersz_cnt         );
  FD_MCNT_SET(         SEND, PKT_OVERSZ,                  ctx->quic->metrics.pkt_oversz_cnt          );
  FD_MCNT_SET(         SEND, PKT_VERNEG,                  ctx->quic->metrics.pkt_verneg_cnt          );
  FD_MCNT_SET(         SEND, PKT_RETRANSMISSIONS,         ctx->quic->metrics.pkt_retransmissions_cnt );

  FD_MCNT_SET(         SEND, HANDSHAKES_CREATED,          ctx->quic->metrics.hs_created_cnt          );
  FD_MCNT_SET(         SEND, HANDSHAKE_ERROR_ALLOC_FAIL,  ctx->quic->metrics.hs_err_alloc_fail_cnt   );
  FD_MCNT_SET(         SEND, HANDSHAKE_EVICTED,           ctx->quic->metrics.hs_evicted_cnt          );

  FD_MCNT_SET(         SEND, FRAME_FAIL_PARSE,            ctx->quic->metrics.frame_rx_err_cnt        );

  FD_MHIST_COPY(       SEND, SERVICE_DURATION_SECONDS,    ctx->quic->metrics.service_duration        );
  FD_MHIST_COPY(       SEND, RECEIVE_DURATION_SECONDS,    ctx->quic->metrics.receive_duration        );
}


#define STEM_BURST                        1UL /* send_txns */
#define STEM_LAZY                         100000000UL /* 100ms */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_send_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_send_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_send = {
  .name                     = "send",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
