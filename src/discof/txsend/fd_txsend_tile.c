#include "fd_txsend_tile.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "generated/fd_txsend_tile_seccomp.h"

#include "../../util/net/fd_net_headers.h"
#include "../../waltz/quic/fd_quic.h"

#define IN_KIND_SIGN   (0UL)
#define IN_KIND_GOSSIP (1UL)
#define IN_KIND_EPOCH  (2UL)
#define IN_KIND_TOWER  (3UL)
#define IN_KIND_NET    (4UL)

fd_quic_limits_t quic_limits = {
  .conn_cnt                    = 128UL,
  .handshake_cnt               = 128UL,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 16UL * 128UL,
  .min_inflight_frame_cnt_conn = 4UL,
  .stream_id_cnt               = 64UL,
  .tx_buf_sz                   = FD_TXN_MTU,
  .stream_pool_cnt             = 128UL,
};

#define MAP_NAME               peer_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              peer_entry_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#define MAP_IMPL_STYLE         2
#include "../../util/tmpl/fd_map_chain.c"

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( 128UL, fd_quic_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_txsend_tile_t), sizeof(fd_txsend_tile_t) );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),           fd_quic_footprint( &quic_limits ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),          peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_txsend_tile_t * ctx ) {
  FD_MCNT_SET(         TXSEND, RECEIVED_BYTES,              ctx->quic->metrics.net_rx_byte_cnt         );
  FD_MCNT_ENUM_COPY(   TXSEND, RECEIVED_FRAMES,             ctx->quic->metrics.frame_rx_cnt            );
  FD_MCNT_SET(         TXSEND, RECEIVED_PACKETS,            ctx->quic->metrics.net_rx_pkt_cnt          );
  FD_MCNT_SET(         TXSEND, STREAM_RECEIVED_BYTES,       ctx->quic->metrics.stream_rx_byte_cnt      );
  FD_MCNT_SET(         TXSEND, STREAM_RECEIVED_EVENTS,      ctx->quic->metrics.stream_rx_event_cnt     );

  FD_MCNT_SET(         TXSEND, SENT_PACKETS,                ctx->quic->metrics.net_tx_pkt_cnt          );
  FD_MCNT_SET(         TXSEND, SENT_BYTES,                  ctx->quic->metrics.net_tx_byte_cnt         );
  FD_MCNT_SET(         TXSEND, RETRY_SENT,                  ctx->quic->metrics.retry_tx_cnt            );
  FD_MCNT_ENUM_COPY(   TXSEND, ACK_TX,                      ctx->quic->metrics.ack_tx                  );

  FD_MGAUGE_ENUM_COPY( TXSEND, CONNECTIONS_STATE,           ctx->quic->metrics.conn_state_cnt          );
  FD_MGAUGE_SET(       TXSEND, CONNECTIONS_ALLOC,           ctx->quic->metrics.conn_alloc_cnt          );
  FD_MCNT_SET(         TXSEND, CONNECTIONS_CREATED,         ctx->quic->metrics.conn_created_cnt        );
  FD_MCNT_SET(         TXSEND, CONNECTIONS_CLOSED,          ctx->quic->metrics.conn_closed_cnt         );
  FD_MCNT_SET(         TXSEND, CONNECTIONS_ABORTED,         ctx->quic->metrics.conn_aborted_cnt        );
  FD_MCNT_SET(         TXSEND, CONNECTIONS_TIMED_OUT,       ctx->quic->metrics.conn_timeout_cnt        );
  FD_MCNT_SET(         TXSEND, CONNECTIONS_RETRIED,         ctx->quic->metrics.conn_retry_cnt          );
  FD_MCNT_SET(         TXSEND, CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt   );
  FD_MCNT_SET(         TXSEND, CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_ENUM_COPY(   TXSEND, PKT_CRYPTO_FAILED,           ctx->quic->metrics.pkt_decrypt_fail_cnt    );
  FD_MCNT_ENUM_COPY(   TXSEND, PKT_NO_KEY,                  ctx->quic->metrics.pkt_no_key_cnt          );
  FD_MCNT_ENUM_COPY(   TXSEND, PKT_NO_CONN,                 ctx->quic->metrics.pkt_no_conn_cnt         );
  FD_MCNT_ENUM_COPY(   TXSEND, FRAME_TX_ALLOC,              ctx->quic->metrics.frame_tx_alloc_cnt      );
  FD_MCNT_SET(         TXSEND, PKT_NET_HEADER_INVALID,      ctx->quic->metrics.pkt_net_hdr_err_cnt     );
  FD_MCNT_SET(         TXSEND, PKT_QUIC_HEADER_INVALID,     ctx->quic->metrics.pkt_quic_hdr_err_cnt    );
  FD_MCNT_SET(         TXSEND, PKT_UNDERSZ,                 ctx->quic->metrics.pkt_undersz_cnt         );
  FD_MCNT_SET(         TXSEND, PKT_OVERSZ,                  ctx->quic->metrics.pkt_oversz_cnt          );
  FD_MCNT_SET(         TXSEND, PKT_VERNEG,                  ctx->quic->metrics.pkt_verneg_cnt          );
  FD_MCNT_ENUM_COPY(   TXSEND, PKT_RETRANSMISSIONS,         ctx->quic->metrics.pkt_retransmissions_cnt );

  FD_MCNT_SET(         TXSEND, HANDSHAKES_CREATED,          ctx->quic->metrics.hs_created_cnt          );
  FD_MCNT_SET(         TXSEND, HANDSHAKE_ERROR_ALLOC_FAIL,  ctx->quic->metrics.hs_err_alloc_fail_cnt   );
  FD_MCNT_SET(         TXSEND, HANDSHAKE_EVICTED,           ctx->quic->metrics.hs_evicted_cnt          );

  FD_MCNT_SET(         TXSEND, FRAME_FAIL_PARSE,            ctx->quic->metrics.frame_rx_err_cnt        );

  FD_MHIST_COPY(       TXSEND, SERVICE_DURATION_SECONDS,    ctx->quic->metrics.service_duration        );
  FD_MHIST_COPY(       TXSEND, RECEIVE_DURATION_SECONDS,    ctx->quic->metrics.receive_duration        );
}

static void
quic_tls_cv_sign( void *      signer_ctx,
                  uchar       signature[ static 64 ],
                  uchar const payload[ static 130 ] ) {
  fd_txsend_tile_t * ctx = signer_ctx;

  fd_keyguard_client_sign( ctx->keyguard_client, signature, payload, 130UL, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

static void
send_to_net( fd_txsend_tile_t *   ctx,
             fd_ip4_hdr_t const * ip4_hdr,
             fd_udp_hdr_t const * udp_hdr,
             uchar        const * payload,
             ulong                payload_sz,
             long                 now ) {
  uint  const ip_dst = FD_LOAD( uint, ip4_hdr->daddr_c );
  ulong const ip_sz  = FD_IP4_GET_LEN( *ip4_hdr );

  fd_txsend_out_t * net_out_link = ctx->net_out;
  uchar * packet_l2 = fd_chunk_to_laddr( net_out_link->mem, net_out_link->chunk );
  uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
  uchar * packet_l4 = packet_l3 + ip_sz;
  uchar * packet_l5 = packet_l4 + sizeof(fd_udp_hdr_t);

  fd_memcpy( packet_l2, ctx->packet_hdr->eth, sizeof(fd_eth_hdr_t) );
  fd_memcpy( packet_l3, ip4_hdr,              ip_sz                );
  fd_memcpy( packet_l4, udp_hdr,              sizeof(fd_udp_hdr_t) );
  fd_memcpy( packet_l5, payload,              payload_sz           );

  ulong sig   = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
  ulong sz_l2 = sizeof(fd_eth_hdr_t) + ip_sz + sizeof(fd_udp_hdr_t) + payload_sz;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( now );
  fd_stem_publish( ctx->stem, net_out_link->idx, sig, net_out_link->chunk, sz_l2, 0UL, 0, tspub );
  net_out_link->chunk = fd_dcache_compact_next( net_out_link->chunk, sz_l2, net_out_link->chunk0, net_out_link->wmark );
}

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush FD_PARAM_UNUSED ) {
  fd_txsend_tile_t * ctx = _ctx;

  long now = fd_log_wallclock();

  for( ulong i=0; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;
    uchar * buf = batch[ i ].buf;
    fd_ip4_hdr_t * ip4_hdr    = fd_type_pun( buf );
    ulong const    ip4_len    = FD_IP4_GET_LEN( *ip4_hdr );
    fd_udp_hdr_t * udp_hdr    = fd_type_pun( buf + ip4_len );
    uchar        * payload    = buf + ip4_len + sizeof(fd_udp_hdr_t);
    FD_TEST( batch[ i ].buf_sz >= ip4_len + sizeof(fd_udp_hdr_t) );
    ulong          payload_sz = batch[ i ].buf_sz - ip4_len - sizeof(fd_udp_hdr_t);
    send_to_net( ctx, ip4_hdr, udp_hdr, payload, payload_sz, now );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           ctx ) {
  fd_txsend_tile_t * tile = ctx;

  for( ulong i=0UL; i<tile->conns_len; i++ ) {
    if( FD_UNLIKELY( tile->conns[ i ].conn==conn ) ) {
      if( FD_UNLIKELY( i!=tile->conns_len-1UL ) ) tile->conns[ i ] = tile->conns[ tile->conns_len-1UL ];
      tile->conns_len--;
      return;
    }
  }

  FD_LOG_ERR(( "unknown connection finalized" ));
}

/* This QUIC servicing is very precarious. Recall a few facts,

    1) QUIC needs to be serviced periodically to make progress
    2) QUIC servicing may produce outgoing packets that need to be sent
       to the network
    3) Elsewhere, the the tile publishes frags to the verify tile to
       send our own votes into our leader pipeline

   You could service QUIC in before_credit, as the QUIC tile does, but
   this has a problem.  If you publish frags in before_credit, you might
   overrun the downstream consumer.  For net tile, this is OK because it
   expects that (as does verify).  But the credit counting mechanism
   doesn't expect this behavior and will underflow.  (That's also not
   ideal, in case some plugin wanted to listen reliably on quic->verify
   they could not, if it got underflowed).  Here though, we want to
   avoid dropping outgoing votes to verify, since they might be needed
   for liveness of a small cluster.

   We thus take the trade of servicing QUIC in after_credit, which means
   it could theoretically get backpressured by verify, however this
   isn't realistic in practice, as verify polls round robin and there's
   only one vote per slot. */

static inline void
after_credit( fd_txsend_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  ctx->stem = stem;

  *charge_busy = fd_quic_service( ctx->quic, fd_log_wallclock() );
  *opt_poll_in = !*charge_busy; /* refetch credits to prevent above documented situation */

  if( FD_UNLIKELY( ctx->leader_schedules<2UL ) ) return;

  fd_pubkey_t const * leaders[ 7UL ];

  for( ulong i=0UL; i<7UL; i++ ) {
    ulong target_slot = ctx->voted_slot+1UL + i*FD_EPOCH_SLOTS_PER_ROTATION;
    leaders[ i ] = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, target_slot );
    FD_TEST( leaders[ i ] );
  }

  /* Disconect any QUIC connection to a leader that does not have a
     rotation coming up in the next 7 slots. */
  for( ulong i=0UL; i<ctx->conns_len; i++ ) {
    int keep_conn = 0;
    for( ulong j=0UL; j<7UL; j++ ) {
      if( fd_pubkey_eq( &ctx->conns[ i ].pubkey, leaders[ j ] ) ) {
        keep_conn = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !keep_conn ) ) fd_quic_conn_close( ctx->conns[ i ].conn, 0U );
  }

  /* Connect to any leader that does not have a connection yet. */
  for( ulong i=0UL; i<7UL; i++ ) {
    fd_pubkey_t const * leader = leaders[ i ];
    peer_entry_t * peer = peer_map_ele_query( ctx->peer_map, leader, NULL, ctx->peers );
    if( FD_UNLIKELY( !peer ) ) continue; /* no contact info */

    for( ulong j=0UL; j<2UL; j++ ) {
      if( FD_UNLIKELY( ctx->conns_len==128UL ) ) break; /* connection limit reached */
      if( FD_UNLIKELY( !peer->quic_ip_addrs[ j ] || !peer->quic_ports[ j ] ) ) continue;

      /* Don't try to reconnect more than once every two seconds ...
         Basically Agave limits us to 8 connections per minute, so if we
         keep trying to reconnect rapidly it's much less effective than
         waiting a little bit to ensure we stay under the threshold.

         We should probably make this a bit more sophisticated, with a
         simple model that considers past connection attempts, and
         future leader slots (e.g. we might still want to burn an
         attempt if a leader slot is imminent, even if we recently tried
         to connect).  For now the dumb logic seems to work well enough. */
      long now = fd_log_wallclock();
      if( FD_UNLIKELY( peer->quic_last_connected[ j ]+2e9L<now ) ) continue;

      fd_quic_conn_t * conn = fd_quic_connect( ctx->quic,
                                               peer->quic_ip_addrs[ j ],
                                               peer->quic_ports[ j ],
                                               ctx->src_ip_addr,
                                               ctx->src_port,
                                               now );
      FD_TEST( conn ); /* never out of connection objects, per above check */
      ctx->conns[ ctx->conns_len ].conn   = conn;
      ctx->conns[ ctx->conns_len ].pubkey = *leader;
      peer->quic_last_connected[ j ] = now;
      ctx->conns_len++;
    }
  }
}

void
send_vote_to_leader( fd_txsend_tile_t *  ctx,
                     fd_pubkey_t const * leader_pubkey,
                     uchar const       * vote_payload,
                     ulong               vote_payload_sz ) {
  peer_entry_t const * peer = peer_map_ele_query_const( ctx->peer_map, leader_pubkey, NULL, ctx->peers );
  if( FD_UNLIKELY( !peer ) ) return; /* no known contact info */

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_UNLIKELY( !peer->udp_ip_addrs[ i ] | !peer->udp_ports[ i ] ) ) continue;

    fd_ip4_hdr_t * ip4_hdr = ctx->packet_hdr->ip4;
    fd_udp_hdr_t * udp_hdr = ctx->packet_hdr->udp;

    ip4_hdr->daddr       = peer->udp_ip_addrs[ i ];
    ip4_hdr->net_tot_len = fd_ushort_bswap( (ushort)(vote_payload_sz+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
    ip4_hdr->net_id      = fd_ushort_bswap( ctx->net_id++ );
    ip4_hdr->check       = fd_ip4_hdr_check_fast( ip4_hdr );

    udp_hdr->net_dport = fd_ushort_bswap( peer->udp_ports[ i ] );
    udp_hdr->net_len   = fd_ushort_bswap( (ushort)( vote_payload_sz+sizeof(fd_udp_hdr_t) ) );
    send_to_net( ctx, ip4_hdr, udp_hdr, vote_payload, vote_payload_sz, fd_log_wallclock() );
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_quic_conn_t * conn = peer->quic_conns[ i ];
    if( FD_UNLIKELY( !conn ) ) continue;

    fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
    if( FD_UNLIKELY( !stream ) ) continue;

    fd_quic_stream_send( stream, vote_payload, vote_payload_sz, 1 );
  }
}

static inline void
handle_contact_info_update( fd_txsend_tile_t *                 ctx,
                            fd_gossip_update_message_t const * msg ) {
  peer_entry_t * entry = &ctx->peers[ msg->contact_info->idx ];
  if( FD_UNLIKELY( entry->tombstoned ) ) {
    FD_TEST( peer_map_ele_remove( ctx->peer_map, &entry->pubkey, NULL, ctx->peers ) );
    entry->quic_last_connected[ 0 ] = 0L;
    entry->quic_last_connected[ 1 ] = 0L;
    for( ulong i=0UL; i<2UL; i++ ) {
      entry->quic_ip_addrs[ i ] = 0U;
      entry->quic_ports   [ i ] = 0U;
      entry->udp_ip_addrs [ i ] = 0U;
      entry->udp_ports    [ i ] = 0U;
    }
  }

  entry->tombstoned = 0;
  fd_memcpy( entry->pubkey.uc, msg->origin, 32UL );

  static ulong const quic_socket_idx[ 2UL ] = {
    FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC,
    FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_QUIC,
  };

  static ulong const udp_socket_idx[ 2UL ] = {
    FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE,
    FD_GOSSIP_CONTACT_INFO_SOCKET_TPU,
  };

  /* If an IP address or port is updated via. gossip to be 0, it's no
     longer reachable and we just ignore the update, since there's a
     chance the old one is still valid. */

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_LIKELY( !msg->contact_info->value->sockets[ quic_socket_idx[ i ] ].is_ipv6 && msg->contact_info->value->sockets[ quic_socket_idx[ i ] ].ip4 ) ) {
      entry->quic_ip_addrs[ i ] = msg->contact_info->value->sockets[ quic_socket_idx[ i ] ].ip4;
    }
    if( FD_LIKELY( fd_ushort_bswap( msg->contact_info->value->sockets[ quic_socket_idx[ i ] ].port ) ) ) {
      entry->quic_ports   [ i ] = fd_ushort_bswap( msg->contact_info->value->sockets[ quic_socket_idx[ i ] ].port );
    }
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_LIKELY( !msg->contact_info->value->sockets[ udp_socket_idx[ i ] ].is_ipv6 && msg->contact_info->value->sockets[ udp_socket_idx[ i ] ].ip4 ) ) {
      entry->udp_ip_addrs[ i ] = msg->contact_info->value->sockets[ udp_socket_idx[ i ] ].ip4;
    }
    if( FD_LIKELY( fd_ushort_bswap( msg->contact_info->value->sockets[ udp_socket_idx[ i ] ].port ) ) ) {
      entry->udp_ports   [ i ] = fd_ushort_bswap( msg->contact_info->value->sockets[ udp_socket_idx[ i ] ].port );
    }
  }

  FD_TEST( peer_map_ele_insert( ctx->peer_map, entry, ctx->peers ) );
}

static inline void
handle_contact_info_remove( fd_txsend_tile_t *                 ctx,
                            fd_gossip_update_message_t const * msg ) {
  peer_entry_t * entry = &ctx->peers[ msg->contact_info->idx ];
  entry->tombstoned = 1;
}

static void
handle_vote_msg( fd_txsend_tile_t *           ctx,
                 fd_stem_context_t *          stem,
                 fd_tower_slot_done_t const * slot_done ) {
  if( FD_UNLIKELY( slot_done->vote_slot==ULONG_MAX ) ) return;
  if( FD_UNLIKELY( !slot_done->has_vote_txn ) ) return;

  ctx->voted_slot = slot_done->vote_slot;

  fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->txsend_out->mem, ctx->txsend_out->chunk );
  FD_TEST( slot_done->vote_txn_sz<=FD_TXN_MTU );
  txnm->payload_sz             = (ushort)slot_done->vote_txn_sz;
  txnm->source_ipv4            = ctx->src_ip_addr;
  txnm->source_tpu             = FD_TXN_M_TPU_SOURCE_TXSEND;
  txnm->block_engine.bundle_id = 0UL;
  fd_memcpy( fd_txn_m_payload( txnm ), slot_done->vote_txn, slot_done->vote_txn_sz );

  txnm->txn_t_sz = (ushort)fd_txn_parse( slot_done->vote_txn, slot_done->vote_txn_sz, fd_txn_m_txn_t( txnm ), NULL );
  FD_TEST( txnm->txn_t_sz );

  uchar * payload = fd_txn_m_payload( txnm );
  fd_txn_t const * txn = fd_txn_m_txn_t_const( txnm );

  uchar *       signatures = payload + txn->signature_off;
  uchar const * message    = payload + txn->message_off;
  ulong         message_sz = slot_done->vote_txn_sz - txn->message_off;
  fd_keyguard_client_vote_txn_sign( ctx->keyguard_client, signatures, slot_done->authority_idx, message, message_sz );

  for( ulong i=0UL; i<3UL; i++ ) {
    ulong target_slot = slot_done->vote_slot+1UL + i*FD_EPOCH_SLOTS_PER_ROTATION;
    fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, target_slot );
    FD_TEST( leader );
    send_vote_to_leader( ctx, leader, payload, slot_done->vote_txn_sz );
  }

  ulong msg_sz = fd_txn_m_realized_footprint( txnm, 0, 0 );
  fd_stem_publish( stem, ctx->txsend_out->idx, 1UL, ctx->txsend_out->chunk, msg_sz, 0UL, 0, 0 );
  ctx->txsend_out->chunk = fd_dcache_compact_next( ctx->txsend_out->chunk, msg_sz, ctx->txsend_out->chunk0, ctx->txsend_out->wmark );
}


static inline int
before_frag( fd_txsend_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig ) {
  (void)seq;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_TOWER ) ) {
    return sig!=FD_TOWER_SIG_SLOT_DONE;
  }

  return 0;
}

static void
during_frag( fd_txsend_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig,
             ulong              chunk,
             ulong              sz,
             ulong              ctl ) {
  (void)seq; (void)sig;

  ctx->chunk = chunk;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EPOCH ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark, ctx->in[ in_idx ].mtu ));

    fd_epoch_info_msg_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    FD_TEST( msg->staked_cnt<=40200UL ); /* implicit sz verification since sz field on frag_meta too small */
  } else {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark, ctx->in[ in_idx ].mtu ));
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz );
    fd_memcpy( ctx->quic_buf, src, sz );
  }
}

static void
after_frag( fd_txsend_tile_t *  ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)tsorig; (void)tspub;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    uchar * ip_packet = ctx->quic_buf+sizeof(fd_eth_hdr_t);
    ulong ip_packet_sz = sz-sizeof(fd_eth_hdr_t);
    fd_quic_process_packet( ctx->quic, ip_packet, ip_packet_sz, fd_log_wallclock() );
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) ) handle_contact_info_update( ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk ) );
    else                                                      handle_contact_info_remove( ctx, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk ) );
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_TOWER ) ) {
    handle_vote_msg( ctx, stem, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk ) );
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EPOCH ) ) {
    fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk ) );
    fd_multi_epoch_leaders_stake_msg_fini( ctx->mleaders );
    ctx->leader_schedules++;
  } else {
    FD_LOG_ERR(( "unknown in_kind %d on link %lu", ctx->in_kind[ in_idx ], in_idx ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_txsend_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txsend_tile_t), sizeof(fd_txsend_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->txsend.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->txsend.identity_key_path, /* pubkey only: */ 1 ) );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );
}

static inline fd_txsend_out_t
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

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_txsend_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_txsend_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txsend_tile_t),  sizeof(fd_txsend_tile_t) );
  void * _quic           = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),            fd_quic_footprint( &quic_limits ) );
  void * _peer_map       = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),           peer_map_footprint( 2UL*FD_CONTACT_INFO_TABLE_SIZE ) );

  ctx->quic = fd_quic_join( fd_quic_new( _quic, &quic_limits ) );
  FD_TEST( ctx->quic );

  ctx->leader_schedules = 0UL;

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  ctx->peer_map = peer_map_join( peer_map_new( _peer_map, 2UL*FD_CONTACT_INFO_TABLE_SIZE, ctx->seed ) );
  FD_TEST( ctx->peer_map );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
  FD_TEST( quic_tx_aio );
  fd_quic_set_aio_net_tx( ctx->quic, quic_tx_aio );

  ctx->quic->config.role         = FD_QUIC_ROLE_CLIENT;
  ctx->quic->config.idle_timeout = 30e9L;
  ctx->quic->config.ack_delay    = 25e6L;
  ctx->quic->config.keep_alive   = 1;
  ctx->quic->config.sign         = quic_tls_cv_sign;
  ctx->quic->config.sign_ctx     = ctx;
  fd_memcpy( ctx->quic->config.identity_public_key, ctx->identity_key, sizeof(ctx->identity_key) );

  ctx->quic->cb.conn_final       = quic_conn_final;
  ctx->quic->cb.quic_ctx         = ctx;

  FD_TEST( fd_quic_init( ctx->quic ));

  for( ulong i=0UL; i<FD_CONTACT_INFO_TABLE_SIZE; i++ ) {
    ctx->peers[ i ].tombstoned = 0;
    for( ulong j=0UL; j<2UL; j++ ) {
      ctx->peers[ i ].quic_ip_addrs[ j ] = 0;
      ctx->peers[ i ].quic_ports   [ j ] = 0;
      ctx->peers[ i ].udp_ip_addrs [ j ] = 0;
      ctx->peers[ i ].udp_ports    [ j ] = 0;
      ctx->peers[ i ].quic_last_connected[ j ] = 0L;
    }
  }

  ctx->voted_slot = ULONG_MAX;

  ctx->src_ip_addr = tile->txsend.ip_addr;
  ctx->src_port    = tile->txsend.txsend_src_port;
  fd_ip4_udp_hdr_init( ctx->packet_hdr, FD_TXN_MTU, ctx->src_ip_addr, ctx->src_port );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if( !strcmp( link->name, "net_txsend"   ) ) {
      fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
      ctx->in_kind[ i ] = IN_KIND_NET;
    } else if( !strcmp( link->name, "gossip_out" ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( !strcmp( link->name, "replay_epoch" ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( !strcmp( link->name, "tower_out"    ) ) ctx->in_kind[ i ] = IN_KIND_TOWER;
    else if( !strcmp( link->name, "sign_txsend"  ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  *ctx->txsend_out = out1( topo, tile, "txsend_out" );;
  *ctx->net_out    = out1( topo, tile, "txsend_net" );;

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_txsend", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "txsend_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
          sign_out->mcache,
          sign_out->dcache,
          sign_in->mcache,
          sign_in->dcache,
          sign_out->mtu ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard" ));
  }

  fd_histf_join( fd_histf_new( ctx->quic->metrics.service_duration, FD_MHIST_SECONDS_MIN( TXSEND, SERVICE_DURATION_SECONDS ),
                                                                    FD_MHIST_SECONDS_MAX( TXSEND, SERVICE_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->quic->metrics.receive_duration, FD_MHIST_SECONDS_MIN( TXSEND, RECEIVE_DURATION_SECONDS ),
                                                                    FD_MHIST_SECONDS_MAX( TXSEND, RECEIVE_DURATION_SECONDS ) ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t      const * topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter   * out ) {

  populate_sock_filter_policy_fd_txsend_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_txsend_tile_instr_cnt;
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

#define STEM_BURST 1UL
#define STEM_LAZY  (10e3L) /* 10us */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_txsend_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_txsend_tile_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_txsend = {
  .name                     = "txsend",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
