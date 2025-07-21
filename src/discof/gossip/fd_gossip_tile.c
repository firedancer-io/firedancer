/* Gossip tile runs the gossip networking protcol for a Firedancer node. */
#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"
#include "generated/fd_gossip_tile_seccomp.h"

#include "../../disco/fd_disco.h"
#include "../../disco/fd_txn_m_t.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../util/net/fd_net_headers.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define CONTACT_INFO_PUBLISH_TIME_NS ((long)5e9)
#define PLUGIN_PUBLISH_TIME_NS ((long)30e9)

#define IN_KIND_NET     (1)
#define IN_KIND_SEND    (2)
#define IN_KIND_SIGN    (4)
#define MAX_IN_LINKS    (8)

static volatile ulong * fd_shred_version;

static ulong
fd_pubkey_hash( fd_pubkey_t const * key, ulong seed ) {
  return fd_hash( seed, key->key, sizeof(fd_pubkey_t) );
}

struct fd_contact_info_elem {
  fd_pubkey_t key;
  ulong next;
  fd_contact_info_t contact_info;
};
typedef struct fd_contact_info_elem fd_contact_info_elem_t;

/* Contact info table */
#define MAP_NAME     fd_contact_info_table
#define MAP_KEY_T    fd_pubkey_t
#define MAP_KEY_EQ   fd_pubkey_eq
#define MAP_KEY_HASH fd_pubkey_hash
#define MAP_T        fd_contact_info_elem_t
#include "../../util/tmpl/fd_map_giant.c"

struct fd_gossip_tile_metrics {
  ulong last_crds_push_contact_info_publish_ts;
  ulong mismatched_contact_info_shred_version;

  /* Below metrics are segmented by TVU, Repair, Send */
  ulong ipv6_contact_info[FD_METRICS_COUNTER_GOSSIP_IPV6_CONTACT_INFO_CNT];
  ulong zero_ipv4_contact_info[FD_METRICS_COUNTER_GOSSIP_ZERO_IPV4_CONTACT_INFO_CNT];
  ulong peer_counts[FD_METRICS_GAUGE_GOSSIP_PEER_COUNTS_CNT];

  ulong shred_version_zero;
};
typedef struct fd_gossip_tile_metrics fd_gossip_tile_metrics_t;
#define FD_GOSSIP_TILE_METRICS_FOOTPRINT ( sizeof( fd_gossip_tile_metrics_t ) )

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
} fd_gossip_in_ctx_t;

struct fd_gossip_tile_ctx {
  fd_gossip_t * gossip;
  fd_gossip_config_t gossip_config;
  long last_shred_dest_push_time;
  long last_plugin_push_time;

  ulong gossip_seed;

  uchar              in_kind[ MAX_IN_LINKS ];
  fd_gossip_in_ctx_t in_links[ MAX_IN_LINKS ];

  fd_contact_info_elem_t * contact_info_table;

  fd_frag_meta_t * shred_contact_out_mcache;
  ulong *          shred_contact_out_sync;
  ulong            shred_contact_out_depth;
  ulong            shred_contact_out_seq;

  fd_wksp_t * shred_contact_out_mem;
  ulong       shred_contact_out_chunk0;
  ulong       shred_contact_out_wmark;
  ulong       shred_contact_out_chunk;

  fd_frag_meta_t * repair_contact_out_mcache;
  ulong *          repair_contact_out_sync;
  ulong            repair_contact_out_depth;
  ulong            repair_contact_out_seq;

  fd_wksp_t * repair_contact_out_mem;
  ulong       repair_contact_out_chunk0;
  ulong       repair_contact_out_wmark;
  ulong       repair_contact_out_chunk;

  fd_frag_meta_t * send_contact_out_mcache;
  ulong *          send_contact_out_sync;
  ulong            send_contact_out_depth;
  ulong            send_contact_out_seq;

  fd_wksp_t * send_contact_out_mem;
  ulong       send_contact_out_chunk0;
  ulong       send_contact_out_wmark;
  ulong       send_contact_out_chunk;
  ulong       send_contact_out_idx;

  fd_frag_meta_t * verify_out_mcache;
  ulong *          verify_out_sync;
  ulong            verify_out_depth;
  ulong            verify_out_seq;

  fd_wksp_t * verify_out_mem;
  ulong       verify_out_chunk0;
  ulong       verify_out_wmark;
  ulong       verify_out_chunk;

  ulong       tower_out_idx;
  fd_wksp_t * tower_out_mem;
  ulong       tower_out_chunk0;
  ulong       tower_out_wmark;
  ulong       tower_out_chunk;

  fd_wksp_t *           wksp;
  fd_gossip_peer_addr_t gossip_my_addr;
  fd_gossip_peer_addr_t tvu_my_addr;
  fd_gossip_peer_addr_t tpu_my_addr;
  fd_gossip_peer_addr_t tpu_quic_my_addr;
  fd_gossip_peer_addr_t tpu_vote_my_addr;
  fd_gossip_peer_addr_t repair_serve_addr;
  ushort                gossip_listen_port;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  // Inputs to plugin/gui

  fd_wksp_t * gossip_plugin_out_mem;
  ulong       gossip_plugin_out_chunk0;
  ulong       gossip_plugin_out_wmark;
  ulong       gossip_plugin_out_chunk;
  ulong       gossip_plugin_out_idx;

  uchar         identity_private_key[32];
  fd_pubkey_t   identity_public_key;

  /* Includes Ethernet, IP, UDP headers */
  uchar gossip_buffer[ FD_NET_MTU ];

  ushort net_id;
  fd_ip4_udp_hdrs_t hdr[1];

  fd_keyguard_client_t  keyguard_client[1];

  fd_stem_context_t * stem;

  ulong replay_vote_txn_sz;
  uchar replay_vote_txn [ FD_TXN_MTU ];

  /* Metrics */
  fd_gossip_tile_metrics_t metrics;
};
typedef struct fd_gossip_tile_ctx fd_gossip_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_gossip_align(), fd_gossip_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_contact_info_table_align(), fd_contact_info_table_footprint( FD_PEER_KEY_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
send_packet( fd_gossip_tile_ctx_t * ctx,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uchar const *          payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *ctx->hdr;

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr       = dst_ip_addr;
  ip4->net_id      = fd_ushort_bswap( ctx->net_id++ );
  ip4->check       = 0U;
  ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  ip4->check       = fd_ip4_hdr_check_fast( ip4 );

  fd_udp_hdr_t * udp = hdr->udp;
  udp->net_dport = dst_port;
  udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );
  udp->check = 0U;

  ulong tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig       = fd_disco_netmux_sig( dst_ip_addr, dst_port, dst_ip_addr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);
  fd_stem_publish( ctx->stem, 0UL, sig, ctx->net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void
gossip_send_packet( uchar const * msg,
                    size_t msglen,
                    fd_gossip_peer_addr_t const * addr,
                    void * arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, addr->addr, addr->port, msg, msglen, tsorig );
}

static void
gossip_deliver_fun( fd_crds_data_t * data,
                    void *           arg ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)arg;

  if( fd_crds_data_is_vote( data ) ) {
    if( FD_UNLIKELY( !ctx->verify_out_mcache ) ) return;

    fd_gossip_vote_t const * gossip_vote = &data->inner.vote;

    uchar * vote_txn_msg = fd_chunk_to_laddr( ctx->verify_out_mem, ctx->verify_out_chunk );
    ulong vote_txn_sz    = gossip_vote->txn.raw_sz;

    fd_contact_info_elem_t * ele = fd_contact_info_table_query( ctx->contact_info_table, &gossip_vote->from, NULL );

    fd_txn_m_t * txnm = (fd_txn_m_t *)vote_txn_msg;
    *txnm = (fd_txn_m_t) { 0UL };
    txnm->payload_sz = (ushort)vote_txn_sz,
    txnm->source_ipv4 = (ele && !fd_gossip_ip_addr_is_ip4( &ele->contact_info.addrs[ 0UL ] )) ? ele->contact_info.addrs[ 0UL ].inner.ip4 /* contact_info: gossip protocol address */ : 0U,
    txnm->source_tpu  = FD_TXN_M_TPU_SOURCE_GOSSIP;
    memcpy( vote_txn_msg + sizeof(fd_txn_m_t), gossip_vote->txn.raw, vote_txn_sz );

    ulong sig = 1UL;
    fd_mcache_publish( ctx->verify_out_mcache, ctx->verify_out_depth, ctx->verify_out_seq, sig, ctx->verify_out_chunk,
      fd_txn_m_realized_footprint( txnm, 0, 0 ), 0UL, 0, 0 );
    ctx->verify_out_seq   = fd_seq_inc( ctx->verify_out_seq, 1UL );
    ctx->verify_out_chunk = fd_dcache_compact_next( ctx->verify_out_chunk, vote_txn_sz, ctx->verify_out_chunk0, ctx->verify_out_wmark );

  } else if( fd_crds_data_is_contact_info_v2( data ) ) {
    fd_gossip_contact_info_v2_t const * contact_info_v2 = &data->inner.contact_info_v2;

    fd_contact_info_elem_t * ele = fd_contact_info_table_query( ctx->contact_info_table, &contact_info_v2->from, NULL );

    if( FD_UNLIKELY( !ele &&
                     !fd_contact_info_table_is_full( ctx->contact_info_table ) ) ) {
      ele = fd_contact_info_table_insert( ctx->contact_info_table, &contact_info_v2->from);
      fd_contact_info_init( &ele->contact_info );
    }

    if( FD_LIKELY( ele ) ) {
      fd_contact_info_from_ci_v2( contact_info_v2, &ele->contact_info );
    }

  } else if( fd_crds_data_is_duplicate_shred( data ) ) {

    fd_gossip_duplicate_shred_t const * duplicate_shred = &data->inner.duplicate_shred;
    uchar * chunk_laddr = fd_chunk_to_laddr( ctx->tower_out_mem, ctx->tower_out_chunk );
    memcpy( chunk_laddr, duplicate_shred, sizeof(fd_gossip_duplicate_shred_t) );
    memcpy( chunk_laddr + sizeof(fd_gossip_duplicate_shred_t), duplicate_shred->chunk, duplicate_shred->chunk_len );
    fd_stem_publish( ctx->stem, ctx->tower_out_idx, data->discriminant, ctx->tower_out_chunk, sizeof(fd_gossip_duplicate_shred_t) + duplicate_shred->chunk_len, 0UL, 0, 0 /* FIXME gossip tile needs to plumb through ts. this callback API is not ideal. */ );

  }
}

static void
gossip_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len,
               int           sign_type ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, signature, buffer, len, sign_type );
}

static void
during_housekeeping( fd_gossip_tile_ctx_t * ctx ) {
  fd_gossip_settime( ctx->gossip, fd_log_wallclock() );
}

static inline int
before_frag( fd_gossip_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  return in_kind != IN_KIND_SEND && fd_disco_netmux_sig_proto( sig ) != DST_PROTO_GOSSIP;
}

static inline void
during_frag( fd_gossip_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {

  uint in_kind = ctx->in_kind[ in_idx ];
  fd_gossip_in_ctx_t const * in_ctx = &ctx->in_links[ in_idx ];

  if( in_kind == IN_KIND_SEND ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>FD_TXN_MTU ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }

    ctx->replay_vote_txn_sz = sz;
    memcpy( ctx->replay_vote_txn, fd_chunk_to_laddr( in_ctx->mem, chunk ), sz );
    return;
  }

  if( in_kind!=IN_KIND_NET ) return;

  void const * src = fd_net_rx_translate_frag( &ctx->in_links[ in_idx ].net_rx, chunk, ctl, sz );
  fd_memcpy( ctx->gossip_buffer, src, sz );
}

static void
after_frag( fd_gossip_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq    FD_PARAM_UNUSED,
            ulong                  sig    FD_PARAM_UNUSED,
            ulong                  sz,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *    stem ) {
  uint in_kind = ctx->in_kind[ in_idx ];

  if( in_kind==IN_KIND_SEND ) {
    fd_crds_data_t vote_txn_crds;
    vote_txn_crds.discriminant          = fd_crds_data_enum_vote;
    vote_txn_crds.inner.vote.txn.raw_sz = ctx->replay_vote_txn_sz;
    memcpy( vote_txn_crds.inner.vote.txn.raw, ctx->replay_vote_txn, ctx->replay_vote_txn_sz );
    fd_txn_parse( vote_txn_crds.inner.vote.txn.raw, ctx->replay_vote_txn_sz, vote_txn_crds.inner.vote.txn.txn_buf, NULL );

    fd_gossip_push_value( ctx->gossip, &vote_txn_crds, NULL );

    static ulong sent_vote_cnt = 0;
    if ( ( ++sent_vote_cnt % 50 ) == 0 )
      FD_LOG_NOTICE(( "Gossip tile has sent %lu vote txns", sent_vote_cnt ));

    return;
  }

  if( in_kind!=IN_KIND_NET ) return;

  if( FD_UNLIKELY( sz<42 ) ) return;

  ctx->stem = stem;
  fd_eth_hdr_t const * eth  = (fd_eth_hdr_t const *)ctx->gossip_buffer;
  fd_ip4_hdr_t const * ip4  = (fd_ip4_hdr_t const *)( (ulong)eth + sizeof(fd_eth_hdr_t) );
  fd_udp_hdr_t const * udp  = (fd_udp_hdr_t const *)( (ulong)ip4 + FD_IP4_GET_LEN( *ip4 ) );
  uchar const *        data = (uchar        const *)( (ulong)udp + sizeof(fd_udp_hdr_t) );
  if( FD_UNLIKELY( (ulong)udp+sizeof(fd_udp_hdr_t) > (ulong)eth+sz ) ) return;
  ulong udp_sz = fd_ushort_bswap( udp->net_len );
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) ) ) return;
  ulong data_sz = udp_sz-sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( (ulong)data+data_sz > (ulong)eth+sz ) ) return;

  fd_gossip_peer_addr_t peer_addr = { .addr=ip4->saddr, .port=udp->net_sport };
  fd_gossip_recv_packet( ctx->gossip, data, data_sz, &peer_addr );
}

static void
publish_peers_to_plugin( fd_gossip_tile_ctx_t * ctx,
                         fd_stem_context_t *    stem ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->gossip_plugin_out_mem, ctx->gossip_plugin_out_chunk );

  ulong i = 0;
  for( fd_contact_info_table_iter_t iter = fd_contact_info_table_iter_init( ctx->contact_info_table );
       !fd_contact_info_table_iter_done( ctx->contact_info_table, iter ) && i < FD_CLUSTER_NODE_CNT;
       iter = fd_contact_info_table_iter_next( ctx->contact_info_table, iter ), ++i ) {
    fd_contact_info_elem_t const * ele = fd_contact_info_table_iter_ele_const( ctx->contact_info_table, iter );
    fd_gossip_update_msg_t * msg = (fd_gossip_update_msg_t *)(dst + sizeof(ulong) + i*FD_GOSSIP_LINK_MSG_SIZE);
    fd_contact_info_to_update_msg( &ele->contact_info, msg );
  }

  *(ulong *)dst = i;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->gossip_plugin_out_idx, FD_PLUGIN_MSG_GOSSIP_UPDATE, ctx->gossip_plugin_out_chunk, 0, 0UL, 0UL, tspub );
  ctx->gossip_plugin_out_chunk = fd_dcache_compact_next( ctx->gossip_plugin_out_chunk, 8UL + 40200UL*(58UL+12UL*34UL), ctx->gossip_plugin_out_chunk0, ctx->gossip_plugin_out_wmark );
}

static void
after_credit( fd_gossip_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in,
              int *                  charge_busy ) {
  (void)opt_poll_in;

  /* TODO: Don't charge the tile as busy if after_credit isn't actually
     doing any work. */
  *charge_busy = 1;

  ctx->stem = stem;
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  if( FD_LIKELY( ctx->shred_contact_out_sync  ) ) fd_mcache_seq_update( ctx->shred_contact_out_sync, ctx->shred_contact_out_seq );
  if( FD_LIKELY( ctx->repair_contact_out_sync ) ) fd_mcache_seq_update( ctx->repair_contact_out_sync, ctx->repair_contact_out_seq );

  long now = fd_gossip_gettime( ctx->gossip );
  if( ( now - ctx->last_shred_dest_push_time )>CONTACT_INFO_PUBLISH_TIME_NS &&
      ctx->shred_contact_out_mcache ) {

    ctx->metrics.last_crds_push_contact_info_publish_ts = (ulong)(ctx->last_shred_dest_push_time);

    ctx->last_shred_dest_push_time = now;

    ulong tvu_peer_cnt = 0;
    ulong repair_peers_cnt = 0;
    ulong send_peers_cnt = 0;

    ulong * shred_dest_msg = fd_chunk_to_laddr( ctx->shred_contact_out_mem, ctx->shred_contact_out_chunk );
    fd_shred_dest_wire_t * tvu_peers = (fd_shred_dest_wire_t *)(shred_dest_msg+1);
    fd_shred_dest_wire_t * repair_peers = fd_chunk_to_laddr( ctx->repair_contact_out_mem, ctx->repair_contact_out_chunk );
    fd_shred_dest_wire_t * send_peers = fd_chunk_to_laddr( ctx->send_contact_out_mem, ctx->send_contact_out_chunk );
    for( fd_contact_info_table_iter_t iter = fd_contact_info_table_iter_init( ctx->contact_info_table );
         !fd_contact_info_table_iter_done( ctx->contact_info_table, iter );
         iter = fd_contact_info_table_iter_next( ctx->contact_info_table, iter ) ) {
      fd_contact_info_elem_t const * ele = fd_contact_info_table_iter_ele_const( ctx->contact_info_table, iter );
      fd_contact_info_t const * ci = &ele->contact_info;

      if( fd_contact_info_get_shred_version( ci )!=fd_gossip_get_shred_version( ctx->gossip ) ) {
        ctx->metrics.mismatched_contact_info_shred_version += 1UL;
        continue;
      }

      {
        ushort tvu_socket_idx = ci->socket_tag_idx[ FD_GOSSIP_SOCKET_TAG_TVU ];
        if( tvu_socket_idx == FD_CONTACT_INFO_SOCKET_TAG_NULL ) {
          ctx->metrics.zero_ipv4_contact_info[ FD_METRICS_ENUM_PEER_TYPES_V_TVU_IDX ] += 1UL;
          continue;
        }
        if( !fd_gossip_ip_addr_is_ip4( &ci->addrs[ ci->sockets[ tvu_socket_idx].index ] )) {
          continue;
        }


        tvu_peers[tvu_peer_cnt].ip4_addr = ci->addrs[ ci->sockets[ tvu_socket_idx].index ].inner.ip4;
        tvu_peers[tvu_peer_cnt].udp_port = ci->ports[ tvu_socket_idx ]; /* NOT converted to net order */
        memcpy( tvu_peers[tvu_peer_cnt].pubkey, &ci->ci_crd.from, sizeof(fd_pubkey_t) );

        tvu_peer_cnt++;
      }

      {
        ushort repair_socket_idx = ci->socket_tag_idx[ FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR ];
        if( repair_socket_idx == FD_CONTACT_INFO_SOCKET_TAG_NULL ) {
          ctx->metrics.zero_ipv4_contact_info[ FD_METRICS_ENUM_PEER_TYPES_V_REPAIR_IDX ] += 1UL;
          continue;
        }
        if( !fd_gossip_ip_addr_is_ip4( &ci->addrs[ ci->sockets[ repair_socket_idx].index ] )) {
          continue;
        }

        repair_peers[repair_peers_cnt].ip4_addr = ci->addrs[ ci->sockets[ repair_socket_idx].index ].inner.ip4;
        repair_peers[repair_peers_cnt].udp_port = ci->ports[ repair_socket_idx ]; /* NOT converted to net order */
        memcpy( repair_peers[repair_peers_cnt].pubkey, &ci->ci_crd.from, sizeof(fd_pubkey_t) );

        repair_peers_cnt++;
      }

      {
        ushort sender_socket_idx = ci->socket_tag_idx[ FD_GOSSIP_SOCKET_TAG_TPU_QUIC ];
        if( sender_socket_idx == FD_CONTACT_INFO_SOCKET_TAG_NULL ) {
          ctx->metrics.zero_ipv4_contact_info[ FD_METRICS_ENUM_PEER_TYPES_V_SEND_IDX ] += 1UL;
          continue;
        }
        if( !fd_gossip_ip_addr_is_ip4( &ci->addrs[ ci->sockets[ sender_socket_idx].index ] )) {
          continue;
        }

        send_peers[send_peers_cnt].ip4_addr = ci->addrs[ ci->sockets[ sender_socket_idx ].index ].inner.ip4;
        send_peers[send_peers_cnt].udp_port = ci->ports[ sender_socket_idx ]; /* NOT converted to net order */
        memcpy( send_peers[send_peers_cnt].pubkey, &ci->ci_crd.from, sizeof(fd_pubkey_t) );

        send_peers_cnt++;
      }
    }

#define UPDATE_PEER_CNTS( _peer_cnt_, _peer_type_ ) \
  ctx->metrics.peer_counts[ FD_METRICS_ENUM_PEER_TYPES_V_ ##_peer_type_ ##_IDX ] = _peer_cnt_;

    UPDATE_PEER_CNTS( tvu_peer_cnt, TVU );
    UPDATE_PEER_CNTS( repair_peers_cnt, REPAIR );
    UPDATE_PEER_CNTS( send_peers_cnt, SEND );

#undef UPDATE_PEER_CNTS

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

    FD_LOG_INFO(( "publishing peers - tvu: %lu, repair: %lu, tpu_vote: %lu", tvu_peer_cnt, repair_peers_cnt, send_peers_cnt ));
    if( tvu_peer_cnt>0 && ctx->shred_contact_out_mcache ) {
      *shred_dest_msg         = tvu_peer_cnt;
      ulong shred_contact_sz  = sizeof(ulong) + (tvu_peer_cnt * sizeof(fd_shred_dest_wire_t));
      ulong shred_contact_sig = 2UL;
      fd_mcache_publish( ctx->shred_contact_out_mcache, ctx->shred_contact_out_depth, ctx->shred_contact_out_seq, shred_contact_sig, ctx->shred_contact_out_chunk,
        shred_contact_sz, 0UL, tsorig, tspub );
      ctx->shred_contact_out_seq   = fd_seq_inc( ctx->shred_contact_out_seq, 1UL );
      ctx->shred_contact_out_chunk = fd_dcache_compact_next( ctx->shred_contact_out_chunk, shred_contact_sz, ctx->shred_contact_out_chunk0, ctx->shred_contact_out_wmark );
    }

    if( repair_peers_cnt>0 && ctx->repair_contact_out_mcache ) {
      ulong repair_contact_sz  = (repair_peers_cnt * sizeof(fd_shred_dest_wire_t));
      ulong repair_contact_sig = 3UL;
      fd_mcache_publish( ctx->repair_contact_out_mcache, ctx->repair_contact_out_depth, ctx->repair_contact_out_seq, repair_contact_sig, ctx->repair_contact_out_chunk,
        repair_peers_cnt, 0UL, tsorig, tspub );
      ctx->repair_contact_out_seq   = fd_seq_inc( ctx->repair_contact_out_seq, 1UL );
      ctx->repair_contact_out_chunk = fd_dcache_compact_next( ctx->repair_contact_out_chunk, repair_contact_sz, ctx->repair_contact_out_chunk0, ctx->repair_contact_out_wmark );
    }

    if( send_peers_cnt>0 && ctx->send_contact_out_mcache ) {
      while( send_peers_cnt ) {
        ulong send_batch_cnt   = fd_ulong_min( send_peers_cnt, 1500UL );
        /* */ send_peers_cnt  -= send_batch_cnt;
        ulong send_contact_sz  = (send_batch_cnt * sizeof(fd_shred_dest_wire_t));
        ulong send_contact_sig = 4UL;

        fd_stem_publish( ctx->stem, ctx->send_contact_out_idx, send_contact_sig, ctx->send_contact_out_chunk,
          send_contact_sz, 0UL, 0, tspub );
        ctx->send_contact_out_chunk = fd_dcache_compact_next( ctx->send_contact_out_chunk, send_contact_sz, ctx->send_contact_out_chunk0, ctx->send_contact_out_wmark );
      }
    }
  }

  if( ctx->gossip_plugin_out_mem && FD_UNLIKELY( ( now - ctx->last_plugin_push_time )>PLUGIN_PUBLISH_TIME_NS ) ) {
    ctx->last_plugin_push_time = now;
    publish_peers_to_plugin( ctx, stem );
  }

  ushort shred_version = fd_gossip_get_shred_version( ctx->gossip );
  if( shred_version!=0U ) {
    *fd_shred_version = shred_version;
  } else {
    ctx->metrics.shred_version_zero += 1UL;
  }
  fd_gossip_continue( ctx->gossip );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_gossip_tile_ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->gossip.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key.uc, identity_key, sizeof(fd_pubkey_t) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->gossip_seed, sizeof(ulong), 0 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( !tile->out_cnt ) ) FD_LOG_ERR(( "gossip tile has no primary output link" ));

  if( FD_UNLIKELY( !tile->gossip.ip_addr ) ) FD_LOG_ERR(( "gossip ip address not set" ));
  if( FD_UNLIKELY( !tile->gossip.gossip_listen_port ) ) FD_LOG_ERR(( "gossip listen port not set" ));

  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  ctx->gossip = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_align(), fd_gossip_footprint() );
  ctx->contact_info_table = fd_contact_info_table_join( fd_contact_info_table_new( FD_SCRATCH_ALLOC_APPEND( l, fd_contact_info_table_align(), fd_contact_info_table_footprint( FD_PEER_KEY_MAX ) ), FD_PEER_KEY_MAX, 0 ) );

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "gossip tile has too many input links" ));

  uint sign_link_in_idx = UINT_MAX;
  memset( ctx->in_kind, 0, sizeof(ctx->in_kind) );
  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if( 0==strcmp( link->name, "net_gossip" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in_links[ in_idx ].net_rx, link->dcache );
      continue;
    } else if( 0==strcmp( link->name, "send_txns" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SEND;
    } else if( 0==strcmp( link->name, "sign_gossip" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SIGN;
      sign_link_in_idx = in_idx;
    } else {
      FD_LOG_ERR(( "gossip tile has unexpected input link %s", link->name ));
    }

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
  }
  if( FD_UNLIKELY( sign_link_in_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing sign_gossip link" ));

  uint sign_link_out_idx = UINT_MAX;
  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];

    if( 0==strcmp( link->name, "gossip_net" ) ) {

      if( FD_UNLIKELY( ctx->net_out_mcache ) ) FD_LOG_ERR(( "gossip tile has multiple gossip_net out links" ));
      ctx->net_out_mcache = link->mcache;
      ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
      ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
      ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
      ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( link->dcache ), link->dcache );
      ctx->net_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, link->dcache, link->mtu );
      ctx->net_out_chunk  = ctx->net_out_chunk0;

    } else if( 0==strcmp( link->name, "crds_shred" ) ) {


      if( FD_UNLIKELY( ctx->shred_contact_out_mcache ) ) FD_LOG_ERR(( "gossip tile has multiple crds_shred out links" ));
      ctx->shred_contact_out_mcache = link->mcache;
      ctx->shred_contact_out_sync   = fd_mcache_seq_laddr( ctx->shred_contact_out_mcache );
      ctx->shred_contact_out_depth  = fd_mcache_depth( ctx->shred_contact_out_mcache );
      ctx->shred_contact_out_seq    = fd_mcache_seq_query( ctx->shred_contact_out_sync );
      ctx->shred_contact_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->shred_contact_out_chunk0 = fd_dcache_compact_chunk0( ctx->shred_contact_out_mem, link->dcache );
      ctx->shred_contact_out_wmark  = fd_dcache_compact_wmark ( ctx->shred_contact_out_mem, link->dcache, link->mtu );
      ctx->shred_contact_out_chunk  = ctx->shred_contact_out_chunk0;

    } else if( 0==strcmp( link->name, "gossip_repai" ) ) {

      if( FD_UNLIKELY( ctx->repair_contact_out_mcache ) ) FD_LOG_ERR(( "gossip tile has multiple gossip_repair out links" ));
      ctx->repair_contact_out_mcache = link->mcache;
      ctx->repair_contact_out_sync   = fd_mcache_seq_laddr( ctx->repair_contact_out_mcache );
      ctx->repair_contact_out_depth  = fd_mcache_depth( ctx->repair_contact_out_mcache );
      ctx->repair_contact_out_seq    = fd_mcache_seq_query( ctx->repair_contact_out_sync );
      ctx->repair_contact_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->repair_contact_out_chunk0 = fd_dcache_compact_chunk0( ctx->repair_contact_out_mem, link->dcache );
      ctx->repair_contact_out_wmark  = fd_dcache_compact_wmark ( ctx->repair_contact_out_mem, link->dcache, link->mtu );
      ctx->repair_contact_out_chunk  = ctx->repair_contact_out_chunk0;

    } else if( 0==strcmp( link->name, "gossip_verif" ) ) {

      if( FD_UNLIKELY( ctx->verify_out_mcache ) ) FD_LOG_ERR(( "gossip tile has multiple gossip_verif out links" ));
      ctx->verify_out_mcache = link->mcache;
      ctx->verify_out_sync   = fd_mcache_seq_laddr( ctx->verify_out_mcache );
      ctx->verify_out_depth  = fd_mcache_depth( ctx->verify_out_mcache );
      ctx->verify_out_seq    = fd_mcache_seq_query( ctx->verify_out_sync );
      ctx->verify_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->verify_out_chunk0 = fd_dcache_compact_chunk0( ctx->verify_out_mem, link->dcache );
      ctx->verify_out_wmark  = fd_dcache_compact_wmark ( ctx->verify_out_mem, link->dcache, link->mtu );
      ctx->verify_out_chunk  = ctx->verify_out_chunk0;

    } else if( 0==strcmp( link->name, "gossip_sign" ) ) {

      sign_link_out_idx = out_idx;

    } else if( 0==strcmp( link->name, "gossip_send" ) ) {

      if( FD_UNLIKELY( ctx->send_contact_out_mcache ) ) FD_LOG_ERR(( "gossip tile has multiple gossip_send out links" ));
      ctx->send_contact_out_mcache = link->mcache;
      ctx->send_contact_out_sync   = fd_mcache_seq_laddr( ctx->send_contact_out_mcache );
      ctx->send_contact_out_depth  = fd_mcache_depth( ctx->send_contact_out_mcache );
      ctx->send_contact_out_seq    = fd_mcache_seq_query( ctx->send_contact_out_sync );
      ctx->send_contact_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->send_contact_out_chunk0 = fd_dcache_compact_chunk0( ctx->send_contact_out_mem, link->dcache );
      ctx->send_contact_out_wmark  = fd_dcache_compact_wmark ( ctx->send_contact_out_mem, link->dcache, link->mtu );
      ctx->send_contact_out_chunk  = ctx->send_contact_out_chunk0;
      ctx->send_contact_out_idx    = out_idx;
    } else if( 0==strcmp( link->name, "gossip_tower" ) ) {

      ctx->tower_out_idx         = fd_topo_find_tile_out_link( topo, tile, "gossip_tower", 0 );
      ctx->tower_out_mem         = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->tower_out_chunk0      = fd_dcache_compact_chunk0( ctx->tower_out_mem, link->dcache );
      ctx->tower_out_wmark       = fd_dcache_compact_wmark ( ctx->tower_out_mem, link->dcache, link->mtu );
      ctx->tower_out_chunk       = ctx->tower_out_chunk0;

      FD_TEST( ctx->tower_out_idx!=ULONG_MAX );
      FD_TEST( ctx->tower_out_mem );
      FD_TEST( fd_dcache_compact_is_safe( ctx->tower_out_mem, link->dcache, link->mtu, link->depth ) );

    } else if( 0==strcmp( link->name, "gossip_plugi" ) ) {

      if( FD_UNLIKELY( ctx->gossip_plugin_out_mem ) ) FD_LOG_ERR(( "gossip tile has multiple gossip_plugi out links" ));
      ctx->gossip_plugin_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->gossip_plugin_out_chunk0 = fd_dcache_compact_chunk0( ctx->gossip_plugin_out_mem, link->dcache );
      ctx->gossip_plugin_out_wmark  = fd_dcache_compact_wmark ( ctx->gossip_plugin_out_mem, link->dcache, link->mtu );
      ctx->gossip_plugin_out_chunk  = ctx->gossip_plugin_out_chunk0;
      ctx->gossip_plugin_out_idx    = out_idx;

    } else {
      FD_LOG_ERR(( "gossip tile has unexpected output link %s", link->name ));
    }

  }
  if( FD_UNLIKELY( sign_link_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing gossip_sign link" ));

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ctx->gossip_my_addr.addr = tile->gossip.ip_addr;
  ctx->gossip_my_addr.port = fd_ushort_bswap( tile->gossip.gossip_listen_port );

  ctx->gossip_listen_port = tile->gossip.gossip_listen_port;

  FD_TEST( ctx->gossip_listen_port!=0 );

  ctx->net_id = (ushort)0;

  fd_ip4_udp_hdr_init( ctx->hdr, FD_NET_MTU, ctx->gossip_my_addr.addr, ctx->gossip_listen_port );

  ctx->last_shred_dest_push_time = 0;

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id [ sign_link_in_idx  ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_link_out_idx ] ];
  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache,
                                                            sign_out->mtu ) )==NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

  /* Gossip set up */
  ctx->gossip = fd_gossip_join( fd_gossip_new( ctx->gossip, ctx->gossip_seed ) );

  FD_LOG_NOTICE(( "gossip my addr - addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->gossip_my_addr.addr ), fd_ushort_bswap( ctx->gossip_my_addr.port ) ));
  ctx->gossip_config.my_addr    = ctx->gossip_my_addr;
  ctx->gossip_config.my_version = (fd_gossip_version_v3_t){
    .major = 42U,
    .minor = 42U,
    .patch = 42U,
    .commit = 0U,
    .feature_set = 0U,
    .client = 2U
  };
  ctx->gossip_config.node_outset   = fd_log_wallclock() / 1000000; /* in ms */
  ctx->gossip_config.public_key    = &ctx->identity_public_key;
  ctx->gossip_config.deliver_fun   = gossip_deliver_fun;
  ctx->gossip_config.deliver_arg   = ctx;
  ctx->gossip_config.send_fun      = gossip_send_packet;
  ctx->gossip_config.send_arg      = ctx;
  ctx->gossip_config.sign_fun      = gossip_signer;
  ctx->gossip_config.sign_arg      = ctx;
  ctx->gossip_config.shred_version = (ushort)tile->gossip.expected_shred_version;

  if( fd_gossip_set_config( ctx->gossip, &ctx->gossip_config ) ) {
    FD_LOG_ERR( ( "error setting gossip config" ) );
  }

  fd_gossip_set_entrypoints( ctx->gossip, tile->gossip.entrypoints, tile->gossip.entrypoints_cnt );

  fd_gossip_update_addr( ctx->gossip, &ctx->gossip_config.my_addr );

  ctx->tvu_my_addr.addr       = tile->gossip.ip_addr;
  ctx->tvu_my_addr.port       = fd_ushort_bswap( tile->gossip.tvu_port );
  ctx->tpu_my_addr.addr       = tile->gossip.ip_addr;
  ctx->tpu_my_addr.port       = fd_ushort_bswap( tile->gossip.tpu_port );
  ctx->tpu_quic_my_addr.addr  = tile->gossip.ip_addr;
  ctx->tpu_quic_my_addr.port  = fd_ushort_bswap( tile->gossip.tpu_quic_port );
  ctx->tpu_vote_my_addr.addr  = tile->gossip.ip_addr;
  ctx->tpu_vote_my_addr.port  = fd_ushort_bswap( tile->gossip.tpu_vote_port );
  ctx->repair_serve_addr.addr = tile->gossip.ip_addr;
  ctx->repair_serve_addr.port = fd_ushort_bswap( tile->gossip.repair_serve_port );

  fd_gossip_update_tvu_addr( ctx->gossip, &ctx->tvu_my_addr );
  fd_gossip_update_tpu_addr( ctx->gossip, &ctx->tpu_my_addr, &ctx->tpu_quic_my_addr );
  fd_gossip_update_tpu_vote_addr( ctx->gossip, &ctx->tpu_vote_my_addr );
  fd_gossip_update_repair_addr( ctx->gossip, &ctx->repair_serve_addr );
  fd_gossip_settime( ctx->gossip, fd_log_wallclock() );
  fd_gossip_start( ctx->gossip );

  FD_LOG_NOTICE(( "gossip listening on port %u", tile->gossip.gossip_listen_port ));

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top>( (ulong)scratch + scratch_footprint( tile ) ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ulong poh_shred_obj_id = fd_pod_query_ulong( topo->props, "poh_shred", ULONG_MAX );
  FD_TEST( poh_shred_obj_id!=ULONG_MAX );

  fd_shred_version = fd_fseq_join( fd_topo_obj_laddr( topo, poh_shred_obj_id ) );
  FD_TEST( fd_shred_version );

  /* Initialize metrics to zero */
  memset( &ctx->metrics, 0, FD_GOSSIP_TILE_METRICS_FOOTPRINT );
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

static inline void
fd_gossip_update_gossip_metrics( fd_gossip_metrics_t * metrics ) {
  FD_MCNT_SET( GOSSIP, RECEIVED_PACKETS, metrics->recv_pkt_cnt );
  FD_MCNT_SET( GOSSIP, CORRUPTED_MESSAGES, metrics->recv_pkt_corrupted_msg );

  FD_MCNT_ENUM_COPY( GOSSIP, RECEIVED_GOSSIP_MESSAGES, metrics->recv_message );
  FD_MCNT_SET( GOSSIP, RECEIVED_UNKNOWN_MESSAGE, metrics->recv_unknown_message );

  FD_MCNT_ENUM_COPY( GOSSIP, RECEIVED_CRDS_PUSH, metrics->recv_crds[ FD_GOSSIP_CRDS_ROUTE_PUSH ] );
  FD_MCNT_ENUM_COPY( GOSSIP, RECEIVED_CRDS_PULL, metrics->recv_crds[ FD_GOSSIP_CRDS_ROUTE_PULL_RESP ] );
  FD_MCNT_ENUM_COPY( GOSSIP, RECEIVED_CRDS_DUPLICATE_MESSAGE_PUSH, metrics->recv_crds_duplicate_message[ FD_GOSSIP_CRDS_ROUTE_PUSH ] );
  FD_MCNT_ENUM_COPY( GOSSIP, RECEIVED_CRDS_DUPLICATE_MESSAGE_PULL, metrics->recv_crds_duplicate_message[ FD_GOSSIP_CRDS_ROUTE_PULL_RESP ] );
  FD_MCNT_ENUM_COPY( GOSSIP, RECEIVED_CRDS_DROP, metrics->recv_crds_drop_reason );

  FD_MCNT_ENUM_COPY( GOSSIP, PUSH_CRDS, metrics->push_crds );
  FD_MCNT_ENUM_COPY( GOSSIP, PUSH_CRDS_DUPLICATE_MESSAGE, metrics->push_crds_duplicate );
  FD_MCNT_ENUM_COPY( GOSSIP, PUSH_CRDS_DROP, metrics->push_crds_drop_reason );
  FD_MGAUGE_SET( GOSSIP, PUSH_CRDS_QUEUE_COUNT, metrics->push_crds_queue_cnt );

  FD_MGAUGE_SET( GOSSIP, VALUE_META_SIZE, metrics->value_meta_cnt );
  FD_MGAUGE_SET( GOSSIP, VALUE_VEC_SIZE, metrics->value_vec_cnt );

  FD_MGAUGE_SET( GOSSIP, ACTIVE_PUSH_DESTINATIONS, metrics->active_push_destinations );
  FD_MCNT_SET( GOSSIP, REFRESH_PUSH_STATES_FAIL_COUNT, metrics->refresh_push_states_failcnt );

  FD_MCNT_ENUM_COPY( GOSSIP, PULL_REQ_FAIL, metrics->handle_pull_req_fails );

  FD_MCNT_ENUM_COPY( GOSSIP, PULL_REQ_BLOOM_FILTER, metrics->handle_pull_req_bloom_filter_result);
  FD_MGAUGE_SET( GOSSIP, PULL_REQ_RESP_PACKETS, metrics->handle_pull_req_npackets );

  FD_MCNT_ENUM_COPY( GOSSIP, PRUNE_FAIL_COUNT, metrics->handle_prune_fails );

  FD_MCNT_SET( GOSSIP, MAKE_PRUNE_STALE_ENTRY, metrics->make_prune_stale_entry );
  FD_MCNT_SET( GOSSIP, MAKE_PRUNE_HIGH_DUPLICATES, metrics->make_prune_high_duplicates );
  FD_MGAUGE_SET( GOSSIP, MAKE_PRUNE_REQUESTED_ORIGINS, metrics->make_prune_requested_origins );
  FD_MCNT_SET( GOSSIP, MAKE_PRUNE_SIGN_DATA_ENCODE_FAILED, metrics->make_prune_sign_data_encode_failed );

  FD_MCNT_ENUM_COPY( GOSSIP, SENT_GOSSIP_MESSAGES, metrics->send_message );

  FD_MCNT_SET( GOSSIP, SENT_PACKETS, metrics->send_packet_cnt );

  FD_MCNT_ENUM_COPY( GOSSIP, SEND_PING_EVENT, metrics->send_ping_events );
  FD_MCNT_SET( GOSSIP, RECV_PING_INVALID_SIGNATURE, metrics->recv_ping_invalid_signature );

  FD_MCNT_ENUM_COPY( GOSSIP, RECV_PONG_EVENT, metrics->recv_pong_events );

  FD_MGAUGE_ENUM_COPY( GOSSIP, GOSSIP_PEER_COUNTS, metrics->gossip_peer_cnt );
}

static inline void
metrics_write( fd_gossip_tile_ctx_t * ctx ) {
  /* Tile-specific metrics */
  FD_MGAUGE_SET( GOSSIP, LAST_CRDS_PUSH_CONTACT_INFO_PUBLISH_TIMESTAMP_NANOS, ctx->metrics.last_crds_push_contact_info_publish_ts );
  FD_MCNT_SET( GOSSIP, MISMATCHED_CONTACT_INFO_SHRED_VERSION, ctx->metrics.mismatched_contact_info_shred_version );
  FD_MCNT_ENUM_COPY( GOSSIP, IPV6_CONTACT_INFO, ctx->metrics.ipv6_contact_info );
  FD_MCNT_ENUM_COPY( GOSSIP, ZERO_IPV4_CONTACT_INFO, ctx->metrics.zero_ipv4_contact_info );
  FD_MGAUGE_ENUM_COPY( GOSSIP, PEER_COUNTS, ctx->metrics.peer_counts );
  FD_MCNT_SET( GOSSIP, SHRED_VERSION_ZERO, ctx->metrics.shred_version_zero );

  /* Gossip-protocol-specific metrics */
  fd_gossip_update_gossip_metrics( fd_gossip_get_metrics( ctx->gossip ) );
}

#define STEM_BURST (30UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gossip_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gossip_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_gossip = {
  .name                     = "gossip",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
