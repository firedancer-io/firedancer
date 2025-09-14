/*  REQUEST HANDLING ARCHITECTURE
    =========================================

    The repair tile implements two distinct request handling patterns
    based on the nature of the operation and its latency requirements:

    1. SYNCHRONOUS REQUEST HANDLING
    -----------------------------------------
    Used for lightweight protocol messages that require immediate
    signing and response. These operations use the keyguard client for
    direct signing, which requires blocking.

    Message types handled synchronously:
    - PINGs & PONGs: Handles peer connectivity and liveness with simple
      round-trip messages.

    - PEER WARM UPs: On receiving peer information in
      handle_new_cluster_contact_info, we prepay the RTT cost by sending
      a placeholder Repair request immediately.

    2. ASYNCHRONOUS REQUEST HANDLING
    --------------------------------
    Used strictly for repair requests. These requests are sent to the
    sign tile, and the repair tile continues handling other operations
    without blocking. Once the sign tile has signed the request, the
    repair tile will complete the request from its pending sign request
    deque and send the response.

    Message types handled asynchronously:
    - WINDOW_INDEX (exact shred): Requests for a specific shred at a
      known slot and index. Used when the repair tile knows exactly
      which shred is missing from a FEC set.

    - HIGHEST_WINDOW_INDEX: Requests for the highest shred in a slot.
      Used to determine the end boundary of a slot when the exact count
      is unknown.

    - ORPHAN: Requests for the highest shred in the parent slot of an
      orphaned slot. Used to establish the chain of slot ancestry when a
      slot's parent is missing.

    Async requests can be distributed across multiple sign tiles using
    round-robin based on the request nonce. This provides load balancing
    and prevents any single sign tile from becoming a bottleneck. */

#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"
#include "generated/fd_repair_tile_seccomp.h"

#include "../tower/fd_tower_tile.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/store/fd_store.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/net/fd_net_headers.h"
#include "../../tango/fd_tango_base.h"

#include "../forest/fd_forest.h"
#include "../reasm/fd_reasm.h"
#include "../../flamenco/repair/fd_catchup.h"

#define LOGGING       1
#define DEBUG_LOGGING 0

#define IN_KIND_CONTACT (0)
#define IN_KIND_NET     (1)
#define IN_KIND_TOWER   (2)
#define IN_KIND_SHRED   (3)
#define IN_KIND_SIGN    (4)
#define IN_KIND_SNAP    (5)
#define IN_KIND_STAKE   (6)
#define IN_KIND_GOSSIP  (7)

#define MAX_IN_LINKS    (16)

#define MAX_REPAIR_PEERS   40200UL
#define MAX_BUFFER_SIZE    ( MAX_REPAIR_PEERS * sizeof( fd_shred_dest_wire_t ) )
#define MAX_SHRED_TILE_CNT ( 16UL )

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  };
  fd_net_rx_bounds_t net_rx;
} fd_repair_in_ctx_t;

struct fd_repair_out_ctx {
  ulong         idx;
  fd_wksp_t *   mem;
  ulong         chunk0;
  ulong         wmark;
  ulong         chunk;
  ulong         in_idx;       /* Index of the incoming link */
  ulong         credits;      /* Available credits for this sign tile */
  ulong         max_credits;  /* Maximum credits (depth) */
};
typedef struct fd_repair_out_ctx fd_repair_out_ctx_t;

struct fd_fec_sig {
  ulong            key; /* map key. 32 msb = slot, 32 lsb = fec_set_idx */
  fd_ed25519_sig_t sig; /* Ed25519 sig identifier of the FEC. */
};
typedef struct fd_fec_sig fd_fec_sig_t;

#define MAP_NAME    fd_fec_sig
#define MAP_T       fd_fec_sig_t
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_repair_tile_ctx {
  long tsprint; /* timestamp for printing */
  long tsrepair; /* timestamp for repair */
  long tsreset; /* timestamp for resetting iterator */

  fd_repair_t * repair;
  fd_repair_config_t repair_config;

  ulong repair_seed;

  fd_ip4_port_t repair_intake_addr;
  fd_ip4_port_t repair_serve_addr;

  ushort                repair_intake_listen_port;
  ushort                repair_serve_listen_port;

  fd_forest_t      * forest;
  fd_fec_sig_t     * fec_sigs;
  fd_reasm_t * reasm;
  fd_forest_iter_t   repair_iter;
  fd_store_t       * store;

  uchar       identity_private_key[ 32 ];
  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  fd_stem_context_t * stem;

  uchar              in_kind[ MAX_IN_LINKS ];
  fd_repair_in_ctx_t in_links[ MAX_IN_LINKS ];

  int skip_frag;

  uint        net_out_idx;
  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  ulong       replay_out_idx;
  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  ulong snap_out_chunk;

  /* These will only be used if shredcap is enabled */
  uint        shredcap_out_idx;
  uint        shredcap_enabled;
  fd_wksp_t * shredcap_out_mem;
  ulong       shredcap_out_chunk0;
  ulong       shredcap_out_wmark;
  ulong       shredcap_out_chunk;

  uint                shred_tile_cnt;
  fd_repair_out_ctx_t shred_out_ctx[ MAX_SHRED_TILE_CNT ];

  /* ping_sign link (to sign tile 0) - used for keyguard client */
  ulong       ping_sign_in_idx;

  ulong       ping_sign_out_idx;
  fd_wksp_t * ping_sign_out_mem;
  ulong       ping_sign_out_chunk0;
  ulong       ping_sign_out_wmark;
  ulong       ping_sign_out_chunk;

  /* repair_sign links (to sign tiles 1+) - for round-robin distribution */
  ulong               repair_sign_cnt;
  fd_repair_out_ctx_t repair_sign_out_ctx[ MAX_SHRED_TILE_CNT ];
  ulong               sign_repair_in_cnt;
  ulong               sign_repair_in_idx[ MAX_SHRED_TILE_CNT ];
  ulong               sign_repair_in_depth[ MAX_SHRED_TILE_CNT ];

  ulong               round_robin_idx;

  /* Request sequence tracking for async signing */
  ulong               request_seq;

  ushort net_id;
  /* Includes Ethernet, IP, UDP headers */
  uchar buffer[ MAX_BUFFER_SIZE ];
  fd_ip4_udp_hdrs_t intake_hdr[1];
  fd_ip4_udp_hdrs_t serve_hdr [1];

  fd_keyguard_client_t keyguard_client[1];

  ulong manifest_slot;
  ulong turbine_slot;

  struct {
    ulong recv_clnt_pkt;
    ulong recv_serv_pkt;
    ulong recv_serv_corrupt_pkt;
    ulong recv_serv_invalid_signature;
    ulong recv_serv_full_ping_table;
    ulong recv_serv_pkt_types[FD_METRICS_ENUM_REPAIR_SERV_PKT_TYPES_CNT];
    ulong recv_pkt_corrupted_msg;
    ulong send_pkt_cnt;
    ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_CNT];
    ulong repaired_slots;
    fd_histf_t store_link_wait[ 1 ];
    fd_histf_t store_link_work[ 1 ];
    fd_histf_t slot_compl_time[ 1 ];
    fd_histf_t response_latency[ 1 ];
  } metrics[ 1 ];

  /* Catchup metrics */
  fd_catchup_t * catchup;

  ulong turbine_slot0;  // catchup considered complete after this slot
};
typedef struct fd_repair_tile_ctx fd_repair_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t)                           );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(),             fd_repair_footprint()                                  );
  l = FD_LAYOUT_APPEND( l, fd_forest_align(),             fd_forest_footprint        ( tile->repair.slot_max   ) );
  l = FD_LAYOUT_APPEND( l, fd_fec_sig_align(),            fd_fec_sig_footprint       ( 20                      ) );
  l = FD_LAYOUT_APPEND( l, fd_reasm_align(),              fd_reasm_footprint         ( 1 << 20                 ) );
  l = FD_LAYOUT_APPEND( l, fd_catchup_align(),            fd_catchup_footprint()                                 );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(),       fd_scratch_smem_footprint  ( FD_REPAIR_SCRATCH_MAX   ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(),       fd_scratch_fmem_footprint  ( FD_REPAIR_SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}


/* Wrapper for keyguard client sign */
static void
repair_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len,
               int           sign_type ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *) signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, signature, buffer, len, sign_type );
}

/* Wrapper for publishing to the sign tile*/
static void
repair_signer_async( void *        signer_ctx,
                     ulong         nonce,
                     uchar const * buffer,
                     ulong         len,
                     int           sign_type,
                     fd_repair_out_ctx_t * sign_out) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *) signer_ctx;

  uchar * dst = fd_chunk_to_laddr( sign_out->mem, sign_out->chunk );
  fd_memcpy( dst, buffer, len );

  ulong sig = ((ulong)nonce << 32) | (ulong)(uint)sign_type;
  fd_stem_publish( ctx->stem, sign_out->idx, sig, sign_out->chunk, len, 0UL, 0UL, 0UL );
  sign_out->chunk = fd_dcache_compact_next( sign_out->chunk, len, sign_out->chunk0, sign_out->wmark );

  ctx->request_seq = fd_seq_inc( ctx->request_seq, 1UL );
}

static void
send_packet( fd_repair_tile_ctx_t * ctx,
             fd_stem_context_t *    stem,
             int                    is_intake,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uint                   src_ip_addr,
             uchar const *          payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {

  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *(is_intake ? ctx->intake_hdr : ctx->serve_hdr);

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->saddr       = src_ip_addr;
  ip4->daddr       = dst_ip_addr;
  ip4->net_id      = fd_ushort_bswap( ctx->net_id++ );
  ip4->check       = 0U;
  ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  ip4->check       = fd_ip4_hdr_check_fast( ip4 );

  fd_udp_hdr_t * udp = hdr->udp;
  udp->net_dport = dst_port;
  udp->net_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );
  hdr->udp->check = 0U;

  ulong tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig       = fd_disco_netmux_sig( dst_ip_addr, dst_port, dst_ip_addr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);
  ulong chunk     = ctx->net_out_chunk;
  fd_stem_publish( stem, ctx->net_out_idx, sig, chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

ulong
fd_repair_handle_ping( fd_repair_tile_ctx_t *        repair_tile_ctx,
                       fd_repair_t *                 glob,
                       fd_gossip_ping_t const *      ping,
                       fd_ip4_port_t const *         peer_addr FD_PARAM_UNUSED,
                       uint                          self_ip4_addr FD_PARAM_UNUSED,
                       uchar *                       msg_buf,
                       ulong                         msg_buf_sz ) {
  fd_repair_protocol_t protocol;
  fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_pong);
  fd_gossip_ping_t * pong = &protocol.inner.pong;

  pong->from = *glob->public_key;

  /* Generate response hash token */
  uchar pre_image[FD_PING_PRE_IMAGE_SZ];
  memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  memcpy( pre_image+16UL, ping->token.uc, 32UL);

  /* Generate response hash token */
  fd_sha256_hash( pre_image, FD_PING_PRE_IMAGE_SZ, &pong->token );

  /* Sign it */
  repair_signer( repair_tile_ctx, pong->signature.uc, pre_image, FD_PING_PRE_IMAGE_SZ, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );

  fd_bincode_encode_ctx_t ctx;
  ctx.data = msg_buf;
  ctx.dataend = msg_buf + msg_buf_sz;
  FD_TEST(0 == fd_repair_protocol_encode(&protocol, &ctx));
  ulong buflen = (ulong)((uchar*)ctx.data - msg_buf);
  return buflen;
}

/* Pass a raw client response packet into the protocol. addr is the address of the sender */
static int
fd_repair_recv_clnt_packet( fd_repair_tile_ctx_t *repair_tile_ctx,
                            fd_stem_context_t *   stem,
                            fd_repair_t *         glob,
                            uchar const *         msg,
                            ulong                 msglen,
                            fd_ip4_port_t const * src_addr,
                            uint                  dst_ip4_addr ) {
  repair_tile_ctx->metrics->recv_clnt_pkt++;

  FD_SCRATCH_SCOPE_BEGIN {
    while( 1 ) {
      ulong decoded_sz;
      fd_repair_response_t * gmsg = fd_bincode_decode1_scratch(
          repair_response, msg, msglen, NULL, &decoded_sz );
      if( FD_UNLIKELY( !gmsg ) ) {
        /* Solana falls back to assuming we got a shred in this case
           https://github.com/solana-labs/solana/blob/master/core/src/repair/serve_repair.rs#L1198 */
        break;
      }
      if( FD_UNLIKELY( decoded_sz != msglen ) ) {
        break;
      }

      switch( gmsg->discriminant ) {
      case fd_repair_response_enum_ping:
        {
          uchar buf[FD_REPAIR_MAX_SIGN_BUF_SIZE];
          ulong buflen = fd_repair_handle_ping( repair_tile_ctx, glob, &gmsg->inner.ping, src_addr, dst_ip4_addr, buf, sizeof(buf) );
          ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
          send_packet( repair_tile_ctx, stem, 1, src_addr->addr, src_addr->port, dst_ip4_addr, buf, buflen, tsorig );
          break;
        }
      }

      return 0;
    }
  } FD_SCRATCH_SCOPE_END;
  return 0;
}

/* Signs and prepares a repair protocol message for sending, either
   synchronously or asynchronously. This is responsible for encoding a
   repair protocol message, signing and preparing it for transmission.

   In synchronous mode (is_async == 0), the message is signed
   immediately using the keyguard client, and the signature is inserted
   into the message buffer before returning.

   In asynchronous mode (is_async != 0), the message is sent to the sign
   tile for signing, and the function returns after queuing the request.
   The actual sending will be completed once the signature is available.
 */
static ulong
fd_repair_sign_and_send( fd_repair_tile_ctx_t *  repair_tile_ctx,
                         fd_repair_protocol_t *  protocol,
                         fd_ip4_port_t *         addr FD_PARAM_UNUSED,
                         uchar                 * buf,
                         ulong                   buflen,
                         int                     is_async,
                         ulong                   nonce,
                         fd_repair_out_ctx_t *   sign_out) {

  FD_TEST( buflen >= FD_REPAIR_MAX_SIGN_BUF_SIZE );
  fd_bincode_encode_ctx_t ctx = { .data = buf, .dataend = buf + buflen };
  if( FD_UNLIKELY( fd_repair_protocol_encode( protocol, &ctx ) != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to encode repair message (type %#x)", protocol->discriminant ));
  }

  buflen = (ulong)ctx.data - (ulong)buf;
  if( FD_UNLIKELY( buflen<68 ) ) {
    FD_LOG_CRIT(( "Attempted to sign unsigned repair message type (type %#x)", protocol->discriminant ));
  }

  /* At this point buffer contains

     [ discriminant ] [ signature ] [ payload ]
     ^                ^             ^
     0                4             68 */

  /* https://github.com/solana-labs/solana/blob/master/core/src/repair/serve_repair.rs#L1258 */

  fd_memcpy( buf+64, buf, 4 );
  buf    += 64UL;
  buflen -= 64UL;

  /* Now it contains

     [ discriminant ] [ payload ]
     ^                ^
     buf              buf+4 */

  /* If async, we send the signing request to the sign tile */
  if( FD_LIKELY( is_async ) ) {
    repair_signer_async( repair_tile_ctx, nonce, buf, buflen, FD_KEYGUARD_SIGN_TYPE_ED25519, sign_out);
    return buflen + 64UL;
  /* If sync, we sign using keyguard */
  } else {
    fd_signature_t sig;
    repair_signer( repair_tile_ctx, sig.uc, buf, buflen, FD_KEYGUARD_SIGN_TYPE_ED25519 );

    /* Reintroduce the signature */
    buf    -= 64UL;
    buflen += 64UL;
    fd_memcpy( buf + 4U, &sig, 64U );

    return buflen;
  }
}

/* Returns a sign_out context that has available credits.
   If no sign_out context has available credits, returns NULL. */
static fd_repair_out_ctx_t *
sign_avail_credits( fd_repair_tile_ctx_t * ctx ) {
  fd_repair_out_ctx_t * sign_out = NULL;

  for( uint i = 0; i < ctx->repair_sign_cnt; i++ ) {
      fd_repair_out_ctx_t * candidate = &ctx->repair_sign_out_ctx[ ctx->round_robin_idx ];
      ctx->round_robin_idx = (ctx->round_robin_idx + 1) % ctx->repair_sign_cnt;
      if( candidate->credits > 0 ) {
          sign_out = candidate;
          break;
      }
  }

  return sign_out;
}

static void
fd_repair_send_initial_request( fd_repair_tile_ctx_t   * ctx,
                                fd_stem_context_t      * stem,
                                fd_repair_t            * glob,
                                fd_pubkey_t const      * recipient,
                                long                     now ) {
  fd_repair_protocol_t protocol;
  fd_repair_construct_request_protocol( glob, &protocol, fd_needed_window_index, 0, 0, recipient, 0, now );
  fd_active_elem_t * active = fd_active_table_query( glob->actives, recipient, NULL );

  ctx->metrics->sent_pkt_types[fd_needed_window_index]++;

  uchar buf[FD_REPAIR_MAX_SIGN_BUF_SIZE];
  ulong buflen       = fd_repair_sign_and_send( ctx, &protocol, &active->addr, buf, sizeof(buf), 0, 1, NULL );
  ulong tsorig       = fd_frag_meta_ts_comp( fd_tickcount() );
  uint  src_ip4_addr = 0U; /* unknown */
  send_packet( ctx, stem, 1, active->addr.addr, active->addr.port, src_ip4_addr, buf, buflen, tsorig );
}

/* Sends a request asynchronously. If successful, adds it to the
   pending_sign_map and publishes to the sign tile. If not, the
   request is skipped for now and will be retried later by the forest
   iterator. */
static void
fd_repair_send_request_async( fd_repair_tile_ctx_t *   ctx,
                              fd_repair_t *            glob,
                              fd_repair_out_ctx_t *    sign_out,
                              enum fd_needed_elem_type type,
                              ulong                    slot,
                              uint                     shred_index,
                              fd_pubkey_t const      * recipient,
                              long                     now ){
    fd_active_elem_t * peer = fd_active_table_query(glob->actives, recipient, NULL);
    if (!peer) FD_LOG_ERR(( "No active peer found for recipient %s", FD_BASE58_ENC_32_ALLOCA(recipient) ));

    /* Acquire and add a pending request from the pool */
    fd_repair_protocol_t protocol;
    fd_repair_pending_sign_req_t * pending = fd_repair_insert_pending_request( ctx->repair, &protocol, peer->addr.addr, peer->addr.port, type, slot, shred_index, now, recipient );

    if( FD_UNLIKELY( !pending ) ) {
        FD_LOG_WARNING(( "No free pending sign reqs" ));
        return;
    }
    ctx->metrics->sent_pkt_types[type]++;
    /* Sign and prepare the message directly into the pending buffer */
    pending->buflen = fd_repair_sign_and_send( ctx, &protocol, &peer->addr, pending->buf, sizeof(pending->buf), 1, pending->nonce, sign_out );

    sign_out->credits--;
}

static void
fd_repair_send_requests_async( fd_repair_tile_ctx_t *   ctx,
                               fd_repair_out_ctx_t *    sign_out,
                               enum fd_needed_elem_type type,
                               ulong                    slot,
                               uint                     shred_index,
                               long                     now ){
  fd_repair_t * glob = ctx->repair;
  fd_pubkey_t const * id = &glob->peers[ glob->peer_idx++ ].key;
  fd_repair_send_request_async( ctx, glob, sign_out, type, slot, shred_index, id, now );
  if( FD_UNLIKELY( glob->peer_idx >= glob->peer_cnt ) ) glob->peer_idx = 0;
}

static inline void
handle_contact_info_update( fd_repair_tile_ctx_t *             ctx,
                            fd_gossip_update_message_t const * msg ) {
  fd_contact_info_t const * contact_info = msg->contact_info.contact_info;
  fd_ip4_port_t repair_peer = contact_info->sockets[ FD_CONTACT_INFO_SOCKET_SERVE_REPAIR ];
  if( FD_UNLIKELY( !repair_peer.addr || !repair_peer.port ) ) return;
  int dup = fd_repair_add_active_peer( ctx->repair, &repair_peer, &contact_info->pubkey );
  if( !dup ) {
    /* The repair process uses a Ping-Pong protocol that incurs one
       round-trip time (RTT) for the initial repair request. To optimize
       this, we proactively send a placeholder Repair request as soon as we
       receive a peer's contact information for the first time, effectively
       prepaying the RTT cost. */
    if( FD_LIKELY( ctx->repair_sign_cnt>0 ) ) {
      fd_repair_send_initial_request( ctx, ctx->stem, ctx->repair, &contact_info->pubkey, fd_log_wallclock() );
    }
  }
}

static inline void
handle_contact_info_remove( fd_repair_tile_ctx_t * ctx             FD_PARAM_UNUSED,
                            fd_gossip_update_message_t const * msg FD_PARAM_UNUSED ) {
  /* TODO: implement me */
}

static inline int
before_frag( fd_repair_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_LIKELY  ( in_kind==IN_KIND_NET   ) ) return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR;
  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) return fd_int_if( fd_forest_root_slot( ctx->forest )==ULONG_MAX, -1, 0 ); /* not ready to read frag */
  if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  return 0;
}

static void
during_frag( fd_repair_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {
  ctx->skip_frag = 0;

  uchar const * dcache_entry;
  ulong dcache_entry_sz;

  // TODO: check for sz>MTU for failure once MTUs are decided
  uint in_kind = ctx->in_kind[ in_idx ];
  fd_repair_in_ctx_t const * in_ctx = &ctx->in_links[ in_idx ];
  if( FD_LIKELY( in_kind==IN_KIND_NET ) ) {
    dcache_entry = fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz );
    dcache_entry_sz = sz;

  } else if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP || in_kind==IN_KIND_SHRED ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }

    dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    dcache_entry_sz = sz;

  } else if( FD_UNLIKELY( in_kind==IN_KIND_TOWER ) ) {
    fd_tower_slot_done_t const * msg = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    if( FD_LIKELY( msg->new_root ) ) {
      fd_forest_publish( ctx->forest, msg->root_slot );
      ctx->repair_iter = fd_forest_iter_init( ctx->forest );
      fd_reasm_publish( ctx->reasm, &msg->root_block_id );
      return;
    }
    return;

  } else if( FD_UNLIKELY( in_kind==IN_KIND_STAKE ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    fd_stake_weight_msg_t const * msg = fd_type_pun_const( dcache_entry );
    (void)msg;
    //fd_repair_set_stake_weights_init( ctx->repair,  msg->weights, msg->staked_cnt );
    return;
  } else if( FD_UNLIKELY( in_kind==IN_KIND_SNAP ) ) {

    if( FD_UNLIKELY( ctx->in_kind[in_idx]!=IN_KIND_SNAP || fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) ctx->snap_out_chunk = chunk;
    return;

  } else if ( FD_UNLIKELY( in_kind==IN_KIND_SIGN ) ) {
    dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    dcache_entry_sz = sz;
  } else {
    FD_LOG_ERR(( "Frag from unknown link (kind=%u in_idx=%lu)", in_kind, in_idx ));
  }

  if( FD_LIKELY( dcache_entry_sz > 0 ) ) fd_memcpy( ctx->buffer, dcache_entry, dcache_entry_sz );
}

static inline void
after_frag_snap( fd_repair_tile_ctx_t * ctx,
                 ulong                  sig,
                 uchar const          * chunk ) {
  if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) return;
  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)chunk;
  fd_forest_init( ctx->forest, manifest->slot );
  FD_TEST( fd_forest_root_slot( ctx->forest )!=ULONG_MAX );
  fd_hash_t manifest_block_id = { .ul = { 0xf17eda2ce7b1d } }; /* FIXME manifest_block_id */
  fd_reasm_init( ctx->reasm, &manifest_block_id, manifest->slot );
}

static ulong FD_FN_UNUSED
fd_repair_send_ping( fd_repair_tile_ctx_t        * repair_tile_ctx,
                     fd_repair_t                 * glob,
                     fd_pinged_elem_t            * val,
                     uchar                       * buf,
                     ulong                         buflen ) {
  fd_repair_response_t gmsg;
  fd_repair_response_new_disc( &gmsg, fd_repair_response_enum_ping );
  fd_gossip_ping_t * ping = &gmsg.inner.ping;
  ping->from = *glob->public_key;

  uchar pre_image[FD_PING_PRE_IMAGE_SZ];
  memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  memcpy( pre_image+16UL, val->token.uc, 32UL );

  fd_sha256_hash( pre_image, FD_PING_PRE_IMAGE_SZ, &ping->token );

  repair_signer( repair_tile_ctx, ping->signature.uc, pre_image, FD_PING_PRE_IMAGE_SZ, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );

  fd_bincode_encode_ctx_t ctx;
  FD_TEST( buflen >= FD_REPAIR_MAX_SIGN_BUF_SIZE );
  ctx.data = buf;
  ctx.dataend = buf + buflen;
  FD_TEST(0 == fd_repair_response_encode(&gmsg, &ctx));
  return (ulong)((uchar*)ctx.data - buf);
}

static void FD_FN_UNUSED
fd_repair_recv_pong(fd_repair_t * glob, fd_gossip_ping_t const * pong, fd_ip4_port_t const * from) {
  fd_pinged_elem_t * val = fd_pinged_table_query(glob->pinged, from, NULL);
  if( val == NULL || !fd_pubkey_eq( &val->id, &pong->from ) )
    return;

  /* Verify response hash token */
  uchar pre_image[FD_PING_PRE_IMAGE_SZ];
  memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  memcpy( pre_image+16UL, val->token.uc, 32UL );

  fd_hash_t pre_image_hash;
  fd_sha256_hash( pre_image, FD_PING_PRE_IMAGE_SZ, pre_image_hash.uc );

  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, pre_image_hash.uc,  32UL );
  fd_hash_t golden;
  fd_sha256_fini( sha, golden.uc );

  fd_sha512_t sha2[1];
  if( fd_ed25519_verify( /* msg */ golden.uc,
                         /* sz */ 32U,
                         /* sig */ pong->signature.uc,
                         /* public_key */ pong->from.uc,
                         sha2 )) {
    FD_LOG_WARNING(("Failed sig verify for pong"));
    return;
  }

  val->good = 1;
}

static void
fd_repair_handle_sign_response( fd_repair_tile_ctx_t * ctx,
                                ulong                  in_idx,
                                ulong                  sig,
                                fd_stem_context_t *    stem ) {
  /* Nonce was packed into sig, so we need to unpack it */
  ulong response_nonce = sig >> 32;
  /* Look up the pending request by nonce. Since the repair_sign links are
     reliable, the incoming sign_repair fragments represent a complete
     set of the previously sent outgoing messages. However, with
     multiple sign tiles, the responses may not arrive in order. */

  /* Find which sign tile sent this response and increment its credits */
  for( uint i = 0; i < ctx->repair_sign_cnt; i++ ) {
    if( ctx->repair_sign_out_ctx[i].in_idx == in_idx ) {
      if( ctx->repair_sign_out_ctx[i].credits < ctx->repair_sign_out_ctx[i].max_credits ) {
        ctx->repair_sign_out_ctx[i].credits++;
      }
      break;
    }
  }

  fd_repair_pending_sign_req_t * pending = fd_repair_query_pending_request( ctx->repair, response_nonce );
  if( FD_LIKELY( pending ) ) {
    fd_memcpy( pending->buf + pending->sig_offset, ctx->buffer, 64UL );
    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
    uint src_ip4_addr = 0U;
    ctx->metrics->send_pkt_cnt++;
    fd_active_elem_t * active = fd_active_table_query( ctx->repair->actives, &pending->recipient, NULL );
    if( FD_LIKELY( active ) ) {
      active->req_cnt++;
      active->last_req_ts = fd_tickcount();
      if( FD_UNLIKELY( active->first_req_ts == 0 ) ) active->first_req_ts = active->last_req_ts;
    }
    send_packet( ctx, stem, 1, pending->dst_ip_addr, pending->dst_port, src_ip4_addr, pending->buf, pending->buflen, tsorig );

    fd_repair_remove_pending_request( ctx->repair, response_nonce );
    return;
  } else {
    FD_LOG_ERR(( "No pending request found for nonce %lu", response_nonce ));
  }
}

static void
after_frag( fd_repair_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq    FD_PARAM_UNUSED,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *    stem ) {
  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  ctx->stem = stem;

  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP ) ) {
    fd_gossip_update_message_t const * msg = (fd_gossip_update_message_t const *)fd_type_pun_const( ctx->buffer );
    if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) ){
      handle_contact_info_update( ctx, msg );
    } else {
      /* TODO: this needs to be implemented */
      handle_contact_info_remove( ctx, msg );
    }
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SIGN ) ) {
    fd_repair_handle_sign_response( ctx, in_idx, sig, stem );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) {
    int resolver_evicted = sz == 0;
    int fec_completes    = sz == FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t);
    if( FD_UNLIKELY( resolver_evicted ) ) {
      ulong spilled_slot        = fd_disco_shred_repair_shred_sig_slot       ( sig );
      uint  spilled_fec_set_idx = fd_disco_shred_repair_shred_sig_fec_set_idx( sig );
      uint  spilled_max_idx     = fd_disco_shred_repair_shred_sig_data_cnt   ( sig );

      fd_forest_fec_clear( ctx->forest, spilled_slot, spilled_fec_set_idx, spilled_max_idx );
      return;
    }

    fd_shred_t * shred = (fd_shred_t *)fd_type_pun( ctx->buffer );
    uint         nonce = FD_LOAD(uint, ctx->buffer + fd_shred_header_sz( shred->variant ) );
    if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) {
      FD_LOG_INFO(( "shred %lu %u %u too old, ignoring", shred->slot, shred->idx, shred->fec_set_idx ));
      return;
    };
#   if LOGGING
    if( FD_UNLIKELY( shred->slot > ctx->turbine_slot ) ) {
      FD_LOG_INFO(( "\n\n[Turbine]\n"
                    "slot:             %lu\n"
                    "root:             %lu\n",
                    shred->slot,
                    fd_forest_root_slot( ctx->forest ) ));
    }
#   endif
    ctx->turbine_slot  = fd_ulong_max( shred->slot, ctx->turbine_slot );
    if( FD_UNLIKELY( ctx->turbine_slot0 == ULONG_MAX ) ) {
      ctx->turbine_slot0 = shred->slot;
      fd_catchup_set_turbine_slot0( ctx->catchup, shred->slot );
    }

    /* TODO add automated caught-up test */

    /* Insert the shred sig (shared by all shred members in the FEC set)
       into the map. */

    fd_fec_sig_t * fec_sig = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx, NULL );
    if( FD_UNLIKELY( !fec_sig && !fec_completes ) ) {
      fec_sig = fd_fec_sig_insert( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx );
      memcpy( fec_sig->sig, shred->signature, sizeof(fd_ed25519_sig_t) );
    }

    /* When this is a FEC completes msg, it is implied that all the
       other shreds in the FEC set can also be inserted.  Shred inserts
       into the forest are idempotent so it is fine to insert the same
       shred multiple times. */

    if( FD_UNLIKELY( fec_completes ) ) {
      fd_forest_blk_t * ele = fd_forest_blk_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off );
      fd_forest_fec_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, shred->idx, shred->fec_set_idx, 0 );
      FD_TEST( ele ); /* must be non-empty */

      fd_hash_t const * merkle_root         = (fd_hash_t const *)fd_type_pun_const( ctx->buffer + FD_SHRED_DATA_HEADER_SZ );
      fd_hash_t const * chained_merkle_root = (fd_hash_t const *)fd_type_pun_const( ctx->buffer + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) );

      int     data_complete  = !!( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );
      int     slot_complete  = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );

      FD_TEST( !fd_reasm_query( ctx->reasm, merkle_root ) );
      fd_hash_t const * cmr = chained_merkle_root;
      if( FD_UNLIKELY( shred->slot - shred->data.parent_off == fd_reasm_slot0( ctx->reasm ) && shred->fec_set_idx == 0) ) {
        cmr = &fd_reasm_root( ctx->reasm )->key;
      }
      FD_TEST( fd_reasm_insert( ctx->reasm, merkle_root, cmr, shred->slot, shred->fec_set_idx, shred->data.parent_off, (ushort)(shred->idx - shred->fec_set_idx + 1), data_complete, slot_complete ) );

      if( FD_UNLIKELY( ele->complete_idx != UINT_MAX && ele->buffered_idx == ele->complete_idx &&
                       0==memcmp( ele->cmpl, ele->fecs, sizeof(fd_forest_blk_idxs_t) * fd_forest_blk_idxs_word_cnt ) ) ) {
        long now = fd_tickcount();
        long start_ts = ele->first_req_ts == 0 || ele->slot > ctx->turbine_slot0 ? ele->first_shred_ts : ele->first_req_ts;
        fd_histf_sample( ctx->metrics->slot_compl_time, (ulong)(now - start_ts) );
        fd_catchup_add_slot( ctx->catchup, ele->slot, start_ts, now, ele->repair_cnt, ele->turbine_cnt );
        FD_LOG_INFO(( "slot is complete %lu. num_data_shreds: %u, num_repaired: %u, num_turbine: %u", ele->slot, ele->complete_idx + 1, ele->repair_cnt, ele->turbine_cnt ));
      }
    }

    /* Insert the shred into the map. */

    int is_code = fd_shred_is_code( fd_shred_type( shred->variant ) );
    int src = fd_disco_shred_repair_shred_sig_is_turbine( sig ) ? SHRED_SRC_TURBINE : SHRED_SRC_REPAIR;
    if( FD_LIKELY( !is_code ) ) {
      long rtt = 0;
      if( FD_UNLIKELY( ( rtt = fd_repair_inflight_remove( ctx->repair, shred->slot, shred->idx, nonce ) ) > 0 ) ) {
        fd_histf_sample( ctx->metrics->response_latency, (ulong)rtt );
      }

      int               slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
      fd_forest_blk_t * blk           = fd_forest_blk_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off );
      fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, shred->idx, shred->fec_set_idx, slot_complete, src );

      /* Check if there are FECs to force complete. Algorithm: window
         through the idxs in interval [i, j). If j = next fec_set_idx
         then we know we can force complete the FEC set interval [i, j)
         (assuming it wasn't already completed based on `cmpl`). */

      uint i = blk->consumed_idx + 1;
      for( uint j = i; j < blk->buffered_idx + 1; j++ ) {
        if( FD_UNLIKELY( fd_forest_blk_idxs_test( blk->fecs, j ) ) ) {
          fd_fec_sig_t * fec_sig  = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | i, NULL );
          ulong          sig      = fd_ulong_load_8( fec_sig->sig );
          ulong          tile_idx = sig % ctx->shred_tile_cnt;
          uint           last_idx = j - i;

          uchar * chunk = fd_chunk_to_laddr( ctx->shred_out_ctx[tile_idx].mem, ctx->shred_out_ctx[tile_idx].chunk );
          memcpy( chunk, fec_sig->sig, sizeof(fd_ed25519_sig_t) );
          fd_fec_sig_remove( ctx->fec_sigs, fec_sig );
          fd_stem_publish( stem, ctx->shred_out_ctx[tile_idx].idx, last_idx, ctx->shred_out_ctx[tile_idx].chunk, sizeof(fd_ed25519_sig_t), 0UL, 0UL, 0UL );
          ctx->shred_out_ctx[tile_idx].chunk = fd_dcache_compact_next( ctx->shred_out_ctx[tile_idx].chunk, sizeof(fd_ed25519_sig_t), ctx->shred_out_ctx[tile_idx].chunk0, ctx->shred_out_ctx[tile_idx].wmark );
          blk->consumed_idx = j;
          i = j + 1;
        }
      }
    } else {
      fd_forest_code_shred_insert( ctx->forest, shred->slot, shred->idx );
    }
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_STAKE ) ) {
    //fd_repair_set_stake_weights_fini( ctx->repair );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SNAP ) ) {
    after_frag_snap( ctx, sig, fd_chunk_to_laddr( ctx->in_links[ in_idx ].mem, ctx->snap_out_chunk ) );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_TOWER ) ) {
    return;
  }

  fd_eth_hdr_t const * eth  = (fd_eth_hdr_t const *)ctx->buffer;
  fd_ip4_hdr_t const * ip4  = (fd_ip4_hdr_t const *)( (ulong)eth + sizeof(fd_eth_hdr_t) );
  fd_udp_hdr_t const * udp  = (fd_udp_hdr_t const *)( (ulong)ip4 + FD_IP4_GET_LEN( *ip4 ) );
  uchar *              data = (uchar              *)( (ulong)udp + sizeof(fd_udp_hdr_t) );
  if( FD_UNLIKELY( (ulong)udp+sizeof(fd_udp_hdr_t) > (ulong)eth+sz ) ) return;
  ulong udp_sz = fd_ushort_bswap( udp->net_len );
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) ) ) return;
  ulong data_sz = udp_sz-sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( (ulong)data+data_sz > (ulong)eth+sz ) ) return;

  fd_ip4_port_t peer_addr = { .addr=ip4->saddr, .port=udp->net_sport };
  ushort dport = udp->net_dport;
  if( ctx->repair_intake_addr.port == dport ) {
    fd_repair_recv_clnt_packet( ctx, stem, ctx->repair, data, data_sz, &peer_addr, ip4->daddr );
  } else if( ctx->repair_serve_addr.port == dport ) {
  } else {
    FD_LOG_WARNING(( "Unexpectedly received packet for port %u", (uint)fd_ushort_bswap( dport ) ));
  }
}

#define MAX_REQ_PER_CREDIT 1

static inline void
after_credit( fd_repair_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in,
              int *                  charge_busy ) {

  fd_forest_t          * forest   = ctx->forest;
  fd_forest_blk_t      * pool     = fd_forest_pool( forest );
  fd_forest_subtrees_t * subtrees = fd_forest_subtrees( forest );

  fd_reasm_fec_t * rfec = fd_reasm_next( ctx->reasm );
  if( FD_LIKELY( rfec ) ) {

    if( FD_LIKELY( ctx->store ) ) { /* some topologies don't run with store */

      /* Linking only requires a shared lock because the fields that are
          modified are only read on publish which uses exclusive lock. */

      long shacq_start, shacq_end, shrel_end;

      FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
        if( FD_UNLIKELY( !fd_store_link( ctx->store, &rfec->key, &rfec->cmr ) ) ) FD_LOG_WARNING(( "failed to link %s %s. slot %lu fec_set_idx %u", FD_BASE58_ENC_32_ALLOCA( &rfec->key ), FD_BASE58_ENC_32_ALLOCA( &rfec->cmr ), rfec->slot, rfec->fec_set_idx ));
      } FD_STORE_SHARED_LOCK_END;
      fd_histf_sample( ctx->metrics->store_link_wait, (ulong)fd_long_max(shacq_end - shacq_start, 0) );
      fd_histf_sample( ctx->metrics->store_link_work, (ulong)fd_long_max(shrel_end - shacq_end,   0) );
    }

    ulong sig   = rfec->slot << 32 | rfec->fec_set_idx;
    memcpy( fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk ), rfec, sizeof(fd_reasm_fec_t) );
    fd_stem_publish( stem, ctx->replay_out_idx, sig, ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), 0, 0, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_reasm_fec_t), ctx->replay_out_chunk0, ctx->replay_out_wmark );

    /* We might have more reassembled FEC sets to deliver to the
       downstream consumer, so prioritize that over sending out repairs
       (which will only increase the number of buffered to send.) */

    /* FIXME instead of draining the chainer, only skip the rest of
       after_credit and after_frag when the chainer pool is full.
       requires a refactor to the chainer and topology. */

    *opt_poll_in = 0; *charge_busy = 1; return;
  }

  if( FD_UNLIKELY( ctx->forest->root==ULONG_MAX ) ) return;
  if( FD_UNLIKELY( ctx->repair->peer_cnt==0     ) ) return; /* no peers to send requests to */

  *charge_busy = 1;

  long now = fd_log_wallclock();

#if MAX_REQ_PER_CREDIT > FD_REPAIR_NUM_NEEDED_PEERS
  /* If the requests are > 1 per credit then we need to starve
     after_credit for after_frag to get the chance to be called. We could
     get rid of this all together considering max requests per credit is
     1 currently, but it could be useful for benchmarking purposes in the
     future. */
  if( FD_UNLIKELY( now - ctx->tsrepair < (long)20e6 ) ) {
    return;
  }
  ctx->tsrepair = now;
#endif

  /* Verify that there is at least one sign tile with available credits.
     If not, we can't send any requests and leave early. */
  fd_repair_out_ctx_t * sign_out = sign_avail_credits( ctx );
  if( FD_UNLIKELY( !sign_out ) ) {
      // FD_LOG_NOTICE(( "No sign tiles have available credits" ));
      return;
  }

  /* Always request orphans first */
  int total_req = 0;
  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
        !fd_forest_subtrees_iter_done( iter, subtrees, pool );
        iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_blk_t * orphan = fd_forest_subtrees_iter_ele( iter, subtrees, pool );
    if( fd_repair_need_orphan( ctx->repair, orphan->slot ) ) {
      fd_repair_send_requests_async( ctx, sign_out, fd_needed_orphan, orphan->slot, UINT_MAX, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
      fd_repair_continue( ctx->repair );
      return;
    }
  }

  if( FD_UNLIKELY( total_req >= MAX_REQ_PER_CREDIT ) ) {
    fd_repair_continue( ctx->repair );
    return; /* we have already sent enough requests */
  }

  // Travel down frontier

  /* Every so often we'll need to reset the frontier iterator to the
     head of frontier, because we could end up traversing down a very
     long tree if we are far behind. */

  if( FD_UNLIKELY( now - ctx->tsreset > (long)100e6 ) ) {
    // reset iterator to the beginning of the forest frontier
    ctx->repair_iter = fd_forest_iter_init( ctx->forest );
    ctx->tsreset = now;
  }

  /* We are at the head of the turbine, so we should give turbine the
     chance to complete the shreds. !ele handles an edgecase where all
     frontier are fully complete and the iter is done */

  fd_forest_blk_t * ele = fd_forest_pool_ele( pool, ctx->repair_iter.ele_idx );
  if( FD_LIKELY( !ele || ( ele->slot==ctx->turbine_slot && (now-ctx->tsreset)<(long)30e6 ) ) ) return;

  while( total_req < MAX_REQ_PER_CREDIT ){
    ele = fd_forest_pool_ele( pool, ctx->repair_iter.ele_idx );

    // Request first, advance iterator second.
    if( ctx->repair_iter.shred_idx == UINT_MAX && fd_repair_need_highest_window_index( ctx->repair, ele->slot, 0 ) ){
      fd_repair_send_requests_async( ctx, sign_out, fd_needed_highest_window_index, ele->slot, 0, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
    } else if( fd_repair_need_window_index( ctx->repair, ele->slot, ctx->repair_iter.shred_idx ) ) {
      fd_repair_send_requests_async( ctx, sign_out, fd_needed_window_index, ele->slot, ctx->repair_iter.shred_idx, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
      if( FD_UNLIKELY( ele->first_req_ts == 0 ) ) ele->first_req_ts = fd_tickcount();
    }

    ctx->repair_iter = fd_forest_iter_next( ctx->repair_iter, forest );

    if( FD_UNLIKELY( fd_forest_iter_done( ctx->repair_iter, forest ) ) ) {
      /* No more elements in the forest frontier, or the iterator got
         invalidated, so we can start from top again. */
      ctx->repair_iter = fd_forest_iter_init( forest );
      break;
    }
  }

  fd_repair_continue( ctx->repair );
}

static inline void
during_housekeeping( fd_repair_tile_ctx_t * ctx ) {
  fd_repair_settime( ctx->repair, fd_log_wallclock() );

# if DEBUG_LOGGING
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - ctx->tsprint > (long)10e9 ) ) {
    fd_forest_print( ctx->forest );
    fd_reasm_print( ctx->reasm );
    ctx->tsprint = fd_log_wallclock();
  }
# endif
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_repair_tile_ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->repair.identity_key_path, /* pubkey only: */ 0 );
  fd_memcpy( ctx->identity_private_key, identity_key, sizeof(fd_pubkey_t) );
  fd_memcpy( ctx->identity_public_key.uc, identity_key + 32UL, sizeof(fd_pubkey_t) );

  ctx->repair_config.private_key = ctx->identity_private_key;
  ctx->repair_config.public_key  = &ctx->identity_public_key;

  FD_TEST( fd_rng_secure( &ctx->repair_seed, sizeof(ulong) ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  ctx->tsprint  = fd_log_wallclock();
  ctx->tsrepair = fd_log_wallclock();
  ctx->tsreset  = fd_log_wallclock();

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "repair tile has too many input links" ));

  ctx->sign_repair_in_cnt = 0;
  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if( 0==strcmp( link->name, "net_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in_links[ in_idx ].net_rx, link->dcache );
      continue;
    } else if( 0==strcmp( link->name, "gossip_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_GOSSIP;
    } else if( 0==strcmp( link->name, "tower_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_TOWER;
    } else if( 0==strcmp( link->name, "shred_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SHRED;
    } else if( 0==strcmp( link->name, "sign_repair" ) || 0==strcmp( link->name, "sign_ping" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SIGN;
      if( 0==strcmp( link->name, "sign_ping" ) ) {
        ctx->in_kind[ in_idx ] = IN_KIND_SIGN;
        ctx->ping_sign_in_idx = in_idx;
      } if( 0==strcmp( link->name, "sign_repair" ) ) {
        ctx->in_kind[ in_idx ] = IN_KIND_SIGN;
        ctx->sign_repair_in_idx[ ctx->sign_repair_in_cnt ] = in_idx;
        ctx->sign_repair_in_depth[ ctx->sign_repair_in_cnt ] = link->depth;
        ctx->sign_repair_in_cnt++;
      }
    } else if( 0==strcmp( link->name, "snap_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    } else if( 0==strcmp( link->name, "replay_stake" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_STAKE;
    }else {
      FD_LOG_ERR(( "repair tile has unexpected input link %s", link->name ));
    }

    // ulong i = fd_topo_find_tile_in_link( topo, tile, "snap_out", 0 );
    // FD_LOG_ERR(( "snap_out link idx %lu", i ));

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;

    FD_TEST( fd_dcache_compact_is_safe( ctx->in_links[in_idx].mem, link->dcache, link->mtu, link->depth ) );
  }

  uint net_link_out_idx      = UINT_MAX;
  ctx->ping_sign_out_idx     = UINT_MAX;
  ctx->repair_sign_cnt       = 0;
  ctx->request_seq           = 0UL;
  uint shred_tile_idx        = 0;
  uint sign_repair_match_cnt = 0;
  ctx->round_robin_idx       = 0UL;

  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];

    if( 0==strcmp( link->name, "repair_net" ) ) {

      if( net_link_out_idx!=UINT_MAX ) continue; /* only use first net link */
      net_link_out_idx = out_idx;
      ctx->net_out_idx = out_idx;
      ctx->net_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, link->dcache );
      ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, link->dcache, link->mtu );
      ctx->net_out_chunk  = ctx->net_out_chunk0;
    } else if( 0==strcmp( link->name, "repair_repla" ) ) {

      ctx->replay_out_idx    = out_idx;
      ctx->replay_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, link->dcache );
      ctx->replay_out_wmark  = fd_dcache_compact_wmark( ctx->replay_out_mem, link->dcache, link->mtu );
      ctx->replay_out_chunk  = ctx->replay_out_chunk0;

    } else if( 0==strcmp( link->name, "repair_shred" ) ) {

      fd_repair_out_ctx_t * shred_out = &ctx->shred_out_ctx[ shred_tile_idx++ ];
      shred_out->idx                  = out_idx;
      shred_out->mem                  = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      shred_out->chunk0               = fd_dcache_compact_chunk0( shred_out->mem, link->dcache );
      shred_out->wmark                = fd_dcache_compact_wmark( shred_out->mem, link->dcache, link->mtu );
      shred_out->chunk                = shred_out->chunk0;

    } else if( 0==strcmp( link->name, "repair_scap" ) ) {

      ctx->shredcap_enabled    = 1;
      ctx->shredcap_out_idx    = out_idx;
      ctx->shredcap_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->shredcap_out_chunk0 = fd_dcache_compact_chunk0( ctx->shredcap_out_mem, link->dcache );
      ctx->shredcap_out_wmark  = fd_dcache_compact_wmark( ctx->shredcap_out_mem, link->dcache, link->mtu );
      ctx->shredcap_out_chunk  = ctx->shredcap_out_chunk0;

    } else if( 0==strcmp( link->name, "ping_sign" ) ) {
      ctx->ping_sign_out_idx = out_idx;
      ctx->ping_sign_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->ping_sign_out_chunk0 = fd_dcache_compact_chunk0( ctx->ping_sign_out_mem, link->dcache );
      ctx->ping_sign_out_wmark  = fd_dcache_compact_wmark( ctx->ping_sign_out_mem, link->dcache, link->mtu );
      ctx->ping_sign_out_chunk  = ctx->ping_sign_out_chunk0;

    } else if( 0==strcmp( link->name, "repair_sign" ) ) {
      fd_repair_out_ctx_t * repair_sign_out = &ctx->repair_sign_out_ctx[ ctx->repair_sign_cnt++ ];
      repair_sign_out->idx    = out_idx;
      repair_sign_out->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      repair_sign_out->chunk0 = fd_dcache_compact_chunk0( repair_sign_out->mem, link->dcache );
      repair_sign_out->wmark  = fd_dcache_compact_wmark( repair_sign_out->mem, link->dcache, link->mtu );
      repair_sign_out->chunk  = repair_sign_out->chunk0;
      repair_sign_out->in_idx = ctx->sign_repair_in_idx[ sign_repair_match_cnt ];
      repair_sign_out->max_credits = ctx->sign_repair_in_depth[ sign_repair_match_cnt ];
      repair_sign_out->credits = ctx->sign_repair_in_depth[ sign_repair_match_cnt ];
      sign_repair_match_cnt++;

    } else {
      FD_LOG_ERR(( "repair tile has unexpected output link %s", link->name ));
    }

  }
  if( FD_UNLIKELY( ctx->ping_sign_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing ping_sign link for keyguard client" ));
  if( FD_UNLIKELY( net_link_out_idx ==UINT_MAX ) ) FD_LOG_ERR(( "Missing repair_net link" ));
  if( FD_UNLIKELY( ctx->repair_sign_cnt != ctx->sign_repair_in_cnt ) ) {
    FD_LOG_ERR(( "Mismatch between repair_sign output links (%lu) and sign_repair input links (%lu)",
                 ctx->repair_sign_cnt, ctx->sign_repair_in_cnt ));
  }

  ctx->shred_tile_cnt = shred_tile_idx;
  FD_TEST( ctx->shred_tile_cnt == fd_topo_tile_name_cnt( topo, "shred" ) );

  /* Scratch mem setup */

  ctx->repair   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(), fd_repair_footprint() );
  ctx->forest   = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(), fd_forest_footprint( tile->repair.slot_max ) );
  ctx->fec_sigs = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_sig_align(), fd_fec_sig_footprint( 20 ) );
  ctx->reasm    = FD_SCRATCH_ALLOC_APPEND( l, fd_reasm_align(), fd_reasm_footprint( 1 << 20 ) );
  ctx->catchup  = FD_SCRATCH_ALLOC_APPEND( l, fd_catchup_align(), fd_catchup_footprint() );

  ctx->store = NULL;
  ulong store_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "store" );
  if( FD_LIKELY( store_obj_id!=ULONG_MAX ) ) { /* firedancer-only */
    ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
    FD_TEST( ctx->store->magic == FD_STORE_MAGIC );
  }

  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( FD_REPAIR_SCRATCH_MAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( FD_REPAIR_SCRATCH_DEPTH ) );

  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, FD_REPAIR_SCRATCH_MAX, FD_REPAIR_SCRATCH_DEPTH );

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ctx->repair_intake_addr.port = fd_ushort_bswap( tile->repair.repair_intake_listen_port );
  ctx->repair_serve_addr.port  = fd_ushort_bswap( tile->repair.repair_serve_listen_port  );

  ctx->repair_intake_listen_port = tile->repair.repair_intake_listen_port;
  ctx->repair_serve_listen_port = tile->repair.repair_serve_listen_port;

  ctx->net_id = (ushort)0;

  fd_ip4_udp_hdr_init( ctx->intake_hdr, FD_REPAIR_MAX_PACKET_SIZE, 0, ctx->repair_intake_listen_port );
  fd_ip4_udp_hdr_init( ctx->serve_hdr,  FD_REPAIR_MAX_PACKET_SIZE, 0, ctx->repair_serve_listen_port  );

  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ ctx->ping_sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->ping_sign_out_idx ] ];
  if( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                        sign_out->mcache,
                                                        sign_out->dcache,
                                                        sign_in->mcache,
                                                        sign_in->dcache,
                                                        sign_out->mtu ) ) == NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

  /* Repair set up */

  ctx->repair   = fd_repair_join ( fd_repair_new ( ctx->repair, ctx->repair_seed ) );
  ctx->forest   = fd_forest_join ( fd_forest_new ( ctx->forest, tile->repair.slot_max, ctx->repair_seed ) );
  ctx->fec_sigs = fd_fec_sig_join( fd_fec_sig_new( ctx->fec_sigs, 20 ) );
  ctx->reasm    = fd_reasm_join  ( fd_reasm_new  ( ctx->reasm, 1 << 20, 0 ) );
  ctx->catchup  = fd_catchup_join( fd_catchup_new( ctx->catchup ) );

  ctx->repair->next_nonce = 1;

  ctx->repair_iter = fd_forest_iter_init( ctx->forest );
  FD_TEST( fd_forest_iter_done( ctx->repair_iter, ctx->forest ) );

  ctx->turbine_slot  = 0;
  ctx->turbine_slot0 = ULONG_MAX;

  FD_LOG_INFO(( "repair my addr - intake addr: " FD_IP4_ADDR_FMT ":%u, serve_addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_intake_addr.addr ), fd_ushort_bswap( ctx->repair_intake_addr.port ),
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_serve_addr.addr ), fd_ushort_bswap( ctx->repair_serve_addr.port ) ));

  if( fd_repair_set_config( ctx->repair, &ctx->repair_config ) ) {
    FD_LOG_ERR( ( "error setting repair config" ) );
  }

  fd_repair_update_addr( ctx->repair, &ctx->repair_intake_addr, &ctx->repair_serve_addr );

  fd_histf_join( fd_histf_new( ctx->metrics->store_link_wait, FD_MHIST_SECONDS_MIN( REPAIR, STORE_LINK_WAIT ),
                                                              FD_MHIST_SECONDS_MAX( REPAIR, STORE_LINK_WAIT ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->store_link_work, FD_MHIST_SECONDS_MIN( REPAIR, STORE_LINK_WORK ),
                                                              FD_MHIST_SECONDS_MAX( REPAIR, STORE_LINK_WORK ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->slot_compl_time, FD_MHIST_SECONDS_MIN( REPAIR, SLOT_COMPLETE_TIME ),
                                                              FD_MHIST_SECONDS_MAX( REPAIR, SLOT_COMPLETE_TIME ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->response_latency, FD_MHIST_MIN( REPAIR, RESPONSE_LATENCY ),
                                                               FD_MHIST_MAX( REPAIR, RESPONSE_LATENCY ) ) );
  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_start( ctx->repair );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_repair_tile(
    out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)-1 );
  return sock_filter_policy_fd_repair_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

static inline void
metrics_write( fd_repair_tile_ctx_t * ctx ) {
  /* Repair-protocol-specific metrics */
  FD_MCNT_SET( REPAIR, RECV_CLNT_PKT,               ctx->metrics->recv_clnt_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_PKT,               ctx->metrics->recv_serv_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_CORRUPT_PKT,       ctx->metrics->recv_serv_corrupt_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_INVALID_SIGNATURE, ctx->metrics->recv_serv_invalid_signature );
  FD_MCNT_SET( REPAIR, RECV_SERV_FULL_PING_TABLE,   ctx->metrics->recv_serv_full_ping_table );
  FD_MCNT_SET( REPAIR, RECV_PKT_CORRUPTED_MSG,      ctx->metrics->recv_pkt_corrupted_msg );
  FD_MCNT_SET( REPAIR, REQUEST_PEERS,               ctx->repair->peer_cnt                );

  FD_MCNT_SET      ( REPAIR, SHRED_REPAIR_REQ,    ctx->metrics->send_pkt_cnt );
  FD_MCNT_ENUM_COPY( REPAIR, RECV_SERV_PKT_TYPES, ctx->metrics->recv_serv_pkt_types );
  FD_MCNT_ENUM_COPY( REPAIR, SENT_PKT_TYPES,      ctx->metrics->sent_pkt_types );

  FD_MHIST_COPY( REPAIR, STORE_LINK_WAIT,     ctx->metrics->store_link_wait );
  FD_MHIST_COPY( REPAIR, STORE_LINK_WORK,     ctx->metrics->store_link_work );
  FD_MHIST_COPY( REPAIR, SLOT_COMPLETE_TIME,  ctx->metrics->slot_compl_time );
  FD_MHIST_COPY( REPAIR, RESPONSE_LATENCY,    ctx->metrics->response_latency );

  ulong max_repaired_slot = 0;
  fd_forest_consumed_t const * consumed = fd_forest_consumed_const( ctx->forest );
  fd_forest_cns_t const *      conspool = fd_forest_conspool_const( ctx->forest );
  fd_forest_blk_t const *      pool     = fd_forest_pool_const( ctx->forest );
  for( fd_forest_consumed_iter_t iter = fd_forest_consumed_iter_init( consumed, conspool );
       !fd_forest_consumed_iter_done( iter, consumed, conspool );
       iter = fd_forest_consumed_iter_next( iter, consumed, conspool ) ) {
    fd_forest_cns_t const * ele = fd_forest_consumed_iter_ele_const( iter, consumed, conspool );
    fd_forest_blk_t const * ele_ = fd_forest_pool_ele_const( pool, ele->forest_pool_idx );
    if( ele_->slot > max_repaired_slot ) max_repaired_slot = ele_->slot;
  }
  FD_MCNT_SET( REPAIR, REPAIRED_SLOTS, max_repaired_slot );
}

/* TODO: This is not correct, but is temporary and will be fixed
   when the new store is implemented allowing the burst to be increased.
   The burst should be bounded by the number of stem_publishes that
   occur in a single frag loop. */
#define STEM_BURST (64UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_repair_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_repair_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_repair = {
  .name                     = "repair",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
