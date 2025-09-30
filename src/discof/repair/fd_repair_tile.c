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

    Note we do MANUAL credit tracking for these asynchronous sign links
    (see out_ctx_t definition).  In particular, credits tracks the
    RETURN sign_repair link.  This is because repair_sign is reliable,
    and sign_repair is unreliable.  If both links were reliable, and the
    links filled completely, stem would get into a deadlock. Neither
    repair or sign would have credits, which would prevent frags from
    getting polled in repair or sign, which would prevent any credits
    from getting returned back to the tiles.

    Thus the sign_repair link must be unreliable. This is mostly ok,
    because repair_sign is still reliable, so in theory repair_tile
    would never publish enough frags such that sign_repair would get
    overrun.

    However, there is a fairly common case that breaks this.  Consider
    the scenario

            repair_sign (depth 128)        sign_repair (depth 128)
    repair  ---------------------->  sign ------------------------> repair
            [rest free, r130, r129]       [r128, r127, ... , r1] (full)

    This would happen because repair is publishing too many requests too
    fast(common in catchup), and not polling enough frags from sign.
    Nothing is stopping repair from publishing more requests, because
    sign is functioning fast enough to handle the requests. However,
    nothing is stopping sign from polling the next request and signing
    it, and PUBLISHING it on the sign_repair link that is already full,
    because the sign_repair link is unreliable.

    In fact the only time we could stop repair from publishing more
    requests is if repair_sign was full, and repair would get
    backpressured, but sign would still be able to poll requests and
    overrun the sign_repair link.

    This is why we need to manually track credits for the sign_repair
    link. We must ensure that there are never more than 128 items in the
    ENTIRE repair_sign -> sign tile -> sign_repair work queue, else
    there is always a possibility of an overrun in the sign_repair link.

    To lose a frag to overrun isn't necessarily critical, but in general
    the repair tile relies on the fact that a signing task published to
    sign tile will always come back.  If we lose a frag to overrun, then
    there will be an entry in the pending signs structure that is never
    removed, and theoretically the map could fill up. Conceptually, with
    a reliable sign->repair->sign structure, there should be no eviction
    needed in this pending signs structure.

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
#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/store/fd_store.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../tower/fd_tower_tile.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/net/fd_net_headers.h"
#include "../../tango/fd_tango_base.h"

#include "../forest/fd_forest.h"
#include "fd_repair_metrics.h"
#include "fd_inflight.h"
#include "fd_repair.h"
#include "fd_policy.h"

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
#define IN_KIND_GENESIS (8)

#define MAX_IN_LINKS    (16)

#define MAX_REPAIR_PEERS   40200UL
#define MAX_BUFFER_SIZE    ( MAX_REPAIR_PEERS * sizeof( fd_shred_dest_wire_t ) )
#define MAX_SHRED_TILE_CNT ( 16UL )
#define MAX_SIGN_TILE_CNT  ( 16UL )

/* Maximum size of a network packet */
#define FD_REPAIR_MAX_PACKET_SIZE 1232
/* Max number of validators that can be actively queried */
#define FD_ACTIVE_KEY_MAX (FD_CONTACT_INFO_TABLE_SIZE)
/* Max number of pending shred requests */
#define FD_NEEDED_KEY_MAX (1<<20)
/* Max number of pending sign requests */
#define FD_REPAIR_PENDING_SIGN_REQ_MAX (1<<10)

/* static map from request type to metric array index */
static uint metric_index[FD_REPAIR_KIND_ORPHAN + 1] = {
  [FD_REPAIR_KIND_SHRED]         = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_WINDOW_IDX,
  [FD_REPAIR_KIND_HIGHEST_SHRED] = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_HIGHEST_WINDOW_IDX,
  [FD_REPAIR_KIND_ORPHAN]        = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_NEEDED_ORPHAN_IDX,
};

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  };
  fd_net_rx_bounds_t net_rx;
} in_ctx_t;

struct out_ctx {
  ulong         idx;
  fd_wksp_t *   mem;
  ulong         chunk0;
  ulong         wmark;
  ulong         chunk;

  ulong         in_idx;       /* index of the incoming link */
  ulong         credits;      /* available credits for link */
  ulong         max_credits;  /* maximum credits (depth) */

  /* credits / max_credits are used by the repair_sign link.  In
     particular, credits manages the RETURN sign_repair link.  See top
     of file for more details. */
};
typedef struct out_ctx out_ctx_t;

struct fd_fec_sig {
  ulong            key; /* map key. 32 msb = slot, 32 lsb = fec_set_idx */
  fd_ed25519_sig_t sig; /* Ed25519 sig identifier of the FEC. */
};
typedef struct fd_fec_sig fd_fec_sig_t;

#define MAP_NAME    fd_fec_sig
#define MAP_T       fd_fec_sig_t
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

/* Pending sign request structure for async request handling */
#define FD_REPAIR_PENDING_SIGN_REQ_MAX (1<<10) /* TODO: should be parameterized on link depth, not fixed. its on a branch somewhere*/
struct fd_repair_pending_sign {
  ulong       nonce;        /* map key, unique nonce */
  ulong       next;         /* used internally by fd_map_chain */
  ulong       buflen;
  union {
    uchar           buf[sizeof(fd_repair_msg_t)];
    fd_repair_msg_t msg;
  };
};
typedef struct fd_repair_pending_sign fd_repair_pending_sign_t;

#define MAP_NAME    fd_signs_map
#define MAP_KEY     nonce
#define MAP_T       fd_repair_pending_sign_t
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct ctx {
  long tsdebug; /* timestamp for debug printing */
  long tsprint; /* timestamp for printing */

  ulong repair_seed;

  fd_ip4_port_t repair_intake_addr;
  fd_ip4_port_t repair_serve_addr;

  fd_forest_t    * forest;
  fd_fec_sig_t   * fec_sigs;
  fd_store_t     * store;
  fd_policy_t    * policy;
  fd_inflights_t * inflight;
  fd_repair_t    * protocol;

  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  fd_stem_context_t * stem;

  uchar    in_kind[ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  int skip_frag;

  uint        net_out_idx;
  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  ulong snap_out_chunk;

  uint      shred_tile_cnt;
  out_ctx_t shred_out_ctx[ MAX_SHRED_TILE_CNT ];

  /* ping_sign link (to sign tile 0) - used for keyguard client */
  ulong       ping_sign_out_idx;
  fd_wksp_t * ping_sign_out_mem;
  ulong       ping_sign_out_chunk0;
  ulong       ping_sign_out_wmark;
  ulong       ping_sign_out_chunk;

  /* repair_sign links (to sign tiles 1+) - for round-robin distribution */
  ulong     repair_sign_cnt;
  out_ctx_t repair_sign_out_ctx[ MAX_SIGN_TILE_CNT ];

  ulong     sign_rrobin_idx;
  ulong     sign_request_seq; /* Request sequence tracking for async signing */

  /* Pending sign requests for async operations */
  fd_repair_pending_sign_t * signs_map;

  ushort net_id;
  /* Includes Ethernet, IP, UDP headers */
  uchar buffer[ MAX_BUFFER_SIZE ];
  fd_ip4_udp_hdrs_t intake_hdr[1];
  fd_ip4_udp_hdrs_t serve_hdr [1];

  fd_keyguard_client_t keyguard_client[1];

  ulong manifest_slot;
  struct {
    ulong send_pkt_cnt;
    ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_CNT];
    ulong repaired_slots;
    ulong current_slot;
    ulong sign_tile_unavail;
    fd_histf_t slot_compl_time[ 1 ];
    fd_histf_t response_latency[ 1 ];

    /* diagnostics */
    volatile ulong * last_replayed_slot;
  } metrics[ 1 ];

  /* Slot-level metrics */
  fd_repair_metrics_t * slot_metrics;

  ulong turbine_slot0;  // catchup considered complete after this slot
};
typedef struct ctx ctx_t;

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
  ulong total_sign_depth = tile->repair.repair_sign_depth * tile->repair.repair_sign_cnt;
  int   lg_sign_depth    = fd_ulong_find_msb( fd_ulong_pow2_up(total_sign_depth) ) + 1;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),            sizeof(ctx_t)                                                  );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(),         fd_repair_footprint   ()                                       );
  l = FD_LAYOUT_APPEND( l, fd_forest_align(),         fd_forest_footprint   ( tile->repair.slot_max )                );
  l = FD_LAYOUT_APPEND( l, fd_policy_align(),         fd_policy_footprint   ( FD_NEEDED_KEY_MAX, FD_ACTIVE_KEY_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_inflights_align(),      fd_inflights_footprint()                                       );
  l = FD_LAYOUT_APPEND( l, fd_fec_sig_align(),        fd_fec_sig_footprint  ( 20 )                                   );
  l = FD_LAYOUT_APPEND( l, fd_signs_map_align(),      fd_signs_map_footprint( lg_sign_depth )                        );
  l = FD_LAYOUT_APPEND( l, fd_repair_metrics_align(), fd_repair_metrics_footprint  ()                                );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* Pending Sign Request API

   These functions manage the pool and map of pending sign requests in
   the repair module. Each request is identified by a unique nonce,
   allowing for nonce to be used as a key in the map.

   All functions assume the repair context is valid and not used concurrently.
*/

fd_repair_pending_sign_t *
pending_sign_request_insert( ctx_t *                  ctx,
                             fd_repair_msg_t const *  msg ) {

  /* Check if there is any space for a new pending sign request. Should never fail as long as credit management is working. */
  if( FD_UNLIKELY( fd_signs_map_key_cnt( ctx->signs_map )==fd_signs_map_key_max( ctx->signs_map ) ) ) return NULL;

  fd_repair_pending_sign_t * pending = fd_signs_map_insert( ctx->signs_map, msg->shred.nonce );
  if( FD_UNLIKELY( !pending ) ) return NULL; // Not possible, unless the same nonce is used twice.
  pending->nonce  = msg->shred.nonce;
  pending->msg    = *msg;
  pending->buflen = fd_repair_sz( msg );
  return pending;
}

fd_repair_pending_sign_t *
pending_sign_request_query( ctx_t * ctx,
                            ulong   nonce ) {
  return fd_signs_map_query( ctx->signs_map, nonce, NULL );
}

int
pending_sign_request_remove( ctx_t * ctx,
                             ulong   nonce  ) {
  fd_repair_pending_sign_t * pending = fd_signs_map_query( ctx->signs_map, nonce, NULL );
  if( FD_UNLIKELY( !pending ) ) return -1;
  fd_signs_map_remove( ctx->signs_map, pending );
  return 0;
}

/* Wrapper for keyguard client sign */
static void
repair_signer_sync( ctx_t *       ctx,
                    uchar         signature[ static 64 ],
                    uchar const * buffer,
                    ulong         len,
                    int           sign_type ) {
  fd_keyguard_client_sign( ctx->keyguard_client, signature, buffer, len, sign_type );
}

/* Wrapper for publishing to the sign tile*/
static void
repair_signer_async( ctx_t *                    ctx,
                     fd_repair_pending_sign_t * pending,
                     int                        sign_type,
                     out_ctx_t *                sign_out) {
  ulong   nonce       = pending->nonce;
  ulong   preimage_sz = 0;
  uchar * preimage    = preimage_req( &pending->msg, &preimage_sz );
  uchar * dst         = fd_chunk_to_laddr( sign_out->mem, sign_out->chunk );
  fd_memcpy( dst, preimage, preimage_sz );

  ulong sig = ((ulong)nonce << 32) | (uint)sign_type;
  fd_stem_publish( ctx->stem, sign_out->idx, sig, sign_out->chunk, preimage_sz, 0UL, 0UL, 0UL );
  sign_out->chunk = fd_dcache_compact_next( sign_out->chunk, preimage_sz, sign_out->chunk0, sign_out->wmark );

  ctx->sign_request_seq = fd_seq_inc( ctx->sign_request_seq, 1UL );
}

static void
send_packet( ctx_t * ctx,
             fd_stem_context_t *    stem,
             int                    is_intake,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uint                   src_ip_addr,
             uchar const *          payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {
  ctx->metrics->send_pkt_cnt++;
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

/* Returns a sign_out context that has available credits.
   If no sign_out context has available credits, returns NULL. */

static out_ctx_t *
sign_avail_credits( ctx_t * ctx ) {
  out_ctx_t * sign_out = NULL;
  /* find sign_tile with maximum credits */
  ulong max_credits = 0;
  for( uint i = 0; i < ctx->repair_sign_cnt; i++ ) {
    if( ctx->repair_sign_out_ctx[i].credits > max_credits ) {
      max_credits = ctx->repair_sign_out_ctx[i].credits;
      sign_out = &ctx->repair_sign_out_ctx[i];
    }
  }
  return sign_out;
}

/* Signs a request asynchronously that will be published to the network
   later. If successful, adds it to the signs_map and publishes
   to the sign tile. If not, the request is skipped for now and will be
   retried later by the forest iterator. */
static void
fd_repair_send_request_async( ctx_t                 * ctx,
                              out_ctx_t             * sign_out,
                              fd_repair_msg_t const * msg ){
  /* Acquire and add a pending request from the pool */
  fd_repair_pending_sign_t * pending = pending_sign_request_insert( ctx, msg /*, now, recipient */);
  if( FD_UNLIKELY( !pending ) ) {
    return;
  }
  /* Sign and prepare the message directly into the pending buffer */
  repair_signer_async( ctx, pending, FD_KEYGUARD_SIGN_TYPE_ED25519, sign_out );

  ctx->metrics->sent_pkt_types[metric_index[msg->kind]]++;
  sign_out->credits--;
}

static inline int
before_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig ) {
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
during_frag( ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {
  ctx->skip_frag = 0;

  uint             in_kind =  ctx->in_kind[ in_idx ];
  in_ctx_t const * in_ctx  = &ctx->in_links[ in_idx ];

  if( FD_UNLIKELY( in_kind==IN_KIND_TOWER ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>in_ctx->mtu ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    uchar const * dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    fd_memcpy( ctx->buffer, dcache_entry, sz );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_GENESIS ) ) {
    return;
  }
  if( FD_UNLIKELY( in_kind==IN_KIND_NET ) ) {
    uchar const * dcache_entry = fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz );
    fd_memcpy( ctx->buffer, dcache_entry, sz );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>in_ctx->mtu ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    uchar const * dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    fd_memcpy( ctx->buffer, dcache_entry, sz );
    return;
  }

  if( FD_LIKELY  ( in_kind==IN_KIND_SHRED  ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>in_ctx->mtu ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    uchar const * dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    if( FD_LIKELY( sz > 0 ) ) fd_memcpy( ctx->buffer, dcache_entry, sz );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_STAKE ) ) {
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SNAP ) ) {
    if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) ctx->snap_out_chunk = chunk;
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SIGN ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>in_ctx->mtu ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    uchar const * dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    fd_memcpy( ctx->buffer, dcache_entry, sz );
    return;
  }

  FD_LOG_ERR(( "Frag from unknown link (kind=%u in_idx=%lu)", in_kind, in_idx ));
}

static inline void
after_snap( ctx_t * ctx,
                 ulong                  sig,
                 uchar const          * chunk ) {
  if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) return;
  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)chunk;

  fd_forest_init( ctx->forest, manifest->slot );
  FD_TEST( fd_forest_root_slot( ctx->forest )!=ULONG_MAX );
}

static inline void
after_contact( ctx_t * ctx, fd_gossip_update_message_t const * msg ) {
  fd_contact_info_t const * contact_info = msg->contact_info.contact_info;
  fd_ip4_port_t repair_peer = contact_info->sockets[ FD_CONTACT_INFO_SOCKET_SERVE_REPAIR ];
  if( FD_UNLIKELY( !repair_peer.addr || !repair_peer.port ) ) return;
  fd_policy_peer_t const * peer = fd_policy_peer_insert( ctx->policy, &contact_info->pubkey, &repair_peer );
  if( peer ) {
    /* The repair process uses a Ping-Pong protocol that incurs one
       round-trip time (RTT) for the initial repair request. To optimize
       this, we proactively send a placeholder Repair request as soon as we
       receive a peer's contact information for the first time, effectively
       prepaying the RTT cost. */
    fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &contact_info->pubkey );
    fd_repair_msg_t  * init = fd_repair_shred( ctx->protocol, &contact_info->pubkey, (ulong)fd_log_wallclock()/1000000L, 0, 0, 0 );
    ctx->metrics->sent_pkt_types[metric_index[FD_REPAIR_KIND_SHRED]]++;

    ulong   preimage_sz = 0;
    uchar * preimage    = preimage_req( init, &preimage_sz );
    repair_signer_sync( ctx, init->shred.sig, preimage, preimage_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

    ulong tsorig       = fd_frag_meta_ts_comp( fd_tickcount() );
    uint  src_ip4_addr = 0U; /* unknown */
    send_packet( ctx, ctx->stem, 1, peer->ip4, peer->port, src_ip4_addr, (uchar *)fd_type_pun( init ), fd_repair_sz( init ), tsorig );
  }
}

static inline void
after_sign( ctx_t             * ctx,
            ulong               in_idx,
            ulong               sig,
            fd_stem_context_t * stem ) {
  ulong nonce = sig >> 32;
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

  fd_repair_pending_sign_t * pending = pending_sign_request_query( ctx, nonce );
  if( FD_LIKELY( pending ) ) {
    fd_memcpy( pending->buf + 4, ctx->buffer, 64UL );
    uint  src_ip4 = 0U;

    fd_policy_peer_t * active = fd_policy_peer_query( ctx->policy, &pending->msg.shred.to );
    if( FD_UNLIKELY( !active ) ) { /* randomly test the below case */
      FD_LOG_INFO(( "Signed a message for %s, but it is no longer in the active peer list", FD_BASE58_ENC_32_ALLOCA( &pending->msg.shred.to ) ));
      /* Happens extremely rarely, so we can just pick a new peer and
         synchronously resign it right here. */
      fd_pubkey_t const * new_peer  = fd_policy_peer_select( ctx->policy );
      pending->msg.shred.to         = *new_peer;
      fd_repair_msg_t * init        = &pending->msg;
      ulong             preimage_sz = 0;
      uchar *           preimage    = preimage_req( init, &preimage_sz );
      repair_signer_sync( ctx, init->shred.sig, preimage, preimage_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );
    }
    fd_inflights_request_insert( ctx->inflight, pending->nonce,  &pending->msg.shred.to );
    fd_policy_peer_request_update( ctx->policy, &pending->msg.shred.to );
    send_packet( ctx, stem, 1, active->ip4, active->port, src_ip4, pending->buf, pending->buflen, fd_frag_meta_ts_comp( fd_tickcount() ) );

    pending_sign_request_remove( ctx, nonce );
  } else {
    FD_LOG_CRIT(( "No pending request found for nonce %lu", nonce ));
  }
}

static inline void
after_shred( ctx_t      * ctx,
             ulong        sig,
             fd_shred_t * shred,
             ulong        nonce ) {
  /* Insert the shred sig (shared by all shred members in the FEC set)
      into the map. */

  int is_code = fd_shred_is_code( fd_shred_type( shred->variant ) );
  int src = fd_disco_shred_out_shred_sig_is_turbine( sig ) ? SHRED_SRC_TURBINE : SHRED_SRC_REPAIR;
  if( FD_LIKELY( !is_code ) ) {
    long rtt = 0;
    fd_pubkey_t peer;
    if( FD_UNLIKELY( ( rtt = fd_inflights_request_remove( ctx->inflight, nonce, &peer ) ) > 0 ) ) {
      fd_policy_peer_response_update( ctx->policy, &peer, rtt );
      fd_histf_sample( ctx->metrics->response_latency, (ulong)rtt );
    }

    int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
    int ref_tick      = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
    fd_forest_blk_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off );
    fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, shred->idx, shred->fec_set_idx, slot_complete, ref_tick, src );

    /* Check if there are FECs to force complete. Algorithm: window
       through the idxs in interval [i, j). If j = next fec_set_idx
       then we know we can force complete the FEC set interval [i, j)
       (assuming it wasn't already completed based on `cmpl`). */

  } else {
    fd_forest_code_shred_insert( ctx->forest, shred->slot, shred->idx );
  }
}

static inline void
after_fec( ctx_t      * ctx,
           fd_shred_t * shred ) {

  /* When this is a FEC completes msg, it is implied that all the
     other shreds in the FEC set can also be inserted.  Shred inserts
     into the forest are idempotent so it is fine to insert the same
     shred multiple times. */

  int slot_complete = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );
  int ref_tick      = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;

  fd_forest_blk_t * ele = fd_forest_blk_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off );
  fd_forest_fec_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, shred->idx, shred->fec_set_idx, slot_complete, ref_tick );
  FD_TEST( ele ); /* must be non-empty */

  /* metrics for completed slots */
  if( FD_UNLIKELY( ele->complete_idx != UINT_MAX && ele->buffered_idx==ele->complete_idx &&
                   0==memcmp( ele->cmpl, ele->fecs, sizeof(fd_forest_blk_idxs_t) * fd_forest_blk_idxs_word_cnt ) ) ) {
    long now = fd_tickcount();
    long start_ts = ele->first_req_ts == 0 || ele->slot > ctx->turbine_slot0 ? ele->first_shred_ts : ele->first_req_ts;
    ulong duration_ticks = (ulong)(now - start_ts);
    fd_histf_sample( ctx->metrics->slot_compl_time, duration_ticks );
    fd_repair_metrics_add_slot( ctx->slot_metrics, ele->slot, start_ts, now, ele->repair_cnt, ele->turbine_cnt );
    FD_LOG_INFO(( "slot is complete %lu. num_data_shreds: %u, num_repaired: %u, num_turbine: %u, num_recovered: %u, duration: %.2f ms", ele->slot, ele->complete_idx + 1, ele->repair_cnt, ele->turbine_cnt, ele->recovered_cnt, (double)fd_metrics_convert_ticks_to_nanoseconds(duration_ticks) / 1e6 ));
  }
}

static inline void
after_net( ctx_t * ctx,
           ulong   sz  ) {
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
    if( FD_UNLIKELY( data_sz < sizeof(fd_repair_ping_t) ) ) {
      FD_LOG_WARNING(( "data_sz %lu < sizeof(fd_repair_ping_t) %lu", data_sz, sizeof(fd_repair_ping_t) ));
      return;
    }
    fd_repair_ping_t * res = (fd_repair_ping_t *)fd_type_pun( data );
    switch( res->kind ) {
    case FD_REPAIR_KIND_PING: {
      fd_repair_msg_t * pong = fd_repair_pong( ctx->protocol, &res->ping.hash );

      uchar pre_image[FD_REPAIR_PONG_PREIMAGE_SZ];
      preimage_pong( &res->ping.hash, pre_image, sizeof(pre_image) );
      repair_signer_sync( ctx, (uchar *)&pong->pong.sig, pre_image, FD_REPAIR_PONG_PREIMAGE_SZ, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );
      send_packet( ctx, ctx->stem, 1, peer_addr.addr, peer_addr.port, ip4->daddr, (uchar *)pong, fd_repair_sz( pong ), fd_frag_meta_ts_comp( fd_tickcount() ) );
      break;
    }
    default: FD_LOG_ERR(( "unhandled kind %u", (uint)res->kind ));
   }
  } else {
    FD_LOG_WARNING(( "Unexpectedly received packet for port %u", (uint)fd_ushort_bswap( dport ) ));
  }
}

static inline void
after_evict( ctx_t * ctx,
             ulong   sig ) {
  ulong spilled_slot        = fd_disco_shred_out_shred_sig_slot       ( sig );
  uint  spilled_fec_set_idx = fd_disco_shred_out_shred_sig_fec_set_idx( sig );
  uint  spilled_max_idx     = fd_disco_shred_out_shred_sig_data_cnt   ( sig );

  fd_forest_fec_clear( ctx->forest, spilled_slot, spilled_fec_set_idx, spilled_max_idx );
}

static void
after_frag( ctx_t * ctx,
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
  if( FD_UNLIKELY( in_kind==IN_KIND_GENESIS ) ) {
    fd_forest_init( ctx->forest, 0 );
    fd_policy_reset( ctx->policy, ctx->forest );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP ) ) {
    fd_gossip_update_message_t const * msg = (fd_gossip_update_message_t const *)fd_type_pun_const( ctx->buffer );
    if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) ){
      after_contact( ctx, msg );
    } else {
      fd_policy_peer_remove( ctx->policy, &msg->contact_info.contact_info->pubkey );
    }
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_TOWER ) ) {
    fd_tower_slot_done_t const * msg = (fd_tower_slot_done_t const *)fd_type_pun_const( ctx->buffer );
    if( FD_LIKELY( msg->new_root ) ) {
      fd_forest_publish( ctx->forest, msg->root_slot );
      fd_policy_reset  ( ctx->policy, ctx->forest );
    }
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SIGN ) ) {
    after_sign( ctx, in_idx, sig, stem );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) {
    /* There are 3 message types from shred:
        1. resolver evict - incomplete FEC set is evicted by resolver
        2. fec complete   - FEC set is completed by resolver. Also contains a shred.
        3. shred          - new shred

        Msgs 2 and 3 have a shred header in ctx->buffer */
    int resolver_evicted = sz == 0;
    int fec_completes    = sz == FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int);
    if( FD_UNLIKELY( resolver_evicted ) ) {
      after_evict( ctx, sig );
      return;
    }

    fd_shred_t * shred = (fd_shred_t *)fd_type_pun( ctx->buffer );
    uint         nonce = FD_LOAD(uint, ctx->buffer + fd_shred_header_sz( shred->variant ) );
    if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) {
      FD_LOG_INFO(( "shred %lu %u %u too old, ignoring", shred->slot, shred->idx, shred->fec_set_idx ));
      return;
    };
#   if LOGGING
    if( FD_UNLIKELY( shred->slot > ctx->metrics->current_slot ) ) {
      FD_LOG_INFO(( "\n\n[Turbine]\n"
                    "slot:             %lu\n"
                    "root:             %lu\n",
                    shred->slot,
                    fd_forest_root_slot( ctx->forest ) ));
    }
#   endif
    ctx->metrics->current_slot  = fd_ulong_max( shred->slot, ctx->metrics->current_slot );
    if( FD_UNLIKELY( ctx->turbine_slot0 == ULONG_MAX ) ) {
      ctx->turbine_slot0 = shred->slot;
      fd_repair_metrics_set_turbine_slot0( ctx->slot_metrics, shred->slot );
      fd_policy_set_turbine_slot0( ctx->policy, shred->slot );
    }

    if( FD_UNLIKELY( fec_completes ) ) {
      after_fec( ctx, shred );
    } else {
      /* Don't want to reinsert the shred sig for an already complete FEC set */
      fd_fec_sig_t * fec_sig = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx, NULL );
      if( FD_UNLIKELY( !fec_sig ) ) {
        fec_sig = fd_fec_sig_insert( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx );
        memcpy( fec_sig->sig, shred->signature, sizeof(fd_ed25519_sig_t) );
      }
      after_shred( ctx, sig, shred, nonce );
    }

    /* Check if there are FECs to force complete. Algorithm: window
       through the idxs in interval [i, j). If j = next fec_set_idx
       then we know we can force complete the FEC set interval [i, j)
       (assuming it wasn't already completed based on `cmpl`). */

    fd_forest_blk_t * blk = fd_forest_query( ctx->forest, shred->slot );
    if( blk ) {
      uint i = blk->consumed_idx + 1;
      for( uint j = i; j < blk->buffered_idx + 1; j++ ) {
        if( FD_UNLIKELY( fd_forest_blk_idxs_test( blk->fecs, j ) ) ) {
          fd_fec_sig_t * fec_sig  = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | i, NULL );
          if( FD_LIKELY( fec_sig ) ) {
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
      }
    }

    ulong max_repaired_slot = 0;
    fd_forest_conslist_t const * conslist = fd_forest_conslist_const( ctx->forest );
    fd_forest_cns_t const *      conspool = fd_forest_conspool_const( ctx->forest );
    fd_forest_blk_t const *      pool     = fd_forest_pool_const( ctx->forest );
    for( fd_forest_conslist_iter_t iter = fd_forest_conslist_iter_fwd_init( conslist, conspool );
         !fd_forest_conslist_iter_done( iter, conslist, conspool );
         iter = fd_forest_conslist_iter_fwd_next( iter, conslist, conspool ) ) {
      fd_forest_cns_t const * ele = fd_forest_conslist_iter_ele_const( iter, conslist, conspool );
      fd_forest_blk_t const * ele_ = fd_forest_pool_ele_const( pool, ele->forest_pool_idx );
      if( ele_->slot > max_repaired_slot ) max_repaired_slot = ele_->slot;
    }
    ctx->metrics->repaired_slots = max_repaired_slot;
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_STAKE ) ) {
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SNAP ) ) {
    after_snap( ctx, sig, fd_chunk_to_laddr( ctx->in_links[ in_idx ].mem, ctx->snap_out_chunk ) );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_NET ) ) {
    after_net( ctx, sz );
    return;
  }

}

static inline void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem FD_PARAM_UNUSED,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( ctx->forest->root != ULONG_MAX && now - ctx->tsprint > (long)1e9 ) ) {
    ulong replay_slot  = *ctx->metrics->last_replayed_slot;
    ulong replay_diff  = ctx->metrics->current_slot - replay_slot;
    ulong turbine_diff = ctx->metrics->current_slot - ctx->metrics->repaired_slots;
    FD_LOG_NOTICE(( "\n\n[Firedancer]\n"
                    "Replay:  %lu (-%lu)\n"
                    "Repair:  %lu (-%lu)\n"
                    "Shred:   %lu\n",
                    replay_slot, replay_diff,
                    ctx->metrics->repaired_slots, turbine_diff,
                    ctx->metrics->current_slot ));
    ctx->tsprint = now;
  }

  *charge_busy = 1;

  /* Verify that there is at least one sign tile with available credits.
     If not, we can't send any requests and leave early. */
  out_ctx_t * sign_out = sign_avail_credits( ctx );
  if( FD_UNLIKELY( !sign_out ) ) {
    ctx->metrics->sign_tile_unavail++;
    return;
  }

  fd_repair_msg_t const * cout = fd_policy_next( ctx->policy, ctx->forest, ctx->protocol, now, ctx->metrics->current_slot );
  if( FD_UNLIKELY( !cout ) ) return;

  fd_repair_send_request_async( ctx, sign_out, cout );

}

static inline void
during_housekeeping( ctx_t * ctx ) {
  (void)ctx;
# if DEBUG_LOGGING
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - ctx->tsdebug > (long)10e9 ) ) {
    fd_forest_print( ctx->forest );
    ctx->tsdebug = fd_log_wallclock();
  }
# endif
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  fd_memset( ctx, 0, sizeof(ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->repair.identity_key_path, /* pubkey only: */ 0 );
  fd_memcpy( ctx->identity_public_key.uc, identity_key + 32UL, sizeof(fd_pubkey_t) );

  FD_TEST( fd_rng_secure( &ctx->repair_seed, sizeof(ulong) ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong total_sign_depth = tile->repair.repair_sign_depth * tile->repair.repair_sign_cnt;
  int   lg_sign_depth    = fd_ulong_find_msb( fd_ulong_pow2_up(total_sign_depth) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),            sizeof(ctx_t)                                                  );
  ctx->protocol     = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),         fd_repair_footprint   ()                                       );
  ctx->forest       = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(),         fd_forest_footprint   ( tile->repair.slot_max )                );
  ctx->policy       = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),         fd_policy_footprint   ( FD_NEEDED_KEY_MAX, FD_ACTIVE_KEY_MAX ) );
  ctx->inflight     = FD_SCRATCH_ALLOC_APPEND( l, fd_inflights_align(),      fd_inflights_footprint()                                       );
  ctx->fec_sigs     = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_sig_align(),        fd_fec_sig_footprint  ( 20 )                                   );
  ctx->signs_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_signs_map_align(),      fd_signs_map_footprint( lg_sign_depth )                        );
  ctx->slot_metrics = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_metrics_align(), fd_repair_metrics_footprint()                                  );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() ) == (ulong)scratch + scratch_footprint( tile ) );

  ctx->protocol     = fd_repair_join        ( fd_repair_new        ( ctx->protocol, &ctx->identity_public_key                              ) );
  ctx->forest       = fd_forest_join        ( fd_forest_new        ( ctx->forest,   tile->repair.slot_max, ctx->repair_seed                ) );
  ctx->policy       = fd_policy_join        ( fd_policy_new        ( ctx->policy,   FD_NEEDED_KEY_MAX, FD_ACTIVE_KEY_MAX, ctx->repair_seed ) );
  ctx->inflight     = fd_inflights_join     ( fd_inflights_new     ( ctx->inflight                                                         ) );
  ctx->fec_sigs     = fd_fec_sig_join       ( fd_fec_sig_new       ( ctx->fec_sigs, 20                                                     ) );
  ctx->signs_map    = fd_signs_map_join     ( fd_signs_map_new     ( ctx->signs_map, lg_sign_depth                                         ) );
  ctx->slot_metrics = fd_repair_metrics_join( fd_repair_metrics_new( ctx->slot_metrics                                                     ) );

  /* Process in links */

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "repair tile has too many input links" ));

  uint  sign_repair_in_idx[ MAX_SIGN_TILE_CNT ] = {0};
  uint  sign_repair_idx  = 0;
  uint  sign_ping_in_idx = 0;
  ulong sign_link_depth  = 0;

  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if( 0==strcmp( link->name, "net_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in_links[ in_idx ].net_rx, link->dcache );
      continue;
    } else if( 0==strcmp( link->name, "sign_repair" ) ) {
      ctx->in_kind[ in_idx ]                  = IN_KIND_SIGN;
      sign_repair_in_idx[ sign_repair_idx++ ] = in_idx;
      sign_link_depth                         = link->depth;
    } else if( 0==strcmp( link->name, "sign_ping" )) {
      ctx->in_kind[ in_idx ] = IN_KIND_SIGN;
      sign_ping_in_idx       = in_idx;
    }
    else if( 0==strcmp( link->name, "gossip_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_GOSSIP;
    else if( 0==strcmp( link->name, "tower_out"    ) ) ctx->in_kind[ in_idx ] = IN_KIND_TOWER;
    else if( 0==strcmp( link->name, "shred_out"    ) ) ctx->in_kind[ in_idx ] = IN_KIND_SHRED;
    else if( 0==strcmp( link->name, "snap_out"     ) ) ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    else if( 0==strcmp( link->name, "replay_stake" ) ) ctx->in_kind[ in_idx ] = IN_KIND_STAKE;
    else if( 0==strcmp( link->name, "genesi_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_GENESIS;
    else FD_LOG_ERR(( "repair tile has unexpected input link %s", link->name ));

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;

    FD_TEST( fd_dcache_compact_is_safe( ctx->in_links[in_idx].mem, link->dcache, link->mtu, link->depth ) );
  }

  ctx->net_out_idx       = UINT_MAX;
  ctx->shred_tile_cnt    = 0;
  ctx->ping_sign_out_idx = UINT_MAX;
  ctx->repair_sign_cnt   = 0;
  ctx->sign_request_seq  = 0;
  ctx->sign_rrobin_idx   = 0;

  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];

    if( 0==strcmp( link->name, "repair_net" ) ) {

      if( ctx->net_out_idx!=UINT_MAX ) continue; /* only use first net link */
      ctx->net_out_idx    = out_idx;
      ctx->net_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, link->dcache );
      ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, link->dcache, link->mtu );
      ctx->net_out_chunk  = ctx->net_out_chunk0;

    } else if( 0==strcmp( link->name, "repair_shred" ) ) {

      out_ctx_t * shred_out = &ctx->shred_out_ctx[ ctx->shred_tile_cnt++ ];
      shred_out->idx        = out_idx;
      shred_out->mem        = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      shred_out->chunk0     = fd_dcache_compact_chunk0( shred_out->mem, link->dcache );
      shred_out->wmark      = fd_dcache_compact_wmark( shred_out->mem, link->dcache, link->mtu );
      shred_out->chunk      = shred_out->chunk0;

    } else if( 0==strcmp( link->name, "ping_sign" ) ) {

      ctx->ping_sign_out_idx    = out_idx;
      ctx->ping_sign_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->ping_sign_out_chunk0 = fd_dcache_compact_chunk0( ctx->ping_sign_out_mem, link->dcache );
      ctx->ping_sign_out_wmark  = fd_dcache_compact_wmark( ctx->ping_sign_out_mem, link->dcache, link->mtu );
      ctx->ping_sign_out_chunk  = ctx->ping_sign_out_chunk0;

    } else if( 0==strcmp( link->name, "repair_sign" ) ) {

      out_ctx_t * repair_sign_out  = &ctx->repair_sign_out_ctx[ ctx->repair_sign_cnt ];
      repair_sign_out->idx         = out_idx;
      repair_sign_out->mem         = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      repair_sign_out->chunk0      = fd_dcache_compact_chunk0( repair_sign_out->mem, link->dcache );
      repair_sign_out->wmark       = fd_dcache_compact_wmark( repair_sign_out->mem, link->dcache, link->mtu );
      repair_sign_out->chunk       = repair_sign_out->chunk0;
      repair_sign_out->in_idx      = sign_repair_in_idx[ ctx->repair_sign_cnt++ ]; /* match to the sign_repair input link */
      repair_sign_out->max_credits = sign_link_depth;
      repair_sign_out->credits     = sign_link_depth;
    } else {
      FD_LOG_ERR(( "repair tile has unexpected output link %s", link->name ));
    }
  }
  if( FD_UNLIKELY( ctx->ping_sign_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing ping_sign link for keyguard client" ));
  if( FD_UNLIKELY( ctx->net_out_idx==UINT_MAX       ) ) FD_LOG_ERR(( "Missing repair_net link" ));
  if( FD_UNLIKELY( ctx->repair_sign_cnt!=sign_repair_idx ) ) {
    FD_LOG_ERR(( "Mismatch between repair_sign output links (%lu) and sign_repair input links (%u)", ctx->repair_sign_cnt, sign_repair_idx ));
  }

  FD_TEST( ctx->shred_tile_cnt == fd_topo_tile_name_cnt( topo, "shred" ) );

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id[ sign_ping_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->ping_sign_out_idx ] ];
  if( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                       sign_out->mcache,
                                                       sign_out->dcache,
                                                       sign_in->mcache,
                                                       sign_in->dcache,
                                                       sign_out->mtu ) ) == NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

# if DEBUG_LOGGING
  if( fd_signs_map_key_max( ctx->signs_map ) < tile->repair.repair_sign_depth * tile->repair.repair_sign_cnt ) {
    FD_LOG_ERR(( "repair pending signs tracking map is too small: %lu < %lu.  Increase the key_max", fd_signs_map_key_max( ctx->signs_map ), tile->repair.repair_sign_depth * tile->repair.repair_sign_cnt ));
  }
# endif

  ctx->store = NULL;
  ulong store_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "store" );
  if( FD_LIKELY( store_obj_id!=ULONG_MAX ) ) { /* firedancer-only */
    ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
    FD_TEST( ctx->store->magic == FD_STORE_MAGIC );
  }

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->repair_intake_addr.port = fd_ushort_bswap( tile->repair.repair_intake_listen_port );
  ctx->repair_serve_addr.port  = fd_ushort_bswap( tile->repair.repair_serve_listen_port  );

  ctx->net_id = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->intake_hdr, FD_REPAIR_MAX_PACKET_SIZE, 0, tile->repair.repair_intake_listen_port );
  fd_ip4_udp_hdr_init( ctx->serve_hdr,  FD_REPAIR_MAX_PACKET_SIZE, 0, tile->repair.repair_serve_listen_port  );

  /* Repair set up */

  ctx->turbine_slot0 = ULONG_MAX;
  FD_LOG_INFO(( "repair my addr - intake addr: " FD_IP4_ADDR_FMT ":%u, serve_addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_intake_addr.addr ), fd_ushort_bswap( ctx->repair_intake_addr.port ),
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_serve_addr.addr ), fd_ushort_bswap( ctx->repair_serve_addr.port ) ));

  memset( ctx->metrics, 0, sizeof(ctx->metrics) );
  fd_topo_tile_t * replay_tile = &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ];
  if( FD_UNLIKELY( replay_tile == NULL || replay_tile->metrics == NULL ) ) {
    ctx->metrics->last_replayed_slot = &ctx->metrics->repaired_slots;
  } else {
    ulong volatile * const replay_metrics = fd_metrics_tile( replay_tile->metrics );
    ctx->metrics->last_replayed_slot = replay_metrics+MIDX( COUNTER, REPLAY, MAX_REPLAYED_SLOT );
  }

  fd_histf_join( fd_histf_new( ctx->metrics->slot_compl_time, FD_MHIST_SECONDS_MIN( REPAIR, SLOT_COMPLETE_TIME ),
                                                              FD_MHIST_SECONDS_MAX( REPAIR, SLOT_COMPLETE_TIME ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->response_latency, FD_MHIST_MIN( REPAIR, RESPONSE_LATENCY ),
                                                               FD_MHIST_MAX( REPAIR, RESPONSE_LATENCY ) ) );

  ctx->tsdebug = fd_log_wallclock();
  ctx->tsprint = fd_log_wallclock();
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
metrics_write( ctx_t * ctx ) {
  FD_MCNT_SET( REPAIR, CURRENT_SLOT,      ctx->metrics->current_slot );
  FD_MCNT_SET( REPAIR, REPAIRED_SLOTS,    ctx->metrics->repaired_slots );
  FD_MCNT_SET( REPAIR, REQUEST_PEERS,     fd_peer_pool_used( ctx->policy->peers.pool ) );
  FD_MCNT_SET( REPAIR, SIGN_TILE_UNAVAIL, ctx->metrics->sign_tile_unavail );

  FD_MCNT_SET      ( REPAIR, TOTAL_PKT_COUNT, ctx->metrics->send_pkt_cnt   );
  FD_MCNT_ENUM_COPY( REPAIR, SENT_PKT_TYPES,  ctx->metrics->sent_pkt_types );

  FD_MHIST_COPY( REPAIR, SLOT_COMPLETE_TIME, ctx->metrics->slot_compl_time );
  FD_MHIST_COPY( REPAIR, RESPONSE_LATENCY,   ctx->metrics->response_latency );
}

#undef DEBUG_LOGGING

/* TODO: This is not correct, but is temporary and will be fixed
   when fixed FEC 32 goes in, and we can finally get rid of force
   completes BS. */
#define STEM_BURST (64UL)

#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

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
