/* The rotor tile is responsible for repairing missing shreds that were
   not received via Turbine or missing slots of interest from Votor.
   The goal is to ensure that slots we "care" about have their FEC sets
   inserted into store.

   Most of rotor is copied over from repair tile, */

#define _GNU_SOURCE

#include "../genesis/fd_genesi_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_clock_tile.h"
#include "generated/fd_rotor_tile_seccomp.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_rnonce_ss.h"
#include "../../disco/shred/fd_shred_tile.h"
#include "fd_rotor_tile.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../replay/fd_replay_tile.h"
#include "../votor/fd_votor_tile.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../tango/fd_tango_base.h"

#include "../repair/fd_repair_metrics.h"
#include "../repair/fd_inflight.h"
#include "../repair/fd_repair.h"
#include "../repair/fd_policy.h"


#include "../../discof/chainer/fd_chainer.h"
#include "../../disco/store/fd_store.h"
#include "../../discof/replay/fd_block_marker.h"

#define DEBUG_LOGGING 0

#define IN_KIND_CONTACT (0)
#define IN_KIND_NET     (1)
#define IN_KIND_SHRED   (2)
#define IN_KIND_SIGN    (3)
#define IN_KIND_SNAP    (4)
#define IN_KIND_GOSSIP  (5)
#define IN_KIND_GENESIS (6)
#define IN_KIND_REPLAY  (7)
#define IN_KIND_VOTOR   (8) /* Alpenglow rooting */

#define MAX_IN_LINKS    (32)
#define MAX_SHRED_TILE_CNT ( 16UL )
#define MAX_SIGN_TILE_CNT  ( 16UL )

/* Max number of validators that can be actively queried */
#define FD_REPAIR_PEER_MAX (FD_CONTACT_INFO_TABLE_SIZE)

/* Max number of pending repair requests recently made to keep track of.
   Calculated generally as we estimate around 50k/s/core to sign
   requests. Assuming an over-provisioned 4 sign tiles just for repair,
   this means we can make up to ~200k requests per second.  With a dedup
   timeout of 80ms, this means we can make up to ~16k requests within
   the dedup timeout window.  We round up to the next power of two to
   get the dedup cache max.  Since we are sizing the dedup cache for a
   generous margin, and this number not particularly fragile or
   sensitive, we can leave it static. */
#define FD_REQLIM_CACHE_MAX (1<<20)

/* static map from request type to metric array index */
static uint metric_index[AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID + 1] = {
  [FD_REPAIR_KIND_PONG]          = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_PONG_IDX,
  [FD_REPAIR_KIND_SHRED]         = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_NEEDED_WINDOW_IDX,
  [FD_REPAIR_KIND_HIGHEST_SHRED] = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_NEEDED_HIGHEST_WINDOW_IDX,
  [FD_REPAIR_KIND_ORPHAN]        = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_NEEDED_ORPHAN_IDX,
  [AG_REPAIR_KIND_PARENT_FEC_COUNT]   = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_PARENT_FEC_COUNT_IDX,
  [AG_REPAIR_KIND_FEC_ROOT]           = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_FEC_ROOT_IDX,
  [AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID] = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_SHRED_BLOCK_ID_IDX,
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

  /* See repair tile for explanation of sign credit management */

  ulong in_idx;      /* index of the incoming link */
  ulong credits;     /* available credits for link */
  ulong max_credits; /* maximum credits (depth) */
};
typedef struct out_ctx out_ctx_t;

/* Data needed to sign and send a pong that is not contained in the
   pong msg itself. */

struct pong_data {
  fd_ip4_port_t  peer_addr;
  fd_hash_t      hash;
  uint           daddr;
  fd_pubkey_t    key;
};
typedef struct pong_data pong_data_t;

struct sign_req {
  ulong       key;        /* map key, ctx->pending_key_next */
  ulong       buflen;
  union {
    uchar           buf[sizeof(fd_repair_msg_t)];
    fd_repair_msg_t msg;
  };
  pong_data_t  pong_data; /* populated only for pong msgs */
};
typedef struct sign_req sign_req_t;

#define MAP_NAME         fd_signs_map
#define MAP_KEY          key
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) (k==ULONG_MAX)
#define MAP_T            sign_req_t
#define MAP_MEMOIZE      0
#include "../../util/tmpl/fd_map_dynamic.c"
struct sign_pending {
  fd_repair_msg_t msg;
  pong_data_t     pong_data; /* populated only for pong msgs */
};
typedef struct sign_pending sign_pending_t;

#define QUEUE_NAME       fd_signs_queue
#define QUEUE_T          sign_pending_t
#define QUEUE_MAX        (2*FD_REPAIR_PEER_MAX)
#include "../../util/tmpl/fd_queue.c"

#define QUEUE_NAME       ag_req_queue
#define QUEUE_T          fd_repair_msg_t
#define QUEUE_MAX        (FD_FEC_BLK_MAX)
#include "../../util/tmpl/fd_queue.c"

struct ctx {
  long tsdebug; /* timestamp for debug printing */
  long ts_diag; /* timestamp for catchup diagnostic printing */

  ulong repair_seed;

  /* When set (alpenglow only), the repair policy walk emits ONLY
     block-id requests (ShredForBlockId, driven by known block_ids and
     the event-driven getParentAndFecSetCount/getFecRoot path).  All
     legacy positional emissions -- HighestShred, window Shred, Orphan,
     and the orphan-pass shred-0 -- are suppressed.  Used to exercise /
     test the block-id repair + catchup path in isolation. */
  int   block_id_repair_only;

  /* When set, publish_fec_replay re-publishes the entire ancestry path
     of FECs -- from the chainer root down to the FEC being delivered,
     in root-to-target order -- on every delivery, instead of just the
     single delivered FEC.  Lets replay reconstruct a fork from root
     without relying on incremental delivery.  The path is queued onto
     deliver_queue and drained one FEC per after_credit. */
  int         deliver_from_root;
  out_ele_t * deliver_queue; /* sized to the chainer's FEC capacity */

  fd_keyswitch_t * keyswitch;
  int              halt_signing;

  fd_ip4_port_t repair_intake_addr;

  fd_chainer_t   * chainer; /* alpenglow chainer */
  fd_store_t     * store;   /* rotor publishes/removes FEC sets to/from the store */
  fd_store_map_t   store_map[1];
  fd_policy_t    * policy;
  fd_reqlim_t    * dedup;
  fd_inflights_t * inflights;
  fd_repair_t    * protocol;

  ulong enforce_fixed_fec_set; /* min slot where the feature is enforced */

  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  fd_stem_context_t * stem;

  uchar    in_kind[ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  int skip_frag;

  out_ctx_t net_out_ctx[1];

  out_ctx_t repair_out_ctx[1];

  /* repair_sign links (to sign tiles 1+) - for round-robin distribution */

  ulong     repair_sign_cnt;
  out_ctx_t repair_sign_out_ctx[ MAX_SIGN_TILE_CNT ];

  ulong     sign_rrobin_idx;

  /* Pending sign requests for async operations */

  uint             pending_key_next;
  sign_req_t     * signs_map;    /* contains any request currently in the repair->sign or sign->repair dcache */
  sign_pending_t * pong_queue;   /* contains any pong or initial warmup request waiting to be dispatched to repair->sign. Size is 2*FD_REPAIR_PEER_MAX */
  fd_repair_msg_t * ag_req_queue; /* contains any alpenglow request waiting to be dispatched to sign->repair. Sized to FD_FEC_BLK_MAX */

  ushort net_id;

  /* Buffers for incoming unreliable frags */
  uchar net_buf[ FD_NET_MTU ];
  uchar sign_buf[ sizeof(fd_ed25519_sig_t) ];

  /* Store chunk for incoming reliable frags */
  ulong chunk;
  ulong snap_out_chunk; /* store second to last chunk for snap_out */

  fd_ip4_udp_hdrs_t intake_hdr[1];

  fd_rnonce_ss_t repair_nonce_ss[1];
  uint ag_nonce; /* simple incrementing nonce for alpenglow requests */

  ulong manifest_slot;
  struct {
    ulong send_pkt_cnt;
    ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_CNT];
    ulong current_slot;
    ulong old_shred;
    ulong last_requested_slot;
    ulong last_requested_orphan;
    ulong sign_tile_unavail;
    ulong rerequest;
    ulong malformed_ping;
    ulong unknown_peer_ping;
    ulong fail_sigverify_ping;
    fd_histf_t slot_compl_time[ 1 ];
    fd_histf_t response_latency[ 1 ];
    ulong blk_evicted;
    ulong blk_failed_insert;

    ulong slot_evicted;
    ulong slot_evicted_by;
    ulong slot_failed_insert;

    ulong failed_chain_verify_cnt;
    ulong failed_chain_verify_slot;

    /* failed verify of alpenglow block-id repair */
    ulong failed_shred_block_id_cnt;
    ulong failed_fec_root_cnt;
    ulong failed_parent_fec_count_cnt;

    ulong fecs_delivered; /* diagnostic: FECs pushed to replay via out_queue */
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
  ulong total_sign_depth = tile->rotor.repair_sign_depth * tile->rotor.repair_sign_cnt;
  int   lg_sign_depth    = fd_ulong_find_msb( fd_ulong_pow2_up(total_sign_depth) ) + 1;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),            sizeof(ctx_t)                                                      );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(),         fd_repair_footprint     ()                                         );
  l = FD_LAYOUT_APPEND( l, fd_chainer_align(),        fd_chainer_footprint    ( tile->rotor.slot_max )                  );
  l = FD_LAYOUT_APPEND( l, fd_policy_align(),         fd_policy_footprint     ( FD_REPAIR_PEER_MAX )                     );
  l = FD_LAYOUT_APPEND( l, fd_reqlim_align(),         fd_reqlim_footprint     ( FD_REQLIM_CACHE_MAX )                    );
  l = FD_LAYOUT_APPEND( l, fd_inflights_align(),      fd_inflights_footprint  ()                                         );
  l = FD_LAYOUT_APPEND( l, fd_signs_map_align(),      fd_signs_map_footprint  ( lg_sign_depth )                          );
  l = FD_LAYOUT_APPEND( l, fd_signs_queue_align(),    fd_signs_queue_footprint()                                         );
  l = FD_LAYOUT_APPEND( l, ag_req_queue_align(),      ag_req_queue_footprint()                                           );
  l = FD_LAYOUT_APPEND( l, fd_repair_metrics_align(), fd_repair_metrics_footprint()                                      );
  l = FD_LAYOUT_APPEND( l, out_queue_align(),         out_queue_footprint( (ulong)tile->rotor.slot_max * FD_CHAINER_SLOT_VER_MAX * FD_FEC_BLK_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* Below functions manage the current pending sign requests. */

static sign_req_t *
sign_map_insert( ctx_t *                 ctx,
                 fd_repair_msg_t const * msg,
                 pong_data_t const     * opt_pong_data ) {
  if( FD_UNLIKELY( fd_signs_map_key_cnt( ctx->signs_map )==fd_signs_map_key_max( ctx->signs_map ) ) ) return NULL;

  sign_req_t * pending = fd_signs_map_insert( ctx->signs_map, ctx->pending_key_next++ );
  if( FD_UNLIKELY( !pending ) ) return NULL; /* Not possible, unless the same key is used twice. */
  pending->msg    = *msg;
  pending->buflen = fd_repair_sz( msg );
  if( FD_UNLIKELY( opt_pong_data ) ) pending->pong_data = *opt_pong_data;
  return pending;
}

static int
sign_map_remove( ctx_t * ctx,
                 ulong   key ) {
  sign_req_t * pending = fd_signs_map_query( ctx->signs_map, key, NULL );
  if( FD_UNLIKELY( !pending ) ) return -1;
  fd_signs_map_remove( ctx->signs_map, pending );
  return 0;
}

static void
send_packet( ctx_t             * ctx,
             fd_stem_context_t * stem,
             uint                dst_ip_addr,
             ushort              dst_port,
             uint                src_ip_addr,
             uchar const *       payload,
             ulong               payload_sz,
             ulong               tsorig ) {
  ctx->metrics->send_pkt_cnt++;
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_ctx->mem, ctx->net_out_ctx->chunk );
  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *ctx->intake_hdr;

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->saddr       = src_ip_addr;
  ip4->daddr       = dst_ip_addr;
  ip4->net_id      = fd_ushort_bswap( ctx->net_id++ );
  ip4->check       = 0U;
  ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  ip4->check       = fd_ip4_hdr_check_fast( ip4 );

  fd_udp_hdr_t * udp = hdr->udp;
  udp->net_dport = dst_port;
  udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );
  hdr->udp->check = 0U;

  ulong tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig       = fd_disco_netmux_sig( dst_ip_addr, dst_port, dst_ip_addr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);
  ulong chunk     = ctx->net_out_ctx->chunk;
  fd_stem_publish( stem, ctx->net_out_ctx->idx, sig, chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_ctx->chunk = fd_dcache_compact_next( chunk, packet_sz, ctx->net_out_ctx->chunk0, ctx->net_out_ctx->wmark );
}

/* Returns a sign_out context with max available credits.
   If no sign_out context has available credits, returns NULL. */
static out_ctx_t *
sign_avail_credits( ctx_t * ctx ) {
  out_ctx_t * sign_out = NULL;
  ulong max_credits = 0;
  for( uint i = 0; i < ctx->repair_sign_cnt; i++ ) {
    if( ctx->repair_sign_out_ctx[i].credits > max_credits ) {
      max_credits =  ctx->repair_sign_out_ctx[i].credits;
      sign_out    = &ctx->repair_sign_out_ctx[i];
    }
  }
  return sign_out;
}

/* Prepares the signing preimage and publishes a signing request that
   will be signed asynchronously by the sign tile.  The signed data will
   be returned via dcache as a frag. */
static void
fd_repair_send_sign_request( ctx_t                 * ctx,
                             out_ctx_t             * sign_out,
                             fd_repair_msg_t const * msg,
                             pong_data_t     const * opt_pong_data ) {

  if( FD_UNLIKELY( ctx->halt_signing ) ) FD_LOG_CRIT(( "can't dispatch sign requests while halting signing" ));

  /* New sign request */
  sign_req_t * pending = sign_map_insert( ctx, msg, opt_pong_data );
  if( FD_UNLIKELY( !pending ) ) return;

  ulong   sig         = 0;
  ulong   preimage_sz = 0;
  uchar * dst         = fd_chunk_to_laddr( sign_out->mem, sign_out->chunk );

  if( FD_UNLIKELY( msg->kind == FD_REPAIR_KIND_PONG ) ) {
    uchar pre_image[FD_REPAIR_PONG_PREIMAGE_SZ];
    preimage_pong( &opt_pong_data->hash, pre_image );
    preimage_sz = FD_REPAIR_PONG_PREIMAGE_SZ;
    fd_memcpy( dst, pre_image, preimage_sz );
    sig = ((ulong)pending->key << 32) | (uint)FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519;
  } else {
    /* Sign and prepare the message directly into the pending buffer */
    uchar * preimage = preimage_req( &pending->msg, &preimage_sz );
    fd_memcpy( dst, preimage, preimage_sz );
    sig = ((ulong)pending->key << 32) | (uint)FD_KEYGUARD_SIGN_TYPE_ED25519;
  }

  fd_stem_publish( ctx->stem, sign_out->idx, sig, sign_out->chunk, preimage_sz, 0UL, 0UL, 0UL );
  sign_out->chunk = fd_dcache_compact_next( sign_out->chunk, preimage_sz, sign_out->chunk0, sign_out->wmark );

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
  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) return fd_int_if( ctx->chainer->root==ULONG_MAX, -1, 0 ); /* not ready to read frag */
  if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  if( FD_UNLIKELY( in_kind==IN_KIND_REPLAY ) ) return sig!=REPLAY_SIG_MISSING_FEC;
  return 0;
}

static void
during_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig,
             ulong   chunk,
             ulong   sz,
             ulong   ctl ) {
  ctx->skip_frag = 0;

  uint             in_kind =  ctx->in_kind[ in_idx ];
  in_ctx_t const * in_ctx  = &ctx->in_links[ in_idx ];
  ctx->chunk = chunk;

  if( FD_UNLIKELY( in_kind==IN_KIND_NET ) ) {
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
    uchar const * dcache_entry = fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz );
    fd_memcpy( ctx->net_buf, dcache_entry, sz );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_GENESIS ) ) {
    FD_TEST( sizeof(fd_genesis_meta_t)<=sig );
    return;
  }

  if( FD_UNLIKELY( sz!=0UL && ( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>in_ctx->mtu ) ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu] in kind %u", chunk, sz, in_ctx->chunk0, in_ctx->wmark, in_kind ));

  if( FD_UNLIKELY( in_kind==IN_KIND_SNAP ) ) {
    if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) ctx->snap_out_chunk = chunk;
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SIGN ) ) {
    /* sign_repair is unreliable, so we copy the frag for convention.
       Theoretically impossible to overrun. */
    uchar const * dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    fd_memcpy( ctx->sign_buf, dcache_entry, sz );
    return;
  }
}

static inline void
after_snap( ctx_t * ctx,
            ulong         sig,
            uchar const * chunk ) {
  if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) return;
  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)chunk;

  fd_chainer_init( ctx->chainer, manifest->slot, (fd_hash_t *)fd_type_pun( manifest->block_id ) );
}

static inline void
after_gossip( ctx_t * ctx, fd_gossip_update_message_t const * msg, ulong sig ) {
  switch( sig ) {
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
      fd_policy_peer_remove( ctx->policy, fd_type_pun_const( msg->origin ) );
      break;
    }
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
      fd_gossip_contact_info_t const * contact_info = msg->contact_info->value;
      fd_ip4_port_t repair_peer;
      repair_peer.addr = contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR ].is_ipv6 ? 0U : contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR ].ip4;
      repair_peer.port = contact_info->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR ].port;
      if( FD_UNLIKELY( !repair_peer.addr || !repair_peer.port ) ) return;
      fd_policy_peer_t const * peer = fd_policy_peer_upsert( ctx->policy, fd_type_pun_const( msg->origin ), &repair_peer );
      if( FD_LIKELY( peer && !fd_signs_queue_full( ctx->pong_queue ) ) ) {
        /* The repair process uses a Ping-Pong protocol that incurs one
           round-trip time (RTT) for the initial repair request.  To
           optimize this, we proactively send a placeholder repair request
           as soon as we receive a peer's contact information for the first
           time, effectively prepaying the RTT cost. */
        fd_repair_msg_t * init = fd_repair_shred( ctx->protocol, fd_type_pun_const( msg->origin ), (ulong)fd_log_wallclock()/1000000L, 0, 0, 0 );
        fd_signs_queue_push( ctx->pong_queue, (sign_pending_t){ .msg = *init } );
      }
      break;
    }
    default: FD_LOG_ERR(( "bad gossip sig %lu", sig ));
  }
}

static inline void
after_sign( ctx_t             * ctx,
            ulong               in_idx,
            ulong               sig,
            fd_stem_context_t * stem ) {
  ulong pending_key = sig >> 32;
  //FD_LOG_NOTICE(( "after_sign: %lu", pending_key ));
  /* Look up the pending request. Since the repair_sign links are
     reliable, the incoming sign_repair fragments represent a complete
     set of the previously sent outgoing messages. However, with
     multiple sign tiles, the responses may arrive interleaved. */

  /* Find which sign tile sent this response and increment its credits */
  for( uint i = 0; i < ctx->repair_sign_cnt; i++ ) {
    if( ctx->repair_sign_out_ctx[i].in_idx == in_idx ) {
      if( FD_LIKELY( ctx->repair_sign_out_ctx[i].credits < ctx->repair_sign_out_ctx[i].max_credits ) ) ctx->repair_sign_out_ctx[i].credits++;
      break;
    }
  }

  sign_req_t * pending_ = fd_signs_map_query( ctx->signs_map, pending_key, NULL );
  if( FD_UNLIKELY( !pending_ ) ) FD_LOG_CRIT(( "No pending request found for key %lu", pending_key )); /* implies either bad programmer error or something happened with sign tile */

  sign_req_t   pending[1] = { *pending_ }; /* Make a copy of the pending request so we can sign_map_remove immediately. */
  sign_map_remove( ctx, pending_key );

  /* This is a pong message */
  if( FD_UNLIKELY( pending->msg.kind == FD_REPAIR_KIND_PONG ) ) {
    fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &pending->pong_data.key );
    if( FD_LIKELY( peer && peer->ping ) ) peer->ping--; /* prevent underflow if the peer was removed/readded */

    fd_memcpy( pending->msg.pong.sig, ctx->sign_buf, 64UL );
    send_packet( ctx, stem, pending->pong_data.peer_addr.addr, pending->pong_data.peer_addr.port, pending->pong_data.daddr, pending->buf, fd_repair_sz( &pending->msg ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    return;
  }

  /* Inject the signature into the pending request */
  fd_memcpy( pending->buf + 4, ctx->sign_buf, 64UL );
  uint  src_ip4 = 0U;

  /* This is a warmup message */
  if( FD_UNLIKELY( pending->msg.kind == FD_REPAIR_KIND_SHRED && pending->msg.shred.slot == 0 ) ) {
    fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &pending->msg.shred.to );
    if( FD_UNLIKELY( peer ) ) send_packet( ctx, stem, peer->ip4, peer->port, src_ip4, pending->buf, pending->buflen, fd_frag_meta_ts_comp( fd_tickcount() ) );
    else { /* This is a warmup request for a peer that is no longer active.  There's no reason to pick another peer for a warmup rq, so just drop it. */ }
    return;
  }

  /* This is a regular repair shred request

     We need to ensure we always send out any shred requests we have,
     because policy_next has no way to revisit a shred.  But the fact
     that peers can drop out of the peer list makes this complicated.
     If the peer is still there (common), it's fine.  If the peer is not
     there, we can add this request to the inflights table, pretend
     we've sent it and let the inflight timeout request it down the
     line. */

  fd_policy_peer_t * active = fd_policy_peer_query( ctx->policy, &pending->msg.shred.to );
  if( FD_UNLIKELY( !active ) ) {
     /* Already added to the inflights table, pretend we've sent it
        and let the inflight timeout request it down the line. */
    return;
  }
  /* Happy path - all is well, our peer didn't drop out from beneath us. */
  if( FD_UNLIKELY( pending->msg.kind == FD_REPAIR_KIND_ORPHAN ) ) ctx->metrics->last_requested_orphan = pending->msg.orphan.slot;
  else                                                            ctx->metrics->last_requested_slot   = pending->msg.shred.slot;

  send_packet( ctx, stem, active->ip4, active->port, src_ip4, pending->buf, pending->buflen, fd_frag_meta_ts_comp( fd_tickcount() ) );
}

/* takes ping after hdr strip.  ip4/udp point at the stripped headers
   (needed to address the pong back to the sender). */
static inline void
after_ping( ctx_t *              ctx,
            uchar const *        data,
            ulong                data_sz,
            fd_ip4_hdr_t const * ip4,
            fd_udp_hdr_t const * udp ) {
  fd_ip4_port_t peer_addr = { .addr=ip4->saddr, .port=udp->net_sport };

  fd_repair_ping_t ping[1];
  int err = fd_repair_ping_de( ping, data, data_sz );
  if( FD_UNLIKELY( err ) ) {
    ctx->metrics->malformed_ping++;
    return;
  }

  fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &ping->ping.from );
  if( FD_UNLIKELY( !peer ) ) {
    ctx->metrics->unknown_peer_ping++;
    return;
  }
  if( FD_UNLIKELY( peer->ping ) ) return;
  if( FD_UNLIKELY( fd_signs_queue_full( ctx->pong_queue ) ) ) return;

  fd_sha512_t sha[1];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( ping->ping.hash.uc, 32UL, ping->ping.sig, ping->ping.from.uc, sha ) ) ) {
    ctx->metrics->fail_sigverify_ping++;
    return;
  }

  /* Any gossip peer can send a ping, but they are bounded to at most
     one ping in the queue so they can't evict others' pings without
     multiple gossip identities. */

  fd_repair_msg_t * pong = fd_repair_pong( ctx->protocol, &ping->ping.hash );
  fd_signs_queue_push( ctx->pong_queue, (sign_pending_t){ .msg = *pong, .pong_data = { .peer_addr = peer_addr, .hash = ping->ping.hash, .daddr = ip4->daddr, .key = ping->ping.from } } );
  peer->ping++;
}

/* This is a response for an Alpenglow repair request type, which
   returns metadata about a verified slot - not a shred.  Specifically,
   responses for parent_and_fec_set_count and fec_set_root are routed
   directly to repair tile, as they do not contain a shred. */

static inline void
after_alpen_meta_repair( ctx_t * ctx,
                         ag_repair_response_t * response ) {
  uint nonce = response->nonce;
  fd_meta_inflight_t * request = fd_meta_inflights_request_match( ctx->inflights, nonce );
  if( FD_UNLIKELY( !request ) ) return;

  fd_pubkey_t to = {0};
  if( FD_UNLIKELY( request->slot <= ctx->chainer->root ) ) goto cleanup; /* rooted in flight: obsolete */

  if( FD_UNLIKELY( ( response->kind == AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT && request->kind != AG_REPAIR_KIND_PARENT_FEC_COUNT ) ||
                   ( response->kind == AG_REPAIR_RESPONSE_FEC_SET_ROOT         && request->kind != AG_REPAIR_KIND_FEC_ROOT ) ) ) {
    // recreate original message for req_queue
    fd_repair_msg_t * msg = ( request->kind==AG_REPAIR_KIND_PARENT_FEC_COUNT )
                              ? ag_repair_parent_and_fec_set_count( ctx->protocol, &to, (ulong)(fd_log_wallclock()/(long)1e6), ctx->ag_nonce++, request->slot, &request->block_id )
                              : ag_repair_fec_set_root            ( ctx->protocol, &to, (ulong)(fd_log_wallclock()/(long)1e6), ctx->ag_nonce++, request->slot, &request->block_id, request->fec_set_idx );
    ag_req_queue_push( ctx->ag_req_queue, *msg );
    goto cleanup;
  }

  /* Each case verifies the response's merkle proof chains up to the block
     id we requested before handing the metadata to the chainer */
  switch( response->kind ) {
    case AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT: {
      ag_parent_fec_count_res_t * parent_fec_set_res = &response->parent_fec_set_res;

      if( FD_UNLIKELY( ag_repair_parent_fec_count_verify( parent_fec_set_res, &request->block_id ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( request->block_id.uc, block_id );
        FD_LOG_INFO(( "failed to verify ParentFecSetCount response for nonce: %u, slot: %lu, block_id: %s", nonce, request->slot, block_id ));
        ctx->metrics->failed_parent_fec_count_cnt++;
        fd_repair_msg_t * msg = ag_repair_parent_and_fec_set_count( ctx->protocol, &to, (ulong)(fd_log_wallclock()/(long)1e6), ctx->ag_nonce++, request->slot, &request->block_id );
        ag_req_queue_push( ctx->ag_req_queue, *msg );
        goto cleanup;
      }

      fd_chainer_verified_parent_fec_count( ctx->chainer, request->slot, &request->block_id, parent_fec_set_res->fec_set_count, parent_fec_set_res->parent_slot, &parent_fec_set_res->parent_block_id );

      ulong now_ms = (ulong)(fd_log_wallclock()/(long)1e6);
      for( uint i = 0; i < parent_fec_set_res->fec_set_count; i++ ) {
        uint              req_nonce = ctx->ag_nonce++;

        fd_repair_msg_t * msg = ag_repair_fec_set_root( ctx->protocol, &to, now_ms, req_nonce,
                                                        request->slot, &request->block_id, i*FD_FEC_SHRED_CNT );
        ag_req_queue_push( ctx->ag_req_queue, *msg );
      }
      break;
    }
    case AG_REPAIR_RESPONSE_FEC_SET_ROOT: {
      ag_fec_root_res_t * fec_set_root = &response->fec_set_root;

      if( FD_UNLIKELY( ag_repair_fec_set_root_verify( fec_set_root, &request->block_id, request->fec_set_idx ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( request->block_id.uc, block_id );
        FD_LOG_INFO(( "failed to verify FecSetRoot response for nonce: %u, slot: %lu, fec_set_idx: %u, block_id: %s", nonce, request->slot, request->fec_set_idx, block_id ));
        ctx->metrics->failed_fec_root_cnt++;
        fd_repair_msg_t * msg = ag_repair_fec_set_root( ctx->protocol, &to, (ulong)(fd_log_wallclock()/(long)1e6), ctx->ag_nonce++, request->slot, &request->block_id, request->fec_set_idx );
        ag_req_queue_push( ctx->ag_req_queue, *msg );
        goto cleanup;
      }

      /* The response carries only the 20-byte FEC-set root prefix */
      fd_hash_t fec_root_mr = {0};
      memcpy( fec_root_mr.uc, fec_set_root->root, FD_SHRED_MERKLE_NODE_SZ );
      fd_chainer_verified_hash_insert( ctx->chainer, request->slot, &request->block_id, request->fec_set_idx, &fec_root_mr );
      break;
    }
  }

cleanup:
  fd_meta_inflight_pool_ele_release( ctx->inflights->ag_pool, request );
  return;
}

/* ag_parse_parent_marker pulls the block's DECLARED parent out of the
   BlockMarker that a batch-opening data shred carries: a BlockComponent
   whose entry count is 0 is a marker, and the BlockHeaderV1 (shred 0) /
   UpdateParentV1 (a later batch) variants both carry (parent_slot,
   parent_block_id).  Alpenglow chains on this, never on parent_off,
   because the block_id double merkle binds exactly these bytes.

   Both variants are ~54 bytes, so they always fit in the opening shred
   and never need cross-shred reassembly.  Returns 1 and fills the out
   params on a well formed marker, 0 otherwise.
   https://github.com/anza-xyz/agave/blob/master/entry/src/block_component.rs */

static int
ag_parse_parent_marker( fd_shred_t const * shred,
                        ulong *            out_parent_slot,
                        fd_hash_t *        out_parent_block_id ) {
  uchar const * payload = fd_shred_data_payload( shred );
  ulong         sz      = fd_shred_payload_sz( shred );

  fd_block_marker_t marker[1];
  ulong marker_sz;
  int err = fd_block_marker_de( marker, payload, sz, &marker_sz );
  if( FD_UNLIKELY( err ) ) return 0;

  if( marker->variant==HEADER ) {
    memcpy( out_parent_slot,         &marker->header.parent_slot,        8UL );
    memcpy( out_parent_block_id->uc,  marker->header.parent_block_id.uc, 32UL );
    return 1;
  }

  if( marker->variant==UPDATE_PARENT ) {
    memcpy( out_parent_slot,         &marker->update_parent.new_parent_slot,        8UL );
    memcpy( out_parent_block_id->uc,  marker->update_parent.new_parent_block_id.uc, 32UL );
    return 1;
  }

  return 0; /* FOOTER / GENESIS_CERTIFICATE carry no parent */
}

static inline void
after_alpen_shred( ctx_t      * ctx,
                   ulong        sig,
                   fd_shred_t * shred,
                   ulong        nonce,
                   fd_hash_t *  mr ) {
  if( FD_UNLIKELY( shred->slot <= ctx->chainer->root ) ) return;
  if( FD_UNLIKELY( fd_shred_is_code( fd_shred_type( shred->variant ) ) ) ) return; /* TODO */

  if( FD_UNLIKELY( fd_shred_sig_src( sig )==SHRED_SIG_SRC_REPAIR ) ) {
    if( FD_UNLIKELY( !(nonce & 0x80000000UL) ) ) {
      /* not normal repair */
      if( FD_UNLIKELY( !(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) ) ) return;
    } else {
      /* Ordinary per-shred repair.  Requests for different versions of
         the same (slot, idx) share the time-bucketed rnonce, so scan
         all inflights with this key.  Prefer an entry whose block-id
         version verifies against this shred's merkle root; fall back to
         a plain positional (block_id zero) entry. */
      uint            fec_set_idx     = shred->idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
      fd_inflight_t * match           = NULL;
      fd_inflight_t * match_zero      = NULL;

      for( fd_inflight_t * ele = fd_inflights_request_query( ctx->inflights, nonce, shred->slot, shred->idx );
                           ele;
                           ele = fd_inflights_request_query_next( ctx->inflights, ele ) ) {
        if( FD_UNLIKELY( fd_hash_check_zero( &ele->block_id ) ) ) {
          if( FD_LIKELY( !match_zero || ele->timestamp_ns<match_zero->timestamp_ns ) ) match_zero = ele;
        } else if( FD_LIKELY( fd_chainer_shred_for_block_id_verify( ctx->chainer, shred->slot, fec_set_idx, &ele->block_id, mr ) ) ) {
          if( FD_LIKELY( !match || ele->timestamp_ns<match->timestamp_ns ) ) match = ele;
        }
      }
      if( FD_UNLIKELY( !match ) ) match = match_zero;

      if( FD_LIKELY( match ) ) {
        fd_pubkey_t peer     = match->pubkey;
        fd_hash_t   block_id = match->block_id;
        long        rtt      = fd_inflights_request_remove( ctx->inflights, match );
        fd_policy_peer_response_update( ctx->policy, &peer, rtt );
        fd_histf_sample( ctx->metrics->response_latency, (ulong)rtt );

        /* A FEC created from a FecSetRoot repair response is keyed by
           only its 20-byte root prefix.  Now that a real shred delivered
           the full merkle root, re-key it so the following shred_insert
           (and later shreds) associate with this FEC via the full root. */
        if( FD_LIKELY( !fd_hash_check_zero( &block_id ) ) ) {
          fd_chainer_fec_rekey( ctx->chainer, shred->slot, &block_id, fec_set_idx, mr );
        }
      } else {
        return;
      }
    }
  }

  /* Parent discovery.  Shred 0 of a slot has the block-header marker (its
     own component/FEC set), carrying the declared parent_slot and the
     parent's double-merkle block_id.

     TODO: mid-block UpdateParent markers (at FEC-set boundaries after a
     DATA_COMPLETE) also rebind the double-merkle parent; not handled
     here yet. */
  ulong       parent_slot        = AG_UNKNOWN_SLOT;
  fd_hash_t   parent_block_id    = {0};
  if( FD_UNLIKELY( shred->idx == 0 ) ) {
    if( FD_UNLIKELY( !ag_parse_parent_marker( shred, &parent_slot, &parent_block_id ) ) ) {
      /* What to do with this slot if theres no block header?  Replay
         handles this fine downstream - it would just immediately mark
         the block dead. */
      FD_LOG_WARNING(( "invalid block header in slot: %lu, ignoring shred 0", shred->slot ));
      return;
    }
  }

  int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
  fd_chainer_shred_insert( ctx->chainer, shred->slot, shred->idx, slot_complete, mr, parent_slot, &parent_block_id );
}

/* fec_completes */
static inline void
after_alpen_fec( ctx_t      * ctx,
                 ulong        sig,
                 fd_shred_t * shred,
  fd_hash_t  * mr ) {
  if( FD_UNLIKELY( shred->slot <= ctx->chainer->root ) ) {
    fd_store_remove( ctx->store, ctx->store_map, mr );
    return;
  }

  int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
  int data_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE);
  if( fd_chainer_fec_complete( ctx->chainer, shred->slot, shred->fec_set_idx, slot_complete, data_complete, sig==SHRED_SIG_FEC_COMPLETE_LEADER, mr ) ) {
    fd_store_remove( ctx->store, ctx->store_map, mr );
  };
}

static inline void
after_votor_notar_fallback( ctx_t * ctx,
                            fd_votor_repair_t const * nf ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( ctx->chainer, nf->slot, &nf->block_id );
  if( FD_LIKELY( slotv ) ) return; /* we already have this NF version recorded, no need for action */
  /* else, we don't have this NF version, we need to repair for it. */
  fd_chainer_notar_fallback( ctx->chainer, nf->slot, nf->block_id );

  uint                nonce = ctx->ag_nonce++;
  fd_pubkey_t const * peer  = fd_policy_peer_select( ctx->policy );
  if( FD_LIKELY( peer ) ) {
    ulong now_ms = (ulong)(fd_log_wallclock()/(long)1e6);
    fd_repair_msg_t * msg = ag_repair_parent_and_fec_set_count( ctx->protocol,
                                                                peer,
                                                                now_ms,
                                                                nonce,
                                                                nf->slot,
                                                                &nf->block_id );
    if( FD_UNLIKELY( fd_signs_queue_full( ctx->pong_queue ) ) ) FD_LOG_CRIT(( "TODO: separate to different queue" ));
    fd_signs_queue_push( ctx->pong_queue, (sign_pending_t){ .msg = *msg } );
  }
  fd_meta_inflights_request_insert( ctx->inflights, nonce, AG_REPAIR_KIND_PARENT_FEC_COUNT, nf->slot, &nf->block_id, 0U );
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx,
            ulong               seq    FD_PARAM_UNUSED,
            ulong               sig,
            ulong               sz,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub FD_PARAM_UNUSED,
            fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  ctx->stem = stem;
  in_ctx_t const * in_ctx  = &ctx->in_links[ in_idx ];
  uint             in_kind = ctx->in_kind[ in_idx ];

  switch( in_kind ) {
    /* Unreliable frags */
    case IN_KIND_NET:  {
      fd_eth_hdr_t * eth; fd_ip4_hdr_t * ip4; fd_udp_hdr_t * udp;
      uchar * data; ulong data_sz;
      if( FD_UNLIKELY( !fd_ip4_udp_hdr_strip( ctx->net_buf, sz, &data, &data_sz, &eth, &ip4, &udp ) ) ) {
        ctx->metrics->malformed_ping++; // todo generalize
        return;
      }

      if( FD_LIKELY( data_sz == sizeof(fd_repair_ping_t) )) {
        after_ping( ctx, data, data_sz, ip4, udp );
      } else { /* alpen repair response */
        ag_repair_response_t response[1];
        if( FD_UNLIKELY( ag_repair_response_de( response, data, data_sz ) ) ) return; /* malformed */
        after_alpen_meta_repair( ctx, response );
      }
      break;
    }
    case IN_KIND_REPLAY: {
      ctx->deliver_from_root = 1;
      break;
    }
    case IN_KIND_SIGN: {
      after_sign( ctx, in_idx, sig, stem );
      break;
    }
    /* Reliable frags read directly from dcache */
    case IN_KIND_SNAP: {
      after_snap( ctx, sig, fd_chunk_to_laddr( ctx->in_links[ in_idx ].mem, ctx->snap_out_chunk ) );
      break;
    }
    case IN_KIND_GENESIS: {
      fd_genesis_meta_t const * meta = (fd_genesis_meta_t const *)fd_type_pun_const( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
      fd_hash_t block_id = {0};
      if( meta->bootstrap ) fd_chainer_init( ctx->chainer, 0, &block_id );
      break;
    }
    case IN_KIND_GOSSIP: {
      fd_gossip_update_message_t const * msg = (fd_gossip_update_message_t const *)fd_type_pun_const( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
      after_gossip( ctx, msg, sig );
      break;
    }
    case IN_KIND_VOTOR: {
      switch( sig ) {
        case FD_VOTOR_SIG_ROOTED: {
          fd_votor_rooted_t const * rooted = fd_chunk_to_laddr_const( in_ctx->mem, ctx->chunk );
          if( FD_LIKELY( rooted->slot > ctx->chainer->root ) ) fd_chainer_publish( ctx->chainer, rooted->slot, &rooted->block_id, ctx->store );
          break;
        }
        case FD_VOTOR_SIG_REPAIR: {
          fd_votor_repair_t const * nf = fd_chunk_to_laddr_const( in_ctx->mem, ctx->chunk );
          if( FD_UNLIKELY( nf->slot <= ctx->chainer->root ) ) return;
          after_votor_notar_fallback( ctx, nf );
          break;
        }
        default: return;
      }
      break;
    }
    case IN_KIND_SHRED: {

      /* There are 3 message types from shred:
          1. resolver evict - incomplete FEC set is evicted by resolver
          2. fec complete   - FEC set is completed by resolver. Also contains a shred.
          3. shred          - new shred

          Msgs 2 and 3 have a shred header in the dcache.  Msg 1 is empty. */

      uint sig_src = fd_shred_sig_src( sig );
      int  sig_res = fd_shred_sig_res( sig );

      if( FD_UNLIKELY( sig_src==SHRED_SIG_FEC_EVICTED ) ) {
        fd_fec_evicted_t * evicted = (fd_fec_evicted_t *)fd_type_pun( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
        fd_chainer_fec_evicted( ctx->chainer, evicted->slot, evicted->fec_set_idx, &evicted->merkle_root );
        return;
      }

      uchar * src = fd_chunk_to_laddr( in_ctx->mem, ctx->chunk );
      fd_shred_base_t * shred_msg = (fd_shred_base_t *)fd_type_pun( src );
      fd_shred_t      * shred     = &shred_msg->shred; /* completes & shred messages all have a shred header at the same offset (after merkle root) */

      if( FD_UNLIKELY( shred->slot > ctx->metrics->current_slot && sig_src == SHRED_SIG_SRC_TURBINE ) ) {
        FD_LOG_INFO(( "[Turbine] slot: %lu, root: %lu", shred->slot, ctx->chainer->root ));
        ctx->metrics->current_slot = shred->slot;
      }

      if( FD_UNLIKELY( ctx->turbine_slot0 == ULONG_MAX && sig_src == SHRED_SIG_SRC_TURBINE ) ) {
        ctx->turbine_slot0 = shred->slot;

        ulong slot_delta;
        int cf = __builtin_usubl_overflow( ctx->turbine_slot0, ctx->chainer->root, &slot_delta );
        if( FD_UNLIKELY( cf || slot_delta > fd_slotv_pool_max( ctx->chainer->slotv_pool ) ) ) {
          /* TODO: It's most optimal to define the catchup target as the
             first notarize cert we receive. But we currently dont have
             any info in the rotor tile to know if we are unstaked or
             not. And if we are unstaked, we will not be getting any
             certs from votor.  So for now we will just use the first
             turbine shred we receive. */

          FD_LOG_ERR(( "Catchup slot distance exceeds the repair buffer: target %lu - snapshot slot %lu > %lu. "
                       "Restart with a more recent snapshot or increase config rotor.slot_max", ctx->turbine_slot0, ctx->chainer->root, fd_slotv_pool_max( ctx->chainer->slotv_pool ) ));
          return;
        }
        fd_repair_metrics_set_turbine_slot0( ctx->slot_metrics, shred->slot );
        fd_policy_set_turbine_slot0( ctx->policy, shred->slot );

        /* On first turbine shred, seed repair by queuing highest_shred
           requests for slots between snapshot and turbine_slot0. This
           bypasses forest entirely and dispatches directly via the sign
           queue. Cap at half queue capacity to leave room for pongs.
           Skipped in block-id-only mode: catchup slots have no known
           block_id yet, so positional seeding is not used there. */
        ulong root = ctx->chainer->root;
        if( FD_LIKELY( root != ULONG_MAX && shred->slot > root && !ctx->block_id_repair_only ) ) {
          ulong capacity = fd_signs_queue_max( ctx->pong_queue ) - fd_signs_queue_cnt( ctx->pong_queue );
          ulong seed_cnt = fd_ulong_min( shred->slot-root, capacity/2 );
          long  now_ms   = fd_log_wallclock()/(long)1e6;
          for( ulong i=1; i<=seed_cnt; i++ ) {
            ulong slot = root + i;
            fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
            if( FD_UNLIKELY( !peer ) ) break;
            fd_repair_msg_t * msg = fd_repair_shred( ctx->protocol, peer, (ulong)now_ms, 0, slot, 0 );
            if( FD_LIKELY( msg ) )  fd_signs_queue_push( ctx->pong_queue, (sign_pending_t){ .msg = *msg } );
          }
        }
      }

      if( FD_UNLIKELY( sig==SHRED_SIG_FEC_COMPLETE || sig==SHRED_SIG_FEC_COMPLETE_LEADER ) ) {
        fd_fec_complete_t * complete_msg = (fd_fec_complete_t *)fd_type_pun( src );
        after_alpen_fec( ctx, sig, &complete_msg->last_shred_hdr, &complete_msg->merkle_root );
      } else if( FD_LIKELY( sig_res!=SHRED_SIG_RESULT_EQVOC ) ) {
        after_alpen_shred( ctx, sig, shred, shred_msg->rnonce, &shred_msg->merkle_root );
      }
      return;
    }
    default: FD_LOG_ERR(( "bad in_kind %u", in_kind )); /* Should never reach here since before_frag should have filtered out any unexpected frags. */
  }
}

/* Defer a request by adding it to the outstanding inflights table so it
   can be re-requested after a timeout window.  Nonce is 0 because these
   are not real requests made to the network, and cannot be matched
   by a shred response. */
static void
defer_inflight_request( ctx_t * ctx, ulong slot, ulong shred_idx, fd_hash_t const * hash ) {
  if( FD_LIKELY( hash && fd_hash_check_zero( hash ) ) ) hash = NULL;
  fd_hash_t target = {0};
  if( FD_UNLIKELY( hash ) ) target = *hash;

  fd_inflight_key_t key  = { .slot = slot, .shred_idx = shred_idx, .nonce = 0 };
  fd_inflight_t *   pool = ctx->inflights->pool;
  for( ulong idx = fd_inflight_map_idx_query_const( ctx->inflights->map, &key, ULONG_MAX, pool );
             idx != ULONG_MAX;
             idx = fd_inflight_map_idx_next_const( idx, ULONG_MAX, pool ) ) {
    if( fd_hash_eq( &pool[ idx ].block_id, &target ) ) return; /* this version already in map */
  }

  fd_hash_t peer = { .ul[0] = 0 };
  fd_inflights_request_insert( ctx->inflights, 0, &peer, slot, shred_idx, hash );
}

/* Should be called for any shred request made.  block_id is the
   ShredForBlockId version being repaired, or NULL for a plain
   positional shred request. */
static void
record_inflight_request( ctx_t * ctx, ulong nonce, fd_pubkey_t const * peer, ulong slot, ulong shred_idx, fd_hash_t const * block_id ) {
  if( FD_LIKELY( block_id && fd_hash_check_zero( block_id ) ) ) block_id = NULL;
  fd_inflights_request_insert( ctx->inflights, nonce, peer, slot, shred_idx, block_id );
  fd_policy_peer_request_update( ctx->policy, peer );
}

static void
ag_policy_block_id_next( ctx_t * ctx, out_ctx_t * sign_out, long now, int * charge_busy ) {
  fd_chainer_t       * chainer    = ctx->chainer;
  fd_chainer_slotv_t * pool       = chainer->slotv_pool;
  fd_sched_ele_t     * sched_pool = chainer->sched_pool;
  fd_sched_repair_t  * treap      = chainer->repair_treap;

  long now_ms = now/(long)1e6;

  /* (1) Redispatch an aged-out metadata request under a fresh nonce, so
     a late response to the old request is simply unmatched. */
  if( FD_UNLIKELY( fd_meta_inflights_should_drain( ctx->inflights, now ) ) ) {
    fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
    if( FD_LIKELY( peer ) ) {
      *charge_busy = 1;
      ulong nonce; uint kind; ulong slot; fd_hash_t block_id; uint fec_set_idx;
      fd_meta_inflights_request_pop( ctx->inflights, &nonce, &kind, &slot, &block_id, &fec_set_idx );

      if( FD_UNLIKELY( slot <= ctx->chainer->root ) ) return; /* rooted while outstanding: drop, don't re-request */

      uint              new_nonce = ctx->ag_nonce++;
      fd_repair_msg_t * msg       = ( kind==AG_REPAIR_KIND_PARENT_FEC_COUNT )
        ? ag_repair_parent_and_fec_set_count( ctx->protocol, peer, (ulong)now_ms, new_nonce, slot, &block_id )
        : ag_repair_fec_set_root            ( ctx->protocol, peer, (ulong)now_ms, new_nonce, slot, &block_id, fec_set_idx );
      fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
      fd_meta_inflights_request_insert( ctx->inflights, new_nonce, kind, slot, &block_id, fec_set_idx );
      return;
    }
  }

  /* (2) Redispatch an aged-out ShredForBlockId request at DEDUP_TIMEOUT
     intervals. */
  if( FD_UNLIKELY( fd_inflights_should_drain( ctx->inflights, now ) ) ) {
    ulong nonce; ulong slot; ulong shred_idx; fd_hash_t block_id;
    *charge_busy = 1;
    fd_inflights_request_pop( ctx->inflights, &nonce, &slot, &block_id, &shred_idx );

    fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( ctx->chainer, slot, &block_id );
    if( FD_UNLIKELY( slot > ctx->chainer->root && slotv && !fd_chainer_shred_test( ctx->chainer, slotv, (uint)shred_idx ) ) ) {
      /* The re-request needs the prior getFecRoot to still be present:
         without it the response would be dropped by
         fd_chainer_shred_for_block_id_verify. */
      uint fec_set_idx = (uint)shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
      int  fec_present = !!fd_chainer_fec_query( ctx->chainer, slot, fec_set_idx, &block_id );

      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      if( FD_UNLIKELY( !peer || !fec_present || fd_reqlim_next( ctx->dedup, fd_reqlim_key( FD_REPAIR_KIND_SHRED, slot, (uint)shred_idx ), now ) ) ) {
        /* No peers available (or getFecRoot evicted), park the request
           in inflights. */
        defer_inflight_request( ctx, slot, shred_idx, &block_id );
      } else {
        ctx->metrics->rerequest++;
        nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, slot, (uint)shred_idx, now );
        fd_repair_msg_t * msg = ag_repair_shred_block_id( ctx->protocol, peer, (ulong)now_ms, (uint)nonce, slot, &block_id, (uint)shred_idx );
        fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
        record_inflight_request( ctx, nonce, peer, slot, shred_idx, &block_id );
        return;
      }
    }
  }

  /* (3) No new requests allowed if inflights is near capacity. */
  if( FD_UNLIKELY( fd_inflights_outstanding_free( ctx->inflights ) <= fd_signs_map_key_cnt( ctx->signs_map ) ) ) return;

  /* Orphan (ancestry) pass: for orphans whose block_id is known, issue
     getParentAndFecSetCount to discover ancestry.  Orphans without a
     block_id are skipped -- there is no positional fallback in this
     mode. */
  fd_sched_orphan_t * otreap = chainer->orphan_treap;
  fd_sched_orphan_fwd_iter_t onext;
  for( fd_sched_orphan_fwd_iter_t oit = fd_sched_orphan_fwd_iter_init( otreap, sched_pool );
                                       !fd_sched_orphan_fwd_iter_done( oit ); oit = onext ) {
    onext = fd_sched_orphan_fwd_iter_next( oit, sched_pool );
    fd_chainer_slotv_t * o = fd_slotv_pool_ele( pool, fd_sched_orphan_fwd_iter_ele( oit, sched_pool )->slotv_idx );

    /* parent present or covered by the snapshot -> resolved */
    if( o->parent_slot!=AG_UNKNOWN_SLOT &&
        ( o->parent_slot<=chainer->root || fd_chainer_slot_query( chainer, o->parent_slot ) ) ) {
      fd_chainer_orphan_remove( chainer, o );
      continue;
    }

    if( FD_UNLIKELY( fd_hash_check_zero( &o->block_id ) ) ) continue; /* need block_id first */

    ulong oslot = o->slot;
    if( !fd_reqlim_next( ctx->dedup, fd_reqlim_key( AG_REPAIR_KIND_PARENT_FEC_COUNT, oslot, 0 ), now ) ) {
      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      if( FD_UNLIKELY( !peer ) ) break;
      uint nonce = ctx->ag_nonce++;
      fd_repair_msg_t * msg = ag_repair_parent_and_fec_set_count( ctx->protocol, peer, (ulong)now_ms, nonce, oslot, &o->block_id );
      *charge_busy = 1;
      fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
      fd_meta_inflights_request_insert( ctx->inflights, nonce, AG_REPAIR_KIND_PARENT_FEC_COUNT, oslot, &o->block_id, 0U );
      return;
    }
  }

  /* Shred-fill pass: only versions whose block_id is known are
     repairable; the tip / fec count is learned from
     getParentAndFecSetCount, not HighestShred. */
  for( fd_sched_repair_fwd_iter_t it = fd_sched_repair_fwd_iter_init( treap, sched_pool );
                                      !fd_sched_repair_fwd_iter_done( it ); ) {
    fd_chainer_slotv_t * e = fd_slotv_pool_ele( pool, fd_sched_repair_fwd_iter_ele( it, sched_pool )->slotv_idx );
    it = fd_sched_repair_fwd_iter_next( it, sched_pool );

    ulong slot = e->slot;

    if( FD_UNLIKELY( fd_hash_check_zero( &e->block_id ) ) ) continue; /* need block_id first */

    if( e->buffered_idx!=UINT_MAX &&
      ( e->highest_requested==UINT_MAX || e->buffered_idx > e->highest_requested ) )
      e->highest_requested = e->buffered_idx;

    if( FD_UNLIKELY( e->complete_idx==UINT_MAX ) ) continue; /* fec count comes from getParentAndFecSetCount */

    /* make individual shred request */

    uint idx = e->highest_requested+1;
    while( FD_UNLIKELY( idx<FD_SHRED_BLK_MAX && fd_chainer_shred_test( chainer, e, idx ) ) ) idx++;

    if( FD_UNLIKELY( idx > e->complete_idx ) ) {
      e->highest_requested = idx;
      fd_chainer_repair_remove( chainer, e );
      continue;
    };

    /* Gate on prior getFecRoot being present.  The ShredForBlockId
       response would race the getFecRoot and be dropped by
       fd_chainer_shred_for_block_id_verify, then re-requested only
       after the reqlim timeout.  Retry this idx on a later walk, once
       the root lands. */
    uint fec_set_idx = idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
    if( FD_UNLIKELY( !fd_chainer_fec_query( chainer, slot, fec_set_idx, &e->block_id ) ) ) continue;

    fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
    if( FD_UNLIKELY( !peer ) ) break;
    ulong nonce           = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, slot, idx, now );
    fd_repair_msg_t * msg = ag_repair_shred_block_id( ctx->protocol, peer, (ulong)now_ms, (uint)nonce, slot, &e->block_id, idx );
    *charge_busy = 1;
    fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
    record_inflight_request( ctx, nonce, peer, slot, idx, &e->block_id );
    e->highest_requested = idx;
    return;
  }
}

/* ag_policy_next is the standard Alpenglow repair pipeline, driven once
   per after_credit (ag_policy_block_id_next is the block-id-only
   variant).  In priority order it: (1) redispatches an outstanding
   metadata request (ParentAndFecSetCount / FecSetRoot) that has aged
   past its drain timeout, (2) redispatches an outstanding shred request
   likewise, (3) gates on inflight capacity, then (4) walks the chainer's
   slotv treaps to issue new requests -- an orphan (ancestry) pass
   followed by a min-slot-first shred-fill pass.

   The shred-fill walk issues a request for each still-missing shred
   exactly once, advancing highest_requested only on a shred we already
   have or a request we actually send, so a budget cutoff never strands
   an index; fd_inflights owns all re-drive and a fully-requested slotv
   is popped from the treap.  At most one request is sent per call.

   TODO revise & refactor later */
static void
ag_policy_next( ctx_t * ctx, out_ctx_t * sign_out, long now, int * charge_busy ) {
  fd_chainer_t       * chainer    = ctx->chainer;
  fd_chainer_slotv_t * pool       = chainer->slotv_pool;
  fd_sched_ele_t     * sched_pool = chainer->sched_pool;
  fd_sched_repair_t  * treap      = chainer->repair_treap;

  long now_ms = now/(long)1e6;

  /* (1) Redispatch an aged-out metadata request under a fresh nonce, so
     a late response to the old request is simply unmatched. */
  if( FD_UNLIKELY( fd_meta_inflights_should_drain( ctx->inflights, now ) ) ) {
    fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
    if( FD_LIKELY( peer ) ) {
      *charge_busy = 1;
      ulong nonce; uint kind; ulong slot; fd_hash_t block_id; uint fec_set_idx;
      fd_meta_inflights_request_pop( ctx->inflights, &nonce, &kind, &slot, &block_id, &fec_set_idx );

      /* conditions where we can toss this request:
          1. rooted this slot
          2. this is a ParentFecSetCount request, but we already have that information.
          3. this is a FecSetRoot request, but we already have that information. */
      if( FD_UNLIKELY( slot <= ctx->chainer->root ) ) return; /* rooted while outstanding: drop, don't re-request */
      fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( ctx->chainer, slot, &block_id );
      if(  kind==AG_REPAIR_KIND_PARENT_FEC_COUNT && slotv && slotv->complete_idx!=UINT_MAX && slotv->parent_slot!=AG_UNKNOWN_SLOT ) return; /* we already have the ParentFecSetCount */
      if(  kind==AG_REPAIR_KIND_FEC_ROOT         && fd_chainer_fec_query( ctx->chainer, slot, fec_set_idx, &block_id ) ) return; /* we already have the FecSetRoot */

      uint              new_nonce = ctx->ag_nonce++;
      fd_repair_msg_t * msg       = ( kind==AG_REPAIR_KIND_PARENT_FEC_COUNT )
                                    ? ag_repair_parent_and_fec_set_count( ctx->protocol, peer, (ulong)now_ms, new_nonce, slot, &block_id )
                                    : ag_repair_fec_set_root            ( ctx->protocol, peer, (ulong)now_ms, new_nonce, slot, &block_id, fec_set_idx );
      fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
      fd_meta_inflights_request_insert( ctx->inflights, new_nonce, kind, slot, &block_id, fec_set_idx );
      return;
    }
  }

  /* (2) Redispatch an aged-out shred request at DEDUP_TIMEOUT intervals. */
  if( FD_UNLIKELY( fd_inflights_should_drain( ctx->inflights, now ) ) ) {
    ulong nonce; ulong slot; ulong shred_idx; fd_hash_t block_id;
    *charge_busy = 1;
    fd_inflights_request_pop( ctx->inflights, &nonce, &slot, &block_id, &shred_idx );

    fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( ctx->chainer, slot, &block_id );
    if( FD_UNLIKELY( slotv && !fd_chainer_shred_test( ctx->chainer, slotv, (uint)shred_idx ) ) ) {
      /* A block-id request is re-driven as ShredForBlockId, which needs
         the prior getFecRoot to still be present: without it the
         response would be dropped by
         fd_chainer_shred_for_block_id_verify. */
      uint fec_set_idx  = (uint)shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
      int  has_block_id = !fd_hash_check_zero( &block_id );
      int  fec_present  = !has_block_id || !!fd_chainer_fec_query( ctx->chainer, slot, fec_set_idx, &block_id );

      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      if( FD_UNLIKELY( !peer || !fec_present || fd_reqlim_next( ctx->dedup, fd_reqlim_key( FD_REPAIR_KIND_SHRED, slot, (uint)shred_idx ), now ) ) ) {
        /* No peers available (or getFecRoot evicted), park the request
           in inflights. */
        defer_inflight_request( ctx, slot, shred_idx, &block_id );
      } else {
        ctx->metrics->rerequest++;
        nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, slot, (uint)shred_idx, now );
        fd_repair_msg_t * msg = has_block_id
                                 ? ag_repair_shred_block_id( ctx->protocol, peer, (ulong)now_ms, (uint)nonce, slot, &block_id, (uint)shred_idx )
                                 : fd_repair_shred( ctx->protocol, peer, (ulong)now_ms, (uint)nonce, slot, shred_idx );
        fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
        record_inflight_request( ctx, nonce, peer, slot, shred_idx, &block_id );
        return;
      }
    }
  }

  /* (3) No new shred requests allowed if inflights is near capacity. */
  if( FD_UNLIKELY( fd_inflights_outstanding_free( ctx->inflights ) <= fd_signs_map_key_cnt( ctx->signs_map ) ) ) return;

  /* Orphan (ancestry) pass
     - Parent slot unknown: request our own shred 0 (contents names the
       parent).
     - Parent slot known but the parent slotv is absent: the slotv
       stays in the treap and we fire an Orphan request for it.

     An orphan whose parent slotv exists (or whose parent is covered by
     the snapshot, i.e. at/below the chainer root) is resolved: remove
     it from the treap. */
  fd_sched_orphan_t * otreap = chainer->orphan_treap;
  fd_sched_orphan_fwd_iter_t onext;
  for( fd_sched_orphan_fwd_iter_t oit = fd_sched_orphan_fwd_iter_init( otreap, sched_pool );
                                       !fd_sched_orphan_fwd_iter_done( oit ); oit = onext ) {
    onext = fd_sched_orphan_fwd_iter_next( oit, sched_pool );
    fd_chainer_slotv_t * o = fd_slotv_pool_ele( pool, fd_sched_orphan_fwd_iter_ele( oit, sched_pool )->slotv_idx );

    /* parent present or covered by the snapshot -> resolved TODO - can potentially remove this call */
    if( o->parent_slot!=AG_UNKNOWN_SLOT &&
      ( o->parent_slot<=chainer->root || fd_chainer_slot_query( chainer, o->parent_slot ) ) ) {
      fd_chainer_orphan_remove( chainer, o );
      continue;
    }

    ulong oslot = o->slot;

    if( o->parent_slot==AG_UNKNOWN_SLOT && !fd_hash_check_zero( &o->block_id ) ) {
      /* getParentAndFecSetCount for block id repair -- a
         shred-0 request is ineffectual as it must pass validation. */
      if( !fd_reqlim_next( ctx->dedup, fd_reqlim_key( AG_REPAIR_KIND_PARENT_FEC_COUNT, oslot, 0 ), now ) ) {
        fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
        if( FD_UNLIKELY( !peer ) ) break;
        uint nonce = ctx->ag_nonce++;
        fd_repair_msg_t * msg = ag_repair_parent_and_fec_set_count( ctx->protocol, peer, (ulong)now_ms, nonce, oslot, &o->block_id );
        *charge_busy = 1;
        fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
        fd_meta_inflights_request_insert( ctx->inflights, nonce, AG_REPAIR_KIND_PARENT_FEC_COUNT, oslot, &o->block_id, 0U );
        return;
      }
    } else if( o->parent_slot==AG_UNKNOWN_SLOT && !fd_reqlim_next( ctx->dedup, fd_reqlim_key( FD_REPAIR_KIND_SHRED, oslot, 0 ), now ) ) {
      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      if( FD_UNLIKELY( !peer ) ) break;
      uint nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, oslot, 0U, now );
      fd_repair_msg_t * msg = fd_repair_shred( ctx->protocol, peer, (ulong)now_ms, (uint)nonce, oslot, 0 );
      *charge_busy = 1;
      fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
      record_inflight_request( ctx, nonce, peer, oslot, 0UL, NULL );
      return;
    } else if( o->parent_slot!=AG_UNKNOWN_SLOT && !fd_reqlim_next( ctx->dedup, fd_reqlim_key( FD_REPAIR_KIND_ORPHAN, oslot, UINT_MAX ), now ) ) {
      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      if( FD_UNLIKELY( !peer ) ) break;
      uint nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 0, oslot, 0U, now );
      fd_repair_msg_t * msg = fd_repair_orphan( ctx->protocol, peer, (ulong)now_ms, (uint)nonce, oslot );
      *charge_busy = 1;
      fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
      return;
    }
  }

  for( fd_sched_repair_fwd_iter_t it = fd_sched_repair_fwd_iter_init( treap, sched_pool );
                                      !fd_sched_repair_fwd_iter_done( it ); ) {
    fd_chainer_slotv_t * e = fd_slotv_pool_ele( pool, fd_sched_repair_fwd_iter_ele( it, sched_pool )->slotv_idx );
    it = fd_sched_repair_fwd_iter_next( it, sched_pool );

    ulong slot = e->slot;

    if( e->buffered_idx!=UINT_MAX &&
      ( e->highest_requested==UINT_MAX || e->buffered_idx > e->highest_requested ) )
      e->highest_requested = e->buffered_idx;

    if( FD_UNLIKELY( e->complete_idx==UINT_MAX ) ) {
      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      /* No peers available.  Nothing has been consumed for this slotv
         and it stays in the repair treap. Retry it on next walk. */
      if( FD_UNLIKELY( !peer ) ) break;
      if( !fd_reqlim_next( ctx->dedup, fd_reqlim_key( FD_REPAIR_KIND_HIGHEST_SHRED, slot, UINT_MAX ), now ) ) {
        uint nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 0, slot, 0U, now );
        fd_repair_msg_t * msg = fd_repair_highest_shred( ctx->protocol, peer, (ulong)now_ms, nonce, slot, 0 );
        *charge_busy = 1;
        fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
        return;
      }
      continue;
    }

    /* make individual shred request */

    uint idx = e->highest_requested+1;
    while( FD_UNLIKELY( idx<FD_SHRED_BLK_MAX && fd_chainer_shred_test( chainer, e, idx ) ) ) idx++;

    if( FD_UNLIKELY( idx > e->complete_idx ) ) {
      e->highest_requested = idx;
      fd_chainer_repair_remove( chainer, e );
      continue;
    };

    if( FD_UNLIKELY( fd_hash_check_zero( &e->block_id ) ) ) {
      /* TODO eager repair time gate */
      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      /* No peers available (yet).  highest_requested has not advanced
         past idx and no inflight was recorded, so the next walk retries
         this same shred request once gossip has discovered a peer. */
      if( FD_UNLIKELY( !peer ) ) break;
      ulong nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, slot, idx, now );
      fd_repair_msg_t * msg = fd_repair_shred( ctx->protocol, peer, (ulong)now/(ulong)1e6, (uint)nonce, slot, idx );
      *charge_busy = 1;
      fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
      record_inflight_request( ctx, nonce, peer, slot, idx, NULL );
    } else {
      /* block_id known -> Alpenglow block-id repair.  Gate on prior
         getFecRoot being present.  The ShredForBlockId response would
         race the getFecRoot and be dropped by
         fd_chainer_shred_for_block_id_verify, then re-requested only
         after the reqlim timeout. Retry this idx on a later walk, once
         the root lands. */
      uint  fec_set_idx = idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
      if( FD_UNLIKELY( !fd_chainer_fec_query( chainer, slot, fec_set_idx, &e->block_id ) ) ) continue;

      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      if( FD_UNLIKELY( !peer ) ) break;
      ulong nonce           = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, slot, idx, now );
      fd_repair_msg_t * msg = ag_repair_shred_block_id( ctx->protocol, peer, (ulong)now_ms, (uint)nonce, slot, &e->block_id, idx );
      *charge_busy = 1;
      fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
      record_inflight_request( ctx, nonce, peer, slot, idx, &e->block_id );
    }
    e->highest_requested = idx;
    return;
  }
}

/* publish_fec builds and publishes a single ROTOR_SIG_FEC_REPLAY
   message to replay for the FEC fec owned by version slotv.  When
   from_root is set (the deliver_from_root recovery redelivery), the
   block_id is always populated with the version's finalized block_id
   -- even for mid-slot turbine FECs that the normal path leaves zero --
   so replay can dedup the redelivered path by (slot, block_id) and skip
   blocks it has already replayed. */
static void
publish_fec( ctx_t *              ctx,
             fd_stem_context_t *  stem,
             fd_chainer_slotv_t * slotv,
             fd_chainer_fec_t *   fec,
             int                  from_root ) {
  fd_hash_t null_hash = {0};

  fd_rotor_replay_fec_t * msg = fd_chunk_to_laddr( ctx->repair_out_ctx->mem, ctx->repair_out_ctx->chunk );
  msg->slot            = fec->slot;
  msg->fec_set_idx     = fec->fec_set_idx;
  msg->mr              = fec->merkle_root;
  msg->parent_slot     = slotv->parent_slot;
  msg->parent_block_id = slotv->parent_block_id;
  msg->slot_complete   = fec->slot_complete;
  msg->data_complete   = fec->data_complete;
  msg->is_leader       = fec->is_leader;
  /* Redelivered (from_root) FECs carry the finalized DMR in block_id so
     mark them known (replay needs to lookup on the DMR and SKIP). */
  msg->known_id        = !slotv->turbine || from_root;
  msg->block_id        = ( slotv->turbine && !fec->slot_complete && !from_root ) ? null_hash : slotv->block_id;

  if( FD_UNLIKELY( fec->slot_complete ) ) {
    FD_BASE58_ENCODE_32_BYTES( slotv->block_id.uc, block_id );
    FD_LOG_INFO(( "[%s] slot is complete %lu. num_data_shreds: %u. block_id: %s, parent_slot: %lu, turbine: %d",
                    __func__,
                    slotv->slot,
                    slotv->complete_idx + 1,
                    block_id,
                    slotv->parent_slot,
                    slotv->turbine ));
  }

  fd_stem_publish( stem, ctx->repair_out_ctx->idx, ROTOR_SIG_FEC_REPLAY, ctx->repair_out_ctx->chunk, sizeof(fd_rotor_replay_fec_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->repair_out_ctx->chunk = fd_dcache_compact_next( ctx->repair_out_ctx->chunk, sizeof(fd_rotor_replay_fec_t), ctx->repair_out_ctx->chunk0, ctx->repair_out_ctx->wmark );
  ctx->metrics->fecs_delivered++;
}

/* full_fec_path_queue queues every FEC from the chainer root down to
   (target_slotv, target_fec), inclusive, onto ctx->deliver_queue in
   root-to-target order. */
static void
full_fec_path_queue( ctx_t *              ctx,
                     fd_chainer_slotv_t * target_slotv,
                     fd_chainer_fec_t *   target_fec ) {
  fd_chainer_t * chainer = ctx->chainer;

  for( fd_chainer_slotv_t * slotv = target_slotv;
                            slotv && slotv->slot > chainer->root;
                            slotv = fd_chainer_slot_version_query( chainer, slotv->parent_slot, &slotv->parent_block_id ) ) {
    uint slotv_idx = (uint)fd_slotv_pool_idx( chainer->slotv_pool, slotv );

    uint kmax;
    if( FD_LIKELY( slotv==target_slotv ) ) {
      kmax = target_fec->fec_set_idx / (uint)FD_FEC_SHRED_CNT; /* target: up to the delivered FEC */
    } else {
      if( FD_UNLIKELY( slotv->buffered_fec_idx==UINT_MAX ) ) continue; /* ancestor with no complete FEC buffered */
      kmax = slotv->buffered_fec_idx / (uint)FD_FEC_SHRED_CNT;         /* ancestor: all buffered FECs */
    }

    for( int k=(int)kmax; k>=0; k-- ) {
      if( FD_UNLIKELY( out_queue_full( ctx->deliver_queue ) ) ) FD_LOG_ERR(( "deliver_from_root queue full" ));
      out_queue_push_head( ctx->deliver_queue, (out_ele_t){ .slotv_idx = slotv_idx, .fec_idx = slotv->fec[ k ] } );
    }
  }
}

/* publish_fec_replay pops one delivered FEC off the chainer's out_queue
   and publishes it to replay on repair_out with ROTOR_SIG_FEC_REPLAY.
   When ctx->deliver_from_root is set the entire ancestry path from the
   chainer root to that FEC is instead queued onto ctx->deliver_queue,
   which after_credit drains one FEC per call.  Returns 1 if a delivered
   FEC was consumed. */
static int
publish_fec_replay( ctx_t * ctx, fd_stem_context_t * stem ) {
  out_ele_t * out_queue = ctx->chainer->out_queue;
  if( FD_LIKELY( out_queue_empty( out_queue ) ) ) return 0;

  out_ele_t out_ele = out_queue_pop_head( out_queue );
  if( FD_UNLIKELY( out_ele.slotv_idx == UINT_MAX ) ) return 1;

  fd_chainer_fec_t   * fec   = fd_fec_pool_ele( ctx->chainer->fec_pool, out_ele.fec_idx );
  fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( ctx->chainer->slotv_pool, out_ele.slotv_idx );

  if( FD_UNLIKELY( ctx->deliver_from_root ) ) {
    full_fec_path_queue( ctx, slotv, fec );
    ctx->deliver_from_root = 0;
  }
  else publish_fec( ctx, stem, slotv, fec, 0 /* from_root */ );

  return 1;
}

static inline void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  long now = fd_log_wallclock();

  /* deliver_queue has FECs when replay has signaled a bank eviction,
     and we added the full path of FECs from root up until the next FEC we need to deliver.
     TODO: bad hygeine, either move into chainer or move the out_queue to the rotor tile. */
  if( FD_UNLIKELY( !out_queue_empty( ctx->deliver_queue ) ) ) {
    out_ele_t            e     = out_queue_pop_head( ctx->deliver_queue );
    fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( ctx->chainer->slotv_pool, e.slotv_idx );
    fd_chainer_fec_t   * fec   = fd_fec_pool_ele  ( ctx->chainer->fec_pool,   e.fec_idx   );
    publish_fec( ctx, stem, slotv, fec, 1 /* from_root: always populate block_id */ );
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  /* Publish any FECs the chainer has delivered for replay. */
  if( publish_fec_replay( ctx, stem ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( ctx->halt_signing ) ) {
    *charge_busy = 1;
    return;
  }

  /* Verify that there is at least one sign tile with available credits.
     If not, we can't send any requests and leave early. */
  out_ctx_t * sign_out = sign_avail_credits( ctx );
  if( FD_UNLIKELY( !sign_out ) ) {
    ctx->metrics->sign_tile_unavail++;
    return;
  }

  /* If inflights is at capacity, then the only thing we can send is:
     pongs, initial highest window index requests, or resend things that
     are already inflight.  Any new requests that would cause an
     inflight to be added to the queue must be deferred. */

  if( FD_UNLIKELY( !fd_signs_queue_empty( ctx->pong_queue ) ) ) {
    sign_pending_t signable = fd_signs_queue_pop( ctx->pong_queue );
    fd_repair_send_sign_request( ctx, sign_out, &signable.msg, signable.msg.kind == FD_REPAIR_KIND_PONG ? &signable.pong_data : NULL );
    *charge_busy = 1;
    return;
  }

  if( FD_UNLIKELY( !ag_req_queue_empty( ctx->ag_req_queue ) ) ) {
    fd_repair_msg_t     msg  = ag_req_queue_pop( ctx->ag_req_queue );
    fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
    fd_pubkey_t to = {0};
    if( FD_LIKELY( peer ) ) {
      msg.header.to = *peer;
      fd_repair_send_sign_request( ctx, sign_out, &msg, NULL );
    } else {
      peer = &to;
    }
    if( FD_LIKELY( msg.kind==AG_REPAIR_KIND_FEC_ROOT ) ) fd_meta_inflights_request_insert( ctx->inflights, msg.fec_set_root.nonce,         AG_REPAIR_KIND_FEC_ROOT,         msg.fec_set_root.slot,         &msg.fec_set_root.block_id,         msg.fec_set_root.fec_set_idx );
    else                                                 fd_meta_inflights_request_insert( ctx->inflights, msg.parent_fec_set_count.nonce, AG_REPAIR_KIND_PARENT_FEC_COUNT, msg.parent_fec_set_count.slot, &msg.parent_fec_set_count.block_id, 0U );
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  /* Alpenglow drives its entire request pipeline (metadata/shred
     redispatch, capacity gate, and the orphan + shred-fill walk) from
     the policy walk. */
  if( FD_UNLIKELY( ctx->block_id_repair_only ) ) ag_policy_block_id_next( ctx, sign_out, now, charge_busy );
  else                                           ag_policy_next         ( ctx, sign_out, now, charge_busy );
  return;
}

static void
signs_queue_update_identity( ctx_t * ctx ) {
  ulong queue_cnt = fd_signs_queue_cnt( ctx->pong_queue );
  for( ulong i=0UL; i<queue_cnt; i++ ) {
    sign_pending_t signable = fd_signs_queue_pop( ctx->pong_queue );
    switch( signable.msg.kind ) {
      case FD_REPAIR_KIND_PONG:
        memcpy( signable.msg.pong.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) );
        break;
      case FD_REPAIR_KIND_SHRED:
        memcpy( signable.msg.shred.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) );
        break;
      case FD_REPAIR_KIND_HIGHEST_SHRED:
        memcpy( signable.msg.highest_shred.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) );
        break;
      case FD_REPAIR_KIND_ORPHAN:
        memcpy( signable.msg.orphan.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) );
        break;
      case AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID:
        memcpy( signable.msg.shred_block_id.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) );
        break;
      default:
        FD_LOG_CRIT(( "Unhandled repair kind %u", signable.msg.kind ));
        break;
    }
    fd_signs_queue_push( ctx->pong_queue, signable );
  }
  queue_cnt = ag_req_queue_cnt( ctx->ag_req_queue );
  for( ulong i=0UL; i<queue_cnt; i++ ) {
    fd_repair_msg_t msg = ag_req_queue_pop( ctx->ag_req_queue );
    switch( msg.kind ) {
      case AG_REPAIR_KIND_FEC_ROOT:
        memcpy( msg.fec_set_root.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) );
        break;
      case AG_REPAIR_KIND_PARENT_FEC_COUNT:
        memcpy( msg.parent_fec_set_count.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) );
        break;
      default:
        FD_LOG_CRIT(( "Unhandled repair kind %u", msg.kind ));
        break;
    }
    ag_req_queue_push( ctx->ag_req_queue, msg );
  }
}

static inline void
during_housekeeping( ctx_t * ctx ) {
# if DEBUG_LOGGING
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - ctx->tsdebug > (long)10e9 ) ) {
    fd_forest_print( ctx->forest );
    ctx->tsdebug = fd_log_wallclock();
  }
# endif

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: unhalting" ));
    FD_CHECK_CRIT( ctx->halt_signing, "state machine corruption" );
    ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {

    if( !ctx->halt_signing ) {
      /* At this point, stop sending new sign requests to the sign tile
         and wait for all outstanding sign requests to be received back
         from the sign tile.  We also need to update any pending
         outgoing sign requests with the new identity key. */
      FD_LOG_DEBUG(( "keyswitch: halting signing" ));
      ctx->halt_signing = 1;
      memcpy( ctx->identity_public_key.uc, ctx->keyswitch->bytes, 32UL );
      ctx->protocol->identity_key = ctx->identity_public_key;
      signs_queue_update_identity( ctx );
    }

    if( fd_signs_map_key_cnt( ctx->signs_map )==0UL ) {
      /* Once there are no more in flight sign requests, we are ready to
         say that the keyswitch is completed. */
      FD_LOG_DEBUG(( "keyswitch: completed, no more outstanding stale sign requests" ));
      fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
    }
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  fd_memset( ctx, 0, sizeof(ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->rotor.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key.uc, identity_key, sizeof(fd_pubkey_t) );

  FD_TEST( fd_rng_secure( &ctx->repair_seed, sizeof(ulong) ) );

  ulong rnonce_ss_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "rnonce_ss" );
  FD_TEST( rnonce_ss_id!=ULONG_MAX );
  memcpy( ctx->repair_nonce_ss, fd_topo_obj_laddr( topo, rnonce_ss_id ), sizeof(fd_rnonce_ss_t) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong total_sign_depth = tile->rotor.repair_sign_depth * tile->rotor.repair_sign_cnt;
  int   lg_sign_depth    = fd_ulong_find_msb( fd_ulong_pow2_up(total_sign_depth) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),            sizeof(ctx_t)                                                 );
  ctx->protocol      = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),         fd_repair_footprint()                                         );
  ctx->chainer       = FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(),        fd_chainer_footprint( tile->rotor.slot_max )                 );
  ctx->policy        = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),         fd_policy_footprint( FD_REPAIR_PEER_MAX )                     );
  ctx->dedup         = FD_SCRATCH_ALLOC_APPEND( l, fd_reqlim_align(),         fd_reqlim_footprint( FD_REQLIM_CACHE_MAX )                    );
  ctx->inflights     = FD_SCRATCH_ALLOC_APPEND( l, fd_inflights_align(),      fd_inflights_footprint()                                      );
  ctx->signs_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_signs_map_align(),      fd_signs_map_footprint( lg_sign_depth )                       );
  ctx->pong_queue    = FD_SCRATCH_ALLOC_APPEND( l, fd_signs_queue_align(),    fd_signs_queue_footprint()                                    );
  ctx->ag_req_queue  = FD_SCRATCH_ALLOC_APPEND( l, ag_req_queue_align(),      ag_req_queue_footprint()                                        );
  ctx->slot_metrics  = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_metrics_align(), fd_repair_metrics_footprint()                                 );
  ctx->deliver_queue = FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),         out_queue_footprint( (ulong)tile->rotor.slot_max * FD_CHAINER_SLOT_VER_MAX * FD_FEC_BLK_MAX ) );
  ulong scratch_top  = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->chainer       = fd_chainer_join       ( fd_chainer_new       ( ctx->chainer,   tile->rotor.slot_max, ctx->repair_seed                                        ) );
  ctx->deliver_queue = out_queue_join        ( out_queue_new        ( ctx->deliver_queue, (ulong)tile->rotor.slot_max * FD_CHAINER_SLOT_VER_MAX * FD_FEC_BLK_MAX     ) );

  ctx->protocol      = fd_repair_join        ( fd_repair_new        ( ctx->protocol,  &ctx->identity_public_key                                                      ) );
  ctx->policy        = fd_policy_join        ( fd_policy_new        ( ctx->policy,    FD_REPAIR_PEER_MAX, ctx->repair_seed, ctx->repair_nonce_ss ) );
  ctx->dedup         = fd_reqlim_join        ( fd_reqlim_new        ( ctx->dedup,     FD_REQLIM_CACHE_MAX, ctx->repair_seed                      ) );
  ctx->inflights     = fd_inflights_join     ( fd_inflights_new     ( ctx->inflights, ctx->repair_seed+1234UL                                                       ) );
  ctx->signs_map     = fd_signs_map_join     ( fd_signs_map_new     ( ctx->signs_map, lg_sign_depth, 0UL                                                            ) );
  ctx->pong_queue    = fd_signs_queue_join   ( fd_signs_queue_new   ( ctx->pong_queue                                                                               ) );
  ctx->ag_req_queue  = ag_req_queue_join     ( ag_req_queue_new     ( ctx->ag_req_queue                                                                             ) );
  ctx->slot_metrics  = fd_repair_metrics_join( fd_repair_metrics_new( ctx->slot_metrics                                                                             ) );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );
  FD_TEST( fd_store_map_ljoin( ctx->store, ctx->store_map ) );

  ctx->halt_signing = 0;

  /* Flip to 1 to exercise block-id-only repair/catchup */
  ctx->block_id_repair_only = 0;
  ctx->deliver_from_root    = 0;

  /* Process in links */

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "repair tile has too many input links" ));

  uint  sign_repair_in_idx[ MAX_SIGN_TILE_CNT ] = {0};
  uint  sign_repair_idx  = 0;
  ulong sign_link_depth  = 0;

  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if( 0==strcmp( link->name, "net_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in_links[ in_idx ].net_rx, link->dcache );
      continue;
    } else if( 0==strcmp( link->name, "sign_repair" ) ) {
      ctx->in_kind[ in_idx ]                  = IN_KIND_SIGN;
      sign_repair_in_idx[ sign_repair_idx++ ] = in_idx;
      sign_link_depth                         = link->depth;
    }
    else if( 0==strcmp( link->name, "gossip_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_GOSSIP;
    else if( 0==strcmp( link->name, "shred_out"    ) ) ctx->in_kind[ in_idx ] = IN_KIND_SHRED;
    else if( 0==strcmp( link->name, "snapin_manif" ) ) ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    else if( 0==strcmp( link->name, "genesi_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_GENESIS;
    else if( 0==strcmp( link->name, "replay_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_REPLAY;
    else if( 0==strcmp( link->name, "votor_out"    ) ) ctx->in_kind[ in_idx ] = IN_KIND_VOTOR;
    else FD_LOG_ERR(( "repair tile has unexpected input link %s", link->name ));

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;

    FD_TEST( fd_dcache_compact_is_safe( ctx->in_links[in_idx].mem, link->dcache, link->mtu, link->depth ) );
  }

  ctx->net_out_ctx->idx    = UINT_MAX;
  ctx->repair_out_ctx->idx = UINT_MAX;
  ctx->repair_sign_cnt   = 0;
  ctx->sign_rrobin_idx   = 0;

  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ out_idx ] ];

    if( 0==strcmp( link->name, "repair_net" ) ) {

      if( ctx->net_out_ctx->idx!=UINT_MAX ) continue; /* only use first net link */
      ctx->net_out_ctx->idx    = out_idx;
      ctx->net_out_ctx->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->net_out_ctx->chunk0 = fd_dcache_compact_chunk0( ctx->net_out_ctx->mem, link->dcache );
      ctx->net_out_ctx->wmark  = fd_dcache_compact_wmark( ctx->net_out_ctx->mem, link->dcache, link->mtu );
      ctx->net_out_ctx->chunk  = ctx->net_out_ctx->chunk0;

    } else if( 0==strcmp( link->name, "repair_out" ) ) {

      out_ctx_t * replay_out = ctx->repair_out_ctx;
      replay_out->idx        = out_idx;
      replay_out->mem        = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      replay_out->chunk0     = fd_dcache_compact_chunk0( replay_out->mem, link->dcache );
      replay_out->wmark      = fd_dcache_compact_wmark( replay_out->mem, link->dcache, link->mtu );
      replay_out->chunk      = replay_out->chunk0;

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
  FD_TEST( ctx->net_out_ctx->idx!=UINT_MAX );
  FD_TEST( ctx->repair_out_ctx->idx!=UINT_MAX );
  if( FD_UNLIKELY( ctx->repair_sign_cnt!=sign_repair_idx ) ) {
    FD_LOG_ERR(( "Mismatch between repair_sign output links (%lu) and sign_repair input links (%u)", ctx->repair_sign_cnt, sign_repair_idx ));
  }
  if( FD_UNLIKELY( fd_signs_map_key_max( ctx->signs_map ) < tile->rotor.repair_sign_depth * tile->rotor.repair_sign_cnt ) ) {
    FD_LOG_ERR(( "Repair pending signs tracking map is too small: %lu < %lu.", fd_signs_map_key_max( ctx->signs_map ), tile->rotor.repair_sign_depth * tile->rotor.repair_sign_cnt ));
  }

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->repair_intake_addr.port = fd_ushort_bswap( tile->rotor.repair_client_listen_port );

  /* TODO clean these up */
  ctx->net_id = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->intake_hdr, 0, 0, tile->rotor.repair_client_listen_port );

  /* Repair set up */

  ctx->turbine_slot0 = ULONG_MAX;
  FD_LOG_INFO(( "repair my addr - intake addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_intake_addr.addr ), fd_ushort_bswap( ctx->repair_intake_addr.port )
  ));

  memset( ctx->metrics, 0, sizeof(ctx->metrics) );

  fd_histf_join( fd_histf_new( ctx->metrics->slot_compl_time, FD_MHIST_SECONDS_MIN( REPAIR, SLOT_COMPLETE_DURATION_SECONDS ),
                                                              FD_MHIST_SECONDS_MAX( REPAIR, SLOT_COMPLETE_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->response_latency, FD_MHIST_MIN( REPAIR, RESPONSE_LATENCY_NANOS ),
                                                               FD_MHIST_MAX( REPAIR, RESPONSE_LATENCY_NANOS ) ) );

  ctx->tsdebug = fd_log_wallclock();
  ctx->pending_key_next = 0;
  ctx->ag_nonce = 0;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_rotor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_rotor_tile_instr_cnt;
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
  FD_MGAUGE_SET( ROTOR, SLOT_CURRENT,          ctx->metrics->current_slot );
  FD_MGAUGE_SET( ROTOR, SLOT_HIGHEST_REPAIRED, ctx->chainer->highest_repaired ); //fd_forest_highest_repaired_slot( ctx->forest ) );
  FD_MCNT_SET( ROTOR, SHRED_OLD,               ctx->metrics->old_shred );
  FD_MCNT_SET( ROTOR, PEER_REQUESTED,          fd_policy_peer_pool_used( ctx->policy->peers.pool ) );
  FD_MCNT_SET( ROTOR, SHRED_REREQUESTED,       ctx->metrics->rerequest );

  FD_MGAUGE_SET( ROTOR, SLOT_LAST_REQUESTED,   ctx->metrics->last_requested_slot );
  FD_MGAUGE_SET( ROTOR, ORPHAN_LAST_REQUESTED, ctx->metrics->last_requested_orphan );
  FD_MGAUGE_SET( ROTOR, REQUEST_INFLIGHT,      fd_inflight_pool_used( ctx->inflights->pool ) - ctx->inflights->popped_cnt );

  FD_MCNT_SET      ( ROTOR, PKT_TX,     ctx->metrics->send_pkt_cnt   );
  FD_MCNT_ENUM_COPY( ROTOR, REQUEST_TX, ctx->metrics->sent_pkt_types );

  FD_MHIST_COPY( ROTOR, RESPONSE_LATENCY_NANOS,         ctx->metrics->response_latency );

  FD_MCNT_SET( ROTOR, PING_UNKNOWN_PEER,     ctx->metrics->unknown_peer_ping );
  FD_MCNT_SET( ROTOR, PING_MALFORMED,        ctx->metrics->malformed_ping );
  FD_MCNT_SET( ROTOR, PING_SIGNATURE_FAILED, ctx->metrics->fail_sigverify_ping );

  FD_MCNT_SET( ROTOR, SHRED_BLOCK_ID_FAILED,   ctx->metrics->failed_shred_block_id_cnt );
  FD_MCNT_SET( ROTOR, FEC_ROOT_FAILED,         ctx->metrics->failed_fec_root_cnt );
  FD_MCNT_SET( ROTOR, PARENT_FEC_COUNT_FAILED, ctx->metrics->failed_parent_fec_count_cnt );
}

#undef DEBUG_LOGGING

/* At most one sign request is made in after_credit.  Then at most one
   message is published in after_frag. */
#define STEM_BURST (3UL)

/* Set LAZY to a reasonable value that keeps housekeeping time low.
   Repair tile's only reliable consumer is replay. */
#define STEM_LAZY  (64000)

#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_rotor = {
  .name                     = "rotor",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
