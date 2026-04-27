/* The repair tile is responsible for repairing missing shreds that were
   not received via Turbine.  The goal is to ensure that slots we "care"
   about have their FEC sets inserted into store.

   Generally there are two distinct traffic patterns:

   a. Firedancer boots up and fires off a large number of repairs to
      recover all the blocks between the snapshot on which it is booting
      and the head of the chain.  In this mode, repair tile utilization
      is very high along with net and sign utilization.

   b. Firedancer catches up to the head of the chain and enters steady
      state where most shred traffic is delivered over turbine.  In this
      state, repairs are only occasionally needed to recover shreds lost
      due to anomalies like packet loss, transmitter (leader) never sent
      them or even a malicious leader etc.  On rare occasion, repair
      will also need to recover a different version of a block that
      equivocated.

   To accomplish the above, repair mainly processes 4 kinds of frags:

   1. Shred data (from shred tile)

      Any shred (coding or data) that passes validation and filtering in
      the shred tile is forwarded to repair.  Repair uses these to track
      which shreds have been received in `fd_forest`, a tree data
      structure that mirrors the block/slot ancestry chain.  It also
      uses these shreds to discover slots or ancestries that were not
      known. fd_forest tracks metadata for each slot, including slot
      completion status, merkle roots, and metrics.

      Any shred that we can correlate with a repair request we made is
      used to update peer response latency metrics in fd_policy (See
      fd_policy.h for more details).

   2. FEC status messages (from shred tile)

      These fall under two categories: FEC completion and FEC eviction.
      When all shreds in a FEC set have been recovered, the shred tile
      sends a completion message. This may trigger chained merkle
      verification if the slot has a confirmed block_id.  The completed
      FEC message is always forwarded to replay via repair_out.

      When an incomplete FEC set is evicted from the shred tile's FEC
      resolver (e.g. due to capacity), it also notifies repair.  Repair
      clears the corresponding FEC set entries from the forest so those
      shred indices can be re-requested if they are necessary.  As
      mentioned in fd_forest.h, forest needs to maintain a strict subset
      of shreds that are known by fec_resolver, store, and reasm in
      order to guarantee forward progress always.

   3. Pings (from net tile)

      Repair peers use a ping-pong protocol to verify liveness before
      serving repair requests.  When a ping arrives over the network,
      repair validates the message and constructs a pong response. To
      prevent spam attacks, repair has stopgaps like tracking how many
      pongs per peer are currently in the sign queue and dropping pings
      from unknown peers.  These are the only untrusted inputs to
      repair.

   4. Sign task responses (from sign tile)

      Repair requests are signed asynchronously; the repair tile
      constructs a repair request, dispatches it to a sign tile via the
      repair_sign output link.  The repair-sign communication is
      manually managed via credit tracking in the repair tile (see
      comment in out_ctx_t struct definition).

      After receiving the signature back from sign tile, repair injects
      the signature into the pending request and dispatches it to the
      net tile via the repair_net output link. The behavior depends on
      the request type:
      - Pong: the signed pong is sent to the peer that pinged us.
      - Warmup: a proactive request sent when a new peer's contact info
        first arrives, prepaying the ping-pong RTT cost.  The signed
        request is sent to the peer if it is still active.
      - Regular shred request: the request is recorded in an inflight
        table (for tracking response latency and timeouts) and the
        signed packet is sent to the selected peer.

   Secondary "other" frags that are processed but not part of core
   repair logic:

   5. Confirmation messages from tower

      Tower sends two kinds of messages relevant to repair:
      - slot_done: indicates a slot has finished replay and may advance
        the root.  Repair publishes (roots) the forest up to that slot,
        pruning old ancestry.
      - slot_confirmed: indicates a slot has reached a confirmation
        level (e.g. duplicate-confirmed).  If the slot is not yet in the
        forest, repair creates a sentinel block so it can be repaired.
        It also stores the confirmed block_id and may trigger chained
        merkle verification. See fd_forest.h on more details about
        chained merkle verification.

   6. Eviction messages from replay (reasm)

      When the replay tile's reassembly buffer evicts a FEC set (e.g.
      due to pool capacity) from itself and from store, it notifies
      repair with the slot and fec_set_idx.  Repair clears those FEC
      entries from the forest so the shreds can be re-requested.

   7. Contact info messages from gossip

      Gossip forwards contact info updates and removals for other
      validators.  Repair uses these to maintain a list of peers to
      make requests to.

   If fd_forest tracks what we know about each shred, fd_policy and
   fd_inflights is responsible for deciding what next repair request to
   make. fd_policy and fd_inflights split responsibility: fd_policy
   makes any new requests, orphan requests, and requests directly off
   the forest iterator, while fd_inflights re-requests anything that has
   been requested but not received yet within a timeout window. */

#define _GNU_SOURCE

#include "../genesis/fd_genesi_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "generated/fd_repair_tile_seccomp.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_rnonce_ss.h"
#include "../../disco/shred/fd_shred_tile.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../replay/fd_replay_tile.h"
#include "../tower/fd_tower_tile.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../tango/fd_tango_base.h"

#include "../forest/fd_forest.h"
#include "fd_repair_metrics.h"
#include "fd_inflight.h"
#include "fd_repair.h"
#include "fd_policy.h"

#define DEBUG_LOGGING 0

#define IN_KIND_CONTACT (0)
#define IN_KIND_NET     (1)
#define IN_KIND_TOWER   (2)
#define IN_KIND_SHRED   (3)
#define IN_KIND_SIGN    (4)
#define IN_KIND_SNAP    (5)
#define IN_KIND_GOSSIP  (6)
#define IN_KIND_GENESIS (7)
#define IN_KIND_REPLAY  (8)

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
#define FD_DEDUP_CACHE_MAX (1<<15)

/* static map from request type to metric array index */
static uint metric_index[FD_REPAIR_KIND_ORPHAN + 1] = {
  [FD_REPAIR_KIND_PONG]          = FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_V_PONG_IDX,
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

  /* Repair tile directly tracks credit outside of stem for these
     asynchronous sign links.  In particular, credits tracks the RETURN
     sign_repair link.  This is because repair_sign and
     sign_repair are unreliable.  If both links were reliable, and the
     links filled completely, stem would get into a deadlock.  Neither
     repair or sign would have credits, which would prevent frags from
     getting polled in repair or sign, which would prevent any credits
     from getting returned back to the tiles.  So the sign_repair return
     link must be unreliable. credits / max_credits are used by the
     repair_sign link,  but credits tracks the RETURN
     sign_repair link.

     Consider the scenario:

             repair_sign (depth 128)        sign_repair (depth 128)
     repair  ---------------------->  sign ------------------------> repair
             [rest free, r130, r129]       [r128, r127, ... , r1] (full)

     If repair is publishing too many requests too fast(common in
     catchup), and not polling enough frags from sign, without manual
     management the sign_repair link would be overrun.  Nothing is
     stopping repair from publishing more requests, because sign is
     functioning fast enough to handle the requests. However, nothing is
     stopping sign from polling the next request and signing it, and
     PUBLISHING it on the sign_repair link that is already full, because
     the sign_repair link is unreliable.

     This is why we need to manually track credits for the sign_repair
     link. We must ensure that there are never more than 128 items in
     the ENTIRE repair_sign -> sign tile -> sign_repair work queue, else
     there is always a possibility of an overrun in the sign_repair
     link.

     We can furthermore ensure some nice properties by having the
     repair_sign link have a greater depth than the sign_repair link.
     This way, we exclusively use manual credit management to control
     the rate at which we publish requests to sign.  This allows for
     repair_sign to also be unreliable.  Even when the repair sign link
     is "full", we can avoid backpressure and continue polling frags,
     without overruning the sign_repair link.

     To lose a frag to overrun isn't necessarily critical, but in
     general the repair tile relies on the fact that a signing task
     published to sign tile will always come back.  If we lose a frag to
     overrun, then there will be an entry in the pending signs structure
     that is never removed, and theoretically the map could fill up.
     Conceptually, with a reliable (unreliable links, but strictly
     controlled count-per-link) sign->repair->sign structure, there
     should be no eviction needed in this pending signs structure. */

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

/* Because the sign tiles could be all busy when a contact info or a
   ping arrives, we need to save ping messages to be signed in a queue
   and dispatched in after_credit when there are sign tiles available.
   The size of the queue is sized to be the number of warm up
   requests we might burst to the queue all at once (at most
   FD_REPAIR_PEER_MAX), then doubled for good measure.

   There is a possibility that someone could spam pings to block other
   peers' pings (and prevent us from responding to those pings). To
   mitigate this, we track the number of pings currently living in the
   sign queue that belong to each peer.  If a peer already has a pong
   living in the sign queue, we drop the pings from that peer.

   The peer could send us a new bogus ping every time we pop their ping
   from the sign queue, but there would be no way to prevent other
   peers' pings from getting processed, so the wasted work and impact
   would be minimal.

   Typical flow is that a pong will get added to the pong_queue during
   an after_frag call.  Then on the following after_credit will get
   popped from the sign_queue and added to sign_map, and then dispatched
   to the sign tile.

   Note that after the first turbine shred arrives, the signs_queue also
   stores highest window index requests for slots between snapshot and
   turbine_slot0, which are dispatched first before any other requests
   as a catchup optimization.  This doesn't break any of the inflight
   invariants as highest window index requests do not get added to the
   inflight table. */

struct sign_pending {
  fd_repair_msg_t msg;
  pong_data_t     pong_data; /* populated only for pong msgs */
};
typedef struct sign_pending sign_pending_t;

#define QUEUE_NAME       fd_signs_queue
#define QUEUE_T          sign_pending_t
#define QUEUE_MAX        (2*FD_REPAIR_PEER_MAX)
#include "../../util/tmpl/fd_queue.c"

struct ctx {
  long tsdebug; /* timestamp for debug printing */

  ulong repair_seed;

  fd_keyswitch_t * keyswitch;
  int              halt_signing;

  fd_ip4_port_t repair_intake_addr;
  fd_ip4_port_t repair_serve_addr;

  fd_forest_t    * forest;
  fd_policy_t    * policy;
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
  sign_req_t     * signs_map;  /* contains any request currently in the repair->sign or sign->repair dcache */
  sign_pending_t * pong_queue;  /* contains any pong or initial warmup request waiting to be dispatched to repair->sign. Size is 2*FD_REPAIR_PEER_MAX */

  ushort net_id;

  /* Buffers for incoming unreliable frags */
  uchar net_buf[ FD_NET_MTU ];
  uchar sign_buf[ sizeof(fd_ed25519_sig_t) ];

  /* Store chunk for incoming reliable frags */
  ulong chunk;
  ulong snap_out_chunk; /* store second to last chunk for snap_out */

  fd_ip4_udp_hdrs_t intake_hdr[1];
  fd_ip4_udp_hdrs_t serve_hdr [1];

  fd_rnonce_ss_t repair_nonce_ss[1];

  ulong manifest_slot;
  struct {
    ulong send_pkt_cnt;
    ulong sent_pkt_types[FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPES_CNT];
    ulong repaired_slots;
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
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),            sizeof(ctx_t)                                                      );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(),         fd_repair_footprint     ()                                         );
  l = FD_LAYOUT_APPEND( l, fd_forest_align(),         fd_forest_footprint     ( tile->repair.slot_max )                  );
  l = FD_LAYOUT_APPEND( l, fd_policy_align(),         fd_policy_footprint     ( FD_DEDUP_CACHE_MAX, FD_REPAIR_PEER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_inflights_align(),      fd_inflights_footprint  ()                                         );
  l = FD_LAYOUT_APPEND( l, fd_signs_map_align(),      fd_signs_map_footprint  ( lg_sign_depth )                          );
  l = FD_LAYOUT_APPEND( l, fd_signs_queue_align(),    fd_signs_queue_footprint()                                         );
  l = FD_LAYOUT_APPEND( l, fd_repair_metrics_align(), fd_repair_metrics_footprint()                                      );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* Below functions manage the current pending sign requests. */

static sign_req_t *
sign_map_insert( ctx_t *                 ctx,
                 fd_repair_msg_t const * msg,
                 pong_data_t const     * opt_pong_data ) {

  /* Check if there is any space for a new pending sign request. Should never fail as long as credit management is working. */
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
    preimage_pong( &opt_pong_data->hash, pre_image, sizeof(pre_image) );
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
  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) return fd_int_if( fd_forest_root_slot( ctx->forest )==ULONG_MAX, -1, 0 ); /* not ready to read frag */
  if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  if( FD_UNLIKELY( in_kind==IN_KIND_REPLAY ) ) return sig!=REPLAY_SIG_REASM_EVICTED;
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
                 ulong                  sig,
                 uchar const          * chunk ) {
  if( FD_UNLIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) return;
  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)chunk;

  fd_forest_init( ctx->forest, manifest->slot );
}

static inline void
after_contact( ctx_t * ctx, fd_gossip_update_message_t const * msg ) {
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
}

static inline void
after_sign( ctx_t             * ctx,
            ulong               in_idx,
            ulong               sig,
            fd_stem_context_t * stem ) {
  ulong pending_key = sig >> 32;
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

  fd_policy_peer_t * active         = fd_policy_peer_query( ctx->policy, &pending->msg.shred.to );
  int                is_regular_req = pending->msg.kind == FD_REPAIR_KIND_SHRED && pending->msg.shred.nonce > 0; // not a highest/orphan request

  if( FD_UNLIKELY( !active ) ) {
    if( FD_LIKELY( is_regular_req ) ) {
      /* Artificially add to the inflights table, pretend we've sent it
         and let the inflight timeout request it down the line. */
      fd_inflights_request_insert( ctx->inflights, pending->msg.shred.nonce, &pending->msg.shred.to, pending->msg.shred.slot, pending->msg.shred.shred_idx );
    }
    return;
  }
  /* Happy path - all is well, our peer didn't drop out from beneath us. */
  if( FD_LIKELY( is_regular_req ) ) {
    fd_inflights_request_insert( ctx->inflights, pending->msg.shred.nonce, &pending->msg.shred.to, pending->msg.shred.slot, pending->msg.shred.shred_idx );
    fd_policy_peer_request_update( ctx->policy, &pending->msg.shred.to );
  }

  if( FD_UNLIKELY( pending->msg.kind == FD_REPAIR_KIND_ORPHAN ) ) ctx->metrics->last_requested_orphan = pending->msg.orphan.slot;
  else                                                            ctx->metrics->last_requested_slot   = pending->msg.shred.slot;

  send_packet( ctx, stem, active->ip4, active->port, src_ip4, pending->buf, pending->buflen, fd_frag_meta_ts_comp( fd_tickcount() ) );
}

static int
blk_insert_check( ctx_t * ctx, fd_forest_blk_t * new_blk, ulong new_slot, ulong evicted ) {
  if( FD_UNLIKELY( !new_blk ) ) {
    ctx->metrics->blk_failed_insert++;
    ctx->metrics->slot_failed_insert = new_slot;
    return 0;
  } else {
    if( FD_UNLIKELY( evicted != ULONG_MAX ) ) {
      ctx->metrics->blk_evicted++;
      ctx->metrics->slot_evicted    = evicted;
      ctx->metrics->slot_evicted_by = new_slot;
    }
    return 1;
  }
}

static inline void
after_shred( ctx_t      * ctx,
             ulong        sig,
             fd_shred_t * shred,
             ulong        nonce,
             fd_hash_t *  mr,
             fd_hash_t *  cmr ) {
  /* Insert the shred sig (shared by all shred members in the FEC set)
      into the map. */
  int is_code = fd_shred_is_code( fd_shred_type( shred->variant ) );
  int src     = fd_shred_sig_src( sig )==SHRED_SIG_SRC_TURBINE ? SHRED_SRC_TURBINE : SHRED_SRC_REPAIR /* bad or good repair */ ;

  if( FD_LIKELY( !is_code ) ) {
    long rtt = 0;
    fd_pubkey_t peer;
    if( FD_UNLIKELY( src == SHRED_SRC_REPAIR && ( rtt = fd_inflights_request_remove( ctx->inflights, nonce, shred->slot, shred->idx, &peer ) ) > 0 ) ) {
      fd_policy_peer_response_update( ctx->policy, &peer, rtt );
      fd_histf_sample( ctx->metrics->response_latency, (ulong)rtt );
    }

    /* we don't want to add a slot to the forest that chains to a slot
       older than root, to avoid filling forest up with junk.
       Especially if we are close to full and we are having trouble
       rooting, we can't rely on publishing to prune these useless
       subtrees. TODO: do the same with reasm/store/shred? */
    if( FD_UNLIKELY( shred->slot - shred->data.parent_off < fd_forest_root_slot( ctx->forest ) ) ) return;

    int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
    int ref_tick      = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
    ulong evicted     = ULONG_MAX;
    fd_forest_blk_t * blk = fd_forest_blk_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, &evicted );
    if( FD_LIKELY( blk_insert_check( ctx, blk, shred->slot, evicted ) ) ) {
      fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, shred->idx, shred->fec_set_idx, slot_complete, ref_tick, src, mr, cmr );
    }
  } else {
    fd_forest_code_shred_insert( ctx->forest, shred->slot, shred->idx );
  }
}

/* Kicks off the chained merkle verification starting at a slot with
   a confirmed, canonical block_id.  Either finishes successfully and
   returns early, or detects an incorrect FEC set and clears it.  In
   this case the verification is paused and state is saved at where
   it left off.  Verification can be re-triggered in after_fec as well. */
static inline void
check_confirmed( ctx_t           * ctx,
                 fd_forest_blk_t * blk,
                 fd_hash_t const * confirmed_bid ) {

  if( FD_LIKELY( !blk->chain_confirmed && blk->complete_idx != UINT_MAX && blk->buffered_idx == blk->complete_idx ) ) {
    /* The above conditions say that all the shreds of the block have arrived. */
    fd_forest_blk_t * bad_blk = fd_forest_fec_chain_verify( ctx->forest, blk, confirmed_bid );
    if( FD_LIKELY( !bad_blk ) ) {
      /* chain verified successfully from blk to as far as we have fec data */
      return;
    }

    uint bad_fec_idx = fd_forest_merkle_last_incorrect_idx( bad_blk );
    fd_hash_t const * expected = (bad_fec_idx == bad_blk->complete_idx - (FD_FEC_SHRED_CNT - 1)) ? &bad_blk->confirmed_bid : &bad_blk->merkle_roots[(bad_fec_idx / 32) + 1].cmr;

    FD_BASE58_ENCODE_32_BYTES( confirmed_bid->uc,                        confirmed_bid_b58 );
    FD_BASE58_ENCODE_32_BYTES( expected->uc,                             expected_mr );
    FD_BASE58_ENCODE_32_BYTES( bad_blk->merkle_roots[bad_fec_idx].mr.uc, recorded_mr );

    FD_LOG_WARNING(( "[%s] slot %lu block_id %s confirmation detected incorrect FECs. bad FEC is slot %lu fec set %u. expected mr (%s) != recorded mr (%s)",
                       __func__,
                       blk->slot,
                       confirmed_bid_b58,
                       bad_blk->slot,
                       bad_fec_idx,
                       expected_mr,
                       recorded_mr ));

    ctx->metrics->failed_chain_verify_cnt++;
    ctx->metrics->failed_chain_verify_slot = bad_blk->slot;

    /* If we have a bad block, we need to dump and repair backwards from
       the point where the merkle root is incorrect.
       We start only by dumping the last incorrect FEC. It's possible that
       this is the only incorrect one.  If it isn't though, when the slot
       recompletes, this function will trigger again and we will dump the
       second to last incorrect FEC. */

    fd_forest_fec_clear( ctx->forest, bad_blk->slot, bad_fec_idx, FD_FEC_SHRED_CNT - 1 );
  }
}

static inline void
after_fec( ctx_t      * ctx,
           fd_shred_t * shred,
           fd_hash_t  * mr,
           fd_hash_t  * cmr ) {

  /* When this is a FEC completes msg, it is implied that all the
     other shreds in the FEC set can also be inserted.  Shred inserts
     into the forest are idempotent so it is fine to insert the same
     shred multiple times. */

  int slot_complete = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );
  int ref_tick      = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;

  /* Similar to after_shred, do not insert a slot that chains to a slot older than root */
  if( FD_UNLIKELY( shred->slot - shred->data.parent_off < fd_forest_root_slot( ctx->forest ) ) ) return;
  ulong evicted  = ULONG_MAX;
  fd_forest_blk_t * ele = fd_forest_blk_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, &evicted );
  if( FD_UNLIKELY( !blk_insert_check( ctx, ele, shred->slot, evicted ) ) ) return;
  fd_forest_fec_insert( ctx->forest, shred->slot, shred->slot - shred->data.parent_off, shred->idx, shred->fec_set_idx, slot_complete, ref_tick, mr, cmr );

  /* metrics for completed slots */
  if( FD_UNLIKELY( ele->complete_idx != UINT_MAX && ele->buffered_idx==ele->complete_idx ) ) {
    long now = fd_tickcount();
    long start_ts = ele->first_req_ts == 0 || ele->slot >= ctx->turbine_slot0 ? ele->first_shred_ts : ele->first_req_ts;
    ulong duration_ticks = (ulong)(now - start_ts);
    fd_histf_sample( ctx->metrics->slot_compl_time, duration_ticks );
    fd_repair_metrics_add_slot( ctx->slot_metrics, ele->slot, start_ts, now, ele->repair_cnt, ele->turbine_cnt );
    /* Note: this log does not imply that the slot is fully executable.
       It's possible that we have a slot that doesn't chain verify,
       which could be un-executable. */
    FD_BASE58_ENCODE_32_BYTES( ele->merkle_roots[ele->complete_idx / 32].mr.uc, block_id );
    FD_BASE58_ENCODE_32_BYTES( mr->uc, fec_mr );
    FD_LOG_INFO(( "[%s] slot is complete %lu. num_data_shreds: %u, num_repaired: %u, num_turbine: %u, num_recovered: %u, duration: %.2f ms. last recvd fec: %u, mr %s. current block_id: %s",
                    __func__,
                    ele->slot,
                    ele->complete_idx + 1,
                    ele->repair_cnt,
                    ele->turbine_cnt,
                    ele->recovered_cnt,
                    (double)fd_metrics_convert_ticks_to_nanoseconds(duration_ticks) / 1e6,
                    shred->fec_set_idx,
                    fec_mr,
                    block_id ));
  }

  /* re-trigger continuation of chained merkle verification if this FEC
     set enables it  TODO MOVE TO AFTER_SHRED? */
  if( FD_UNLIKELY( ele->lowest_verified_fec == (shred->fec_set_idx / 32UL) + 1 ) &&
                   ele->buffered_idx == ele->complete_idx ) {
    check_confirmed( ctx, ele, &ele->confirmed_bid /* if lowest_verified_fec is not UINT_MAX, confirmed_bid must be populated */ );
  }
}

static inline void
after_net( ctx_t * ctx,
           ulong   sz  ) {
  fd_eth_hdr_t * eth; fd_ip4_hdr_t * ip4; fd_udp_hdr_t * udp;
  uchar * data; ulong data_sz;
  if( FD_UNLIKELY( !fd_ip4_udp_hdr_strip( ctx->net_buf, sz, &data, &data_sz, &eth, &ip4, &udp ) ) ) {
    ctx->metrics->malformed_ping++;
    return;
  }
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

static inline void
after_evict( ctx_t * ctx,
             fd_fec_evicted_t * evicted ) {
  fd_forest_fec_clear( ctx->forest, evicted->slot, evicted->fec_set_idx, FD_FEC_SHRED_CNT - 1 );
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx,
            ulong               seq    FD_PARAM_UNUSED,
            ulong               sig,
            ulong               sz,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  ctx->stem = stem;
  in_ctx_t const * in_ctx  = &ctx->in_links[ in_idx ];
  uint             in_kind = ctx->in_kind[ in_idx ];

  switch( in_kind ) {
    /* Unreliable frags */
    case IN_KIND_NET:  {
      after_net( ctx, sz );
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
      if( meta->bootstrap ) fd_forest_init( ctx->forest, 0 );
      break;
    }
    case IN_KIND_GOSSIP: {
      fd_gossip_update_message_t const * msg = (fd_gossip_update_message_t const *)fd_type_pun_const( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
      if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) ){
        after_contact( ctx, msg );
      } else {
        fd_policy_peer_remove( ctx->policy, fd_type_pun_const( msg->origin ) );
      }
      break;
    }
    case IN_KIND_REPLAY: {
      fd_replay_fec_evicted_t const * msg = (fd_replay_fec_evicted_t const *)fd_type_pun_const( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
      fd_forest_fec_clear( ctx->forest, msg->slot, msg->fec_set_idx, FD_FEC_SHRED_CNT - 1 );
      break;
    }
    case IN_KIND_TOWER: {
      if( FD_LIKELY( sig==FD_TOWER_SIG_SLOT_DONE ) ) {
        fd_tower_slot_done_t const * msg = (fd_tower_slot_done_t const *)fd_type_pun_const( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
        if( FD_LIKELY( msg->root_slot!=ULONG_MAX && msg->root_slot > fd_forest_root_slot( ctx->forest ) ) ) fd_forest_publish( ctx->forest, msg->root_slot );
      } else if( FD_LIKELY( sig==FD_TOWER_SIG_SLOT_CONFIRMED ) ) {
        fd_tower_slot_confirmed_t const * msg = (fd_tower_slot_confirmed_t const *)fd_type_pun_const( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
        if( msg->slot > fd_forest_root_slot( ctx->forest ) && (msg->level >= FD_TOWER_SLOT_CONFIRMED_DUPLICATE ) ) {
          fd_forest_blk_t * blk = fd_forest_query( ctx->forest, msg->slot );
          if( FD_UNLIKELY( !blk ) ) {
            /* If we receive a confirmation for a slot we don't have,
               create a sentinel forest block that we can repair from. */
            ulong evicted = ULONG_MAX;
            blk = fd_forest_blk_insert( ctx->forest, msg->slot, ULONG_MAX, &evicted );
            if( FD_UNLIKELY( !blk_insert_check( ctx, blk, msg->slot, evicted ) ) ) break;
          }

          /* Confirm the block */
          blk->confirmed_bid = msg->block_id;
          check_confirmed( ctx, blk, &msg->block_id );
        }
      }
      break;
    }
    case IN_KIND_SHRED: {

      /* There are 3 message types from shred:
          1. resolver evict - incomplete FEC set is evicted by resolver
          2. fec complete   - FEC set is completed by resolver. Also contains a shred.
          3. shred          - new shred

          Msgs 2 and 3 have a shred header in the dcache.  Msg 1 is empty. */

      if( FD_UNLIKELY( sig==SHRED_SIG_FEC_EVICTED ) ) {
        fd_fec_evicted_t * evicted = (fd_fec_evicted_t *)fd_type_pun( fd_chunk_to_laddr( in_ctx->mem, ctx->chunk ) );
        after_evict( ctx, evicted );
        return;
      }

      uchar * src = fd_chunk_to_laddr( in_ctx->mem, ctx->chunk );
      fd_shred_base_t * shred_msg = (fd_shred_base_t *)fd_type_pun( src );
      fd_shred_t      * shred     = &shred_msg->shred; /* completes & shred messages all have a shred header at the same offset (after merkle root) */

      if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) {
        ctx->metrics->old_shred++;
        return;
      };

      if( FD_UNLIKELY( shred->slot > ctx->metrics->current_slot ) ) {
        FD_LOG_INFO(( "[Turbine] slot: %lu, root: %lu", shred->slot, fd_forest_root_slot( ctx->forest ) ));
        ctx->metrics->current_slot = shred->slot;
      }

      if( FD_UNLIKELY( ctx->turbine_slot0 == ULONG_MAX ) ) {
        ctx->turbine_slot0 = shred->slot;
        fd_repair_metrics_set_turbine_slot0( ctx->slot_metrics, shred->slot );
        fd_policy_set_turbine_slot0( ctx->policy, shred->slot );

        /* On first turbine shred, seed repair by queuing highest_shred
           requests for slots between snapshot and turbine_slot0. This
           bypasses forest entirely and dispatches directly via the sign
           queue. Cap at half queue capacity to leave room for pongs. */
        ulong root = fd_forest_root_slot( ctx->forest );
        if( FD_LIKELY( root != ULONG_MAX && shred->slot > root ) ) {
          ulong capacity = fd_signs_queue_max( ctx->pong_queue ) - fd_signs_queue_cnt( ctx->pong_queue );
          ulong seed_cnt = fd_ulong_min( shred->slot-root, capacity/2 );
          long  now_ms   = fd_log_wallclock()/(long)1e6;
          for( ulong i=1; i<=seed_cnt; i++ ) {
            ulong slot = root + i;
            fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
            if( FD_UNLIKELY( !peer ) ) break;
            fd_repair_msg_t * msg = fd_repair_highest_shred( ctx->protocol, peer, (ulong)now_ms, 0, slot, 0 );
            if( FD_LIKELY( msg ) )  fd_signs_queue_push( ctx->pong_queue, (sign_pending_t){ .msg = *msg } );
          }
        }
      }


      if( FD_UNLIKELY( sig==SHRED_SIG_FEC_COMPLETE || sig==SHRED_SIG_FEC_COMPLETE_LEADER ) ) {
        fd_fec_complete_t * complete_msg = (fd_fec_complete_t *)fd_type_pun( src );
        after_fec( ctx, &complete_msg->last_shred_hdr, &complete_msg->merkle_root, &complete_msg->chained_merkle_root );

        /* forward along to replay */
        memcpy( fd_chunk_to_laddr( ctx->repair_out_ctx->mem, ctx->repair_out_ctx->chunk ), src, sz );
        fd_stem_publish( ctx->stem, ctx->repair_out_ctx->idx, sig, ctx->repair_out_ctx->chunk, sz, 0UL, 0UL, tspub );
        ctx->repair_out_ctx->chunk = fd_dcache_compact_next( ctx->repair_out_ctx->chunk, sz, ctx->repair_out_ctx->chunk0, ctx->repair_out_ctx->wmark );
      } else if( FD_LIKELY( fd_shred_sig_res( sig )!=SHRED_SIG_RESULT_EQVOC ) ) {
        fd_hash_t * cmr = (fd_hash_t *)fd_type_pun(shred_msg->shred_ + fd_shred_chain_off( shred->variant ));
        after_shred( ctx, sig, shred, shred_msg->rnonce, &shred_msg->merkle_root, cmr );
      }

      /* update metrics */
      ctx->metrics->repaired_slots = fd_forest_highest_repaired_slot( ctx->forest );
      return;
    }
    default: FD_LOG_ERR(( "bad in_kind %u", in_kind )); /* Should never reach here since before_frag should have filtered out any unexpected frags. */
  }
}

static inline void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem FD_PARAM_UNUSED,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {
  long now = fd_log_wallclock();

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

  if( FD_UNLIKELY( fd_inflights_should_drain( ctx->inflights, now ) ) ) {
    ulong nonce; ulong slot; ulong shred_idx;
    *charge_busy = 1;
    fd_inflights_request_pop( ctx->inflights, &nonce, &slot, &shred_idx );
    fd_forest_blk_t * blk = fd_forest_query( ctx->forest, slot );
    if( FD_UNLIKELY( blk && !fd_forest_blk_idxs_test( blk->idxs, shred_idx ) ) ) {
      fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
      ctx->metrics->rerequest++;
      nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, slot, (uint)shred_idx, now );
      if( FD_UNLIKELY( !peer ) ) {
        /* No peers. But we CANNOT lose this request. */
        /* Add this request to the inflights table, pretend we've sent it and let the inflight timeout request it down the line. */
        fd_hash_t hash = { .ul[0] = 0 };
        fd_inflights_request_insert( ctx->inflights, nonce, &hash, slot, shred_idx );
      } else {
        fd_repair_msg_t * msg = fd_repair_shred( ctx->protocol, peer, (ulong)now/(ulong)1e6, (uint)nonce, slot, shred_idx );
        fd_repair_send_sign_request( ctx, sign_out, msg, NULL );
        return;
      }
    }
  }

  if( FD_UNLIKELY( fd_inflights_outstanding_free( ctx->inflights ) <= fd_signs_map_key_cnt( ctx->signs_map ) ) ) return; /* no new requests allowed */

  fd_repair_msg_t const * cout = fd_policy_next( ctx->policy, ctx->forest, ctx->protocol, now, ctx->metrics->current_slot, charge_busy );
  if( FD_UNLIKELY( !cout ) ) return;
  fd_repair_send_sign_request( ctx, sign_out, cout, NULL );
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
      default:
        FD_LOG_CRIT(( "Unhandled repair kind %u", signable.msg.kind ));
        break;
    }
    fd_signs_queue_push( ctx->pong_queue, signable );
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
    FD_CRIT( ctx->halt_signing, "state machine corruption" );
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
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  fd_memset( ctx, 0, sizeof(ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->repair.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key.uc, identity_key, sizeof(fd_pubkey_t) );

  FD_TEST( fd_rng_secure( &ctx->repair_seed, sizeof(ulong) ) );

  FD_LOG_DEBUG(( "Generating rnonce_ss" ));
  ulong rnonce_ss_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "rnonce_ss" );
  FD_TEST( rnonce_ss_id!=ULONG_MAX );
  void * shared_rnonce = fd_topo_obj_laddr( topo, rnonce_ss_id );
  ulong * nonce_initialized = (ulong *)(sizeof(fd_rnonce_ss_t)+(uchar *)shared_rnonce);
  FD_TEST( fd_rng_secure( shared_rnonce, sizeof(fd_rnonce_ss_t) ) );
  memcpy( ctx->repair_nonce_ss, shared_rnonce, sizeof(fd_rnonce_ss_t) );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *nonce_initialized ) = 1UL;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong total_sign_depth = tile->repair.repair_sign_depth * tile->repair.repair_sign_cnt;
  int   lg_sign_depth    = fd_ulong_find_msb( fd_ulong_pow2_up(total_sign_depth) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),            sizeof(ctx_t)                                                 );
  ctx->protocol     = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),         fd_repair_footprint()                                         );
  ctx->forest       = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(),         fd_forest_footprint( tile->repair.slot_max )                  );
  ctx->policy       = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),         fd_policy_footprint( FD_DEDUP_CACHE_MAX, FD_REPAIR_PEER_MAX ) );
  ctx->inflights    = FD_SCRATCH_ALLOC_APPEND( l, fd_inflights_align(),      fd_inflights_footprint()                                      );
  ctx->signs_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_signs_map_align(),      fd_signs_map_footprint( lg_sign_depth )                       );
  ctx->pong_queue   = FD_SCRATCH_ALLOC_APPEND( l, fd_signs_queue_align(),    fd_signs_queue_footprint()                                    );
  ctx->slot_metrics = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_metrics_align(), fd_repair_metrics_footprint()                                 );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() ) == (ulong)scratch + scratch_footprint( tile ) );

  ctx->protocol     = fd_repair_join        ( fd_repair_new        ( ctx->protocol, &ctx->identity_public_key                                                      ) );
  ctx->forest       = fd_forest_join        ( fd_forest_new        ( ctx->forest,   tile->repair.slot_max, ctx->repair_seed                                        ) );
  ctx->policy       = fd_policy_join        ( fd_policy_new        ( ctx->policy,   FD_DEDUP_CACHE_MAX, FD_REPAIR_PEER_MAX, ctx->repair_seed, ctx->repair_nonce_ss ) );
  ctx->inflights    = fd_inflights_join     ( fd_inflights_new     ( ctx->inflights, ctx->repair_seed+1234UL                                                       ) );
  ctx->signs_map    = fd_signs_map_join     ( fd_signs_map_new     ( ctx->signs_map, lg_sign_depth, 0UL                                                            ) );
  ctx->pong_queue   = fd_signs_queue_join   ( fd_signs_queue_new   ( ctx->pong_queue                                                                               ) );
  ctx->slot_metrics = fd_repair_metrics_join( fd_repair_metrics_new( ctx->slot_metrics                                                                             ) );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->halt_signing = 0;

  /* Process in links */

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "repair tile has too many input links" ));

  uint  sign_repair_in_idx[ MAX_SIGN_TILE_CNT ] = {0};
  uint  sign_repair_idx  = 0;
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
    }
    else if( 0==strcmp( link->name, "gossip_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_GOSSIP;
    else if( 0==strcmp( link->name, "tower_out"    ) ) ctx->in_kind[ in_idx ] = IN_KIND_TOWER;
    else if( 0==strcmp( link->name, "shred_out"    ) ) ctx->in_kind[ in_idx ] = IN_KIND_SHRED;
    else if( 0==strcmp( link->name, "snapin_manif" ) ) ctx->in_kind[ in_idx ] = IN_KIND_SNAP;
    else if( 0==strcmp( link->name, "genesi_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_GENESIS;
    else if( 0==strcmp( link->name, "replay_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_REPLAY;
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
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];

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
  if( FD_UNLIKELY( fd_signs_map_key_max( ctx->signs_map ) < tile->repair.repair_sign_depth * tile->repair.repair_sign_cnt ) ) {
    FD_LOG_ERR(( "Repair pending signs tracking map is too small: %lu < %lu.", fd_signs_map_key_max( ctx->signs_map ), tile->repair.repair_sign_depth * tile->repair.repair_sign_cnt ));
  }

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->repair_intake_addr.port = fd_ushort_bswap( tile->repair.repair_intake_listen_port );
  ctx->repair_serve_addr.port  = fd_ushort_bswap( tile->repair.repair_serve_listen_port  );

  /* TODO clean these up */
  ctx->net_id = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->intake_hdr, 0, 0, tile->repair.repair_intake_listen_port );
  fd_ip4_udp_hdr_init( ctx->serve_hdr,  0, 0, tile->repair.repair_serve_listen_port  );

  /* Repair set up */

  ctx->turbine_slot0 = ULONG_MAX;
  FD_LOG_INFO(( "repair my addr - intake addr: " FD_IP4_ADDR_FMT ":%u, serve_addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_intake_addr.addr ), fd_ushort_bswap( ctx->repair_intake_addr.port ),
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_serve_addr.addr ), fd_ushort_bswap( ctx->repair_serve_addr.port ) ));

  memset( ctx->metrics, 0, sizeof(ctx->metrics) );

  fd_histf_join( fd_histf_new( ctx->metrics->slot_compl_time, FD_MHIST_SECONDS_MIN( REPAIR, SLOT_COMPLETE_TIME ),
                                                              FD_MHIST_SECONDS_MAX( REPAIR, SLOT_COMPLETE_TIME ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->response_latency, FD_MHIST_MIN( REPAIR, RESPONSE_LATENCY ),
                                                               FD_MHIST_MAX( REPAIR, RESPONSE_LATENCY ) ) );

  ctx->tsdebug = fd_log_wallclock();
  ctx->pending_key_next = 0;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_repair_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
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
  FD_MCNT_SET( REPAIR, OLD_SHRED,         ctx->metrics->old_shred );
  FD_MCNT_SET( REPAIR, REQUEST_PEERS,     fd_policy_peer_pool_used( ctx->policy->peers.pool ) );
  FD_MCNT_SET( REPAIR, SIGN_TILE_UNAVAIL, ctx->metrics->sign_tile_unavail );
  FD_MCNT_SET( REPAIR, REREQUEST_QUEUE,   ctx->metrics->rerequest );

  FD_MGAUGE_SET( REPAIR, LAST_REQUESTED_SLOT,   ctx->metrics->last_requested_slot );
  FD_MGAUGE_SET( REPAIR, LAST_REQUESTED_ORPHAN, ctx->metrics->last_requested_orphan );
  FD_MGAUGE_SET( REPAIR, INFLIGHT_REQUESTS,     fd_inflight_pool_used( ctx->inflights->pool ) - ctx->inflights->popped_cnt );

  FD_MCNT_SET      ( REPAIR, TOTAL_PKT_COUNT, ctx->metrics->send_pkt_cnt   );
  FD_MCNT_ENUM_COPY( REPAIR, SENT_PKT_TYPES,  ctx->metrics->sent_pkt_types );

  FD_MHIST_COPY( REPAIR, SLOT_COMPLETE_TIME, ctx->metrics->slot_compl_time );
  FD_MHIST_COPY( REPAIR, RESPONSE_LATENCY,   ctx->metrics->response_latency );

  FD_MCNT_SET  ( REPAIR, BLK_EVICTED,        ctx->metrics->blk_evicted );
  FD_MCNT_SET  ( REPAIR, BLK_FAILED_INSERT,  ctx->metrics->blk_failed_insert );
  FD_MGAUGE_SET( REPAIR, SLOT_EVICTED,       ctx->metrics->slot_evicted );
  FD_MGAUGE_SET( REPAIR, SLOT_EVICTED_BY,    ctx->metrics->slot_evicted_by );
  FD_MGAUGE_SET( REPAIR, SLOT_FAILED_INSERT, ctx->metrics->slot_failed_insert );

  FD_MCNT_SET  ( REPAIR, FAILED_CHAIN_VERIFY_CNT,  ctx->metrics->failed_chain_verify_cnt );
  FD_MGAUGE_SET( REPAIR, FAILED_CHAIN_VERIFY_SLOT, ctx->metrics->failed_chain_verify_slot );

  FD_MCNT_SET( REPAIR, UNKNOWN_PEER_PING,     ctx->metrics->unknown_peer_ping );
  FD_MCNT_SET( REPAIR, MALFORMED_PING,        ctx->metrics->malformed_ping );
  FD_MCNT_SET( REPAIR, FAILED_SIGVERIFY_PING, ctx->metrics->fail_sigverify_ping );
}

#undef DEBUG_LOGGING

/* At most one sign request is made in after_credit.  Then at most one
   message is published in after_frag. */
#define STEM_BURST (2UL)

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
