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
#include "../../disco/store/fd_store.h"
#include "fd_rotor_tile.h"
#include "../replay/fd_replay_tile.h"
#include "../votor/fd_votor_tile.h"
#include "../restore/utils/fd_ssmsg.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/pod/fd_pod_format.h"

#include "../repair/fd_repair.h"
#include "../repair/fd_policy.h"
#include "../repair/fd_inflight.h"
#include "fd_chainer.h"
#include "fd_schedulor.h"
#include "fd_requestor.h"
#include "fd_repair_stats.h"
#include "fd_rotor_tile_private.h"

#define IN_KIND_CONTACT (0)
#define IN_KIND_NET     (1)
#define IN_KIND_SHRED   (2)
#define IN_KIND_SIGN    (3)
#define IN_KIND_SNAP    (4)
#define IN_KIND_GOSSIP  (5)
#define IN_KIND_GENESIS (6)
#define IN_KIND_REPLAY  (7)
#define IN_KIND_VOTOR   (8)

#define MAX_IN_LINKS      (32)
#define MAX_SIGN_TILE_CNT (16UL)
struct ctx {
  fd_clock_tile_t clock[1];

  ulong       repair_seed;
  fd_pubkey_t identity_public_key;

  fd_chainer_t *      chainer;   /* slot version / FEC store */
  fd_schedulor_t *    schedulor; /* blocks to check, by timeout */
  fd_requestor_t *    requestor; /* cursor walk of the block being repaired */
  fd_repair_t *       protocol;  /* repair message construction */
  fd_policy_t *       policy;    /* repair peers and selection */
  fd_inflights_t *    rtt;       /* sent requests by nonce, for response latency only */
  fd_repair_stats_t * stats;  /* per-slot repair timing, the legacy forest stats */

  fd_store_t *     store;     /* rotor publishes/removes FEC sets to/from the store */
  fd_store_map_t   store_map[1];

  fd_keyswitch_t * keyswitch;
  int              halt_signing;

  /* When set, publish_fec_replay re-publishes the entire ancestry path
     of FECs from the chainer root down to the FEC being delivered, so
     replay can reconstruct a fork it evicted.  See fd_rotor_tile.h. */
  int         deliver_from_root;
  out_ele_t * redeliver;

  /* Pending sign requests */

  ulong            pending_key_next;
  sign_req_t *     signs_map;
  sign_pending_t * toss_queue;

  fd_wksp_t * wksp;

  fd_stem_context_t * stem;

  uchar    in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];


  out_ctx_t net_out_ctx   [1];
  out_ctx_t replay_out_ctx[1];

  /* repair_sign links (to sign tiles 1+), round-robin */
  ulong     repair_sign_cnt;
  out_ctx_t repair_sign_out_ctx[ MAX_SIGN_TILE_CNT ];

  /* Buffer for incoming net frags */
  uchar net_buf[ FD_NET_MTU ];

  /* The snapshot manifest arrives on one frag and is applied on the
     DONE frag that follows; snapin_manif is reliable so the chunk
     stays valid in between. */
  ulong manifest_chunk;

  ushort            net_id;
  fd_ip4_udp_hdrs_t intake_hdr[1];

  fd_rnonce_ss_t repair_nonce_ss[1];
  uint           ag_nonce; /* counter nonce for alpenglow metadata requests */

  ulong turbine_slot0; /* first turbine slot seen */
  int   catchup_seeded; /* the root..turbine_slot0 seed burst has been sent */
  ulong current_slot;  /* highest turbine slot seen */

  struct {
    ulong send_pkt_cnt;
    ulong sent_by_kind[ 16 ];
    ulong checks;
    ulong no_peer;
    ulong malformed_ping;
    ulong unknown_peer_ping;
    ulong fail_sigverify_ping;
    ulong unsolicited_meta;
    ulong failed_parent_fec_count;
    ulong failed_fec_root;
    ulong fecs_delivered;
    ulong shred_old;               /* shreds at or below the root */
    ulong sign_unavail;            /* no sign tile credit available */

    /* the two replay message kinds rotor acts on, counted in before_frag */
    ulong replay_root_advanced;
    ulong replay_missing_fec;

    /* response side */
    ulong repair_shred_rx;         /* data shreds that arrived as repair responses */
    ulong shred_match_block_id;    /* ... credited to a ShredForBlockId request */
    ulong shred_match_positional;  /* ... credited to a positional Shred request */
    ulong shred_match_miss;        /* ... matching no outstanding request */
    ulong meta_rx;                 /* metadata responses received */
    ulong meta_malformed;          /* ... that failed to decode */
    ulong meta_ok_parent_fec_count;
    ulong meta_ok_fec_root;

    fd_histf_t response_latency[ 1 ];
  } metrics[ 1 ];
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

FD_FN_PURE static inline int
lg_sign_depth( fd_topo_tile_t const * tile ) {
  ulong total_sign_depth = tile->rotor.repair_sign_depth * tile->rotor.repair_sign_cnt;
  return fd_ulong_find_msb( fd_ulong_pow2_up( total_sign_depth ) ) + 1;
}

/* block_max is the chainer's block pool size, which is also the
   schedulor's task count. */

FD_FN_PURE static inline ulong
block_max( fd_topo_tile_t const * tile ) {
  return tile->rotor.slot_max * FD_CHAINER_SLOT_VER_MAX;
}

FD_FN_PURE static inline ulong
fec_max( fd_topo_tile_t const * tile ) {
  return block_max( tile ) * ( tile->rotor.max_shreds_per_block / FD_FEC_SHRED_CNT );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),          sizeof(ctx_t)                                                                     );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(),       fd_repair_footprint    ()                                                         );
  l = FD_LAYOUT_APPEND( l, fd_chainer_align(),      fd_chainer_footprint   ( tile->rotor.slot_max, tile->rotor.max_shreds_per_block ) );
  l = FD_LAYOUT_APPEND( l, fd_schedulor_align(),    fd_schedulor_footprint ( block_max( tile ) )                                      );
  l = FD_LAYOUT_APPEND( l, fd_requestor_align(),    fd_requestor_footprint ()                                                         );
  l = FD_LAYOUT_APPEND( l, fd_policy_align(),       fd_policy_footprint    ( FD_REPAIR_PEER_MAX )                                     );
  l = FD_LAYOUT_APPEND( l, fd_inflights_align(),    fd_inflights_footprint ()                                                         );
  l = FD_LAYOUT_APPEND( l, fd_repair_stats_align(), fd_repair_stats_footprint( tile->rotor.slot_max )                                 );
  l = FD_LAYOUT_APPEND( l, fd_signs_map_align(),    fd_signs_map_footprint ( lg_sign_depth( tile ) )                                  );
  l = FD_LAYOUT_APPEND( l, toss_queue_align(),      toss_queue_footprint   ()                                                         );
  l = FD_LAYOUT_APPEND( l, out_queue_align(),       out_queue_footprint    ( fec_max( tile ) )                                        );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* Sign pipeline */

static sign_req_t *
sign_map_insert( ctx_t *                 ctx,
                 fd_repair_msg_t const * msg,
                 pong_data_t const *     opt_pong_data ) {
  if( FD_UNLIKELY( fd_signs_map_key_cnt( ctx->signs_map )==fd_signs_map_key_max( ctx->signs_map ) ) ) return NULL;

  sign_req_t * pending = fd_signs_map_insert( ctx->signs_map, ctx->pending_key_next++ );
  if( FD_UNLIKELY( !pending ) ) return NULL; /* Not possible, unless the same key is used twice. */
  pending->msg    = *msg;
  pending->buflen = fd_repair_sz( msg );
  if( FD_UNLIKELY( opt_pong_data ) ) pending->pong_data = *opt_pong_data;
  return pending;
}

static void
send_packet( ctx_t *             ctx,
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

/* sign_avail_credits returns the sign_out context with the most
   available credits, or NULL if none has any. */

static out_ctx_t *
sign_avail_credits( ctx_t * ctx ) {
  out_ctx_t * sign_out    = NULL;
  ulong       max_credits = 0;
  for( uint i=0; i<ctx->repair_sign_cnt; i++ ) {
    if( ctx->repair_sign_out_ctx[i].credits > max_credits ) {
      max_credits =  ctx->repair_sign_out_ctx[i].credits;
      sign_out    = &ctx->repair_sign_out_ctx[i];
    }
  }
  return sign_out;
}

static void
send_sign_request( ctx_t *                 ctx,
                   fd_stem_context_t *     stem,
                   out_ctx_t *             sign_out,
                   fd_repair_msg_t const * msg,
                   pong_data_t const *     opt_pong_data ) {
  if( FD_UNLIKELY( ctx->halt_signing ) ) FD_LOG_CRIT(( "can't dispatch sign requests while halting signing" ));

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
    uchar * preimage = preimage_req( &pending->msg, &preimage_sz );
    fd_memcpy( dst, preimage, preimage_sz );
    sig = ((ulong)pending->key << 32) | (uint)FD_KEYGUARD_SIGN_TYPE_ED25519;
  }

  fd_stem_publish( stem, sign_out->idx, sig, sign_out->chunk, preimage_sz, 0UL, 0UL, 0UL );
  sign_out->chunk = fd_dcache_compact_next( sign_out->chunk, preimage_sz, sign_out->chunk0, sign_out->wmark );

  if( FD_LIKELY( msg->kind<16U ) ) ctx->metrics->sent_by_kind[ msg->kind ]++;
  sign_out->credits--;
}

static void
dispatch_request( ctx_t *                    ctx,
                  fd_stem_context_t *        stem,
                  out_ctx_t *                sign_out,
                  fd_rotor_request_t const * req,
                  long                       now ) {
  fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
  if( FD_UNLIKELY( !peer ) ) { ctx->metrics->no_peer++; return; }

  ulong             now_ms = (ulong)( now/(long)1e6 );
  fd_repair_msg_t * msg;

  switch( req->kind ) {
  case FD_REPAIR_KIND_SHRED: {
    uint nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, req->slot, req->idx, now );
    msg = fd_repair_shred( ctx->protocol, peer, now_ms, nonce, req->slot, req->idx );
    fd_inflights_shred_insert( ctx->rtt, FD_REPAIR_KIND_SHRED, nonce, peer, req->slot, req->idx, NULL, NULL, now );
    break;
  }
  case FD_REPAIR_KIND_HIGHEST_SHRED: {
    uint nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 0, req->slot, 0U, now );
    msg = fd_repair_highest_shred( ctx->protocol, peer, now_ms, nonce, req->slot, 0 );
    break;
  }
  case FD_REPAIR_KIND_ORPHAN: {
    uint nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 0, req->slot, 0U, now );
    msg = fd_repair_orphan( ctx->protocol, peer, now_ms, nonce, req->slot );
    break;
  }
  case AG_REPAIR_KIND_PARENT_FEC_COUNT: {
    uint nonce = ctx->ag_nonce++;
    msg = ag_repair_parent_and_fec_set_count( ctx->protocol, peer, now_ms, nonce, req->slot, &req->block_id );
    fd_inflights_meta_insert( ctx->rtt, nonce, AG_REPAIR_KIND_PARENT_FEC_COUNT, peer, req->slot, &req->block_id, 0U, now );
    break;
  }
  case AG_REPAIR_KIND_FEC_ROOT: {
    uint nonce = ctx->ag_nonce++;
    msg = ag_repair_fec_set_root( ctx->protocol, peer, now_ms, nonce, req->slot, &req->block_id, req->idx );
    fd_inflights_meta_insert( ctx->rtt, nonce, AG_REPAIR_KIND_FEC_ROOT, peer, req->slot, &req->block_id, req->idx, now );
    break;
  }
  case AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID: {
    uint nonce = fd_rnonce_ss_compute( ctx->repair_nonce_ss, 1, req->slot, req->idx, now );
    msg = ag_repair_shred_block_id( ctx->protocol, peer, now_ms, nonce, req->slot, &req->block_id, req->idx );
    fd_inflights_shred_insert( ctx->rtt, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, nonce, peer, req->slot, req->idx, &req->block_id, &req->fec_root, now );
    break;
  }
  default:
    FD_LOG_CRIT(( "bad request kind %u", req->kind ));
  }

  send_sign_request( ctx, stem, sign_out, msg, NULL );
  fd_policy_peer_request_update( ctx->policy, peer );
}

/* Repair drivers

   The chainer reports what each call did through its return value, the
   block it created if any; completion is stamped on the block itself
   (complete_ts) and read from there.  A new block is checked right
   away.  A block whose metadata just landed is not pulled forward: its
   parked check picks the metadata up when it fires, within one parent
   timeout.  A completed block needs no action: its parked check
   fires within one timeout and asks for its ancestry if the parent is
   absent, or answers DONE.  Stale checks, for a turbine block renamed
   at finalization or a pruned slot, pop, find nothing and are dropped
   by the requestor.  FEC eviction schedules nothing for now: the block
   is re-asked on its next timeout. */

static inline void
block_created( ctx_t *                    ctx,
               fd_chainer_block_t const * block,
               long                       now ) {
  fd_repair_stats_slot_start( ctx->stats, block->slot, now );
  fd_schedulor_block_insert( ctx->schedulor, block->slot, &block->block_id, now );
}

/* handle_ping answers a repair ping with a signed pong.  ip4/udp point
   at the stripped headers, needed to address the pong. */

static inline void
handle_ping( ctx_t *              ctx,
            uchar const *        data,
            ulong                data_sz,
            fd_ip4_hdr_t const * ip4,
            fd_udp_hdr_t const * udp ) {
  fd_ip4_port_t peer_addr = { .addr=ip4->saddr, .port=udp->net_sport };

  fd_repair_ping_t ping[1];
  if( FD_UNLIKELY( fd_repair_ping_de( ping, data, data_sz ) ) ) { ctx->metrics->malformed_ping++; return; }

  fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &ping->ping.from );
  if( FD_UNLIKELY(  !peer ) ) { ctx->metrics->unknown_peer_ping++; return; }

  if( FD_UNLIKELY( peer->ping ) )                         return; /* one queued pong per peer */
  if( FD_UNLIKELY( toss_queue_full( ctx->toss_queue ) ) ) return;

  fd_sha512_t sha[1];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( ping->ping.hash.uc, 32UL, ping->ping.sig, ping->ping.from.uc, sha ) ) ) {
    ctx->metrics->fail_sigverify_ping++;
    return;
  }

  fd_repair_msg_t * pong = fd_repair_pong( ctx->protocol, &ping->ping.hash );
  toss_queue_push( ctx->toss_queue, (sign_pending_t){ .msg = *pong, .pong_data = { .peer_addr = peer_addr, .hash = ping->ping.hash, .daddr = ip4->daddr, .key = ping->ping.from } } );
  peer->ping++;
}

static inline void
handle_meta_response( ctx_t *       ctx,
                      uchar const * data,
                      ulong         data_sz,
                      long          now ) {
  ag_repair_response_t response[1];
  ctx->metrics->meta_rx++;
  if( FD_UNLIKELY( ag_repair_response_de( response, data, data_sz, ctx->chainer->fec_blk_max ) ) ) { ctx->metrics->meta_malformed++; return; }

  fd_inflight_t request[1];
  if( FD_UNLIKELY( !fd_inflights_meta_match( ctx->rtt, response->nonce, request ) ) ) { ctx->metrics->unsolicited_meta++; return; }

  uint      kind        = request->key.kind;
  ulong     slot        = request->key.slot;
  uint      fec_set_idx = request->key.idx;
  fd_hash_t block_id    = request->block_id;
  if( FD_UNLIKELY( slot <= ctx->chainer->root ) ) return; /* rooted in flight: obsolete */

  switch( response->kind ) {
    case AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT: {
      if( FD_UNLIKELY( kind!=AG_REPAIR_KIND_PARENT_FEC_COUNT ) ) return; /* wrong kind for this nonce */

      ag_parent_fec_count_res_t * res = &response->parent_fec_set_res;
      if( FD_UNLIKELY( ag_repair_parent_fec_count_verify( res, &block_id ) ) ) {
        ctx->metrics->failed_parent_fec_count++;
        return;
      }
      if( FD_UNLIKELY( res->parent_slot < ctx->chainer->root ) ) {
        fd_schedulor_block_remove( ctx->schedulor, slot, &block_id ); /* dead fork: will never connect */
        return;
      }
      fd_chainer_block_t * parent = fd_chainer_verified_parent_fec_count( ctx->chainer, slot, &block_id, res->fec_set_count, res->parent_slot, &res->parent_block_id );
      if( FD_UNLIKELY( parent ) ) block_created( ctx, parent, now );
      ctx->metrics->meta_ok_parent_fec_count++;
      break;
    }
    case AG_REPAIR_RESPONSE_FEC_SET_ROOT: {
      if( FD_UNLIKELY( kind!=AG_REPAIR_KIND_FEC_ROOT ) ) return;

      ag_fec_root_res_t * res = &response->fec_set_root;
      if( FD_UNLIKELY( ag_repair_fec_set_root_verify( res, &block_id, fec_set_idx ) ) ) {
        ctx->metrics->failed_fec_root++;
        return;
      }
      fd_hash_t fec_root_mr = {0}; /* the response carries only the 20-byte root prefix */
      memcpy( fec_root_mr.uc, res->root, FD_SHRED_MERKLE_NODE_SZ );
      fd_chainer_block_t * created = fd_chainer_verified_hash_insert( ctx->chainer, slot, &block_id, fec_set_idx, &fec_root_mr );
      if( FD_UNLIKELY( created ) ) block_created( ctx, created, now );
      ctx->metrics->meta_ok_fec_root++;
      break;
    }
    default: break;
  }
}

/* Inputs */

static int
before_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_LIKELY  ( in_kind==IN_KIND_NET    ) ) return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR;
  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED  ) ) return fd_int_if( ctx->chainer->root==ULONG_MAX, -1, 0 );
  if( FD_UNLIKELY( in_kind==IN_KIND_GOSSIP ) ) return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  if( FD_UNLIKELY( in_kind==IN_KIND_REPLAY ) ) {
    ctx->metrics->replay_root_advanced += (ulong)( sig==REPLAY_SIG_ROOT_ADVANCED );
    ctx->metrics->replay_missing_fec   += (ulong)( sig==REPLAY_SIG_MISSING_FEC   );
    return sig!=REPLAY_SIG_MISSING_FEC && sig!=REPLAY_SIG_ROOT_ADVANCED;
  }
  if( FD_UNLIKELY( in_kind==IN_KIND_VOTOR  ) ) return sig!=FD_VOTOR_SIG_REPAIR;
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
  uint             in_kind =  ctx->in_kind[ in_idx ];
  in_ctx_t const * in_ctx  = &ctx->in_links[ in_idx ];

  if( FD_LIKELY( in_kind!=IN_KIND_NET ) ) return;

  ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
  FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
  uchar const * dcache_entry = fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz );
  fd_memcpy( ctx->net_buf, dcache_entry, sz );
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx,
            ulong               seq    FD_PARAM_UNUSED,
            ulong               sig    FD_PARAM_UNUSED,
            ulong               sz,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub  FD_PARAM_UNUSED,
            fd_stem_context_t * stem   FD_PARAM_UNUSED ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]!=IN_KIND_NET ) ) return; /* returnable_frag */

  fd_eth_hdr_t * eth; fd_ip4_hdr_t * ip4; fd_udp_hdr_t * udp; uchar * data; ulong data_sz;
  if( FD_UNLIKELY( !fd_ip4_udp_hdr_strip( ctx->net_buf, sz, &data, &data_sz, &eth, &ip4, &udp ) ) ) { ctx->metrics->malformed_ping++; return; }

  if( FD_LIKELY( data_sz==sizeof(fd_repair_ping_t) ) ) handle_ping( ctx, data, data_sz, ip4, udp );
  else                                                 handle_meta_response( ctx, data, data_sz, fd_clock_tile_now( ctx->clock ) );
}

static inline void
handle_snap( ctx_t *       ctx,
             uchar const * chunk ) {
  fd_snapshot_manifest_t const * manifest = (fd_snapshot_manifest_t const *)fd_type_pun_const( chunk );
  fd_chainer_init( ctx->chainer, manifest->slot, (fd_hash_t const *)fd_type_pun_const( manifest->block_id ) );
}

static inline void
handle_genesis( ctx_t *       ctx,
                ulong         sig,
                uchar const * chunk ) {
  FD_TEST( sizeof(fd_genesis_meta_t)<=sig );
  fd_genesis_meta_t const * meta = (fd_genesis_meta_t const *)fd_type_pun_const( chunk );
  fd_hash_t block_id = {0};
  if( meta->bootstrap ) fd_chainer_init( ctx->chainer, 0, &block_id );
}

static void maybe_seed_catchup( ctx_t * ctx );

static inline void
handle_gossip( ctx_t *                            ctx,
              fd_gossip_update_message_t const * msg,
              ulong                              sig ) {
  /* defined below; fires when both turbine_slot0 and enough peers exist */
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
      if( FD_LIKELY( peer && !toss_queue_full( ctx->toss_queue ) ) ) {
        /* Prepay the ping-pong round trip: send a placeholder request
           as soon as we learn a peer's contact info. */
        fd_repair_msg_t * init = fd_repair_shred( ctx->protocol, fd_type_pun_const( msg->origin ), (ulong)fd_log_wallclock()/1000000L, 0, 0, 0 );
        toss_queue_push( ctx->toss_queue, (sign_pending_t){ .msg = *init } );
      }
      maybe_seed_catchup( ctx ); /* may be the call that crosses the peer threshold */
      break;
    }
    default: FD_LOG_ERR(( "bad gossip sig %lu", sig ));
  }
}

static inline void
handle_sign( ctx_t *             ctx,
            ulong               in_idx,
            ulong               sig,
            uchar const *       signature,
            fd_stem_context_t * stem ) {
  ulong pending_key = sig >> 32;

  /* Return the credit to the sign tile that answered */
  for( uint i=0; i<ctx->repair_sign_cnt; i++ ) {
    if( ctx->repair_sign_out_ctx[i].in_idx == in_idx ) {
      if( FD_LIKELY( ctx->repair_sign_out_ctx[i].credits < ctx->repair_sign_out_ctx[i].max_credits ) ) ctx->repair_sign_out_ctx[i].credits++;
      break;
    }
  }

  sign_req_t * pending_ = fd_signs_map_query( ctx->signs_map, pending_key, NULL );
  if( FD_UNLIKELY( !pending_ ) ) FD_LOG_CRIT(( "No pending request found for key %lu", pending_key ));

  sign_req_t pending[1] = { *pending_ }; /* copy so the map entry can be released now */
  fd_signs_map_remove( ctx->signs_map, pending_ );

  if( FD_UNLIKELY( pending->msg.kind == FD_REPAIR_KIND_PONG ) ) {
    fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &pending->pong_data.key );
    if( FD_LIKELY( peer && peer->ping ) ) peer->ping--; /* prevent underflow if the peer was removed/readded */

    fd_memcpy( pending->msg.pong.sig, signature, 64UL );
    send_packet( ctx, stem, pending->pong_data.peer_addr.addr, pending->pong_data.peer_addr.port, pending->pong_data.daddr, pending->buf, fd_repair_sz( &pending->msg ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    return;
  }

  /* Inject the signature and send to the peer it was addressed to.  If
     the peer has since left, drop it. */
  fd_memcpy( pending->buf + 4, signature, 64UL );
  fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &pending->msg.shred.to );
  if( FD_UNLIKELY( !peer ) ) return;
  send_packet( ctx, stem, peer->ip4, peer->port, 0U, pending->buf, pending->buflen, fd_frag_meta_ts_comp( fd_tickcount() ) );
}

static inline void
handle_replay( ctx_t *       ctx,
               ulong         sig,
               uchar const * chunk ) {
  if( FD_UNLIKELY( sig==REPLAY_SIG_MISSING_FEC ) ) {
    ctx->deliver_from_root = 1;
    return;
  }
  if( FD_LIKELY( sig==REPLAY_SIG_ROOT_ADVANCED ) ) {
    fd_replay_root_advanced_t const * root = (fd_replay_root_advanced_t const *)fd_type_pun_const( chunk );
    if( FD_LIKELY( root->slot > ctx->chainer->root ) ) {
      fd_chainer_publish  ( ctx->chainer,   root->slot, &root->block_id, ctx->store );
      fd_schedulor_publish( ctx->schedulor, root->slot );
    }
  }
}

static inline void
handle_votor( ctx_t *       ctx,
              long          now,
              uchar const * chunk ) {
  /* A votor block id for a block we may not have: the chainer records
     it and the first check asks for its parent and FEC count. */

  fd_votor_repair_t const * nf = (fd_votor_repair_t const *)fd_type_pun_const( chunk );
  if( FD_UNLIKELY( nf->slot <= ctx->chainer->root ) ) return;
  fd_chainer_block_t * created = fd_chainer_verified_block_insert( ctx->chainer, nf->slot, nf->block_id );
  if( FD_LIKELY( created ) ) block_created( ctx, created, now );
}

/* ag_parse_parent_marker pulls the block's declared parent out of the
   BlockMarker.  Returns 1 and fills the out params on a well formed
   marker, 0 otherwise. */

static int
ag_parse_parent_marker( fd_shred_t const * shred,
                        ulong *            out_parent_slot,
                        fd_hash_t *        out_parent_block_id ) {
  uchar const * payload = fd_shred_data_payload( shred );
  ulong         sz      = fd_shred_payload_sz( shred );

  fd_block_marker_t marker[1];
  if( FD_UNLIKELY( fd_block_marker_de( marker, payload, sz ) ) ) return 0;

  if( marker->kind==FD_BLOCK_MARKER_KIND_HEADER ) {
    memcpy( out_parent_slot,         &marker->header.parent_slot,        8UL );
    memcpy( out_parent_block_id->uc,  marker->header.parent_block_id.uc, 32UL );
    return 1;
  }
  return 0;
}

static void
maybe_seed_catchup( ctx_t * ctx ) {
  ulong root     = ctx->chainer->root;
  ulong peer_cnt = fd_policy_peer_cnt( ctx->policy );

  if( FD_LIKELY  ( ctx->catchup_seeded           ) )               return;
  if( FD_UNLIKELY( ctx->turbine_slot0==ULONG_MAX ) )               return;
  if( FD_UNLIKELY( root==ULONG_MAX || ctx->turbine_slot0<=root ) ) return;
  if( FD_UNLIKELY( peer_cnt<64UL                 ) )               return;

  ulong capacity = toss_queue_max( ctx->toss_queue ) - toss_queue_cnt( ctx->toss_queue );
  ulong seed_cnt = fd_ulong_min( ctx->turbine_slot0-root, capacity/2 );
  long  now_ms   = fd_log_wallclock()/(long)1e6;
  ulong sent     = 0UL;
  for( ulong i=1UL; i<=seed_cnt; i++ ) {
    fd_pubkey_t const * peer = fd_policy_peer_select( ctx->policy );
    if( FD_UNLIKELY( !peer ) ) break;
    fd_repair_msg_t * msg = fd_repair_shred( ctx->protocol, peer, (ulong)now_ms, 0, root + i, 0 );
    toss_queue_push( ctx->toss_queue, (sign_pending_t){ .msg = *msg } );
    msg = fd_repair_highest_shred( ctx->protocol, peer, (ulong)now_ms, 0, root + i, 0 );
    toss_queue_push( ctx->toss_queue, (sign_pending_t){ .msg = *msg } );
    sent++;
  }
  ctx->catchup_seeded = 1;
  FD_LOG_NOTICE(( "catch-up seed: %lu slots (%lu..%lu) over %lu peers, %lu requested of %lu behind",
                  sent, root+1UL, root+sent, peer_cnt, sent, ctx->turbine_slot0-root ));
}

static void
handle_turbine_slot0( ctx_t * ctx,
                     ulong   slot ) {
  ctx->turbine_slot0 = slot;

  ulong slot_delta;
  int cf = __builtin_usubl_overflow( slot, ctx->chainer->root, &slot_delta );
  if( FD_UNLIKELY( cf || slot_delta > fd_block_pool_max( ctx->chainer->block_pool ) ) ) {
    FD_LOG_ERR(( "Catchup slot distance exceeds the repair buffer: target %lu - snapshot slot %lu > %lu. "
                 "Restart with a more recent snapshot or increase config rotor.slot_max", slot, ctx->chainer->root, fd_block_pool_max( ctx->chainer->block_pool ) ));
  }

  FD_LOG_NOTICE(( "handle_turbine_slot0: slot %lu", slot ));
  maybe_seed_catchup( ctx );
  /* TODO stem_publish to replay turbine slot 0 frag. */
}

static inline void
handle_shred( ctx_t *            ctx,
              uint               sig_src,
              fd_shred_t const * shred,
              ulong              nonce,
              fd_hash_t const *  mr,
              long               now ) {
  if( FD_UNLIKELY( shred->slot<=ctx->chainer->root ) ) { ctx->metrics->shred_old++; return; }

  if( FD_UNLIKELY( sig_src==SHRED_SIG_SRC_TURBINE ) ) {
    if( FD_UNLIKELY( shred->slot > ctx->current_slot ) ) ctx->current_slot = shred->slot;
    if( FD_UNLIKELY( ctx->turbine_slot0==ULONG_MAX ) )   handle_turbine_slot0( ctx, shred->slot );
  }

  int is_data = fd_shred_is_data( fd_shred_type( shred->variant ) );

  fd_repair_stats_shred_received( ctx->stats, shred->slot, is_data, sig_src, now );

  if( FD_UNLIKELY( !is_data ) ) return;
  if( FD_UNLIKELY( sig_src==SHRED_SIG_SRC_REPAIR && fd_rnonce_ss_normal_repair( (uint)nonce ) ) ) {
    /* Credit a repaired shred to the peer that served it.  Try the
       block-id key first, then the positional one. */
    ctx->metrics->repair_shred_rx++;
    fd_pubkey_t peer;
    long rtt = fd_inflights_shred_match( ctx->rtt, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, nonce, shred->slot, shred->idx, mr, &peer, NULL, now );
    if( FD_LIKELY( rtt ) ) ctx->metrics->shred_match_block_id++;
    else {
      rtt = fd_inflights_shred_match( ctx->rtt, FD_REPAIR_KIND_SHRED, nonce, shred->slot, shred->idx, NULL, &peer, NULL, now );
      if( FD_LIKELY( rtt ) ) ctx->metrics->shred_match_positional++;
      else                   ctx->metrics->shred_match_miss++;
    }
    if( FD_LIKELY( rtt ) ) {
      fd_policy_peer_response_update( ctx->policy, &peer, rtt );
      fd_histf_sample( ctx->metrics->response_latency, (ulong)rtt );
    }
  }

  /* Parent discovery on shred 0.  */
  ulong     parent_slot     = AG_UNKNOWN_SLOT;
  fd_hash_t parent_block_id = {0};
  if( FD_UNLIKELY( shred->idx==0U && !ag_parse_parent_marker( shred, &parent_slot, &parent_block_id ) ) ) {
    FD_LOG_WARNING(( "invalid block header in slot: %lu, ignoring shred 0", shred->slot ));
    return;
  }

  int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
  fd_chainer_block_t * created = fd_chainer_shred_insert( ctx->chainer, shred->slot, shred->idx, slot_complete, mr, parent_slot, &parent_block_id );
  if( FD_UNLIKELY( created ) ) block_created( ctx, created, now ); /* first turbine shred of the slot */
}

static inline void
handle_fec_complete( ctx_t *      ctx,
                     ulong        sig,
                     fd_shred_t * shred,
                     fd_hash_t *  mr,
                     long         now ) {
  if( FD_UNLIKELY( shred->slot <= ctx->chainer->root ) ) {
    fd_store_remove( ctx->store, ctx->store_map, mr );
    return;
  }

  int slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
  int data_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE);
  int rejected;
  fd_chainer_block_t * created = fd_chainer_fec_complete( ctx->chainer, shred->slot, shred->fec_set_idx, slot_complete, data_complete, sig==SHRED_SIG_FEC_COMPLETE_LEADER, mr, &rejected );
  if( FD_UNLIKELY( created ) ) block_created( ctx, created, now ); /* the block exists even if the set was refused */
  if( FD_UNLIKELY( rejected ) ) {
    fd_store_remove( ctx->store, ctx->store_map, mr );
    return;
  }
}

static int
returnable_frag( ctx_t *             ctx,
                 ulong               in_idx,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  uint             in_kind =  ctx->in_kind[ in_idx ];
  in_ctx_t const * in_ctx  = &ctx->in_links[ in_idx ];

  if( FD_LIKELY( in_kind==IN_KIND_NET ) ) return 0; /* return early for unreliable links */

  if( FD_UNLIKELY( sz!=0UL && ( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>in_ctx->mtu ) ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu] in kind %u", chunk, sz, in_ctx->chunk0, in_ctx->wmark, in_kind ));

  long now = fd_clock_tile_now( ctx->clock );
  switch( in_kind ) {
    case IN_KIND_SIGN:    handle_sign( ctx, in_idx, sig, fd_chunk_to_laddr_const( in_ctx->mem, chunk ), stem ); break;
    case IN_KIND_GOSSIP:  handle_gossip( ctx, fd_chunk_to_laddr_const( in_ctx->mem, chunk ), sig ); break;
    case IN_KIND_GENESIS: handle_genesis( ctx, sig, fd_chunk_to_laddr_const( in_ctx->mem, chunk ) ); break;
    case IN_KIND_REPLAY:  handle_replay( ctx, sig, fd_chunk_to_laddr_const( in_ctx->mem, chunk ) ); break;
    case IN_KIND_VOTOR:   handle_votor( ctx, now, fd_chunk_to_laddr_const( in_ctx->mem, chunk ) ); break;
    case IN_KIND_SNAP: {
      if( FD_LIKELY( fd_ssmsg_sig_message( sig )!=FD_SSMSG_DONE ) ) { ctx->manifest_chunk = chunk; break; } /* applied at DONE */
      handle_snap( ctx, fd_chunk_to_laddr_const( in_ctx->mem, ctx->manifest_chunk ) );
      break;
    }
    case IN_KIND_SHRED: {
      uint sig_src = fd_shred_sig_src( sig );
      int  sig_res = fd_shred_sig_res( sig );

      if( FD_UNLIKELY( sig_src==SHRED_SIG_FEC_EVICTED ) ) {
        fd_fec_evicted_t const * evicted = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
        if( FD_UNLIKELY( evicted->slot <= ctx->chainer->root ) ) break;
        fd_hash_t mr = evicted->merkle_root;
        fd_chainer_fec_evicted( ctx->chainer, evicted->slot, evicted->fec_set_idx, &mr ); /* no schedulor action: re-asked on the next timeout */
        break;
      }

      uchar           * src       = fd_chunk_to_laddr( in_ctx->mem, chunk );
      fd_shred_base_t * shred_msg = (fd_shred_base_t *)fd_type_pun( src );
      fd_shred_t      * shred     = &shred_msg->shred; /* completes and shred messages share the header position */

      if( FD_UNLIKELY( sig==SHRED_SIG_FEC_COMPLETE || sig==SHRED_SIG_FEC_COMPLETE_LEADER ) ) {
        fd_fec_complete_t * complete_msg = (fd_fec_complete_t *)fd_type_pun( src );
        handle_fec_complete( ctx, sig, &complete_msg->last_shred_hdr, &complete_msg->merkle_root, now );
      } else if( FD_LIKELY( sig_res!=SHRED_SIG_RESULT_EQVOC ) ) {
        handle_shred( ctx, sig_src, shred, shred_msg->rnonce, &shred_msg->merkle_root, now );
      }
      break;
    }
    default: FD_LOG_ERR(( "unreachable" ));
  }
  return 0;
}

/* Delivery to replay */

/* publish_fec publishes one FEC of version block to replay.  See
   fd_rotor_tile.h for the known_id / block_id keying rules. */

static void
publish_fec( ctx_t *              ctx,
             fd_stem_context_t *  stem,
             fd_chainer_block_t * block,
             fd_chainer_fec_t *   fec,
             int                  from_root ) {
  fd_hash_t null_hash = {0};

  fd_rotor_replay_fec_t * msg = fd_chunk_to_laddr( ctx->replay_out_ctx->mem, ctx->replay_out_ctx->chunk );
  msg->slot            = fec->slot;
  msg->fec_set_idx     = fec->fec_set_idx;
  msg->mr              = fec->merkle_root;
  msg->parent_slot     = block->parent_slot;
  msg->parent_block_id = block->parent_block_id;
  msg->slot_complete   = fec->slot_complete;
  msg->data_complete   = fec->data_complete;
  msg->is_leader       = fec->is_leader;

  int block_id_known   = !fd_hash_check_zero( &block->block_id );
  msg->known_id        = !block->turbine;
  msg->block_id        = ( block_id_known && ( msg->known_id || from_root || fec->slot_complete ) ) ? block->block_id : null_hash;

  /* The block is delivered whole: report its repair stats once.  A
     from_root re-delivery replays FECs replay already saw, so it does
     not report again. */
  if( FD_UNLIKELY( fec->slot_complete && !from_root ) ) fd_repair_stats_print_slot( ctx->stats, block->slot, block->complete_ts );

  fd_stem_publish( stem, ctx->replay_out_ctx->idx, ROTOR_SIG_FEC_REPLAY, ctx->replay_out_ctx->chunk, sizeof(fd_rotor_replay_fec_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out_ctx->chunk = fd_dcache_compact_next( ctx->replay_out_ctx->chunk, sizeof(fd_rotor_replay_fec_t), ctx->replay_out_ctx->chunk0, ctx->replay_out_ctx->wmark );
  ctx->metrics->fecs_delivered++;
}

/* full_fec_path_queue queues every FEC from the chainer root down to
   (target_block, target_fec), inclusive, onto ctx->redeliver in
   root-to-target order. */

static void
full_fec_path_queue( ctx_t *              ctx,
                     fd_chainer_block_t * target_block,
                     fd_chainer_fec_t *   target_fec ) {
  fd_chainer_t * chainer = ctx->chainer;

  for( fd_chainer_block_t * block = target_block;
                            block && block->slot > chainer->root;
                            block = fd_chainer_block_query( chainer, block->parent_slot, &block->parent_block_id ) ) {
    uint block_idx = (uint)fd_block_pool_idx( chainer->block_pool, block );

    uint kmax;
    if( FD_LIKELY( block==target_block ) ) {
      kmax = target_fec->fec_set_idx / (uint)FD_FEC_SHRED_CNT;
    } else {
      if( FD_UNLIKELY( block->buffered_fec_idx==UINT_MAX ) ) continue;
      kmax = block->buffered_fec_idx / (uint)FD_FEC_SHRED_CNT;
    }

    uint const * fecs = fd_chainer_block_fecs( chainer, block );
    for( int k=(int)kmax; k>=0; k-- ) {
      if( FD_UNLIKELY( out_queue_full( ctx->redeliver ) ) ) FD_LOG_ERR(( "deliver_from_root queue full" ));
      out_queue_push_head( ctx->redeliver, (out_ele_t){ .block_idx = block_idx, .fec_idx = fecs[ k ] } );
    }
  }
}

/* publish_fec_replay pops one delivered FEC off the chainer's out_queue
   and publishes it, or, when deliver_from_root is set, queues its whole
   ancestry path onto redeliver instead.  Returns 1 if a delivered
   FEC was consumed. */

static int
publish_fec_replay( ctx_t *             ctx,
                    fd_stem_context_t * stem ) {
  out_ele_t * out_queue = ctx->chainer->out_queue;
  if( FD_LIKELY( out_queue_empty( out_queue ) ) ) return 0;

  out_ele_t out_ele = out_queue_pop_head( out_queue );
  if( FD_UNLIKELY( out_ele.block_idx == UINT_MAX ) ) return 1;

  fd_chainer_fec_t   * fec   = fd_fec_pool_ele( ctx->chainer->fec_pool, out_ele.fec_idx );
  fd_chainer_block_t * block = fd_block_pool_ele( ctx->chainer->block_pool, out_ele.block_idx );

  if( FD_UNLIKELY( ctx->deliver_from_root ) ) {
    full_fec_path_queue( ctx, block, fec );
    ctx->deliver_from_root = 0;
  }
  else publish_fec( ctx, stem, block, fec, 0 /* from_root */ );

  return 1;
}

/* Main loop */

static int
requestor_next( ctx_t *             ctx,
                  fd_stem_context_t * stem,
                  out_ctx_t *         sign_out,
                  long                now ) {
  fd_rotor_request_t request[1];
  ulong slot;
  fd_hash_t block_id;
  int result = fd_requestor_block_advance( ctx->requestor, ctx->chainer, request, &slot, &block_id );
  switch( result ) {
  case FD_REQUESTOR_ADVANCE_REQUEST:
    dispatch_request( ctx, stem, sign_out, request, now );
    return 1;
  case FD_REQUESTOR_ADVANCE_DONE:
    return 0;
  case FD_REQUESTOR_ADVANCE_REQUESTED_PARENT:
    dispatch_request( ctx, stem, sign_out, request, now ); /* the walk's one metadata request */
    fd_schedulor_block_insert( ctx->schedulor, slot, &block_id, now + FD_SCHEDULOR_PARENT_TIMEOUT_NS );
    return 1;
  case FD_REQUESTOR_ADVANCE_REQUESTED:
    fd_schedulor_block_insert( ctx->schedulor, slot, &block_id, now + FD_SCHEDULOR_REQUEST_TIMEOUT_NS );
    return 0;
  case FD_REQUESTOR_ADVANCE_IDLE:
    return 0;
  default:
    FD_LOG_CRIT(( "bad requestor advance result %d", result ));
  }
}

static void
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  long now = fd_clock_tile_now( ctx->clock );

  /* 1. Deliveries to replay. */

  if( FD_UNLIKELY( !out_queue_empty( ctx->redeliver ) ) ) {
    out_ele_t            e     = out_queue_pop_head( ctx->redeliver );
    fd_chainer_block_t * block = fd_block_pool_ele( ctx->chainer->block_pool, e.block_idx );
    fd_chainer_fec_t   * fec   = fd_fec_pool_ele  ( ctx->chainer->fec_pool,   e.fec_idx   );
    publish_fec( ctx, stem, block, fec, 1 /* from_root */ );
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( publish_fec_replay( ctx, stem ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( ctx->halt_signing ) ) { *charge_busy = 1; return; }

  out_ctx_t * sign_out = sign_avail_credits( ctx );
  if( FD_UNLIKELY( !sign_out ) ) { ctx->metrics->sign_unavail++; return; }

  /* 2. Fire-and-forget messages. */

  if( FD_UNLIKELY( !toss_queue_empty( ctx->toss_queue ) ) ) {
    sign_pending_t signable = toss_queue_pop( ctx->toss_queue );
    send_sign_request( ctx, stem, sign_out, &signable.msg, signable.msg.kind == FD_REPAIR_KIND_PONG ? &signable.pong_data : NULL );
    *charge_busy = 1;
    return;
  }

  if( FD_LIKELY( requestor_next( ctx, stem, sign_out, now ) ) ) {
    *charge_busy = 1;
    return;
  }

  ulong     slot;
  fd_hash_t block_id;
  if( FD_LIKELY( fd_schedulor_block_pop( ctx->schedulor, now, &slot, &block_id ) ) ) {
    fd_requestor_block_start( ctx->requestor, slot, &block_id );
    ctx->metrics->checks++;
    requestor_next( ctx, stem, sign_out, now );
    *charge_busy = 1;
  }
}

/* Housekeeping */

/* signs_queue_update_identity restamps queued, unsigned messages with
   the new identity after a keyswitch. */

static void
signs_queue_update_identity( ctx_t * ctx ) {
  ulong queue_cnt = toss_queue_cnt( ctx->toss_queue );
  for( ulong i=0UL; i<queue_cnt; i++ ) {
    sign_pending_t signable = toss_queue_pop( ctx->toss_queue );
    switch( signable.msg.kind ) {
      case FD_REPAIR_KIND_PONG:  memcpy( signable.msg.pong.from.uc,  ctx->identity_public_key.uc, sizeof(fd_pubkey_t) ); break;
      case FD_REPAIR_KIND_SHRED: memcpy( signable.msg.shred.from.uc, ctx->identity_public_key.uc, sizeof(fd_pubkey_t) ); break;
      default: FD_LOG_CRIT(( "Unhandled repair kind %u", signable.msg.kind ));
    }
    toss_queue_push( ctx->toss_queue, signable );
  }
}

static inline void
during_housekeeping( ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) fd_clock_tile_recal( ctx->clock );

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_CHECK_CRIT( ctx->halt_signing, "state machine corruption" );
    ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    if( !ctx->halt_signing ) {
      /* Stop issuing sign requests, wait for the outstanding ones to
         return, and restamp anything still queued with the new key. */
      ctx->halt_signing = 1;
      memcpy( ctx->identity_public_key.uc, ctx->keyswitch->bytes, 32UL );
      ctx->protocol->identity_key = ctx->identity_public_key;
      signs_queue_update_identity( ctx );
    }
    if( fd_signs_map_key_cnt( ctx->signs_map )==0UL ) {
      fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
    }
  }
}

/* Init */

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

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),        sizeof(ctx_t)                                                                     );
  ctx->protocol      = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),     fd_repair_footprint    ()                                                         );
  ctx->chainer       = FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(),    fd_chainer_footprint   ( tile->rotor.slot_max, tile->rotor.max_shreds_per_block ) );
  ctx->schedulor     = FD_SCRATCH_ALLOC_APPEND( l, fd_schedulor_align(),  fd_schedulor_footprint ( block_max( tile ) )                                      );
  ctx->requestor     = FD_SCRATCH_ALLOC_APPEND( l, fd_requestor_align(),  fd_requestor_footprint ()                                                         );
  ctx->policy        = FD_SCRATCH_ALLOC_APPEND( l, fd_policy_align(),     fd_policy_footprint    ( FD_REPAIR_PEER_MAX )                                     );
  ctx->rtt           = FD_SCRATCH_ALLOC_APPEND( l, fd_inflights_align(),  fd_inflights_footprint ()                                                         );
  ctx->stats         = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_stats_align(), fd_repair_stats_footprint( tile->rotor.slot_max )                               );
  ctx->signs_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_signs_map_align(),  fd_signs_map_footprint ( lg_sign_depth( tile ) )                                  );
  ctx->toss_queue    = FD_SCRATCH_ALLOC_APPEND( l, toss_queue_align(),    toss_queue_footprint   ()                                                         );
  ctx->redeliver     = FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),     out_queue_footprint    ( fec_max( tile ) )                                        );
  ulong scratch_top  = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->chainer    = fd_chainer_join     ( fd_chainer_new     ( ctx->chainer,   tile->rotor.slot_max, tile->rotor.max_shreds_per_block, ctx->repair_seed ) );
  ctx->schedulor  = fd_schedulor_join   ( fd_schedulor_new   ( ctx->schedulor, block_max( tile ), ctx->repair_seed                                      ) );
  ctx->requestor  = fd_requestor_join   ( fd_requestor_new   ( ctx->requestor                                                                           ) );
  ctx->protocol   = fd_repair_join      ( fd_repair_new      ( ctx->protocol,  &ctx->identity_public_key                                                ) );
  ctx->policy     = fd_policy_join      ( fd_policy_new      ( ctx->policy,    FD_REPAIR_PEER_MAX, ctx->repair_seed, ctx->repair_nonce_ss               ) );
  ctx->rtt        = fd_inflights_join   ( fd_inflights_new   ( ctx->rtt,       ctx->repair_seed+1234UL                                                  ) );
  ctx->stats      = fd_repair_stats_join( fd_repair_stats_new( ctx->stats, tile->rotor.slot_max                                                         ) );
  ctx->signs_map  = fd_signs_map_join   ( fd_signs_map_new   ( ctx->signs_map, lg_sign_depth( tile ), 0UL                                               ) );
  ctx->toss_queue = toss_queue_join     ( toss_queue_new     ( ctx->toss_queue                                                                          ) );
  ctx->redeliver  = out_queue_join      ( out_queue_new      ( ctx->redeliver, fec_max( tile )                                                          ) );
  FD_TEST( ctx->chainer && ctx->schedulor && ctx->requestor && ctx->protocol && ctx->policy && ctx->rtt && ctx->stats && ctx->signs_map && ctx->toss_queue && ctx->redeliver );
  FD_TEST( fd_block_pool_max( ctx->chainer->block_pool )==block_max( tile ) );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );
  FD_TEST( fd_store_map_ljoin( ctx->store, ctx->store_map ) );

  ctx->halt_signing      = 0;
  ctx->deliver_from_root = 0;

  /* Process in links */

  if( FD_UNLIKELY( tile->in_cnt > MAX_IN_LINKS ) ) FD_LOG_ERR(( "rotor tile has too many input links" ));

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
      if( FD_UNLIKELY( sign_repair_idx>=MAX_SIGN_TILE_CNT ) ) FD_LOG_ERR(( "rotor tile has too many sign_repair links" ));
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
    else FD_LOG_ERR(( "rotor tile has unexpected input link %s", link->name ));

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;

    FD_TEST( fd_dcache_compact_is_safe( ctx->in_links[in_idx].mem, link->dcache, link->mtu, link->depth ) );
  }

  /* Process out links */

  ctx->net_out_ctx->idx    = ULONG_MAX;
  ctx->replay_out_ctx->idx = ULONG_MAX;
  ctx->repair_sign_cnt     = 0UL;

  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ out_idx ] ];

    out_ctx_t * out;
    if( 0==strcmp( link->name, "repair_net" ) ) {
      if( ctx->net_out_ctx->idx!=ULONG_MAX ) continue; /* only use first net link */
      out = ctx->net_out_ctx;
    } else if( 0==strcmp( link->name, "repair_out" ) ) {
      out = ctx->replay_out_ctx;
    } else if( 0==strcmp( link->name, "repair_sign" ) ) {
      if( FD_UNLIKELY( ctx->repair_sign_cnt>=MAX_SIGN_TILE_CNT ) ) FD_LOG_ERR(( "rotor tile has too many repair_sign links" ));
      out              = &ctx->repair_sign_out_ctx[ ctx->repair_sign_cnt ];
      out->in_idx      = sign_repair_in_idx[ ctx->repair_sign_cnt++ ]; /* match to the sign_repair input link */
      out->max_credits = sign_link_depth;
      out->credits     = sign_link_depth;
    } else {
      FD_LOG_ERR(( "rotor tile has unexpected output link %s", link->name ));
    }

    out->idx    = out_idx;
    out->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    out->chunk0 = fd_dcache_compact_chunk0( out->mem, link->dcache );
    out->wmark  = fd_dcache_compact_wmark ( out->mem, link->dcache, link->mtu );
    out->chunk  = out->chunk0;
  }

  FD_TEST( ctx->net_out_ctx->idx   !=ULONG_MAX );
  FD_TEST( ctx->replay_out_ctx->idx!=ULONG_MAX );
  if( FD_UNLIKELY( ctx->repair_sign_cnt!=sign_repair_idx ) ) {
    FD_LOG_ERR(( "Mismatch between repair_sign output links (%lu) and sign_repair input links (%u)", ctx->repair_sign_cnt, sign_repair_idx ));
  }
  if( FD_UNLIKELY( fd_signs_map_key_max( ctx->signs_map ) < tile->rotor.repair_sign_depth * tile->rotor.repair_sign_cnt ) ) {
    FD_LOG_ERR(( "Pending signs map is too small: %lu < %lu.", fd_signs_map_key_max( ctx->signs_map ), tile->rotor.repair_sign_depth * tile->rotor.repair_sign_cnt ));
  }

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ctx->net_id = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->intake_hdr, 0, 0, tile->rotor.repair_client_listen_port );

  ctx->turbine_slot0  = ULONG_MAX;
  ctx->catchup_seeded = 0;
  ctx->current_slot  = 0UL;
  memset( ctx->metrics, 0, sizeof(ctx->metrics) );

  fd_clock_tile_init( ctx->clock );
  ctx->pending_key_next = 0UL;
  ctx->ag_nonce         = 0U;

  fd_requestor_set_block_id_only( ctx->requestor, 0 );

  fd_histf_join( fd_histf_new( ctx->metrics->response_latency,
                               FD_MHIST_MIN( ROTOR, RESPONSE_LATENCY_NANOS ),
                               FD_MHIST_MAX( ROTOR, RESPONSE_LATENCY_NANOS ) ) );
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

/* request_tx_idx maps a wire repair kind to its RepairSentRequestType
   metric index, or ULONG_MAX for a kind this tile never sends. */

static inline ulong
request_tx_idx( ulong kind ) {
  switch( kind ) {
  case FD_REPAIR_KIND_SHRED:               return FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_NEEDED_WINDOW_IDX;
  case FD_REPAIR_KIND_HIGHEST_SHRED:       return FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_NEEDED_HIGHEST_WINDOW_IDX;
  case FD_REPAIR_KIND_ORPHAN:              return FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_NEEDED_ORPHAN_IDX;
  case AG_REPAIR_KIND_PARENT_FEC_COUNT:    return FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_PARENT_FEC_COUNT_IDX;
  case AG_REPAIR_KIND_FEC_ROOT:            return FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_FEC_ROOT_IDX;
  case AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID:  return FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_SHRED_BLOCK_ID_IDX;
  case FD_REPAIR_KIND_PONG:                return FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_PONG_IDX;
  default:                                 return ULONG_MAX;
  }
}

static inline void
metrics_write( ctx_t * ctx ) {
  ulong request_tx[ FD_METRICS_COUNTER_ROTOR_REQUEST_TX_CNT ] = {0};
  for( ulong kind=0UL; kind<sizeof(ctx->metrics->sent_by_kind)/sizeof(ulong); kind++ ) {
    ulong idx = request_tx_idx( kind );
    if( FD_LIKELY( idx!=ULONG_MAX ) ) request_tx[ idx ] = ctx->metrics->sent_by_kind[ kind ];
  }

  FD_MCNT_SET      ( ROTOR, PKT_TX,     ctx->metrics->send_pkt_cnt );
  FD_MCNT_ENUM_COPY( ROTOR, REQUEST_TX, request_tx                 );

  FD_MGAUGE_SET( ROTOR, SLOT_HIGHEST_REPAIRED, ctx->chainer->highest_repaired                  );
  FD_MGAUGE_SET( ROTOR, SLOT_CURRENT,          ctx->current_slot                               );
  FD_MGAUGE_SET( ROTOR, SLOT_TURBINE_FIRST,    ctx->turbine_slot0                              );
  FD_MGAUGE_SET( ROTOR, BLOCK_CHECK_QUEUED,    fd_schedulor_queued_cnt( ctx->schedulor )        );
  FD_MGAUGE_SET( ROTOR, REQUEST_INFLIGHT,      fd_inflights_outstanding_cnt( ctx->rtt )         );

  FD_MCNT_SET( ROTOR, FEC_DELIVERED, ctx->metrics->fecs_delivered );

  FD_MCNT_SET( ROTOR, SHRED_OLD,           ctx->metrics->shred_old              );
  FD_MCNT_SET( ROTOR, SHRED_RX,            ctx->metrics->repair_shred_rx        );
  FD_MCNT_SET( ROTOR, SHRED_RX_BLOCK_ID,   ctx->metrics->shred_match_block_id   );
  FD_MCNT_SET( ROTOR, SHRED_RX_POSITIONAL, ctx->metrics->shred_match_positional );
  FD_MCNT_SET( ROTOR, SHRED_RX_UNMATCHED,  ctx->metrics->shred_match_miss       );

  FD_MCNT_SET( ROTOR, META_RX,                 ctx->metrics->meta_rx                  );
  FD_MCNT_SET( ROTOR, META_MALFORMED,          ctx->metrics->meta_malformed           );
  FD_MCNT_SET( ROTOR, META_UNSOLICITED,        ctx->metrics->unsolicited_meta         );
  FD_MCNT_SET( ROTOR, PARENT_FEC_COUNT_OK,     ctx->metrics->meta_ok_parent_fec_count );
  FD_MCNT_SET( ROTOR, PARENT_FEC_COUNT_FAILED, ctx->metrics->failed_parent_fec_count  );
  FD_MCNT_SET( ROTOR, FEC_ROOT_OK,             ctx->metrics->meta_ok_fec_root         );
  FD_MCNT_SET( ROTOR, FEC_ROOT_FAILED,         ctx->metrics->failed_fec_root          );

  FD_MCNT_SET( ROTOR, REPLAY_ROOT_ADVANCED, ctx->metrics->replay_root_advanced );
  FD_MCNT_SET( ROTOR, REPLAY_MISSING_FEC,   ctx->metrics->replay_missing_fec   );

  FD_MCNT_SET( ROTOR, PING_MALFORMED,        ctx->metrics->malformed_ping      );
  FD_MCNT_SET( ROTOR, PING_UNKNOWN_PEER,     ctx->metrics->unknown_peer_ping   );
  FD_MCNT_SET( ROTOR, PING_SIGNATURE_FAILED, ctx->metrics->fail_sigverify_ping );

  FD_MHIST_COPY( ROTOR, RESPONSE_LATENCY_NANOS, ctx->metrics->response_latency );
}

/* after_credit publishes at most one frag (a FEC to replay, or one
   sign request).  after_frag publishes at most one packet (a signed
   request or pong on its way out).  returnable_frag publishes nothing. */
#define STEM_BURST (3UL)

/* Keeps housekeeping time low.  The tile's only reliable consumer is
   replay. */
#define STEM_LAZY  (64000)

#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag
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
