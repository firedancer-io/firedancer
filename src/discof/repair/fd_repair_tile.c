/* Repair tile runs the repair protocol for a Firedancer node. */
#include "fd_fec_chainer.h"
#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"
#include "generated/fd_repair_tile_seccomp.h"

#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/store/fd_store.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/net/fd_net_headers.h"

#include "../forest/fd_forest.h"
#include "fd_fec_chainer.h"

#define IN_KIND_NET     (0)
#define IN_KIND_CONTACT (1)
#define IN_KIND_STAKE   (2)
#define IN_KIND_SHRED   (3)
#define IN_KIND_SIGN    (4)
#define MAX_IN_LINKS    (16)

#define NET_OUT_IDX      (0)
#define SIGN_OUT_IDX     (1)
#define REPLAY_OUT_IDX   (2)
#define ARCHIVE_OUT_IDX  (3)

#define MAX_REPAIR_PEERS 40200UL
#define MAX_BUFFER_SIZE  ( MAX_REPAIR_PEERS * sizeof(fd_shred_dest_wire_t))
#define MAX_SHRED_TILE_CNT (16UL)

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
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
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

struct fd_reasm {
  ulong slot;
  uint  cnt;
};
typedef struct fd_reasm fd_reasm_t;

#define MAP_NAME     fd_reasm
#define MAP_T        fd_reasm_t
#define MAP_KEY      slot
#define MAP_MEMOIZE  0
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_repair_tile_ctx {
  long tsprint; /* timestamp for printing */
  long tsrepair; /* timestamp for repair */
  long tsreset; /* timestamp for resetting iterator */
  ulong * wmark;
  ulong   prev_wmark;

  fd_repair_t * repair;
  fd_repair_config_t repair_config;

  ulong repair_seed;

  fd_repair_peer_addr_t repair_intake_addr;
  fd_repair_peer_addr_t repair_serve_addr;

  ushort                repair_intake_listen_port;
  ushort                repair_serve_listen_port;

  fd_forest_t      * forest;
  fd_fec_sig_t     * fec_sigs;
  fd_reasm_t       * reasm;
  fd_fec_chainer_t * fec_chainer;
  fd_forest_iter_t   repair_iter;
  fd_store_t       * store;

  ulong * turbine_slot0;
  ulong * turbine_slot;

  uchar       identity_private_key[ 32 ];
  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  uchar              in_kind[ MAX_IN_LINKS ];
  fd_repair_in_ctx_t in_links[ MAX_IN_LINKS ];

  int skip_frag;

  uint        net_out_idx;
  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  /* These will only be used if shredcap is enabled */
  uint        shredcap_out_idx;
  uint        shredcap_enabled;
  fd_wksp_t * shredcap_out_mem;
  ulong       shredcap_out_chunk0;
  ulong       shredcap_out_wmark;
  ulong       shredcap_out_chunk;

  uint                shred_tile_cnt;
  fd_repair_out_ctx_t shred_out_ctx[ MAX_SHRED_TILE_CNT ];

  ushort net_id;
  /* Includes Ethernet, IP, UDP headers */
  uchar buffer[ MAX_BUFFER_SIZE ];
  fd_ip4_udp_hdrs_t intake_hdr[1];
  fd_ip4_udp_hdrs_t serve_hdr [1];

  fd_keyguard_client_t keyguard_client[1];
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t)             );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(),             fd_repair_footprint()                    );
  l = FD_LAYOUT_APPEND( l, fd_forest_align(),             fd_forest_footprint( tile->repair.slot_max ) );
  l = FD_LAYOUT_APPEND( l, fd_fec_sig_align(),            fd_fec_sig_footprint( 20 ) );
  l = FD_LAYOUT_APPEND( l, fd_reasm_align(),              fd_reasm_footprint( 20 ) );
  // l = FD_LAYOUT_APPEND( l, fd_fec_repair_align(),         fd_fec_repair_footprint( ( 1<<20 ), tile->repair.shred_tile_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_fec_chainer_align(),        fd_fec_chainer_footprint( 1 << 20 ) ); // TODO: fix this
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(),       fd_scratch_smem_footprint( FD_REPAIR_SCRATCH_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(),       fd_scratch_fmem_footprint( FD_REPAIR_SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
repair_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len,
               int           sign_type ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *) signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, signature, buffer, len, sign_type );
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

static inline void
handle_new_cluster_contact_info( fd_repair_tile_ctx_t * ctx,
                                 uchar const *          buf,
                                 ulong                  buf_sz ) {
  fd_shred_dest_wire_t const * in_dests = (fd_shred_dest_wire_t const *)fd_type_pun_const( buf );

  ulong dest_cnt = buf_sz;
  if( FD_UNLIKELY( dest_cnt >= MAX_REPAIR_PEERS ) ) {
    FD_LOG_WARNING(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_REPAIR_PEERS ));
    return;
  }

  /* Stop adding peers after we reach the peer max, but we may want to
     consider an eviction policy. */
  for( ulong i=0UL; i<dest_cnt; i++ ) {
   if( FD_UNLIKELY( ctx->repair->peer_cnt >= FD_ACTIVE_KEY_MAX ) ) break;// FIXME: aiming to move all peer tracking out of lib into tile, leaving like this for now
    fd_repair_peer_addr_t repair_peer = {
      .addr = in_dests[i].ip4_addr,
      .port = fd_ushort_bswap( in_dests[i].udp_port ),
    };
    int dup = fd_repair_add_active_peer( ctx->repair, &repair_peer, in_dests[i].pubkey );
    if( !dup ) {
      ulong hash_src = 0xfffffUL & fd_ulong_hash( (ulong)in_dests[i].ip4_addr | ((ulong)repair_peer.port<<32) );
      FD_LOG_INFO(( "Added repair peer: pubkey %s hash_src %lu", FD_BASE58_ENC_32_ALLOCA(in_dests[i].pubkey), hash_src ));
    }
  }
}

ulong
fd_repair_handle_ping( fd_repair_tile_ctx_t *  repair_tile_ctx,
                       fd_repair_t *                 glob,
                       fd_gossip_ping_t const *      ping,
                       fd_gossip_peer_addr_t const * peer_addr FD_PARAM_UNUSED,
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
fd_repair_recv_clnt_packet( fd_repair_tile_ctx_t *        repair_tile_ctx,
                            fd_stem_context_t *           stem,
                            fd_repair_t *                 glob,
                            uchar const *                 msg,
                            ulong                         msglen,
                            fd_repair_peer_addr_t const * src_addr,
                            uint                          dst_ip4_addr ) {
  glob->metrics.recv_clnt_pkt++;

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
          uchar buf[1024];
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

static ulong
fd_repair_sign_and_send( fd_repair_tile_ctx_t *  repair_tile_ctx,
                         fd_repair_protocol_t *  protocol,
                         fd_gossip_peer_addr_t * addr FD_PARAM_UNUSED,
                         uchar                 * buf,
                         ulong                   buflen ) {

  FD_TEST( buflen >= 1024UL );
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

  fd_signature_t sig;
  repair_signer( repair_tile_ctx, sig.uc, buf, buflen, FD_KEYGUARD_SIGN_TYPE_ED25519 );

  /* Reintroduce the signature */

  buf    -= 64UL;
  buflen += 64UL;
  fd_memcpy( buf + 4U, &sig, 64U );

  return buflen;
}


static void
fd_repair_send_request( fd_repair_tile_ctx_t   * repair_tile_ctx,
                        fd_stem_context_t      * stem,
                        fd_repair_t            * glob,
                        enum fd_needed_elem_type type,
                        ulong                    slot,
                        uint                     shred_index,
                        fd_pubkey_t const      * recipient,
                        long                     now ) {

  /* Send requests starting where we left off last time. i.e. if n < current_nonce, seek forward */
  /* Track statistics */
  fd_repair_protocol_t protocol;
  fd_repair_construct_request_protocol( glob, &protocol, type, slot, shred_index, recipient, glob->next_nonce, now );
  glob->next_nonce++;
  fd_active_elem_t * active = fd_active_table_query( glob->actives, recipient, NULL );

  active->avg_reqs++;
  glob->metrics.send_pkt_cnt++;

  uchar buf[1024];
  ulong buflen       = fd_repair_sign_and_send( repair_tile_ctx, &protocol, &active->addr, buf, sizeof(buf) );
  ulong tsorig       = fd_frag_meta_ts_comp( fd_tickcount() );
  uint  src_ip4_addr = 0U; /* unknown */
  send_packet( repair_tile_ctx, stem, 1, active->addr.addr, active->addr.port, src_ip4_addr, buf, buflen, tsorig );
}

static void
fd_repair_send_requests( fd_repair_tile_ctx_t *   ctx,
                         fd_stem_context_t *      stem,
                         enum fd_needed_elem_type type,
                         ulong                    slot,
                         uint                     shred_index,
                         long                     now ){
  fd_repair_t * glob = ctx->repair;

  for( uint i=0; i<FD_REPAIR_NUM_NEEDED_PEERS; i++ ) {
    fd_pubkey_t const * id = &glob->peers[ glob->peer_idx++ ].key;
    fd_repair_send_request( ctx, stem, glob, type, slot, shred_index, id, now );
    if( FD_UNLIKELY( glob->peer_idx >= glob->peer_cnt ) ) glob->peer_idx = 0; /* wrap around */
  }
}


static inline int
before_frag( fd_repair_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_LIKELY( in_kind==IN_KIND_NET ) ) return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR;
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

  } else if( FD_UNLIKELY( in_kind==IN_KIND_CONTACT ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    dcache_entry_sz = sz * sizeof(fd_shred_dest_wire_t);

  } else if( FD_UNLIKELY( in_kind==IN_KIND_STAKE ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    fd_stake_weight_msg_t const * msg = fd_type_pun_const( dcache_entry );
    fd_repair_set_stake_weights_init( ctx->repair,  msg->weights, msg->staked_cnt );
    return;

  } else if( FD_LIKELY( in_kind==IN_KIND_SHRED ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    dcache_entry_sz = sz;

  } else {
    FD_LOG_ERR(( "Frag from unknown link (kind=%u in_idx=%lu)", in_kind, in_idx ));
  }

  fd_memcpy( ctx->buffer, dcache_entry, dcache_entry_sz );
}

static void
after_frag( fd_repair_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq    FD_PARAM_UNUSED,
            ulong                  sig    FD_PARAM_UNUSED,
            ulong                  sz,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *    stem ) {

  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_UNLIKELY( in_kind==IN_KIND_CONTACT ) ) {
    handle_new_cluster_contact_info( ctx, ctx->buffer, sz );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_STAKE ) ) {
    fd_repair_set_stake_weights_fini( ctx->repair );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) {

    /* Initialize the forest, which requires the root to be ready.  This
       must be the case if we have received a frag from shred, because
       shred requires stake weights, which implies a genesis or snapshot
       slot has been loaded. */

    ulong wmark = fd_fseq_query( ctx->wmark );
    if( FD_UNLIKELY( fd_forest_root_slot( ctx->forest ) == ULONG_MAX ) ) {
      FD_LOG_NOTICE(( "Forest initializing with root %lu", wmark ));
      fd_forest_init( ctx->forest, wmark );
      fd_hash_t mr = { 0 }; /* FIXME */
      fd_fec_chainer_init( ctx->fec_chainer, wmark, &mr );
      FD_TEST( fd_forest_root_slot( ctx->forest ) != ULONG_MAX );
      ctx->prev_wmark = wmark;
    }

    if( FD_UNLIKELY( ctx->prev_wmark < wmark ) ) {
      fd_forest_publish( ctx->forest, wmark );
      fd_fec_chainer_publish( ctx->fec_chainer, wmark );
      ctx->prev_wmark  = wmark;
      // invalidate our repair iterator
      ctx->repair_iter = fd_forest_iter_init( ctx->forest );
    }

    fd_shred_t * shred = (fd_shred_t *)fd_type_pun( ctx->buffer );
    if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) {
      // FD_LOG_WARNING(( "shred %lu %u %u too old, ignoring", shred->slot, shred->idx, shred->fec_set_idx ));
      return;
    };

    /* Update turbine_slot0 and turbine_slot. */

    if( FD_UNLIKELY( fd_fseq_query( ctx->turbine_slot0 )==ULONG_MAX ) ) {
      fd_fseq_update( ctx->turbine_slot0, shred->slot );
      FD_LOG_NOTICE(("First turbine slot %lu", shred->slot));
    }
    fd_fseq_update( ctx->turbine_slot, fd_ulong_max( shred->slot, fd_fseq_query( ctx->turbine_slot ) ) );
    if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) return; /* shred too old */

    /* TODO add automated caught-up test */

    /* Insert the shred sig (shared by all shred members in the FEC set)
       into the map. */

    fd_fec_sig_t * fec_sig = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx, NULL );
    if( FD_UNLIKELY( !fec_sig ) ) {
      fec_sig = fd_fec_sig_insert( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx );
      memcpy( fec_sig->sig, shred->signature, sizeof(fd_ed25519_sig_t) );
    }

    /* When this is a FEC completes msg, it is implied that all the
       other shreds in the FEC set can also be inserted.  Shred inserts
       into the forest are idempotent so it is fine to insert the same
       shred multiple times. */

    if( FD_UNLIKELY( sz == FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) ) ) {
      fd_forest_ele_t * ele = NULL;
      for( uint idx = shred->fec_set_idx; idx <= shred->idx; idx++ ) {
        ele = fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->data.parent_off, idx, shred->fec_set_idx, 0, 0 );
      }
      FD_TEST( ele ); /* must be non-empty */
      fd_forest_ele_idxs_insert( ele->cmpl, shred->fec_set_idx );

      fd_hash_t const * merkle_root  = (fd_hash_t const *)fd_type_pun_const( ctx->buffer + FD_SHRED_DATA_HEADER_SZ );
      fd_hash_t const * chained_root = (fd_hash_t const *)fd_type_pun_const( ctx->buffer + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) );

      int     data_complete  = !!( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );
      int     slot_complete  = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );

      FD_TEST( fd_fec_pool_free( ctx->fec_chainer->pool ) );
      FD_TEST( !fd_fec_chainer_query( ctx->fec_chainer, shred->slot, shred->fec_set_idx ) );
      FD_TEST( fd_fec_chainer_insert( ctx->fec_chainer, shred->slot, shred->fec_set_idx, (ushort)(shred->idx - shred->fec_set_idx + 1), data_complete, slot_complete, shred->data.parent_off, merkle_root, chained_root ) );
    }

    /* Insert the shred into the map. */

    int is_code = fd_shred_is_code( fd_shred_type( shred->variant ) );
    if( FD_LIKELY( !is_code ) ) {
      fd_repair_inflight_remove( ctx->repair, shred->slot, shred->idx );

      int               data_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE);
      int               slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
      fd_forest_ele_t * ele           = fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->data.parent_off, shred->idx, shred->fec_set_idx, data_complete, slot_complete );

      /* Check if there are FECs to force complete. Algorithm: window
         through the idxs in interval [i, j). If j = next fec_set_idx
         then we know we can force complete the FEC set interval [i, j)
         (assuming it wasn't already completed based on `cmpl`). */

      uint i = 0;
      for( uint j = 1; j < ele->buffered_idx + 1; j++ ) { /* TODO iterate by word */
        if( FD_UNLIKELY( fd_forest_ele_idxs_test( ele->cmpl, i ) && fd_forest_ele_idxs_test( ele->fecs, j ) ) ) {
          i = j;
        } else if( FD_UNLIKELY( fd_forest_ele_idxs_test( ele->fecs, j ) || j == ele->complete_idx ) ) {
          if ( j == ele->complete_idx ) j++;
          fd_forest_ele_idxs_insert( ele->cmpl, i );

          /* Find the shred tile owning this FEC set. */

          fd_fec_sig_t * fec_sig = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | i, NULL );

          ulong sig      = fd_ulong_load_8( fec_sig->sig );
          ulong tile_idx = sig % ctx->shred_tile_cnt;
          uint  last_idx = j - i - 1;

          uchar * chunk = fd_chunk_to_laddr( ctx->shred_out_ctx[tile_idx].mem, ctx->shred_out_ctx[tile_idx].chunk );
          memcpy( chunk, fec_sig->sig, sizeof(fd_ed25519_sig_t) );
          fd_stem_publish( stem, ctx->shred_out_ctx[tile_idx].idx, last_idx, ctx->shred_out_ctx[tile_idx].chunk, sizeof(fd_ed25519_sig_t), 0UL, 0UL, 0UL );
          ctx->shred_out_ctx[tile_idx].chunk = fd_dcache_compact_next( ctx->shred_out_ctx[tile_idx].chunk, sizeof(fd_ed25519_sig_t), ctx->shred_out_ctx[tile_idx].chunk0, ctx->shred_out_ctx[tile_idx].wmark );
          i = j;
        } else {
          // FD_LOG_NOTICE(( "not a fec boundary %lu %u", ele->slot, j ));
        }
      }
    }
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

  fd_gossip_peer_addr_t peer_addr = { .addr=ip4->saddr, .port=udp->net_sport };
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
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy ) {

  if( FD_LIKELY( !fd_fec_out_empty( ctx->fec_chainer->out ) && ctx->store ) ) {

    fd_fec_out_t out = fd_fec_out_pop_head( ctx->fec_chainer->out );
    fd_hash_t *  cmr = &out.chained_root;
    if( FD_UNLIKELY( ctx->store->slot0==(out.slot - out.parent_off) ) ) {

      /* FIXME This is a hack to handle the fact the `block_id` field is
         not available in the snapshot manifest, which is the chained
         merkle root of the very first FEC after the snapshot slot. */

      fd_hash_t null = { 0 };
      memcpy( cmr, &null, sizeof(fd_hash_t) );
    }

    /* Linking only requires a shared lock because the fields that are
        modified are only read on publish which uses exclusive lock. */
    long shacq_start, shacq_end, shrel_end;

    FD_STORE_SHACQ_TIMED( ctx->store, shacq_start, shacq_end );
    if( FD_UNLIKELY( !fd_store_link( ctx->store, &out.merkle_root, &out.chained_root ) ) ) FD_LOG_WARNING(( "failed to link %s %s. slot %lu fec_set_idx %u", FD_BASE58_ENC_32_ALLOCA( &out.merkle_root ), FD_BASE58_ENC_32_ALLOCA( &out.chained_root ), out.slot, out.fec_set_idx ));
    FD_STORE_SHREL_TIMED( ctx->store, shrel_end );

    memcpy( fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk ), &out, sizeof(fd_fec_out_t) );
    ulong sig   = out.slot << 32 | out.fec_set_idx;
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, REPLAY_OUT_IDX, sig, ctx->replay_out_chunk, sizeof(fd_fec_out_t), 0, 0, tspub );
    ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_fec_out_t), ctx->replay_out_chunk0, ctx->replay_out_wmark );

    fd_histf_sample( ctx->repair->metrics.store_link_wait, (ulong)fd_long_max(shacq_end - shacq_start, 0) );
    fd_histf_sample( ctx->repair->metrics.store_link_work, (ulong)fd_long_max(shrel_end - shacq_end,   0) );

    if( FD_UNLIKELY( ctx->shredcap_enabled ) ) {
      uchar * chunk = fd_chunk_to_laddr( ctx->shredcap_out_mem, ctx->shredcap_out_chunk );
      ulong   sz    = 0;

      memcpy( chunk + sz, &out.merkle_root, sizeof(fd_hash_t) );
      sz += sizeof(fd_hash_t);

      fd_store_shacq( ctx->store );

      fd_store_fec_t const * fec = fd_store_query_const( ctx->store, &out.merkle_root );

      memcpy( chunk + sz, &fec->data_sz, sizeof(ulong) );
      sz += sizeof(ulong);

      memcpy( chunk + sz, fec->data, fec->data_sz );
      sz += fec->data_sz;

      fd_store_shrel( ctx->store );

      memcpy( chunk + sz, &out, sizeof(fd_fec_out_t) );
      sz += sizeof(fd_fec_out_t);

      fd_stem_publish( stem, ctx->shredcap_out_idx, sz, ctx->shredcap_out_chunk, sz, 0, 0, tspub );
      ctx->shredcap_out_chunk = fd_dcache_compact_next( ctx->shredcap_out_chunk, sz, ctx->shredcap_out_chunk0, ctx->shredcap_out_wmark );
    }

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

  fd_forest_t          * forest   = ctx->forest;
  fd_forest_ele_t      * pool     = fd_forest_pool( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );

  // Always request orphans

  int total_req = 0;
  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
        !fd_forest_orphaned_iter_done( iter, orphaned, pool );
        iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_ele_t * orphan = fd_forest_orphaned_iter_ele( iter, orphaned, pool );
    if( fd_repair_need_orphan( ctx->repair, orphan->slot ) ) {
      fd_repair_send_requests( ctx, stem, fd_needed_orphan, orphan->slot, UINT_MAX, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
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

  if( FD_UNLIKELY( now - ctx->tsreset > (long)40e6 ) ) {
    // reset iterator to the beginning of the forest frontier
    ctx->repair_iter = fd_forest_iter_init( ctx->forest );
    ctx->tsreset = now;
  }

  /* We are at the head of the turbine, so we should give turbine the
     chance to complete the shreds. !ele handles an edgecase where all
     frontier are fully complete and the iter is done */

  fd_forest_ele_t const * ele = fd_forest_pool_ele_const( pool, ctx->repair_iter.ele_idx );
  if( FD_LIKELY( !ele || ( ele->slot == fd_fseq_query( ctx->turbine_slot ) && ( now - ctx->tsreset ) < (long)30e6 ) ) ){
    return;
  }

  while( total_req < MAX_REQ_PER_CREDIT ){
    ele = fd_forest_pool_ele_const( pool, ctx->repair_iter.ele_idx );
    // Request first, advance iterator second.
    if( ctx->repair_iter.shred_idx == UINT_MAX && fd_repair_need_highest_window_index( ctx->repair, ele->slot, 0 ) ){
      fd_repair_send_requests( ctx, stem, fd_needed_highest_window_index, ele->slot, 0, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
    } else if( fd_repair_need_window_index( ctx->repair, ele->slot, ctx->repair_iter.shred_idx ) ) {
      fd_repair_send_requests( ctx, stem, fd_needed_window_index, ele->slot, ctx->repair_iter.shred_idx, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
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

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - ctx->tsprint > (long)1e9 ) ) {
    fd_forest_print( ctx->forest );
    ctx->tsprint = fd_log_wallclock();
  }
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

  ctx->repair_config.private_key             = ctx->identity_private_key;
  ctx->repair_config.public_key              = &ctx->identity_public_key;
  ctx->repair_config.good_peer_cache_file_fd = -1;

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

  uint sign_link_in_idx = UINT_MAX;
  for( uint in_idx=0U; in_idx<(tile->in_cnt); in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if( 0==strcmp( link->name, "net_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in_links[ in_idx ].net_rx, link->dcache );
      continue;
    } else if( 0==strcmp( link->name, "gossip_repai" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_CONTACT;
    } else if( 0==strcmp( link->name, "stake_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_STAKE;
    } else if( 0==strcmp( link->name, "shred_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SHRED;
    } else if( 0==strcmp( link->name, "sign_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_SIGN;
      sign_link_in_idx = in_idx;
    } else {
      FD_LOG_ERR(( "repair tile has unexpected input link %s", link->name ));
    }

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;
    FD_TEST( fd_dcache_compact_is_safe( ctx->in_links[in_idx].mem, link->dcache, link->mtu, link->depth ) );
  }
  if( FD_UNLIKELY( sign_link_in_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing sign_repair link" ));

  uint net_link_out_idx  = UINT_MAX;
  uint sign_link_out_idx = UINT_MAX;
  uint shred_tile_idx    = 0;
  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];

    if( 0==strcmp( link->name, "repair_net" ) ) {

      if( net_link_out_idx!=UINT_MAX ) continue; /* only use first net link */
      net_link_out_idx = out_idx;
      ctx->net_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, link->dcache );
      ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, link->dcache, link->mtu );
      ctx->net_out_chunk  = ctx->net_out_chunk0;

    } else if( 0==strcmp( link->name, "repair_sign" ) ) {

      sign_link_out_idx = out_idx;

    } else if( 0==strcmp( link->name, "repair_repla" ) ) {

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

    } else {
      FD_LOG_ERR(( "repair tile has unexpected output link %s", link->name ));
    }

  }
  if( FD_UNLIKELY( sign_link_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing repair_sign link" ));
  if( FD_UNLIKELY( net_link_out_idx ==UINT_MAX ) ) FD_LOG_ERR(( "Missing repair_net link" ));
  ctx->shred_tile_cnt = shred_tile_idx;
  FD_TEST( ctx->shred_tile_cnt == fd_topo_tile_name_cnt( topo, "shred" ) );

  /* Scratch mem setup */

  ctx->repair     = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(), fd_repair_footprint() );
  ctx->forest = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(), fd_forest_footprint( tile->repair.slot_max ) );
  ctx->fec_sigs = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_sig_align(), fd_fec_sig_footprint( 20 ) );
  ctx->reasm = FD_SCRATCH_ALLOC_APPEND( l, fd_reasm_align(), fd_reasm_footprint( 20 ) );
  // ctx->fec_repair = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_repair_align(), fd_fec_repair_footprint(  ( 1<<20 ), tile->repair.shred_tile_cnt ) );
  /* Look at fec_repair.h for an explanation of this fec_max. */

  ctx->fec_chainer = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_chainer_align(), fd_fec_chainer_footprint( 1 << 20 ) );

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

  /* Keyguard setup */
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_link_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_link_out_idx ] ];
  if( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                        sign_out->mcache,
                                                        sign_out->dcache,
                                                        sign_in->mcache,
                                                        sign_in->dcache ) ) == NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

  FD_LOG_NOTICE(( "repair starting" ));

  /* Repair set up */

  ctx->repair = fd_repair_join( fd_repair_new( ctx->repair, ctx->repair_seed ) );
  ctx->forest = fd_forest_join( fd_forest_new( ctx->forest, tile->repair.slot_max, ctx->repair_seed ) );
  // ctx->fec_repair  = fd_fec_repair_join( fd_fec_repair_new( ctx->fec_repair, ( tile->repair.max_pending_shred_sets + 2 ), tile->repair.shred_tile_cnt,  0 ) );
  ctx->fec_sigs = fd_fec_sig_join( fd_fec_sig_new( ctx->fec_sigs, 20 ) );
  ctx->reasm = fd_reasm_join( fd_reasm_new( ctx->reasm, 20 ) );
  ctx->fec_chainer = fd_fec_chainer_join( fd_fec_chainer_new( ctx->fec_chainer, 1 << 20, 0 ) );
  ctx->repair_iter = fd_forest_iter_init( ctx->forest );
  FD_TEST( fd_forest_iter_done( ctx->repair_iter, ctx->forest ) );

  /**********************************************************************/
  /* turbine_slot fseq                                                  */
  /**********************************************************************/

  ulong turbine_slot0_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "turbine_slot0" );
  FD_TEST( turbine_slot0_obj_id!=ULONG_MAX );
  ctx->turbine_slot0 = fd_fseq_join( fd_topo_obj_laddr( topo, turbine_slot0_obj_id ) );
  FD_TEST( ctx->turbine_slot0 );
  FD_TEST( fd_fseq_query( ctx->turbine_slot0 )==ULONG_MAX );

  ulong turbine_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "turbine_slot" );
  FD_TEST( turbine_slot_obj_id!=ULONG_MAX );
  ctx->turbine_slot = fd_fseq_join( fd_topo_obj_laddr( topo, turbine_slot_obj_id ) );
  FD_TEST( ctx->turbine_slot );
  fd_fseq_update( ctx->turbine_slot, 0UL );

  FD_LOG_NOTICE(( "repair my addr - intake addr: " FD_IP4_ADDR_FMT ":%u, serve_addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_intake_addr.addr ), fd_ushort_bswap( ctx->repair_intake_addr.port ),
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_serve_addr.addr ), fd_ushort_bswap( ctx->repair_serve_addr.port ) ));

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->wmark ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  ctx->prev_wmark = fd_fseq_query( ctx->wmark );

  if( fd_repair_set_config( ctx->repair, &ctx->repair_config ) ) {
    FD_LOG_ERR( ( "error setting repair config" ) );
  }

  fd_repair_update_addr( ctx->repair, &ctx->repair_intake_addr, &ctx->repair_serve_addr );

  fd_histf_join( fd_histf_new( ctx->repair->metrics.store_link_wait, FD_MHIST_SECONDS_MIN( REPAIR, STORE_LINK_WAIT ),
                                                                     FD_MHIST_SECONDS_MAX( REPAIR, STORE_LINK_WAIT ) ) );
  fd_histf_join( fd_histf_new( ctx->repair->metrics.store_link_work, FD_MHIST_SECONDS_MIN( REPAIR, STORE_LINK_WORK ),
                                                                     FD_MHIST_SECONDS_MAX( REPAIR, STORE_LINK_WORK ) ) );

  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_start( ctx->repair );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_repair_tile(
    out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)tile->repair.good_peer_cache_file_fd );
  return sock_filter_policy_fd_repair_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( -1!=tile->repair.good_peer_cache_file_fd ) )
    out_fds[ out_cnt++ ] = tile->repair.good_peer_cache_file_fd; /* good peer cache file */
  return out_cnt;
}

static inline void
metrics_write( fd_repair_tile_ctx_t * ctx ) {
  /* Repair-protocol-specific metrics */
  fd_repair_metrics_t * metrics = fd_repair_get_metrics( ctx->repair );
  FD_MCNT_SET( REPAIR, RECV_CLNT_PKT, metrics->recv_clnt_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_PKT, metrics->recv_serv_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_CORRUPT_PKT, metrics->recv_serv_corrupt_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_INVALID_SIGNATURE, metrics->recv_serv_invalid_signature );
  FD_MCNT_SET( REPAIR, RECV_SERV_FULL_PING_TABLE, metrics->recv_serv_full_ping_table );
  FD_MCNT_ENUM_COPY( REPAIR, RECV_SERV_PKT_TYPES, metrics->recv_serv_pkt_types );
  FD_MCNT_SET( REPAIR, RECV_PKT_CORRUPTED_MSG, metrics->recv_pkt_corrupted_msg );
  FD_MCNT_SET( REPAIR, SEND_PKT_CNT, metrics->send_pkt_cnt );
  FD_MCNT_ENUM_COPY( REPAIR, SENT_PKT_TYPES, metrics->sent_pkt_types );
  FD_MHIST_COPY( REPAIR, STORE_LINK_WAIT, metrics->store_link_wait );
  FD_MHIST_COPY( REPAIR, STORE_LINK_WORK, metrics->store_link_work );
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
