/* Repair tile runs the repair protocol for a Firedancer node. */
#include "fd_fec_chainer.h"
#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"
#include "generated/fd_repair_tile_seccomp.h"

#include "../store/util.h"
#include "../../flamenco/repair/fd_repair.h"

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../choreo/fd_choreo_base.h"
#include "../../util/net/fd_net_headers.h"

#include "../forest/fd_forest.h"
#include "fd_fec_repair.h"
#include "fd_fec_chainer.h"

#include <errno.h>

#define IN_KIND_NET     (0)
#define IN_KIND_CONTACT (1)
#define IN_KIND_STAKE   (2)
#define IN_KIND_STORE   (3)
#define IN_KIND_SHRED   (4)
#define IN_KIND_SIGN    (5)
#define MAX_IN_LINKS    (16)

#define STORE_OUT_IDX  (0)
#define NET_OUT_IDX    (1)
#define SIGN_OUT_IDX   (2)
#define REPLAY_OUT_IDX (3)
#define REPAIR_OUT_IDX (4)

#define MAX_REPAIR_PEERS 40200UL
#define MAX_BUFFER_SIZE  ( MAX_REPAIR_PEERS * sizeof(fd_shred_dest_wire_t))
#define MAX_SHRED_TILE_CNT (16UL)

#define FD_FOREST_ELE_MAX (1 << 14UL) /* FIXME */
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

struct fd_repair_tile_ctx {
  long tsprint; /* timestamp for printing */
  long tsrepair; /* timestamp for repair */
  ulong * wmark;

  fd_repair_t * repair;
  fd_repair_config_t repair_config;

  ulong repair_seed;

  fd_repair_peer_addr_t repair_intake_addr;
  fd_repair_peer_addr_t repair_serve_addr;

  ushort                repair_intake_listen_port;
  ushort                repair_serve_listen_port;

  fd_forest_t *     forest;
  fd_fec_sig_t * fec_sigs;
  // fd_fec_repair_t *  fec_repair;
  fd_fec_chainer_t * fec_chainer;
  ulong curr_turbine_slot;
  ulong repairing_slot;

  uchar       identity_private_key[ 32 ];
  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  uchar              in_kind[ MAX_IN_LINKS ];
  fd_repair_in_ctx_t in_links[ MAX_IN_LINKS ];

  int skip_frag;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_frag_meta_t * store_out_mcache;
  ulong *          store_out_sync;
  ulong            store_out_depth;
  ulong            store_out_seq;

  fd_wksp_t * store_out_mem;
  ulong       store_out_chunk0;
  ulong       store_out_wmark;
  ulong       store_out_chunk;

  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  uint                shred_tile_cnt;
  fd_repair_out_ctx_t shred_out_ctx[ MAX_SHRED_TILE_CNT ];

  ushort net_id;
  /* Includes Ethernet, IP, UDP headers */
  uchar buffer[ MAX_BUFFER_SIZE ];
  fd_ip4_udp_hdrs_t intake_hdr[1];
  fd_ip4_udp_hdrs_t serve_hdr [1];

  fd_stake_ci_t * stake_ci;

  fd_stem_context_t * stem;

  fd_wksp_t  *      blockstore_wksp;
  fd_blockstore_t   blockstore_ljoin;
  fd_blockstore_t * blockstore;

  fd_keyguard_client_t keyguard_client[1];

  fd_forest_frontier_iter_t frontier_iter; /* current frontier we are going down */
  fd_forest_ele_t * q_head;                  /* head of BFS quwayway*/
  fd_forest_ele_t * q_tail;
  uint              last_sent_idx; /* lol */
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
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(),             fd_repair_footprint( FD_NEEDED_KEY_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_forest_align(),             fd_forest_footprint( FD_FOREST_ELE_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_fec_sig_align(),             fd_fec_sig_footprint( 20 ) );
  // l = FD_LAYOUT_APPEND( l, fd_fec_repair_align(),         fd_fec_repair_footprint( ( 1<<20 ), tile->repair.shred_tile_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_fec_chainer_align(),        fd_fec_chainer_footprint( FD_FOREST_ELE_MAX * 4 ) ); // TODO: fix this
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(),       fd_scratch_smem_footprint( FD_REPAIR_SCRATCH_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(),       fd_scratch_fmem_footprint( FD_REPAIR_SCRATCH_DEPTH ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),           fd_stake_ci_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

void
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
  fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
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

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    fd_repair_peer_addr_t repair_peer = {
      .addr = in_dests[i].ip4_addr,
      .port = fd_ushort_bswap( in_dests[i].udp_port ),
    };

    fd_repair_add_active_peer( ctx->repair, &repair_peer, in_dests[i].pubkey );
  }
}

static inline void
handle_new_stake_weights( fd_repair_tile_ctx_t * ctx ) {
  ulong stakes_cnt = ctx->stake_ci->scratch->staked_cnt;

  if( stakes_cnt >= MAX_REPAIR_PEERS ) {
    FD_LOG_ERR(( "Cluster nodes had %lu stake weights, which was more than the max of %lu", stakes_cnt, MAX_REPAIR_PEERS ));
  }

  fd_stake_weight_t const * in_stake_weights = ctx->stake_ci->stake_weight;
  fd_repair_set_stake_weights( ctx->repair, in_stake_weights, stakes_cnt );
}


static void
repair_send_intake_packet( uchar const *                 msg,
                           size_t                        msglen,
                           fd_gossip_peer_addr_t const * addr,
                           uint                          src_addr,
                           void *                        arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, 1, addr->addr, addr->port, src_addr, msg, msglen, tsorig );
}

static void
repair_send_serve_packet( uchar const *                 msg,
                          size_t                        msglen,
                          fd_gossip_peer_addr_t const * addr,
                          uint                          src_addr,
                          void *                        arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, 0, addr->addr, addr->port, src_addr, msg, msglen, tsorig );
}

static void
repair_shred_deliver( fd_shred_t const *            shred,
                      ulong                         shred_sz,
                      fd_repair_peer_addr_t const * from FD_PARAM_UNUSED,
                      fd_pubkey_t const *           id FD_PARAM_UNUSED,
                      void *                        arg ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)arg;

  fd_shred_t * out_shred = fd_chunk_to_laddr( ctx->store_out_mem, ctx->store_out_chunk );
  fd_memcpy( out_shred, shred, shred_sz );

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = 0UL;
  fd_stem_publish( ctx->stem, STORE_OUT_IDX, sig, ctx->store_out_chunk, shred_sz, 0UL, 0UL, tspub );
  ctx->store_out_chunk = fd_dcache_compact_next( ctx->store_out_chunk, shred_sz, ctx->store_out_chunk0, ctx->store_out_wmark );
}

static void
repair_shred_deliver_fail( fd_pubkey_t const * id FD_PARAM_UNUSED,
                           ulong               slot,
                           uint                shred_index,
                           void *              arg FD_PARAM_UNUSED,
                           int                 reason ) {
  FD_LOG_DEBUG(( "repair failed to get shred - slot: %lu, shred_index: %u, reason: %d", slot, shred_index, reason ));
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

static int
is_fec_completes_msg( ulong sz ) {
  return sz == FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ;
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
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
    return;

  } else if( FD_UNLIKELY( in_kind==IN_KIND_STORE ) ) {
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in_ctx->chunk0, in_ctx->wmark ));
    }
    dcache_entry = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    dcache_entry_sz = sz;

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
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    handle_new_stake_weights( ctx );
    return;
  }

  if( FD_UNLIKELY( in_kind==IN_KIND_SHRED ) ) {

    /* Initialize the forest, which requires the root to be ready.  This
       must be the case if we have received a frag from shred, because
       shred requires stake weights, which implies a genesis or snapshot
       slot has been loaded. */

    if( FD_UNLIKELY( fd_forest_root_slot( ctx->forest ) == ULONG_MAX ) ) {
      fd_forest_init( ctx->forest, fd_fseq_query( ctx->wmark ) );
      uchar mr[ FD_SHRED_MERKLE_ROOT_SZ ] = { 0 }; /* FIXME */
      fd_fec_chainer_init( ctx->fec_chainer, fd_fseq_query( ctx->wmark ), mr );
      FD_TEST( fd_forest_root_slot( ctx->forest ) != ULONG_MAX );
    }

    fd_shred_t * shred = (fd_shred_t *)fd_type_pun( ctx->buffer );
    if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) return; /* shred too old */

    /* Insert the shred sig (shared by all shred members in the FEC set)
       into the map. */

    // FD_LOG_NOTICE(( "shred %lu %u %u", shred->slot, shred->idx, shred->fec_set_idx ));

    fd_fec_sig_t * fec_sig = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx, NULL );
    if( FD_UNLIKELY( !fec_sig ) ) {
      // FD_LOG_NOTICE(( "inserting FEC %lu %lu %u", (shred->slot << 32) | shred->fec_set_idx, shred->slot, shred->fec_set_idx ));
      fec_sig = fd_fec_sig_insert( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx );
      memcpy( fec_sig->sig, shred->signature, sizeof(fd_ed25519_sig_t) );
    }

    /* When this is a FEC completes msg, it is implied that all the
       other shreds in the FEC set can also be inserted.  Shred inserts
       into the forest are idempotent so it is fine to insert the same
       shred multiple times. */

    if( FD_UNLIKELY( is_fec_completes_msg( sz ) ) ) {
      fd_forest_ele_t * ele = NULL;
      for( uint idx = shred->fec_set_idx; idx <= shred->idx; idx++ ) {
        ele = fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->data.parent_off, idx, shred->fec_set_idx, 0, 0 );
      }
      FD_TEST( ele ); /* must be non-empty */
      fd_forest_ele_idxs_insert( ele->cmpl, shred->fec_set_idx );

      uchar * merkle        = ctx->buffer + FD_SHRED_DATA_HEADER_SZ;
      int     data_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE);
      int     slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);

      FD_TEST( fd_fec_pool_free( ctx->fec_chainer->pool ) );
      FD_TEST( fd_fec_chainer_insert( ctx->fec_chainer, shred->slot, shred->fec_set_idx, (ushort)(shred->idx - shred->fec_set_idx + 1), data_complete, slot_complete, shred->data.parent_off, merkle, merkle /* FIXME */ ) );
      while( FD_LIKELY( !fd_fec_out_empty( ctx->fec_chainer->out ) ) ) {
        fd_fec_out_t out = fd_fec_out_pop_head( ctx->fec_chainer->out );
        FD_TEST( out.err == FD_FEC_CHAINER_SUCCESS );
        if( FD_UNLIKELY( out.data_complete ) ) {
          ulong sig   = fd_disco_repair_replay_sig( out.slot, out.parent_off, out.data_cnt, out.slot_complete );
          ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
          fd_stem_publish( ctx->stem, REPLAY_OUT_IDX, sig, 0, 0, 0, tsorig, tspub );
        }
      }
    }

    /* Insert the shred into the map. */


    int is_code = fd_shred_is_code( fd_shred_type( shred->variant ) );
    // FD_LOG_NOTICE(( "shred %lu %u %u %d", shred->slot, shred->idx, shred->fec_set_idx, is_code ));
    if( FD_LIKELY( !is_code ) ) {
      int               data_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE);
      int               slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);
      fd_forest_ele_t * ele           = fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->data.parent_off, shred->idx, shred->fec_set_idx, data_complete, slot_complete );

      /* Check if there are FECs to force complete. Algorithm: window
         through the idxs in interval [i, j). If j = next fec_set_idx
         then we know we can force complete the FEC set interval [i, j)
         (assuming it wasn't already completed based on `cmpl`). */

      uint i = 0;
      // FD_LOG_WARNING(( "slot %lu buffered_idx %u", shred->slot, ele->buffered_idx ));
      for(ulong i =0; i < ele->buffered_idx + 1; i++) {
        if ( fd_forest_ele_idxs_test( ele->fecs, i ) ) {
          // FD_LOG_WARNING(( "fec %lu", i ));
        }
      }
      for( uint j = 1; j < ele->buffered_idx + 1; j++ ) { /* TODO iterate by word */
        if( FD_UNLIKELY( fd_forest_ele_idxs_test( ele->cmpl, i ) && fd_forest_ele_idxs_test( ele->fecs, j ) ) ) {
          // FD_LOG_WARNING(( "skipping %lu %u", ele->slot, i ));
          i = j;
        } else if( FD_UNLIKELY( fd_forest_ele_idxs_test( ele->fecs, j ) || j == ele->complete_idx ) ) {
          // FD_LOG_WARNING(( "force completing %lu %u", ele->slot, i ));
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
  }

  ctx->stem = stem;
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
    fd_repair_recv_clnt_packet( ctx->repair, data, data_sz, &peer_addr, ip4->daddr );
  } else if( ctx->repair_serve_addr.port == dport ) {
    fd_repair_recv_serv_packet( ctx->repair, data, data_sz, &peer_addr, ip4->daddr );
  } else {
    FD_LOG_WARNING(( "Unexpectedly received packet for port %u", (uint)fd_ushort_bswap( dport ) ));
  }
}

static inline void
after_credit( fd_repair_tile_ctx_t * ctx,
               fd_stem_context_t *   stem FD_PARAM_UNUSED,
               int *                 opt_poll_in FD_PARAM_UNUSED,
               int *                 charge_busy ) {
  *charge_busy = 1;
  long now = fd_log_wallclock();
  fd_repair_settime( ctx->repair, now );

  if( FD_UNLIKELY( fd_forest_root_slot( ctx->forest ) == ULONG_MAX ) ) return;

  /* TODO: fix peer selection... */
  fd_pubkey_t * ids[FD_REPAIR_NUM_NEEDED_PEERS] = {0};
  get_peers( ctx->repair, ids, FD_REPAIR_NUM_NEEDED_PEERS );

  fd_forest_t *          forest   = ctx->forest;
  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );

  int sent = 0;

#define LOOP_PEERS_AND_SEND( tag )                                             \
  for( int i=0; i<FD_REPAIR_NUM_NEEDED_PEERS; i++ ) {                          \
    if( FD_LIKELY( ids[i] ) ) {                                                \
      fd_active_elem_t * peer = fd_repair_active_query( ctx->repair, ids[i] ); \
      sent = 1;                                                                \
      fd_repair_send_request( ctx->repair, tag, peer );                        \
    }                                                                          \
  }

  /* currently BFS-ing a slot on the frontier / it's children*/
  if( FD_LIKELY( ctx->q_head ) ) {
    fd_forest_ele_t * head = ctx->q_head;
    FD_LOG_INFO(("current queue head: %lu, buffered_idx: %u, complete_idx: %u", head->slot, head->buffered_idx, head->complete_idx));
    fd_forest_ele_t * tail = ctx->q_tail;
    fd_forest_ele_t * prev = NULL;

    if( FD_UNLIKELY( head->complete_idx == UINT_MAX ) ) {
      uint highest = head->buffered_idx == UINT_MAX ? 0 : head->buffered_idx;
      ulong tag = fd_repair_need_highest_window_index( ctx->repair, head->slot, highest );
      if( tag ) LOOP_PEERS_AND_SEND( tag );
    }

    uint next_send_idx = fd_uint_max( head->buffered_idx + 1, ctx->last_sent_idx + 1 );
    for( uint idx = next_send_idx; idx <= head->complete_idx; idx++ ) {
      if( FD_LIKELY( !fd_forest_ele_idxs_test( head->idxs, idx ) ) ) {
        ulong tag = fd_repair_need_window_index( ctx->repair, head->slot, idx );
        if( tag ) {
          LOOP_PEERS_AND_SEND( tag );
          ctx->last_sent_idx = idx;
          break;
        }
      };
      ctx->last_sent_idx = idx;
    }

    /* Advance queue */

    int slot_complete = ( head->complete_idx == 0 && head->buffered_idx == 0 ) ||
                         fd_uint_if( head->buffered_idx == UINT_MAX, 0, head->buffered_idx ) >= head->complete_idx;

    if( FD_UNLIKELY( ctx->last_sent_idx >= head->complete_idx || slot_complete ) ) {


      /* finished repair requests for this slot, so this means we can
         add its children to the BFS qwayway */

      ctx->last_sent_idx = UINT_MAX;
      fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        tail->prev     = fd_forest_pool_idx( pool, child );
        tail           = fd_forest_pool_ele( pool, tail->prev );
        tail->prev     = null;
        child          = fd_forest_pool_ele( pool, child->sibling );
      }
      prev       = head;
      head       = fd_forest_pool_ele( pool, head->prev );
      FD_LOG_INFO(("advancing queue head: %lu, buffered: %u/%u TO child slot: %lu", prev->slot, prev->buffered_idx, prev->complete_idx,  head != NULL ? head->slot: 0 ));
      prev->prev = null;
      ctx->q_head = head;
      ctx->q_tail = tail;
    }
  } else { // q_head == NULL
    //FD_LOG_INFO(( "nothing on queue, checking frontier" ));
    /* Nothing on queue. check next frontier slot
       Note: because the frontier may change over multiple after_credit
       iterations, we may be missing some frontier slots... but its
       probably ok i think we'll just get it on the next one. */

    if( FD_UNLIKELY( fd_forest_frontier_iter_done( ctx->frontier_iter, frontier, pool ) ) ) {
      ctx->frontier_iter = fd_forest_frontier_iter_init( frontier, pool );
    }
    fd_forest_ele_t * ele = fd_forest_frontier_iter_ele( ctx->frontier_iter, frontier, pool );
    ctx->q_head = ele;
    ctx->q_tail = ele;

    ctx->frontier_iter = fd_forest_frontier_iter_next( ctx->frontier_iter, frontier, pool );
  }

  /* if we still havent sent a repair request, fire the orphan reqs. */

  if( !sent ) {
    //FD_LOG_INFO(("sending orphaned repair requests"));
    for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
    !fd_forest_orphaned_iter_done( iter, orphaned, pool );
    iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
      fd_forest_ele_t * orphan = fd_forest_orphaned_iter_ele( iter, orphaned, pool );
      ulong tag = 0;
      if( FD_LIKELY( tag = fd_repair_need_orphan( ctx->repair, orphan->slot ) ) ){
        LOOP_PEERS_AND_SEND( tag );
      }
    }
  }
  #undef LOOP_PEERS_AND_SEND
  fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );

  fd_repair_continue( ctx->repair );

  FD_LOG_INFO(("done with this after_credit iter"));

}

static inline void
after_credit2( fd_repair_tile_ctx_t * ctx,
              fd_stem_context_t *    stem FD_PARAM_UNUSED,
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy ) {

  /* TODO: Don't charge the tile as busy if after_credit isn't actually
     doing any work. */
  *charge_busy = 1;

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - ctx->tsrepair < (long)50e6 ) ) return;
  ctx->tsrepair = now;
  fd_repair_settime( ctx->repair, now );

  if( FD_UNLIKELY( ctx->forest->root == ULONG_MAX ) ) return;

  fd_forest_t *          forest   = ctx->forest;
  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );

  fd_pubkey_t * ids[FD_REPAIR_NUM_NEEDED_PEERS] = {0};
  get_peers( ctx->repair, ids, FD_REPAIR_NUM_NEEDED_PEERS );

#define LOOP_PEERS_AND_SEND( tag )                                             \
  for( int i=0; i<FD_REPAIR_NUM_NEEDED_PEERS; i++ ) {                          \
    if( FD_LIKELY( ids[i] ) ) {                                                \
      fd_active_elem_t * peer = fd_repair_active_query( ctx->repair, ids[i] ); \
      fd_repair_send_request( ctx->repair, tag, peer );                        \
    }                                                                          \
  }


  // req sent:
  // resp recieve: 19:54:00:0434069
  //
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( frontier, pool );
       !fd_forest_frontier_iter_done( iter, frontier, pool );
       iter = fd_forest_frontier_iter_next( iter, frontier, pool ) ) {
    fd_forest_ele_t *       ele  = fd_forest_frontier_iter_ele( iter, frontier, pool );
    fd_forest_ele_t *       head = ele;
    fd_forest_ele_t *       tail = head;
    fd_forest_ele_t *       prev = NULL;
    while( FD_LIKELY( head ) ) {

      /*if( FD_UNLIKELY( head->complete_idx == UINT_MAX ) ) {
        uint highest = head->buffered_idx == UINT_MAX ? 0 : head->buffered_idx;
        ulong tag = fd_repair_need_highest_window_index( ctx->repair, head->slot, highest );
        if( !tag ) break;
        LOOP_PEERS_AND_SEND( tag );
      }*/

      for( uint idx = head->buffered_idx + 1; idx < fd_ulong_min( head->complete_idx, head->buffered_idx + 5 ); idx++ ) {
        if( FD_LIKELY( !fd_forest_ele_idxs_test( head->idxs, idx ) ) ) {
          ulong tag = fd_repair_need_window_index( ctx->repair, head->slot, idx );
          if( !tag ) continue;
          LOOP_PEERS_AND_SEND( tag );
        };
      }
      ctx->repairing_slot = head->slot;
      break; // only sending to root of each frontier for now
      fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        tail->prev     = fd_forest_pool_idx( pool, child );
        tail           = fd_forest_pool_ele( pool, tail->prev );
        tail->prev     = fd_forest_pool_idx_null( pool );
        child          = fd_forest_pool_ele( pool, child->sibling );
      }
      prev       = head;
      head       = fd_forest_pool_ele( pool, head->prev );
      prev->prev = null;
    }
  }

  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
       !fd_forest_orphaned_iter_done( iter, orphaned, pool );
       iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_ele_t * orphan = fd_forest_orphaned_iter_ele( iter, orphaned, pool );
    ulong tag = 0;
    if( FD_LIKELY( tag = fd_repair_need_orphan( ctx->repair, orphan->slot ) ) ){
      LOOP_PEERS_AND_SEND( tag );
    }

    fd_forest_ele_t * head = orphan;
    fd_forest_ele_t * tail = head;
    fd_forest_ele_t * prev = NULL;
    while( FD_LIKELY( head ) ) {
      for( uint idx = head->buffered_idx + 1; idx < fd_ulong_min( head->complete_idx, FD_REEDSOL_DATA_SHREDS_MAX); idx++ ) {
        if( FD_LIKELY( !fd_forest_ele_idxs_test( head->idxs, idx ) ) ) {
          fd_repair_need_window_index( ctx->repair, head->slot, idx );
        };
      }
      fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        tail->prev     = fd_forest_pool_idx( pool, child );
        tail           = fd_forest_pool_ele( pool, tail->prev );
        tail->prev     = fd_forest_pool_idx_null( pool );
        child          = fd_forest_pool_ele( pool, child->sibling );
      }
      prev       = head;
      head       = fd_forest_pool_ele( pool, head->prev );
      prev->prev = null;
    }
  }

  fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );

  fd_repair_continue( ctx->repair );

  FD_LOG_INFO(("done with this after_credit iter"));
}

static inline void
during_housekeeping( fd_repair_tile_ctx_t * ctx ) {
  fd_repair_settime( ctx->repair, fd_log_wallclock() );

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - ctx->tsprint > (long)1e9 ) ) {
    fd_forest_print( ctx->forest );
    ctx->tsprint = fd_log_wallclock();

    if( ctx->curr_turbine_slot == 0 || ctx->repairing_slot == 0 ) {
      return;
    }

    FD_LOG_NOTICE( ( "\n\n[Repair]\n"
      "current turbine: %lu\n"
      "repairing:       %lu\n"
      "slots behind:    %lu\n"
      "live:            %d\n",
      ctx->curr_turbine_slot,
      ctx->repairing_slot,
      ctx->curr_turbine_slot - ctx->repairing_slot,
      ( ctx->curr_turbine_slot - ctx->repairing_slot ) < 5 ) );
  }

  if( FD_UNLIKELY( !ctx->stem ) ) {
    return;
  }

  // /* Note: just running Testnet, without repairs routed through shred
  //    yet, this loop almost never catches blind complete messages.
  //    After repairs route through shred, could be worth adding some way
  //    to handle the below case w/out constantly looping for it. */

  // fd_fec_intra_map_t * fec_intra_map  = ctx->fec_repair->intra_map;
  // fd_fec_intra_t     * fec_intra_pool = ctx->fec_repair->intra_pool;

  // fd_fec_intra_pool_private_t const * meta = fd_fec_intra_pool_private_meta_const( fec_intra_pool );
  // FD_TEST( meta->magic == 0xF17EDA2CE7900100UL );

  // for( fd_fec_intra_map_iter_t iter = fd_fec_intra_map_iter_init( fec_intra_map, fec_intra_pool );
  //       !fd_fec_intra_map_iter_done( iter, fec_intra_map, fec_intra_pool );
  //       iter = fd_fec_intra_map_iter_next( iter, fec_intra_map, fec_intra_pool ) ) {

  //   fd_fec_intra_t const * fec = fd_fec_intra_map_iter_ele_const( iter, fec_intra_map, fec_intra_pool );
  //   if( FD_UNLIKELY( fec->completes_idx != UINT_MAX ) ) continue; // already completed, or being taken care of
  //   if( FD_UNLIKELY( fec->buffered_idx  == UINT_MAX ) ) continue; // nothing buffered

  //   /* This occurs when fec_1 completes fully with only data shreds
  //      before any shred of fec_2 arrives, and thus fec_1 may never know
  //      what it's completes_idx is. We catch these cases here. */

  //   if( FD_UNLIKELY( check_blind_fec_completed( ctx->fec_repair, ctx->fec_chainer, fec->slot, fec->fec_set_idx ) ) ){
  //     /* find the shred tile owning this FEC set */
  //     fd_ed25519_sig_t null_sig = { 0 };
  //     FD_TEST( memcmp( fec->sig, null_sig, sizeof(fd_ed25519_sig_t)) != 0 );

  //     ulong shred_sig = fd_ulong_load_8( &fec->sig );
  //     int   tile_idx  = (int) ( shred_sig % (ulong)ctx->shred_tile_cnt );
  //     uint  last_idx  = fec->buffered_idx;
  //     ulong sig       = fd_disco_repair_shred_sig( last_idx );

  //     FD_LOG_WARNING(("[%s] sending blind force_complete message to shred tile %d, with sig %lu", __func__, tile_idx, shred_sig ));
  //     uchar * shed_out_buf = fd_chunk_to_laddr( ctx->shred_out_ctx[tile_idx].mem, ctx->shred_out_ctx[tile_idx].chunk );
  //     fd_memcpy( shed_out_buf, &fec->sig, sizeof( fd_ed25519_sig_t ) );
  //     fd_stem_publish( ctx->stem, ctx->shred_out_ctx[tile_idx].idx, sig, ctx->shred_out_ctx[tile_idx].chunk, sizeof( fd_ed25519_sig_t ), 0UL, 0UL, 0UL );
  //     ctx->shred_out_ctx[tile_idx].chunk = fd_dcache_compact_next( ctx->shred_out_ctx[tile_idx].chunk, sizeof(fd_ed25519_sig_t), ctx->shred_out_ctx[tile_idx].chunk0, ctx->shred_out_ctx[tile_idx].wmark );
  //   }
  // }
}

static long
repair_get_shred( ulong  slot,
                  uint   shred_idx,
                  void * buf,
                  ulong  buf_max,
                  void * arg ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)arg;
  fd_blockstore_t * blockstore = ctx->blockstore;
  if( FD_UNLIKELY( blockstore == NULL ) ) {
    return -1;
  }

  if( shred_idx == UINT_MAX ) {
    int err = FD_MAP_ERR_AGAIN;
    while( err == FD_MAP_ERR_AGAIN ) {
      fd_block_map_query_t query[1] = { 0 };
      err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
      fd_block_info_t * meta = fd_block_map_query_ele( query );
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return -1L;
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      shred_idx = (uint)meta->slot_complete_idx;
      err = fd_block_map_query_test( query );
    }
  }
  long sz = fd_buf_shred_query_copy_data( blockstore, slot, shred_idx, buf, buf_max );
  return sz;
}

static ulong
repair_get_parent( ulong  slot,
                   void * arg ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)arg;
  fd_blockstore_t * blockstore = ctx->blockstore;
  if( FD_UNLIKELY( blockstore == NULL ) ) {
    return FD_SLOT_NULL;
  }
  return fd_blockstore_parent_slot_query( blockstore, slot );
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

  tile->repair.good_peer_cache_file_fd = open( tile->repair.good_peer_cache_file, O_RDWR | O_CREAT, 0644 );
  if( FD_UNLIKELY( tile->repair.good_peer_cache_file_fd==-1 ) ) {
    FD_LOG_WARNING(( "Failed to open the good peer cache file (%s) (%i-%s)", tile->repair.good_peer_cache_file, errno, fd_io_strerror( errno ) ));
  }
  ctx->repair_config.good_peer_cache_file_fd = tile->repair.good_peer_cache_file_fd;

  FD_TEST( fd_rng_secure( &ctx->repair_seed, sizeof(ulong) ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  ctx->tsprint = fd_log_wallclock();
  ctx->tsrepair = fd_log_wallclock();

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
    } else if( 0==strcmp( link->name, "store_repair" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_STORE;
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


  uint sign_link_out_idx = UINT_MAX;
  uint shred_tile_idx    = 0;
  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];

    if( 0==strcmp( link->name, "repair_store" ) ) {

      if( FD_UNLIKELY( ctx->store_out_mcache ) ) FD_LOG_ERR(( "repair tile has multiple repair_store out links" ));
      ctx->store_out_mcache = link->mcache;
      ctx->store_out_sync   = fd_mcache_seq_laddr( ctx->store_out_mcache );
      ctx->store_out_depth  = fd_mcache_depth( ctx->store_out_mcache );
      ctx->store_out_seq    = fd_mcache_seq_query( ctx->store_out_sync );
      ctx->store_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->store_out_chunk0 = fd_dcache_compact_chunk0( ctx->store_out_mem, link->dcache );
      ctx->store_out_wmark  = fd_dcache_compact_wmark( ctx->store_out_mem, link->dcache, link->mtu );
      ctx->store_out_chunk  = ctx->store_out_chunk0;

    } else if( 0==strcmp( link->name, "repair_net" ) ) {

      if( FD_UNLIKELY( ctx->net_out_mcache ) ) FD_LOG_ERR(( "repair tile has multiple repair_net out links" ));
      ctx->net_out_mcache = link->mcache;
      ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
      ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
      ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
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

    } else if ( 0==strcmp( link->name, "repair_shred" ) ) {
      fd_repair_out_ctx_t * shred_out = &ctx->shred_out_ctx[ shred_tile_idx++ ];
      shred_out->idx              = out_idx;
      shred_out->mem              = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      shred_out->chunk0           = fd_dcache_compact_chunk0( shred_out->mem, link->dcache );
      shred_out->wmark            = fd_dcache_compact_wmark( shred_out->mem, link->dcache, link->mtu );
      shred_out->chunk            = shred_out->chunk0;
    } else {
      FD_LOG_ERR(( "repair tile has unexpected output link %s", link->name ));
    }

  }
  if( FD_UNLIKELY( sign_link_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing gossip_sign link" ));
  ctx->shred_tile_cnt = shred_tile_idx;
  FD_TEST( ctx->shred_tile_cnt == tile->repair.shred_tile_cnt );

  /* Scratch mem setup */

  ctx->blockstore = &ctx->blockstore_ljoin;
  ctx->repair     = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(), fd_repair_footprint( FD_NEEDED_KEY_MAX ) );
  ctx->forest = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(), fd_forest_footprint( FD_FOREST_ELE_MAX ) );
  ctx->fec_sigs = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_sig_align(), fd_fec_sig_footprint( 20 ) );
  // ctx->fec_repair = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_repair_align(), fd_fec_repair_footprint(  ( 1<<20 ), tile->repair.shred_tile_cnt ) );
  /* Look at fec_repair.h for an explanation of this fec_max. */

  ctx->fec_chainer = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_chainer_align(), fd_fec_chainer_footprint( FD_FOREST_ELE_MAX * 4 ) );

  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( FD_REPAIR_SCRATCH_MAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( FD_REPAIR_SCRATCH_DEPTH ) );

  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, FD_REPAIR_SCRATCH_MAX, FD_REPAIR_SCRATCH_DEPTH );

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ctx->repair_intake_addr.port = fd_ushort_bswap( tile->repair.repair_intake_listen_port );
  ctx->repair_serve_addr.port  = fd_ushort_bswap( tile->repair.repair_serve_listen_port  );

  ctx->repair_intake_listen_port = tile->repair.repair_intake_listen_port;
  ctx->repair_serve_listen_port = tile->repair.repair_serve_listen_port;

  void * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci , &ctx->identity_public_key ) );

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

  /* Blockstore setup */
  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore_wksp = topo->workspaces[ topo->objs[ blockstore_obj_id ].wksp_id ].wksp;

  if( ctx->blockstore_wksp==NULL ) {
    FD_LOG_ERR(( "no blocktore workspace" ));
  }

  ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, fd_topo_obj_laddr( topo, blockstore_obj_id ) );
  FD_TEST( ctx->blockstore!=NULL );

  FD_LOG_NOTICE(( "repair starting" ));

  /* Repair set up */

  ctx->repair      = fd_repair_join( fd_repair_new( ctx->repair, FD_NEEDED_KEY_MAX, ctx->repair_seed ) );
  ctx->forest  = fd_forest_join( fd_forest_new( ctx->forest, FD_FOREST_ELE_MAX, ctx->repair_seed ) );
  // ctx->fec_repair  = fd_fec_repair_join( fd_fec_repair_new( ctx->fec_repair, ( tile->repair.max_pending_shred_sets + 2 ), tile->repair.shred_tile_cnt,  0 ) );
  ctx->fec_sigs = fd_fec_sig_join( fd_fec_sig_new( ctx->fec_sigs, 20 ) );
  ctx->fec_chainer = fd_fec_chainer_join( fd_fec_chainer_new( ctx->fec_chainer, FD_FOREST_ELE_MAX * 4, 0 ) );
  ctx->q_head = NULL;
  ctx->q_tail = NULL;
  ctx->last_sent_idx = UINT_MAX;
  ctx->frontier_iter.chain_rem = 0;

  FD_LOG_NOTICE(( "repair my addr - intake addr: " FD_IP4_ADDR_FMT ":%u, serve_addr: " FD_IP4_ADDR_FMT ":%u",
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_intake_addr.addr ), fd_ushort_bswap( ctx->repair_intake_addr.port ),
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_serve_addr.addr ), fd_ushort_bswap( ctx->repair_serve_addr.port ) ));

  ctx->repair_config.fun_arg = ctx;
  ctx->repair_config.deliver_fun = repair_shred_deliver;
  ctx->repair_config.deliver_fail_fun = repair_shred_deliver_fail;
  ctx->repair_config.clnt_send_fun = repair_send_intake_packet;
  ctx->repair_config.serv_send_fun = repair_send_serve_packet;
  ctx->repair_config.serv_get_shred_fun = repair_get_shred;
  ctx->repair_config.serv_get_parent_fun = repair_get_parent;
  ctx->repair_config.sign_fun = repair_signer;
  ctx->repair_config.sign_arg = ctx;

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->wmark ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));

  if( fd_repair_set_config( ctx->repair, &ctx->repair_config ) ) {
    FD_LOG_ERR( ( "error setting repair config" ) );
  }

  fd_repair_update_addr( ctx->repair, &ctx->repair_intake_addr, &ctx->repair_serve_addr );

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
fd_repair_update_repair_metrics( fd_repair_metrics_t * metrics ) {
  FD_MCNT_SET( REPAIR, RECV_CLNT_PKT, metrics->recv_clnt_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_PKT, metrics->recv_serv_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_CORRUPT_PKT, metrics->recv_serv_corrupt_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_INVALID_SIGNATURE, metrics->recv_serv_invalid_signature );
  FD_MCNT_SET( REPAIR, RECV_SERV_FULL_PING_TABLE, metrics->recv_serv_full_ping_table );
  FD_MCNT_ENUM_COPY( REPAIR, RECV_SERV_PKT_TYPES, metrics->recv_serv_pkt_types );
  FD_MCNT_SET( REPAIR, RECV_PKT_CORRUPTED_MSG, metrics->recv_pkt_corrupted_msg );
  FD_MCNT_SET( REPAIR, SEND_PKT_CNT, metrics->send_pkt_cnt );
  FD_MCNT_ENUM_COPY( REPAIR, SENT_PKT_TYPES, metrics->sent_pkt_types );
}

static inline void
metrics_write( fd_repair_tile_ctx_t * ctx ) {
  /* Repair-protocol-specific metrics */
  fd_repair_update_repair_metrics( fd_repair_get_metrics( ctx->repair ) );
}

/* TODO: This is probably not correct. */
#define STEM_BURST (2UL)

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
