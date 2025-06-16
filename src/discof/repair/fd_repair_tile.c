#include "generated/fd_repair_tile_seccomp.h"

#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../disco/topo/fd_topo.h"
#include "../../discof/repair/fd_repair.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/pod/fd_pod_format.h"

#include "fd_fec_chainer.h"
#include "fd_forest.h"
#include "fd_policy.h"
#include "fd_repair.h"

/* The repair tile sits downstream of the shred tile and discovers */

#define IN_KIND_NET     (0)
#define IN_KIND_CONTACT (1)
#define IN_KIND_ROOT    (2)
#define IN_KIND_STAKE   (3)
#define IN_KIND_SHRED   (4)
#define IN_KIND_SIGN    (5)
#define MAX_IN_LINKS    (16)

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
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
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

struct ctx {
  ulong       seed;         /* rng seed */
  fd_pubkey_t identity_key; /* our validator identity pubkey */

  fd_fec_chainer_t * fec_chainer;
  fd_fec_sig_t *     fec_sigs;
  fd_forest_t *      forest;
  fd_policy_t *      policy;
  fd_reasm_t *       reasm;
  fd_repair_t *      repair;
  fd_stake_ci_t *    stake_ci;

  long                 tsprint; /* timestamp for printing */
  ushort               client_port;
  ushort               server_port;
  fd_ip4_udp_hdrs_t    client_hdr[1];
  fd_ip4_udp_hdrs_t    server_hdr[1];
  ushort               net_id;
  ulong *              turbine_slot0;
  ulong *              turbine_slot;
  fd_keyguard_client_t keyguard_client[1];

  uchar frag[ FD_SHRED_MAX_SZ ]; /* during_frag buffer */

  uchar    in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  ulong       replay_out_idx;
  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  uint      shred_tile_cnt;
  out_ctx_t shred_out_ctx[ 16 /* max shred tile cnt */ ];
};
typedef struct ctx ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  /* TODO fix bounds */
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),          sizeof(ctx_t)                            );
  l = FD_LAYOUT_APPEND( l, fd_fec_chainer_align(),  fd_fec_chainer_footprint( 1 << 20 )      );
  l = FD_LAYOUT_APPEND( l, fd_fec_sig_align(),      fd_fec_sig_footprint( 20 )               );
  l = FD_LAYOUT_APPEND( l, fd_forest_align(),       fd_forest_footprint( 4096 )              );
  l = FD_LAYOUT_APPEND( l, fd_reasm_align(),        fd_reasm_footprint( 20 )                 );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),     fd_stake_ci_footprint()                  );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( ctx_t * ctx ) {
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now - ctx->tsprint > (long)1e9 ) ) {
    fd_forest_print( ctx->forest );
    ctx->tsprint = fd_log_wallclock();
  }
}

static inline void
metrics_write( ctx_t * ctx ) {
  (void)ctx; /* FIXME: Implement metrics write */
  // fd_repair_metrics_t * metrics = fd_repair_get_metrics( ctx->repair );
  // FD_MCNT_SET( REPAIR, RECV_CLNT_PKT, ctx->req_cnt );
  // FD_MCNT_SET( REPAIR, RECV_SERV_PKT, ctx->res_cnt );
  // FD_MCNT_SET( REPAIR, RECV_SERV_CORRUPT_PKT, metrics->recv_serv_corrupt_pkt );
  // FD_MCNT_SET( REPAIR, RECV_SERV_INVALID_SIGNATURE, metrics->recv_serv_invalid_signature );
  // FD_MCNT_SET( REPAIR, RECV_SERV_FULL_PING_TABLE, metrics->recv_serv_full_ping_table );
  // FD_MCNT_ENUM_COPY( REPAIR, RECV_SERV_PKT_TYPES, metrics->recv_serv_pkt_types );
  // FD_MCNT_SET( REPAIR, RECV_PKT_CORRUPTED_MSG, metrics->recv_pkt_corrupted_msg );
  // FD_MCNT_SET( REPAIR, SEND_PKT_CNT, metrics->send_pkt_cnt );
  // FD_MCNT_ENUM_COPY( REPAIR, SENT_PKT_TYPES, metrics->sent_pkt_types );
}

static void
send_packet( ctx_t *       ctx,
             int           is_intake,
             uint          dst_ip_addr,
             ushort        dst_port,
             uint          src_ip_addr,
             uchar const * payload,
             ulong         payload_sz,
             ulong         tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *(is_intake ? ctx->client_hdr : ctx->server_hdr);

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
after_credit( ctx_t *             ctx,
              fd_stem_context_t * stem FD_PARAM_UNUSED,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy ) {

  if( FD_UNLIKELY( ctx->forest->root == ULONG_MAX ) ) return;
  if( FD_UNLIKELY( ctx->policy->peers->cnt == 0   ) ) return;

  *charge_busy = 1;

  fd_repair_req_t *  req  = fd_policy_req_next( ctx->policy, ctx->forest, ctx->repair );
  fd_repair_peer_t * peer = fd_repair_peer_map_query( ctx->repair->peer_map, req->to, NULL );
  FD_TEST( peer ); /* policy and repair out of sync */

  uchar buf[ sizeof(fd_repair_req_t) ];
  ulong sz = fd_repair_serialize_req( fd_repair_keyguard_sign_req( ctx->keyguard_client, req ), buf );
  send_packet( ctx, 1, peer->ip4, peer->port, 0U /* populated by net */, buf, sz, 0UL /* FIXME */ );
}

static inline int
before_frag( ctx_t * ctx,
             ulong   in_idx,
             ulong   seq FD_PARAM_UNUSED,
             ulong   sig ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  if( FD_LIKELY( in_kind==IN_KIND_NET ) ) return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR;
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

  in_ctx_t const * in_ctx = &ctx->in_links[in_idx];
  uchar const *    frag   = fd_chunk_to_laddr_const( in_ctx->mem, chunk );

  switch( ctx->in_kind[in_idx] ) {
  case IN_KIND_CONTACT: fd_memcpy( ctx->frag, frag, sz * sizeof(fd_shred_dest_wire_t) );                                 break;
  case IN_KIND_NET:     fd_memcpy( ctx->frag, fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz ), sz );         break;
  case IN_KIND_ROOT:                                                                                                     break;
  case IN_KIND_STAKE:   fd_stake_ci_stake_msg_init( ctx->stake_ci, (fd_stake_weight_msg_t *)fd_type_pun_const( frag ) ); break;
  case IN_KIND_SHRED:   fd_memcpy( ctx->frag, frag, sz);                                                                 break;
  default:              FD_LOG_ERR(( "unhandled link (kind=%u in_idx=%lu)", ctx->in_kind[in_idx], in_idx ));
  }
}

static void
after_contact( ctx_t * ctx, ulong sz ) {
  fd_shred_dest_wire_t const * in_dests = (fd_shred_dest_wire_t const *)fd_type_pun_const( ctx->frag );
  for( ulong i = 0UL; i < sz; i++ ) {
    fd_pubkey_t const * key = in_dests[i].pubkey;
    fd_repair_peer_t * peer = fd_repair_peer_map_query( ctx->repair->peer_map, *key, NULL );
    if ( FD_UNLIKELY( !peer ) ) peer = fd_repair_peer_map_insert( ctx->repair->peer_map, *key );
    peer->ip4  = in_dests[i].ip4_addr;
    peer->port = fd_ushort_bswap( in_dests[i].udp_port );
  }
}

static void
after_net( ctx_t * ctx, ulong sz ) {
  fd_eth_hdr_t const * eth  = (fd_eth_hdr_t const *)ctx->frag;
  fd_ip4_hdr_t const * ip4  = (fd_ip4_hdr_t const *)( (ulong)eth + sizeof(fd_eth_hdr_t) );
  fd_udp_hdr_t const * udp  = (fd_udp_hdr_t const *)( (ulong)ip4 + FD_IP4_GET_LEN( *ip4 ) );
  uchar *              data = (uchar              *)( (ulong)udp + sizeof(fd_udp_hdr_t) );
  if( FD_UNLIKELY( (ulong)udp+sizeof(fd_udp_hdr_t) > (ulong)eth+sz ) ) return;
  ulong udp_sz = fd_ushort_bswap( udp->net_len );
  if( FD_UNLIKELY( udp_sz<sizeof(fd_udp_hdr_t) ) ) return;
  ulong data_sz = udp_sz-sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( (ulong)data+data_sz > (ulong)eth+sz ) ) return;

  FD_TEST( data );
  ulong dsz; fd_repair_response_t * res = fd_bincode_decode1_scratch( repair_response, data, data_sz, NULL, &dsz );
  FD_TEST( res ); /* shreds are routed to shred, not repair, so this decode must succeed. */
  switch( res->discriminant ) {
  case fd_repair_response_enum_ping: {
    if( FD_UNLIKELY( res->inner.ping.token_len != sizeof(fd_hash_t) ) ) return; /* invalid ping token */
    fd_hash_t ping_token;
    memcpy( ping_token.uc, res->inner.ping.token, sizeof(fd_hash_t) );
    uchar buf[ sizeof(fd_repair_pong_t) ];
    ulong sz = fd_repair_serialize_pong( fd_repair_keyguard_sign_pong( ctx->keyguard_client, fd_repair_pong( ctx->repair, &ping_token ) ), buf );
    send_packet( ctx, 1, ip4->saddr, udp->net_sport, 0U /* populated by net */, buf, sz, 0UL /* FIXME */ );
    break;
  }
  default: FD_LOG_ERR(( "unhandled kind %u", (uint)res->discriminant ));
  }
}

static void
after_root( ctx_t * ctx, ulong root ) {
  if( FD_UNLIKELY( ctx->forest->root == fd_forest_pool_idx_null( fd_forest_pool( ctx->forest ) ) ) ) {
    FD_LOG_NOTICE(( "setting root %lu", root ));
    fd_forest_init( ctx->forest, root );
    uchar mr[ FD_SHRED_MERKLE_ROOT_SZ ] = { 0 }; /* FIXME */
    fd_fec_chainer_init( ctx->fec_chainer, root, mr );
    FD_TEST( fd_forest_root_slot( ctx->forest ) != ULONG_MAX );
  } else {
    fd_forest_publish( ctx->forest, root );
  }
}

static void
after_shred( ctx_t * ctx, ulong sz, ulong tsorig, fd_stem_context_t * stem ) {
  fd_shred_t * shred = (fd_shred_t *)fd_type_pun( ctx->frag );
  if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) return; /* shred too old */

  if( FD_UNLIKELY( shred->slot > fd_fseq_query( ctx->turbine_slot ) ) ) {
    fd_fseq_update( ctx->turbine_slot, shred->slot );
  }

  /* Insert the FEC set sig (shared by shreds in a FEC set). */

  fd_fec_sig_t * fec_sig = fd_fec_sig_query( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx, NULL );
  if( FD_UNLIKELY( !fec_sig ) ) {
    fec_sig = fd_fec_sig_insert( ctx->fec_sigs, (shred->slot << 32) | shred->fec_set_idx );
    memcpy( fec_sig->sig, shred->signature, sizeof(fd_ed25519_sig_t) );
  }

  /* When this is a FEC completes msg, it is implied that all the
     other shreds in the FEC set can also be inserted.  Shred inserts
     into the forest are idempotent so it is fine to insert the same
     shred multiple times. */

  if( FD_UNLIKELY( sz == FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ ) ) {
    fd_forest_ele_t * ele = NULL;
    for( uint idx = shred->fec_set_idx; idx <= shred->idx; idx++ ) {
      ele = fd_forest_data_shred_insert( ctx->forest, shred->slot, shred->data.parent_off, idx, shred->fec_set_idx, 0, 0 );
    }
    FD_TEST( ele ); /* must be non-empty */
    fd_forest_ele_idxs_insert( ele->cmpl, shred->fec_set_idx );

    uchar * merkle        = ctx->frag + FD_SHRED_DATA_HEADER_SZ;
    int     data_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE);
    int     slot_complete = !!(shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);

    FD_TEST( fd_fec_pool_free( ctx->fec_chainer->pool ) );
    FD_TEST( !fd_fec_chainer_query( ctx->fec_chainer, shred->slot, shred->fec_set_idx ) );
    FD_TEST( fd_fec_chainer_insert( ctx->fec_chainer, shred->slot, shred->fec_set_idx, (ushort)(shred->idx - shred->fec_set_idx + 1), data_complete, slot_complete, shred->data.parent_off, merkle, merkle /* FIXME */ ) );

    while( FD_LIKELY( !fd_fec_out_empty( ctx->fec_chainer->out ) ) ) {
      fd_fec_out_t out = fd_fec_out_pop_head( ctx->fec_chainer->out );
      if( FD_UNLIKELY( out.err != FD_FEC_CHAINER_SUCCESS ) ) FD_LOG_ERR(( "fec chainer err %d", out.err ));
      fd_reasm_t * reasm = fd_reasm_query( ctx->reasm, out.slot, NULL );
      if( FD_UNLIKELY( !reasm ) ) {
        reasm      = fd_reasm_insert( ctx->reasm, out.slot );
        reasm->cnt = 0;
      }
      if( FD_UNLIKELY( out.data_complete ) ) {
        uint  cnt   = out.fec_set_idx + out.data_cnt - reasm->cnt;
        ulong sig   = fd_disco_repair_replay_sig( out.slot, out.parent_off, cnt, out.slot_complete );
        ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
        reasm->cnt = out.fec_set_idx + out.data_cnt;
        fd_stem_publish( stem, ctx->replay_out_idx, sig, 0, 0, 0, tsorig, tspub );
        if( FD_UNLIKELY( out.slot_complete ) ) {
          fd_reasm_remove( ctx->reasm, reasm );
        }
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
       through the idxs in interval [i, j). If j = next fec_set_idx then
       we know we can force complete the FEC set interval [i, j)
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

static void
after_stake( ctx_t * ctx ) {
  fd_stake_ci_stake_msg_fini( ctx->stake_ci );
}

static void
after_frag( ctx_t *             ctx,
            ulong               in_idx,
            ulong               seq FD_PARAM_UNUSED,
            ulong               sig FD_PARAM_UNUSED,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub FD_PARAM_UNUSED,
            fd_stem_context_t * stem ) {

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_CONTACT: after_contact( ctx, sz );                                 break;
  case IN_KIND_NET:     after_net    ( ctx, sz );                                 break;
  case IN_KIND_ROOT:    after_root   ( ctx, fd_forest_root_slot( ctx->forest ) ); break;
  case IN_KIND_SHRED:   after_shred  ( ctx, sz, tsorig, stem );                   break;
  case IN_KIND_STAKE:   after_stake  ( ctx );                                     break;
  default:              FD_LOG_ERR(( "unhandled in_kind %u", ctx->in_kind[in_idx] ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  fd_memset( ctx, 0, sizeof(ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ulong) ) );
  uchar * identity_key = fd_keyload_load( tile->repair.identity_key_path, 1 );
  FD_TEST( identity_key );
  memcpy( ctx->identity_key.uc, identity_key, sizeof(fd_pubkey_t) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  ctx->fec_chainer = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_chainer_align(), fd_fec_chainer_footprint( 1 << 20 )      );
  ctx->fec_sigs    = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_sig_align(),     fd_fec_sig_footprint( 20 )               );
  ctx->forest      = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(),      fd_forest_footprint( 1 << 12 )           );
  ctx->reasm       = FD_SCRATCH_ALLOC_APPEND( l, fd_reasm_align(),       fd_reasm_footprint( 20 )                 );
  ctx->repair      = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),      fd_repair_footprint( 4096 )              );
  ctx->stake_ci    = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),    fd_stake_ci_footprint()                  );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->fec_chainer = fd_fec_chainer_join( fd_fec_chainer_new( ctx->fec_chainer, 1 << 20, 0 ) );
  ctx->fec_sigs    = fd_fec_sig_join( fd_fec_sig_new( ctx->fec_sigs, 20 ) );
  ctx->forest      = fd_forest_join( fd_forest_new( ctx->forest, 1 << 12, ctx->seed ) );
  ctx->reasm       = fd_reasm_join( fd_reasm_new( ctx->reasm, 20 ) );
  ctx->repair      = fd_repair_join( fd_repair_new( ctx->repair, 4096 ) );
  ctx->stake_ci    = fd_stake_ci_join( fd_stake_ci_new( ctx->stake_ci , &ctx->identity_key ) );

  ctx->tsprint  = fd_log_wallclock();
  ctx->client_port = tile->repair.client_port;
  ctx->server_port = tile->repair.server_port;
  fd_ip4_udp_hdr_init( ctx->client_hdr, FD_REPAIR_PKT_MAX, 0, ctx->client_port );
  fd_ip4_udp_hdr_init( ctx->server_hdr, FD_REPAIR_PKT_MAX, 0, ctx->server_port );
  ctx->net_id = 0U;
  ulong turbine_slot0_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "turbine_slot0" );
  FD_TEST( turbine_slot0_obj_id!=ULONG_MAX );
  ctx->turbine_slot0 = fd_fseq_join( fd_topo_obj_laddr( topo, turbine_slot0_obj_id ) );
  FD_TEST( ctx->turbine_slot0 );
  ulong turbine_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "turbine_slot" );
  FD_TEST( turbine_slot_obj_id!=ULONG_MAX );
  ctx->turbine_slot = fd_fseq_join( fd_topo_obj_laddr( topo, turbine_slot_obj_id ) );
  FD_TEST( ctx->turbine_slot );

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
    } else if( 0==strcmp( link->name, "root_out" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_ROOT;
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

    if( FD_LIKELY( link->mtu > 0 ) ) {
      ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
      ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
      ctx->in_links[ in_idx ].mtu    = link->mtu;
      FD_TEST( fd_dcache_compact_is_safe( ctx->in_links[in_idx].mem, link->dcache, link->mtu, link->depth ) );
    }
  }
  if( FD_UNLIKELY( sign_link_in_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing sign_repair link" ));

  uint sign_link_out_idx = UINT_MAX;
  uint shred_tile_idx    = 0;
  for( uint out_idx=0U; out_idx<(tile->out_cnt); out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];
    if( 0==strcmp( link->name, "repair_net" ) ) {
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
      ctx->replay_out_idx    = out_idx;
      ctx->replay_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, link->dcache );
      ctx->replay_out_wmark  = fd_dcache_compact_wmark( ctx->replay_out_mem, link->dcache, link->mtu );
      ctx->replay_out_chunk  = ctx->replay_out_chunk0;
    } else if ( 0==strcmp( link->name, "repair_shred" ) ) {
      out_ctx_t * shred_out = &ctx->shred_out_ctx[ shred_tile_idx++ ];
      shred_out->idx                  = out_idx;
      shred_out->mem                  = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      shred_out->chunk0               = fd_dcache_compact_chunk0( shred_out->mem, link->dcache );
      shred_out->wmark                = fd_dcache_compact_wmark( shred_out->mem, link->dcache, link->mtu );
      shred_out->chunk                = shred_out->chunk0;
    } else {
      FD_LOG_ERR(( "repair tile has unexpected output link %s", link->name ));
    }
  }

  if( FD_UNLIKELY( sign_link_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing gossip_sign link" ));
  ctx->shred_tile_cnt = shred_tile_idx;
  FD_TEST( ctx->shred_tile_cnt == fd_topo_tile_name_cnt( topo, "shred" ) );

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id [ sign_link_in_idx  ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_link_out_idx ] ];
  FD_TEST( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client, sign_out->mcache, sign_out->dcache, sign_in->mcache, sign_in->dcache ) ) );
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

/* TODO: This is probably not correct. */
#define STEM_BURST (2UL)

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
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
