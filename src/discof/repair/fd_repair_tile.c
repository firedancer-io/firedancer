#include "generated/fd_repair_tile_seccomp.h"

#include "../../choreo/fd_choreo_base.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../disco/topo/fd_topo.h"
#include "../../discof/replay/fd_exec.h"
#include "../../discof/repair/fd_repair.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/pod/fd_pod_format.h"

#include "../forest/fd_forest.h"
#include "fd_fec_chainer.h"

/* The repair tile sits downstream of the shred tile and discovers */

#define IN_KIND_NET     (0)
#define IN_KIND_CONTACT (1)
#define IN_KIND_STAKE   (2)
#define IN_KIND_SHRED   (3)
#define IN_KIND_SIGN    (4)
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
  long    tsprint;  /* timestamp for printing */
  long    tsrepair; /* timestamp for repair */

  fd_repair_t * repair;

  ushort client_port;
  ushort server_port;

  fd_fec_chainer_t * fec_chainer;
  fd_fec_sig_t *     fec_sigs;
  fd_forest_t *      forest;
  fd_forest_iter_t   forest_iter;
  fd_reasm_t *       reasm;
  fd_repair_t *      repair;
  fd_stake_ci_t *    stake_ci;

  ulong req_cnt;
  ulong res_cnt;

  ulong * curr_turbine_slot;

  fd_pubkey_t identity_key;

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

  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  uint      shred_tile_cnt;
  out_ctx_t shred_out_ctx[MAX_SHRED_TILE_CNT];

  uchar frag[ MAX_FRAG_SZ ];

  ushort net_id;
  /* Includes Ethernet, IP, UDP headers */
  fd_ip4_udp_hdrs_t client_hdr[1];
  fd_ip4_udp_hdrs_t server_hdr [1];

  fd_keyguard_client_t keyguard_client[1];
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
  l = FD_LAYOUT_APPEND( l, fd_forest_align(),       fd_forest_footprint( FD_FOREST_ELE_MAX ) );
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
  fd_repair_metrics_t * metrics = fd_repair_get_metrics( ctx->repair );
  FD_MCNT_SET( REPAIR, RECV_CLNT_PKT, ctx->req_cnt );
  FD_MCNT_SET( REPAIR, RECV_SERV_PKT, ctx->res_cnt );
  FD_MCNT_SET( REPAIR, RECV_SERV_CORRUPT_PKT, metrics->recv_serv_corrupt_pkt );
  FD_MCNT_SET( REPAIR, RECV_SERV_INVALID_SIGNATURE, metrics->recv_serv_invalid_signature );
  FD_MCNT_SET( REPAIR, RECV_SERV_FULL_PING_TABLE, metrics->recv_serv_full_ping_table );
  FD_MCNT_ENUM_COPY( REPAIR, RECV_SERV_PKT_TYPES, metrics->recv_serv_pkt_types );
  FD_MCNT_SET( REPAIR, RECV_PKT_CORRUPTED_MSG, metrics->recv_pkt_corrupted_msg );
  FD_MCNT_SET( REPAIR, SEND_PKT_CNT, metrics->send_pkt_cnt );
  FD_MCNT_ENUM_COPY( REPAIR, SENT_PKT_TYPES, metrics->sent_pkt_types );
}

#define MAX_REQ_PER_CREDIT 500

static inline void
after_credit( fd_repair_tile_ctx_t * ctx,
              fd_stem_context_t *    stem FD_PARAM_UNUSED,
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy ) {
  /* TODO: Don't charge the tile as busy if after_credit isn't actually
     doing any work. */
  *charge_busy = 1;

  if( FD_UNLIKELY( ctx->forest->root == ULONG_MAX ) ) return;
  if( FD_UNLIKELY( ctx->repair->peer_cnt == 0 ) ) return; /* no peers to send requests to */

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
      fd_repair_send_requests( ctx, fd_needed_orphan, orphan->slot, UINT_MAX, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
    }
  }

  if( FD_UNLIKELY( total_req >= MAX_REQ_PER_CREDIT ) ) {
    fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );
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
      fd_repair_send_requests( ctx, fd_needed_highest_window_index, ele->slot, 0, now );
      total_req += FD_REPAIR_NUM_NEEDED_PEERS;
    } else if( fd_repair_need_window_index( ctx->repair, ele->slot, ctx->repair_iter.shred_idx ) ) {
      fd_repair_send_requests( ctx, fd_needed_window_index, ele->slot, ctx->repair_iter.shred_idx, now );
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

  fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );
  fd_repair_continue( ctx->repair );
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
    case IN_KIND_NET:
      fd_memcpy( ctx->frag, fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz ), sz );
      break;

    case IN_KIND_CONTACT:
      fd_memcpy( ctx->frag, frag, sz * sizeof( fd_shred_dest_wire_t ) ); /* FIXME terrible misuse of `sz` */
      break;

    case IN_KIND_STAKE:
      fd_stake_ci_stake_msg_init( ctx->stake_ci, frag );
      break;

    case IN_KIND_SHRED:
      fd_memcpy( ctx->frag, frag, sz);
      break;

    default:
      FD_LOG_ERR(( "Frag from unknown link (kind=%u in_idx=%lu)", ctx->in_kind[in_idx], in_idx ));
  }
}

static void
after_contact( ctx_t * ctx, ulong sz ) {
  fd_shred_dest_wire_t const * in_dests = (fd_shred_dest_wire_t const *)fd_type_pun_const( ctx->frag );
  for( ulong i = 0UL; i < sz; i++ ) {
    ctx->peers[ctx->peer_cnt++] = (fd_peer_t){
      .key = *in_dests[i].pubkey,
      .ip4 = { .addr = in_dests[i].ip4_addr, .port = fd_ushort_bswap( in_dests[i].udp_port ) }
    };
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
  fd_gossip_peer_addr_t peer_addr = { .addr=ip4->saddr, .port=udp->net_sport };
  ushort dport = udp->net_dport;
  if( FD_LIKELY( ctx->client_port == dport ) ) {

  }
}

static void
after_stake( ctx_t * ctx ) {
  fd_stake_ci_stake_msg_fini( ctx->stake_ci );
  /* no-op */
}

static void
after_shred( ctx_t * ctx, ulong tsorig, fd_stem_context_t * stem ) {

  /* Initialize the forest, which requires the root to be ready.  This
      must be the case if we have received a frag from shred, because
      shred requires stake weights, which implies a genesis or snapshot
      slot has been loaded. */

  ulong wmark = fd_fseq_query( ctx->wmark );
  if( FD_UNLIKELY( fd_forest_root_slot( ctx->forest ) == ULONG_MAX ) ) {
    fd_forest_init( ctx->forest, wmark );
    uchar mr[ FD_SHRED_MERKLE_ROOT_SZ ] = { 0 }; /* FIXME */
    fd_fec_chainer_init( ctx->fec_chainer, wmark, mr );
    FD_TEST( fd_forest_root_slot( ctx->forest ) != ULONG_MAX );
    ctx->prev_wmark = wmark;
  }
  if( FD_UNLIKELY( ctx->prev_wmark < wmark ) ) {
    fd_forest_publish( ctx->forest, wmark );
    ctx->prev_wmark = wmark;
  }

  fd_shred_t * shred = (fd_shred_t *)fd_type_pun( ctx->frag );
  /* FIXME: This is a hack to initialize the poh_slot fseq. This
      should be removed when we use msg passing instead of fseq. */
  if( fd_fseq_query( ctx->first_turbine_slot ) == ULONG_MAX ) {
    fd_fseq_update( ctx->first_turbine_slot, shred->slot );
  }
  if( FD_UNLIKELY( shred->slot <= fd_forest_root_slot( ctx->forest ) ) ) return; /* shred too old */

  // FD_LOG_NOTICE(( "shred %lu %u", shred->slot, shred->idx ));

  /* Insert the shred sig (shared by all shred members in the FEC set)
      into the map. */

  // FD_LOG_NOTICE(( "shred %lu %u %u", shred->slot, shred->idx, shred->fec_set_idx ));

  if( FD_UNLIKELY( shred->slot > fd_fseq_query( ctx->curr_turbine_slot ) ) ) {
    fd_fseq_update( ctx->curr_turbine_slot, shred->slot );
  }

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
        fd_stem_publish( stem, REPLAY_OUT_IDX, sig, 0, 0, 0, tsorig, tspub );
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
    case IN_KIND_CONTACT:
      after_contact( ctx, sz );
      break;

    case IN_KIND_NET:
      after_net( ctx, sz );
      break;

    case IN_KIND_STAKE:
      after_stake( ctx );
      break;

    case IN_KIND_SHRED:
      after_shred( ctx, tsorig, stem );
      break;

    default:
      FD_LOG_ERR(( "after_frag: unknown in_kind %u", ctx->in_kind[in_idx] ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  fd_memset( ctx, 0, sizeof(ctx_t) );

  memcpy( ctx->identity_key, fd_keyload_load( tile->tower.identity_key_path, 1 ), sizeof(fd_pubkey_t) );
  uchar const * identity_key = fd_keyload_load( tile->repair.identity_key_path, /* pubkey only: */ 0 );
  memcpy( ctx->identity_private_key,   identity_key,                       sizeof(fd_pubkey_t) );
  memcpy( ctx->identity_public_key.uc, identity_key + sizeof(fd_pubkey_t), sizeof(fd_pubkey_t) );

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
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  ctx->tsprint  = fd_log_wallclock();
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
  FD_TEST( ctx->shred_tile_cnt == tile->repair.shred_tile_cnt );

  ctx->fec_chainer = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_chainer_align(), fd_fec_chainer_footprint( 1 << 20 )      );
  ctx->fec_sigs    = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_sig_align(),     fd_fec_sig_footprint( 20 )               );
  ctx->forest      = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(),      fd_forest_footprint( FD_FOREST_ELE_MAX ) );
  ctx->reasm       = FD_SCRATCH_ALLOC_APPEND( l, fd_reasm_align(),       fd_reasm_footprint( 20 )                 );
  ctx->stake_ci    = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),    fd_stake_ci_footprint()                  );

  ctx->fec_chainer = fd_fec_chainer_join( fd_fec_chainer_new( ctx->fec_chainer, 1 << 20, 0 ) );
  ctx->fec_sigs    = fd_fec_sig_join( fd_fec_sig_new( ctx->fec_sigs, 20 ) );
  ctx->forest      = fd_forest_join( fd_forest_new( ctx->forest, FD_FOREST_ELE_MAX, ctx->repair_seed ) );
  ctx->reasm       = fd_reasm_join( fd_reasm_new( ctx->reasm, 20 ) );
  ctx->stake_ci    = fd_stake_ci_join( fd_stake_ci_new( ctx->stake_ci , &ctx->identity_public_key ) );

  ctx->client_port = tile->repair.client_port;
  ctx->server_port = tile->repair.server_port;

  ctx->net_id = (ushort)0;

  fd_ip4_udp_hdr_init( ctx->client_hdr, FD_REPAIR_MAX_PACKET_SIZE, 0, ctx->client_port );
  fd_ip4_udp_hdr_init( ctx->server_hdr,  FD_REPAIR_MAX_PACKET_SIZE, 0, ctx->server_port );

  /* Keyguard setup */
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_link_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_link_out_idx ] ];
  if( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client, sign_out->mcache, sign_out->dcache, sign_in->mcache, sign_in->dcache ) ) == NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

  /* Repair set up */


  /**********************************************************************/
  /* turbine_slot fseq                                                  */
  /**********************************************************************/

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

  /* TODO: this is a hack to set the first turbine slot so that replay
     knows when we have caught up to a slot >= where we last voted. It
    is assumed turbine has proceeded past the slot from which validator
    stopped replaying and therefore also stopped voting (crashed,
    shutdown, etc.). This is important for voting, because you need have
    "read-back" your latest landed tower before you can vote. Using an
    fseq is a temporary hack, and this will be replaced with the standard
    frag-signaling pattern across tiles with a separate consensus tile. */
  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ctx->first_turbine_slot = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );

  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_start( ctx->repair );
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
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
