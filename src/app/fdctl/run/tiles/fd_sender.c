/* Sender tile signs and sends transactions to the current leader. Currently
   only supports transactions which require one signature. */

#define _GNU_SOURCE

#include "../../../../disco/tiles.h"

#include "generated/sender_seccomp.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../util/fd_util.h"
#include "../../../../choreo/fd_choreo.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/store/fd_store.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/keyguard/fd_keyguard.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/runtime/fd_runtime.h"
#include "../../../../disco/fd_disco.h"

#include "../../../../util/net/fd_net_headers.h"

#define SCRATCH_MAX    (4UL /*KiB*/ << 10)
#define SCRATCH_DEPTH  (4UL) /* 4 scratch frames */

struct fd_sender_tile_ctx {
  fd_pubkey_t identity_key[ 1 ];
  fd_pubkey_t vote_acct_addr[ 1 ];

  fd_stake_ci_t * stake_ci;
  ulong *         poh_slot;
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  uchar txn_buf[ sizeof(fd_txn_p_t) ] __attribute__((aligned(alignof(fd_txn_p_t))));

  fd_gossip_peer_addr_t tpu_serve_addr;
  fd_net_hdrs_t         packet_hdr[ 1 ];
  uchar                 src_mac_addr[6];
  ushort                net_id;

  ulong       stake_in_idx;
  fd_wksp_t * stake_in_mem;
  ulong       stake_in_chunk0;
  ulong       stake_in_wmark;

  ulong       contact_in_idx;
  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

  ulong       replay_in_idx;
  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  ulong       poh_in_idx;
  fd_wksp_t * poh_in_mem;
  ulong       poh_in_chunk0;
  ulong       poh_in_wmark;

  ulong            gossip_out_idx;
  fd_frag_meta_t * gossip_out_mcache;
  ulong *          gossip_out_sync;
  ulong            gossip_out_depth;
  ulong            gossip_out_seq;

  fd_wksp_t * gossip_out_mem;
  ulong       gossip_out_chunk0;
  ulong       gossip_out_wmark;
  ulong       gossip_out_chunk;

  ulong            dedup_out_idx;
  fd_frag_meta_t * dedup_out_mcache;
  ulong *          dedup_out_sync;
  ulong            dedup_out_depth;
  ulong            dedup_out_seq;

  fd_wksp_t * dedup_out_mem;
  ulong       dedup_out_chunk0;
  ulong       dedup_out_wmark;
  ulong       dedup_out_chunk;

  ulong            net_out_idx;
  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  ulong                sign_in_idx;
  ulong                sign_out_idx;
  fd_keyguard_client_t keyguard_client[ 1 ];

};
typedef struct fd_sender_tile_ctx fd_sender_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 0UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sender_tile_ctx_t), sizeof(fd_sender_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_sender_tile_ctx_t) );
}

static void
send_packet( fd_sender_tile_ctx_t * ctx,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uchar const *          payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  fd_memcpy( packet, ctx->packet_hdr, sizeof(fd_net_hdrs_t) );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *)packet;

  hdr->udp->net_dport = fd_ushort_bswap( dst_port );

  memset( hdr->eth->dst, 0U, 6UL );
  memcpy( hdr->ip4->daddr_c, &dst_ip_addr, 4UL );
  hdr->ip4->net_id = fd_ushort_bswap( ctx->net_id++ );
  hdr->ip4->check  = 0U;
  hdr->ip4->net_tot_len  = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  hdr->ip4->check  = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4 ) );

  ulong packet_sz = payload_sz + sizeof(fd_net_hdrs_t);
  fd_memcpy( packet+sizeof(fd_net_hdrs_t), payload, payload_sz );
  hdr->udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  hdr->udp->check = fd_ip4_udp_check( *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->saddr_c ),
                                      *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->daddr_c ),
                                      (fd_udp_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->udp ),
                                      packet + sizeof(fd_net_hdrs_t) );

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = fd_disco_netmux_sig( 0U, 0U, dst_ip_addr, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
  fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static int
get_current_leader_tpu_vote_contact( fd_sender_tile_ctx_t *      ctx,
                                     fd_shred_dest_weighted_t ** out_dest ) {
  ulong poh_slot = fd_fseq_query( ctx->poh_slot );
  if( poh_slot==ULONG_MAX ) { return -1; }

  fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, poh_slot );
  if( FD_UNLIKELY( !lsched      ) ) { return -1; }

  fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, poh_slot );
  if( FD_UNLIKELY( !slot_leader ) ) { return -1 ; } /* Count this as bad slot too */

  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, poh_slot );
  fd_shred_dest_idx_t sdest_idx = fd_shred_dest_pubkey_to_idx( sdest, slot_leader );
  if( FD_UNLIKELY( sdest_idx==FD_SHRED_DEST_NO_DEST ) ) {
    return -1;
  }

  *out_dest = fd_shred_dest_idx_to_dest( sdest, sdest_idx );

  return 0;
}

static inline void
handle_new_cluster_contact_info( fd_sender_tile_ctx_t * ctx,
                                 uchar const *         buf,
                                 ulong                 buf_sz ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = buf_sz;

  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_SHRED_DESTS ));

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header );
  fd_shred_dest_weighted_t * dests = fd_stake_ci_dest_add_init( ctx->stake_ci );

  ctx->new_dest_ptr = dests;
  ctx->new_dest_cnt = dest_cnt;

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    memcpy( dests[i].pubkey.uc, in_dests[i].pubkey, 32UL );
    dests[i].ip4  = in_dests[i].ip4_addr;
    dests[i].port = in_dests[i].udp_port;
  }
}

static inline void
finalize_new_cluster_contact_info( fd_sender_tile_ctx_t * ctx ) {
  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static void
after_credit( void *             _ctx,
	            fd_mux_context_t * mux_ctx FD_PARAM_UNUSED,
              int *              opt_poll_in FD_PARAM_UNUSED ) {
  fd_sender_tile_ctx_t * ctx = (fd_sender_tile_ctx_t *)_ctx;
  (void)ctx;

  /* TODO: compute some metrics here */
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq        FD_PARAM_UNUSED,
             ulong  sig        FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter FD_PARAM_UNUSED ) {
  fd_sender_tile_ctx_t * ctx = (fd_sender_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->sign_in_idx ) ) {
    FD_LOG_CRIT(( "signing tile send out of band fragment" ));
  }

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in_chunk0 || chunk>ctx->stake_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_in_chunk0, ctx->stake_in_wmark ));
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_in_mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
  }

  if( FD_UNLIKELY( in_idx==ctx->contact_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->contact_in_chunk0 || chunk>ctx->contact_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->contact_in_chunk0, ctx->contact_in_wmark ));
    }

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry, sz );
  }

  if( FD_UNLIKELY( in_idx==ctx->replay_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->replay_in_chunk0 || chunk>ctx->replay_in_wmark || sz!=sizeof(fd_txn_p_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->replay_in_chunk0, ctx->replay_in_wmark ));
    }

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->replay_in_mem, chunk );
    memcpy( ctx->txn_buf, dcache_entry, sz );
  }
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq          FD_PARAM_UNUSED,
            ulong *            opt_sig      FD_PARAM_UNUSED,
            ulong *            opt_chunk    FD_PARAM_UNUSED,
            ulong *            opt_sz       FD_PARAM_UNUSED,
            ulong *            opt_tsorig   FD_PARAM_UNUSED,
            int *              opt_filter   FD_PARAM_UNUSED,
            fd_mux_context_t * mux          FD_PARAM_UNUSED ) {
  fd_sender_tile_ctx_t * ctx = (fd_sender_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==ctx->contact_in_idx ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( in_idx==ctx->replay_in_idx ) ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)fd_type_pun(ctx->txn_buf);

    /* sign the txn */
    uchar * signature = txn->payload + TXN(txn)->signature_off;
    uchar * message   = txn->payload + TXN(txn)->message_off;
    ulong message_sz  = txn->payload_sz - TXN(txn)->message_off;
    fd_keyguard_client_sign( ctx->keyguard_client, signature, message, message_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

    uchar * msg_to_gossip = fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );
    memcpy( msg_to_gossip, txn->payload, txn->payload_sz );

    /* send to leader */
    fd_shred_dest_weighted_t * leader_dest = NULL;
    int res = get_current_leader_tpu_vote_contact( ctx, &leader_dest );
    /* TODO: add metrics for successful votes sent and failed votes */
    if( res==0 ) {
      send_packet( ctx, leader_dest->ip4, leader_dest->port, msg_to_gossip, txn->payload_sz, 0UL );
    }

    /* send to gossip */
    fd_mcache_publish( ctx->gossip_out_mcache, ctx->gossip_out_depth, ctx->gossip_out_seq, 1UL, ctx->gossip_out_chunk,
      txn->payload_sz, 0UL, 0, 0 );
    ctx->gossip_out_seq   = fd_seq_inc( ctx->gossip_out_seq, 1UL );
    ctx->gossip_out_chunk = fd_dcache_compact_next( ctx->gossip_out_chunk, txn->payload_sz,
                                                    ctx->gossip_out_chunk0, ctx->gossip_out_wmark );
    /* send to dedup */
    uchar * msg_to_pack = fd_chunk_to_laddr( ctx->dedup_out_mem, ctx->dedup_out_chunk );
    memcpy( msg_to_pack, msg_to_gossip, txn->payload_sz );
    fd_mcache_publish( ctx->dedup_out_mcache, ctx->dedup_out_depth, ctx->dedup_out_seq, 1UL, ctx->dedup_out_chunk,
      txn->payload_sz, 0UL, 0, 0 );
    ctx->dedup_out_seq    = fd_seq_inc( ctx->dedup_out_seq, 1UL );
    ctx->dedup_out_chunk = fd_dcache_compact_next( ctx->dedup_out_chunk, txn->payload_sz, ctx->dedup_out_chunk0,
        ctx->dedup_out_wmark );
  }
}

static void
privileged_init( fd_topo_t *      topo  FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_sender_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sender_tile_ctx_t), sizeof(fd_sender_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->sender.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->sender.identity_key_path, /* pubkey only: */ 1 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  fd_flamenco_boot( NULL, NULL );

  if( FD_UNLIKELY( tile->out_link_id_primary != ULONG_MAX ) )
    FD_LOG_ERR(( "sender has a primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_sender_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sender_tile_ctx_t), sizeof(fd_sender_tile_ctx_t) );
  // TODO: set the lo_mark_slot to the actual snapshot slot!
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() ), ctx->identity_key ) );
  void * scratch_smem        = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  void * scratch_fmem        = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );

  /* scratch space attach */
  fd_scratch_attach( scratch_smem, scratch_fmem, SCRATCH_MAX, SCRATCH_DEPTH );

  ctx->net_id = (ushort)0;
  fd_memcpy( ctx->src_mac_addr, tile->sender.src_mac_addr, 6 );

  ctx->tpu_serve_addr.addr = tile->sender.ip_addr;
  ctx->tpu_serve_addr.port = fd_ushort_bswap( tile->sender.tpu_listen_port );
  fd_net_create_packet_header_template( ctx->packet_hdr, FD_TXN_MTU, ctx->tpu_serve_addr.addr, ctx->src_mac_addr,
      ctx->tpu_serve_addr.port );

  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ctx->poh_slot = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );

  /* Set up stake input */
  ctx->stake_in_idx = fd_topo_find_tile_in_link( topo, tile, "stake_out", 0 );
  FD_TEST( ctx->stake_in_idx!=ULONG_MAX );
  fd_topo_link_t * stake_in_link = &topo->links[ tile->in_link_id[ ctx->stake_in_idx ] ];
  ctx->stake_in_mem    = topo->workspaces[ topo->objs[ stake_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_in_mem, stake_in_link->dcache );
  ctx->stake_in_wmark  = fd_dcache_compact_wmark( ctx->stake_in_mem, stake_in_link->dcache, stake_in_link->mtu );

  /* Set up contact input */
  ctx->contact_in_idx = fd_topo_find_tile_in_link( topo, tile, "gossip_voter", 0 );
  FD_TEST( ctx->contact_in_idx!=ULONG_MAX );
  fd_topo_link_t * contact_in_link = &topo->links[ tile->in_link_id[ ctx->contact_in_idx ] ];
  ctx->contact_in_mem    = topo->workspaces[ topo->objs[ contact_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark( ctx->contact_in_mem, contact_in_link->dcache, contact_in_link->mtu );

  /* Set up replay tile input */
  ctx->replay_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_voter", 0 );
  FD_TEST( ctx->replay_in_idx!=ULONG_MAX );
  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ ctx->replay_in_idx ] ];
  ctx->replay_in_mem    = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

  /* Set up repair request output */
  ctx->gossip_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_gossip", 0 );
  FD_TEST( ctx->gossip_out_idx!=ULONG_MAX );
  fd_topo_link_t * gossip_out_link = &topo->links[ tile->out_link_id[ ctx->gossip_out_idx ] ];
  ctx->gossip_out_mcache = gossip_out_link->mcache;
  ctx->gossip_out_sync   = fd_mcache_seq_laddr( ctx->gossip_out_mcache );
  ctx->gossip_out_depth  = fd_mcache_depth( ctx->gossip_out_mcache );
  ctx->gossip_out_seq    = fd_mcache_seq_query( ctx->gossip_out_sync );
  ctx->gossip_out_mem    = topo->workspaces[ topo->objs[ gossip_out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->gossip_out_chunk0 = fd_dcache_compact_chunk0( ctx->gossip_out_mem, gossip_out_link->dcache );
  ctx->gossip_out_wmark  = fd_dcache_compact_wmark ( ctx->gossip_out_mem, gossip_out_link->dcache, gossip_out_link->mtu );
  ctx->gossip_out_chunk  = ctx->gossip_out_chunk0;

  /* Set up dedup output */
  ctx->dedup_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_dedup", 0 );
  FD_TEST( ctx->dedup_out_idx!=ULONG_MAX );
  fd_topo_link_t * dedup_out_link = &topo->links[ tile->out_link_id[ ctx->dedup_out_idx ] ];
  ctx->dedup_out_mcache = dedup_out_link->mcache;
  ctx->dedup_out_sync   = fd_mcache_seq_laddr( ctx->dedup_out_mcache );
  ctx->dedup_out_depth  = fd_mcache_depth( ctx->dedup_out_mcache );
  ctx->dedup_out_seq    = fd_mcache_seq_query( ctx->dedup_out_sync );
  ctx->dedup_out_mem    = topo->workspaces[ topo->objs[ dedup_out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->dedup_out_chunk0 = fd_dcache_compact_chunk0( ctx->dedup_out_mem, dedup_out_link->dcache );
  ctx->dedup_out_wmark  = fd_dcache_compact_wmark ( ctx->dedup_out_mem, dedup_out_link->dcache, dedup_out_link->mtu );
  ctx->dedup_out_chunk  = ctx->dedup_out_chunk0;

  /* Set up net output */
  ctx->net_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_net", 0 );
  FD_TEST( ctx->net_out_idx!=ULONG_MAX );
  fd_topo_link_t * net_out_link = &topo->links[ tile->out_link_id[ ctx->net_out_idx ] ];
  ctx->net_out_mcache = net_out_link->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out_link->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out_link->dcache, net_out_link->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;


  /* Set up keyguard(s) */
  ctx->sign_in_idx  = fd_topo_find_tile_in_link( topo, tile, "sign_voter", 0 );
  ctx->sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "voter_sign", 0 );
  FD_TEST( ctx->sign_in_idx==( tile->in_cnt-1 ) );

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id[ ctx->sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->sign_out_idx ] ];

  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) )==NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
}


static ulong
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_sender( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_sender_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch     FD_PARAM_UNUSED,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_sender = {
  .name                     = "sender",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
