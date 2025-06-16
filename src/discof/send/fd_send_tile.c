/* Send tile signs and sends transactions to the current leader.
   Currently only supports transactions which require one signature.
   Designed with voting as primary use case. Signing those votes will
   eventually move to a separate consensus tile.*/
#define _GNU_SOURCE

#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"
#include "generated/fd_send_tile_seccomp.h"

#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../disco/shred/fd_stake_ci.h"

#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../flamenco/gossip/fd_gossip.h"

#include "../../choreo/fd_choreo.h"

#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../util/net/fd_net_headers.h"

#define IN_KIND_GOSSIP (0)
#define IN_KIND_STAKE  (1)
#define IN_KIND_TOWER  (2)

struct fd_send_link_in {
  fd_wksp_t *  mem;
  ulong        chunk0;
  ulong        wmark;
  ulong        kind;
};
typedef struct fd_send_link_in fd_send_link_in_t;

struct fd_send_link_out {
  ulong            idx;
  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};
typedef struct fd_send_link_out fd_send_link_out_t;

struct fd_send_tile_ctx {
  fd_pubkey_t identity_key[ 1 ];
  fd_pubkey_t vote_acct_addr[ 1 ];

  fd_stake_ci_t * stake_ci;
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  uchar txn_buf[ sizeof(fd_txn_p_t) ] __attribute__((aligned(alignof(fd_txn_p_t))));

  fd_gossip_peer_addr_t tpu_serve_addr;
  fd_ip4_udp_hdrs_t     packet_hdr[1];
  ushort                net_id;

  #define FD_SEND_MAX_IN_LINK_CNT 32UL
  fd_send_link_in_t in_links[ FD_SEND_MAX_IN_LINK_CNT ];

  fd_send_link_out_t gossip_verify_out[1];
  fd_send_link_out_t net_out         [1];

  ulong                sign_out_idx;
  fd_keyguard_client_t keyguard_client[ 1 ];

  struct {

    /* Transaction metrics          */
    ulong txns_sent_to_leader;      /* Successfully sent to leader                   */

    /* Leader metrics                 */
    ulong leader_sched_not_found;     /* Number of times leader schedule not found     */
    ulong leader_not_found;           /* Number of times slot leader not found         */
    ulong leader_contact_not_found;   /* Number of times leader contact not found      */
    ulong leader_contact_nonroutable; /* Number of times leader contact is nonroutable */

  } metrics;

};
typedef struct fd_send_tile_ctx fd_send_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
send_packet( fd_send_tile_ctx_t  *  ctx,
             fd_stem_context_t   *  stem,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uchar const         *  payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {
  fd_send_link_out_t * net_out_link = ctx->net_out;
  uchar * packet = fd_chunk_to_laddr( net_out_link->mem, net_out_link->chunk );

  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *ctx->packet_hdr;

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr  = dst_ip_addr;
  ip4->net_id = fd_ushort_bswap( ctx->net_id++ );
  ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  ip4->check  = fd_ip4_hdr_check_fast( ip4 );

  fd_udp_hdr_t * udp = hdr->udp;
  udp->net_dport = fd_ushort_bswap( dst_port );
  udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );
  udp->check     = 0U; /* indicates no checksum */

  ulong tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig       = fd_disco_netmux_sig( dst_ip_addr, dst_port, dst_ip_addr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);
  fd_stem_publish( stem, net_out_link->idx, sig, net_out_link->chunk, packet_sz, 0UL, tsorig, tspub );
  net_out_link->chunk = fd_dcache_compact_next( net_out_link->chunk, packet_sz, net_out_link->chunk0, net_out_link->wmark );
}


static int
get_current_leader_tpu_vote_contact( fd_send_tile_ctx_t        * ctx,
                                     ulong                       poh_slot,
                                     fd_shred_dest_weighted_t ** out_dest ) {

  fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, poh_slot );
  if( FD_UNLIKELY( !lsched      ) ) {
    ctx->metrics.leader_sched_not_found++;
    return -1;
  }

  fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, poh_slot );
  if( FD_UNLIKELY( !slot_leader ) ) {
    ctx->metrics.leader_not_found++;
    return -1;
  }

  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, poh_slot );
  fd_shred_dest_idx_t sdest_idx = fd_shred_dest_pubkey_to_idx( sdest, slot_leader );
  if( FD_UNLIKELY( sdest_idx==FD_SHRED_DEST_NO_DEST ) ) {
    ctx->metrics.leader_contact_not_found++;
    return -1;
  }

  *out_dest = fd_shred_dest_idx_to_dest( sdest, sdest_idx );

  if( FD_UNLIKELY( (*out_dest)->ip4==0 || (*out_dest)->port==0 ) ) {
    ctx->metrics.leader_contact_nonroutable++;
    return -1;
  }

  return 0;
}

static inline void
handle_new_cluster_contact_info( fd_send_tile_ctx_t *  ctx,
                                 uchar const *         buf,
                                 ulong                 buf_sz ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = buf_sz / sizeof(fd_shred_dest_wire_t);

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
finalize_new_cluster_contact_info( fd_send_tile_ctx_t * ctx ) {
  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static void
during_frag( fd_send_tile_ctx_t   * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {

  fd_send_link_in_t * in_link = &ctx->in_links[ in_idx ];
  if( FD_UNLIKELY( chunk<in_link->chunk0 || chunk>in_link->wmark ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu] on link %lu", chunk, sz, in_link->chunk0, in_link->wmark, in_idx ));
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( in_link->mem, chunk );
  ulong         kind         = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_STAKE ) ) {
    if( sz>sizeof(fd_stake_weight_t)*(MAX_SHRED_DESTS+1UL) ) {
      FD_LOG_ERR(( "sz %lu >= max expected stake update size %lu", sz, sizeof(fd_stake_weight_t) * (MAX_SHRED_DESTS+1UL) ));
    }
    fd_stake_ci_stake_msg_init( ctx->stake_ci, fd_type_pun_const( dcache_entry ) );
  }

  if( FD_UNLIKELY( kind==IN_KIND_GOSSIP ) ) {
    if( sz>sizeof(fd_shred_dest_wire_t)*MAX_SHRED_DESTS ) {
      FD_LOG_ERR(( "sz %lu >= max expected gossip update size %lu", sz, sizeof(fd_shred_dest_wire_t) * MAX_SHRED_DESTS ));
    }
    handle_new_cluster_contact_info( ctx, dcache_entry, sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_TOWER ) ) {
    if( sz!=sizeof(fd_txn_p_t) ) {
      FD_LOG_ERR(( "sz %lu != expected txn size %lu", sz, sizeof(fd_txn_p_t) ));
    }
    memcpy( ctx->txn_buf, dcache_entry, sz );
  }
}

static void
after_frag( fd_send_tile_ctx_t   * ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig,
            ulong                  tspub,
            fd_stem_context_t    * stem ) {
  (void)seq;
  (void)sig;
  (void)sz;
  (void)tsorig;
  (void)tspub;
  (void)stem;
  fd_send_link_in_t * in_link  = &ctx->in_links[ in_idx ];
  ulong                kind    = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_GOSSIP ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  if( FD_UNLIKELY( kind==IN_KIND_STAKE ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( kind==IN_KIND_TOWER ) ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)fd_type_pun(ctx->txn_buf);

    /* sign the txn */
    uchar * signature = txn->payload + TXN(txn)->signature_off;
    uchar * message   = txn->payload + TXN(txn)->message_off;
    ulong message_sz  = txn->payload_sz - TXN(txn)->message_off;
    fd_keyguard_client_sign( ctx->keyguard_client, signature, message, message_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

    /* send to leader */
    fd_shred_dest_weighted_t * leader_dest = NULL;
    int res = get_current_leader_tpu_vote_contact( ctx, sig + 1, &leader_dest ); /* FIXME send to next few leaders */
    if( res==0 ) {
      send_packet( ctx, stem, leader_dest->ip4, leader_dest->port, txn->payload, txn->payload_sz, 0UL );
      ctx->metrics.txns_sent_to_leader++;
    }

    /* send to gossip and dedup */
    fd_send_link_out_t * gossip_verify_out = ctx->gossip_verify_out;
    uchar * msg_to_gossip = fd_chunk_to_laddr( gossip_verify_out->mem, gossip_verify_out->chunk );
    fd_memcpy( msg_to_gossip, txn->payload, txn->payload_sz );
    fd_stem_publish( stem, gossip_verify_out->idx, 1UL, gossip_verify_out->chunk, txn->payload_sz, 0UL, 0, 0 );
    gossip_verify_out->chunk = fd_dcache_compact_next( gossip_verify_out->chunk, txn->payload_sz, gossip_verify_out->chunk0,
        gossip_verify_out->wmark );
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_send_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->send.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->send.identity_key_path, /* pubkey only: */ 1 ) );
}

static void
setup_input_link( fd_send_tile_ctx_t  * ctx,
                  fd_topo_t           * topo,
                  fd_topo_tile_t      * tile,
                  ulong                 kind,
                  const char          * name ) {
  ulong in_idx = fd_topo_find_tile_in_link( topo, tile, name, 0 );
  FD_TEST( in_idx!=ULONG_MAX );
  fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ in_idx ] ];
  fd_send_link_in_t * in_link_desc = &ctx->in_links[ in_idx ];
  in_link_desc->mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
  in_link_desc->chunk0 = fd_dcache_compact_chunk0( in_link_desc->mem, in_link->dcache );
  in_link_desc->wmark  = fd_dcache_compact_wmark( in_link_desc->mem, in_link->dcache, in_link->mtu );
  in_link_desc->kind   = kind;
}

static void
setup_output_link( fd_send_link_out_t  * desc,
                   fd_topo_t           * topo,
                   fd_topo_tile_t      * tile,
                   const char          * name ) {
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, name, 0 );
  FD_TEST( out_idx!=ULONG_MAX );
  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ out_idx ] ];
  desc->idx    = out_idx;
  desc->mcache = out_link->mcache;
  desc->sync   = fd_mcache_seq_laddr( desc->mcache );
  desc->depth  = fd_mcache_depth( desc->mcache );
  desc->mem    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  desc->chunk0 = fd_dcache_compact_chunk0( desc->mem, out_link->dcache );
  desc->wmark  = fd_dcache_compact_wmark( desc->mem, out_link->dcache, out_link->mtu );
  desc->chunk  = desc->chunk0;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( !tile->out_cnt ) ) FD_LOG_ERR(( "send has no primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_send_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() ), ctx->identity_key ) );

  ctx->net_id   = (ushort)0;

  ctx->tpu_serve_addr.addr = tile->send.ip_addr;
  ctx->tpu_serve_addr.port = tile->send.tpu_listen_port;
  fd_ip4_udp_hdr_init( ctx->packet_hdr, FD_TXN_MTU, ctx->tpu_serve_addr.addr, ctx->tpu_serve_addr.port );

  setup_input_link( ctx, topo, tile, IN_KIND_GOSSIP, "gossip_send" );
  setup_input_link( ctx, topo, tile, IN_KIND_STAKE,  "stake_out" );
  setup_input_link( ctx, topo, tile, IN_KIND_TOWER, "tower_send" );

  setup_output_link( ctx->gossip_verify_out, topo, tile, "send_txns" );
  setup_output_link( ctx->net_out,           topo, tile, "send_net"  );

  /* Set up keyguard(s) */

  ulong                sign_in_idx         = fd_topo_find_tile_in_link( topo, tile, "sign_send", 0 );
  fd_topo_link_t     * sign_in             = &topo->links[ tile->in_link_id[ sign_in_idx ] ];

  ctx->sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "send_sign", 0 );
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ ctx->sign_out_idx ] ];

  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) )==NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

  /* init metrics */
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
}


static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_send_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_send_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

static void
metrics_write( fd_send_tile_ctx_t * ctx ) {
  /* Transaction metrics */
  FD_MCNT_SET( SEND, TXNS_SENT_TO_LEADER,   ctx->metrics.txns_sent_to_leader );

  /* Leader metrics */
  FD_MCNT_SET( SEND, LEADER_SCHED_NOT_FOUND,     ctx->metrics.leader_sched_not_found );
  FD_MCNT_SET( SEND, LEADER_NOT_FOUND,           ctx->metrics.leader_not_found );
  FD_MCNT_SET( SEND, LEADER_CONTACT_NOT_FOUND,   ctx->metrics.leader_contact_not_found );
  FD_MCNT_SET( SEND, LEADER_CONTACT_NONROUTABLE, ctx->metrics.leader_contact_nonroutable );
}


#define STEM_BURST (3UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_send_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_send_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_send = {
  .name                     = "send",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
