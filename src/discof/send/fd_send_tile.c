#include "fd_send_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "generated/fd_send_tile_seccomp.h"

#include <errno.h>
#include <sys/random.h>

/* map leader pubkey to contact info
   a peer entry can be in 3 states:
   - UNSTAKED: no element in map
   - NO_CI: pubkey maps to CI
   - CI: pubkey maps to CI

The state machine works as follows:

receive stake msg including pubkey:
  - if UNSTAKED, create new entry in NO_CI state

receive contact info:
  - Update contact info. NO_CI -> CI.
*/

#define MAP_NAME               fd_send_conn_map
#define MAP_T                  fd_send_conn_entry_t
#define MAP_LG_SLOT_CNT        17
#define MAP_KEY                pubkey
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(key)      ((key).ui[3])
#include "../../util/tmpl/fd_map.c"

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( 128UL, fd_send_conn_map_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_send_conn_map_align(), fd_send_conn_map_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
send_udp( fd_send_tile_ctx_t  *  ctx,
          fd_pubkey_t const   *  pubkey,
          uchar const         *  payload,
          ulong                  payload_sz ) {

  fd_send_conn_entry_t * entry = fd_send_conn_map_query( ctx->conn_map, *pubkey, NULL );
  FD_TEST( entry );
  if( entry->ip4_addr == 0 || entry->udp_port == 0 ) {
    ctx->metrics.send_result_cnt[FD_METRICS_ENUM_TXN_SEND_RESULT_V_MISSING_C_I_IDX]++;
    FD_LOG_WARNING(( "send_tile: Skipping unroutable pubkey %s", FD_BASE58_ENC_32_ALLOCA( pubkey->key )));
    return;
  }

  uint   const dst_ip   = entry->ip4_addr;
  ushort const dst_port = entry->udp_port;

  fd_send_link_out_t * net_out_link = ctx->net_out;
  fd_ip4_udp_hdrs_t * hdrs = fd_chunk_to_laddr( net_out_link->mem, net_out_link->chunk );
  fd_memset( hdrs, 0, sizeof(fd_ip4_udp_hdrs_t) );
  hdrs->eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

  hdrs->ip4->verihl = FD_IP4_VERIHL(4,5);
  hdrs->ip4->tos = (uchar)(0); /* FIXME: set this? */
  hdrs->ip4->net_tot_len = (ushort)( 20 + 8 + payload_sz );
  hdrs->ip4->net_id = 0; /* FIXME: set this? */
  hdrs->ip4->net_frag_off = 0x4000u;
  hdrs->ip4->ttl = 64;
  hdrs->ip4->protocol = FD_IP4_HDR_PROTOCOL_UDP;
  hdrs->ip4->check  = 0;
  hdrs->ip4->saddr  = ctx->src_ip_addr;
  hdrs->ip4->daddr  = dst_ip;

  hdrs->udp->net_sport = ctx->src_port;
  hdrs->udp->net_dport = dst_port;
  hdrs->udp->net_len = (ushort)( 8 + payload_sz );
  hdrs->udp->check = 0;

  uchar * packet_l5 = fd_type_pun( hdrs+1 );
  fd_memcpy( packet_l5, payload, payload_sz );

  ulong const tot_sz = sizeof(fd_ip4_udp_hdrs_t) + payload_sz;

  ulong sig = fd_disco_netmux_sig( dst_ip, 0U, dst_ip, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
  ulong tspub = (ulong)ctx->now;
  fd_stem_publish( ctx->stem, net_out_link->idx, sig, net_out_link->chunk, tot_sz, 0UL, 0, tspub );
  net_out_link->chunk = fd_dcache_compact_next( net_out_link->chunk, tot_sz, net_out_link->chunk0, net_out_link->wmark );

  ctx->metrics.send_result_cnt[FD_METRICS_ENUM_TXN_SEND_RESULT_V_SUCCESS_IDX]++;
}


/* handle_new_contact_info handles a new contact. Validates contact info
   and starts/restarts a connection if necessary. */
static inline void
handle_new_contact_info( fd_send_tile_ctx_t   * ctx,
                         fd_shred_dest_wire_t * contact ) {
  uint    new_ip   = contact->ip4_addr;
  ushort  new_port = contact->udp_port;
  if( FD_UNLIKELY( new_ip==0 || new_port==0 ) ) {
    ctx->metrics.new_contact_info[FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_V_UNROUTABLE_IDX]++;
    return;
  }

  fd_send_conn_entry_t * entry  = fd_send_conn_map_query( ctx->conn_map, *contact->pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) {
    /* Skip if UNSTAKED */
    FD_LOG_DEBUG(("send_tile: Skipping unstaked pubkey %s at %u.%u.%u.%u:%u", FD_BASE58_ENC_32_ALLOCA( contact->pubkey->key ), new_ip&0xFF, (new_ip>>8)&0xFF, (new_ip>>16)&0xFF, (new_ip>>24)&0xFF, new_port));
    ctx->metrics.new_contact_info[FD_METRICS_ENUM_NEW_CONTACT_OUTCOME_V_UNSTAKED_IDX]++;
    return;
  }

  entry->ip4_addr  = new_ip;
  entry->udp_port  = new_port;
}

static inline void
finalize_new_cluster_contact_info( fd_send_tile_ctx_t * ctx ) {
  for( ulong i=0UL; i<ctx->contact_cnt; i++ ) {
    handle_new_contact_info( ctx, &ctx->contact_buf[i] );
  }
}

/* Called during after_frag for stake messages. */
static void
finalize_stake_msg( fd_send_tile_ctx_t * ctx ) {

  fd_multi_epoch_leaders_stake_msg_fini( ctx->mleaders );

  /* Get the current stake destinations */
  fd_vote_stake_weight_t const * stakes = fd_multi_epoch_leaders_get_stake_weights( ctx->mleaders );
  ulong                       stake_cnt = fd_multi_epoch_leaders_get_stake_cnt( ctx->mleaders );
  if( FD_UNLIKELY( !stakes ) ) {
    FD_LOG_WARNING(( "No stake destinations available for current slot" ));
    return;
  }

  /* populate staked validators in connection map */
  for( ulong i=0UL; i<stake_cnt; i++ ) {
    fd_vote_stake_weight_t const * stake_info = &stakes[i];
    fd_pubkey_t            const   pubkey     = stake_info->id_key;

    fd_send_conn_entry_t * entry = fd_send_conn_map_query( ctx->conn_map, pubkey, NULL );
    /* UNSTAKED -> staked: create new entry in CI state */
    if( FD_UNLIKELY( !entry ) ) {
      FD_LOG_DEBUG(("send_tile: creating new entry for pubkey %s", FD_BASE58_ENC_32_ALLOCA( pubkey.key )));
      entry = fd_send_conn_map_insert( ctx->conn_map, pubkey );
    }
  }
}

/* Stem callbacks */

static inline void
before_credit( fd_send_tile_ctx_t * ctx,
               fd_stem_context_t  * stem,
               int *                charge_busy FD_PARAM_UNUSED) {
  ctx->stem = stem;

  ctx->now = fd_tickcount();
}

static void
during_frag( fd_send_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED) {

  fd_send_link_in_t * in_link = &ctx->in_links[ in_idx ];
  if( FD_UNLIKELY( chunk<in_link->chunk0 || chunk>in_link->wmark ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu] on link %lu", chunk, sz, in_link->chunk0, in_link->wmark, in_idx ));
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( in_link->mem, chunk );
  ulong         kind         = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_STAKE ) ) {
    if( sz>sizeof(fd_stake_weight_t)*(MAX_STAKED_LEADERS+1UL) ) {
      FD_LOG_ERR(( "sz %lu >= max expected stake update size %lu", sz, sizeof(fd_stake_weight_t) * (MAX_STAKED_LEADERS+1UL) ));
    }
    fd_multi_epoch_leaders_stake_msg_init( ctx->mleaders, fd_type_pun_const( dcache_entry ) );
  }

  if( FD_UNLIKELY( kind==IN_KIND_GOSSIP ) ) {
    if( sz>sizeof(fd_shred_dest_wire_t)*MAX_STAKED_LEADERS ) {
      FD_LOG_ERR(( "sz %lu >= max expected gossip update size %lu", sz, sizeof(fd_shred_dest_wire_t) * MAX_STAKED_LEADERS ));
    }
    ctx->contact_cnt = sz / sizeof(fd_shred_dest_wire_t);
    fd_memcpy( ctx->contact_buf, dcache_entry, sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_TOWER ) ) {
    if( sz!=sizeof(fd_txn_p_t) ) {
      FD_LOG_ERR(( "sz %lu != expected txn size %lu", sz, sizeof(fd_txn_p_t) ));
    }
    fd_memcpy( ctx->txn_buf, dcache_entry, sz );
  }
}

static void
after_frag( fd_send_tile_ctx_t * ctx,
            ulong                in_idx,
            ulong                seq FD_PARAM_UNUSED,
            ulong                sig,
            ulong                sz FD_PARAM_UNUSED,
            ulong                tsorig FD_PARAM_UNUSED,
            ulong                tspub FD_PARAM_UNUSED,
            fd_stem_context_t *  stem ) {

  ctx->stem = stem;

  fd_send_link_in_t * in_link = &ctx->in_links[ in_idx ];
  ulong                 kind  = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_TOWER ) ) {

    fd_txn_p_t * txn = (fd_txn_p_t *)fd_type_pun(ctx->txn_buf);

    /* sign the txn */
    uchar * signature = txn->payload + TXN(txn)->signature_off;
    uchar * message   = txn->payload + TXN(txn)->message_off;
    ulong message_sz  = txn->payload_sz - TXN(txn)->message_off;
    fd_keyguard_client_sign( ctx->keyguard_client, signature, message, message_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

    ulong poh_slot = sig;

    /* send to leader for next few slots */
    for( ulong i=0UL; i<SEND_TO_LEADER_CNT; i++ ) {
      fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, poh_slot );
      if( FD_LIKELY( leader ) ) {
        send_udp( ctx, leader, txn->payload, txn->payload_sz );
      } else {
        ctx->metrics.leader_not_found++;
        FD_LOG_DEBUG(("send_tile: Failed to get leader contact"));
      }
    }

    /* send to gossip and dedup */
    fd_send_link_out_t * gossip_verify_out = ctx->gossip_verify_out;
    uchar * msg_to_gossip = fd_chunk_to_laddr( gossip_verify_out->mem, gossip_verify_out->chunk );
    fd_memcpy( msg_to_gossip, txn->payload, txn->payload_sz );
    fd_stem_publish( stem, gossip_verify_out->idx, 1UL, gossip_verify_out->chunk, txn->payload_sz, 0UL, 0, 0 );
    gossip_verify_out->chunk = fd_dcache_compact_next( gossip_verify_out->chunk, txn->payload_sz, gossip_verify_out->chunk0,
        gossip_verify_out->wmark );
  }

  if( FD_UNLIKELY( kind==IN_KIND_GOSSIP ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  if( FD_UNLIKELY( kind==IN_KIND_STAKE ) ) {
    finalize_stake_msg( ctx );
    return;
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_send_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_send_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->send.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)(fd_keyload_load( tile->send.identity_key_path, /* pubkey only: */ 1 ) );
  FD_LOG_NOTICE(( "identity_key: %s", FD_BASE58_ENC_32_ALLOCA( ctx->identity_key[ 0 ].key ) ));
}

static fd_send_link_in_t *
setup_input_link( fd_send_tile_ctx_t * ctx,
                  fd_topo_t          * topo,
                  fd_topo_tile_t     * tile,
                  ulong                kind,
                  const char         * name ) {
  ulong in_idx = fd_topo_find_tile_in_link( topo, tile, name, 0 );
  FD_TEST( in_idx!=ULONG_MAX );
  fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ in_idx ] ];
  fd_send_link_in_t * in_link_desc = &ctx->in_links[ in_idx ];
  in_link_desc->mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
  in_link_desc->chunk0 = fd_dcache_compact_chunk0( in_link_desc->mem, in_link->dcache );
  in_link_desc->wmark  = fd_dcache_compact_wmark( in_link_desc->mem, in_link->dcache, in_link->mtu );
  in_link_desc->dcache = in_link->dcache;
  in_link_desc->kind   = kind;
  return in_link_desc;
}

static void
setup_output_link( fd_send_link_out_t * desc,
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

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  /* Initialize connection map */
  void * conn_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_send_conn_map_align(), fd_send_conn_map_footprint() );
  ctx->conn_map = fd_send_conn_map_join( fd_send_conn_map_new( conn_map_mem ) );
  if( FD_UNLIKELY( !ctx->conn_map ) ) FD_LOG_ERR(( "fd_send_conn_map_join failed" ));

  ctx->src_ip_addr = tile->send.ip_addr;
  ctx->src_port    = tile->send.send_src_port;
  fd_ip4_udp_hdr_init( ctx->packet_hdr, FD_TXN_MTU, ctx->src_ip_addr, ctx->src_port );

  setup_input_link( ctx, topo, tile, IN_KIND_GOSSIP, "gossip_send" );
  setup_input_link( ctx, topo, tile, IN_KIND_STAKE,  "stake_out"   );
  setup_input_link( ctx, topo, tile, IN_KIND_TOWER,  "tower_send"  );

  fd_send_link_in_t * net_in = setup_input_link( ctx, topo, tile, IN_KIND_NET, "net_send" );
  fd_net_rx_bounds_init( &ctx->net_in_bounds, net_in->dcache );

  setup_output_link( ctx->gossip_verify_out, topo, tile, "send_txns" );
  setup_output_link( ctx->net_out,           topo, tile, "send_net"  );

  /* Set up keyguard(s) */
  ulong             sign_in_idx  =  fd_topo_find_tile_in_link(  topo, tile, "sign_send", 0 );
  ulong             sign_out_idx =  fd_topo_find_tile_out_link( topo, tile, "send_sign", 0 );
  fd_topo_link_t  * sign_in      =  &topo->links[ tile->in_link_id[  sign_in_idx  ] ];
  fd_topo_link_t  * sign_out     =  &topo->links[ tile->out_link_id[ sign_out_idx ] ];

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
populate_allowed_seccomp( fd_topo_t      const * topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter   * out ) {

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

  FD_MCNT_SET( SEND, LEADER_NOT_FOUND,        ctx->metrics.leader_not_found        );

  FD_MCNT_ENUM_COPY( SEND, NEW_CONTACT_INFO, ctx->metrics.new_contact_info );
  FD_MCNT_ENUM_COPY( SEND, SEND_RESULT, ctx->metrics.send_result_cnt );
}


#define STEM_BURST                  1UL /* send_txns */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_send_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_send_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
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
