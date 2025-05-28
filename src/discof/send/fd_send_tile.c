#include "fd_send_tile.h"

#include <errno.h>
#include <sys/random.h>

/* map ip/port to quic conn */
#define MAP_NAME        fd_send_conn_map
#define MAP_T           fd_send_conn_entry_t
#define MAP_LG_SLOT_CNT 16
#include "../../util/tmpl/fd_map.c"

// Helper function to create connection key from ip+port
static inline ulong
conn_key( uint ip4, ushort port ) {
  return ((ulong)ip4 << 16) | (ulong)port;
}

static inline fd_quic_limits_t
quic_limits( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  fd_quic_limits_t limits = {
    .conn_cnt      = MAX_LEADER_CNT,
    .handshake_cnt = MAX_LEADER_CNT,

    .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_frame_cnt          = 16UL * MAX_LEADER_CNT,
    .min_inflight_frame_cnt_conn = 4UL,
    .stream_id_cnt               = 16UL,
    .tx_buf_sz                   = FD_TXN_MTU,
    .stream_pool_cnt             = 2048UL
  };
  if( FD_UNLIKELY( !fd_quic_footprint( &limits ) ) ) {
    FD_LOG_ERR(( "Invalid QUIC limits in config" ));
  }
  return limits;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( 128UL, fd_quic_align() ), fd_send_conn_map_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  fd_quic_limits_t limits = quic_limits( tile );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_send_tile_ctx_t), sizeof(fd_send_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) );
  l = FD_LAYOUT_APPEND( l, fd_send_conn_map_align(), fd_send_conn_map_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
quic_now( void * ctx FD_PARAM_UNUSED ) {
  return (ulong)fd_tickcount();
}

static void
quic_tls_cv_sign( void *      signer_ctx,
                  uchar       signature[ static 64 ],
                  uchar const payload[ static 130 ] ) {
  fd_send_tile_ctx_t * ctx = signer_ctx;
  fd_sha512_t * sha512 = fd_sha512_join( ctx->sha512 );
  fd_ed25519_sign( signature, payload, 130UL, ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
  fd_sha512_leave( sha512 );
}

static fd_quic_conn_t *
find_quic_conn( fd_send_tile_ctx_t * ctx,
                uint                 dst_ip,
                ushort               dst_port ) {
  ulong key = conn_key( dst_ip, dst_port );
  fd_send_conn_entry_t * entry = fd_send_conn_map_query( ctx->conn_map, key, NULL );
  if( FD_LIKELY( entry ) ) {
    return entry->conn;
  }
  return NULL;
}

static void
quic_connect( fd_send_tile_ctx_t * ctx,
              uint                 dst_ip,
              ushort               dst_port ) {
  ulong key = conn_key( dst_ip, dst_port );

  if( fd_send_conn_map_query( ctx->conn_map, key, NULL ) ) {
    return;
  }

  FD_LOG_NOTICE(("Creating new QUIC connection for destination %u.%u.%u.%u:%hu",
  dst_ip&0xff, (dst_ip>>8)&0xff, (dst_ip>>16)&0xff, (dst_ip>>24)&0xff, dst_port));

  // Create new connection
  fd_quic_conn_t * conn = fd_quic_connect( ctx->quic, dst_ip, dst_port, ctx->src_ip_addr, ctx->src_port );
  if( FD_LIKELY( conn ) ) {
    fd_send_conn_entry_t * entry = fd_send_conn_map_insert( ctx->conn_map, key );
    if( FD_LIKELY( entry ) ) {
      entry->conn = conn;
      ctx->metrics.quic_conns_created++;
    } else {
      // Map is full, close the connection
      fd_quic_conn_close( conn, 0UL );
    }
  }
}


static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           quic_ctx ) {
  fd_send_tile_ctx_t * ctx = quic_ctx;

  // Remove from connection map - need to iterate to find by conn pointer
  for( ulong slot_idx=0UL; slot_idx<fd_send_conn_map_slot_cnt(); slot_idx++ ) {
    fd_send_conn_entry_t * entry = &ctx->conn_map[slot_idx];
    if( !fd_send_conn_map_key_inval( entry->key ) && entry->conn == conn ) {
      fd_send_conn_map_remove( ctx->conn_map, entry );
      ctx->metrics.quic_conns_closed++;
      break;
    }
  }
}

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush ) {
  (void)flush;

  fd_send_tile_ctx_t * ctx = _ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;

    uint const ip_dst = FD_LOAD( uint, batch[ i ].buf+offsetof( fd_ip4_hdr_t, daddr_c ) );

    fd_send_link_out_t * net_out_link = ctx->net_out;
    uchar * packet_l2 = fd_chunk_to_laddr( net_out_link->mem, net_out_link->chunk );
    uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
    memset( packet_l2, 0, 12 );
    FD_STORE( ushort, packet_l2+offsetof( fd_eth_hdr_t, net_type ), fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    fd_memcpy( packet_l3, batch[ i ].buf, batch[ i ].buf_sz );
    ulong sz_l2 = sizeof(fd_eth_hdr_t) + batch[ i ].buf_sz;

    /* send packets are just round-robined by sequence number, so for now
       just indicate where they came from so they don't bounce back */
    ulong sig = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );

    ulong tspub = (ulong)fd_tickcount();

    fd_stem_publish( ctx->stem, net_out_link->idx, sig, net_out_link->chunk, sz_l2, 0UL, 0, tspub );
    net_out_link->chunk = fd_dcache_compact_next( net_out_link->chunk, sz_l2, net_out_link->chunk0, net_out_link->wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

static void
send_packet( fd_send_tile_ctx_t *  ctx,
             fd_stem_context_t   *  stem FD_PARAM_UNUSED,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uchar const         *  payload,
             ulong                  payload_sz,
             ulong                  tsorig FD_PARAM_UNUSED ) {

  fd_quic_conn_t * conn = find_quic_conn( ctx, dst_ip_addr, dst_port );
  if( FD_UNLIKELY( !conn ) ) {
    ctx->metrics.quic_conn_not_found++;
    FD_LOG_NOTICE(("Quic conn not found when trying to send to leader"));
    return;
  }

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  if( FD_UNLIKELY( !stream ) ) {
    ctx->metrics.quic_stream_unavail++;
    FD_LOG_NOTICE(("Quic stream unavailable when trying to send to leader"));
    return;
  }

  fd_quic_stream_send( stream, payload, payload_sz, 1 );
}


static int
get_current_leader_tpu_vote_contact( fd_send_tile_ctx_t *        ctx,
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

  return 0;
}

static inline void
handle_new_cluster_contact_info( fd_send_tile_ctx_t * ctx,
                                 uchar const *        buf,
                                 ulong                buf_sz ) {
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
  for( ulong i=0UL; i<ctx->new_dest_cnt; i++ ) {
    quic_connect( ctx, ctx->new_dest_ptr[i].ip4, ctx->new_dest_ptr[i].port );
  }
}

static void
during_frag( fd_send_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {

  fd_send_link_in_t * in_link = &ctx->in_links[ in_idx ];
  if( FD_UNLIKELY( chunk<in_link->chunk0 || chunk>in_link->wmark ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu] on link %lu", chunk, sz,
          in_link->chunk0, in_link->wmark, in_idx ));

  uchar const * dcache_entry = fd_chunk_to_laddr_const( in_link->mem, chunk );
  ulong         kind         = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_NET ) ) {
    void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds, chunk, ctl, sz );
    fd_memcpy( ctx->quic_buf, src, sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_REPLAY ) ) {
    if( sz!=sizeof(fd_txn_p_t) ) {
      FD_LOG_ERR(( "sz %lu != expected txn size %lu", sz, sizeof(fd_txn_p_t) ));
    }
    fd_memcpy( ctx->txn_buf, dcache_entry, sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_STAKE ) ) {
    if( sz>sizeof(fd_stake_weight_t)*(MAX_SHRED_DESTS+1UL) ) {
      FD_LOG_ERR(( "sz %lu >= max expected stake update size %lu", sz, sizeof(fd_stake_weight_t) * (MAX_SHRED_DESTS+1UL) ));
    }
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
  }

  if( FD_UNLIKELY( kind==IN_KIND_GOSSIP ) ) {
    if( sz>sizeof(fd_shred_dest_wire_t)*MAX_SHRED_DESTS ) {
      FD_LOG_ERR(( "sz %lu >= max expected gossip update size %lu", sz, sizeof(fd_shred_dest_wire_t) * MAX_SHRED_DESTS ));
    }
    handle_new_cluster_contact_info( ctx, dcache_entry, sz );
  }

}

static void
after_frag( fd_send_tile_ctx_t * ctx,
            ulong                in_idx,
            ulong                seq,
            ulong                sig,
            ulong                sz,
            ulong                tsorig,
            ulong                tspub,
            fd_stem_context_t *  stem ) {
  (void)seq;
  (void)sig;
  (void)sz;
  (void)tsorig;
  (void)tspub;

  ctx->stem = stem;

  fd_send_link_in_t * in_link = &ctx->in_links[ in_idx ];
  ulong                 kind  = in_link->kind;

  if( FD_UNLIKELY( kind==IN_KIND_NET ) ) {
    uchar * ip_pkt = ctx->quic_buf + sizeof(fd_eth_hdr_t);
    ulong   ip_sz  = sz - sizeof(fd_eth_hdr_t);
    fd_quic_process_packet( ctx->quic, ip_pkt, ip_sz );
  }

  if( FD_UNLIKELY( kind==IN_KIND_REPLAY ) ) {
    fd_txn_p_t * txn = (fd_txn_p_t *)fd_type_pun(ctx->txn_buf);

    /* sign the txn */
    uchar * signature = txn->payload + TXN(txn)->signature_off;
    uchar * message   = txn->payload + TXN(txn)->message_off;
    ulong message_sz  = txn->payload_sz - TXN(txn)->message_off;
    fd_keyguard_client_sign( ctx->keyguard_client, signature, message, message_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

    ulong poh_slot = sig;

    /* send to leader */
    fd_shred_dest_weighted_t * leader_dest = NULL;
    int res = get_current_leader_tpu_vote_contact( ctx, poh_slot, &leader_dest );
    if( res==0 ) {
      send_packet( ctx, stem, leader_dest->ip4, leader_dest->port, txn->payload, txn->payload_sz, 0UL );
      ctx->metrics.txns_sent_to_leader++;
    } else {
      FD_LOG_ERR(("Failed to get leader contact"));
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
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
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
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() ), ctx->identity_key ) );

  // Initialize QUIC
  if( FD_UNLIKELY( getrandom( ctx->tls_priv_key, ED25519_PRIV_KEY_SZ, 0 )!=ED25519_PRIV_KEY_SZ ) ) {
    FD_LOG_ERR(( "getrandom failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_sha512_t * sha512 = fd_sha512_join( fd_sha512_new( ctx->sha512 ) );
  fd_ed25519_public_from_private( ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
  fd_sha512_leave( sha512 );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
  if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  fd_quic_limits_t limits = quic_limits( tile );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) ), &limits ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_new failed" ));

  // Initialize connection map
  void * conn_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_send_conn_map_align(), fd_send_conn_map_footprint() );
  ctx->conn_map = fd_send_conn_map_join( fd_send_conn_map_new( conn_map_mem ) );
  if( FD_UNLIKELY( !ctx->conn_map ) ) FD_LOG_ERR(( "fd_send_conn_map_join failed" ));

  quic->config.role                       = FD_QUIC_ROLE_CLIENT;
  quic->config.idle_timeout               = 30UL * 1000UL * 1000UL * 1000UL; // 30 seconds
  quic->config.ack_delay                  = 25UL * 1000UL * 1000UL; // 25ms
  quic->config.initial_rx_max_stream_data = FD_TXN_MTU;
  quic->config.keep_alive                 = 1;
  fd_memcpy( quic->config.identity_public_key, ctx->tls_pub_key, ED25519_PUB_KEY_SZ );

  quic->config.sign         = quic_tls_cv_sign;
  quic->config.sign_ctx     = ctx;

  quic->cb.conn_final       = quic_conn_final;
  quic->cb.now              = quic_now;
  quic->cb.now_ctx          = ctx;
  quic->cb.quic_ctx         = ctx;

  fd_quic_set_aio_net_tx( quic, quic_tx_aio );
  fd_quic_set_clock_tickcount( quic );
  if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

  ctx->quic = quic;

  ctx->net_id   = (ushort)0;

  ctx->src_ip_addr = tile->send.ip_addr;
  ctx->src_port    = tile->send.send_src_port;
  fd_ip4_udp_hdr_init( ctx->packet_hdr, FD_TXN_MTU, ctx->src_ip_addr, ctx->src_port );

  setup_input_link( ctx, topo, tile, IN_KIND_GOSSIP, "gossip_send" );
  setup_input_link( ctx, topo, tile, IN_KIND_STAKE,  "stake_out" );
  setup_input_link( ctx, topo, tile, IN_KIND_REPLAY, "replay_send" );

  fd_send_link_in_t * net_in = setup_input_link( ctx, topo, tile, IN_KIND_NET, "net_send" );
  fd_net_rx_bounds_init( &ctx->net_in_bounds, net_in->dcache );

  setup_output_link( ctx->gossip_verify_out, topo, tile, "send_txns" );
  setup_output_link( ctx->net_out,           topo, tile, "send_net"  );

  /* Set up keyguard(s) */

  ulong                sign_in_idx         = fd_topo_find_tile_in_link( topo, tile, "sign_send", 0 );
  fd_topo_link_t     * sign_in             = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_send_link_in_t * sign_in_desc        = &ctx->in_links[ sign_in_idx ];
  /* *** */            sign_in_desc->kind  = IN_KIND_SIGN;

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

static inline void
before_credit( fd_send_tile_ctx_t * ctx,
               fd_stem_context_t  * stem,
               int *                charge_busy ) {
  ctx->stem = stem;

  /* Publishes to mcache via callbacks */
  *charge_busy = fd_quic_service( ctx->quic );
}

static void
metrics_write( fd_send_tile_ctx_t * ctx ) {
  /* Transaction metrics */
  FD_MCNT_SET( SEND, TXNS_SENT_TO_LEADER,      ctx->metrics.txns_sent_to_leader );

  /* Leader metrics */
  FD_MCNT_SET( SEND, LEADER_SCHED_NOT_FOUND,   ctx->metrics.leader_sched_not_found );
  FD_MCNT_SET( SEND, LEADER_NOT_FOUND,         ctx->metrics.leader_not_found );
  FD_MCNT_SET( SEND, LEADER_CONTACT_NOT_FOUND, ctx->metrics.leader_contact_not_found );

  /* QUIC metrics */
  FD_MCNT_SET(       SEND, RECEIVED_BYTES,         ctx->quic->metrics.net_rx_byte_cnt );
  FD_MCNT_ENUM_COPY( SEND, RECEIVED_FRAMES,        ctx->quic->metrics.frame_rx_cnt );
  FD_MCNT_SET(       SEND, RECEIVED_PACKETS,       ctx->quic->metrics.net_rx_pkt_cnt );
  FD_MCNT_SET(       SEND, STREAM_RECEIVED_BYTES,  ctx->quic->metrics.stream_rx_byte_cnt );
  FD_MCNT_SET(       SEND, STREAM_RECEIVED_EVENTS, ctx->quic->metrics.stream_rx_event_cnt );

  FD_MCNT_SET(       SEND, SENT_PACKETS,     ctx->quic->metrics.net_tx_pkt_cnt );
  FD_MCNT_SET(       SEND, SENT_BYTES,       ctx->quic->metrics.net_tx_byte_cnt );
  FD_MCNT_SET(       SEND, RETRY_SENT,       ctx->quic->metrics.retry_tx_cnt );
  FD_MCNT_ENUM_COPY( SEND, ACK_TX,           ctx->quic->metrics.ack_tx );

  FD_MGAUGE_SET( SEND, CONNECTIONS_ACTIVE,          ctx->quic->metrics.conn_active_cnt );
  FD_MCNT_SET(   SEND, CONNECTIONS_CREATED,         ctx->quic->metrics.conn_created_cnt );
  FD_MCNT_SET(   SEND, CONNECTIONS_CLOSED,          ctx->quic->metrics.conn_closed_cnt );
  FD_MCNT_SET(   SEND, CONNECTIONS_ABORTED,         ctx->quic->metrics.conn_aborted_cnt );
  FD_MCNT_SET(   SEND, CONNECTIONS_TIMED_OUT,       ctx->quic->metrics.conn_timeout_cnt );
  FD_MCNT_SET(   SEND, CONNECTIONS_RETRIED,         ctx->quic->metrics.conn_retry_cnt );
  FD_MCNT_SET(   SEND, CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt );
  FD_MCNT_SET(   SEND, CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_ENUM_COPY( SEND, PKT_CRYPTO_FAILED,       ctx->quic->metrics.pkt_decrypt_fail_cnt );
  FD_MCNT_ENUM_COPY( SEND, PKT_NO_KEY,              ctx->quic->metrics.pkt_no_key_cnt );
  FD_MCNT_SET(       SEND, PKT_NO_CONN,             ctx->quic->metrics.pkt_no_conn_cnt );
  FD_MCNT_SET(       SEND, PKT_TX_ALLOC_FAIL,       ctx->quic->metrics.pkt_tx_alloc_fail_cnt );
  FD_MCNT_SET(       SEND, PKT_NET_HEADER_INVALID,  ctx->quic->metrics.pkt_net_hdr_err_cnt );
  FD_MCNT_SET(       SEND, PKT_QUIC_HEADER_INVALID, ctx->quic->metrics.pkt_quic_hdr_err_cnt );
  FD_MCNT_SET(       SEND, PKT_UNDERSZ,             ctx->quic->metrics.pkt_undersz_cnt );
  FD_MCNT_SET(       SEND, PKT_OVERSZ,              ctx->quic->metrics.pkt_oversz_cnt );
  FD_MCNT_SET(       SEND, PKT_VERNEG,              ctx->quic->metrics.pkt_verneg_cnt );
  FD_MCNT_SET(       SEND, PKT_RETRANSMISSIONS,     ctx->quic->metrics.pkt_retransmissions_cnt );

  FD_MCNT_SET(   SEND, HANDSHAKES_CREATED,          ctx->quic->metrics.hs_created_cnt );
  FD_MCNT_SET(   SEND, HANDSHAKE_ERROR_ALLOC_FAIL,  ctx->quic->metrics.hs_err_alloc_fail_cnt );
  FD_MCNT_SET(   SEND, HANDSHAKE_EVICTED,           ctx->quic->metrics.hs_evicted_cnt );

  FD_MCNT_SET(   SEND, FRAME_FAIL_PARSE,            ctx->quic->metrics.frame_rx_err_cnt );

  FD_MHIST_COPY( SEND, SERVICE_DURATION_SECONDS,    ctx->quic->metrics.service_duration );
  FD_MHIST_COPY( SEND, RECEIVE_DURATION_SECONDS,    ctx->quic->metrics.receive_duration );
}


#define STEM_BURST (3UL)

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
