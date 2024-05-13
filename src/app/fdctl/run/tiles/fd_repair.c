/* Repair tile runs the repair protocol for a Firedancer node. */

#define _GNU_SOURCE

#include "tiles.h"

#include "generated/repair_seccomp.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../util/fd_util.h"
#include "../../../../disco/tvu/util.h"
#include "../../../../disco/fd_disco.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/shred/fd_stake_ci.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>

#include "../../../../util/net/fd_net_headers.h"

#define NET_IN_IDX      0
#define CONTACT_IN_IDX  1
#define STAKE_IN_IDX    2
#define STORE_IN_IDX    3

#define NET_OUT_IDX   0

#define MAX_REPAIR_PEERS 40200UL
#define MAX_BUFFER_SIZE  ( MAX_REPAIR_PEERS * sizeof(fd_shred_dest_wire_t))

struct fd_repair_tile_ctx {
  fd_repair_t * repair;
  fd_repair_config_t repair_config;

  ulong repair_seed;

  fd_repair_peer_addr_t repair_intake_addr;
  fd_repair_peer_addr_t repair_serve_addr;

  ushort                repair_intake_listen_port;
  ushort                repair_serve_listen_port;

  uchar       identity_private_key[ 32 ];
  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

  fd_wksp_t * stake_weights_in_mem;
  ulong       stake_weights_in_chunk0;
  ulong       stake_weights_in_wmark;

  fd_wksp_t * repair_req_in_mem;
  ulong       repair_req_in_chunk0;
  ulong       repair_req_in_wmark;

  fd_wksp_t *     net_in_mem;
  ulong           net_in_chunk0;
  ulong           net_in_wmark;

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

  uchar src_mac_addr[6];
  ushort net_id;
  /* Includes Ethernet, IP, UDP headers */
  uchar buffer[ MAX_BUFFER_SIZE ];
  fd_net_hdrs_t intake_hdr[1];
  fd_net_hdrs_t serve_hdr[1];

  fd_stake_ci_t * stake_ci;

  fd_mux_context_t * mux;
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
  l = FD_LAYOUT_APPEND( l, fd_repair_align(), fd_repair_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( FD_REPAIR_SCRATCH_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( FD_REPAIR_SCRATCH_DEPTH ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_repair_tile_ctx_t) );
}

static void
send_packet( fd_repair_tile_ctx_t * ctx,
             int                    is_intake,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uchar const *          payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  fd_memcpy( packet, ( is_intake ? ctx->intake_hdr : ctx->serve_hdr ), sizeof(fd_net_hdrs_t) );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *)packet;

  hdr->udp->net_dport = dst_port;

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
handle_new_repair_requests( fd_repair_tile_ctx_t * ctx,
                            uchar const *          buf,
                            ulong                  buf_sz ) {

  fd_repair_request_t const * repair_reqs = (fd_repair_request_t const *) buf;
  ulong repair_req_cnt = buf_sz;

  for( ulong i=0UL; i<repair_req_cnt; i++ ) {
    fd_repair_request_t const * repair_req = &repair_reqs[i];
    int rc = 0;
    switch(repair_req->type) {
      case FD_REPAIR_REQ_TYPE_NEED_WINDOW_INDEX: {
        rc = fd_repair_need_window_index( ctx->repair, repair_req->slot, repair_req->shred_index );
        break;
      }
      case FD_REPAIR_REQ_TYPE_NEED_HIGHEST_WINDOW_INDEX: {
        rc = fd_repair_need_highest_window_index( ctx->repair, repair_req->slot, repair_req->shred_index );
        break;
      }
      case FD_REPAIR_REQ_TYPE_NEED_ORPHAN: {
        rc = fd_repair_need_orphan( ctx->repair, repair_req->slot );
        break;
      }
    }

    if( rc < 0 ) {
      FD_LOG_DEBUG(( "failed to issue repair request" ));
    }
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
                           void * arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, 1, addr->addr, addr->port, msg, msglen, tsorig );
}

static void
repair_send_serve_packet( uchar const *                 msg,
                          size_t                        msglen,
                          fd_gossip_peer_addr_t const * addr,
                          void * arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, 0, addr->addr, addr->port, msg, msglen, tsorig );
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
  fd_mux_publish( ctx->mux, sig, ctx->store_out_chunk, shred_sz, 0UL, 0UL, tspub );
  ctx->store_out_chunk = fd_dcache_compact_next( ctx->store_out_chunk, shred_sz, ctx->store_out_chunk0, ctx->store_out_wmark );
}

static void
repair_shred_deliver_fail( fd_pubkey_t const * id FD_PARAM_UNUSED,
                           ulong               slot,
                           uint                shred_index,
                           void *              arg FD_PARAM_UNUSED,
                           int                 reason ) {
  FD_LOG_WARNING(( "repair failed to get shred - slot: %lu, shred_index: %u, reason: %u", slot, shred_index, reason ));
}

static void
before_frag( void * _ctx FD_PARAM_UNUSED,
             ulong  in_idx,
             ulong  seq  FD_PARAM_UNUSED,
             ulong  sig,
             int *  opt_filter ) {

  if( FD_LIKELY( in_idx==NET_IN_IDX ) ) {
    *opt_filter = fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq FD_PARAM_UNUSED,
             ulong  sig FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter FD_PARAM_UNUSED ) {

  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;
  uchar const * dcache_entry;
  ulong dcache_entry_sz;

  // TODO: check for sz>MTU for failure once MTUs are decided
  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->contact_in_chunk0 || chunk>ctx->contact_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->contact_in_chunk0, ctx->contact_in_wmark ));
    }
    dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    dcache_entry_sz = sz * sizeof(fd_shred_dest_wire_t);

  } else if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_weights_in_chunk0 || chunk>ctx->stake_weights_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_weights_in_chunk0, ctx->stake_weights_in_wmark ));
    }

    dcache_entry = fd_chunk_to_laddr_const( ctx->stake_weights_in_mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
    return;

  } else if( FD_UNLIKELY( in_idx==STORE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->repair_req_in_chunk0 || chunk>ctx->repair_req_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->repair_req_in_chunk0, ctx->repair_req_in_wmark ));
    }

    dcache_entry = fd_chunk_to_laddr_const( ctx->repair_req_in_mem, chunk );
    dcache_entry_sz = sz * sizeof(fd_repair_request_t);
  } else if ( FD_LIKELY( in_idx == NET_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->net_in_chunk0 || chunk>ctx->net_in_wmark || sz>FD_NET_MTU ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->net_in_chunk0, ctx->net_in_wmark ));
    }

    dcache_entry = fd_chunk_to_laddr_const( ctx->net_in_mem, chunk );
    dcache_entry_sz = sz;
  } else {
    FD_LOG_ERR(("Unknown in_idx %lu for repair", in_idx));
  }

  fd_memcpy( ctx->buffer, dcache_entry, dcache_entry_sz );
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq        FD_PARAM_UNUSED,
            ulong *            opt_sig,
            ulong *            opt_chunk  FD_PARAM_UNUSED,
            ulong *            opt_sz,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter FD_PARAM_UNUSED,
            fd_mux_context_t * mux ) {

  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    handle_new_cluster_contact_info( ctx, ctx->buffer, *opt_sz );
    return;
  }

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    handle_new_stake_weights( ctx );
    return;
  }

  if( FD_UNLIKELY( in_idx==STORE_IN_IDX ) ) {
    handle_new_repair_requests( ctx, ctx->buffer, *opt_sz );
    return;
  }

  ctx->mux = mux;
  ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *)ctx->buffer;

  fd_repair_peer_addr_t peer_addr;
  peer_addr.l = 0;
  peer_addr.addr = FD_LOAD( uint, hdr->ip4->saddr_c );
  peer_addr.port = hdr->udp->net_sport;

  ushort dport = hdr->udp->net_dport;
  if( ctx->repair_intake_addr.port == dport )
    fd_repair_recv_clnt_packet( ctx->repair, ctx->buffer + hdr_sz, *opt_sz - hdr_sz, &peer_addr );
  else if( ctx->repair_serve_addr.port == dport )
    fd_repair_recv_serv_packet( ctx->repair, ctx->buffer + hdr_sz, *opt_sz - hdr_sz, &peer_addr );
  else
    FD_LOG_WARNING(( "received packet for port %u, which seems wrong", (uint)fd_ushort_bswap( dport ) ));
}

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux FD_PARAM_UNUSED ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );

  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_continue( ctx->repair );
}

static long
repair_get_shred( ulong  slot FD_PARAM_UNUSED,
                  int    shred_idx FD_PARAM_UNUSED,
                  void * buf FD_PARAM_UNUSED,
                  ulong  buf_max FD_PARAM_UNUSED,
                  void * arg FD_PARAM_UNUSED ) {
  return -1; /* Always fail for now */
}

static long
repair_get_parent( ulong  slot FD_PARAM_UNUSED,
                   void * arg FD_PARAM_UNUSED ) {
  return -1; /* Always fail for now */
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->repair.identity_key_path, /* pubkey only: */ 0 );
  fd_memcpy( ctx->identity_private_key, identity_key, sizeof(fd_pubkey_t) );
  fd_memcpy( ctx->identity_public_key.uc, identity_key + 32UL, sizeof(fd_pubkey_t) );

  ctx->repair_config.private_key = ctx->identity_private_key;
  ctx->repair_config.public_key  = &ctx->identity_public_key;

  FD_TEST( sizeof(ulong) == getrandom( &ctx->repair_seed, sizeof(ulong), 0 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {

  if( FD_UNLIKELY( tile->in_cnt != 4 ||
                   strcmp( topo->links[ tile->in_link_id[ NET_IN_IDX     ] ].name, "net_repair")     ||
                   strcmp( topo->links[ tile->in_link_id[ CONTACT_IN_IDX ] ].name, "gossip_repai" ) ||
                   strcmp( topo->links[ tile->in_link_id[ STAKE_IN_IDX ] ].name,   "stake_out" )     ||
                   strcmp( topo->links[ tile->in_link_id[ STORE_IN_IDX ] ].name,   "store_repair" ) ) ) {
    FD_LOG_ERR(( "repair tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_cnt != 1 ||
                   strcmp( topo->links[ tile->out_link_id[ NET_OUT_IDX ] ].name, "repair_net" ) ) ) {
    FD_LOG_ERR(( "repair tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "repair tile has no primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  ctx->repair = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(), fd_repair_footprint() );

  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( FD_REPAIR_SCRATCH_MAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( FD_REPAIR_SCRATCH_DEPTH ) );

  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, FD_REPAIR_SCRATCH_MAX, FD_REPAIR_SCRATCH_DEPTH );

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ctx->repair_intake_addr.addr = tile->repair.ip_addr;
  ctx->repair_intake_addr.port = fd_ushort_bswap( tile->repair.repair_intake_listen_port );

  ctx->repair_serve_addr.addr = tile->repair.ip_addr;
  ctx->repair_serve_addr.port = fd_ushort_bswap( tile->repair.repair_serve_listen_port );

  ctx->repair_intake_listen_port = tile->repair.repair_intake_listen_port;
  ctx->repair_serve_listen_port = tile->repair.repair_serve_listen_port;

  void * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci , &ctx->identity_public_key ) );

  ctx->net_id = (ushort)0;
  fd_memcpy( ctx->src_mac_addr, tile->repair.src_mac_addr, 6 );

  fd_net_create_packet_header_template( ctx->intake_hdr, FD_REPAIR_MAX_PACKET_SIZE, ctx->repair_intake_addr.addr, ctx->src_mac_addr, ctx->repair_intake_listen_port );
  fd_net_create_packet_header_template( ctx->serve_hdr, FD_REPAIR_MAX_PACKET_SIZE, ctx->repair_serve_addr.addr, ctx->src_mac_addr, ctx->repair_serve_listen_port );

  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ 0 ] ];

  ctx->net_in_mem  = topo->workspaces[ topo->objs[ netmux_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_in_chunk0  = fd_disco_compact_chunk0( ctx->net_in_mem );
  ctx->net_in_wmark  = fd_disco_compact_wmark ( ctx->net_in_mem, netmux_link->mtu );

  FD_LOG_NOTICE(( "repair starting" ));

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ NET_OUT_IDX ] ];
  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;


  fd_topo_link_t * store_out = &topo->links[ tile->out_link_id_primary ];
  ctx->store_out_mcache = store_out->mcache;
  ctx->store_out_sync   = fd_mcache_seq_laddr( ctx->store_out_mcache );
  ctx->store_out_depth  = fd_mcache_depth( ctx->store_out_mcache );
  ctx->store_out_seq    = fd_mcache_seq_query( ctx->store_out_sync );
  ctx->store_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( store_out->dcache ), store_out->dcache );
  ctx->store_out_mem    = topo->workspaces[ topo->objs[ store_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_out_wmark  = fd_dcache_compact_wmark( ctx->store_out_mem, store_out->dcache, store_out->mtu );
  ctx->store_out_chunk  = ctx->store_out_chunk0;

  /* Set up contact info tile input */
  fd_topo_link_t * contact_in_link   = &topo->links[ tile->in_link_id[ CONTACT_IN_IDX ] ];
  ctx->contact_in_mem    = topo->workspaces[ topo->objs[ contact_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark ( ctx->contact_in_mem, contact_in_link->dcache, contact_in_link->mtu );

  /* Set up tile stake weight tile input */
  fd_topo_link_t * stake_weights_in_link   = &topo->links[ tile->in_link_id[ STAKE_IN_IDX ] ];
  ctx->stake_weights_in_mem    = topo->workspaces[ topo->objs[ stake_weights_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_weights_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_weights_in_mem, stake_weights_in_link->dcache );
  ctx->stake_weights_in_wmark  = fd_dcache_compact_wmark ( ctx->stake_weights_in_mem, stake_weights_in_link->dcache, stake_weights_in_link->mtu );

  /* Set up tile repair request input */
  fd_topo_link_t * repair_req_in_link = &topo->links[ tile->in_link_id[ STORE_IN_IDX ] ];
  ctx->repair_req_in_mem    = topo->workspaces[ topo->objs[ repair_req_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->repair_req_in_chunk0 = fd_dcache_compact_chunk0( ctx->repair_req_in_mem, repair_req_in_link->dcache );
  ctx->repair_req_in_wmark  = fd_dcache_compact_wmark ( ctx->repair_req_in_mem, repair_req_in_link->dcache, repair_req_in_link->mtu );

  /* Repair set up */

  ctx->repair = fd_repair_join( fd_repair_new( ctx->repair, ctx->repair_seed ) );

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
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_repair( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_repair_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch FD_PARAM_UNUSED,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_repair = {
  .name                     = "repair",
  .mux_flags                = FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .mux_after_credit         = after_credit
};
