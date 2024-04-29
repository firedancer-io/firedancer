/* Repair tile runs the repair protocol for a Firedancer node. */

#define _GNU_SOURCE 

#include "tiles.h"

#include "generated/repair_seccomp.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../util/fd_util.h"
#include "../../../../disco/tvu/util.h"

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

#define NET_IN_IDX      0
#define CONTACT_IN_IDX  1
#define STAKE_IN_IDX    2
#define STORE_IN_IDX    3

#define STORE_OUT_IDX   0

#define MAX_REPAIR_PEERS 40200UL

#define SMAX    (1UL << 30UL)
#define SDEPTH  (1UL << 11UL)


static int
fd_pubkey_eq( fd_pubkey_t const * key1, fd_pubkey_t const * key2 ) {
  return memcmp( key1->key, key2->key, sizeof(fd_pubkey_t) ) == 0;
}

static ulong
fd_pubkey_hash( fd_pubkey_t const * key, ulong seed ) {
  return fd_hash( seed, key->key, sizeof(fd_pubkey_t) ); 
}

static void
fd_pubkey_copy( fd_pubkey_t * keyd, fd_pubkey_t const * keys ) {
  memcpy( keyd->key, keys->key, sizeof(fd_pubkey_t) );
}

/* Contact info table */
#define MAP_NAME     fd_contact_info_table
#define MAP_KEY_T    fd_pubkey_t
#define MAP_KEY_EQ   fd_pubkey_eq
#define MAP_KEY_HASH fd_pubkey_hash
#define MAP_KEY_COPY fd_pubkey_copy
#define MAP_T        fd_contact_info_elem_t
#include "../../../../util/tmpl/fd_map_giant.c"


struct fd_repair_tile_ctx {
  fd_repair_t * repair;
  fd_repair_config_t repair_config;

  fd_repair_peer_addr_t repair_my_intake_addr;
  fd_repair_peer_addr_t repair_my_serve_addr;
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

  fd_wksp_t *     net_in;
  ulong           chunk;
  ulong           wmark;

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

  /* Includes Ethernet, IP, UDP headers */
  ulong repair_buffer_sz;
  uchar repair_buffer[ FD_NET_MTU ];
};
typedef struct fd_repair_tile_ctx fd_repair_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
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
  l = FD_LAYOUT_APPEND( l, fd_repair_align(), fd_repair_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SMAX ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SDEPTH ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_repair_tile_ctx_t) );
}
typedef struct __attribute__((packed)) {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];
} eth_ip_udp_t;

static inline void
populate_packet_header_template( eth_ip_udp_t * pkt,
                                 ulong          payload_sz,
                                 uint           src_ip,
                                 uchar const *  src_mac,
                                 ushort         src_port ) {
  memset( pkt->eth->dst, 0,       6UL );
  memcpy( pkt->eth->src, src_mac, 6UL );
  pkt->eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

  pkt->ip4->verihl       = FD_IP4_VERIHL( 4U, 5U );
  pkt->ip4->tos          = (uchar)0;
  pkt->ip4->net_tot_len  = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  pkt->ip4->net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
  pkt->ip4->ttl          = (uchar)64;
  pkt->ip4->protocol     = FD_IP4_HDR_PROTOCOL_UDP;
  pkt->ip4->check        = 0U;
  memcpy( pkt->ip4->saddr_c, &src_ip, 4UL );
  memset( pkt->ip4->daddr_c, 0,       4UL ); /* varies by shred */

  pkt->udp->net_sport = fd_ushort_bswap( src_port );
  pkt->udp->net_dport = (ushort)0; /* varies by shred */
  pkt->udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  pkt->udp->check     = (ushort)0;
}

static void FD_FN_UNUSED
send_packet( fd_repair_tile_ctx_t * ctx,
             uint    ip,
             ushort  port,
             uchar const * payload,
             ulong   payload_sz,
             ulong   tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  eth_ip_udp_t * hdr = (eth_ip_udp_t *)packet;
  uchar mac[6] = {0};
  populate_packet_header_template( hdr, payload_sz, ctx->repair_my_intake_addr.addr, mac, ctx->repair_intake_listen_port );

  hdr->udp->net_dport = port;

  memcpy( hdr->eth->dst, mac, 6UL );
  memcpy( hdr->ip4->daddr_c, &ip, 4UL );

  // TODO: LML handle checksum correctly
  hdr->ip4->check = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4 ) );

  ulong packet_sz = payload_sz + sizeof(eth_ip_udp_t);
  fd_memcpy( packet+sizeof(eth_ip_udp_t), payload, payload_sz );

  hdr->udp->check = fd_ip4_udp_check( *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->saddr_c ), 
                                      *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->daddr_c ), 
                                      (fd_udp_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->udp ), 
                                      packet + sizeof(eth_ip_udp_t) );

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = fd_disco_netmux_sig( ip, port, FD_NETMUX_SIG_MIN_HDR_SZ, DST_PROTO_OUTGOING, (ushort)0 );
  fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static inline void
handle_new_cluster_contact_info( fd_repair_tile_ctx_t * ctx,
                                 uchar const    * buf ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = header[ 0 ];

  if( dest_cnt >= MAX_REPAIR_PEERS ) {
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_REPAIR_PEERS ));
  }

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header+1UL );

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    fd_repair_peer_addr_t repair_peer = {
      .addr = in_dests[i].ip4_addr,
      .port = in_dests[i].udp_port,
    };
   
    fd_repair_add_active_peer( ctx->repair, &repair_peer, in_dests[i].pubkey );
  }
}

static inline void
handle_new_repair_requests( fd_repair_tile_ctx_t * ctx,
                            uchar const    * buf,
                            ulong buf_sz ) {

  fd_repair_request_t const * repair_reqs = (fd_repair_request_t const *)fd_type_pun_const( buf );
  ulong repair_req_cnt = buf_sz;
  // FD_LOG_WARNING(("Repair requests %lu received %lu", repair_req_cnt, buf_sz));
  for( ulong i = 0; i < repair_req_cnt; i++ ) {
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
      FD_LOG_WARNING(( "failed to issue repair request" ));
    }
  }

}

static inline void
handle_new_stake_weights( fd_repair_tile_ctx_t * ctx,
                          uchar const    * buf ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong stakes_cnt = header[ 1 ]; 

  if( stakes_cnt >= MAX_REPAIR_PEERS ) {
    FD_LOG_ERR(( "Cluster nodes had %lu stake weights, which was more than the max of %lu", stakes_cnt, MAX_REPAIR_PEERS ));
  }

  fd_stake_weight_t const * in_stake_weights = fd_type_pun_const( header+4UL );
  fd_repair_set_stake_weights( ctx->repair, in_stake_weights, stakes_cnt );
}


static void 
repair_send_packet( uchar const * msg, 
                    size_t msglen, 
                    fd_gossip_peer_addr_t const * addr, 
                    void * arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, addr->addr, fd_ushort_bswap( addr->port ), msg, msglen, tsorig );
}

static void
repair_shred_deliver( fd_shred_t const * shred,
                      ulong shred_sz, 
                      fd_repair_peer_addr_t const * from FD_PARAM_UNUSED, 
                      fd_pubkey_t const * id FD_PARAM_UNUSED, 
                      void * arg ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)arg;
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  
  fd_shred_t * out_shred = fd_chunk_to_laddr( ctx->store_out_mem, ctx->store_out_chunk );
  fd_memcpy( out_shred, shred, shred_sz );
  
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( ctx->store_out_mcache, ctx->store_out_depth, ctx->store_out_seq, 1, ctx->store_out_chunk,
    shred_sz, 0UL, tsorig, tspub );
  ctx->store_out_seq   = fd_seq_inc( ctx->store_out_seq, 1UL );
  ctx->store_out_chunk = fd_dcache_compact_next( ctx->store_out_chunk, shred_sz, ctx->store_out_chunk0, ctx->store_out_wmark );}

static void
repair_shred_deliver_fail( fd_pubkey_t const * id FD_PARAM_UNUSED, 
                           ulong slot, 
                           uint shred_index,
                           void * arg FD_PARAM_UNUSED,
                           int reason ) {
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
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {

  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->contact_in_chunk0 || chunk>ctx->contact_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->contact_in_chunk0, ctx->contact_in_wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_weights_in_chunk0 || chunk>ctx->stake_weights_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_weights_in_chunk0, ctx->stake_weights_in_wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_weights_in_mem, chunk );
    handle_new_stake_weights( ctx, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( in_idx==STORE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->repair_req_in_chunk0 || chunk>ctx->repair_req_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->repair_req_in_chunk0, ctx->repair_req_in_wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->repair_req_in_mem, chunk );
    handle_new_repair_requests( ctx, dcache_entry, sz );
    return;
  }
  
  if( FD_UNLIKELY( chunk<ctx->chunk || chunk>ctx->wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->chunk, ctx->wmark ));
    *opt_filter = 1;
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->net_in, chunk );
  ulong  hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
  FD_TEST( hdr_sz < sz ); /* Should be ensured by the net tile */

  ctx->repair_buffer_sz = sz;
  fd_memcpy( ctx->repair_buffer, dcache_entry, sz );

  *opt_filter = 0;

  return;
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq        FD_PARAM_UNUSED,
            ulong *            opt_sig,
            ulong *            opt_chunk  FD_PARAM_UNUSED,
            ulong *            opt_sz     FD_PARAM_UNUSED,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter,
            fd_mux_context_t * mux        FD_PARAM_UNUSED) {

  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  *opt_filter = 1;

  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    return;
  }

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    return;
  }

  if( FD_UNLIKELY( in_idx==STORE_IN_IDX ) ) {
    return;
  }

  uint   ip = fd_disco_netmux_sig_dst_ip( *opt_sig );
  ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
  eth_ip_udp_t * hdr = (eth_ip_udp_t *)ctx->repair_buffer;

  fd_repair_peer_addr_t peer_addr;
  peer_addr.l = 0;
  peer_addr.addr = ip;
  peer_addr.port = fd_ushort_bswap( hdr->udp->net_sport );

  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_continue( ctx->repair );
  fd_repair_recv_packet( ctx->repair, ctx->repair_buffer + hdr_sz, ctx->repair_buffer_sz - hdr_sz, &peer_addr );
}

static void
privileged_init( fd_topo_t *      topo    FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile    FD_PARAM_UNUSED,
                 void *           scratch FD_PARAM_UNUSED) {

}

static void
during_housekeeping( void * _ctx ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  fd_mcache_seq_update( ctx->store_out_sync, ctx->store_out_seq );

  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_continue( ctx->repair );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  fd_flamenco_boot( NULL, NULL );

  if( FD_UNLIKELY( tile->in_cnt != 4 ||
                   strcmp( topo->links[ tile->in_link_id[ NET_IN_IDX     ] ].name, "net_repair")     ||
                   strcmp( topo->links[ tile->in_link_id[ CONTACT_IN_IDX ] ].name, "gossip_repai" ) ||
                   strcmp( topo->links[ tile->in_link_id[ STAKE_IN_IDX ] ].name,   "stake_out" )     ||
                   strcmp( topo->links[ tile->in_link_id[ STORE_IN_IDX ] ].name,   "store_repair" ) ) ) {
    FD_LOG_ERR(( "repair tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_cnt != 1 ||
                   strcmp( topo->links[ tile->out_link_id[ STORE_OUT_IDX ] ].name, "repair_store" ) ) ) {
    FD_LOG_ERR(( "repair tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "repair tile has no primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  ctx->repair = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(), fd_repair_footprint() );

  void * smem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SMAX ) );
  void * fmem = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SDEPTH ) );

  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, SMAX, SDEPTH );
  
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  
  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  void * alloc_shmem = fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { 
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); 
  }

  ctx->repair_my_intake_addr.addr = tile->repair.ip_addr;
  ctx->repair_my_intake_addr.port = tile->repair.repair_intake_listen_port;

  ctx->repair_my_serve_addr.addr = tile->repair.ip_addr;
  ctx->repair_my_serve_addr.port = tile->repair.repair_serve_listen_port;
  
  ctx->repair_intake_listen_port = tile->repair.repair_intake_listen_port;
  ctx->repair_serve_listen_port = tile->repair.repair_serve_listen_port;

  FD_TEST( ctx->repair_intake_listen_port!=0 );
  FD_TEST( ctx->repair_serve_listen_port!=0 );

  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ 0 ] ];

  ctx->net_in    = topo->workspaces[ topo->objs[ netmux_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->chunk  = fd_disco_compact_chunk0( ctx->net_in );
  ctx->wmark  = fd_disco_compact_wmark ( ctx->net_in, netmux_link->mtu );

  // TODO: make configurable
  FD_TEST( getrandom( ctx->identity_private_key, 32UL, 0 ) == 32UL );
  fd_sha512_t sha[1];
  FD_TEST( fd_ed25519_public_from_private( ctx->identity_public_key.uc, ctx->identity_private_key, sha ) );

  FD_LOG_NOTICE(( "repair starting" ));

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id_primary ];
  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;


  fd_topo_link_t * store_out = &topo->links[ tile->out_link_id[ STORE_OUT_IDX ] ];
  ctx->store_out_mcache = store_out->mcache;
  ctx->store_out_sync   = fd_mcache_seq_laddr( ctx->store_out_mcache );
  ctx->store_out_depth  = fd_mcache_depth( ctx->store_out_mcache );
  ctx->store_out_seq    = fd_mcache_seq_query( ctx->store_out_sync );
  ctx->store_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( store_out->dcache ), store_out->dcache );
  ctx->store_out_mem    = topo->workspaces[ topo->objs[ store_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_out_wmark  = fd_dcache_compact_wmark( ctx->store_out_mem, store_out->dcache, store_out->mtu );
  ctx->store_out_chunk  = ctx->store_out_chunk0;

  fd_memcpy( ctx->src_mac_addr, tile->repair.src_mac_addr, 6 );

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

  /* Valloc setup */
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { 
    FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) ); 
  }

  fd_valloc_t valloc = fd_alloc_virtual( alloc );

  /* Gossip set up */

  // TODO: actually get a reasonable seed
  ulong seed = 42;
  ctx->repair = fd_repair_join( fd_repair_new( ctx->repair, seed, valloc ) );

  FD_LOG_NOTICE(( "repair my addr - intake addr: " FD_IP4_ADDR_FMT ":%u, serve_addr: " FD_IP4_ADDR_FMT ":%u", 
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_my_intake_addr.addr ), ctx->repair_my_intake_addr.port,
    FD_IP4_ADDR_FMT_ARGS( ctx->repair_my_serve_addr.addr ), ctx->repair_my_serve_addr.port ));

  ctx->repair_config.private_key = ctx->identity_private_key;
  ctx->repair_config.public_key = &ctx->identity_public_key;
  ctx->repair_config.fun_arg = ctx;
  ctx->repair_config.deliver_fun = repair_shred_deliver;
  ctx->repair_config.deliver_fail_fun = repair_shred_deliver_fail;
  ctx->repair_config.send_fun = repair_send_packet;

  if( fd_repair_set_config( ctx->repair, &ctx->repair_config ) ) {
    FD_LOG_ERR( ( "error setting gossip config" ) );
  }

  fd_repair_update_addr( ctx->repair, &ctx->repair_my_intake_addr, &ctx->repair_my_serve_addr );

  fd_repair_settime( ctx->repair, fd_log_wallclock() );\
  fd_repair_start( ctx->repair );

  FD_LOG_NOTICE(( "repair listening - intake port: %u, serve port: %u", tile->repair.repair_intake_listen_port, tile->repair.repair_serve_listen_port ));
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
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .mux_during_housekeeping  = during_housekeeping,
};
