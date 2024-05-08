/* Gossip tile runs the gossip networking protcol for a Firedancer node. */

#define _GNU_SOURCE 

#include "tiles.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../../../disco/fd_disco.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/tvu/util.h"
#include "../../../../flamenco/gossip/fd_gossip.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"
#include "../../../../util/net/fd_net_headers.h"

#include "generated/gossip_seccomp.h"


#define NET_IN_IDX      0
#define SIGN_IN_IDX     1

#define SHRED_OUT_IDX   0
#define REPAIR_OUT_IDX  1
#define PACK_OUT_IDX    2
#define SIGN_OUT_IDX    3

#define CONTACT_INFO_PUBLISH_TIME_NS ((long)5e9)

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

struct fd_gossip_tile_ctx {
  fd_gossip_t * gossip;
  fd_gossip_config_t gossip_config;
  long last_shred_dest_push_time;

  ulong gossip_seed;

  fd_contact_info_elem_t * contact_info_table;

  fd_frag_meta_t * shred_contact_out_mcache;
  ulong *          shred_contact_out_sync;
  ulong            shred_contact_out_depth;
  ulong            shred_contact_out_seq;

  fd_wksp_t * shred_contact_out_mem;
  ulong       shred_contact_out_chunk0;
  ulong       shred_contact_out_wmark;
  ulong       shred_contact_out_chunk;

  fd_frag_meta_t * repair_contact_out_mcache;
  ulong *          repair_contact_out_sync;
  ulong            repair_contact_out_depth;
  ulong            repair_contact_out_seq;

  fd_wksp_t * repair_contact_out_mem;
  ulong       repair_contact_out_chunk0;
  ulong       repair_contact_out_wmark;
  ulong       repair_contact_out_chunk;
  
  fd_frag_meta_t * pack_out_mcache;
  ulong *          pack_out_sync;
  ulong            pack_out_depth;
  ulong            pack_out_seq;

  fd_wksp_t * pack_out_mem;
  ulong       pack_out_chunk0;
  ulong       pack_out_wmark;
  ulong       pack_out_chunk;


  fd_wksp_t *     wksp;
  fd_gossip_peer_addr_t gossip_my_addr;
  fd_gossip_peer_addr_t tvu_my_addr;
  fd_gossip_peer_addr_t tvu_my_fwd_addr;
  fd_gossip_peer_addr_t tpu_my_addr;
  fd_gossip_peer_addr_t tpu_vote_my_addr;
  ushort                gossip_listen_port;
  
  fd_wksp_t *     net_in_mem;
  ulong           net_in_chunk;
  ulong           net_in_wmark;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  uchar         identity_private_key[32];
  fd_pubkey_t   identity_public_key;

  /* Includes Ethernet, IP, UDP headers */
  ulong gossip_buffer_sz;
  uchar gossip_buffer[ FD_NET_MTU ];

  ushort net_id;
  uchar src_mac_addr[6];
  fd_net_hdrs_t hdr[1];

  fd_keyguard_client_t  keyguard_client[1];

  fd_mux_context_t * mux;
};
typedef struct fd_gossip_tile_ctx fd_gossip_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_gossip_align(), fd_gossip_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_contact_info_table_align(), fd_contact_info_table_footprint( FD_PEER_KEY_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_gossip_tile_ctx_t) );
}

static void
send_packet( fd_gossip_tile_ctx_t * ctx,
             uint                   dst_ip_addr,
             ushort                 dst_port,
             uchar const *          payload,
             ulong                  payload_sz,
             ulong                  tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  fd_memcpy( packet, ctx->hdr, sizeof(fd_net_hdrs_t) );
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
  ulong sig   = fd_disco_netmux_sig( 0U, 0U, dst_ip_addr, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
  fd_mux_publish( ctx->mux, sig, ctx->net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void 
gossip_send_packet( uchar const * msg, 
                    size_t msglen, 
                    fd_gossip_peer_addr_t const * addr, 
                    void * arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, addr->addr, addr->port, msg, msglen, tsorig );
}


static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)arg;

  if( fd_crds_data_is_vote( data ) ) {
    fd_gossip_vote_t const * gossip_vote = &data->inner.vote;
    
    uchar * vote_txn_msg = fd_chunk_to_laddr( ctx->pack_out_mem, ctx->pack_out_chunk );
    ulong vote_txn_sz    = gossip_vote->txn.raw_sz;
    memcpy( vote_txn_msg, gossip_vote->txn.raw, vote_txn_sz );
    ulong sig = 1UL;
    fd_mcache_publish( ctx->pack_out_mcache, ctx->pack_out_depth, ctx->pack_out_seq, sig, ctx->pack_out_chunk,
      vote_txn_sz, 0UL, 0, 0 );
    ctx->pack_out_seq   = fd_seq_inc( ctx->pack_out_seq, 1UL );
    ctx->pack_out_chunk = fd_dcache_compact_next( ctx->pack_out_chunk, vote_txn_sz, ctx->pack_out_chunk0, ctx->pack_out_wmark );
  } else if( fd_crds_data_is_contact_info_v1( data ) ) {
    fd_gossip_contact_info_v1_t const * contact_info = &data->inner.contact_info_v1;
    FD_LOG_DEBUG(("contact info v1 - ip: " FD_IP4_ADDR_FMT ", port: %u", FD_IP4_ADDR_FMT_ARGS( contact_info->gossip.addr.inner.ip4 ), contact_info->gossip.port ));

    fd_contact_info_elem_t * ele = fd_contact_info_table_query( ctx->contact_info_table, &contact_info->id, NULL );
    if( ele==NULL ) {
      /* Insert the element */
      ele = fd_contact_info_table_insert( ctx->contact_info_table, &contact_info->id );
    }

    ele->contact_info = *contact_info;
  }
}

void
gossip_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, signature, buffer, len );
}

static void
before_frag( void * _ctx        FD_PARAM_UNUSED,
             ulong  in_idx      FD_PARAM_UNUSED, 
             ulong  seq         FD_PARAM_UNUSED,
             ulong  sig,
             int *  opt_filter ) {
  if( fd_disco_netmux_sig_proto( sig )!=DST_PROTO_GOSSIP ) {
    *opt_filter = 1;
    return;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx      FD_PARAM_UNUSED,
             ulong  seq         FD_PARAM_UNUSED,
             ulong  sig         FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;
  if( in_idx!=NET_IN_IDX ) {
    *opt_filter = 1;
    return;
  }

  if( FD_UNLIKELY( chunk<ctx->net_in_chunk || chunk>ctx->net_in_wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->net_in_chunk, ctx->net_in_wmark ));
    *opt_filter = 1;
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->net_in_mem, chunk );

  ctx->gossip_buffer_sz = sz;
  fd_memcpy( ctx->gossip_buffer, dcache_entry, sz );
}

static void
after_frag( void *             _ctx,
            ulong              in_idx     FD_PARAM_UNUSED,
            ulong              seq        FD_PARAM_UNUSED,
            ulong *            opt_sig,
            ulong *            opt_chunk  FD_PARAM_UNUSED,
            ulong *            opt_sz     FD_PARAM_UNUSED,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter FD_PARAM_UNUSED,
            fd_mux_context_t * mux ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;

  ctx->mux = mux;
  ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
  fd_net_hdrs_t * hdr = (fd_net_hdrs_t *)ctx->gossip_buffer;

  fd_gossip_peer_addr_t peer_addr;
  peer_addr.l    = 0;
  peer_addr.addr = FD_LOAD( uint, hdr->ip4->saddr_c );
  peer_addr.port = hdr->udp->net_sport;

  fd_gossip_recv_packet( ctx->gossip, ctx->gossip_buffer + hdr_sz, ctx->gossip_buffer_sz - hdr_sz, &peer_addr );
}

static void
after_credit( void * _ctx,
              fd_mux_context_t * mux_ctx ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;
  ctx->mux = mux_ctx;
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  fd_mcache_seq_update( ctx->shred_contact_out_sync, ctx->shred_contact_out_seq );
  fd_mcache_seq_update( ctx->repair_contact_out_sync, ctx->repair_contact_out_seq );

  long now = fd_log_wallclock();
  if( ( now - ctx->last_shred_dest_push_time )>CONTACT_INFO_PUBLISH_TIME_NS ) {
    ctx->last_shred_dest_push_time = now;

    ulong tvu_peer_cnt = 0;
    ulong repair_peers_cnt = 0;

    ulong * shred_dest_msg = fd_chunk_to_laddr( ctx->shred_contact_out_mem, ctx->shred_contact_out_chunk );
    fd_shred_dest_wire_t * tvu_peers = (fd_shred_dest_wire_t *)(shred_dest_msg+1);

    fd_shred_dest_wire_t * repair_peers = fd_chunk_to_laddr( ctx->repair_contact_out_mem, ctx->repair_contact_out_chunk );
    for( fd_contact_info_table_iter_t iter = fd_contact_info_table_iter_init( ctx->contact_info_table );
         !fd_contact_info_table_iter_done( ctx->contact_info_table, iter );
         iter = fd_contact_info_table_iter_next( ctx->contact_info_table, iter ) ) {
      fd_contact_info_elem_t const * ele = fd_contact_info_table_iter_ele_const( ctx->contact_info_table, iter );

      if( ele->contact_info.shred_version!=fd_gossip_get_shred_version( ctx->gossip ) ) {
        continue;
      }

      {
        if( !fd_gossip_ip_addr_is_ip4( &ele->contact_info.tvu.addr ) ) {
          continue;
        }

        // TODO: add a consistency check function for IP addresses
        if( ele->contact_info.tvu.addr.inner.ip4==0 ) {
          continue;
        }

        tvu_peers[tvu_peer_cnt].ip4_addr = ele->contact_info.tvu.addr.inner.ip4;
        tvu_peers[tvu_peer_cnt].udp_port = ele->contact_info.tvu.port;
        memcpy( tvu_peers[tvu_peer_cnt].pubkey, ele->contact_info.id.key, sizeof(fd_pubkey_t) );
        
        tvu_peer_cnt++;
      }

      {
        if( !fd_gossip_ip_addr_is_ip4( &ele->contact_info.repair.addr ) ) {
          continue;
        }

        // TODO: add a consistency check function for IP addresses
        if( ele->contact_info.serve_repair.addr.inner.ip4 == 0 ) {
          continue;
        }

        repair_peers[repair_peers_cnt].ip4_addr = ele->contact_info.serve_repair.addr.inner.ip4;
        repair_peers[repair_peers_cnt].udp_port = ele->contact_info.serve_repair.port;
        memcpy( repair_peers[repair_peers_cnt].pubkey, ele->contact_info.id.key, sizeof(fd_pubkey_t) );
        
        repair_peers_cnt++;
      }
    }

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

    if( tvu_peer_cnt>0 ) {
      *shred_dest_msg         = tvu_peer_cnt;
      ulong shred_contact_sz  = sizeof(ulong) + (tvu_peer_cnt * sizeof(fd_shred_dest_wire_t));
      ulong shred_contact_sig = 2UL;
      fd_mcache_publish( ctx->shred_contact_out_mcache, ctx->shred_contact_out_depth, ctx->shred_contact_out_seq, shred_contact_sig, ctx->shred_contact_out_chunk,
        shred_contact_sz, 0UL, tsorig, tspub );
      ctx->shred_contact_out_seq   = fd_seq_inc( ctx->shred_contact_out_seq, 1UL );
      ctx->shred_contact_out_chunk = fd_dcache_compact_next( ctx->shred_contact_out_chunk, shred_contact_sz, ctx->shred_contact_out_chunk0, ctx->shred_contact_out_wmark );
    }

    if( repair_peers_cnt>0 ) {
      ulong repair_contact_sz  = (repair_peers_cnt * sizeof(fd_shred_dest_wire_t));
      ulong repair_contact_sig = 3UL;
      fd_mcache_publish( ctx->repair_contact_out_mcache, ctx->repair_contact_out_depth, ctx->repair_contact_out_seq, repair_contact_sig, ctx->repair_contact_out_chunk,
        repair_peers_cnt, 0UL, tsorig, tspub );
      ctx->repair_contact_out_seq   = fd_seq_inc( ctx->repair_contact_out_seq, 1UL );
      ctx->repair_contact_out_chunk = fd_dcache_compact_next( ctx->repair_contact_out_chunk, repair_contact_sz, ctx->repair_contact_out_chunk0, ctx->repair_contact_out_wmark );
    }
  }

  fd_gossip_settime( ctx->gossip, now );
  fd_gossip_continue( ctx->gossip );
}

static void
privileged_init( fd_topo_t *      topo    FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );

  uchar const * identity_key = fd_keyload_load( tile->gossip.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key.uc, identity_key, sizeof(fd_pubkey_t) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->gossip_seed, sizeof(ulong), 0 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( tile->in_cnt != 2UL ||
                   strcmp( topo->links[ tile->in_link_id[ NET_IN_IDX     ] ].name, "net_gossip" ) ||
                   strcmp( topo->links[ tile->in_link_id[ SIGN_IN_IDX    ] ].name, "sign_gossip" ) ) ) {
    FD_LOG_ERR(( "gossip tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_cnt != 4 ||
                   strcmp( topo->links[ tile->out_link_id[ SHRED_OUT_IDX  ] ].name, "crds_shred" )    ||
                   strcmp( topo->links[ tile->out_link_id[ REPAIR_OUT_IDX ] ].name, "gossip_repai" )  ||
                   strcmp( topo->links[ tile->out_link_id[ PACK_OUT_IDX   ] ].name, "gossip_pack" )   ||
                   strcmp( topo->links[ tile->out_link_id[ SIGN_OUT_IDX   ] ].name, "gossip_sign" ) ) ) {
    FD_LOG_ERR(( "gossip tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));
  }

  if( FD_UNLIKELY( tile->out_link_id_primary==ULONG_MAX ) )
    FD_LOG_ERR(( "gossip tile has no primary output link" ));

  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  ctx->gossip = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_align(), fd_gossip_footprint() );
  ctx->contact_info_table = fd_contact_info_table_join( fd_contact_info_table_new( FD_SCRATCH_ALLOC_APPEND( l, fd_contact_info_table_align(), fd_contact_info_table_footprint( FD_PEER_KEY_MAX ) ), FD_PEER_KEY_MAX, 0 ) );
  
  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id_primary ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  void * alloc_shmem = fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { 
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); 
  }

  ctx->gossip_my_addr.addr = tile->gossip.ip_addr;
  ctx->gossip_my_addr.port = fd_ushort_bswap( tile->gossip.gossip_listen_port );

  ctx->gossip_listen_port = tile->gossip.gossip_listen_port;

  FD_TEST( ctx->gossip_listen_port!=0 );

  ctx->net_id = (ushort)0;
  fd_memcpy( ctx->src_mac_addr, tile->repair.src_mac_addr, 6 );

  fd_net_create_packet_header_template( ctx->hdr, FD_NET_MTU, ctx->gossip_my_addr.addr, ctx->src_mac_addr, ctx->gossip_listen_port );

  ctx->last_shred_dest_push_time = 0;

  fd_topo_link_t * sign_in  = &topo->links[ tile->in_link_id[ SIGN_IN_IDX ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) )==NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }

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
  // TODO: remove valloc and make gossip statically (bump) allocated
  ctx->gossip = fd_gossip_join( fd_gossip_new( ctx->gossip, ctx->gossip_seed, valloc ) );

  FD_LOG_NOTICE(( "gossip my addr - addr: " FD_IP4_ADDR_FMT ":%u", 
    FD_IP4_ADDR_FMT_ARGS( ctx->gossip_my_addr.addr ), fd_ushort_bswap( ctx->gossip_my_addr.port ) ));
  ctx->gossip_config.my_addr       = ctx->gossip_my_addr;
  ctx->gossip_config.private_key   = ctx->identity_private_key;
  ctx->gossip_config.public_key    = &ctx->identity_public_key;
  ctx->gossip_config.deliver_fun   = gossip_deliver_fun;
  ctx->gossip_config.deliver_arg   = ctx;
  ctx->gossip_config.send_fun      = gossip_send_packet;
  ctx->gossip_config.send_arg      = ctx;
  ctx->gossip_config.sign_fun      = gossip_signer;
  ctx->gossip_config.sign_arg      = ctx;
  ctx->gossip_config.shred_version = (ushort)tile->gossip.expected_shred_version;

  if( fd_gossip_set_config( ctx->gossip, &ctx->gossip_config ) ) {
    FD_LOG_ERR( ( "error setting gossip config" ) );
  }

  fd_gossip_set_entrypoints( ctx->gossip, tile->gossip.entrypoints, tile->gossip.entrypoints_cnt, tile->gossip.entrypoint_ports );

  fd_gossip_update_addr( ctx->gossip, &ctx->gossip_config.my_addr );

  ctx->tvu_my_addr.addr      = tile->gossip.ip_addr;
  ctx->tvu_my_addr.port      = fd_ushort_bswap( tile->gossip.tvu_port );
  ctx->tvu_my_fwd_addr.addr  = tile->gossip.ip_addr;
  ctx->tvu_my_fwd_addr.port  = fd_ushort_bswap( tile->gossip.tvu_fwd_port );
  ctx->tpu_my_addr.addr      = tile->gossip.ip_addr;
  ctx->tpu_my_addr.port      = fd_ushort_bswap( tile->gossip.tpu_port );
  ctx->tpu_vote_my_addr.addr = tile->gossip.ip_addr;
  ctx->tpu_vote_my_addr.port = fd_ushort_bswap( tile->gossip.tpu_vote_port );

  fd_gossip_update_tvu_addr( ctx->gossip, &ctx->tvu_my_addr, &ctx->tvu_my_fwd_addr );
  fd_gossip_update_tpu_addr( ctx->gossip, &ctx->tpu_my_addr );
  fd_gossip_update_tpu_vote_addr( ctx->gossip, &ctx->tpu_vote_my_addr );
  fd_gossip_settime( ctx->gossip, fd_log_wallclock() );
  fd_gossip_start( ctx->gossip );

  FD_LOG_NOTICE(( "gossip listening on port %u", tile->gossip.gossip_listen_port ));

  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ NET_IN_IDX ] ];

  ctx->net_in_mem    = topo->workspaces[ topo->objs[ netmux_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_in_chunk  = fd_disco_compact_chunk0( ctx->net_in_mem );
  ctx->net_in_wmark  = fd_disco_compact_wmark( ctx->net_in_mem, netmux_link->mtu );
  
  /* Set up shred contact info tile output */
  fd_topo_link_t * shred_contact_out = &topo->links[ tile->out_link_id[ SHRED_OUT_IDX ] ];
  ctx->shred_contact_out_mcache      = shred_contact_out->mcache;
  ctx->shred_contact_out_sync        = fd_mcache_seq_laddr( ctx->shred_contact_out_mcache );
  ctx->shred_contact_out_depth       = fd_mcache_depth( ctx->shred_contact_out_mcache );
  ctx->shred_contact_out_seq         = fd_mcache_seq_query( ctx->shred_contact_out_sync );
  ctx->shred_contact_out_mem         = topo->workspaces[ topo->objs[ shred_contact_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->shred_contact_out_chunk0      = fd_dcache_compact_chunk0( ctx->shred_contact_out_mem, shred_contact_out->dcache );
  ctx->shred_contact_out_wmark       = fd_dcache_compact_wmark ( ctx->shred_contact_out_mem, shred_contact_out->dcache, shred_contact_out->mtu );
  ctx->shred_contact_out_chunk       = ctx->shred_contact_out_chunk0;

  /* Set up repair contact info tile output */
  fd_topo_link_t * repair_contact_out = &topo->links[ tile->out_link_id[ REPAIR_OUT_IDX ] ];
  ctx->repair_contact_out_mcache      = repair_contact_out->mcache;
  ctx->repair_contact_out_sync        = fd_mcache_seq_laddr( ctx->repair_contact_out_mcache );
  ctx->repair_contact_out_depth       = fd_mcache_depth( ctx->repair_contact_out_mcache );
  ctx->repair_contact_out_seq         = fd_mcache_seq_query( ctx->repair_contact_out_sync );
  ctx->repair_contact_out_mem         = topo->workspaces[ topo->objs[ repair_contact_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->repair_contact_out_chunk0      = fd_dcache_compact_chunk0( ctx->repair_contact_out_mem, repair_contact_out->dcache );
  ctx->repair_contact_out_wmark       = fd_dcache_compact_wmark ( ctx->repair_contact_out_mem, repair_contact_out->dcache, repair_contact_out->mtu );
  ctx->repair_contact_out_chunk       = ctx->repair_contact_out_chunk0;

  /* Set up repair contact info tile output */
  fd_topo_link_t * pack_out = &topo->links[ tile->out_link_id[ PACK_OUT_IDX ] ];
  ctx->pack_out_mcache      = pack_out->mcache;
  ctx->pack_out_sync        = fd_mcache_seq_laddr( ctx->pack_out_mcache );
  ctx->pack_out_depth       = fd_mcache_depth( ctx->pack_out_mcache );
  ctx->pack_out_seq         = fd_mcache_seq_query( ctx->pack_out_sync );
  ctx->pack_out_mem         = topo->workspaces[ topo->objs[ pack_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_out_chunk0      = fd_dcache_compact_chunk0( ctx->pack_out_mem, pack_out->dcache );
  ctx->pack_out_wmark       = fd_dcache_compact_wmark ( ctx->pack_out_mem, pack_out->dcache, pack_out->mtu );
  ctx->pack_out_chunk       = ctx->pack_out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top>( (ulong)scratch + scratch_footprint( tile ) ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

}

static ulong
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_gossip( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_gossip_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch      FD_PARAM_UNUSED,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_gossip = {
  .name                     = "gossip",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
