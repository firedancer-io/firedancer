#define _GNU_SOURCE 

#include "tiles.h"

#include "generated/gossip_seccomp.h"
#include "../../../../flamenco/gossip/fd_gossip.h"
#include "../../../../util/fd_util.h"

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

#define SHRED_OUT_IDX   0
#define REPAIR_OUT_IDX  0
#define NET_OUT_IDX     0

struct __attribute__((packed)) fd_shred_dest_wire {
  uchar  pubkey[32];
  /* The Labs splice writes this as octets, which means when we read
     this, it's essentially network byte order */
  uint   ip4_addr;
  ushort udp_port;
};
typedef struct fd_shred_dest_wire fd_shred_dest_wire_t;

struct fd_contact_info_elem {
  fd_pubkey_t key;
  ulong next;
  fd_gossip_contact_info_v1_t contact_info;
};
typedef struct fd_contact_info_elem fd_contact_info_elem_t;

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

  fd_contact_info_elem_t * contact_info_table;

  // fd_frag_meta_t * shred_contact_out_mcache;
  // ulong *          shred_contact_out_sync;
  // ulong            shred_contact_out_depth;
  // ulong            shred_contact_out_seq;

  // fd_wksp_t * shred_contact_out_mem;
  // ulong       shred_contact_out_chunk0;
  // ulong       shred_contact_out_wmark;
  // ulong       shred_contact_out_chunk;

  // fd_frag_meta_t * repair_contact_out_mcache;
  // ulong *          repair_contact_out_sync;
  // ulong            repair_contact_out_depth;
  // ulong            repair_contact_out_seq;

  // fd_wksp_t * repair_contact_out_mem;
  // ulong       repair_contact_out_chunk0;
  // ulong       repair_contact_out_wmark;
  // ulong       repair_contact_out_chunk;

  long last_spam_time;
  fd_rng_t rng[1];

  fd_mux_context_t * mux_ctx;
};
typedef struct fd_gossip_tile_ctx fd_gossip_tile_ctx_t;

static fd_wksp_t *     g_wksp = NULL;
static char            g_gossip_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
static char            g_gossip_my_addr[ 22 ];   // len('255.255.255.255:65535') == 22
static ushort          g_gossip_listen_port;

/* Inspired from tiles/fd_shred.c */
static fd_wksp_t *     g_net_in;
static ulong           g_chunk;
static ulong           g_wmark;

static fd_frag_meta_t * g_net_out_mcache;
static ulong *          g_net_out_sync;
static ulong            g_net_out_depth;
static ulong            g_net_out_seq;

static fd_wksp_t * g_net_out_mem;
static ulong       g_net_out_chunk0;
static ulong       g_net_out_wmark;
static ulong       g_net_out_chunk;

static uchar         g_identity_private_key[32];
static fd_pubkey_t   g_identity_public_key;

static uchar              g_src_mac_addr[6];

static ulong g_num_packets_sent;

/* Includes Ethernet, IP, UDP headers */
static uchar g_gossip_buffer[ FD_NET_MTU ];

static fd_gossip_peer_addr_t *
resolve_hostport( const char * str /* host:port */, fd_gossip_peer_addr_t * res ) {
  fd_memset( res, 0, sizeof( fd_gossip_peer_addr_t ) );

  /* Find the : and copy out the host */
  char buf[128];
  uint i;
  for( i = 0;; ++i ) {
    if( str[i] == '\0' || i > sizeof( buf ) - 1U ) {
      FD_LOG_ERR( ( "missing colon" ) );
      return NULL;
    }
    if( str[i] == ':' ) {
      buf[i] = '\0';
      break;
    }
    buf[i] = str[i];
  }
  if( i == 0 ) /* :port means $HOST:port */
    gethostname( buf, sizeof( buf ) );

  struct hostent * host = gethostbyname( buf );
  if( host == NULL ) {
    FD_LOG_WARNING( ( "unable to resolve host %s", buf ) );
    return NULL;
  }
  /* Convert result to repair address */
  res->l    = 0;
  res->addr = ( (struct in_addr *)host->h_addr )->s_addr;
  int port  = atoi( str + i + 1 );
  if( ( port > 0 && port < 1024 ) || port > (int)USHORT_MAX ) {
    FD_LOG_ERR( ( "invalid port number" ) );
    return NULL;
  }
  res->port = htons( (ushort)port );

  return res;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;

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

#ifdef FD_GOSSIP_DEMO
  pkt->udp->net_sport = fd_ushort_bswap( src_port ) + (ushort)(g_num_packets_sent % 4U);
#else
  pkt->udp->net_sport = fd_ushort_bswap( src_port );
#endif
  pkt->udp->net_dport = (ushort)0; /* varies by shred */
  pkt->udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  pkt->udp->check     = (ushort)0;
}

static void
send_packet( fd_gossip_tile_ctx_t * ctx,
             uint    ip,
             ushort  port,
             uchar const * payload,
             ulong   payload_sz,
             ulong   tsorig ) {
  uchar * packet = fd_chunk_to_laddr( g_net_out_mem, g_net_out_chunk );

  eth_ip_udp_t * hdr = (eth_ip_udp_t *)packet;
  memset(packet, 0, sizeof(eth_ip_udp_t));
  uchar mac[6] = {0};
  populate_packet_header_template( hdr, payload_sz, ctx->gossip_config.my_addr.addr, mac, g_gossip_listen_port );

  hdr->udp->net_dport = port;

  memcpy( hdr->eth->dst, mac, 6UL );
  memcpy( hdr->ip4->daddr_c, &ip, 4UL );

  // TODO: LML handle checksum correctly
  hdr->ip4->check = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4 ) );
 
  ulong packet_sz = payload_sz + sizeof(eth_ip_udp_t);
  fd_memcpy( packet+sizeof(eth_ip_udp_t), payload, payload_sz );

  hdr->udp->check = fd_ip4_udp_check( *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->saddr_c ), 
                                      *(uint *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4->daddr_c ), 
                                      (fd_udp_hdr_t const *)FD_ADDRESS_OF_PACKED_MEMBER( hdr->udp ), 
                                      packet + sizeof(eth_ip_udp_t) );

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = fd_disco_netmux_sig( ip, port, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_GOSSIP, (ushort)0 );
  // fd_mcache_publish( g_net_out_mcache, g_net_out_depth, g_net_out_seq, sig, g_net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  // g_net_out_seq   = fd_seq_inc( g_net_out_seq, 1UL );
  // g_net_out_chunk = fd_dcache_compact_next( g_net_out_chunk, packet_sz, g_net_out_chunk0, g_net_out_wmark );
  fd_mux_publish( ctx->mux_ctx, sig, g_net_out_chunk, packet_sz, 0UL, tsorig, tspub );
  g_net_out_chunk = fd_dcache_compact_next( g_net_out_chunk, packet_sz, g_net_out_chunk0, g_net_out_wmark );
}

static void 
gossip_send_packet( uchar const * msg, 
                    size_t msglen, 
                    fd_gossip_peer_addr_t const * addr, 
                    void * arg ) {
  g_num_packets_sent++;
/*
  if(g_num_packets_sent > 1) {
    return;
  }
  */
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, addr->addr, addr->port, msg, msglen, tsorig );
}


static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)arg;

  if( fd_crds_data_is_contact_info_v1( data ) ) {
    fd_gossip_contact_info_v1_t const * contact_info = &data->inner.contact_info_v1;

    // TODO: what to do when the contact table is full?
    fd_contact_info_elem_t * ele = fd_contact_info_table_query( ctx->contact_info_table, &contact_info->id, NULL );
    if( ele == NULL ) {
      /* Insert the element */
      ele = fd_contact_info_table_insert( ctx->contact_info_table, &contact_info->id );
      FD_LOG_NOTICE(("contact info v1 - ip: " FD_IP4_ADDR_FMT ", port: %u", FD_IP4_ADDR_FMT_ARGS( contact_info->gossip.addr.inner.ip4 ), contact_info->gossip.port ));
    }

    ele->contact_info = *contact_info;
  }
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)_ctx;
  (void)in_idx;
  (void)seq;

  if( fd_disco_netmux_sig_src_tile( sig ) != SRC_TILE_NET ) {
    *opt_filter = 1;
    return;
  }
  
  ushort port = fd_disco_netmux_sig_port( sig );
  *opt_filter = !(port==g_gossip_listen_port);
}

static void
during_frag( void * ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)ctx;
  (void)in_idx;
  (void)sig;
  (void)chunk;
  (void)sz;
  
  if( FD_UNLIKELY( chunk<g_chunk || chunk>g_wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, g_chunk, g_wmark ));
    *opt_filter = 1;
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( g_net_in, chunk );
  ulong  hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
  ushort port = fd_disco_netmux_sig_port( sig );
  FD_TEST( hdr_sz < sz ); /* Should be ensured by the net tile */
  uchar * pkt;
  if( FD_UNLIKELY( port==g_gossip_listen_port ) ) {
    pkt = g_gossip_buffer;
  } else {
    FD_LOG_ERR(( "port %u not handled", port ));
    *opt_filter = 1;
    return;
  }

  fd_memcpy( pkt, dcache_entry, sz );
  *opt_filter = 0;

  return;
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)opt_chunk;
  (void)opt_filter;
  (void)mux;
  (void)seq;
  (void)opt_tsorig;

  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;

  ctx->mux_ctx = mux;

  uint   ip = fd_disco_netmux_sig_ip_addr( *opt_sig );
  ushort port = fd_disco_netmux_sig_port( *opt_sig );
  // uint ip = 2471188301; // 147.75.199.41
  if( FD_UNLIKELY( port==g_gossip_listen_port ) ) {
    *opt_filter = 0;
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
    eth_ip_udp_t * hdr = (eth_ip_udp_t *)g_gossip_buffer;

    fd_gossip_peer_addr_t peer_addr;
    peer_addr.l = 0;
    peer_addr.addr = ip;
    peer_addr.port = hdr->udp->net_sport;

    fd_gossip_recv_packet( ctx->gossip, g_gossip_buffer + hdr_sz, *opt_sz - hdr_sz, &peer_addr );
  } else {
    FD_LOG_ERR(( "port %u not handled", port ));
    *opt_filter = 1;
    return;
  }
}

static void
after_credit( void * _ctx, fd_mux_context_t * mux_ctx ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;

  ctx->mux_ctx = mux_ctx;
  long now = fd_log_wallclock();
  g_num_packets_sent = 0;
  fd_gossip_settime( ctx->gossip, now );
  fd_gossip_continue( ctx->gossip );

 
#ifdef FD_GOSSIP_DEMO
  if( now - ctx->last_shred_dest_push_time > (long)1e6 ) {
    ctx->last_shred_dest_push_time = now;
    if(fd_contact_info_table_key_cnt( ctx->contact_info_table ) != 0) {
      fd_slot_hash_t slot_hashes[16];
      for( ulong i = 0; i < 16; i++ ) {
        slot_hashes[i].slot = fd_rng_ulong(ctx->rng);
        memset(slot_hashes[i].hash.uc, 0, sizeof(fd_hash_t));
      }
      
      fd_crds_data_t crds_data;
      fd_crds_data_new_disc( &crds_data, fd_crds_data_enum_accounts_hashes );
      memcpy( crds_data.inner.accounts_hashes.from.key, ctx->gossip_config.public_key, sizeof(fd_pubkey_t) );
      crds_data.inner.accounts_hashes.hashes_len = 16;
      crds_data.inner.accounts_hashes.hashes = slot_hashes;
      crds_data.inner.accounts_hashes.wallclock =  (ulong)fd_log_wallclock( ) / (ulong)1000000;

      fd_gossip_push_value( ctx->gossip, &crds_data, NULL );
    }
  }
#endif
}

static void
during_housekeeping( void * _ctx ) {
  fd_gossip_tile_ctx_t * ctx = (fd_gossip_tile_ctx_t *)_ctx;
  (void)ctx;
  // fd_mcache_seq_update( ctx->shred_contact_out_sync, ctx->shred_contact_out_seq );
  // fd_mcache_seq_update( ctx->repair_contact_out_sync, ctx->repair_contact_out_seq );
  // fd_mcache_seq_update( g_net_out_sync, g_net_out_seq );
} 

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;

  g_wksp = topo->workspaces[ tile->wksp_id ].wksp;
  
  strncpy( g_gossip_peer_addr, tile->gossip.gossip_peer_addr, sizeof(g_gossip_peer_addr) );
  strncpy( g_gossip_my_addr, tile->gossip.gossip_my_addr, sizeof(g_gossip_my_addr) );
  g_gossip_listen_port = tile->gossip.gossip_listen_port;

  FD_TEST( g_gossip_listen_port!=0 );

  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ 0 ] ];

  g_net_in    = topo->workspaces[ netmux_link->wksp_id ].wksp;
  g_chunk  = fd_disco_compact_chunk0( g_net_in );
  g_wmark  = fd_disco_compact_wmark ( g_net_in, netmux_link->mtu );

  // TODO: make configurable
  FD_TEST( getrandom( g_identity_private_key, 32UL, 0 ) == 32UL );
  fd_sha512_t sha[1];
  FD_TEST( fd_ed25519_public_from_private( g_identity_public_key.uc, g_identity_private_key, sha ) );

  FD_LOG_NOTICE(( "gossip starting - identity: %32J", g_identity_public_key.key ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( tile->in_cnt != 1 ||
                   topo->links[ tile->in_link_id[ NET_IN_IDX     ] ].kind != FD_TOPO_LINK_KIND_DEDUP_TO_GOSSIP ) ) {
    FD_LOG_ERR(( "gossip tile has none or unexpected input links %lu %lu %lu",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].kind, topo->links[ tile->in_link_id[ 1 ] ].kind ));
  }

  // if( FD_UNLIKELY( tile->out_cnt != 1 ||
  //                  topo->links[ tile->out_link_id[ NET_OUT_IDX ] ].kind != FD_TOPO_LINK_KIND_GOSSIP_TO_NETMUX ) ) {
  //   FD_LOG_ERR(( "gossip tile has none or unexpected output links %lu %lu %lu",
  //                tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].kind, topo->links[ tile->out_link_id[ 1 ] ].kind ));
  // }

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "gossip tile has no primary output link" ));

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id_primary ];

  g_net_out_mcache = net_out->mcache;
  g_net_out_sync   = fd_mcache_seq_laddr( g_net_out_mcache );
  g_net_out_depth  = fd_mcache_depth( g_net_out_mcache );
  g_net_out_seq    = fd_mcache_seq_query( g_net_out_sync );
  g_net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  g_net_out_mem    = topo->workspaces[ net_out->wksp_id ].wksp;
  g_net_out_wmark  = fd_dcache_compact_wmark ( g_net_out_mem, net_out->dcache, net_out->mtu );
  g_net_out_chunk  = g_net_out_chunk0;

  fd_memcpy( g_src_mac_addr, tile->gossip.src_mac_addr, 6 );

  void * alloc_shmem = fd_wksp_alloc_laddr( g_wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { 
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); 
  }

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossip_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossip_tile_ctx_t), sizeof(fd_gossip_tile_ctx_t) );
  ctx->gossip = FD_SCRATCH_ALLOC_APPEND( l, fd_gossip_align(), fd_gossip_footprint() );
  ctx->contact_info_table = fd_contact_info_table_join( fd_contact_info_table_new( FD_SCRATCH_ALLOC_APPEND( l, fd_contact_info_table_align(), fd_contact_info_table_footprint( FD_PEER_KEY_MAX ) ), FD_PEER_KEY_MAX, 0 ) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->last_shred_dest_push_time = 0;
  ctx->last_spam_time = 0;
  g_num_packets_sent = 0;

  // /* Set up shred contact info tile output */
  // fd_topo_link_t * shred_contact_out = &topo->links[ tile->out_link_id[ 0 ] ];
  // ctx->shred_contact_out_mcache = shred_contact_out->mcache;
  // ctx->shred_contact_out_sync   = fd_mcache_seq_laddr( ctx->shred_contact_out_mcache );
  // ctx->shred_contact_out_depth  = fd_mcache_depth( ctx->shred_contact_out_mcache );
  // ctx->shred_contact_out_seq    = fd_mcache_seq_query( ctx->shred_contact_out_sync );
  // ctx->shred_contact_out_mem    = topo->workspaces[ shred_contact_out->wksp_id ].wksp;
  // ctx->shred_contact_out_chunk0 = fd_dcache_compact_chunk0( ctx->shred_contact_out_mem, shred_contact_out->dcache );
  // ctx->shred_contact_out_wmark  = fd_dcache_compact_wmark ( ctx->shred_contact_out_mem, shred_contact_out->dcache, shred_contact_out->mtu );
  // ctx->shred_contact_out_chunk  = ctx->shred_contact_out_chunk0;

  // /* Set up repair contact info tile output */
  // fd_topo_link_t * repair_contact_out = &topo->links[ tile->out_link_id[ 1 ] ];
  // ctx->repair_contact_out_mcache = repair_contact_out->mcache;
  // ctx->repair_contact_out_sync   = fd_mcache_seq_laddr( ctx->repair_contact_out_mcache );
  // ctx->repair_contact_out_depth  = fd_mcache_depth( ctx->repair_contact_out_mcache );
  // ctx->repair_contact_out_seq    = fd_mcache_seq_query( ctx->repair_contact_out_sync );
  // ctx->repair_contact_out_mem    = topo->workspaces[ repair_contact_out->wksp_id ].wksp;
  // ctx->repair_contact_out_chunk0 = fd_dcache_compact_chunk0( ctx->repair_contact_out_mem, repair_contact_out->dcache );
  // ctx->repair_contact_out_wmark  = fd_dcache_compact_wmark ( ctx->repair_contact_out_mem, repair_contact_out->dcache, repair_contact_out->mtu );
  // ctx->repair_contact_out_chunk  = ctx->repair_contact_out_chunk0;

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
  ctx->gossip = fd_gossip_join( fd_gossip_new( ctx->gossip, seed, valloc ) );

  FD_LOG_NOTICE(( "gossip my addr - addr: %s", g_gossip_my_addr ));
  FD_TEST( resolve_hostport( g_gossip_my_addr, &ctx->gossip_config.my_addr ) );
  ctx->gossip_config.private_key = g_identity_private_key;
  ctx->gossip_config.public_key = &g_identity_public_key;
  ctx->gossip_config.fun_arg = ctx;
  ctx->gossip_config.deliver_fun = gossip_deliver_fun;
  ctx->gossip_config.send_fun = gossip_send_packet;
#ifdef FD_GOSSIP_DEMO
  ctx->gossip_config.shred_version = 4242;
#else
  ctx->gossip_config.shred_version = 0;
#endif

  if( fd_gossip_set_config( ctx->gossip, &ctx->gossip_config ) ) {
    FD_LOG_ERR( ( "error setting gossip config" ) );
  }

  fd_gossip_peer_addr_t gossip_peer_addr;
  FD_LOG_NOTICE(( "gossip initial peer - addr: %s", g_gossip_peer_addr ));
  if( fd_gossip_add_active_peer( ctx->gossip, resolve_hostport( g_gossip_peer_addr, &gossip_peer_addr ) ) ) {
    FD_LOG_ERR( ( "error adding gossip active peer" ) );
  }

  fd_gossip_update_addr( ctx->gossip, &ctx->gossip_config.my_addr );

  fd_gossip_peer_addr_t tvu_my_addr;
  fd_gossip_peer_addr_t tvu_my_fwd_addr;
  if( resolve_hostport( tile->gossip.tvu_my_addr, &tvu_my_addr ) == NULL ) {
    FD_LOG_ERR( ( "error parsing tvu addr" ) );
  }

  if( resolve_hostport( tile->gossip.tvu_my_fwd_addr, &tvu_my_fwd_addr ) == NULL ) {
    FD_LOG_ERR(( "error parsing tvu fwd addr" ) );
  }

  fd_rng_join( fd_rng_new( ctx->rng, 42, 0UL ) );

  fd_gossip_update_tvu_addr( ctx->gossip, &tvu_my_addr, &tvu_my_fwd_addr );
  fd_gossip_settime( ctx->gossip, fd_log_wallclock() );
  fd_gossip_start( ctx->gossip );

  FD_LOG_NOTICE(( "gossip listening on port %u", tile->gossip.gossip_listen_port ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_gossip( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_gossip_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_tile_config_t fd_tile_gossip = {
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .mux_during_housekeeping  = during_housekeeping,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .mux_after_credit         = after_credit,
};
