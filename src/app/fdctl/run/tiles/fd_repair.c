#define _GNU_SOURCE 

#include "tiles.h"

#include "generated/repair_seccomp.h"
#include "../../../../flamenco/repair/fd_repair.h"
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
#define CONTACT_IN_IDX  1
#define SIGN_IN_IDX     2

#define NET_OUT_IDX     0
#define SIGN_OUT_IDX    1

#define MAX_REPAIR_PEERS 40200UL

struct __attribute__((packed)) fd_shred_dest_wire {
  fd_pubkey_t pubkey[1];
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


struct fd_repair_tile_ctx {
  fd_repair_t * repair;
  fd_repair_config_t repair_config;

  fd_repair_peer_addr_t repair_my_intake_addr;
  fd_repair_peer_addr_t repair_my_serve_addr;
  ushort                repair_listen_port;

  uchar       identity_private_key[ 32 ];
  fd_pubkey_t identity_public_key;

  fd_wksp_t * wksp;

  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

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

  uchar src_mac_addr[6];

  /* Includes Ethernet, IP, UDP headers */
  ulong repair_buffer_sz;
  uchar repair_buffer[ FD_NET_MTU ];

  fd_keyguard_client_t keyguard_client[1];
};
typedef struct fd_repair_tile_ctx fd_repair_tile_ctx_t;

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
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_repair_align(), fd_repair_footprint() );
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
  populate_packet_header_template( hdr, payload_sz, ctx->repair_my_serve_addr.addr, mac, ctx->repair_listen_port );

  hdr->udp->net_dport = port;

  memcpy( hdr->eth->dst, mac, 6UL );
  memcpy( hdr->ip4->daddr_c, &ip, 4UL );

  // TODO: LML handle checksum correctly
  hdr->ip4->check = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4 ) );

  ulong packet_sz = payload_sz + sizeof(eth_ip_udp_t);
  fd_memcpy( packet+sizeof(eth_ip_udp_t), payload, payload_sz );

  fd_udp_hdr_t udp_hdr = *hdr->udp;
  hdr->udp->check = fd_ip4_udp_check( *(uint *)hdr->ip4->saddr_c, *(uint *)hdr->ip4->daddr_c, &udp_hdr, packet + sizeof(eth_ip_udp_t));

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = fd_disco_netmux_sig( ip, port, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_GOSSIP, (ushort)0 );
  fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig,ctx->net_out_chunk, packet_sz, 0UL, tsorig, tspub );
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

static void 
repair_send_packet( uchar const * msg, 
                    size_t msglen, 
                    fd_gossip_peer_addr_t const * addr, 
                    void * arg ) {
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  send_packet( arg, addr->addr, addr->port, msg, msglen, tsorig );
}

static void
repair_shred_deliver_fun( fd_shred_t const * shred,
                          ulong shred_len, 
                          fd_repair_peer_addr_t const * from, 
                          fd_pubkey_t const * id, 
                          void * arg ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)arg;

  (void)shred;
  (void)shred_len;
  (void)from;
  (void)id;
  (void)ctx;
}

void
repair_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *) signer_ctx;
  fd_keyguard_client_sign( ctx->keyguard_client, signature, buffer, len );
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)seq;

  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  if( FD_LIKELY( in_idx==NET_IN_IDX ) ) {
    *opt_filter = fd_disco_netmux_sig_port( sig )!=ctx->repair_listen_port;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;

  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->contact_in_chunk0 || chunk>ctx->contact_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->contact_in_chunk0, ctx->contact_in_wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry );
    return;
  }

  
  if( FD_UNLIKELY( chunk<ctx->chunk || chunk>ctx->wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->chunk, ctx->wmark ));
    *opt_filter = 1;
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->net_in, chunk );
  ulong  hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
  ushort port = fd_disco_netmux_sig_port( sig );
  FD_TEST( hdr_sz < sz ); /* Should be ensured by the net tile */
  uchar * pkt;
  ulong * pkt_sz;
  if( FD_UNLIKELY( port==ctx->repair_listen_port ) ) {
    pkt = ctx->repair_buffer;
    pkt_sz = &ctx->repair_buffer_sz;
  } else {
    FD_LOG_ERR(( "port %u not handled %lu", port, in_idx ));
    *opt_filter = 1;
    return;
  }

  *pkt_sz = sz;
  fd_memcpy( pkt, dcache_entry, *pkt_sz );
  // fd_memcpy( pkt, dcache_entry+hdr_sz, sz-hdr_sz );
  // ctx->shred_buffer_sz = sz-hdr_sz;
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
  (void)opt_sz;
  (void)opt_filter;
  (void)mux;
  (void)seq;
  (void)opt_tsorig;

  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    return;
  }

  *opt_filter = 1;

  uint   ip = fd_disco_netmux_sig_ip_addr( *opt_sig );
  ushort port = fd_disco_netmux_sig_port( *opt_sig );
  // uint ip = 2471188301; // 147.75.199.41
  if( FD_UNLIKELY( port==ctx->repair_listen_port ) ) {
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
    eth_ip_udp_t * hdr = (eth_ip_udp_t *)ctx->repair_buffer;

    fd_repair_peer_addr_t peer_addr;
    peer_addr.l = 0;
    peer_addr.addr = ip;
    peer_addr.port = hdr->udp->net_sport;

    fd_repair_settime( ctx->repair, fd_log_wallclock() );
    fd_repair_continue( ctx->repair );
    fd_repair_recv_packet( ctx->repair, ctx->repair_buffer + hdr_sz, ctx->repair_buffer_sz - hdr_sz, &peer_addr );
  } else {
    FD_LOG_ERR(( "port %u not handled %lu", port, in_idx ));
    *opt_filter = 1;
    return;
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;
}

static void
during_housekeeping( void * _ctx ) {
  fd_repair_tile_ctx_t * ctx = (fd_repair_tile_ctx_t *)_ctx;

  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_continue( ctx->repair );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( tile->in_cnt != 3 ||
                   topo->links[ tile->in_link_id[ NET_IN_IDX     ] ].kind != FD_TOPO_LINK_KIND_NETMUX_TO_OUT    ||
                   topo->links[ tile->in_link_id[ CONTACT_IN_IDX ] ].kind != FD_TOPO_LINK_KIND_GOSSIP_TO_REPAIR ||
                   topo->links[ tile->in_link_id[ SIGN_IN_IDX ] ].kind != FD_TOPO_LINK_KIND_SIGN_TO_REPAIR ) )
    FD_LOG_ERR(( "repair tile has none or unexpected input links %lu", tile->in_cnt ));

  if( FD_UNLIKELY( tile->out_cnt != 2 ||
                   topo->links[ tile->out_link_id[ NET_OUT_IDX ] ].kind != FD_TOPO_LINK_KIND_REPAIR_TO_NETMUX ||
                   topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ].kind != FD_TOPO_LINK_KIND_REPAIR_TO_SIGN ) )
    FD_LOG_ERR(( "repair tile has none or unexpected output links %lu %lu %lu", tile->out_cnt ));
      
  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "repair tile has no primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_repair_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_tile_ctx_t), sizeof(fd_repair_tile_ctx_t) );
  ctx->repair = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(), fd_repair_footprint() );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  
  ctx->wksp = topo->workspaces[ tile->wksp_id ].wksp;

  void * alloc_shmem = fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { 
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); 
  }
  
  ctx->repair_listen_port = tile->repair.repair_listen_port;

  FD_TEST( ctx->repair_listen_port!=0 );

  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ 0 ] ];

  ctx->net_in    = topo->workspaces[ netmux_link->wksp_id ].wksp;
  ctx->chunk  = fd_disco_compact_chunk0( ctx->net_in );
  ctx->wmark  = fd_disco_compact_wmark ( ctx->net_in, netmux_link->mtu );

  // TODO: make configurable
  FD_TEST( getrandom( ctx->identity_private_key, 32UL, 0 ) == 32UL );
  fd_sha512_t sha[1];
  FD_TEST( fd_ed25519_public_from_private( ctx->identity_public_key.uc, ctx->identity_private_key, sha ) );

  FD_LOG_NOTICE(( "gossip starting - identity: %32J", ctx->identity_public_key.key ));

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id_primary ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ net_out->wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_memcpy( ctx->src_mac_addr, tile->gossip.src_mac_addr, 6 );
  /* Set up contact info tile output */

  fd_topo_link_t * contact_in_link   = &topo->links[ tile->in_link_id[ CONTACT_IN_IDX ] ];
  ctx->contact_in_mem    = topo->workspaces[ contact_in_link->wksp_id ].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark ( ctx->contact_in_mem, contact_in_link->dcache, contact_in_link->mtu );

  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ SIGN_IN_IDX ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  if ( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                        sign_out->mcache,
                                                        sign_out->dcache,
                                                        sign_in->mcache,
                                                        sign_in->dcache ) ) == NULL ) {
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

  // TODO: actually get a reasonable seed
  ulong seed = 42;
  ctx->repair = fd_repair_join( fd_repair_new( ctx->repair, seed, valloc ) );

  FD_LOG_NOTICE(( "repair my addr - intake addr: %s, serve_addr: %s", tile->repair.repair_my_intake_addr, tile->repair.repair_my_serve_addr ));
  FD_TEST( resolve_hostport( tile->repair.repair_my_intake_addr, &ctx->repair_my_intake_addr ) );
  FD_TEST( resolve_hostport( tile->repair.repair_my_serve_addr, &ctx->repair_my_serve_addr ) );

  ctx->repair_config.private_key = ctx->identity_private_key;
  ctx->repair_config.public_key = &ctx->identity_public_key;
  ctx->repair_config.fun_arg = ctx;
  ctx->repair_config.deliver_fun = repair_shred_deliver_fun;
  ctx->repair_config.send_fun = repair_send_packet;
  ctx->repair_config.sign_fun = repair_signer;
  ctx->repair_config.sign_arg = ctx;

  if( fd_repair_set_config( ctx->repair, &ctx->repair_config ) ) {
    FD_LOG_ERR( ( "error setting gossip config" ) );
  }

  fd_repair_update_addr( ctx->repair, &ctx->repair_my_intake_addr, &ctx->repair_my_serve_addr );

  fd_repair_settime( ctx->repair, fd_log_wallclock() );
  fd_repair_start( ctx->repair );

  FD_LOG_NOTICE(( "repair listening on port %u", tile->repair.repair_listen_port ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_repair( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_repair_instr_cnt;
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

fd_tile_config_t fd_tile_repair = {
  .mux_flags                = FD_MUX_FLAG_COPY,
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
