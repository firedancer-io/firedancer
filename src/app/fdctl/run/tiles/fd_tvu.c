#include "tiles.h"

#include "../../../../disco/tvu/fd_tvu.h"

#include "generated/tvu_seccomp.h"

#include <linux/unistd.h>
#include "../../../../flamenco/fd_flamenco.h"

fd_wksp_t *     g_wksp = NULL;
char            g_repair_peer_id[ FD_BASE58_ENCODED_32_SZ ];
char            g_repair_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_gossip_peer_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_my_gossip_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_my_repair_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_tvu_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_tvu_fwd_addr[ 22 ]; // len('255.255.255.255:65535') == 22
char            g_load[ PATH_MAX ];
char            g_snapshot[ PATH_MAX ];
char            g_incremental_snapshot[ PATH_MAX ];
char            g_validate_snapshot[ 22 ];
char            g_check_hash[ 22 ];
char            g_shredlog_fpath[ PATH_MAX ];
uint            g_page_cnt;
ushort          g_gossip_listen_port;
ushort          g_repair_listen_port;
ushort          g_tvu_port;
ushort          g_tvu_fwd_port;
ushort          g_rpc_listen_port;

/* Inspired from tiles/fd_shred.c */
fd_wksp_t *     g_net_in;
ulong           g_chunk;
ulong           g_wmark;

fd_frag_meta_t * g_net_out_mcache;
ulong *          g_net_out_sync;
ulong            g_net_out_depth;
ulong            g_net_out_seq;

fd_wksp_t * g_net_out_mem;
ulong       g_net_out_chunk0;
ulong       g_net_out_wmark;
ulong       g_net_out_chunk;

/* Includes Ethernet, IP, UDP headers */
ulong g_shred_buffer_sz;
uchar g_shred_buffer[ FD_NET_MTU ];
ulong g_gossip_buffer_sz;
uchar g_gossip_buffer[ FD_NET_MTU ];
ulong g_repair_buffer_sz;
uchar g_repair_buffer[ FD_NET_MTU ];
ulong g_tvu_buffer_sz;
uchar g_tvu_buffer[ FD_NET_MTU ];
ulong g_tvu_fwd_buffer_sz;
uchar g_tvu_fwd_buffer[ FD_NET_MTU ];

fd_topo_link_t * g_sign_in = NULL;
fd_topo_link_t * g_sign_out = NULL;
uchar const * g_identity_key = NULL;

typedef struct {
  int socket_fd;
} fd_tvu_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t *tile ) {
  return tile->tvu.page_cnt * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t *tile ) {
  (void)tile;
  return 4096UL;
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_tvu_ctx_t ) );
}

#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"

typedef struct __attribute__((packed)) {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];
} eth_ip_udp_t;

static void
send_packet( ulong   ip,
             ushort  port,
             uchar * payload,
             ulong   payload_sz,
             ulong   tsorig ) {
  (void)port;
  uchar * packet = fd_chunk_to_laddr( g_net_out_mem, g_net_out_chunk );

  eth_ip_udp_t * hdr = (eth_ip_udp_t *)payload;
  
  // swap ports
  ushort tmp_port = hdr->udp->net_dport;
  hdr->udp->net_dport = hdr->udp->net_sport;
  hdr->udp->net_sport = tmp_port;

  // // set mac address
  // hdr->eth->src[0] = 0x40;
  // hdr->eth->src[1] = 0xa6;
  // hdr->eth->src[2] = 0xb7;
  // hdr->eth->src[3] = 0x20;
  // hdr->eth->src[4] = 0x3b;
  // hdr->eth->src[5] = 0xb0;

  // hdr->eth->dst[0] = 0x40;
  // hdr->eth->dst[1] = 0xa6;
  // hdr->eth->dst[2] = 0xb7;
  // hdr->eth->dst[3] = 0x20;
  // hdr->eth->dst[4] = 0x3b;
  // hdr->eth->dst[5] = 0xb0;

  // TODO: LML handle checksum correctly
  // hdr->ip4->check = 0;
  hdr->udp->check = 0;
  // hdr->ip4->check      = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4 ) );

  fd_memcpy( packet, payload, payload_sz );

  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  // ulong sig  = fd_disco_netmux_sig( ip, port, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_TVU, (ushort)0 );
  (void)ip;
  // TODO: LML why is this not routing to lo correctly? Must set the IP address to 127.0.0.1 explicitly
  // ulong sig  = fd_disco_netmux_sig( FD_IP4_ADDR(127, 0, 0, 1), port, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_TVU, (ushort)0 );
  ulong sig  = fd_disco_netmux_sig( FD_IP4_ADDR(147,75,199,41), port, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_TVU, (ushort)0 );

  // TODO: does changing this port break the feedback?
  // ulong sig  = fd_disco_netmux_sig( FD_IP4_ADDR(127, 0, 0, 1), hdr->udp->net_dport, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_TVU, (ushort)0 );

  fd_mcache_publish( g_net_out_mcache, g_net_out_depth, g_net_out_seq, sig, g_net_out_chunk, payload_sz, 0UL, tsorig, tspub );

  g_net_out_seq   = fd_seq_inc( g_net_out_seq, 1UL );
  g_net_out_chunk = fd_dcache_compact_next( g_net_out_chunk, payload_sz, g_net_out_chunk0, g_net_out_wmark );
}

// static void
// echo_packet( uchar * payload,
//              ulong   payload_sz ) {
//   uchar * packet = fd_chunk_to_laddr( g_net_out_mem, g_net_out_chunk );

//   eth_ip_udp_t * hdr = (eth_ip_udp_t *)packet;
  
//   // fill out ethernet, ipv4, and udp headers

//   ulong packet_sz = sizeof( hdr ) + payload_sz;

//   ulong  tsorig = fd_frag_meta_ts_comp( fd_tickcount() ); // TODO: LML actually use the original timestamp
//   ulong  tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
//   ulong  ip;    // TODO: LML fill out correctly
//   ushort port; // TODO: LML fill out correctly
//   ulong  sig  = fd_disco_netmux_sig( ip, port, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_TVU, (ushort)0 );
//   fd_mcache_publish( g_net_out_mcache, g_net_out_depth, g_net_out_seq, sig, g_net_out_chunk, packet_sz, 0UL, tsorig, tspub );
//   g_net_out_seq   = fd_seq_inc( g_net_out_seq, 1UL );
//   g_net_out_chunk = fd_dcache_compact_next( g_net_out_chunk, pkt_sz, g_net_out_chunk0, g_net_out_wmark );
// }

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)_ctx;
  (void)in_idx;
  (void)seq;

  if( fd_disco_netmux_sig_src_tile( sig )!=SRC_TILE_NET ) {
    *opt_filter = 1;
    return;
  }

  ushort port = fd_disco_netmux_sig_port( sig );
  *opt_filter = !(port==g_gossip_listen_port ||
                  port==g_repair_listen_port ||
                  port==g_tvu_port ||
                  port==g_tvu_fwd_port);
}

static void
during_frag( void * ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)ctx;
  (void)in_idx;
  (void)seq;
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
  FD_LOG_NOTICE(( "received packet! port=%hu hdr_sz=%lu sz=%lu", port, hdr_sz, sz ));
  FD_TEST( hdr_sz < sz ); /* Should be ensured by the net tile */
  uchar * pkt;
  ulong * pkt_sz;
  if( FD_UNLIKELY( port==g_gossip_listen_port ) ) {
    pkt = g_gossip_buffer;
    pkt_sz = &g_gossip_buffer_sz;
    FD_LOG_NOTICE(( "received gossip! %u", g_gossip_listen_port ));
  } else if( FD_UNLIKELY( port==g_repair_listen_port ) ) {
    pkt = g_repair_buffer;
    pkt_sz = &g_repair_buffer_sz;
    FD_LOG_NOTICE(( "received repair! %u", g_repair_listen_port ));
  } else if( FD_UNLIKELY( port==g_tvu_port ) ) {
    pkt = g_tvu_buffer;
    pkt_sz = &g_tvu_buffer_sz;
    FD_LOG_NOTICE(( "received tvu! %u", g_tvu_port ));
  } else if( FD_UNLIKELY( port==g_tvu_fwd_port ) ) {
    pkt = g_tvu_fwd_buffer;
    pkt_sz = &g_tvu_fwd_buffer_sz;
    FD_LOG_NOTICE(( "received tvu_fwd! %u", g_tvu_fwd_port ));
  } else {
    FD_LOG_ERR(( "port %u not handled", port ));
    *opt_filter = 1;
    return;
  }

  *pkt_sz = sz;
  fd_memcpy( pkt, dcache_entry, *pkt_sz );
  // fd_memcpy( pkt, dcache_entry+hdr_sz, sz-hdr_sz );
  // g_shred_buffer_sz = sz-hdr_sz;
  *opt_filter = 0;

  return;
}

static void
after_frag( void *             ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)ctx;
  (void)in_idx;
  (void)seq;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_tsorig;
  (void)opt_filter;
  (void)mux;
  *opt_filter = 1;

  ushort  port = fd_disco_netmux_sig_port( *sig );

  uint ip = 2471216937; // 147.75.199.41
  (void)ip;
  (void)send_packet;
  if( FD_UNLIKELY( port==g_gossip_listen_port ) ) {
    send_packet( ip, port, g_gossip_buffer, g_gossip_buffer_sz, fd_frag_meta_ts_comp( fd_tickcount() ) );
    FD_LOG_NOTICE(( "sending gossip back! %u", g_gossip_listen_port ));
  } else if( FD_UNLIKELY( port==g_repair_listen_port ) ) {
    send_packet( ip, port, g_repair_buffer, g_repair_buffer_sz, fd_frag_meta_ts_comp( fd_tickcount() ) );
    FD_LOG_NOTICE(( "sending repair back! %u", g_repair_listen_port ));
  } else if( FD_UNLIKELY( port==g_tvu_port ) ) {
    send_packet( ip, port, g_tvu_buffer, g_tvu_buffer_sz, fd_frag_meta_ts_comp( fd_tickcount() ) );
    FD_LOG_NOTICE(( "sending tvu back! %u", g_tvu_port ));
  } else if( FD_UNLIKELY( port==g_tvu_fwd_port ) ) {
    send_packet( ip, port, g_tvu_fwd_buffer, g_tvu_fwd_buffer_sz, fd_frag_meta_ts_comp( fd_tickcount() ) );
    FD_LOG_NOTICE(( "sending tvu_fwd back! %u", g_tvu_fwd_port ));
  } else {
    FD_LOG_ERR(( "port %u not handled", port ));
    *opt_filter = 1;
    return;
  }
}

static void
during_housekeeping( void * ctx ) {
  (void)ctx;
  // gossip_housekeeping();
  // repair_housekeeping();
}

#include "../../../../util/tile/fd_tile_private.h"
/* Temporary hack until we get the tiles right */
void cpuset_hack( void ) {
  FD_CPUSET_DECL( cpu_set );
  fd_cpuset_insert( cpu_set, 25 );
  fd_cpuset_insert( cpu_set, 26 );
  fd_cpuset_insert( cpu_set, 27 );
  fd_cpuset_insert( cpu_set, 28 );

  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, cpu_set ) ) ) {
    FD_LOG_ERR(( "fd_cpuset_setaffinity failed" ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  g_wksp = topo->workspaces[ tile->wksp_id ].wksp;
  // cpuset_hack();
  
  strncpy( g_repair_peer_id, tile->tvu.repair_peer_id, sizeof(g_repair_peer_id) );
  strncpy( g_repair_peer_addr, tile->tvu.repair_peer_addr, sizeof(g_repair_peer_addr) );
  strncpy( g_gossip_peer_addr, tile->tvu.gossip_peer_addr, sizeof(g_gossip_peer_addr) );
  strncpy( g_my_gossip_addr, tile->tvu.my_gossip_addr, sizeof(g_my_gossip_addr) );
  strncpy( g_my_repair_addr, tile->tvu.my_repair_addr, sizeof(g_my_repair_addr) );
  strncpy( g_tvu_addr, tile->tvu.tvu_addr, sizeof(g_tvu_addr) );
  strncpy( g_tvu_fwd_addr, tile->tvu.tvu_fwd_addr, sizeof(g_tvu_fwd_addr) );
  strncpy( g_load, tile->tvu.load, sizeof(g_load) );
  strncpy( g_shredlog_fpath, tile->tvu.shredlog_fpath, sizeof(g_shredlog_fpath) );
  strncpy( g_snapshot, tile->tvu.snapshot, sizeof(g_snapshot) );
  strncpy( g_incremental_snapshot, tile->tvu.incremental_snapshot, sizeof(g_incremental_snapshot) );
  strncpy( g_validate_snapshot, tile->tvu.validate_snapshot, sizeof(g_validate_snapshot) );
  strncpy( g_check_hash, tile->tvu.check_hash, sizeof(g_check_hash) );
  g_page_cnt = tile->tvu.page_cnt;
  g_gossip_listen_port = tile->tvu.gossip_listen_port;
  g_repair_listen_port = tile->tvu.repair_listen_port;
  g_tvu_port = tile->tvu.tvu_port;
  g_tvu_fwd_port = tile->tvu.tvu_fwd_port;
  g_rpc_listen_port = tile->tvu.rpc_listen_port;

  FD_TEST( g_gossip_listen_port!=0 );
  FD_TEST( g_repair_listen_port!=0 );
  FD_TEST( g_tvu_port!=0 );
  FD_TEST( g_tvu_fwd_port!=0 );
  FD_TEST( g_rpc_listen_port!=0 );

  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ 0 ] ];

  uchar const * identity_key = load_key_into_protected_memory( tile->tvu.identity_key_path, /* pubkey only: */ 0 );

  g_net_in    = topo->workspaces[ netmux_link->wksp_id ].wksp;
  g_chunk  = fd_disco_compact_chunk0( g_net_in );
  g_wmark  = fd_disco_compact_wmark ( g_net_in, netmux_link->mtu );

  g_sign_in = &topo->links[ tile->in_link_id[ 1 ] ];
  g_sign_out = &topo->links[ tile->out_link_id[ 0 ] ];
  g_identity_key = identity_key;

  (void)topo;
  (void)tile;
  (void)scratch;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;

  // // if( FD_UNLIKELY( tile->out_cnt != 1 || topo->links[ tile->out_link_id[ 0 ] ].kind != FD_TOPO_LINK_KIND_TVU_TO_NETMUX ) )
  //   // FD_LOG_ERR(( "tvu tile has none or unexpected netmux output link %lu %lu", tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].kind ));

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "tvu tile has no primary output link" ));

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id_primary ];
  // fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ 0 ] ];

  g_net_out_mcache = net_out->mcache;
  g_net_out_sync   = fd_mcache_seq_laddr( g_net_out_mcache );
  g_net_out_depth  = fd_mcache_depth( g_net_out_mcache );
  g_net_out_seq    = fd_mcache_seq_query( g_net_out_sync );
  g_net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  g_net_out_mem    = topo->workspaces[ net_out->wksp_id ].wksp;
  g_net_out_wmark  = fd_dcache_compact_wmark ( g_net_out_mem, net_out->dcache, net_out->mtu );
  g_net_out_chunk  = g_net_out_chunk0;

  g_sign_in = &topo->links[ tile->in_link_id[ 1 ] ];
  g_sign_out = &topo->links[ tile->out_link_id[ 0 ] ];
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_tvu( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_tvu_instr_cnt;
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

fd_tile_config_t fd_tile_tvu = {
  .mux_flags                = FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_during_housekeeping  = during_housekeeping,
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
};

static int
doit( void ) {
  fd_flamenco_boot(NULL, NULL);
  fd_runtime_ctx_t runtime_ctx;
  memset(&runtime_ctx, 0, sizeof(runtime_ctx));

  fd_replay_t * replay = NULL;
  fd_exec_slot_ctx_t * slot_ctx = NULL;

  fd_keyguard_client_t keyguard_client[1];
  if( fd_keyguard_client_join(
        fd_keyguard_client_new( keyguard_client,
                                g_sign_out->mcache,
                                g_sign_out->dcache,
                                g_sign_in->mcache,
                                g_sign_in->dcache ) ) == NULL ) {
    FD_LOG_ERR(( "Keyguard join failed" ));
  }
  memcpy(runtime_ctx.private_key, g_identity_key, 32);
  FD_LOG_WARNING(("Identity key %32J", runtime_ctx.private_key));
  memcpy(runtime_ctx.public_key.uc, g_identity_key + 32UL, 32);
  fd_runtime_args_t args = {
    .gossip_peer_addr     = g_gossip_peer_addr,
    .my_gossip_addr       = g_my_gossip_addr,
    .my_repair_addr       = g_my_repair_addr,
    .repair_peer_addr     = g_repair_peer_addr,
    .repair_peer_id       = g_repair_peer_id,
    .tvu_addr             = g_tvu_addr,
    .tvu_fwd_addr         = g_tvu_fwd_addr,
    .load                 = g_load,
    .shredlog_fpath       = g_shredlog_fpath,
    .snapshot             = g_snapshot,
    .incremental_snapshot = g_incremental_snapshot,
    .validate_snapshot    = g_validate_snapshot,
    .check_hash           = g_check_hash,
    .allocator            = "libc",
    .index_max            = ULONG_MAX,
    .page_cnt             = g_page_cnt,
    .tcnt                 = 1,
    .txn_max              = 1000, // TODO: LML add --txnmax to default.toml
    .rpc_port             = g_rpc_listen_port,
  };
  fd_tvu_main_setup( &runtime_ctx,
                     &replay,
                     &slot_ctx,
                     keyguard_client,
                     1,
                     g_wksp,
                     &args );
  if( runtime_ctx.blowup ) FD_LOG_ERR(( "blowup" ));

  /**********************************************************************/
  /* Tile                                                               */
  /**********************************************************************/

  if( fd_tvu_main( &runtime_ctx,
                   &args,
                   replay,
                   slot_ctx ) ) {
    return 1;
  }
  return 0;
}

int
fd_tvu_tile( fd_cnc_t *              cnc,
             ulong                   flags,
             ulong                   in_cnt,
             fd_frag_meta_t const ** in_mcache,
             ulong **                in_fseq,
             fd_frag_meta_t *        mcache,
             ulong                   out_cnt,
             ulong **                _out_fseq,
             ulong                   burst,
             ulong                   cr_max,
             long                    lazy,
             fd_rng_t *              rng,
             void *                  scratch,
             void *                  ctx,
             fd_mux_callbacks_t *    callbacks ) {
  (void)cnc;
  (void)flags;
  (void)in_cnt;
  (void)in_mcache;
  (void)in_fseq;
  (void)mcache;
  (void)out_cnt;
  (void)_out_fseq;
  (void)burst;
  (void)cr_max;
  (void)lazy;
  (void)rng;
  (void)scratch;
  (void)ctx;
  (void)callbacks;

  doit();
  return 0;
}
