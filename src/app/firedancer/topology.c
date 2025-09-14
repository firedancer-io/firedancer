#include "topology.h"

#include "../../choreo/fd_choreo_base.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../discof/poh/fd_poh.h"
#include "../../discof/replay/fd_exec.h"
#include "../../discof/gossip/fd_gossip_tile.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/quic/fd_tpu.h"
#include "../../disco/tiles.h"
#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_cpu_topo.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/tile/fd_tile_private.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"

#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

static void
parse_ip_port( const char * name, const char * ip_port, fd_topo_ip_port_t *parsed_ip_port) {
  char buf[ sizeof( "255.255.255.255:65536" ) ];
  memcpy( buf, ip_port, sizeof( buf ) );
  char *ip_end = strchr( buf, ':' );
  if( FD_UNLIKELY( !ip_end ) )
    FD_LOG_ERR(( "[%s] must in the form ip:port", name ));
  *ip_end = '\0';

  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( buf, &( parsed_ip_port->ip ) ) ) ) {
    FD_LOG_ERR(( "could not parse IP %s in [%s]", buf, name ));
  }

  parsed_ip_port->port = fd_cstr_to_ushort( ip_end+1 );
  if( FD_UNLIKELY( !parsed_ip_port->port ) )
    FD_LOG_ERR(( "could not parse port %s in [%s]", ip_end+1, name ));
}

fd_topo_obj_t *
setup_topo_bank_hash_cmp( fd_topo_t * topo, char const * wksp_name ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "bh_cmp", wksp_name );
  return obj;
}

fd_topo_obj_t *
setup_topo_banks( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        max_total_banks,
                  ulong        max_fork_width ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "banks", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_total_banks, "obj.%lu.max_total_banks", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_fork_width, "obj.%lu.max_fork_width", obj->id ) );
  return obj;
}

static fd_topo_obj_t *
setup_topo_fec_sets( fd_topo_t * topo, char const * wksp_name, ulong sz ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "fec_sets", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, sz, "obj.%lu.sz",   obj->id ) );
  return obj;
}

fd_topo_obj_t *
setup_topo_funk( fd_topo_t *  topo,
                 char const * wksp_name,
                 ulong        max_account_records,
                 ulong        max_database_transactions,
                 ulong        heap_size_gib,
                 int          lock_pages ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "funk", wksp_name );
  FD_TEST( fd_pod_insert_ulong(  topo->props, "funk", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_account_records,       "obj.%lu.rec_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_database_transactions, "obj.%lu.txn_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, heap_size_gib*(1UL<<30),   "obj.%lu.heap_max", obj->id ) );
  ulong funk_footprint = fd_funk_footprint( max_database_transactions, max_account_records );
  if( FD_UNLIKELY( !funk_footprint ) ) FD_LOG_ERR(( "Invalid [funk] parameters" ));

  /* Increase workspace partition count */
  ulong wksp_idx = fd_topo_find_wksp( topo, wksp_name );
  FD_TEST( wksp_idx!=ULONG_MAX );
  fd_topo_wksp_t * wksp = &topo->workspaces[ wksp_idx ];
  ulong part_max = fd_wksp_part_max_est( funk_footprint+(heap_size_gib*(1UL<<30)), 1U<<14U );
  if( FD_UNLIKELY( !part_max ) ) FD_LOG_ERR(( "fd_wksp_part_max_est(%lu,16KiB) failed", funk_footprint ));
  wksp->part_max += part_max;
  wksp->is_locked = lock_pages;

  return obj;
}

fd_topo_obj_t *
setup_topo_store( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        fec_max,
                  uint         part_cnt ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "store", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_max,  "obj.%lu.fec_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, part_cnt, "obj.%lu.part_cnt", obj->id ) );
  return obj;
}

fd_topo_obj_t *
setup_topo_txncache( fd_topo_t *  topo,
                     char const * wksp_name,
                     ulong        max_rooted_slots,
                     ulong        max_live_slots,
                     ulong        max_txn_per_slot ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "txncache", wksp_name );

  FD_TEST( fd_pod_insertf_ulong( topo->props, max_rooted_slots, "obj.%lu.max_rooted_slots", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_live_slots,   "obj.%lu.max_live_slots",   obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_txn_per_slot, "obj.%lu.max_txn_per_slot", obj->id ) );

  return obj;
}

static int
resolve_address( char const * address,
                 uint       * ip_addr ) {
  struct addrinfo hints = { .ai_family = AF_INET };
  struct addrinfo * res;
  int err = getaddrinfo( address, NULL, &hints, &res );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "cannot resolve address \"%s\": %i-%s", address, err, gai_strerror( err ) ));
    return 0;
  }

  int resolved = 0;
  for( struct addrinfo * cur=res; cur; cur=cur->ai_next ) {
    if( FD_UNLIKELY( cur->ai_addr->sa_family!=AF_INET ) ) continue;
    struct sockaddr_in const * addr = (struct sockaddr_in const *)cur->ai_addr;
    *ip_addr = addr->sin_addr.s_addr;
    resolved = 1;
    break;
  }

  freeaddrinfo( res );
  return resolved;
}

static int
resolve_peer( char const *    peer,
              fd_ip4_port_t * ip4_port ) {

  /* Split host:port */
  char const * host_port = peer;
  if( FD_LIKELY( strncmp( peer, "http://", 7UL )==0 ) ) {
    host_port += 7UL;
  } else if( FD_LIKELY( strncmp( peer, "https://", 8UL )==0 ) ) {
    host_port += 8UL;
  }

  char const * colon = strrchr( host_port, ':' );
  if( FD_UNLIKELY( !colon ) ) {
    FD_LOG_ERR(( "invalid [gossip.entrypoints] entry \"%s\": no port number", host_port ));
  }

  char fqdn[ 255 ];
  ulong fqdn_len = (ulong)( colon-host_port );
  if( FD_UNLIKELY( fqdn_len>254 ) ) {
    FD_LOG_ERR(( "invalid [gossip.entrypoints] entry \"%s\": hostname too long", host_port ));
  }
  fd_memcpy( fqdn, host_port, fqdn_len );
  fqdn[ fqdn_len ] = '\0';

  /* Parse port number */

  char const * port_str = colon+1;
  char const * endptr   = NULL;
  ulong port = strtoul( port_str, (char **)&endptr, 10 );
  if( FD_UNLIKELY( !endptr || !port || port>USHORT_MAX || *endptr!='\0' ) ) {
    FD_LOG_ERR(( "invalid [gossip.entrypoints] entry \"%s\": invalid port number", host_port ));
  }
  ip4_port->port = (ushort)fd_ushort_bswap( (ushort)port );

  /* Resolve hostname */
  int resolved = resolve_address( fqdn, &ip4_port->addr );
  return resolved;
}

static void
resolve_gossip_entrypoints( config_t * config ) {
  ulong entrypoint_cnt = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<entrypoint_cnt; i++ ) {
    if( FD_UNLIKELY( 0==resolve_peer( config->gossip.entrypoints[ i ], &config->gossip.resolved_entrypoints[ i ] ) ) ) {
      FD_LOG_ERR(( "failed to resolve address of [gossip.entrypoints] entry \"%s\"", config->gossip.entrypoints[ i ] ));
    }
  }
}

void
fd_topo_initialize( config_t * config ) {
  /* TODO: Not here ... */
  resolve_gossip_entrypoints( config );

  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong resolv_tile_cnt = config->layout.resolv_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;

  ulong gossvf_tile_cnt = config->firedancer.layout.gossvf_tile_count;
  ulong exec_tile_cnt   = config->firedancer.layout.exec_tile_count;
  ulong writer_tile_cnt = config->firedancer.layout.writer_tile_count;
  ulong sign_tile_cnt   = config->firedancer.layout.sign_tile_count;

  int snapshots_enabled = !!config->gossip.entrypoints_cnt;
  int solcap_enabled = strcmp( "", config->capture.solcap_capture );

  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );

  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  /*             topo, name */
  fd_topob_wksp( topo, "metric"       );
  fd_topob_wksp( topo, "ipecho"       );
  fd_topob_wksp( topo, "gossvf"       );
  fd_topob_wksp( topo, "gossip"       );
  fd_topob_wksp( topo, "shred"        );
  fd_topob_wksp( topo, "repair"       );
  fd_topob_wksp( topo, "replay"       );
  fd_topob_wksp( topo, "exec"         );
  fd_topob_wksp( topo, "writer"       );
  fd_topob_wksp( topo, "tower"        );
  fd_topob_wksp( topo, "send"         );

  fd_topob_wksp( topo, "quic"         );
  fd_topob_wksp( topo, "verify"       );
  fd_topob_wksp( topo, "dedup"        );
  fd_topob_wksp( topo, "resolv"       );
  fd_topob_wksp( topo, "pack"         );
  fd_topob_wksp( topo, "bank"         );
  fd_topob_wksp( topo, "poh"          );
  fd_topob_wksp( topo, "sign"         );

  fd_topob_wksp( topo, "metric_in"    );

  fd_topob_wksp( topo, "net_gossip"   );
  fd_topob_wksp( topo, "net_shred"    );
  fd_topob_wksp( topo, "net_repair"   );
  fd_topob_wksp( topo, "net_send"     );
  fd_topob_wksp( topo, "net_quic"     );

  fd_topob_wksp( topo, "ipecho_out"   );
  fd_topob_wksp( topo, "gossvf_gossi" );
  fd_topob_wksp( topo, "gossip_gossv" );
  fd_topob_wksp( topo, "gossip_out"   );

  fd_topob_wksp( topo, "shred_repair" );
  fd_topob_wksp( topo, "repair_repla" );
  fd_topob_wksp( topo, "replay_pack"  );
  fd_topob_wksp( topo, "replay_stake" );
  fd_topob_wksp( topo, "replay_exec"  );
  fd_topob_wksp( topo, "replay_tower" );
  fd_topob_wksp( topo, "exec_writer"  );
  fd_topob_wksp( topo, "tower_out"    );
  fd_topob_wksp( topo, "send_txns"    ); /* TODO: Badly named. Rename to indicate tiles */

  fd_topob_wksp( topo, "quic_verify"  );
  fd_topob_wksp( topo, "verify_dedup" );
  fd_topob_wksp( topo, "dedup_resolv" );
  fd_topob_wksp( topo, "resolv_pack"  );
  fd_topob_wksp( topo, "pack_poh"     );
  fd_topob_wksp( topo, "pack_bank"    );
  fd_topob_wksp( topo, "bank_pack"    );
  fd_topob_wksp( topo, "bank_poh"     );
  fd_topob_wksp( topo, "bank_busy"    );
  fd_topob_wksp( topo, "poh_shred"    );
  fd_topob_wksp( topo, "poh_replay"   );

  /* TODO: WTF are these for? */
  fd_topob_wksp( topo, "funk"         );
  fd_topob_wksp( topo, "bh_cmp"       );
  fd_topob_wksp( topo, "fec_sets"     );
  fd_topob_wksp( topo, "tcache"       ); /* TODO: Rename txncache */
  fd_topob_wksp( topo, "exec_spad"    );
  fd_topob_wksp( topo, "banks"        );
  fd_topob_wksp( topo, "store"        );
  fd_topob_wksp( topo, "executed_txn" );

  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_wksp( topo, "sign_gossip"  );

  fd_topob_wksp( topo, "shred_sign"   );
  fd_topob_wksp( topo, "sign_shred"   );

  fd_topob_wksp( topo, "repair_sign"  );
  fd_topob_wksp( topo, "sign_repair"  );

  fd_topob_wksp( topo, "send_sign"    );
  fd_topob_wksp( topo, "sign_send"    );

  if( FD_LIKELY( snapshots_enabled ) ) {
    fd_topob_wksp( topo, "snapdc"      );
    fd_topob_wksp( topo, "snaprd"      );
    fd_topob_wksp( topo, "snapin"      );

    fd_topob_wksp( topo, "snapdc_rd"   );
    fd_topob_wksp( topo, "snapin_rd"   );
    fd_topob_wksp( topo, "snap_stream" ); /* TODO: Rename ... */
    fd_topob_wksp( topo, "snap_zstd"   ); /* TODO: Rename ... */
    fd_topob_wksp( topo, "snap_out"    ); /* TODO: Rename ... */
  }

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /* TODO: Explain this .... USHORT_MAX is not dcache max */
  ulong pending_fec_shreds_depth = fd_ulong_min( fd_ulong_pow2_up( config->tiles.shred.max_pending_shred_sets * FD_REEDSOL_DATA_SHREDS_MAX ), USHORT_MAX + 1 /* dcache max */ );

  /*                                  topo, link_name,      wksp_name,      depth,                                    mtu,                           burst */
  /**/                 fd_topob_link( topo, "gossip_net",   "net_gossip",   config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  /**/                 fd_topob_link( topo, "repair_net",   "net_repair",   config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  /**/                 fd_topob_link( topo, "send_net",     "net_send",     config->net.ingress_buffer_size,          FD_NET_MTU,                    2UL ); /* TODO: 2 is probably not correct, should be 1 */
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );

  if( FD_LIKELY( snapshots_enabled ) ) {
  /**/                 fd_topob_link( topo, "snap_zstd",    "snap_zstd",    8192UL,                                   16384UL,                       1UL ); /* TODO: Rename */
  /**/                 fd_topob_link( topo, "snap_stream",  "snap_stream",  2048UL,                                   USHORT_MAX,                    1UL ); /* TODO: Rename */
  /**/                 fd_topob_link( topo, "snap_out",     "snap_out",     2UL,                                      sizeof(fd_snapshot_manifest_t), 1UL ); /* TODO: Rename */
  /**/                 fd_topob_link( topo, "snapdc_rd",    "snapdc_rd",    128UL,                                    0UL,                           1UL );
  /**/                 fd_topob_link( topo, "snapin_rd",    "snapin_rd",    128UL,                                    0UL,                           1UL );
  }

  /**/                 fd_topob_link( topo, "ipecho_out",   "ipecho_out",   4UL,                                      0UL,                           1UL );
  FOR(gossvf_tile_cnt) fd_topob_link( topo, "gossvf_gossi", "gossvf_gossi", config->net.ingress_buffer_size,          sizeof(fd_gossip_view_t)+FD_NET_MTU, 1UL );
  /**/                 fd_topob_link( topo, "gossip_gossv", "gossip_gossv", 65536UL*4UL,                              sizeof(fd_gossip_ping_update_t), 1UL ); /* TODO: Unclear where this depth comes from ... fix */
  /**/                 fd_topob_link( topo, "gossip_out",   "gossip_out",   65536UL*4UL,                              sizeof(fd_gossip_update_message_t), 1UL ); /* TODO: Unclear where this depth comes from ... fix */

  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  config->tiles.verify.receive_buffer_size, FD_TPU_REASM_MTU,              config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,             1UL );
  /**/                 fd_topob_link( topo, "dedup_resolv", "dedup_resolv", 65536UL,                                  FD_TPU_PARSED_MTU,             1UL );
  FOR(resolv_tile_cnt) fd_topob_link( topo, "resolv_pack",  "resolv_pack",  65536UL,                                  FD_TPU_RESOLVED_MTU,           1UL );
  /**/                 fd_topob_link( topo, "replay_pack",  "replay_pack",  128UL,                                    sizeof(fd_became_leader_t),    1UL ); /* TODO: Depth probably doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "replay_stake", "replay_stake", 128UL,                                    FD_STAKE_OUT_MTU,              1UL ); /* TODO: Depth probably doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "pack_poh",     "pack_poh",     128UL,                                    sizeof(fd_done_packing_t),     1UL );
  /* pack_bank is shared across all banks, so if one bank stalls due to complex transactions, the buffer neeeds to be large so that
     other banks can keep proceeding. */
  /**/                 fd_topob_link( topo, "pack_bank",    "pack_bank",    65536UL,                                  USHORT_MAX,                    1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_poh",     "bank_poh",     16384UL,                                  USHORT_MAX,                    1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_pack",    "bank_pack",    16384UL,                                  USHORT_MAX,                    1UL );
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    16384UL,                                  USHORT_MAX,                    1UL );
  /**/                 fd_topob_link( topo, "poh_replay",   "poh_replay",   128UL,                                    sizeof(fd_poh_leader_slot_ended_t), 1UL ); /* TODO: Depth probably doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "replay_resol", "bank_poh",     128UL,                                    sizeof(fd_completed_bank_t),   1UL ); /* TODO: Don't reuse bank_poh link for this. Depth doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "executed_txn", "executed_txn", 16384UL,                                  64UL,                          1UL ); /* TODO: Rename this ... */

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                          1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "gossip_sign",  "gossip_sign",  128UL,                                    2048UL,                        1UL ); /* TODO: Where does 2048 come from? Depth probably doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "sign_gossip",  "sign_gossip",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL ); /* TODO: Depth probably doesn't need to be 128 */

  FOR(sign_tile_cnt-1) fd_topob_link( topo, "repair_sign",  "repair_sign",  128UL,                                    2048UL,                        1UL ); /* TODO: Where does 2048 come from? Depth probably doesn't need to be 128 */
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "sign_repair",  "sign_repair",  1024UL,                                   sizeof(fd_ed25519_sig_t),      1UL ); /* TODO: WTF is this depth? It should match repair_sign */
  /**/                 fd_topob_link( topo, "ping_sign",    "repair_sign",  128UL,                                    2048UL,                        1UL ); /* TODO: Huh? Why is this a different link? Where does 2048 come from? Depth not 128 */
  /**/                 fd_topob_link( topo, "sign_ping",    "sign_repair",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL ); /* TODO: What is this link ... ?  Why separate, doesn't make sense */

  /**/                 fd_topob_link( topo, "send_sign",    "send_sign",    128UL,                                    FD_TXN_MTU,                    1UL ); /* TODO: Depth probably doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "sign_send",    "sign_send",    128UL,                                    sizeof(fd_ed25519_sig_t),      1UL ); /* TODO: Depth probably doesn't need to be 128 */

  /**/                 fd_topob_link( topo, "repair_repla", "repair_repla", 65536UL,                                  sizeof(fd_reasm_fec_t),        1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_repair", "shred_repair", pending_fec_shreds_depth,                 FD_SHRED_REPAIR_MTU,           3UL ); /* TODO: Pretty sure burst of 3 is incorrect here */
  FOR(shred_tile_cnt)  fd_topob_link( topo, "repair_shred", "shred_repair", pending_fec_shreds_depth,                 sizeof(fd_ed25519_sig_t),      1UL ); /* TODO: Also pending_fec_shreds_depth? Seems wrong */
  /**/                 fd_topob_link( topo, "replay_tower", "replay_tower", fd_ulong_pow2_up( config->firedancer.runtime.max_total_banks*FD_REPLAY_TOWER_VOTE_ACC_MAX ), sizeof(fd_replay_tower_t), 1UL ); /* TODO: Don't think this depth makes much sense? This is weirdly outsized for a vote link */
  /**/                 fd_topob_link( topo, "tower_out",    "tower_out",    1024UL,                                   sizeof(fd_tower_slot_done_t),  1UL );
  /**/                 fd_topob_link( topo, "send_txns",    "send_txns",    128UL,                                    FD_TPU_RAW_MTU,                1UL ); /* TODO: Horribly named. Rename to indicate tile and where its going */

  FOR(exec_tile_cnt)   fd_topob_link( topo, "replay_exec",  "replay_exec",  128UL,                                    10240UL,                       exec_tile_cnt ); /* TODO: Depth probably not 128. MTU is made up and needs to be sized correctly. */
  /* Assuming the number of writer tiles is sufficient to keep up with
     the number of exec tiles, under equilibrium, we should have at least
     enough link space to buffer worst case input shuffling done by the
     stem.  That is, when a link is so unlucky, that the stem RNG decided
     to process every other link except this one, for all writer tiles.
     This would be fd_ulong_pow2_up( exec_tile_cnt*writer_tile_cnt+1UL ).

     This is all assuming we have true pipelining between exec and writer
     tiles.  Right now, we don't.  So in reality there can be at most 1
     in-flight transaction per exec tile, and hence a depth of 1 is in
     theory sufficient for each exec_writer link. */
  FOR(exec_tile_cnt)   fd_topob_link( topo, "exec_writer",  "exec_writer",  128UL,                                    FD_EXEC_WRITER_MTU,            1UL ); /* TODO: Update depth to reflect comment. */

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  fd_topos_net_tiles( topo, net_tile_cnt, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );

  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_gossvf", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_shred",  i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_repair", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_send",   i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_quic",   i, config->net.ingress_buffer_size );

  /*                                  topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave, uses_keyswitch */
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  if( FD_LIKELY( snapshots_enabled ) ) {
                       fd_topob_tile( topo, "snaprd", "snaprd", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
                       fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
                       fd_topob_tile( topo, "snapin", "snapin", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
  }

  /**/                 fd_topob_tile( topo, "ipecho",  "ipecho",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(gossvf_tile_cnt) fd_topob_tile( topo, "gossvf",  "gossvf",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                 fd_topob_tile( topo, "gossip",  "gossip",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );

  FOR(shred_tile_cnt)  fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                 fd_topob_tile( topo, "repair",  "repair",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 ); /* TODO: Wrong? Needs to use keyswitch as signs */
  /**/                 fd_topob_tile( topo, "replay",  "replay",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(exec_tile_cnt)   fd_topob_tile( topo, "exec",    "exec",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(writer_tile_cnt) fd_topob_tile( topo, "writer",  "writer",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "tower",   "tower",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "send",    "send",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  FOR(quic_tile_cnt)   fd_topob_tile( topo, "quic",    "quic",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(verify_tile_cnt) fd_topob_tile( topo, "verify",  "verify",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "dedup",   "dedup",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(resolv_tile_cnt) fd_topob_tile( topo, "resolv",  "resolv",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(resolv_tile_cnt) strncpy( topo->tiles[ topo->tile_cnt-1UL-i ].metrics_name, "resolf", 8UL );
  /**/                 fd_topob_tile( topo, "pack",    "pack",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        config->tiles.bundle.enabled );
  FOR(bank_tile_cnt)   fd_topob_tile( topo, "bank",    "bank",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(bank_tile_cnt)   strncpy( topo->tiles[ topo->tile_cnt-1UL-i ].metrics_name, "bankf", 6UL );
  /**/                 fd_topob_tile( topo, "poh",     "poh",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  FOR(sign_tile_cnt)   fd_topob_tile( topo, "sign",    "sign",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );

  /*                                        topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  FOR(gossvf_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                      fd_topob_tile_in(     topo, "gossvf",  i,            "metric_in", "net_gossvf",   j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                      fd_topob_tile_in (    topo, "shred",   i,            "metric_in", "net_shred",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)   fd_topob_tile_in(     topo, "repair",  0UL,          "metric_in", "net_repair",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topob_tile_out(    topo, "repair",  0UL,                       "repair_net",   0UL                                                );
  /**/                fd_topob_tile_in (    topo, "send",    0UL,          "metric_in", "net_send",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                      fd_topob_tile_in(     topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  FOR(shred_tile_cnt) fd_topos_tile_in_net( topo,                          "metric_in", "shred_net",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net( topo,                          "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net( topo,                          "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net( topo,                          "metric_in", "send_net",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)  fd_topos_tile_in_net( topo,                          "metric_in", "quic_net",     i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  /**/                 fd_topob_tile_out(   topo, "ipecho", 0UL,                        "ipecho_out",   0UL                                                );

  FOR(gossvf_tile_cnt) fd_topob_tile_out(   topo, "gossvf", i,                          "gossvf_gossi", i                                                  );
  FOR(gossvf_tile_cnt) fd_topob_tile_in (   topo, "gossvf", i,             "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(gossvf_tile_cnt) fd_topob_tile_in (   topo, "gossvf", i,             "metric_in", "gossip_gossv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(gossvf_tile_cnt) fd_topob_tile_in (   topo, "gossvf", i,             "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(gossvf_tile_cnt) fd_topob_tile_in (   topo, "gossvf", i,             "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "gossip", 0UL,           "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_out",   0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_net",   0UL                                                );
  /**/                 fd_topob_tile_in (   topo, "gossip", 0UL,           "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(gossvf_tile_cnt) fd_topob_tile_in (   topo, "gossip", 0UL,           "metric_in", "gossvf_gossi", i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "gossip", 0UL,           "metric_in", "send_txns",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_gossv", 0UL                                                );

  if( FD_LIKELY( snapshots_enabled ) ) {
                      fd_topob_tile_in(     topo, "snaprd",  0UL,          "metric_in", "gossip_out",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* TODO: Fix backpressure issues and change this back to reliable. */
                      fd_topob_tile_out(    topo, "snaprd",  0UL,                       "snap_zstd",    0UL                                                );
                      fd_topob_tile_in (    topo, "snaprd",  0UL,          "metric_in", "snapdc_rd",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                      fd_topob_tile_in (    topo, "snaprd",  0UL,          "metric_in", "snapin_rd",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                      fd_topob_tile_in (    topo, "snapdc",  0UL,          "metric_in", "snap_zstd",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                      fd_topob_tile_out(    topo, "snapdc",  0UL,                       "snap_stream",  0UL                                                );
                      fd_topob_tile_out(    topo, "snapdc",  0UL,          "snapdc_rd",                 0UL                                                );
                      fd_topob_tile_in (    topo, "snapin",  0UL,          "metric_in", "snap_stream",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                      fd_topob_tile_out(    topo, "snapin",  0UL,                       "snap_out",     0UL                                                );
                      fd_topob_tile_out(    topo, "snapin",  0UL,          "snapin_rd",                 0UL                                                );
                      fd_topob_tile_in (    topo, "replay",  0UL,          "metric_in", "snap_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  /**/                 fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "tower_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( snapshots_enabled ) {
                       fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "snap_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }
  FOR(shred_tile_cnt)  fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "shred_repair", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "repair",  0UL,                       "repair_repla", 0UL                                                );
  FOR(shred_tile_cnt)  fd_topob_tile_out(   topo, "repair",  0UL,                       "repair_shred", i                                                  );
  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "repair_repla", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_stake", 0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_resol", 0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "executed_txn", 0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_pack",  0UL                                                );
  FOR(exec_tile_cnt)   fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_exec",  i                                                  );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_tower", 0UL                                                );
  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "tower_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "replay",  0UL,          "metric_in", "poh_replay",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(exec_tile_cnt)   fd_topob_tile_in(    topo, "exec",    i,            "metric_in", "replay_exec",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(exec_tile_cnt)   fd_topob_tile_out(   topo, "exec",    i,                         "exec_writer",  i                                                  );
  /* All writer tiles read from all exec tiles.  Each exec tile has a
     single out link, over which all the writer tiles round-robin. */
  FOR(writer_tile_cnt) for( ulong j=0UL; j<exec_tile_cnt; j++ )
                       fd_topob_tile_in(    topo, "writer",  i,            "metric_in", "exec_writer",  j,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "replay_tower", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( snapshots_enabled ) {
                       fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "snap_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }
  /**/                 fd_topob_tile_out(   topo, "tower",   0UL,                       "tower_out",    0UL                                                );
  /**/                 fd_topob_tile_in (   topo, "send",    0UL,          "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "send",    0UL,          "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "send",    0UL,          "metric_in", "tower_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "send",    0UL,                       "send_net",     0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "send",    0UL,                       "send_txns",    0UL                                                );

  FOR(quic_tile_cnt)  fd_topob_tile_out(    topo, "quic",    i,                         "quic_verify",  i                                                  );
  FOR(quic_tile_cnt)  fd_topob_tile_out(    topo, "quic",    i,                         "quic_net",     i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(    topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_in(    topo, "verify",  i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "verify",  0UL,          "metric_in", "send_txns",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(verify_tile_cnt) fd_topob_tile_out(   topo, "verify",  i,                         "verify_dedup", i                                                  );
  FOR(verify_tile_cnt) fd_topob_tile_in(    topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "dedup",   0UL,          "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "dedup",   0UL,                       "dedup_resolv", 0UL                                                );
  FOR(resolv_tile_cnt) fd_topob_tile_in(    topo, "resolv",  i,            "metric_in", "dedup_resolv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_in(    topo, "resolv",  i,            "metric_in", "replay_resol", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_out(   topo, "resolv",  i,                         "resolv_pack",  i                                                  );
  /**/                 fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "resolv_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "replay_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                       fd_topob_tile_out(   topo, "pack",    0UL,                       "pack_bank",    0UL                                                );
                       fd_topob_tile_out(   topo, "pack",    0UL,                       "pack_poh" ,    0UL                                                );
  FOR(bank_tile_cnt)   fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "bank_pack",    i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_in(    topo, "bank",    i,            "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_out(   topo, "bank",    i,                         "bank_poh",     i                                                  );
  FOR(bank_tile_cnt)   fd_topob_tile_out(   topo, "bank",    i,                         "bank_pack",    i                                                  );
  FOR(bank_tile_cnt)   fd_topob_tile_in(    topo, "poh",     0UL,          "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) ) {
  /**/                 fd_topob_tile_in(    topo, "poh",     0UL,          "metric_in", "pack_poh",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }
  /**/                 fd_topob_tile_in(    topo, "poh",     0UL,          "metric_in", "replay_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "poh",     0UL,                       "poh_shred",    0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "poh",     0UL,                       "poh_replay",   0UL                                                );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out(   topo, "shred",   i,                         "shred_repair", i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "repair_shred", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "poh_shred",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out(   topo, "shred",   i,                         "shred_net",    i                                                  );

  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by fd_stem, instead the tiles will
     read the sign responses out of band in a dedicated spin loop.

     TODO: This can probably be fixed now to be relible ... ? */
  /*                                        topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  /**/                 fd_topob_tile_in (   topo, "sign",    0UL,          "metric_in", "gossip_sign",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out(   topo, "gossip",  0UL,                       "gossip_sign",  0UL                                                  );
  /**/                 fd_topob_tile_in (   topo, "gossip",  0UL,          "metric_in", "sign_gossip",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out(   topo, "sign",    0UL,                       "sign_gossip",  0UL                                                  );

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in (   topo, "sign",    0UL,          "metric_in", "shred_sign",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out(   topo, "shred",   i,                         "shred_sign",   i                                                    );
    /**/               fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "sign_shred",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out(   topo, "sign",    0UL,                       "sign_shred",   i                                                    );
  }

  /**/                 fd_topob_tile_in (   topo, "sign",    0UL,          "metric_in", "ping_sign",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out(   topo, "repair",  0UL,                       "ping_sign",    0UL                                                  );
  /**/                 fd_topob_tile_out(   topo, "sign",    0UL,                       "sign_ping",    0UL                                                  );

  FOR(sign_tile_cnt-1UL) fd_topob_tile_out( topo, "repair",  0UL,                       "repair_sign",  i                                                    );
  FOR(sign_tile_cnt-1UL) fd_topob_tile_in ( topo, "sign",    i+1UL,        "metric_in", "repair_sign",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(sign_tile_cnt-1UL) fd_topob_tile_out( topo, "sign",    i+1UL,                     "sign_repair",  i                                                    );
  FOR(sign_tile_cnt-1UL) fd_topob_tile_in ( topo, "repair",  0UL,          "metric_in", "sign_repair",  i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* This link is polled because the signing requests are asynchronous */
  /**/                 fd_topob_tile_in (   topo, "repair",  0UL,          "metric_in", "sign_ping",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );

  /**/                 fd_topob_tile_in (   topo, "sign",    0UL,          "metric_in", "send_sign",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out(   topo, "send",    0UL,                       "send_sign",    0UL                                                  );
  /**/                 fd_topob_tile_in (   topo, "send",    0UL,          "metric_in", "sign_send",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out(   topo, "sign",    0UL,                       "sign_send",    0UL                                                  );

  if( FD_UNLIKELY( config->tiles.archiver.enabled ) ) {
    fd_topob_wksp( topo, "arch_f" );
    fd_topob_wksp( topo, "arch_w" );
    fd_topob_wksp( topo, "feeder" );
    fd_topob_wksp( topo, "arch_f2w" );

    fd_topob_link( topo, "feeder", "feeder", 65536UL, 4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
    fd_topob_link( topo, "arch_f2w", "arch_f2w", 128UL, 4UL*FD_SHRED_STORE_MTU, 1UL );

    fd_topob_tile( topo, "arch_f", "arch_f", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
    fd_topob_tile( topo, "arch_w", "arch_w", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    fd_topob_tile_out( topo, "replay", 0UL,              "feeder", 0UL );
    fd_topob_tile_in(  topo, "arch_f", 0UL, "metric_in", "feeder", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_out( topo, "arch_f", 0UL,              "arch_f2w", 0UL );
    fd_topob_tile_in(  topo, "arch_w", 0UL, "metric_in", "arch_f2w", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  if( FD_UNLIKELY( config->tiles.shredcap.enabled ) ) {
    fd_topob_wksp( topo, "scap" );
    fd_topob_wksp( topo, "repair_scap" );
    fd_topob_wksp( topo, "replay_scap" );

    fd_topob_tile( topo, "scap", "scap", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    fd_topob_link( topo, "repair_scap", "repair_scap", 128UL, FD_SLICE_MAX_WITH_HEADERS, 1UL );
    fd_topob_link( topo, "replay_scap", "replay_scap", 128UL, sizeof(fd_hash_t)+sizeof(ulong), 1UL );

    fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "repair_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    for( ulong j=0UL; j<net_tile_cnt; j++ ) {
      fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "net_shred", j, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }
    for( ulong j=0UL; j<shred_tile_cnt; j++ ) {
      fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "shred_repair", j, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }
    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "gossip_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "repair_scap", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "replay_scap", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_out( topo, "repair", 0UL, "repair_scap", 0UL );
    fd_topob_tile_out( topo, "replay", 0UL, "replay_scap", 0UL );

    /* No default fd_topob_tile_in connection to stake_out */
  }

  fd_topob_wksp( topo, "replay_notif" );
  /* We may be notifying an external service, so always publish on this link. */
  fd_topob_link( topo, "replay_notif", "replay_notif", FD_REPLAY_NOTIF_DEPTH, FD_REPLAY_NOTIF_MTU, 1UL )->permit_no_consumers = 1;
  fd_topob_tile_out( topo, "replay",  0UL, "replay_notif", 0UL );

  int rpc_enabled = config->rpc.port;
  if( FD_UNLIKELY( rpc_enabled ) ) {
    fd_topob_wksp( topo, "rpcsrv" );
    fd_topob_tile( topo, "rpcsrv",  "rpcsrv",  "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    fd_topob_tile_in( topo, "rpcsrv", 0UL, "metric_in", "replay_notif", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "rpcsrv", 0UL, "metric_in", "replay_stake", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "rpcsrv", 0UL, "metric_in", "repair_repla", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "rpcsrv", 0UL, "metric_in", "replay_tower", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  }

  /* For now the only plugin consumer is the GUI */
  int plugins_enabled = config->tiles.gui.enabled;
  if( FD_LIKELY( plugins_enabled ) ) {
    fd_topob_wksp( topo, "plugin_in"    );
    fd_topob_wksp( topo, "plugin_out"   );
    fd_topob_wksp( topo, "plugin"       );

    /**/                 fd_topob_link( topo, "plugin_out",   "plugin_out",   128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );
    /**/                 fd_topob_link( topo, "replay_plugi", "plugin_in",    128UL,                                    4098*8UL,               1UL );
    /**/                 fd_topob_link( topo, "votes_plugin", "plugin_in",    128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );

    /**/                 fd_topob_tile( topo, "plugin",  "plugin",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    /**/                 fd_topob_tile_out( topo, "replay", 0UL,                        "replay_plugi", 0UL                                                  );
    /**/                 fd_topob_tile_out( topo, "replay", 0UL,                        "votes_plugin", 0UL                                                  );
    /**/                 fd_topob_tile_out( topo, "plugin", 0UL,                        "plugin_out", 0UL                                                    );

    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "replay_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "votes_plugin", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  fd_topob_wksp( topo, "writ_repl" );
  FOR(writer_tile_cnt) fd_topob_link(     topo, "writ_repl", "writ_repl", 16384UL, sizeof(fd_writer_replay_txn_finalized_msg_t), 1UL );
  FOR(writer_tile_cnt) fd_topob_tile_out( topo, "writer",    i,                               "writ_repl", i );
  FOR(writer_tile_cnt) fd_topob_tile_in(  topo, "replay",    0UL,      "metric_in", "writ_repl", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  if( FD_UNLIKELY( solcap_enabled ) ) {
    /* Capture account updates, whose updates must be centralized in the replay tile as solcap is currently not thread-safe.
      TODO: remove this when solcap v2 is here. */
    fd_topob_wksp( topo, "capt_replay" );
    FOR(writer_tile_cnt) fd_topob_link(     topo, "capt_replay", "capt_replay", FD_CAPTURE_CTX_MAX_ACCOUNT_UPDATES, FD_CAPTURE_CTX_ACCOUNT_UPDATE_MSG_FOOTPRINT, 1UL );
    FOR(writer_tile_cnt) fd_topob_tile_out( topo, "writer",    i,                               "capt_replay", i );
    FOR(writer_tile_cnt) fd_topob_tile_in(  topo, "replay",    0UL,         "metric_in",        "capt_replay", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  if( FD_LIKELY( config->tiles.gui.enabled ) ) {
    fd_topob_wksp( topo, "gui"          );
    /**/                 fd_topob_tile(     topo, "gui",     "gui",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,        "metric_in",     "plugin_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) )
      FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                   "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                   "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                   topo->tile_cnt, affinity_tile_cnt ));
    if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) )
      FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                       "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                       "individual tile counts in the [layout] section of the configuration file.",
                       topo->tile_cnt, affinity_tile_cnt ));
  }


  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );

  /* There is a special fseq that sits between the pack, bank, and poh
     tiles to indicate when the bank/poh tiles are done processing a
     microblock.  Pack uses this to determine when to "unlock" accounts
     that it marked as locked because they were being used. */

  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );

    fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
    fd_topo_tile_t * pack_tile = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
    fd_topob_tile_uses( topo, poh_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib,
      config->firedancer.funk.lock_pages );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* TODO: Should be readonly? */
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* TODO: Should be readonly? */
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_total_banks, config->firedancer.runtime.max_fork_width );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* TODO: Should be readonly? */
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* TODO: Should be readonly? */
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i   ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  /* TODO: This should not exist in production */
  fd_topo_obj_t * bank_hash_cmp_obj = setup_topo_bank_hash_cmp( topo, "bh_cmp" );
  /**/               fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, bank_hash_cmp_obj->id, "bh_cmp" ) );

  ulong shred_depth = 65536UL; /* from fdctl/topology.c shred_store link. MAKE SURE TO KEEP IN SYNC. */
  ulong fec_set_cnt = shred_depth + config->tiles.shred.max_pending_shred_sets + 4UL;
  ulong fec_sets_sz = fec_set_cnt*sizeof(fd_shred34_t)*4; /* mirrors # of dcache entires in frankendancer */
  fd_topo_obj_t * fec_sets_obj = setup_topo_fec_sets( topo, "fec_sets", shred_tile_cnt*fec_sets_sz );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ], fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_sets_obj->id, "fec_sets" ) );

  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.store.max_completed_shred_sets, (uint)shred_tile_cnt );
  FOR(shred_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "tcache",
      config->firedancer.runtime.max_rooted_slots,
      config->firedancer.runtime.max_live_slots,
      config->firedancer.runtime.max_transactions_per_slot );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_spad_obj = fd_topob_obj( topo, "exec_spad", "exec_spad" );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    for( ulong j=0UL; j<writer_tile_cnt; j++ ) {
      /* For txn_ctx. */
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", j ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    }
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_spad_obj->id, "exec_spad.%lu", i ) );
  }

  if( FD_LIKELY( snapshots_enabled ) ) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  if( FD_UNLIKELY( rpc_enabled ) ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "rpcserv", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "rpcserv", 0UL ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) fd_topo_configure_tile( &topo->tiles[ i ], config );

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );
  fd_topob_finish( topo, CALLBACKS );

  const char * status_cache = config->tiles.replay.status_cache;
  if ( strlen( status_cache ) > 0 ) {
    /* Make the status cache workspace match the parameters used to create the
       checkpoint. This is a bit nonintuitive because of the way
       fd_topo_create_workspace works. */
    fd_wksp_preview_t preview[1];
    int err = fd_wksp_preview( status_cache, preview );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "unable to preview %s: error %d", status_cache, err ));
    fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ txncache_obj->id ].wksp_id ];
    wksp->part_max = preview->part_max;
    wksp->known_footprint = 0;
    wksp->total_footprint = preview->data_max;
    ulong page_sz = FD_SHMEM_GIGANTIC_PAGE_SZ;
    wksp->page_sz = page_sz;
    ulong footprint = fd_wksp_footprint( preview->part_max, preview->data_max );
    wksp->page_cnt = footprint / page_sz;
  }

  config->topo = *topo;
}

void
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config ) {
  int plugins_enabled = config->tiles.gui.enabled;

  if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &tile->metric.prometheus_listen_addr ) ) )
      FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
    tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  } else  if( FD_UNLIKELY( !strcmp( tile->name, "net" ) || !strcmp( tile->name, "sock" ) ) ) {

    tile->net.shred_listen_port              = config->tiles.shred.shred_listen_port;
    tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
    tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;
    tile->net.gossip_listen_port             = config->gossip.port;
    tile->net.repair_intake_listen_port      = config->tiles.repair.repair_intake_listen_port;
    tile->net.repair_serve_listen_port       = config->tiles.repair.repair_serve_listen_port;
    tile->net.send_src_port                  = config->tiles.send.send_src_port;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "netlnk" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "ipecho") ) ) {

    strncpy( tile->ipecho.genesis_path, config->paths.genesis, sizeof(tile->ipecho.genesis_path) );
    tile->ipecho.expected_shred_version = config->consensus.expected_shred_version;
    tile->ipecho.bind_address           = config->net.ip_addr;
    tile->ipecho.bind_port              = config->gossip.port;
    tile->ipecho.entrypoints_cnt        = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->ipecho.entrypoints, config->gossip.resolved_entrypoints, tile->ipecho.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gossvf") ) ) {

    strncpy( tile->gossvf.identity_key_path, config->paths.identity_key, sizeof(tile->gossvf.identity_key_path) );
    tile->gossvf.tcache_depth          = 1<<22UL; /* TODO: user defined option */
    tile->gossvf.shred_version         = 0U;
    tile->gossvf.allow_private_address = config->development.gossip.allow_private_address;
    tile->gossvf.boot_timestamp_nanos   = config->boot_timestamp_nanos;

    tile->gossvf.entrypoints_cnt = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->gossvf.entrypoints, config->gossip.resolved_entrypoints, tile->gossvf.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gossip" ) ) ) {

    if( FD_UNLIKELY( strcmp( config->firedancer.gossip.host, "" ) ) ) {
      if( !resolve_address( config->firedancer.gossip.host, &tile->gossip.ip_addr ) )
        FD_LOG_ERR(( "could not resolve [gossip.host] %s", config->firedancer.gossip.host ));
    } else {
      tile->gossip.ip_addr = config->net.ip_addr;
    }
    strncpy( tile->gossip.identity_key_path, config->paths.identity_key, sizeof(tile->gossip.identity_key_path) );
    tile->gossip.shred_version       = config->consensus.expected_shred_version;
    tile->gossip.max_entries         = config->tiles.gossip.max_entries;
    tile->gossip.boot_timestamp_nanos = config->boot_timestamp_nanos;

    tile->gossip.ip_addr = config->net.ip_addr;

    tile->gossip.ports.gossip           = config->gossip.port;
    tile->gossip.ports.tvu              = config->tiles.shred.shred_listen_port;
    tile->gossip.ports.tpu              = config->tiles.quic.regular_transaction_listen_port;
    tile->gossip.ports.tpu_quic         = config->tiles.quic.quic_transaction_listen_port;
    tile->gossip.ports.repair           = config->tiles.repair.repair_intake_listen_port;

    tile->gossip.entrypoints_cnt        = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->gossip.entrypoints, config->gossip.resolved_entrypoints, tile->gossip.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snaprd" ) ) ) {

    fd_memcpy( tile->snaprd.snapshots_path, config->paths.snapshots, PATH_MAX );
    tile->snaprd.diagnostics                       = 1;
    tile->snaprd.incremental_snapshot_fetch        = config->firedancer.snapshots.incremental_snapshots;
    tile->snaprd.do_download                       = config->firedancer.snapshots.download;
    tile->snaprd.maximum_local_snapshot_age        = config->firedancer.snapshots.maximum_local_snapshot_age;
    tile->snaprd.minimum_download_speed_mib        = config->firedancer.snapshots.minimum_download_speed_mib;
    tile->snaprd.maximum_download_retry_abort      = config->firedancer.snapshots.maximum_download_retry_abort;
    tile->snaprd.max_full_snapshots_to_keep        = config->firedancer.snapshots.max_full_snapshots_to_keep;
    tile->snaprd.max_incremental_snapshots_to_keep = config->firedancer.snapshots.max_incremental_snapshots_to_keep;

    ulong peers_cnt          = config->firedancer.snapshots.sources.http.peers_cnt;
    ulong resolved_peers_cnt = 0UL;

    for( ulong j=0UL; j<peers_cnt; j++ ) {
      if( FD_UNLIKELY( !config->firedancer.snapshots.sources.http.peers[ j ].enabled ) ) continue;

      if( FD_UNLIKELY( 0==resolve_peer( config->firedancer.snapshots.sources.http.peers[ j ].url, &tile->snaprd.http.peers[ resolved_peers_cnt ] ) ) ) {
        FD_LOG_ERR(( "failed to resolve address of [snapshots.sources.http.peers] entry \"%s\"", config->firedancer.snapshots.sources.http.peers[ j ].url ));
      } else {
        resolved_peers_cnt++;
      }
    }

    tile->snaprd.http.peers_cnt = resolved_peers_cnt;
    /* TODO: set up known validators and known validators cnt */

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapdc" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapin" ) ) ) {

    tile->snapin.funk_obj_id            = fd_pod_query_ulong( config->topo.props, "funk",      ULONG_MAX );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "repair" ) ) ) {
    tile->repair.max_pending_shred_sets    = config->tiles.shred.max_pending_shred_sets;
    tile->repair.repair_intake_listen_port = config->tiles.repair.repair_intake_listen_port;
    tile->repair.repair_serve_listen_port  = config->tiles.repair.repair_serve_listen_port;
    tile->repair.slot_max                  = config->tiles.repair.slot_max;

    strncpy( tile->repair.identity_key_path, config->paths.identity_key, sizeof(tile->repair.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "replay" ) )) {

    tile->replay.fec_max = config->tiles.shred.max_pending_shred_sets;
    tile->replay.max_vote_accounts = config->firedancer.runtime.max_vote_accounts;

    /* specified by [tiles.replay] */

    strncpy( tile->replay.blockstore_file,    config->firedancer.blockstore.file,    sizeof(tile->replay.blockstore_file) );
    strncpy( tile->replay.blockstore_checkpt, config->firedancer.blockstore.checkpt, sizeof(tile->replay.blockstore_checkpt) );

    tile->replay.tx_metadata_storage = config->rpc.extended_tx_metadata_storage;

    tile->replay.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );

    tile->replay.bootstrap = !config->gossip.entrypoints_cnt;
    strncpy( tile->replay.genesis_path, config->paths.genesis, sizeof(tile->replay.genesis_path) );

    strncpy( tile->replay.cluster_version, config->tiles.replay.cluster_version, sizeof(tile->replay.cluster_version) );
    strncpy( tile->replay.tower_checkpt, config->tiles.replay.tower_checkpt, sizeof(tile->replay.tower_checkpt) );

    tile->replay.heap_size_gib = config->tiles.replay.heap_size_gib;

    /* not specified by [tiles.replay] */

    strncpy( tile->replay.identity_key_path, config->paths.identity_key, sizeof(tile->replay.identity_key_path) );
    tile->replay.ip_addr = config->net.ip_addr;
    strncpy( tile->replay.vote_account_path, config->paths.vote_account, sizeof(tile->replay.vote_account_path) );
    tile->replay.enable_bank_hash_cmp = 1;

    tile->replay.capture_start_slot = config->capture.capture_start_slot;
    strncpy( tile->replay.solcap_capture, config->capture.solcap_capture, sizeof(tile->replay.solcap_capture) );
    strncpy( tile->replay.dump_proto_dir, config->capture.dump_proto_dir, sizeof(tile->replay.dump_proto_dir) );
    tile->replay.dump_block_to_pb = config->capture.dump_block_to_pb;

    FD_TEST( tile->replay.funk_obj_id == fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX ) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "exec" ) ) ) {

    tile->exec.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );

    tile->exec.capture_start_slot = config->capture.capture_start_slot;
    strncpy( tile->exec.dump_proto_dir, config->capture.dump_proto_dir, sizeof(tile->exec.dump_proto_dir) );
    tile->exec.dump_instr_to_pb = config->capture.dump_instr_to_pb;
    tile->exec.dump_txn_to_pb = config->capture.dump_txn_to_pb;
    tile->exec.dump_syscall_to_pb = config->capture.dump_syscall_to_pb;
    tile->exec.dump_elf_to_pb = config->capture.dump_elf_to_pb;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "writer" ) ) ) {

    tile->writer.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
    strncpy( tile->writer.solcap_capture, config->capture.solcap_capture, sizeof(tile->writer.solcap_capture) );
    tile->writer.capture_start_slot = config->capture.capture_start_slot;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "tower" ) ) ) {

    strncpy( tile->tower.identity_key_path, config->paths.identity_key, sizeof(tile->tower.identity_key_path) );
    strncpy( tile->tower.vote_acc_path, config->paths.vote_account, sizeof(tile->tower.vote_acc_path) );
    strncpy( tile->tower.ledger_path, config->paths.ledger, sizeof(tile->tower.ledger_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "send" ) ) ) {

    tile->send.send_src_port = config->tiles.send.send_src_port;
    tile->send.ip_addr = config->net.ip_addr;
    strncpy( tile->send.identity_key_path, config->paths.identity_key, sizeof(tile->send.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "quic" ) ) ) {

    tile->quic.reasm_cnt                      = config->tiles.quic.txn_reassembly_count;
    tile->quic.out_depth                      = config->tiles.verify.receive_buffer_size;
    tile->quic.max_concurrent_connections     = config->tiles.quic.max_concurrent_connections;
    tile->quic.max_concurrent_handshakes      = config->tiles.quic.max_concurrent_handshakes;
    tile->quic.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
    tile->quic.idle_timeout_millis            = config->tiles.quic.idle_timeout_millis;
    tile->quic.ack_delay_millis               = config->tiles.quic.ack_delay_millis;
    tile->quic.retry                          = config->tiles.quic.retry;
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( tile->quic.key_log_path ), config->tiles.quic.ssl_key_log_file, sizeof(tile->quic.key_log_path) ) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "verify" ) ) ) {

    tile->verify.tcache_depth = config->tiles.verify.signature_cache_size;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "dedup" ) ) ) {

    tile->dedup.tcache_depth = config->tiles.dedup.signature_cache_size;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "resolv" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {

    tile->pack.max_pending_transactions      = config->tiles.pack.max_pending_transactions;
    tile->pack.bank_tile_count               = config->layout.bank_tile_count;
    tile->pack.larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
    tile->pack.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
    tile->pack.use_consumed_cus              = config->tiles.pack.use_consumed_cus;
    tile->pack.schedule_strategy             = config->tiles.pack.schedule_strategy_enum;

    if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
#define PARSE_PUBKEY( _tile, f ) \
      if( FD_UNLIKELY( !fd_base58_decode_32( config->tiles.bundle.f, tile->_tile.bundle.f ) ) )  \
        FD_LOG_ERR(( "[tiles.bundle.enabled] set to true, but failed to parse [tiles.bundle."#f"] %s", config->tiles.bundle.f ));
      tile->pack.bundle.enabled = 1;
      PARSE_PUBKEY( pack, tip_distribution_program_addr );
      PARSE_PUBKEY( pack, tip_payment_program_addr      );
      PARSE_PUBKEY( pack, tip_distribution_authority    );
      tile->pack.bundle.commission_bps = config->tiles.bundle.commission_bps;
      strncpy( tile->pack.bundle.identity_key_path, config->paths.identity_key, sizeof(tile->pack.bundle.identity_key_path) );
      strncpy( tile->pack.bundle.vote_account_path, config->paths.vote_account, sizeof(tile->pack.bundle.vote_account_path) );
    } else {
      fd_memset( &tile->pack.bundle, '\0', sizeof(tile->pack.bundle) );
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "bank" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "poh" ) ) ) {
    strncpy( tile->poh.identity_key_path, config->paths.identity_key, sizeof(tile->poh.identity_key_path) );

    tile->poh.plugins_enabled = plugins_enabled;
    tile->poh.bank_cnt = config->layout.bank_tile_count;
    tile->poh.lagged_consecutive_leader_start = config->tiles.poh.lagged_consecutive_leader_start;

    if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
      tile->poh.bundle.enabled = 1;
      PARSE_PUBKEY( poh, tip_distribution_program_addr );
      PARSE_PUBKEY( poh, tip_payment_program_addr      );
      strncpy( tile->poh.bundle.vote_account_path, config->paths.vote_account, sizeof(tile->poh.bundle.vote_account_path) );
#undef PARSE_PUBKEY
    } else {
      fd_memset( &tile->poh.bundle, '\0', sizeof(tile->poh.bundle) );
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {

    strncpy( tile->shred.identity_key_path, config->paths.identity_key, sizeof(tile->shred.identity_key_path) );

    tile->shred.depth                         = config->topo.links[ tile->out_link_id[ 0 ] ].depth;
    tile->shred.fec_resolver_depth            = config->tiles.shred.max_pending_shred_sets;
    tile->shred.expected_shred_version        = config->consensus.expected_shred_version;
    tile->shred.shred_listen_port             = config->tiles.shred.shred_listen_port;
    tile->shred.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
    for( ulong i=0UL; i<config->tiles.shred.additional_shred_destinations_retransmit_cnt; i++ ) {
      parse_ip_port( "tiles.shred.additional_shred_destinations_retransmit",
                      config->tiles.shred.additional_shred_destinations_retransmit[ i ],
                      &tile->shred.adtl_dests_retransmit[ i ] );
    }
    tile->shred.adtl_dests_retransmit_cnt = config->tiles.shred.additional_shred_destinations_retransmit_cnt;
    for( ulong i=0UL; i<config->tiles.shred.additional_shred_destinations_leader_cnt; i++ ) {
      parse_ip_port( "tiles.shred.additional_shred_destinations_leader",
                      config->tiles.shred.additional_shred_destinations_leader[ i ],
                      &tile->shred.adtl_dests_leader[ i ] );
    }
    tile->shred.adtl_dests_leader_cnt = config->tiles.shred.additional_shred_destinations_leader_cnt;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {

    strncpy( tile->sign.identity_key_path, config->paths.identity_key, sizeof(tile->sign.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "plugin" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gui" ) ) ) {

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.gui.gui_listen_address, &tile->gui.listen_addr ) ) )
      FD_LOG_ERR(( "failed to parse gui listen address `%s`", config->tiles.gui.gui_listen_address ));
    tile->gui.listen_port = config->tiles.gui.gui_listen_port;
    tile->gui.is_voting = strcmp( config->paths.vote_account, "" );
    strncpy( tile->gui.cluster, config->cluster, sizeof(tile->gui.cluster) );
    strncpy( tile->gui.identity_key_path, config->paths.identity_key, sizeof(tile->gui.identity_key_path) );
    strncpy( tile->gui.vote_key_path, config->paths.vote_account, sizeof(tile->gui.vote_key_path) );
    tile->gui.max_http_connections      = config->tiles.gui.max_http_connections;
    tile->gui.max_websocket_connections = config->tiles.gui.max_websocket_connections;
    tile->gui.max_http_request_length   = config->tiles.gui.max_http_request_length;
    tile->gui.send_buffer_size_mb       = config->tiles.gui.send_buffer_size_mb;
    tile->gui.schedule_strategy         = config->tiles.pack.schedule_strategy_enum;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "rpcsrv" ) ) ) {

    strncpy( tile->replay.blockstore_file, config->firedancer.blockstore.file, sizeof(tile->replay.blockstore_file) );
    tile->rpcserv.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
    tile->rpcserv.store_obj_id = fd_pod_query_ulong( config->topo.props, "store", ULONG_MAX );
    tile->rpcserv.rpc_port = config->rpc.port;
    tile->rpcserv.tpu_port = config->tiles.quic.regular_transaction_listen_port;
    tile->rpcserv.tpu_ip_addr = config->net.ip_addr;
    tile->rpcserv.block_index_max = config->rpc.block_index_max;
    tile->rpcserv.txn_index_max = config->rpc.txn_index_max;
    tile->rpcserv.acct_index_max = config->rpc.acct_index_max;
    strncpy( tile->rpcserv.history_file, config->rpc.history_file, sizeof(tile->rpcserv.history_file) );
    strncpy( tile->rpcserv.identity_key_path, config->paths.identity_key, sizeof(tile->rpcserv.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "arch_f" ) ||
                          !strcmp( tile->name, "arch_w" ) ) ) {

    strncpy( tile->archiver.rocksdb_path, config->tiles.archiver.rocksdb_path, sizeof(tile->archiver.rocksdb_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "back" ) ) ) {

    tile->archiver.end_slot = config->tiles.archiver.end_slot;
    strncpy( tile->archiver.ingest_mode, config->tiles.archiver.ingest_mode, sizeof(tile->archiver.ingest_mode) );
    if( FD_UNLIKELY( 0==strlen( tile->archiver.ingest_mode ) ) ) {
      FD_LOG_ERR(( "`archiver.ingest_mode` not specified in toml" ));
    }

    /* Validate arguments based on the ingest mode */
    if( !strcmp( tile->archiver.ingest_mode, "rocksdb" ) ) {
      strncpy( tile->archiver.rocksdb_path, config->tiles.archiver.rocksdb_path, PATH_MAX );
      if( FD_UNLIKELY( 0==strlen( tile->archiver.rocksdb_path ) ) ) {
        FD_LOG_ERR(( "`archiver.rocksdb_path` not specified in toml" ));
      }
    } else if( !strcmp( tile->archiver.ingest_mode, "shredcap" ) ) {
      strncpy( tile->archiver.shredcap_path, config->tiles.archiver.shredcap_path, PATH_MAX );
      if( FD_UNLIKELY( 0==strlen( tile->archiver.shredcap_path ) ) ) {
        FD_LOG_ERR(( "`archiver.shredcap_path` not specified in toml" ));
      }
      strncpy( tile->archiver.bank_hash_path, config->tiles.archiver.bank_hash_path, PATH_MAX );
      if( FD_UNLIKELY( 0==strlen( tile->archiver.bank_hash_path ) ) ) {
        FD_LOG_ERR(( "`archiver.bank_hash_path` not specified in toml" ));
      }
    } else {
      FD_LOG_ERR(( "Invalid ingest mode: %s", tile->archiver.ingest_mode ));
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "scap" ) ) ) {

    tile->shredcap.repair_intake_listen_port = config->tiles.repair.repair_intake_listen_port;
    strncpy( tile->shredcap.folder_path, config->tiles.shredcap.folder_path, sizeof(tile->shredcap.folder_path) );
    tile->shredcap.write_buffer_size = config->tiles.shredcap.write_buffer_size;
    tile->shredcap.enable_publish_stake_weights = 0; /* this is not part of the config */
    strncpy( tile->shredcap.manifest_path, "", PATH_MAX ); /* this is not part of the config */

  } else {
    FD_LOG_ERR(( "unknown tile name `%s`", tile->name ));
  }
}
