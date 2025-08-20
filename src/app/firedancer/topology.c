#include "topology.h"

#include "../../choreo/fd_choreo_base.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../discof/replay/fd_replay_notif.h"
#include "../../discof/gossip/fd_gossip_tile.h"
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

#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

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
setup_topo_runtime_pub( fd_topo_t *  topo,
                        char const * wksp_name,
                        ulong        mem_max ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "runtime_pub", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, mem_max, "obj.%lu.mem_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 12UL,    "obj.%lu.wksp_tag", obj->id ) );
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
resolve_gossip_entrypoint( char const *    host_port,
                           fd_ip4_port_t * ip4_port ) {

  /* Split host:port */

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
    if( FD_UNLIKELY( 0==resolve_gossip_entrypoint( config->gossip.entrypoints[ i ], &config->gossip.resolved_entrypoints[ i ] )) ) {
      FD_LOG_ERR(( "failed to resolve address of [gossip.entrypoints] entry \"%s\"", config->gossip.entrypoints[ i ] ));
    }
  }
}

static void
setup_snapshots( config_t *       config,
                 fd_topo_tile_t * tile ) {
  fd_memcpy( tile->snaprd.snapshots_path, config->paths.snapshots, PATH_MAX );
  fd_memcpy( tile->snaprd.cluster, config->firedancer.snapshots.cluster, sizeof(tile->snaprd.cluster) );
  tile->snaprd.incremental_snapshot_fetch   = config->firedancer.snapshots.incremental_snapshots;
  tile->snaprd.do_download                  = config->firedancer.snapshots.download;
  tile->snaprd.maximum_local_snapshot_age   = config->firedancer.snapshots.maximum_local_snapshot_age;
  tile->snaprd.minimum_download_speed_mib   = config->firedancer.snapshots.minimum_download_speed_mib;
  tile->snaprd.maximum_download_retry_abort = config->firedancer.snapshots.maximum_download_retry_abort;
  /* TODO: set up known validators and known validators cnt */
}

void
fd_topo_initialize( config_t * config ) {
  resolve_gossip_entrypoints( config );
  config->gossip.boot_timestamp_nanos = fd_log_wallclock();

  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  ulong exec_tile_cnt   = config->firedancer.layout.exec_tile_count;
  ulong writer_tile_cnt = config->firedancer.layout.writer_tile_count;
  ulong gossvf_tile_cnt = config->firedancer.layout.gossvf_tile_count;
  ulong resolv_tile_cnt = config->layout.resolv_tile_count;
  ulong sign_tile_cnt   = config->firedancer.layout.sign_tile_count;

  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );

  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  /*             topo, name */
  fd_topob_wksp( topo, "metric_in"  );
  fd_topob_wksp( topo, "net_shred"  );
  fd_topob_wksp( topo, "gossip_net" );
  fd_topob_wksp( topo, "net_repair" );
  fd_topob_wksp( topo, "net_quic"   );
  fd_topob_wksp( topo, "net_send"   );

  fd_topob_wksp( topo, "quic_verify"  );
  fd_topob_wksp( topo, "verify_dedup" );
  fd_topob_wksp( topo, "dedup_pack"   );

//  fd_topob_wksp( topo, "dedup_resolv" );
  fd_topob_wksp( topo, "resolv_pack"  );

  fd_topob_wksp( topo, "shred_repair" );
  fd_topob_wksp( topo, "stake_out"    );

  fd_topob_wksp( topo, "poh_shred"    );

  fd_topob_wksp( topo, "shred_sign"   );
  fd_topob_wksp( topo, "sign_shred"   );

  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_wksp( topo, "sign_gossip"  );

  fd_topob_wksp( topo, "replay_exec"  );
  fd_topob_wksp( topo, "exec_writer"  );

  fd_topob_wksp( topo, "send_sign"    );
  fd_topob_wksp( topo, "sign_send"    );

  fd_topob_wksp( topo, "gossip_out"   );
  fd_topob_wksp( topo, "replay_out"   );
  fd_topob_wksp( topo, "root_out"     );
  fd_topob_wksp( topo, "ipecho_out"  );

  fd_topob_wksp( topo, "gossvf_gossi" );
  fd_topob_wksp( topo, "gossip_gossv" );

  fd_topob_wksp( topo, "repair_sign"  );

  fd_topob_wksp( topo, "repair_repla" );
  fd_topob_wksp( topo, "replay_poh"   );
  fd_topob_wksp( topo, "bank_busy"    );
  fd_topob_wksp( topo, "tower_send"  );
  fd_topob_wksp( topo, "send_txns"    );

  fd_topob_wksp( topo, "quic"        );
  fd_topob_wksp( topo, "verify"      );
  fd_topob_wksp( topo, "dedup"       );
  fd_topob_wksp( topo, "shred"       );
  fd_topob_wksp( topo, "pack"        );
  fd_topob_wksp( topo, "resolv"      );
  fd_topob_wksp( topo, "sign"        );
  fd_topob_wksp( topo, "repair"      );
  fd_topob_wksp( topo, "ipecho"      );
  fd_topob_wksp( topo, "gossvf"      );
  fd_topob_wksp( topo, "gossip"      );
  fd_topob_wksp( topo, "metric"      );
  fd_topob_wksp( topo, "replay"      );
  fd_topob_wksp( topo, "runtime_pub" );
  fd_topob_wksp( topo, "banks"       );
  fd_topob_wksp( topo, "bh_cmp" );
  fd_topob_wksp( topo, "exec"        );
  fd_topob_wksp( topo, "writer"      );
  fd_topob_wksp( topo, "store"       );
  fd_topob_wksp( topo, "fec_sets"    );
  fd_topob_wksp( topo, "tcache"      );
  fd_topob_wksp( topo, "poh"         );
  fd_topob_wksp( topo, "send"        );
  fd_topob_wksp( topo, "tower"       );
  fd_topob_wksp( topo, "exec_spad"   );
  fd_topob_wksp( topo, "exec_fseq"   );
  fd_topob_wksp( topo, "funk" );

  fd_topob_wksp( topo, "snapdc" );
  fd_topob_wksp( topo, "snaprd" );
  fd_topob_wksp( topo, "snapin" );
  fd_topob_wksp( topo, "snapdc_rd" );
  fd_topob_wksp( topo, "snapin_rd" );
  fd_topob_wksp( topo, "snap_stream" );
  fd_topob_wksp( topo, "snap_zstd" );
  fd_topob_wksp( topo, "snap_out" );
  fd_topob_wksp( topo, "replay_manif" );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  ulong pending_fec_shreds_depth = fd_ulong_min( fd_ulong_pow2_up( config->tiles.shred.max_pending_shred_sets * FD_REEDSOL_DATA_SHREDS_MAX ), USHORT_MAX + 1 /* dcache max */ );

  /*                                  topo, link_name,      wksp_name,      depth,                                    mtu,                           burst */
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  config->tiles.verify.receive_buffer_size, FD_TPU_REASM_MTU,              config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,             1UL );
  /**/                 fd_topob_link( topo, "dedup_pack",   "dedup_pack",   config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,             1UL );

  /**/                 fd_topob_link( topo, "stake_out",    "stake_out",    128UL,                                    FD_STAKE_OUT_MTU,              1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                          1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "gossip_sign",  "gossip_sign",  128UL,                                    2048UL,                        1UL );
  /**/                 fd_topob_link( topo, "sign_gossip",  "sign_gossip",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );

//  /**/                 fd_topob_link( topo, "dedup_resolv", "dedup_resolv", 65536UL,                                  FD_TPU_PARSED_MTU,             1UL );
  FOR(resolv_tile_cnt) fd_topob_link( topo, "resolv_pack",  "resolv_pack",  65536UL,                                  FD_TPU_RESOLVED_MTU,           1UL );

  /* TODO: The MTU is currently relatively arbitrary and needs to be resized to the size of the largest
     message that is outbound from the replay to exec. */
  FOR(exec_tile_cnt)   fd_topob_link( topo, "replay_exec",  "replay_exec",  128UL,                                    10240UL,                       exec_tile_cnt );
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

  FOR(exec_tile_cnt)   fd_topob_link( topo, "exec_writer",  "exec_writer",  128UL,                                    FD_EXEC_WRITER_MTU,            1UL );

  /**/                 fd_topob_link( topo, "gossip_out",   "gossip_out",   65536UL*4UL,                              sizeof(fd_gossip_update_message_t), 1UL );
  /**/                 fd_topob_link( topo, "replay_out",   "replay_out",   128UL,                                    sizeof(fd_replay_out_t),       1UL );
  /**/                 fd_topob_link( topo, "root_out",     "root_out",     128UL,                                    sizeof(fd_block_id_t),         1UL );
  /**/                 fd_topob_link( topo, "ipecho_out",   "ipecho_out",   4UL,                                      0UL,                           1UL );

  FOR(gossvf_tile_cnt) fd_topob_link( topo, "gossvf_gossi", "gossvf_gossi", config->net.ingress_buffer_size,          sizeof(fd_gossip_view_t)+FD_NET_MTU, 1UL );
  /**/                 fd_topob_link( topo, "gossip_gossv", "gossip_gossv", 65536UL*4UL,                              sizeof(fd_gossip_ping_update_t), 1UL );

  /**/                 fd_topob_link( topo, "gossip_net",   "gossip_net",   65536*4UL,                                FD_NET_MTU,                    1UL );
  /**/                 fd_topob_link( topo, "send_net",     "net_send",     config->net.ingress_buffer_size,          FD_NET_MTU,                    2UL );

  /**/                 fd_topob_link( topo, "repair_net",   "net_repair",   config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  /**/                 fd_topob_link( topo, "ping_sign",    "repair_sign",  128UL,                                    2048UL,                        1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_repair", "shred_repair", pending_fec_shreds_depth,                 FD_SHRED_REPAIR_MTU,           2UL /* at most 2 msgs per after_frag */ );


  FOR(shred_tile_cnt)  fd_topob_link( topo, "repair_shred", "shred_repair", pending_fec_shreds_depth,                 sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "sign_ping",    "repair_sign",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "repair_sign",  "repair_sign",  128UL,                                    2048UL,                        1UL );
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "sign_repair",  "repair_sign",  1024UL,                                   sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "repair_repla", "repair_repla", 65536UL,                                  sizeof(fd_reasm_fec_t),                                      1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "replay_poh",   "replay_poh",   128UL,                                    (4096UL*sizeof(fd_txn_p_t))+sizeof(fd_microblock_trailer_t), 1UL  );
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    16384UL,                                  USHORT_MAX,                    1UL   );
  /**/                 fd_topob_link( topo, "poh_pack",     "replay_poh",   128UL,                                    sizeof(fd_became_leader_t) ,   1UL   );

  /**/                 fd_topob_link( topo, "tower_send",   "tower_send",   65536UL,                                  sizeof(fd_txn_p_t),            1UL   );
  /**/                 fd_topob_link( topo, "send_txns",    "send_txns",    128UL,                                    FD_TPU_RAW_MTU,                1UL   );
  /**/                 fd_topob_link( topo, "send_sign",    "send_sign",    128UL,                                    FD_TXN_MTU,                    1UL   );
  /**/                 fd_topob_link( topo, "sign_send",    "sign_send",    128UL,                                    sizeof(fd_ed25519_sig_t),      1UL   );
  /**/                 fd_topob_link( topo, "snap_zstd",    "snap_zstd",    8192UL,                                   16384UL,                       1UL );
  /**/                 fd_topob_link( topo, "snap_stream",  "snap_stream",  2048UL,                                   USHORT_MAX,                    1UL );
  /**/                 fd_topob_link( topo, "snap_out",     "snap_out",     2UL,                                      sizeof(fd_snapshot_manifest_t), 1UL );
  /**/                 fd_topob_link( topo, "snapdc_rd",    "snapdc_rd",    128UL,                                    0UL,                           1UL );
  /**/                 fd_topob_link( topo, "snapin_rd",    "snapin_rd",    128UL,                                    0UL,                           1UL );

  /* Replay decoded manifest dcache topo obj */
  fd_topo_obj_t * replay_manifest_dcache = fd_topob_obj( topo, "dcache", "replay_manif" );
  fd_pod_insertf_ulong( topo->props, 2UL << 30UL, "obj.%lu.data_sz", replay_manifest_dcache->id );
  fd_pod_insert_ulong(  topo->props, "manifest_dcache", replay_manifest_dcache->id );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );
  int is_bench_auto_affinity = !strcmp( config->development.bench.affinity, "auto" );

  if( FD_UNLIKELY( is_auto_affinity != is_bench_auto_affinity ) ) {
    FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] and [development.bench.affinity] must all be set to 'auto' or all be set to a specific CPU affinity string." ));
  }

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
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_repair", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_quic",   i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_shred",  i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_send",   i, config->net.ingress_buffer_size );

  /*                                              topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave, uses_keyswitch */
  FOR(quic_tile_cnt)               fd_topob_tile( topo, "quic",    "quic",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(verify_tile_cnt)             fd_topob_tile( topo, "verify",  "verify",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                             fd_topob_tile( topo, "dedup",   "dedup",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(resolv_tile_cnt)             fd_topob_tile( topo, "resolv",  "resolv",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,        0 );
  FOR(shred_tile_cnt)              fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  FOR(sign_tile_cnt)               fd_topob_tile( topo, "sign",    "sign",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                             fd_topob_tile( topo, "metric",  "metric",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  fd_topo_tile_t * pack_tile =     fd_topob_tile( topo, "pack",    "pack",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                             fd_topob_tile( topo, "poh",     "poh",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  FOR(gossvf_tile_cnt)             fd_topob_tile( topo, "gossvf",  "gossvf",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                             fd_topob_tile( topo, "gossip",  "gossip",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                             fd_topob_tile( topo, "ipecho",  "ipecho",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  fd_topo_tile_t * repair_tile =   fd_topob_tile( topo, "repair",  "repair",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                             fd_topob_tile( topo, "send",    "send",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  fd_topo_tile_t * replay_tile =   fd_topob_tile( topo, "replay",  "replay",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(exec_tile_cnt)               fd_topob_tile( topo, "exec",    "exec",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                             fd_topob_tile( topo, "tower",   "tower",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(writer_tile_cnt)             fd_topob_tile( topo, "writer",  "writer",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  fd_topo_tile_t * snaprd_tile = fd_topob_tile( topo, "snaprd", "snaprd", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  snaprd_tile->allow_shutdown = 1;
  fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  snapdc_tile->allow_shutdown = 1;
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "snapin", "snapin", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  snapin_tile->allow_shutdown = 1;

  /* Database cache */

  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib,
      config->firedancer.funk.lock_pages );

  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /*                */ fd_topob_tile_uses( topo, replay_tile,  funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo,  &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* Setup a shared wksp object for banks. */

  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.limits.max_total_banks, config->firedancer.runtime.limits.max_fork_width );
  fd_topob_tile_uses( topo, replay_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  /* Setup a shared wksp object for bank hash cmp. */

  fd_topo_obj_t * bank_hash_cmp_obj = setup_topo_bank_hash_cmp( topo, "bh_cmp" );
  fd_topob_tile_uses( topo, replay_tile, bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, bank_hash_cmp_obj->id, "bh_cmp" ) );

  /* Setup a shared wksp object for fec sets. */

  ulong shred_depth = 65536UL; /* from fdctl/topology.c shred_store link. MAKE SURE TO KEEP IN SYNC. */
  ulong fec_set_cnt = shred_depth + config->tiles.shred.max_pending_shred_sets + 4UL;
  ulong fec_sets_sz = fec_set_cnt*sizeof(fd_shred34_t)*4; /* mirrors # of dcache entires in frankendancer */
  fd_topo_obj_t * fec_sets_obj = setup_topo_fec_sets( topo, "fec_sets", shred_tile_cnt*fec_sets_sz );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile,  fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  fd_topob_tile_uses( topo, repair_tile, fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_sets_obj->id, "fec_sets" ) );

  /* Setup a shared wksp object for runtime pub. */

  fd_topo_obj_t * runtime_pub_obj = setup_topo_runtime_pub( topo, "runtime_pub", config->firedancer.runtime.heap_size_gib<<30 );

  fd_topob_tile_uses( topo, replay_tile, runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, pack_tile,   runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, runtime_pub_obj->id, "runtime_pub" ) );

  /* Setup a shared wksp object for store. */

  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.store.max_completed_shred_sets, (uint)shred_tile_cnt );
  FOR(shred_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  /* Create a txncache to be used by replay. */
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "tcache",
      config->firedancer.runtime.limits.max_rooted_slots,
      config->firedancer.runtime.limits.max_live_slots,
      config->firedancer.runtime.limits.max_transactions_per_slot );
  fd_topob_tile_uses( topo, replay_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );
    fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_spad_obj = fd_topob_obj( topo, "exec_spad", "exec_spad" );
    fd_topob_tile_uses( topo, replay_tile, exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    for( ulong j=0UL; j<writer_tile_cnt; j++ ) {
      /* For txn_ctx. */
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", j ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    }
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_spad_obj->id, "exec_spad.%lu", i ) );
  }

  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_fseq_obj = fd_topob_obj( topo, "fseq", "exec_fseq" );
    fd_topob_tile_uses( topo, replay_tile, exec_fseq_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_fseq_obj->id, "exec_fseq.%lu", i ) );
  }

  fd_topob_tile_uses( topo, snapin_tile, funk_obj,               FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapin_tile, runtime_pub_obj,        FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapin_tile, replay_manifest_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, replay_manifest_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY );

  /* There's another special fseq that's used to communicate the shred
    version from the Agave boot path to the shred tile. */
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "gossip", 0UL ) ];
  fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );

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

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  for( ulong j=0UL; j<shred_tile_cnt; j++ )
                  fd_topos_tile_in_net(  topo,                          "metric_in", "shred_net",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong j=0UL; j<quic_tile_cnt; j++ )
                  fd_topos_tile_in_net(  topo,                          "metric_in", "quic_net",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                      fd_topob_tile_in(  topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_verify",  i                                                  );
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_net",     i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                      fd_topob_tile_in(   topo, "verify",  i,            "metric_in", "quic_verify",  j,           FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_out( topo, "verify",  i,                         "verify_dedup", i                                                 );
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "gossip_out",   0UL,         FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in(  topo, "gossip",  0UL,         "metric_in", "send_txns",     0UL,         FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in(  topo, "verify",  0UL,         "metric_in", "send_txns",     0UL,         FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "dedup",   0UL,         "metric_in", "verify_dedup",  i,           FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "dedup",   0UL,                       "dedup_pack",   0UL                                                );
//  FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "dedup_resolv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
//  FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "replay_resol", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_out( topo, "resolv",  i,                         "resolv_pack",  i                                                  );
  /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "resolv_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /**/             fd_topos_tile_in_net (  topo,                          "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/             fd_topos_tile_in_net (  topo,                          "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/             fd_topos_tile_in_net (  topo,                          "metric_in", "send_net",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in ( topo, "shred",  i,             "metric_in", "net_shred",     j,            FD_TOPOB_UNRELIABLE,   FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt)  fd_topob_tile_in ( topo, "shred",  i,             "metric_in", "poh_shred",     0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in ( topo, "shred",  i,             "metric_in", "stake_out",     0UL,          FD_TOPOB_RELIABLE,     FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in ( topo, "shred",  0UL,           "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_repair",  i                                                    );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_net",     i                                                    );

  FOR(shred_tile_cnt)  fd_topob_tile_in ( topo, "shred",  i,             "metric_in",  "repair_shred", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_out( topo, "repair",  0UL,                       "repair_net",    0UL                                                  );

  /**/                 fd_topob_tile_in ( topo, "tower",  0UL,          "metric_in",  "gossip_out",   0UL,           FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in ( topo, "tower",  0UL,          "metric_in",  "replay_out",   0UL,           FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in ( topo, "tower",  0UL,          "metric_in",  "snap_out",     0UL,           FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "tower",  0UL,                        "root_out",     0UL                                                   );
  /**/                 fd_topob_tile_out( topo, "tower",  0UL,                        "tower_send",   0UL                                                   );

  /**/                 fd_topob_tile_out( topo, "ipecho", 0UL,                        "ipecho_out",   0UL                                                   );
  FOR(shred_tile_cnt)  fd_topob_tile_in ( topo, "shred",  i,             "metric_in", "ipecho_out",   0UL,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED  );

  /* Sign links don't need to be reliable because they are synchronous,
    so there's at most one fragment in flight at a time anyway.  The
    sign links are also not polled by fd_stem, instead the tiles will
    read the sign responses out of band in a dedicated spin loop. */
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in ( topo, "sign",   0UL,           "metric_in", "shred_sign",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",    i                                                    );
    /**/               fd_topob_tile_in ( topo, "shred",  i,             "metric_in", "sign_shred",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",    i                                                    );
  }

  FOR(gossvf_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "net_gossvf",   j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(gossvf_tile_cnt) fd_topob_tile_out( topo, "gossvf",   i,                         "gossvf_gossi", i                                                    );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "gossip_gossv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossvf",   i,            "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_in ( topo, "gossip",   0UL,          "metric_in", "stake_out",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_out",   0UL                                                  );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_net",   0UL                                                  );
  /**/                 fd_topob_tile_in ( topo, "sign",     0UL,          "metric_in", "gossip_sign",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_sign",  0UL                                                  );
  /**/                 fd_topob_tile_in ( topo, "gossip",   0UL,          "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(gossvf_tile_cnt) fd_topob_tile_in ( topo, "gossip",   0UL,          "metric_in", "gossvf_gossi", i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip",   0UL,                       "gossip_gossv", 0UL                                                  );
  /**/                 fd_topob_tile_in ( topo, "gossip",   0UL,          "metric_in", "sign_gossip",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out( topo, "sign",     0UL,                       "sign_gossip",  0UL                                                  );

  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "net_repair",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "gossip_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "root_out",      0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "stake_out",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
                       fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "snap_out",      0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "repair",  0UL,          "metric_in", "shred_repair",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

  /**/                 fd_topob_tile_in ( topo, "replay",  0UL,          "metric_in", "repair_repla",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "stake_out",     0UL                                                  );
  /**/                 fd_topob_tile_in ( topo, "replay",  0UL,          "metric_in", "root_out",      0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "replay_out",    0UL                                                  );
  FOR(bank_tile_cnt)   fd_topob_tile_out( topo, "replay",  0UL,                       "replay_poh",    i                                                    );
  FOR(exec_tile_cnt)   fd_topob_tile_out( topo, "replay",  0UL,                       "replay_exec",   i                                                    ); /* TODO check order in fd_replay.c macros*/

  FOR(exec_tile_cnt)   fd_topob_tile_in(  topo, "exec",    i,            "metric_in", "replay_exec",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED    );
  FOR(exec_tile_cnt)   fd_topob_tile_out( topo, "exec",    i,                         "exec_writer",  i                                                     );
  /* All writer tiles read from all exec tiles.  Each exec tile has a
     single out link, over which all the writer tiles round-robin. */
  FOR(writer_tile_cnt) for( ulong j=0UL; j<exec_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "writer",  i,            "metric_in", "exec_writer",  j,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED    );

  /**/                 fd_topob_tile_in ( topo, "send",   0UL,         "metric_in", "stake_out",     0UL,    FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,         "metric_in", "gossip_out",    0UL,    FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,         "metric_in", "tower_send",    0UL,    FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,         "metric_in", "net_send",      0UL,    FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "send",   0UL,                      "send_net",      0UL                                            );
  /**/                 fd_topob_tile_out( topo, "send",   0UL,                      "send_txns",     0UL                                            );
  /**/                 fd_topob_tile_out( topo, "send",   0UL,                      "send_sign",     0UL                                            );
  /**/                 fd_topob_tile_in ( topo, "sign",   0UL,         "metric_in", "send_sign",     0UL,    FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "sign",   0UL,                      "sign_send",     0UL                                            );
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,         "metric_in", "sign_send",     0UL,    FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );

  /**/                 fd_topob_tile_in ( topo, "pack",   0UL,         "metric_in",  "dedup_pack",   0UL,    FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in ( topo, "pack",   0UL,         "metric_in",  "poh_pack",     0UL,    FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  FOR(bank_tile_cnt)   fd_topob_tile_in ( topo, "poh",    0UL,         "metric_in",  "replay_poh",   i,      FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in ( topo, "poh",    0UL,         "metric_in",  "stake_out",    0UL,    FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                       "poh_shred",    0UL                                            );

                       fd_topob_tile_out( topo, "poh",    0UL,                       "poh_pack",     0UL                                            );

  /**/                 fd_topob_tile_in ( topo, "sign",   0UL,         "metric_in",  "ping_sign",    0UL,    FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                       "ping_sign",    0UL                                            );
  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                       "repair_repla", 0UL                                            );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "repair", 0UL,                       "repair_shred", i                                              );
  /**/                 fd_topob_tile_out( topo, "sign",   0UL,                       "sign_ping",    0UL                                            );

  FOR(sign_tile_cnt-1) fd_topob_tile_out( topo, "repair", 0UL,                        "repair_sign",  i                                              );
  FOR(sign_tile_cnt-1) fd_topob_tile_in ( topo, "sign",   i+1,           "metric_in", "repair_sign",  i,      FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(sign_tile_cnt-1) fd_topob_tile_out( topo, "sign",   i+1,                        "sign_repair",  i                                              );
  FOR(sign_tile_cnt-1) fd_topob_tile_in ( topo, "repair", 0UL,           "metric_in", "sign_repair",  i,      FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_in ( topo, "repair", 0UL,           "metric_in", "sign_ping",    0UL,    FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );


  fd_topob_tile_out( topo, "snaprd", 0UL, "snap_zstd", 0UL );
  fd_topob_tile_in ( topo, "snapdc", 0UL, "metric_in", "snap_zstd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc", 0UL, "snap_stream", 0UL );
  fd_topob_tile_in ( topo, "snapin", 0UL, "metric_in", "snap_stream", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_out( topo, "snapin", 0UL, "snap_out", 0UL );
  fd_topob_tile_in ( topo, "replay", 0UL, "metric_in", "snap_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_in ( topo, "snaprd", 0UL, "metric_in", "snapdc_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc", 0UL, "snapdc_rd", 0UL );
  fd_topob_tile_in ( topo, "snaprd", 0UL, "metric_in", "snapin_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin", 0UL, "snapin_rd", 0UL );
  /* TODO: Fix backpressure issues and change this back to reliable. */
  fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "gossip_out", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

  if( config->tiles.archiver.enabled ) {
    fd_topob_wksp( topo, "arch_f" );
    fd_topob_wksp( topo, "arch_w" );
    /**/ fd_topob_tile( topo, "arch_f", "arch_f", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
    /**/ fd_topob_tile( topo, "arch_w", "arch_w", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    fd_topob_wksp( topo, "feeder" );
    fd_topob_link( topo, "feeder", "feeder", 65536UL, 4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
    /**/ fd_topob_tile_out( topo, "replay", 0UL, "feeder", 0UL );
    /**/ fd_topob_tile_in(  topo, "arch_f", 0UL, "metric_in", "feeder", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_wksp( topo, "arch_f2w" );
    fd_topob_link( topo, "arch_f2w", "arch_f2w", 128UL, 4UL*FD_SHRED_STORE_MTU, 1UL );
    /**/ fd_topob_tile_out( topo, "arch_f", 0UL, "arch_f2w", 0UL );
    /**/ fd_topob_tile_in( topo, "arch_w", 0UL, "metric_in", "arch_f2w", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  if( config->tiles.shredcap.enabled ) {
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
    fd_topob_tile_in( topo, "shrdcp", 0UL, "metric_in", "gossip_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "repair_scap", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "replay_scap", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_out( topo, "repair", 0UL, "repair_scap", 0UL );
    fd_topob_tile_out( topo, "replay", 0UL, "replay_scap", 0UL );

    /* No default fd_topob_tile_in connection to stake_out */
  }

  fd_topob_wksp( topo, "replay_notif" );
  /* We may be notifying an external service, so always publish on this link. */
  /**/ fd_topob_link( topo, "replay_notif", "replay_notif", FD_REPLAY_NOTIF_DEPTH, FD_REPLAY_NOTIF_MTU, 1UL )->permit_no_consumers = 1;
  /**/ fd_topob_tile_out( topo, "replay",  0UL, "replay_notif", 0UL );

  int enable_rpc = ( config->rpc.port != 0 );
  if( enable_rpc ) {
    fd_topob_wksp( topo, "rpcsrv" );
    fd_topo_tile_t * rpcserv_tile = fd_topob_tile( topo, "rpcsrv",  "rpcsrv",  "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    fd_topob_tile_uses( topo, rpcserv_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, rpcserv_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_in( topo, "rpcsrv", 0UL, "metric_in",  "replay_notif", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "rpcsrv", 0UL, "metric_in",  "stake_out",    0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "rpcsrv",  0UL, "metric_in", "repair_repla", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
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
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "votes_plugin", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  fd_topob_wksp( topo, "writ_repl" );
  FOR(writer_tile_cnt) fd_topob_link(     topo, "writ_repl", "writ_repl", 1UL, FD_RUNTIME_PUBLIC_ACCOUNT_UPDATE_MSG_FOOTPRINT, 1UL );
  FOR(writer_tile_cnt) fd_topob_tile_out( topo, "writer",    i,                               "writ_repl", i );
  FOR(writer_tile_cnt) fd_topob_tile_in(  topo, "replay",    0UL,      "metric_in", "writ_repl", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  if( FD_LIKELY( config->tiles.gui.enabled ) ) {
    fd_topob_wksp( topo, "gui"          );
    /**/                 fd_topob_tile(     topo, "gui",     "gui",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,        "metric_in",     "plugin_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !fd_topo_configure_tile( tile, config ) ) {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );

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

int
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config ) {
    if( FD_UNLIKELY( !strcmp( tile->name, "net" ) || !strcmp( tile->name, "sock" ) ) ) {

      tile->net.shred_listen_port              = config->tiles.shred.shred_listen_port;
      tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;
      tile->net.gossip_listen_port             = config->gossip.port;
      tile->net.repair_intake_listen_port      = config->tiles.repair.repair_intake_listen_port;
      tile->net.repair_serve_listen_port       = config->tiles.repair.repair_serve_listen_port;
      tile->net.send_src_port                  = config->tiles.send.send_src_port;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "netlnk" ) ) ) {

      /* already configured */

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

    } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {
      strncpy( tile->shred.identity_key_path, config->paths.identity_key, sizeof(tile->shred.identity_key_path) );

      tile->shred.depth                         = 65536UL;
      tile->shred.fec_resolver_depth            = config->tiles.shred.max_pending_shred_sets;
      tile->shred.expected_shred_version        = config->consensus.expected_shred_version;
      tile->shred.shred_listen_port             = config->tiles.shred.shred_listen_port;
      tile->shred.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;

    } else if( FD_UNLIKELY( !strcmp( tile->name, "gossip" ) ) ) {
      if( FD_UNLIKELY( strcmp( config->gossip.host, "" ) ) ) {
        if( !resolve_address( config->gossip.host, &tile->gossip.ip_addr ) )
          FD_LOG_ERR(( "could not resolve [gossip.host] %s", config->gossip.host ));
      } else {
        tile->gossip.ip_addr = config->net.ip_addr;
      }
      strncpy( tile->gossip.identity_key_path, config->paths.identity_key, sizeof(tile->gossip.identity_key_path) );
      tile->gossip.shred_version       = config->consensus.expected_shred_version;
      tile->gossip.max_entries         = config->tiles.gossip.max_entries;
      tile->gossip.boot_timesamp_nanos = config->gossip.boot_timestamp_nanos;

      tile->gossip.ip_addr = config->net.ip_addr;

      tile->gossip.ports.gossip           = config->gossip.port;
      tile->gossip.ports.tvu              = config->tiles.shred.shred_listen_port;
      tile->gossip.ports.tpu              = config->tiles.quic.regular_transaction_listen_port;
      tile->gossip.ports.tpu_quic         = config->tiles.quic.quic_transaction_listen_port;
      tile->gossip.ports.repair           = config->tiles.repair.repair_intake_listen_port;

      tile->gossip.entrypoints_cnt        = config->gossip.entrypoints_cnt;
      fd_memcpy( tile->gossip.entrypoints, config->gossip.resolved_entrypoints, tile->gossip.entrypoints_cnt * sizeof(fd_ip4_port_t) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "gossvf") ) ) {
      strncpy( tile->gossvf.identity_key_path, config->paths.identity_key, sizeof(tile->gossvf.identity_key_path) );
      tile->gossvf.tcache_depth          = 1<<22UL; /* TODO: user defined option */
      tile->gossvf.shred_version         = 0U;
      tile->gossvf.allow_private_address = config->development.gossip.allow_private_address;
      tile->gossvf.boot_timesamp_nanos   = config->gossip.boot_timestamp_nanos;

      tile->gossvf.entrypoints_cnt = config->gossip.entrypoints_cnt;
      fd_memcpy( tile->gossvf.entrypoints, config->gossip.resolved_entrypoints, tile->gossvf.entrypoints_cnt * sizeof(fd_ip4_port_t) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "ipecho") ) ) {
      tile->ipecho.expected_shred_version = config->consensus.expected_shred_version;
      tile->ipecho.bind_address           = config->net.ip_addr;
      tile->ipecho.bind_port              = config->gossip.port;
      tile->ipecho.entrypoints_cnt        = config->gossip.entrypoints_cnt;
      fd_memcpy( tile->ipecho.entrypoints, config->gossip.resolved_entrypoints, tile->ipecho.entrypoints_cnt * sizeof(fd_ip4_port_t) );
    } else if( FD_UNLIKELY( !strcmp( tile->name, "repair" ) ) ) {
      tile->repair.max_pending_shred_sets    = config->tiles.shred.max_pending_shred_sets;
      tile->repair.repair_intake_listen_port = config->tiles.repair.repair_intake_listen_port;
      tile->repair.repair_serve_listen_port  = config->tiles.repair.repair_serve_listen_port;
      tile->repair.slot_max                  = config->tiles.repair.slot_max;
      strncpy( tile->repair.good_peer_cache_file, config->tiles.repair.good_peer_cache_file, sizeof(tile->repair.good_peer_cache_file) );

      strncpy( tile->repair.identity_key_path, config->paths.identity_key, sizeof(tile->repair.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "replay" ) )) {

      tile->replay.fec_max = config->tiles.shred.max_pending_shred_sets;
      tile->replay.max_vote_accounts = config->firedancer.runtime.limits.max_vote_accounts;

      /* specified by [tiles.replay] */

      strncpy( tile->replay.blockstore_file,    config->firedancer.blockstore.file,    sizeof(tile->replay.blockstore_file) );
      strncpy( tile->replay.blockstore_checkpt, config->firedancer.blockstore.checkpt, sizeof(tile->replay.blockstore_checkpt) );

      tile->replay.tx_metadata_storage = config->rpc.extended_tx_metadata_storage;
      strncpy( tile->replay.funk_checkpt, config->tiles.replay.funk_checkpt, sizeof(tile->replay.funk_checkpt) );

      tile->replay.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
      tile->replay.plugins_enabled = fd_topo_find_tile( &config->topo, "plugin", 0UL ) != ULONG_MAX;

      if( FD_UNLIKELY( !strncmp( config->tiles.replay.genesis,  "", 1 ) &&
                       !strncmp( config->paths.snapshots, "", 1 ) ) ) {
        fd_cstr_printf_check( config->tiles.replay.genesis, PATH_MAX, NULL, "%s/genesis.bin", config->paths.ledger );
      }
      strncpy( tile->replay.genesis, config->tiles.replay.genesis, sizeof(tile->replay.genesis) );

      strncpy( tile->replay.slots_replayed, config->tiles.replay.slots_replayed, sizeof(tile->replay.slots_replayed) );
      strncpy( tile->replay.status_cache, config->tiles.replay.status_cache, sizeof(tile->replay.status_cache) );
      strncpy( tile->replay.cluster_version, config->tiles.replay.cluster_version, sizeof(tile->replay.cluster_version) );
      strncpy( tile->replay.tower_checkpt, config->tiles.replay.tower_checkpt, sizeof(tile->replay.tower_checkpt) );

      tile->replay.max_exec_slices = config->tiles.replay.max_exec_slices;

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

    } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
      strncpy( tile->sign.identity_key_path, config->paths.identity_key, sizeof(tile->sign.identity_key_path) );

    } else if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {
      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &tile->metric.prometheus_listen_addr ) ) )
        FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
      tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;
    } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {
      tile->pack.max_pending_transactions      = config->tiles.pack.max_pending_transactions;
      tile->pack.bank_tile_count               = config->layout.bank_tile_count;
      tile->pack.larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
      tile->pack.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
      tile->pack.use_consumed_cus              = config->tiles.pack.use_consumed_cus;
      tile->pack.schedule_strategy             = config->tiles.pack.schedule_strategy_enum;
      if( FD_UNLIKELY( tile->pack.use_consumed_cus ) ) FD_LOG_ERR(( "Firedancer does not support CU rebating yet.  [tiles.pack.use_consumed_cus] must be false" ));
    } else if( FD_UNLIKELY( !strcmp( tile->name, "poh" ) ) ) {
      strncpy( tile->poh.identity_key_path, config->paths.identity_key, sizeof(tile->poh.identity_key_path) );

      tile->poh.bank_cnt = config->layout.bank_tile_count;
    } else if( FD_UNLIKELY( !strcmp( tile->name, "send" ) ) ) {
      tile->send.send_src_port = config->tiles.send.send_src_port;
      tile->send.ip_addr = config->net.ip_addr;
      strncpy( tile->send.identity_key_path, config->paths.identity_key, sizeof(tile->send.identity_key_path) );
    } else if( FD_UNLIKELY( !strcmp( tile->name, "tower" ) ) ) {
      tile->tower.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
      strncpy( tile->tower.identity_key_path, config->paths.identity_key, sizeof(tile->tower.identity_key_path) );
      strncpy( tile->tower.vote_acc_path, config->paths.vote_account, sizeof(tile->tower.vote_acc_path) );
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
    } else if( FD_UNLIKELY( !strcmp( tile->name, "plugin" ) ) ) {

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
    } else if( FD_UNLIKELY( !strcmp( tile->name, "snaprd" ) ) ) {
      setup_snapshots( config, tile );
    } else if( FD_UNLIKELY( !strcmp( tile->name, "snapdc" ) ) ) {

    } else if( FD_UNLIKELY( !strcmp( tile->name, "snapin" ) ) ) {
      tile->snapin.funk_obj_id            = fd_pod_query_ulong( config->topo.props, "funk",      ULONG_MAX );
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
      return 0;
    }
  return 1;
}
