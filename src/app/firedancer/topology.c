#include "topology.h"

#include "../../disco/net/fd_net_tile.h"
#include "../../disco/quic/fd_tpu.h"
#include "../../disco/tiles.h"
#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_cpu_topo.h"
#include "../../disco/plugin/fd_plugin.h"
#include "../../discof/poh/fd_poh.h"
#include "../../flamenco/snapshot/fd_snapshot_base.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/tile/fd_tile_private.h"

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../funk/fd_funk.h"

#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_obj_t *
setup_topo_blockstore( fd_topo_t *  topo,
                       char const * wksp_name,
                       ulong        shred_max,
                       ulong        block_max,
                       ulong        idx_max,
                       ulong        alloc_max ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "blockstore", wksp_name );

  ulong seed;
  FD_TEST( sizeof(ulong) == getrandom( &seed, sizeof(ulong), 0 ) );

  FD_TEST( fd_pod_insertf_ulong( topo->props, 1UL,        "obj.%lu.wksp_tag",   obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, seed,       "obj.%lu.seed",       obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, shred_max,  "obj.%lu.shred_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, block_max,  "obj.%lu.block_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, idx_max,    "obj.%lu.idx_max",    obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, alloc_max,  "obj.%lu.alloc_max",  obj->id ) );

  /* DO NOT MODIFY LOOSE WITHOUT CHANGING HOW BLOCKSTORE ALLOCATES INTERNAL STRUCTURES */

  ulong blockstore_footprint = fd_blockstore_footprint( shred_max, block_max, idx_max ) + alloc_max;
  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_footprint,  "obj.%lu.loose", obj->id ) );

  return obj;
}

fd_topo_obj_t *
setup_topo_bank_hash_cmp( fd_topo_t * topo, char const * wksp_name ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "bh_cmp", wksp_name );
  return obj;
}

fd_topo_obj_t *
setup_topo_banks( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        max_banks ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "banks", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_banks, "obj.%lu.max_banks", obj->id ) );
  return obj;
}

static fd_topo_obj_t *
setup_topo_fec_sets( fd_topo_t * topo, char const * wksp_name, ulong sz ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "fec_sets", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, sz, "obj.%lu.sz",   obj->id ) );
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

fd_topo_obj_t *
setup_topo_funk( fd_topo_t *  topo,
                 char const * wksp_name,
                 ulong        max_account_records,
                 ulong        max_database_transactions,
                 ulong        heap_size_gib ) {
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
  ulong part_max = fd_wksp_part_max_est( funk_footprint, 1U<<14U );
  if( FD_UNLIKELY( !part_max ) ) FD_LOG_ERR(( "fd_wksp_part_max_est(%lu,16KiB) failed", funk_footprint ));
  wksp->part_max += part_max;

  return obj;
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

  struct addrinfo hints = { .ai_family = AF_INET };
  struct addrinfo * res;
  int err = getaddrinfo( fqdn, NULL, &hints, &res );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "cannot resolve [gossip.entrypoints] entry \"%s\": %i-%s", fqdn, err, gai_strerror( err ) ));
    return 0;
  }

  int resolved = 0;
  for( struct addrinfo * cur=res; cur; cur=cur->ai_next ) {
    if( FD_UNLIKELY( cur->ai_addr->sa_family!=AF_INET ) ) continue;
    struct sockaddr_in const * addr = (struct sockaddr_in const *)cur->ai_addr;
    ip4_port->addr = addr->sin_addr.s_addr;
    resolved = 1;
    break;
  }

  freeaddrinfo( res );
  return resolved;
}

static void
resolve_gossip_entrypoints( config_t * config ) {
  ulong entrypoint_cnt = config->gossip.entrypoints_cnt;
  ulong resolved_entrypoints = 0UL;
  for( ulong j=0UL; j<entrypoint_cnt; j++ ) {
    if( resolve_gossip_entrypoint( config->gossip.entrypoints[j], &config->gossip.resolved_entrypoints[resolved_entrypoints] ) ) {
      resolved_entrypoints++;
    }
  }
  config->gossip.resolved_entrypoints_cnt = resolved_entrypoints;
}

static void
setup_snapshots( config_t *       config,
                 fd_topo_tile_t * tile ) {
  uchar incremental_is_file, incremental_is_url;
  if( strnlen( config->tiles.replay.incremental, PATH_MAX )>0UL ) {
    incremental_is_file = 1U;
  } else {
    incremental_is_file = 0U;
  }
  if( strnlen( config->tiles.replay.incremental_url, PATH_MAX )>0UL ) {
    incremental_is_url = 1U;
  } else {
    incremental_is_url = 0U;
  }
  if( FD_UNLIKELY( incremental_is_file && incremental_is_url ) ) {
    FD_LOG_ERR(( "At most one of the incremental snapshot source strings in the configuration file under [tiles.replay.incremental] and [tiles.replay.incremental_url] may be set." ));
  }
  tile->replay.incremental_src_type = INT_MAX;
  if( FD_LIKELY( incremental_is_url ) ) {
    strncpy( tile->replay.incremental, config->tiles.replay.incremental_url, sizeof(tile->replay.incremental) );
    tile->replay.incremental_src_type = FD_SNAPSHOT_SRC_HTTP;
  }
  if( FD_UNLIKELY( incremental_is_file ) ) {
    strncpy( tile->replay.incremental, config->tiles.replay.incremental, sizeof(tile->replay.incremental) );
    tile->replay.incremental_src_type = FD_SNAPSHOT_SRC_FILE;
  }
  tile->replay.incremental[ sizeof(tile->replay.incremental)-1UL ] = '\0';

  uchar snapshot_is_file, snapshot_is_url;
  if( strnlen( config->tiles.replay.snapshot, PATH_MAX )>0UL ) {
    snapshot_is_file = 1U;
  } else {
    snapshot_is_file = 0U;
  }
  if( strnlen( config->tiles.replay.snapshot_url, PATH_MAX )>0UL ) {
    snapshot_is_url = 1U;
  } else {
    snapshot_is_url = 0U;
  }
  if( FD_UNLIKELY( snapshot_is_file && snapshot_is_url ) ) {
    FD_LOG_ERR(( "At most one of the full snapshot source strings in the configuration file under [tiles.replay.snapshot] and [tiles.replay.snapshot_url] may be set." ));
  }
  tile->replay.snapshot_src_type = INT_MAX;
  if( FD_LIKELY( snapshot_is_url ) ) {
    strncpy( tile->replay.snapshot, config->tiles.replay.snapshot_url, sizeof(tile->replay.snapshot) );
    tile->replay.snapshot_src_type = FD_SNAPSHOT_SRC_HTTP;
  }
  if( FD_UNLIKELY( snapshot_is_file ) ) {
    strncpy( tile->replay.snapshot, config->tiles.replay.snapshot, sizeof(tile->replay.snapshot) );
    tile->replay.snapshot_src_type = FD_SNAPSHOT_SRC_FILE;
  }
  tile->replay.snapshot[ sizeof(tile->replay.snapshot)-1UL ] = '\0';

  strncpy( tile->replay.snapshot_dir, config->tiles.replay.snapshot_dir, sizeof(tile->replay.snapshot_dir) );
  tile->replay.snapshot_dir[ sizeof(tile->replay.snapshot_dir)-1UL ] = '\0';
}

void
fd_topo_initialize( config_t * config ) {
  /* TODO: Not here ... */
  resolve_gossip_entrypoints( config );

  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong resolv_tile_cnt = config->layout.resolv_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;

  ulong exec_tile_cnt   = config->firedancer.layout.exec_tile_count;
  ulong writer_tile_cnt = config->firedancer.layout.writer_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  /*             topo, name */
  fd_topob_wksp( topo, "metric_in"    );
  fd_topob_wksp( topo, "net_gossip"   );
  fd_topob_wksp( topo, "net_repair"   );
  fd_topob_wksp( topo, "net_send"     );
  fd_topob_wksp( topo, "net_quic"     );
  fd_topob_wksp( topo, "net_shred"    );

  /* TODO: Switch to one gossip out, consumed by anyone interested. */
  fd_topob_wksp( topo, "gossip_shred" );
  fd_topob_wksp( topo, "gossip_repai" );
  fd_topob_wksp( topo, "gossip_verif" ); /* TODO: Already verified? Then dedup */
  fd_topob_wksp( topo, "gossip_tower" );
  fd_topob_wksp( topo, "gossip_send"  );

  fd_topob_wksp( topo, "shred_repair" );
  fd_topob_wksp( topo, "repair_repla" );
  fd_topob_wksp( topo, "replay_pack"  );
  fd_topob_wksp( topo, "replay_stake" );
  fd_topob_wksp( topo, "replay_exec"  );
  fd_topob_wksp( topo, "replay_tower" );
  fd_topob_wksp( topo, "exec_writer"  );
  fd_topob_wksp( topo, "tower_send"   );
  fd_topob_wksp( topo, "send_txns"    );

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
  fd_topob_wksp( topo, "executed_txn" );

  /* TODO: WTF is all of this for? */
  fd_topob_wksp( topo, "funk"         );
  fd_topob_wksp( topo, "runtime_pub"  );
  fd_topob_wksp( topo, "banks"        );
  fd_topob_wksp( topo, "bh_cmp"       );
  fd_topob_wksp( topo, "blockstore"   );
  fd_topob_wksp( topo, "fec_sets"     );
  fd_topob_wksp( topo, "txncache"     );
  fd_topob_wksp( topo, "exec_spad"    );
  fd_topob_wksp( topo, "exec_fseq"    );
  fd_topob_wksp( topo, "writer_fseq"  );
  fd_topob_wksp( topo, "slot_fseqs"   ); /* fseqs for marked slots eg. turbine slot */

  fd_topob_wksp( topo, "gossip_sign"  );
  fd_topob_wksp( topo, "sign_gossip"  );

  fd_topob_wksp( topo, "shred_sign"   );
  fd_topob_wksp( topo, "sign_shred"   );

  fd_topob_wksp( topo, "repair_sign"  );
  fd_topob_wksp( topo, "sign_repair"  );

  fd_topob_wksp( topo, "send_sign"    );
  fd_topob_wksp( topo, "sign_send"    );

  fd_topob_wksp( topo, "gossip"       );
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
  fd_topob_wksp( topo, "shred"        );
  fd_topob_wksp( topo, "sign"         );
  fd_topob_wksp( topo, "metric"       );
  fd_topob_wksp( topo, "cswtch"       );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /* TODO: Explain this .... USHORT_MAX is not dcache max */
  ulong pending_fec_shreds_depth = fd_ulong_min( fd_ulong_pow2_up( config->tiles.shred.max_pending_shred_sets * FD_REEDSOL_DATA_SHREDS_MAX ), USHORT_MAX + 1 /* dcache max */ );

  /*                                  topo, link_name,      wksp_name,      depth,                                    mtu,                    burst */
  /**/                 fd_topob_link( topo, "gossip_net",   "net_gossip",   config->net.ingress_buffer_size,          FD_NET_MTU,             1UL );
  /**/                 fd_topob_link( topo, "repair_net",   "net_repair",   config->net.ingress_buffer_size,          FD_NET_MTU,             1UL );
  /**/                 fd_topob_link( topo, "send_net",     "net_send",     config->net.ingress_buffer_size,          FD_NET_MTU,             2UL ); /* TODO: Is 2 correct? */
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     config->net.ingress_buffer_size,          FD_NET_MTU,             1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    32768UL,                                  FD_NET_MTU,             1UL );

  /* TODO: Switch to one gossip out, consumed by anyone interested. */
  /**/                 fd_topob_link( topo, "gossip_shred", "gossip_shred", 128UL,                                    8UL  + 40200UL * 38UL,  1UL );
  /**/                 fd_topob_link( topo, "gossip_verif", "gossip_verif", config->tiles.verify.receive_buffer_size, FD_TPU_MTU,             1UL );
  /**/                 fd_topob_link( topo, "gossip_tower", "gossip_tower", 128UL,                                    FD_TPU_MTU,             1UL );
  /**/                 fd_topob_link( topo, "gossip_repai", "gossip_repai", 128UL,                                    40200UL * 38UL,         1UL );
  /**/                 fd_topob_link( topo, "gossip_send",  "gossip_send",  128UL,                                    40200UL * 38UL,         1UL );

  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  config->tiles.verify.receive_buffer_size, FD_TPU_REASM_MTU,       config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,      1UL );
  /* dedup_resolv is large currently because pack can encounter stalls when running at very high throughput rates that would
     otherwise cause drops. */
  /**/                 fd_topob_link( topo, "dedup_resolv", "dedup_resolv", 65536UL,                                  FD_TPU_PARSED_MTU,      1UL );
  FOR(resolv_tile_cnt) fd_topob_link( topo, "resolv_pack",  "resolv_pack",  65536UL,                                  FD_TPU_RESOLVED_MTU,    1UL );
  /**/                 fd_topob_link( topo, "replay_pack",  "replay_pack",  128UL,                                    sizeof(fd_became_leader_t), 1UL );
  /**/                 fd_topob_link( topo, "replay_stake", "replay_stake", 128UL,                                    40UL + 40200UL * 40UL,  1UL );
  /**/                 fd_topob_link( topo, "pack_poh",     "pack_poh",     128UL,                                    sizeof(fd_done_packing_t), 1UL );
  /* pack_bank is shared across all banks, so if one bank stalls due to complex transactions, the buffer neeeds to be large so that
     other banks can keep proceeding. */
  /**/                 fd_topob_link( topo, "pack_bank",    "pack_bank",    65536UL,                                  USHORT_MAX,             1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_poh",     "bank_poh",     16384UL,                                  USHORT_MAX,             1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_pack",    "bank_pack",    16384UL,                                  USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    16384UL,                                  USHORT_MAX,             1UL );
  /**/                 fd_topob_link( topo, "poh_replay",   "poh_replay",   128UL,                                    sizeof(fd_poh_leader_slot_ended_t), 1UL );
  /**/                 fd_topob_link( topo, "replay_resol", "bank_poh",     128UL,                                    sizeof(fd_completed_bank_t), 1UL );
  /**/                 fd_topob_link( topo, "executed_txn", "executed_txn", 16384UL,                                  64UL, 1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                   1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   128UL,                                    64UL,                   1UL );

  /* TODO: Where does 2048 come from? */
  /**/                 fd_topob_link( topo, "gossip_sign",  "gossip_sign",  128UL,                                    2048UL,                 1UL );
  /**/                 fd_topob_link( topo, "sign_gossip",  "sign_gossip",  128UL,                                    64UL,                   1UL );

  /**/                 fd_topob_link( topo, "repair_sign",  "repair_sign",  128UL,                                    2048UL,                 1UL );
  /**/                 fd_topob_link( topo, "sign_repair",  "sign_repair",  128UL,                                    64UL,                   1UL );

  /**/                 fd_topob_link( topo, "send_sign",    "send_sign",    128UL,                                    FD_TXN_MTU,             1UL );
  /**/                 fd_topob_link( topo, "sign_send",    "sign_send",    128UL,                                    64UL,                   1UL );

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_repair", "shred_repair", pending_fec_shreds_depth,                 FD_SHRED_REPAIR_MTU,    2UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "repair_shred", "shred_repair", pending_fec_shreds_depth,                 sizeof(fd_ed25519_sig_t), 1UL );
  /**/                 fd_topob_link( topo, "repair_repla", "repair_repla", 65536UL,                                  FD_DISCO_REPAIR_REPLAY_MTU, 1UL );
  /**/                 fd_topob_link( topo, "replay_tower", "replay_tower", 128UL,                                    65536UL,                1UL );
  /**/                 fd_topob_link( topo, "tower_replay", "replay_tower", 128UL,                                    0,                      1UL );
  /**/                 fd_topob_link( topo, "tower_send",   "tower_send",   65536UL,                                  sizeof(fd_txn_p_t),     1UL );
  /**/                 fd_topob_link( topo, "send_txns",    "send_txns",    128UL,                                    FD_TXN_MTU,             1UL );

  /* TODO: The MTU is currently relatively arbitrary and needs to be resized to the size of the largest
     message that is outbound from the replay to exec. */
  FOR(exec_tile_cnt)   fd_topob_link( topo, "replay_exec",  "replay_exec",  128UL,                                    10240UL,                exec_tile_cnt );
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
  FOR(exec_tile_cnt)   fd_topob_link( topo, "exec_writer",  "exec_writer",  128UL,                                    FD_EXEC_WRITER_MTU,     1UL );

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

  fd_topos_net_tiles( topo, config->layout.net_tile_count, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );

  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_gossip", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_repair", i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_send",   i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_quic",   i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_shred",  i, config->net.ingress_buffer_size );

  /*                                  topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave, uses_keyswitch */
  FOR(quic_tile_cnt)   fd_topob_tile( topo, "quic",    "quic",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(verify_tile_cnt) fd_topob_tile( topo, "verify",  "verify",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "dedup",   "dedup",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(resolv_tile_cnt) fd_topob_tile( topo, "resolv",  "resolv",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(resolv_tile_cnt) strncpy( topo->tiles[ topo->tile_cnt-1UL-i ].metrics_name, "resolf", 8UL );
  /**/                 fd_topob_tile( topo, "pack",    "pack",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        config->tiles.bundle.enabled );
  FOR(bank_tile_cnt)   fd_topob_tile( topo, "bank",    "bank",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(bank_tile_cnt)   strncpy( topo->tiles[ topo->tile_cnt-1UL-i ].metrics_name, "bankf", 6UL );
  /**/                 fd_topob_tile( topo, "poh",     "poh",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  FOR(shred_tile_cnt)  fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                 fd_topob_tile( topo, "sign",    "sign",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "cswtch",  "cswtch",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  /**/                 fd_topob_tile( topo, "gossip",  "gossip",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "repair",  "repair",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "replay",  "replay",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(exec_tile_cnt)   fd_topob_tile( topo, "exec",    "exec",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(writer_tile_cnt) fd_topob_tile( topo, "writer",  "writer",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "tower",   "tower",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "send",    "send",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  FOR(quic_tile_cnt)  fd_topos_tile_in_net(  topo,                       "metric_in", "quic_net",     i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt) fd_topos_tile_in_net(  topo,                       "metric_in", "shred_net",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net(  topo,                       "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net(  topo,                       "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net(  topo,                       "metric_in", "send_net",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_verify",  i                                                  );
  FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_net",     i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "gossip_verif", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "verify",  0UL,          "metric_in", "send_txns",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(verify_tile_cnt) fd_topob_tile_out( topo, "verify",  i,                         "verify_dedup", i                                                  );
  FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "dedup",   0UL,                       "dedup_resolv", 0UL                                                );
  FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "dedup_resolv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "replay_resol", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_out( topo, "resolv",  i,                         "resolv_pack",  i                                                  );
  /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "resolv_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /* The PoH to pack link is reliable, and must be.  The fragments going
     across here are "you became leader" which pack must respond to
     by publishing microblocks, otherwise the leader TPU will hang
     forever.

     It's marked as unreliable since otherwise we have a reliable credit
     loop which will also starve the pack tile.  This is OK because we
     will never send more than one leader message until the pack tile
     must acknowledge it with a packing done frag, so there will be at
     most one in flight at any time. */
  /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "replay_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                       fd_topob_tile_out( topo, "pack",   0UL,                        "pack_bank",    0UL                                                );
                       fd_topob_tile_out( topo, "pack",   0UL,                        "pack_poh" ,    0UL                                                );
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "bank",   i,             "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_out( topo, "bank",   i,                          "bank_poh",     i                                                  );
  FOR(bank_tile_cnt)   fd_topob_tile_out( topo, "bank",   i,                          "bank_pack",    i                                                  );
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) )
  FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "bank_pack",    i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "pack_poh",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "replay_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_shred",    0UL                                                );
  /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_replay",   0UL                                                );
  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "net_shred",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "poh_shred",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "gossip_shred", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_repair", i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",   i,            "metric_in", "repair_shred", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_net",    i                                                  );

  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "repair", 0UL,           "metric_in", "net_repair",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "repair", 0UL,           "metric_in", "gossip_repai", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "repair", 0UL,           "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "repair", 0UL,           "metric_in", "shred_repair", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                        "repair_repla", 0UL                                                );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "repair", 0UL,                        "repair_shred", i                                                  );
  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                        "repair_net",   0UL                                                );

  /**/                 fd_topob_tile_in(  topo, "tower",   0UL,          "metric_in", "gossip_tower", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "tower",   0UL,          "metric_in", "replay_tower", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "tower",   0UL,                       "tower_replay", 0UL                                                );
  /**/                 fd_topob_tile_out( topo, "tower",   0UL,                       "tower_send",   0UL                                                );

  FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "gossip", 0UL,           "metric_in", "net_gossip",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in(  topo, "gossip",  0UL,          "metric_in", "send_txns",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_net",   0UL                                                );
  /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_shred", 0UL                                                );
  /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_repai", 0UL                                                );
  /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_verif", 0UL                                                );
  /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_send",  0UL                                                );
  /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_tower", 0UL                                                );

  /**/                 fd_topob_tile_in(  topo, "replay",  0UL,          "metric_in", "repair_repla", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "replay",  0UL,          "metric_in", "tower_replay", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(  topo, "replay",  0UL,          "metric_in", "poh_replay",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "replay_stake", 0UL                                                );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "replay_pack",  0UL                                                );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "replay_tower", 0UL                                                );
  FOR(exec_tile_cnt)   fd_topob_tile_out( topo, "replay",  0UL,                       "replay_exec",  i                                                  ); /* TODO check order in fd_replay.c macros*/
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "replay_resol", 0UL                                                );
  /**/                 fd_topob_tile_out( topo, "replay",  0UL,                       "executed_txn", 0UL                                                );

  FOR(exec_tile_cnt)   fd_topob_tile_in(  topo, "exec",    i,            "metric_in", "replay_exec",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(exec_tile_cnt)   fd_topob_tile_out( topo, "exec",    i,                         "exec_writer",  i                                                  );

  /* All writer tiles read from all exec tiles.  Each exec tile has a
     single out link, over which all the writer tiles round-robin. */
  FOR(writer_tile_cnt) for( ulong j=0UL; j<exec_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "writer",  i,            "metric_in", "exec_writer",  j,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /**/                 fd_topob_tile_in ( topo, "send",   0UL,           "metric_in", "net_send",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,           "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,           "metric_in", "gossip_send",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,           "metric_in", "tower_send",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out( topo, "send",   0UL,                        "send_txns",    0UL                                                );
  /**/                 fd_topob_tile_out( topo, "send",   0UL,                        "send_net",     0UL                                                );

  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by fd_stem, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",   i                                                    );
    /**/               fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "sign_shred",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",   i                                                    );
  }

  /**/                 fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "gossip_sign",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_sign",  0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "gossip", 0UL,           "metric_in", "sign_gossip",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out( topo, "sign",   0UL,                        "sign_gossip",  0UL                                                  );

  /**/                 fd_topob_tile_in ( topo, "sign",   0UL,           "metric_in", "send_sign",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "send",   0UL,                        "send_sign",    0UL                                                  );
  /**/                 fd_topob_tile_in ( topo, "send",   0UL,           "metric_in", "sign_send",    0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out( topo, "sign",   0UL,                        "sign_send",    0UL                                                  );

  /**/                 fd_topob_tile_in(  topo, "sign",   0UL,         "metric_in",  "repair_sign",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/                 fd_topob_tile_out( topo, "repair", 0UL,                       "repair_sign",   0UL                                                  );
  /**/                 fd_topob_tile_in(  topo, "repair", 0UL,         "metric_in",  "sign_repair",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/                 fd_topob_tile_out( topo, "sign",   0UL,                       "sign_repair",   0UL                                                  );

  /* For now the only plugin consumer is the GUI */
  int plugins_enabled = config->tiles.gui.enabled;
  if( FD_LIKELY( plugins_enabled ) ) {
    fd_topob_wksp( topo, "plugin_in"    );
    fd_topob_wksp( topo, "plugin_out"   );
    fd_topob_wksp( topo, "plugin"       );

    /**/                 fd_topob_link( topo, "plugin_out",   "plugin_out",   128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );
    /**/                 fd_topob_link( topo, "replay_plugi", "plugin_in",    128UL,                                    4098*8UL,                     1UL );
    /**/                 fd_topob_link( topo, "gossip_plugi", "plugin_in",    128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );

    /**/                 fd_topob_tile( topo, "plugin",  "plugin",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    /**/                 fd_topob_tile_out( topo, "replay", 0UL,                        "replay_plugi", 0UL                                               );
    /**/                 fd_topob_tile_out( topo, "gossip", 0UL,                        "gossip_plugi", 0UL                                               );
    /**/                 fd_topob_tile_out( topo, "plugin", 0UL,                        "plugin_out", 0UL                                                 );

    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "replay_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "gossip_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  if( FD_LIKELY( config->tiles.gui.enabled ) ) {
    fd_topob_wksp( topo, "gui"          );
    /**/                 fd_topob_tile( topo, "gui",     "gui",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "plugin_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
    fd_topob_wksp( topo, "bundle_verif" );
    fd_topob_wksp( topo, "bundle_sign"  );
    fd_topob_wksp( topo, "sign_bundle"  );
    fd_topob_wksp( topo, "pack_sign"    );
    fd_topob_wksp( topo, "sign_pack"    );
    fd_topob_wksp( topo, "bundle"       );

    /**/                 fd_topob_link( topo, "bundle_verif", "bundle_verif", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,         1UL );
    /**/                 fd_topob_link( topo, "bundle_sign",  "bundle_sign",  65536UL,                                  9UL,                       1UL );
    /**/                 fd_topob_link( topo, "sign_bundle",  "sign_bundle",  128UL,                                    64UL,                      1UL );
    /**/                 fd_topob_link( topo, "pack_sign",    "pack_sign",    65536UL,                                  1232UL,                    1UL );
    /**/                 fd_topob_link( topo, "sign_pack",    "sign_pack",    128UL,                                    64UL,                      1UL );

    /**/                 fd_topob_tile( topo, "bundle",  "bundle",  "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 1 );

    /**/                 fd_topob_tile_out( topo, "bundle", 0UL, "bundle_verif", 0UL );
    FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "verify", i,             "metric_in", "bundle_verif",   0UL,        FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

    /**/                 fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "bundle_sign",    0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/                 fd_topob_tile_out( topo, "bundle", 0UL,                        "bundle_sign",    0UL                                                );
    /**/                 fd_topob_tile_in(  topo, "bundle", 0UL,           "metric_in", "sign_bundle",    0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/                 fd_topob_tile_out( topo, "sign",   0UL,                        "sign_bundle",    0UL                                                );

    /**/                 fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "pack_sign",      0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/                 fd_topob_tile_out( topo, "pack",   0UL,                        "pack_sign",      0UL                                                );
    /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "sign_pack",      0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/                 fd_topob_tile_out( topo, "sign",   0UL,                        "sign_pack",      0UL                                                );

    if( plugins_enabled ) {
      fd_topob_wksp( topo, "bundle_plugi" );
      /* bundle_plugi must be kind of deep, to prevent exhausting shared
         flow control credits when publishing many packets at once. */
      fd_topob_link( topo, "bundle_plugi", "bundle_plugi", 65536UL, sizeof(fd_plugin_msg_block_engine_update_t), 1UL );
      fd_topob_tile_in( topo, "plugin", 0UL, "metric_in", "bundle_plugi", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_out( topo, "bundle", 0UL, "bundle_plugi", 0UL );
    }
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

  /* There's another special fseq that's used to communicate the shred
     version from the Agave boot path to the shred tile.  TODO: Delete
     this, obtain shred version from gossip tile. */
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
  fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );



  fd_topo_obj_t * funk_obj = setup_topo_funk( topo,
                                              "funk",
                                              config->firedancer.funk.max_account_records,
                                              config->firedancer.funk.max_database_transactions,
                                              config->firedancer.funk.heap_size_gib );
  /* TODO: Some of these should be readonly? */
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_obj_t * blockstore_obj = setup_topo_blockstore( topo,
                                                          "blockstore",
                                                          config->firedancer.blockstore.shred_max,
                                                          config->firedancer.blockstore.block_max,
                                                          config->firedancer.blockstore.idx_max,
                                                          config->firedancer.blockstore.alloc_max );

  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ], blockstore_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_obj->id, "blockstore" ) );
  FD_TEST( blockstore_obj->id ); /* TODO: Why!? */

  fd_topo_obj_t * banks_obj = setup_topo_banks( topo,
                                                "banks",
                                                config->firedancer.runtime.limits.max_banks );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  fd_topo_obj_t * bank_hash_cmp_obj = setup_topo_bank_hash_cmp( topo, "bh_cmp" );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, bank_hash_cmp_obj->id, "bh_cmp" ) );

  fd_topo_obj_t * runtime_pub_obj = setup_topo_runtime_pub( topo,
                                                            "runtime_pub",
                                                            config->firedancer.runtime.heap_size_gib<<30UL );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i   ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, runtime_pub_obj->id, "runtime_pub" ) );

  ulong shred_depth = 65536UL; /* from fdctl/topology.c shred_store link. MAKE SURE TO KEEP IN SYNC. */
  ulong fec_set_cnt = shred_depth+config->tiles.shred.max_pending_shred_sets+4UL;
  ulong fec_sets_sz = fec_set_cnt*sizeof(fd_shred34_t)*4; /* mirrors # of dcache entires in frankendancer */
  fd_topo_obj_t * fec_sets_obj = setup_topo_fec_sets( topo,
                                                      "fec_sets",
                                                      shred_tile_cnt*fec_sets_sz );
  FOR(shred_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "shred",  i   ) ], fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /**/                fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ], fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_sets_obj->id, "fec_sets" ) );

  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo,
                                                      "txncache",
                                                      config->firedancer.runtime.limits.max_rooted_slots,
                                                      config->firedancer.runtime.limits.max_live_slots,
                                                      config->firedancer.runtime.limits.max_transactions_per_slot );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_spad_obj = fd_topob_obj( topo, "exec_spad", "exec_spad" );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    for( ulong j=0UL; j<writer_tile_cnt; j++ ) {
      /* For txn_ctx. */
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", j ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    }
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_spad_obj->id, "exec_spad.%lu", i ) );
  }

  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_fseq_obj = fd_topob_obj( topo, "fseq", "exec_fseq" );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], exec_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], exec_fseq_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_fseq_obj->id, "exec_fseq.%lu", i ) );
  }

  for( ulong i=0UL; i<writer_tile_cnt; i++ ) {
    fd_topo_obj_t * writer_fseq_obj = fd_topob_obj( topo, "fseq", "writer_fseq" );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i   ) ], writer_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], writer_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, writer_fseq_obj->id, "writer_fseq.%lu", i ) );
  }

  /* root_slot is an fseq marking the validator's current tower root.
     TODO: Delete this, not good.*/
  fd_topo_obj_t * root_slot_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, root_slot_obj->id, "root_slot" ) );

  /* turbine_slot0 is an fseq marking the slot number of the first shred
     we observed from Turbine.  This is a useful heuristic for
     determining when replay has progressed past the slot in which we
     last voted.  The idea is once replay has proceeded past the slot
     from which validator stopped replaying and therefore also stopped
     voting (crashed, shutdown, etc.), it will have "read-back" its
     latest tower in the ledger.  Note this logic is not true in the
     case our latest tower vote was for a minority fork.  TODO: Delete
     this, not ideal, replace with mcache frag. */

  fd_topo_obj_t * turbine_slot0_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ], turbine_slot0_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], turbine_slot0_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, turbine_slot0_obj->id, "turbine_slot0" ) );

  /* turbine_slot is an fseq marking the highest slot we've observed on
     a shred.  This is continuously updated as the validator is running
     and is used to determine whether the validator is caught up with
     the rest of the cluster.  TODO: Delete this, not ideal, replace
     with mcache frag. */

  fd_topo_obj_t * turbine_slot_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ], turbine_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], turbine_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, turbine_slot_obj->id, "turbine_slot" ) );

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 0 );

  fd_topob_finish( topo, CALLBACKS );
  config->topo = *topo;
}

void
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

  } else if( FD_UNLIKELY( !strcmp( tile->name, "bundle" ) ) ) {
    strncpy( tile->bundle.url, config->tiles.bundle.url, sizeof(tile->bundle.url) );
    tile->bundle.url_len = strnlen( tile->bundle.url, 255 );
    strncpy( tile->bundle.sni, config->tiles.bundle.tls_domain_name, 256 );
    tile->bundle.sni_len = strnlen( tile->bundle.sni, 255 );
    strncpy( tile->bundle.identity_key_path, config->paths.identity_key, sizeof(tile->bundle.identity_key_path) );
    strncpy( tile->bundle.key_log_path, config->development.bundle.ssl_key_log_file, sizeof(tile->bundle.key_log_path) );
    tile->bundle.buf_sz = config->development.bundle.buffer_size_kib<<10;
    tile->bundle.ssl_heap_sz = config->development.bundle.ssl_heap_size_mib<<20;
    tile->bundle.keepalive_interval_nanos = config->tiles.bundle.keepalive_interval_millis * (ulong)1e6;
    tile->bundle.tls_cert_verify = !!config->tiles.bundle.tls_cert_verify;

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

  } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {
    strncpy( tile->shred.identity_key_path, config->paths.identity_key, sizeof(tile->shred.identity_key_path) );

    tile->shred.depth                         = 65536UL; /* TODO: What? */
    tile->shred.fec_resolver_depth            = config->tiles.shred.max_pending_shred_sets;
    tile->shred.expected_shred_version        = config->consensus.expected_shred_version;
    tile->shred.shred_listen_port             = config->tiles.shred.shred_listen_port;
    tile->shred.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
    char   adtl_dest[ sizeof("255.255.255.255:65536") ];
    memcpy( adtl_dest, config->tiles.shred.additional_shred_destination, sizeof(adtl_dest) );
    if( FD_UNLIKELY( strcmp( adtl_dest, "" ) ) ) {
      char * ip_end = strchr( adtl_dest, ':' );
      if( FD_UNLIKELY( !ip_end ) ) FD_LOG_ERR(( "[tiles.shred.additional_shred_destination] must be empty or in the form ip:port" ));
      *ip_end = '\0';

      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( adtl_dest, &(tile->shred.adtl_dest.ip) ) ) ) {
        FD_LOG_ERR(( "could not parse IP %s in [tiles.shred.additional_shred_destination]", adtl_dest ));
      }

      tile->shred.adtl_dest.port = fd_cstr_to_ushort( ip_end+1 );
      if( FD_UNLIKELY( !tile->shred.adtl_dest.port ) ) FD_LOG_ERR(( "could not parse port %s in [tiles.shred.additional_shred_destination]", ip_end+1 ));
    } else {
      tile->shred.adtl_dest.ip   = 0U;
      tile->shred.adtl_dest.port = 0;
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
    strncpy( tile->sign.identity_key_path, config->paths.identity_key, sizeof(tile->sign.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &tile->metric.prometheus_listen_addr ) ) )
      FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
    tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "cswtch" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gui" ) ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.gui.gui_listen_address, &tile->gui.listen_addr ) ) )
      FD_LOG_ERR(( "failed to parse gui listen address `%s`", config->tiles.gui.gui_listen_address ));
    tile->gui.listen_port = config->tiles.gui.gui_listen_port;
    tile->gui.is_voting = strcmp( config->paths.vote_account, "" );
    strncpy( tile->gui.cluster, config->cluster, sizeof(tile->gui.cluster) );
    strncpy( tile->gui.identity_key_path, config->paths.identity_key, sizeof(tile->gui.identity_key_path) );
    tile->gui.max_http_connections      = config->tiles.gui.max_http_connections;
    tile->gui.max_websocket_connections = config->tiles.gui.max_websocket_connections;
    tile->gui.max_http_request_length   = config->tiles.gui.max_http_request_length;
    tile->gui.send_buffer_size_mb       = config->tiles.gui.send_buffer_size_mb;
    tile->gui.schedule_strategy         = config->tiles.pack.schedule_strategy_enum;
  } else if( FD_UNLIKELY( !strcmp( tile->name, "plugin" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gossip" ) ) ) {
    tile->gossip.ip_addr = config->net.ip_addr;
    strncpy( tile->gossip.identity_key_path, config->paths.identity_key, sizeof(tile->gossip.identity_key_path) );
    tile->gossip.gossip_listen_port =  config->gossip.port;
    tile->gossip.tvu_port = config->tiles.shred.shred_listen_port;
    if( FD_UNLIKELY( tile->gossip.tvu_port>(ushort)(USHORT_MAX-6) ) )
      FD_LOG_ERR(( "shred_listen_port in the config must not be greater than %hu", (ushort)(USHORT_MAX-6) ));
    tile->gossip.expected_shred_version = config->consensus.expected_shred_version;
    tile->gossip.tpu_port             = config->tiles.quic.regular_transaction_listen_port;
    tile->gossip.tpu_quic_port        = config->tiles.quic.quic_transaction_listen_port;
    tile->gossip.tpu_vote_port        = config->tiles.quic.regular_transaction_listen_port; /* TODO: support separate port for tpu vote */
    tile->gossip.repair_serve_port    = config->tiles.repair.repair_serve_listen_port;
    tile->gossip.entrypoints_cnt      = fd_ulong_min( config->gossip.resolved_entrypoints_cnt, FD_TOPO_GOSSIP_ENTRYPOINTS_MAX );
    fd_memcpy( tile->gossip.entrypoints, config->gossip.resolved_entrypoints, tile->gossip.entrypoints_cnt * sizeof(fd_ip4_port_t) );

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

    if( FD_UNLIKELY( !strncmp( config->tiles.replay.genesis,  "", 1 )
                  && !strncmp( config->tiles.replay.snapshot, "", 1 ) ) ) {
      fd_cstr_printf_check( config->tiles.replay.genesis, PATH_MAX, NULL, "%s/genesis.bin", config->paths.ledger );
    }
    strncpy( tile->replay.genesis, config->tiles.replay.genesis, sizeof(tile->replay.genesis) );

    setup_snapshots( config, tile );

    strncpy( tile->replay.slots_replayed, config->tiles.replay.slots_replayed, sizeof(tile->replay.slots_replayed) );
    strncpy( tile->replay.status_cache, config->tiles.replay.status_cache, sizeof(tile->replay.status_cache) );
    strncpy( tile->replay.cluster_version, config->tiles.replay.cluster_version, sizeof(tile->replay.cluster_version) );
    strncpy( tile->replay.tower_checkpt, config->tiles.replay.tower_checkpt, sizeof(tile->replay.tower_checkpt) );

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
    tile->rpcserv.rpc_port = config->rpc.port;
    tile->rpcserv.tpu_port = config->tiles.quic.regular_transaction_listen_port;
    tile->rpcserv.tpu_ip_addr = config->net.ip_addr;
    tile->rpcserv.block_index_max = config->rpc.block_index_max;
    tile->rpcserv.txn_index_max = config->rpc.txn_index_max;
    tile->rpcserv.acct_index_max = config->rpc.acct_index_max;
    strncpy( tile->rpcserv.history_file, config->rpc.history_file, sizeof(tile->rpcserv.history_file) );
    strncpy( tile->rpcserv.identity_key_path, config->paths.identity_key, sizeof(tile->rpcserv.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "exec" ) ) ) {
    tile->exec.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );

    tile->exec.capture_start_slot = config->capture.capture_start_slot;
    strncpy( tile->exec.dump_proto_dir, config->capture.dump_proto_dir, sizeof(tile->exec.dump_proto_dir) );
    tile->exec.dump_instr_to_pb = config->capture.dump_instr_to_pb;
    tile->exec.dump_txn_to_pb = config->capture.dump_txn_to_pb;
    tile->exec.dump_syscall_to_pb = config->capture.dump_syscall_to_pb;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "writer" ) ) ) {
    tile->writer.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "arch_f" ) || !strcmp( tile->name, "arch_w" ) ) ) {
    strncpy( tile->archiver.archiver_path, config->tiles.archiver.archiver_path, sizeof(tile->archiver.archiver_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "back" ) ) ) {
      strncpy( tile->archiver.archiver_path, config->tiles.archiver.archiver_path, PATH_MAX );
      tile->archiver.end_slot = config->tiles.archiver.end_slot;
      if( FD_UNLIKELY( 0==strlen( tile->archiver.archiver_path ) ) ) {
        FD_LOG_ERR(( "`archiver.archiver_path` not specified in toml" ));
      }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "shrdcp" ) ) ) {
    tile->shredcap.repair_intake_listen_port = config->tiles.repair.repair_intake_listen_port;
    strncpy( tile->shredcap.folder_path, config->tiles.shredcap.folder_path, sizeof(config->tiles.shredcap.folder_path) );
    tile->shredcap.write_buffer_size = config->tiles.shredcap.write_buffer_size;

  } else {
    FD_LOG_ERR(( "unknown tile name %lu `%s`", tile->id, tile->name ));
  }
}
