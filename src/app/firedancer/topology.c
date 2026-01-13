#include "topology.h"

#include "../../ballet/lthash/fd_lthash.h"
#include "../../choreo/fd_choreo_base.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../discof/poh/fd_poh.h"
#include "../../discof/replay/fd_exec.h"
#include "../../discof/gossip/fd_gossip_tile.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "../../discof/resolv/fd_resolv_tile.h"
#include "../../discof/repair/fd_repair.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../discof/restore/fd_snapct_tile.h"
#include "../../disco/gui/fd_gui_peers.h"
#include "../../disco/quic/fd_tpu.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../disco/tiles.h"
#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_cpu_topo.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/tile/fd_tile_private.h"
#include "../../discof/restore/utils/fd_ssctrl.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../flamenco/capture/fd_solcap_writer.h"
#include "../../flamenco/progcache/fd_progcache_admin.h"
#include "../../flamenco/runtime/fd_acc_pool.h"
#include "../../vinyl/meta/fd_vinyl_meta.h"
#include "../../vinyl/io/fd_vinyl_io.h" /* FD_VINYL_IO_TYPE_* */

#include <sys/random.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
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
setup_topo_banks( fd_topo_t *  topo,
                  char const * wksp_name,
                  ulong        max_live_slots,
                  ulong        max_fork_width,
                  int          larger_max_cost_per_block ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "banks", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_live_slots, "obj.%lu.max_live_slots", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_fork_width, "obj.%lu.max_fork_width", obj->id ) );
  FD_TEST( fd_pod_insertf_int( topo->props, larger_max_cost_per_block, "obj.%lu.larger_max_cost_per_block", obj->id ) );
  ulong seed;
  FD_TEST( fd_rng_secure( &seed, sizeof( ulong ) ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, seed, "obj.%lu.seed", obj->id ) );
  return obj;
}

fd_topo_obj_t *
setup_topo_banks_locks( fd_topo_t *  topo,
                        char const * wksp_name ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "banks_locks", wksp_name );
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
  ulong size     = funk_footprint+(heap_size_gib*(1UL<<30));
  ulong part_max = fd_wksp_part_max_est( size, 1U<<14U );
  if( FD_UNLIKELY( !part_max ) ) FD_LOG_ERR(( "fd_wksp_part_max_est(%lu,16KiB) failed", size ));
  wksp->part_max += part_max;

  return obj;
}

fd_topo_obj_t *
setup_topo_progcache( fd_topo_t *  topo,
                      char const * wksp_name,
                      ulong        max_cache_entries,
                      ulong        max_database_transactions,
                      ulong        heap_size ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "funk", wksp_name );
  FD_TEST( fd_pod_insert_ulong(  topo->props, "progcache", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_cache_entries,         "obj.%lu.rec_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_database_transactions, "obj.%lu.txn_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, heap_size,                 "obj.%lu.heap_max", obj->id ) );
  ulong funk_footprint = fd_funk_footprint( max_database_transactions, max_cache_entries );
  if( FD_UNLIKELY( !funk_footprint ) ) FD_LOG_ERR(( "Invalid [runtime.program_cache] parameters" ));
  if( FD_UNLIKELY( heap_size<(2*funk_footprint) ) ) {
    FD_LOG_ERR(( "Invalid [runtime.program_cache] parameters: heap_size_mib should be at least %lu",
                 ( 2*funk_footprint )>>20 ));
  }

  /* Increase workspace partition count */
  ulong wksp_idx = fd_topo_find_wksp( topo, wksp_name );
  FD_TEST( wksp_idx!=ULONG_MAX );
  fd_topo_wksp_t * wksp = &topo->workspaces[ wksp_idx ];
  ulong part_max = fd_wksp_part_max_est( heap_size, 1U<<14U );
  if( FD_UNLIKELY( !part_max ) ) FD_LOG_ERR(( "fd_wksp_part_max_est(%lu,16KiB) failed", funk_footprint ));
  wksp->part_max += part_max;

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
                     ulong        max_live_slots,
                     ulong        max_txn_per_slot ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "txncache", wksp_name );

  FD_TEST( fd_pod_insertf_ulong( topo->props, max_live_slots,   "obj.%lu.max_live_slots",   obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_txn_per_slot, "obj.%lu.max_txn_per_slot", obj->id ) );

  return obj;
}

fd_topo_obj_t *
setup_topo_acc_pool( fd_topo_t * topo,
                     ulong       max_account_cnt ) {
  fd_topob_wksp( topo, "acc_pool" );
  fd_topo_obj_t * acc_pool_obj = fd_topob_obj( topo, "acc_pool", "acc_pool" );
  fd_pod_insertf_ulong( topo->props, max_account_cnt, "obj.%lu.max_account_cnt", acc_pool_obj->id );
  FD_TEST( acc_pool_obj );
  FD_TEST( acc_pool_obj->id != ULONG_MAX );
  return acc_pool_obj;
}

void
setup_topo_vinyl_meta( fd_topo_t *    topo,
                       fd_configf_t * config ) {
  fd_topob_wksp( topo, "vinyl_meta" );

  fd_topo_obj_t * map_obj = fd_topob_obj( topo, "vinyl_meta", "vinyl_meta" );
  ulong const meta_max  = fd_ulong_pow2_up( config->vinyl.max_account_records );
  ulong const lock_cnt  = fd_vinyl_meta_lock_cnt_est ( meta_max );
  ulong const probe_max = fd_vinyl_meta_probe_max_est( meta_max );
  fd_pod_insertf_ulong( topo->props, meta_max,  "obj.%lu.ele_max",   map_obj->id );
  fd_pod_insertf_ulong( topo->props, lock_cnt,  "obj.%lu.lock_cnt",  map_obj->id );
  fd_pod_insertf_ulong( topo->props, probe_max, "obj.%lu.probe_max", map_obj->id );
  fd_pod_insertf_ulong( topo->props, (ulong)fd_tickcount(), "obj.%lu.seed", map_obj->id );

  fd_topo_obj_t * meta_pool_obj = fd_topob_obj( topo, "vinyl_meta_e", "vinyl_meta" );
  fd_pod_insertf_ulong( topo->props, meta_max, "obj.%lu.cnt", meta_pool_obj->id );

  fd_pod_insert_ulong( topo->props, "vinyl.meta_map",  map_obj->id );
  fd_pod_insert_ulong( topo->props, "vinyl.meta_pool", meta_pool_obj->id );
}

fd_topo_obj_t *
setup_topo_vinyl_cache( fd_topo_t *    topo,
                        fd_configf_t * config ) {
  fd_topob_wksp( topo, "vinyl_data" );
  fd_topo_obj_t * line_obj = fd_topob_obj( topo, "vinyl_data", "vinyl_data" );
  ulong const heap_max = config->vinyl.cache_size_gib<<30;
  fd_pod_insertf_ulong( topo->props, heap_max, "obj.%lu.data_sz", line_obj->id );
  fd_pod_insert_ulong( topo->props, "vinyl.data", line_obj->id );
  return line_obj;
}

/* Resolves a hostname to a single ip address.  If multiple ip address
   records are returned by getaddrinfo, only the first IPV4 address is
   returned via ip_addr. */
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

/* Resolves a hostname to multiple ip addresses, specified by
   ip_addr_cnt.  ip_addrs points to an array of fd_ip4_port_t objects.
   hints points to an optionally NULL addrinfo hints object.  If hints
   is NULL, a default hints settings containing the IPV4 address family
   hint will be used. */
static int
resolve_addresses( char const *             address,
                   struct addrinfo const *  hints,
                   fd_ip4_port_t *          ip_addrs,
                   ulong                    ip_addr_cnt ) {
  struct addrinfo default_hints = { .ai_family = AF_INET };
  if( FD_UNLIKELY( !hints ) ) {
    hints = &default_hints;
  }

  struct addrinfo * res;
  int err = getaddrinfo( address, NULL, hints, &res );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "cannot resolve address \"%s\": %i-%s", address, err, gai_strerror( err ) ));
    return 0;
  }

  int resolved = 0;
  for( struct addrinfo * cur=res; cur; cur=cur->ai_next ) {
    if( FD_UNLIKELY( (ulong)resolved>=ip_addr_cnt ) ) break;
    if( FD_UNLIKELY( cur->ai_addr->sa_family!=AF_INET ) ) continue;
    struct sockaddr_in const * addr = (struct sockaddr_in const *)cur->ai_addr;
    ip_addrs[ resolved ].addr = addr->sin_addr.s_addr;
    resolved++;
  }

  freeaddrinfo( res );
  return resolved;
}

static int
resolve_peer( char const *            peer,
              struct addrinfo const * addr_resolve_hints,
              char const *            config_str,
              char                    hostname[ static 256UL ],
              fd_ip4_port_t *         ip4_port,
              ulong                   ip4_port_cnt,
              int *                   is_https ) {

  /* Split host:port */
  int          https     = 0;
  char const * host_port = peer;
  if( FD_LIKELY( strncmp( peer, "http://", 7UL )==0 ) ) {
    if( FD_LIKELY( is_https ) ) *is_https  = 0;
    host_port += 7UL;
  } else if( FD_LIKELY( strncmp( peer, "https://", 8UL )==0 ) ) {
    if( FD_LIKELY( is_https ) ) *is_https  = 1;
    host_port += 8UL;
    https      = 1;
  }

  char const * colon    = strrchr( host_port, ':' );
  char const * host_end = colon;
  if( FD_UNLIKELY( !colon && !https ) ) {
    FD_LOG_ERR(( "invalid [%s] entry \"%s\": no port number", config_str, host_port ));
  } else if( FD_LIKELY( !colon && https ) ) {
    host_end = host_port + strlen( host_port );
  }

  ulong fqdn_len = (ulong)( host_end-host_port );
  if( FD_UNLIKELY( fqdn_len>255 ) ) {
    FD_LOG_ERR(( "invalid [%s] entry \"%s\": hostname too long", config_str, host_port ));
  }
  fd_memcpy( hostname, host_port, fqdn_len );
  hostname[ fqdn_len ] = '\0';

  /* Resolve hostname */
  int resolved = resolve_addresses( hostname, addr_resolve_hints, ip4_port, ip4_port_cnt );

  /* Parse port number */

  if( FD_LIKELY( colon ) ) {
    char const * port_str = host_end+1;
    char const * endptr   = NULL;
    ulong port = strtoul( port_str, (char **)&endptr, 10 );
    if( FD_UNLIKELY( endptr==port_str || !port || port>USHORT_MAX || *endptr!='\0' ) ) {
      FD_LOG_ERR(( "invalid [%s] entry \"%s\": invalid port number", config_str, host_port ));
    }
    for( ulong i=0UL; i<(ulong)resolved; i++ ) ip4_port[ i ].port = fd_ushort_bswap( (ushort)port );
  } else if( FD_LIKELY( !colon && https ) ) {
    /* use default https port */
    for( ulong i=0UL; i<(ulong)resolved; i++ ) ip4_port[ i ].port = fd_ushort_bswap( 443U );
  } else {
    FD_LOG_ERR(( "invalid [%s] entry \"%s\": no port number", config_str, host_port ));
  }

  return resolved;
}

static void
resolve_gossip_entrypoints( config_t * config ) {
  ulong entrypoint_cnt = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<entrypoint_cnt; i++ ) {
    char hostname[ 256UL ];
    if( FD_UNLIKELY( 0==resolve_peer( config->gossip.entrypoints[ i ], NULL, "gossip.entrypoints", hostname, &config->gossip.resolved_entrypoints[ i ], 1, NULL ) ) ) {
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
  ulong sign_tile_cnt   = config->firedancer.layout.sign_tile_count;
  ulong lta_tile_cnt    = config->firedancer.layout.snapla_tile_count;

  int snapshots_enabled = !!config->gossip.entrypoints_cnt;
  int vinyl_enabled     = !!config->firedancer.vinyl.enabled;
  int snapshot_lthash_disabled = config->development.snapshots.disable_lthash_verification;

  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );

  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  int solcap_enabled = strlen( config->capture.solcap_capture ) > 0;

  if( vinyl_enabled ) {
    setup_topo_vinyl_meta( topo, &config->firedancer );
  }

  /*             topo, name */
  fd_topob_wksp( topo, "metric"       );
  fd_topob_wksp( topo, "genesi"       );
  fd_topob_wksp( topo, "ipecho"       );
  fd_topob_wksp( topo, "gossvf"       );
  fd_topob_wksp( topo, "gossip"       );
  fd_topob_wksp( topo, "shred"        );
  fd_topob_wksp( topo, "repair"       );
  fd_topob_wksp( topo, "replay"       );
  fd_topob_wksp( topo, "exec"         );
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

  fd_topob_wksp( topo, "genesi_out"   );
  fd_topob_wksp( topo, "ipecho_out"   );
  fd_topob_wksp( topo, "gossvf_gossi" );
  fd_topob_wksp( topo, "gossip_gossv" );
  fd_topob_wksp( topo, "gossip_out"   );

  fd_topob_wksp( topo, "shred_out"    );
  fd_topob_wksp( topo, "replay_stake" );
  fd_topob_wksp( topo, "replay_exec"  );
  fd_topob_wksp( topo, "replay_out"   );
  fd_topob_wksp( topo, "tower_out"    );
  fd_topob_wksp( topo, "send_out"     );

  fd_topob_wksp( topo, "quic_verify"  );
  fd_topob_wksp( topo, "verify_dedup" );
  fd_topob_wksp( topo, "dedup_resolv" );
  fd_topob_wksp( topo, "resolv_pack"  );
  fd_topob_wksp( topo, "pack_poh"     );
  fd_topob_wksp( topo, "pack_bank"    );
  fd_topob_wksp( topo, "resolv_repla" );
  if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) ) {
    fd_topob_wksp( topo, "bank_pack"  );
  }
  fd_topob_wksp( topo, "bank_poh"     );
  fd_topob_wksp( topo, "bank_busy"    );
  fd_topob_wksp( topo, "poh_shred"    );
  fd_topob_wksp( topo, "poh_replay"   );

  fd_topob_wksp( topo, "funk"         );
  fd_topob_wksp( topo, "progcache"    );
  fd_topob_wksp( topo, "fec_sets"     );
  fd_topob_wksp( topo, "txncache"     );
  fd_topob_wksp( topo, "banks"        );
  fd_topob_wksp( topo, "banks_locks"  );
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

  fd_topob_wksp( topo, "exec_sig"     );

  fd_topob_wksp( topo, "cswtch"       );

  fd_topob_wksp( topo, "exec_replay"  );

  if( FD_LIKELY( snapshots_enabled ) ) {
    fd_topob_wksp( topo, "snapct"      );
    fd_topob_wksp( topo, "snapld"      );
    fd_topob_wksp( topo, "snapdc"      );
    fd_topob_wksp( topo, "snapin"      );
    if( vinyl_enabled ) {
      fd_topob_wksp( topo, "snapwh" );
      fd_topob_wksp( topo, "snapwr" );
    }

    fd_topob_wksp( topo, "snapct_ld"   );
    fd_topob_wksp( topo, "snapld_dc"   );
    fd_topob_wksp( topo, "snapdc_in"   );
    if( vinyl_enabled ) fd_topob_wksp( topo, "snapin_wr" );

    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_wksp( topo, "snapin_ct" );
    } else {
      fd_topob_wksp( topo, "snapls_ct" );
    }

    if( FD_LIKELY( config->tiles.gui.enabled ) ) fd_topob_wksp( topo, "snapct_gui"  );
    if( FD_LIKELY( config->tiles.gui.enabled ) ) fd_topob_wksp( topo, "snapin_gui"  );
    fd_topob_wksp( topo, "snapin_manif" );
    fd_topob_wksp( topo, "snapct_repr"  );

    if( FD_LIKELY( !snapshot_lthash_disabled ) ) {
      fd_topob_wksp( topo, "snapla"    );
      fd_topob_wksp( topo, "snapls"    );
      fd_topob_wksp( topo, "snapla_ls" );
      fd_topob_wksp( topo, "snapin_ls" );
    }
  }

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  ulong shred_depth = 65536UL; /* from fdctl/topology.c shred_store link. MAKE SURE TO KEEP IN SYNC. */

  /*                                  topo, link_name,      wksp_name,      depth,                                    mtu,                           burst */
  /**/                 fd_topob_link( topo, "gossip_net",   "net_gossip",   32768UL,                                  FD_NET_MTU,                    1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    32768UL,                                  FD_NET_MTU,                    1UL );
  /**/                 fd_topob_link( topo, "repair_net",   "net_repair",   config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  /**/                 fd_topob_link( topo, "send_net",     "net_send",     config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );
  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     config->net.ingress_buffer_size,          FD_NET_MTU,                    1UL );

  if( FD_LIKELY( snapshots_enabled ) ) {
  /* TODO: Revisit the depths of all the snapshot links */
    /**/               fd_topob_link( topo, "snapct_ld",    "snapct_ld",    128UL,                                    sizeof(fd_ssctrl_init_t),      1UL );
    /**/               fd_topob_link( topo, "snapld_dc",    "snapld_dc",    16384UL,                                  USHORT_MAX,                    1UL );
    /**/               fd_topob_link( topo, "snapdc_in",    "snapdc_in",    16384UL,                                  USHORT_MAX,                    1UL );
    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
                       fd_topob_link( topo, "snapin_ct",    "snapin_ct",    128UL,                                    0UL,                           1UL );
    } else {
                       fd_topob_link( topo, "snapls_ct",    "snapls_ct",    128UL,                                    0UL,                           1UL );
    }
    /**/               fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,                                      sizeof(fd_snapshot_manifest_t),1UL );
    /**/               fd_topob_link( topo, "snapct_repr",  "snapct_repr",  128UL,                                    0UL,                           1UL )->permit_no_consumers = 1; /* TODO: wire in repair later */
    if( FD_LIKELY( config->tiles.gui.enabled ) ) {
      /**/             fd_topob_link( topo, "snapct_gui",   "snapct_gui",   128UL,                                    sizeof(fd_snapct_update_t),    1UL );
      /**/             fd_topob_link( topo, "snapin_gui",   "snapin_gui",   128UL,                                    FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ, 1UL );
    }
    if( vinyl_enabled ) {
      fd_topo_link_t * snapin_wh =
      /**/             fd_topob_link( topo, "snapin_wh",    "snapin_wr",    4UL,                                      16UL<<20,                      1UL );
      /**/             fd_topob_link( topo, "snapwh_wr",    "snapin_wr",    4UL,                                      0UL,                           1UL );
      fd_pod_insertf_ulong( topo->props, 8UL, "obj.%lu.app_sz",  snapin_wh->dcache_obj_id );
    }
    if( FD_LIKELY( !snapshot_lthash_disabled ) ) {
    FOR(lta_tile_cnt) fd_topob_link( topo,  "snapla_ls",    "snapla_ls",    128UL,                                    sizeof(fd_lthash_value_t),     1UL );
    /**/              fd_topob_link( topo,  "snapin_ls",    "snapin_ls",    256UL,                                    sizeof(fd_snapshot_full_account_t), 1UL );
    }
  }

  /**/                 fd_topob_link( topo, "genesi_out",   "genesi_out",   2UL,                                      10UL*1024UL*1024UL+32UL+sizeof(fd_lthash_value_t), 1UL );
  /**/                 fd_topob_link( topo, "ipecho_out",   "ipecho_out",   2UL,                                      0UL,                           1UL );
  FOR(gossvf_tile_cnt) fd_topob_link( topo, "gossvf_gossi", "gossvf_gossi", config->net.ingress_buffer_size,          sizeof(fd_gossip_view_t)+FD_NET_MTU, 1UL );
  /**/                 fd_topob_link( topo, "gossip_gossv", "gossip_gossv", 65536UL*4UL,                              sizeof(fd_gossip_ping_update_t), 1UL ); /* TODO: Unclear where this depth comes from ... fix */
  /**/                 fd_topob_link( topo, "gossip_out",   "gossip_out",   65536UL*4UL,                              sizeof(fd_gossip_update_message_t), 1UL ); /* TODO: Unclear where this depth comes from ... fix */

  FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  config->tiles.verify.receive_buffer_size, FD_TPU_REASM_MTU,              config->tiles.quic.txn_reassembly_count );
  FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,             1UL );
  /**/                 fd_topob_link( topo, "dedup_resolv", "dedup_resolv", 65536UL,                                  FD_TPU_PARSED_MTU,             1UL );
  FOR(resolv_tile_cnt) fd_topob_link( topo, "resolv_pack",  "resolv_pack",  65536UL,                                  FD_TPU_RESOLVED_MTU,           1UL );
  /**/                 fd_topob_link( topo, "replay_stake", "replay_stake", 128UL,                                    FD_STAKE_OUT_MTU,              1UL ); /* TODO: This should be 2 but requires fixing STEM_BURST */
  /**/                 fd_topob_link( topo, "replay_out",   "replay_out",   8192UL,                                   sizeof(fd_replay_message_t),   1UL );
  /**/                 fd_topob_link( topo, "pack_poh",     "pack_poh",     4096UL,                                   sizeof(fd_done_packing_t),     1UL );
  /* pack_bank is shared across all banks, so if one bank stalls due to complex transactions, the buffer needs to be large so that
     other banks can keep proceeding. */
  /**/                 fd_topob_link( topo, "pack_bank",    "pack_bank",    65536UL,                                  USHORT_MAX,                    1UL );
  FOR(bank_tile_cnt)   fd_topob_link( topo, "bank_poh",     "bank_poh",     16384UL,                                  USHORT_MAX,                    1UL );
  if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) ) {
    FOR(bank_tile_cnt) fd_topob_link( topo, "bank_pack",    "bank_pack",    16384UL,                                  USHORT_MAX,                    1UL );
  }
  /**/                 fd_topob_link( topo, "poh_shred",    "poh_shred",    16384UL,                                  USHORT_MAX,                    1UL );
  /**/                 fd_topob_link( topo, "poh_replay",   "poh_replay",   4096UL,                                   sizeof(fd_poh_leader_slot_ended_t), 1UL );
  FOR(resolv_tile_cnt) fd_topob_link( topo, "resolv_repla", "resolv_repla", 4096UL,                                   sizeof(fd_resolv_slot_exchanged_t), 1UL );
  /**/                 fd_topob_link( topo, "executed_txn", "executed_txn", 16384UL,                                  64UL,                          1UL ); /* TODO: Rename this ... */

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                          1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "gossip_sign",  "gossip_sign",  128UL,                                    2048UL,                        1UL ); /* TODO: Where does 2048 come from? Depth probably doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "sign_gossip",  "sign_gossip",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL ); /* TODO: Depth probably doesn't need to be 128 */

  FOR(sign_tile_cnt-1) fd_topob_link( topo, "repair_sign",  "repair_sign",  256UL,                                    FD_REPAIR_MAX_PREIMAGE_SZ,     1UL ); /* See repair_tile.c for explanation */
  FOR(sign_tile_cnt-1) fd_topob_link( topo, "sign_repair",  "sign_repair",  128UL,                                    sizeof(fd_ed25519_sig_t),      1UL );

  /**/                 fd_topob_link( topo, "send_sign",    "send_sign",    128UL,                                    FD_TXN_MTU,                    1UL ); /* TODO: Depth probably doesn't need to be 128 */
  /**/                 fd_topob_link( topo, "sign_send",    "sign_send",    128UL,                                    sizeof(fd_ed25519_sig_t),      1UL ); /* TODO: Depth probably doesn't need to be 128 */

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_out",    "shred_out",    shred_depth,                              FD_SHRED_OUT_MTU,              3UL ); /* TODO: Pretty sure burst of 3 is incorrect here */
  FOR(shred_tile_cnt)  fd_topob_link( topo, "repair_shred", "shred_out",    shred_depth,                              sizeof(fd_ed25519_sig_t),      1UL );
  /**/                 fd_topob_link( topo, "tower_out",    "tower_out",    16384,                                    sizeof(fd_tower_msg_t),        2UL ); /* conf + slot_done. see explanation in fd_tower_tile.h for link_depth */
  /**/                 fd_topob_link( topo, "send_out",     "send_out",     128UL,                                    FD_TPU_RAW_MTU,                1UL );

                       fd_topob_link( topo, "replay_exec",  "replay_exec",  16384UL,                                  sizeof(fd_exec_task_msg_t),    1UL );

  FOR(exec_tile_cnt)   fd_topob_link( topo, "exec_sig",     "exec_sig",     16384UL,                                  64UL,                          1UL );
  FOR(exec_tile_cnt)   fd_topob_link( topo, "exec_replay",  "exec_replay",  16384UL,                                  sizeof(fd_exec_task_done_msg_t), 1UL );

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
  /**/                 fd_topob_tile( topo, "cswtch",  "cswtch",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  if( FD_LIKELY( snapshots_enabled ) ) {
    /**/               fd_topob_tile( topo, "snapct", "snapct", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapld", "snapld", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapin", "snapin", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
    if(vinyl_enabled)  fd_topob_tile( topo, "snapwh", "snapwh", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;
    if(vinyl_enabled)  fd_topob_tile( topo, "snapwr", "snapwr", "metric_in", tile_to_cpu[ topo->tile_cnt ],    0,        0 )->allow_shutdown = 1;

    if( FD_LIKELY( !snapshot_lthash_disabled ) ) {
    FOR(lta_tile_cnt)  fd_topob_tile( topo, "snapla", "snapla", "metric_in", tile_to_cpu[ topo->tile_cnt ],  0,        0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapls", "snapls", "metric_in", tile_to_cpu[ topo->tile_cnt ],  0,        0 )->allow_shutdown = 1;
    }
  }

  /**/                 fd_topob_tile( topo, "genesi",  "genesi",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 )->allow_shutdown = 1;
  /**/                 fd_topob_tile( topo, "ipecho",  "ipecho",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(gossvf_tile_cnt) fd_topob_tile( topo, "gossvf",  "gossvf",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                 fd_topob_tile( topo, "gossip",  "gossip",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );

  FOR(shred_tile_cnt)  fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  /**/                 fd_topob_tile( topo, "repair",  "repair",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 ); /* TODO: Wrong? Needs to use keyswitch as signs */
  /**/                 fd_topob_tile( topo, "replay",  "replay",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  FOR(exec_tile_cnt)   fd_topob_tile( topo, "exec",    "exec",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
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

  if( FD_UNLIKELY( solcap_enabled ) ) {
    fd_topob_wksp( topo, "solcap" );
    fd_topob_tile( topo, "solcap", "solcap", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  }

  if( FD_LIKELY( snapshots_enabled ) ) {
    if( vinyl_enabled ) {
      ulong vinyl_map_obj_id  = fd_pod_query_ulong( topo->props, "vinyl.meta_map",  ULONG_MAX ); FD_TEST( vinyl_map_obj_id !=ULONG_MAX );
      ulong vinyl_pool_obj_id = fd_pod_query_ulong( topo->props, "vinyl.meta_pool", ULONG_MAX ); FD_TEST( vinyl_pool_obj_id!=ULONG_MAX );

      fd_topo_obj_t * vinyl_map_obj  = &topo->objs[ vinyl_map_obj_id ];
      fd_topo_obj_t * vinyl_pool_obj = &topo->objs[ vinyl_pool_obj_id ];

      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], vinyl_map_obj,  FD_SHMEM_JOIN_MODE_READ_WRITE );
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], vinyl_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    }
  }

  /*                                        topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  FOR(gossvf_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                      fd_topob_tile_in(     topo, "gossvf",  i,            "metric_in", "net_gossvf",   j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                      fd_topob_tile_in (    topo, "shred",   i,            "metric_in", "net_shred",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(net_tile_cnt)   fd_topob_tile_in(     topo, "repair",  0UL,          "metric_in", "net_repair",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topob_tile_out(    topo, "repair",  0UL,                       "repair_net",   0UL                                                );
  FOR(net_tile_cnt)   fd_topob_tile_in (    topo, "send",    0UL,          "metric_in", "net_send",     i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                      fd_topob_tile_in(     topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  FOR(shred_tile_cnt) fd_topos_tile_in_net( topo,                          "metric_in", "shred_net",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net( topo,                          "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net( topo,                          "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  /**/                fd_topos_tile_in_net( topo,                          "metric_in", "send_net",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  FOR(quic_tile_cnt)  fd_topos_tile_in_net( topo,                          "metric_in", "quic_net",     i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  /**/                 fd_topob_tile_out(   topo, "genesi", 0UL,                        "genesi_out",   0UL                                                );
  /**/                 fd_topob_tile_in (   topo, "ipecho", 0UL,           "metric_in", "genesi_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
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
  /**/                 fd_topob_tile_in(    topo, "gossip", 0UL,           "metric_in", "send_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_gossv", 0UL                                                );

  int snapshots_gossip_enabled = config->firedancer.snapshots.sources.gossip.allow_any || config->firedancer.snapshots.sources.gossip.allow_list_cnt>0UL;
  if( FD_LIKELY( snapshots_enabled ) ) {
    if( FD_LIKELY( snapshots_gossip_enabled ) ) {
      /**/            fd_topob_tile_in (    topo, "snapct",  0UL,          "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    }

    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
                      fd_topob_tile_in (    topo, "snapct",  0UL,          "metric_in", "snapin_ct",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    } else {
                      fd_topob_tile_in (    topo, "snapct",  0UL,          "metric_in", "snapls_ct",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    }
                      fd_topob_tile_in (    topo, "snapct",  0UL,          "metric_in", "snapld_dc",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                      fd_topob_tile_out(    topo, "snapct",  0UL,                       "snapct_ld",    0UL                                                );
                      fd_topob_tile_out(    topo, "snapct",  0UL,                       "snapct_repr",  0UL                                                );
    if( FD_LIKELY( config->tiles.gui.enabled ) ) {
      /**/            fd_topob_tile_out(    topo, "snapct",  0UL,                       "snapct_gui",   0UL                                                );
    }
    if( vinyl_enabled ) {
      /**/            fd_topob_tile_out(    topo, "snapin",  0UL,                       "snapin_wh",    0UL                                                );
      /**/            fd_topob_tile_in (    topo, "snapwh",  0UL,          "metric_in", "snapin_wh",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      /**/            fd_topob_tile_out(    topo, "snapwh",  0UL,                       "snapwh_wr",    0UL                                                );
      /**/            fd_topob_tile_in (    topo, "snapwr",  0UL,          "metric_in", "snapwh_wr",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapwr", 0UL ) ], &topo->objs[ topo->links[ fd_topo_find_link( topo, "snapin_wh", 0UL ) ].dcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
    }

    /**/              fd_topob_tile_in (    topo, "snapld",  0UL,          "metric_in", "snapct_ld",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/              fd_topob_tile_out(    topo, "snapld",  0UL,                       "snapld_dc",    0UL                                                );

    /**/              fd_topob_tile_in (    topo, "snapdc",  0UL,          "metric_in", "snapld_dc",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/              fd_topob_tile_out(    topo, "snapdc",  0UL,                       "snapdc_in",    0UL                                                );

                      fd_topob_tile_in (    topo, "snapin",  0UL,          "metric_in", "snapdc_in",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    if( FD_LIKELY( config->tiles.gui.enabled ) ) {
      /**/            fd_topob_tile_out(    topo, "snapin", 0UL,                        "snapin_gui",   0UL                                                );
    }
    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
                      fd_topob_tile_out(    topo, "snapin",  0UL,                       "snapin_ct",    0UL                                                );
    } else {
                      fd_topob_tile_out(    topo, "snapin",  0UL,                       "snapin_ls",    0UL                                                );
    }
                      fd_topob_tile_out(    topo, "snapin",  0UL,                       "snapin_manif", 0UL                                                );
    if( FD_LIKELY( !snapshot_lthash_disabled ) ) {
    FOR(lta_tile_cnt) fd_topob_tile_in(     topo, "snapla",  i,            "metric_in", "snapdc_in",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(lta_tile_cnt) fd_topob_tile_out(    topo, "snapla",  i,                         "snapla_ls",    i                                                  );
    /**/              fd_topob_tile_in(     topo, "snapls",  0UL,          "metric_in", "snapin_ls",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(lta_tile_cnt) fd_topob_tile_in(     topo, "snapls",  0UL,          "metric_in", "snapla_ls",    i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/              fd_topob_tile_out(    topo, "snapls",  0UL,                       "snapls_ct",    0UL                                                );
    }
  }

  /**/                 fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "genesi_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "tower_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( snapshots_enabled ) {
                       fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "snapin_manif", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }
  FOR(shred_tile_cnt)  fd_topob_tile_in(    topo, "repair",  0UL,          "metric_in", "shred_out",    i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in(    topo, "replay",  0UL,          "metric_in", "shred_out",    i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out(   topo, "repair",  0UL,                       "repair_shred", i                                                  );
  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "genesi_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_out",   0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_stake", 0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "executed_txn", 0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "replay",  0UL,                       "replay_exec",  0UL                                                );
  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "tower_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "send_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_in(    topo, "replay",  0UL,          "metric_in", "resolv_repla", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  if( FD_LIKELY( snapshots_enabled ) ) {
                       fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "snapin_manif", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  /**/                 fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "poh_replay",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(exec_tile_cnt)   fd_topob_tile_in (   topo, "exec",    i,            "metric_in", "replay_exec",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /**/                 fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "dedup_resolv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "replay_exec",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "tower",   0UL,          "metric_in", "replay_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "tower",   0UL,                       "tower_out",    0UL                                                );

  /**/                 fd_topob_tile_in (   topo, "send",    0UL,          "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "send",    0UL,          "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in (   topo, "send",    0UL,          "metric_in", "tower_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "send",    0UL,                       "send_net",     0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "send",    0UL,                       "send_out",     0UL                                                );

  FOR(quic_tile_cnt)  fd_topob_tile_out(    topo, "quic",    i,                         "quic_verify",  i                                                  );
  FOR(quic_tile_cnt)  fd_topob_tile_out(    topo, "quic",    i,                         "quic_net",     i                                                  );
  /* All verify tiles read from all QUIC tiles, packets are round robin. */
  FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                       fd_topob_tile_in(    topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
  FOR(verify_tile_cnt) fd_topob_tile_in(    topo, "verify",  i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "verify",  0UL,          "metric_in", "send_out",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(verify_tile_cnt) fd_topob_tile_out(   topo, "verify",  i,                         "verify_dedup", i                                                  );
  FOR(verify_tile_cnt) fd_topob_tile_in(    topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "dedup",   0UL,          "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "dedup",   0UL,                       "dedup_resolv", 0UL                                                );
  FOR(resolv_tile_cnt) fd_topob_tile_in(    topo, "resolv",  i,            "metric_in", "dedup_resolv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_in(    topo, "resolv",  i,            "metric_in", "replay_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(resolv_tile_cnt) fd_topob_tile_out(   topo, "resolv",  i,                         "resolv_pack",  i                                                  );
  FOR(resolv_tile_cnt) fd_topob_tile_out(   topo, "resolv",  i,                         "resolv_repla", i                                                  );
  /**/                 fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "resolv_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "replay_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                       fd_topob_tile_out(   topo, "pack",    0UL,                       "pack_bank",    0UL                                                );
                       fd_topob_tile_out(   topo, "pack",    0UL,                       "pack_poh" ,    0UL                                                );
  if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) ) {
    FOR(bank_tile_cnt) fd_topob_tile_in(    topo, "pack",    0UL,          "metric_in", "bank_pack",    i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }
  FOR(bank_tile_cnt)   fd_topob_tile_in(    topo, "bank",    i,            "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(bank_tile_cnt)   fd_topob_tile_out(   topo, "bank",    i,                         "bank_poh",     i                                                  );
  if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) ) {
    FOR(bank_tile_cnt) fd_topob_tile_out(   topo, "bank",    i,                         "bank_pack",    i                                                  );
  }
  FOR(bank_tile_cnt)   fd_topob_tile_in(    topo, "poh",     0UL,          "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "poh",     0UL,          "metric_in", "pack_poh",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_in(    topo, "poh",     0UL,          "metric_in", "replay_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  /**/                 fd_topob_tile_out(   topo, "poh",     0UL,                       "poh_shred",    0UL                                                );
  /**/                 fd_topob_tile_out(   topo, "poh",     0UL,                       "poh_replay",   0UL                                                );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out(   topo, "shred",   i,                         "shred_out",    i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "repair_shred", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_in (   topo, "shred",   i,            "metric_in", "poh_shred",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(shred_tile_cnt)  fd_topob_tile_out(   topo, "shred",   i,                         "shred_net",    i                                                  );

  FOR(exec_tile_cnt)   fd_topob_tile_in (   topo, "dedup",   0UL,          "metric_in", "exec_sig",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(exec_tile_cnt)   fd_topob_tile_in (   topo, "pack",    0UL,          "metric_in", "exec_sig",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  FOR(exec_tile_cnt)   fd_topob_tile_out(   topo, "exec",    i,                         "exec_sig",     i                                                  );
  FOR(exec_tile_cnt)   fd_topob_tile_out(   topo, "exec",    i,                         "exec_replay",  i                                                  );
  FOR(exec_tile_cnt)   fd_topob_tile_in (   topo, "replay",  0UL,          "metric_in", "exec_replay",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );


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

    /* TODO: bundle gui support needs to be integrated here */
  }

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

  FOR(sign_tile_cnt-1UL) fd_topob_tile_out( topo, "repair",  0UL,                       "repair_sign",  i                                                    );
  FOR(sign_tile_cnt-1UL) fd_topob_tile_in ( topo, "sign",    i+1UL,        "metric_in", "repair_sign",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(sign_tile_cnt-1UL) fd_topob_tile_out( topo, "sign",    i+1UL,                     "sign_repair",  i                                                    );
  FOR(sign_tile_cnt-1UL) fd_topob_tile_in ( topo, "repair",  0UL,          "metric_in", "sign_repair",  i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   ); /* This link is polled because the signing requests are asynchronous */

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

    fd_topob_tile( topo, "scap", "scap", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "repair_net", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    for( ulong j=0UL; j<net_tile_cnt; j++ ) {
      fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "net_shred", j, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }
    for( ulong j=0UL; j<shred_tile_cnt; j++ ) {
      fd_topob_tile_in(  topo, "scap", 0UL, "metric_in", "shred_out", j, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    }
    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "gossip_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    fd_topob_tile_in( topo, "scap", 0UL, "metric_in", "replay_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

    /* No default fd_topob_tile_in connection to stake_out */
  }

  int rpc_enabled = config->tiles.rpc.enabled;
  if( FD_UNLIKELY( rpc_enabled ) ) {
    fd_topob_wksp( topo, "rpc" );
    fd_topob_wksp( topo, "rpc_replay" );
    fd_topob_link( topo, "rpc_replay", "rpc_replay", 4UL, 0UL, 1UL );
    fd_topob_tile( topo, "rpc",  "rpc",  "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    fd_topob_tile_out( topo, "rpc", 0UL, "rpc_replay", 0UL );
    fd_topob_tile_in( topo, "rpc",  0UL, "metric_in", "replay_out",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "rpc",  0UL, "metric_in", "genesi_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "rpc_replay", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  if( FD_UNLIKELY( solcap_enabled ) ) {
    fd_topob_link( topo, "cap_repl", "solcap", 32UL, SOLCAP_WRITE_ACCOUNT_DATA_MTU, 1UL );
    fd_topob_tile_out( topo, "replay", 0UL, "cap_repl", 0UL );
    fd_topob_tile_in( topo, "solcap", 0UL, "metric_in", "cap_repl", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    FOR(exec_tile_cnt) fd_topob_link( topo, "cap_exec", "solcap", 32UL, SOLCAP_WRITE_ACCOUNT_DATA_MTU, 1UL );
    FOR(exec_tile_cnt) fd_topob_tile_out( topo, "exec", i, "cap_exec", i );
    FOR(exec_tile_cnt) fd_topob_tile_in( topo, "solcap", 0UL, "metric_in", "cap_exec", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
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

    fd_topo_tile_t * pack_tile = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
    fd_topo_tile_t * bank_tile = &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ];
    fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    fd_topob_tile_uses( topo, bank_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* TODO: Should be readonly? */
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "tower", 0UL  ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(bank_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "bank",   i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(resolv_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "resolv", i   ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );

  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width, config->development.bench.larger_max_cost_per_block );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "tower",  0UL ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(bank_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "bank",   i   ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(resolv_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "resolv", i   ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  fd_topo_obj_t * banks_locks_obj = setup_topo_banks_locks( topo, "banks_locks" );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "tower",  0UL ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(bank_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "bank",   i   ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(resolv_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "resolv", i   ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_locks_obj->id, "banks_locks" ) );

  if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
    if( FD_UNLIKELY( config->firedancer.runtime.max_account_cnt<FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_BUNDLE ) ) {
      FD_LOG_ERR(( "max_account_cnt is less than the minimum required for bundle execution: %lu < %lu", config->firedancer.runtime.max_account_cnt, FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_BUNDLE ));
    }
  }
  if( FD_UNLIKELY( config->firedancer.runtime.max_account_cnt<FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX ) ) {
    FD_LOG_ERR(( "max_account_cnt is less than the minimum required for transaction execution: %lu < %lu", config->firedancer.runtime.max_account_cnt, FD_ACC_POOL_MIN_ACCOUNT_CNT_PER_TX ));
  }
  fd_topo_obj_t * acc_pool_obj = setup_topo_acc_pool( topo, config->firedancer.runtime.max_account_cnt );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], acc_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(bank_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "bank",   i   ) ], acc_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, acc_pool_obj->id, "acc_pool" ) );

  fd_topo_obj_t * progcache_obj = setup_topo_progcache( topo, "progcache",
      fd_progcache_est_rec_max( config->firedancer.runtime.program_cache.heap_size_mib<<20,
                                config->firedancer.runtime.program_cache.mean_cache_entry_size ),
      config->firedancer.funk.max_database_transactions,
      config->firedancer.runtime.program_cache.heap_size_mib<<20 );
  /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], progcache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec",   i   ) ], progcache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(bank_tile_cnt)   fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "bank",   i   ) ], progcache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  if( FD_LIKELY( config->tiles.gui.enabled ) ) {
    fd_topob_wksp( topo, "gui" );

    /**/                 fd_topob_tile(     topo, "gui",     "gui",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 1 );

    /* Read banks */
    /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "gui", 0UL ) ], banks_obj,       FD_SHMEM_JOIN_MODE_READ_ONLY );
    /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "gui", 0UL ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

    /* release ownership of banks */
    /**/                 fd_topob_link( topo, "gui_replay", "gui", 128, 0UL,2UL ); /* burst==2 since a bank and its parent may be sent in one burst */

    /**/                 fd_topob_tile_out( topo, "gui",    0UL,                        "gui_replay", 0UL                                                );
    /**/                 fd_topob_tile_in ( topo, "replay", 0UL,           "metric_in", "gui_replay", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

    /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
    FOR(net_tile_cnt)    fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "net_gossvf",   i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "repair_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "shred_out",    i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "tower_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "replay_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "replay_stake", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "genesi_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "pack_poh",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "bank_poh",       i,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(exec_tile_cnt)   fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "exec_replay",    i,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

    if( FD_LIKELY( snapshots_enabled ) ) {
    /**/                 fd_topob_tile_in ( topo, "gui",    0UL,           "metric_in", "snapct_gui",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in ( topo, "gui",    0UL,           "metric_in", "snapin_gui",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    }
  }

  ulong fec_set_cnt = shred_depth + config->tiles.shred.max_pending_shred_sets + 4UL;
  ulong fec_sets_sz = fec_set_cnt*sizeof(fd_shred34_t)*4; /* mirrors # of dcache entires in frankendancer */
  fd_topo_obj_t * fec_sets_obj = setup_topo_fec_sets( topo, "fec_sets", shred_tile_cnt*fec_sets_sz );
  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
    fd_topob_tile_uses( topo, shred_tile, fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "repair", 0UL ) ], fec_sets_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fec_sets_obj->id, "fec_sets" ) );

   /* The Store fec_max parameter is the max number of FEC sets that can
      be retained before the Tower consensus algorithm indicates a new
      "root", which allows pruning FECs.

      The default value is from multiplying max_live_slots by the
      maximum number of FEC sets in a block (currently 32768 but can be
      reduced to 1024 once FECs are restricted to always be size 32,
      given the current consensus limit of 32768 shreds per block). */

  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.runtime.max_live_slots * FD_SHRED_BLK_MAX / 4 /* FIXME temporary hack to run on 512 gb boxes */, (uint)shred_tile_cnt );
  FOR(shred_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache", config->firedancer.runtime.max_live_slots, fd_ulong_pow2_up( FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) );
  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  if( FD_LIKELY( snapshots_enabled ) ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  FOR(bank_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "genesi", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  if( FD_LIKELY( snapshots_enabled ) ) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  if( FD_UNLIKELY( rpc_enabled ) ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "rpcsrv", 0UL ) ], funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "rpcsrv", 0UL ) ], store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  fd_pod_insert_int( topo->props, "sandbox", config->development.sandbox ? 1 : 0 );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) fd_topo_configure_tile( &topo->tiles[ i ], config );

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );
  fd_topob_finish( topo, CALLBACKS );
  config->topo = *topo;
}

void
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config ) {
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

    tile->ipecho.expected_shred_version = config->consensus.expected_shred_version;
    tile->ipecho.bind_address           = config->net.ip_addr;
    tile->ipecho.bind_port              = config->gossip.port;
    tile->ipecho.entrypoints_cnt        = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->ipecho.entrypoints, config->gossip.resolved_entrypoints, tile->ipecho.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "genesi" ) ) ) {

    tile->genesi.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );

    tile->genesi.allow_download = config->firedancer.snapshots.genesis_download;
    strncpy( tile->genesi.genesis_path, config->paths.genesis, sizeof(tile->genesi.genesis_path) );
    tile->genesi.expected_shred_version = config->consensus.expected_shred_version;
    tile->genesi.entrypoints_cnt        = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->genesi.entrypoints, config->gossip.resolved_entrypoints, tile->genesi.entrypoints_cnt * sizeof(fd_ip4_port_t) );

    tile->genesi.has_expected_genesis_hash = !!strcmp( config->consensus.expected_genesis_hash, "" );

    if( FD_UNLIKELY( strcmp( config->consensus.expected_genesis_hash, "" ) && !fd_base58_decode_32( config->consensus.expected_genesis_hash, tile->genesi.expected_genesis_hash ) ) ) {
      FD_LOG_ERR(( "failed to decode [consensus.expected_genesis_hash] \"%s\" as base58", config->consensus.expected_genesis_hash ));
    }

    tile->genesi.target_gid = config->gid;
    tile->genesi.target_uid = config->uid;

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

    tile->gossip.ports.gossip           = config->gossip.port;
    tile->gossip.ports.tvu              = config->tiles.shred.shred_listen_port;
    tile->gossip.ports.tpu              = config->tiles.quic.regular_transaction_listen_port;
    tile->gossip.ports.tpu_quic         = config->tiles.quic.quic_transaction_listen_port;
    tile->gossip.ports.repair           = config->tiles.repair.repair_intake_listen_port;

    tile->gossip.entrypoints_cnt        = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->gossip.entrypoints, config->gossip.resolved_entrypoints, tile->gossip.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapct" ) ) ) {

    fd_memcpy( tile->snapct.snapshots_path, config->paths.snapshots, PATH_MAX );
    tile->snapct.sources.max_local_full_effective_age = config->firedancer.snapshots.sources.max_local_full_effective_age;
    tile->snapct.sources.max_local_incremental_age    = config->firedancer.snapshots.sources.max_local_incremental_age;
    tile->snapct.incremental_snapshots                = config->firedancer.snapshots.incremental_snapshots;
    tile->snapct.max_full_snapshots_to_keep           = config->firedancer.snapshots.max_full_snapshots_to_keep;
    tile->snapct.max_incremental_snapshots_to_keep    = config->firedancer.snapshots.max_incremental_snapshots_to_keep;
    tile->snapct.full_effective_age_cancel_threshold  = config->firedancer.snapshots.full_effective_age_cancel_threshold;
    tile->snapct.sources.gossip.allow_any             = config->firedancer.snapshots.sources.gossip.allow_any;
    tile->snapct.sources.gossip.allow_list_cnt        = config->firedancer.snapshots.sources.gossip.allow_list_cnt;
    tile->snapct.sources.gossip.block_list_cnt        = config->firedancer.snapshots.sources.gossip.block_list_cnt;
    tile->snapct.sources.servers_cnt                  = config->firedancer.snapshots.sources.servers_cnt;
    for( ulong i=0UL; i<tile->snapct.sources.gossip.allow_list_cnt; i++ ) {
      if( FD_UNLIKELY( !fd_base58_decode_32( config->firedancer.snapshots.sources.gossip.allow_list[ i ], tile->snapct.sources.gossip.allow_list[ i ].uc ) ) ) {
        FD_LOG_ERR(( "[snapshots.sources.gossip.allow_list[%lu]] invalid (%s)", i, config->firedancer.snapshots.sources.gossip.allow_list[ i ] ));
      }
    }
    for( ulong i=0UL; i<tile->snapct.sources.gossip.block_list_cnt; i++ ) {
      if( FD_UNLIKELY( !fd_base58_decode_32( config->firedancer.snapshots.sources.gossip.block_list[ i ], tile->snapct.sources.gossip.block_list[ i ].uc ) ) ) {
        FD_LOG_ERR(( "[snapshots.sources.gossip.block_list[%lu]] invalid (%s)", i, config->firedancer.snapshots.sources.gossip.block_list[ i ] ));
      }
    }

    ulong resolved_peers_cnt = 0UL;
    for( ulong i=0UL; i<tile->snapct.sources.servers_cnt; i++ ) {
      fd_ip4_port_t resolved_addrs[ FD_TOPO_MAX_RESOLVED_ADDRS ];
      struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
      int num_resolved = resolve_peer( config->firedancer.snapshots.sources.servers[ i ],
                                       &hints,
                                       "snapshots.sources.servers",
                                       tile->snapct.sources.servers[ resolved_peers_cnt ].hostname,
                                       resolved_addrs,
                                       FD_TOPO_MAX_RESOLVED_ADDRS,
                                       &tile->snapct.sources.servers[ resolved_peers_cnt ].is_https );
      if( FD_UNLIKELY( 0==num_resolved ) ) {
        FD_LOG_ERR(( "[snapshots.sources.servers[%lu]] invalid (%s)", i, config->firedancer.snapshots.sources.servers[ i ] ));
      } else {
        for( ulong i=0UL; i<(ulong)num_resolved; i++ ) tile->snapct.sources.servers[ resolved_peers_cnt+i ].addr = resolved_addrs[ i ];
        for( ulong i=1UL; i<(ulong)num_resolved; i++ ) {
          tile->snapct.sources.servers[ resolved_peers_cnt+i ].is_https = tile->snapct.sources.servers[ resolved_peers_cnt ].is_https;
          fd_memcpy( tile->snapct.sources.servers[ resolved_peers_cnt+i ].hostname,
                     tile->snapct.sources.servers[ resolved_peers_cnt ].hostname,
                     sizeof(tile->snapct.sources.servers[ resolved_peers_cnt ].hostname) );
        }
        resolved_peers_cnt += (ulong)num_resolved;
      }
    }
    tile->snapct.sources.servers_cnt = resolved_peers_cnt;
  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapld" ) ) ) {

    fd_memcpy( tile->snapld.snapshots_path, config->paths.snapshots, PATH_MAX );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapdc" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapin" ) ) ) {

    tile->snapin.max_live_slots  = config->firedancer.runtime.max_live_slots;
    tile->snapin.funk_obj_id     = fd_pod_query_ulong( config->topo.props, "funk",     ULONG_MAX );
    tile->snapin.txncache_obj_id = fd_pod_query_ulong( config->topo.props, "txncache", ULONG_MAX );

    tile->snapin.use_vinyl = !!config->firedancer.vinyl.enabled;
    tile->snapin.lthash_disabled = !!config->development.snapshots.disable_lthash_verification;
    if( tile->snapin.use_vinyl ) {
      strcpy( tile->snapin.vinyl_path, config->paths.accounts );
      tile->snapin.vinyl_meta_map_obj_id  = fd_pod_query_ulong( config->topo.props, "vinyl.meta_map",  ULONG_MAX );
      tile->snapin.vinyl_meta_pool_obj_id = fd_pod_query_ulong( config->topo.props, "vinyl.meta_pool", ULONG_MAX );

      ulong in_wr_link_id = fd_topo_find_link( &config->topo, "snapin_wh", 0UL );
      FD_TEST( in_wr_link_id!=ULONG_MAX );
      fd_topo_link_t * in_wr_link = &config->topo.links[ in_wr_link_id ];
      tile->snapin.snapwr_depth = in_wr_link->depth;
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapwh" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapwr" ) ) ) {

    strcpy( tile->snapwr.vinyl_path, config->paths.accounts );
    ulong in_wr_link_id = fd_topo_find_link( &config->topo, "snapin_wh", 0UL );
    FD_TEST( in_wr_link_id!=ULONG_MAX );
    fd_topo_link_t * in_wr_link = &config->topo.links[ in_wr_link_id ];
    tile->snapwr.dcache_obj_id = in_wr_link->dcache_obj_id;
  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapla" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "snapls" ) ) )  {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "repair" ) ) ) {
    tile->repair.max_pending_shred_sets    = config->tiles.shred.max_pending_shred_sets;
    tile->repair.repair_intake_listen_port = config->tiles.repair.repair_intake_listen_port;
    tile->repair.repair_serve_listen_port  = config->tiles.repair.repair_serve_listen_port;
    tile->repair.slot_max                  = config->tiles.repair.slot_max;
    tile->repair.repair_sign_cnt           = config->firedancer.layout.sign_tile_count - 1; /* -1 because this excludes the keyguard client */
    tile->repair.end_slot                  = 0;

    for( ulong i=0; i<tile->in_cnt; i++ ) {
      if( !strcmp( config->topo.links[ tile->in_link_id[ i ] ].name, "sign_repair" ) ) {
        tile->repair.repair_sign_depth = config->topo.links[ tile->in_link_id[ i ] ].depth;
        break;
      }
    }
    strncpy( tile->repair.identity_key_path, config->paths.identity_key, sizeof(tile->repair.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "replay" ) )) {

    /* Please maintain same field order as fd_topo.h */

    tile->replay.fec_max = config->firedancer.runtime.max_live_slots * FD_SHRED_BLK_MAX / 4; /* FIXME temporary hack to run on 512 gb boxes */
    tile->replay.max_vote_accounts = config->firedancer.runtime.max_vote_accounts;

    tile->replay.funk_obj_id      = fd_pod_query_ulong( config->topo.props, "funk",      ULONG_MAX ); FD_TEST( tile->replay.funk_obj_id     !=ULONG_MAX );

    tile->replay.txncache_obj_id  = fd_pod_query_ulong( config->topo.props, "txncache",  ULONG_MAX ); FD_TEST( tile->replay.txncache_obj_id !=ULONG_MAX );
    tile->replay.progcache_obj_id = fd_pod_query_ulong( config->topo.props, "progcache", ULONG_MAX ); FD_TEST( tile->replay.progcache_obj_id!=ULONG_MAX );

    strncpy( tile->replay.identity_key_path, config->paths.identity_key, sizeof(tile->replay.identity_key_path) );
    tile->replay.ip_addr = config->net.ip_addr;
    strncpy( tile->replay.vote_account_path, config->paths.vote_account, sizeof(tile->replay.vote_account_path) );

    tile->replay.expected_shred_version = config->consensus.expected_shred_version;

    tile->replay.max_live_slots = config->firedancer.runtime.max_live_slots;

    strncpy( tile->replay.genesis_path, config->paths.genesis, sizeof(tile->replay.genesis_path) );

    tile->replay.larger_max_cost_per_block = config->development.bench.larger_max_cost_per_block;

    /* not specified by [tiles.replay] */

    tile->replay.capture_start_slot = config->capture.capture_start_slot;
    strncpy( tile->replay.solcap_capture, config->capture.solcap_capture, sizeof(tile->replay.solcap_capture) );
    strncpy( tile->replay.dump_proto_dir, config->capture.dump_proto_dir, sizeof(tile->replay.dump_proto_dir) );
    tile->replay.dump_block_to_pb = config->capture.dump_block_to_pb;

    if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
#define PARSE_PUBKEY( _tile, f ) \
      if( FD_UNLIKELY( !fd_base58_decode_32( config->tiles.bundle.f, tile->_tile.bundle.f ) ) )  \
        FD_LOG_ERR(( "[tiles.bundle.enabled] set to true, but failed to parse [tiles.bundle."#f"] %s", config->tiles.bundle.f ));
      tile->replay.bundle.enabled = 1;
      PARSE_PUBKEY( replay, tip_distribution_program_addr );
      PARSE_PUBKEY( replay, tip_payment_program_addr      );
      strncpy( tile->replay.bundle.vote_account_path, config->paths.vote_account, sizeof(tile->replay.bundle.vote_account_path) );
    } else {
      fd_memset( &tile->replay.bundle, '\0', sizeof(tile->replay.bundle) );
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "exec" ) ) ) {

    tile->exec.funk_obj_id      = fd_pod_query_ulong( config->topo.props, "funk",      ULONG_MAX ); FD_TEST( tile->exec.funk_obj_id     !=ULONG_MAX );
    tile->exec.txncache_obj_id  = fd_pod_query_ulong( config->topo.props, "txncache",  ULONG_MAX ); FD_TEST( tile->exec.txncache_obj_id !=ULONG_MAX );
    tile->exec.progcache_obj_id = fd_pod_query_ulong( config->topo.props, "progcache", ULONG_MAX ); FD_TEST( tile->exec.progcache_obj_id!=ULONG_MAX );
    tile->exec.acc_pool_obj_id  = fd_pod_query_ulong( config->topo.props, "acc_pool",  ULONG_MAX ); FD_TEST( tile->exec.acc_pool_obj_id !=ULONG_MAX );

    tile->exec.max_live_slots = config->firedancer.runtime.max_live_slots;

    tile->exec.capture_start_slot = config->capture.capture_start_slot;
    strncpy( tile->exec.solcap_capture, config->capture.solcap_capture, sizeof(tile->exec.solcap_capture) );
    strncpy( tile->exec.dump_proto_dir, config->capture.dump_proto_dir, sizeof(tile->exec.dump_proto_dir) );
    tile->exec.dump_instr_to_pb = config->capture.dump_instr_to_pb;
    tile->exec.dump_txn_to_pb = config->capture.dump_txn_to_pb;
    tile->exec.dump_syscall_to_pb = config->capture.dump_syscall_to_pb;
    tile->exec.dump_elf_to_pb = config->capture.dump_elf_to_pb;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "tower" ) ) ) {

    tile->tower.hard_fork_fatal    = config->firedancer.development.hard_fork_fatal;
    tile->tower.max_live_slots     = config->firedancer.runtime.max_live_slots;
    tile->tower.max_vote_lookahead = config->tiles.tower.max_vote_lookahead;
    strncpy( tile->tower.identity_key, config->paths.identity_key, sizeof(tile->tower.identity_key) );
    strncpy( tile->tower.vote_account, config->paths.vote_account, sizeof(tile->tower.vote_account) );
    strncpy( tile->tower.base_path, config->paths.base, sizeof(tile->tower.base_path) );

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

    tile->resolv.funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {

    tile->pack.max_pending_transactions      = config->tiles.pack.max_pending_transactions;
    tile->pack.bank_tile_count               = config->layout.bank_tile_count;
    tile->pack.larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
    tile->pack.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
    tile->pack.use_consumed_cus              = config->tiles.pack.use_consumed_cus;
    tile->pack.schedule_strategy             = config->tiles.pack.schedule_strategy_enum;

    if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {

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
    tile->bank.txncache_obj_id  = fd_pod_query_ulong( config->topo.props, "txncache",  ULONG_MAX );
    tile->bank.funk_obj_id      = fd_pod_query_ulong( config->topo.props, "funk",      ULONG_MAX );
    tile->bank.progcache_obj_id = fd_pod_query_ulong( config->topo.props, "progcache", ULONG_MAX );
    tile->bank.acc_pool_obj_id  = fd_pod_query_ulong( config->topo.props, "acc_pool",  ULONG_MAX );

    tile->bank.max_live_slots = config->firedancer.runtime.max_live_slots;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "poh" ) ) ) {
    strncpy( tile->poh.identity_key_path, config->paths.identity_key, sizeof(tile->poh.identity_key_path) );

    tile->poh.plugins_enabled = 0;
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

  } else if( FD_UNLIKELY( !strcmp( tile->name, "cswtch" ) ) ) {

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
    tile->gui.websocket_compression     = 1;
    tile->gui.frontend_release_channel  = config->development.gui.frontend_release_channel_enum;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "rpc" ) ) ) {

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.rpc.rpc_listen_address, &tile->rpc.listen_addr ) ) )
      FD_LOG_ERR(( "failed to parse rpc listen address `%s`", config->tiles.rpc.rpc_listen_address ));
    tile->rpc.listen_port = config->tiles.rpc.rpc_listen_port;
    tile->rpc.max_http_connections      = config->tiles.rpc.max_http_connections;
    tile->rpc.max_http_request_length   = config->tiles.rpc.max_http_request_length;
    tile->rpc.send_buffer_size_mb       = config->tiles.rpc.send_buffer_size_mb;

    tile->rpc.max_live_slots = config->firedancer.runtime.max_live_slots;

    strncpy( tile->rpc.identity_key_path, config->paths.identity_key, sizeof(tile->rpc.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "arch_f" ) ||
                          !strcmp( tile->name, "arch_w" ) ) ) {

    strncpy( tile->archiver.rocksdb_path, config->tiles.archiver.rocksdb_path, sizeof(tile->archiver.rocksdb_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "backt" ) ) ) {

    tile->backtest.end_slot = config->tiles.archiver.end_slot;

    /* Validate arguments based on the ingest mode */
    if( !strcmp( config->tiles.archiver.ingest_mode, "rocksdb" ) ) {
      strncpy( tile->backtest.rocksdb_path, config->tiles.archiver.rocksdb_path, PATH_MAX );
      if( FD_UNLIKELY( 0==strlen( tile->backtest.rocksdb_path ) ) ) {
        FD_LOG_ERR(( "`archiver.rocksdb_path` not specified in toml" ));
      }
    } else if( !strcmp( config->tiles.archiver.ingest_mode, "shredcap" ) ) {
      strncpy( tile->backtest.shredcap_path, config->tiles.archiver.shredcap_path, PATH_MAX );
      if( FD_UNLIKELY( 0==strlen( tile->backtest.shredcap_path ) ) ) {
        FD_LOG_ERR(( "`archiver.shredcap_path` not specified in toml" ));
      }
    } else {
      FD_LOG_ERR(( "Invalid ingest mode: %s", config->tiles.archiver.ingest_mode ));
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "scap" ) ) ) {

    tile->shredcap.repair_intake_listen_port = config->tiles.repair.repair_intake_listen_port;
    strncpy( tile->shredcap.folder_path, config->tiles.shredcap.folder_path, sizeof(tile->shredcap.folder_path) );
    tile->shredcap.write_buffer_size = config->tiles.shredcap.write_buffer_size;
    tile->shredcap.enable_publish_stake_weights = 0; /* this is not part of the config */
    strncpy( tile->shredcap.manifest_path, "", PATH_MAX ); /* this is not part of the config */

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

  } else if( FD_UNLIKELY( !strcmp( tile->name, "vinyl" ) ) ) {

    tile->vinyl.vinyl_meta_map_obj_id  = fd_pod_query_ulong( config->topo.props, "vinyl.meta_map",  ULONG_MAX );
    tile->vinyl.vinyl_meta_pool_obj_id = fd_pod_query_ulong( config->topo.props, "vinyl.meta_pool", ULONG_MAX );
    tile->vinyl.vinyl_line_max         = config->firedancer.vinyl.max_cache_entries;
    tile->vinyl.vinyl_data_obj_id      = fd_pod_query_ulong( config->topo.props, "vinyl.data",      ULONG_MAX );
    fd_cstr_ncpy( tile->vinyl.vinyl_bstream_path, config->paths.accounts, sizeof(tile->vinyl.vinyl_bstream_path) );

    tile->vinyl.io_type = config->firedancer.vinyl.io_uring.enabled ?
        FD_VINYL_IO_TYPE_UR : FD_VINYL_IO_TYPE_BD;
    tile->vinyl.uring_depth = config->firedancer.vinyl.io_uring.queue_depth;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "solcap" ) ) ) {

    tile->solcap.capture_start_slot = config->capture.capture_start_slot;
    strncpy( tile->solcap.solcap_capture, config->capture.solcap_capture, sizeof(tile->solcap.solcap_capture) );
    tile->solcap.recent_only = config->capture.recent_only;
    tile->solcap.recent_slots_per_file = config->capture.recent_slots_per_file;

  } else {
    FD_LOG_ERR(( "unknown tile name `%s`", tile->name ));
  }
}
