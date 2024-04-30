#include "../tiles/tiles.h"
#include "../../config.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../util/tile/fd_tile_private.h"
#include <sys/sysinfo.h>

static fd_topo_t topo[1];

void
fd_topo_tvu( config_t * config ) {
  topo[0] = fd_topob_new( config->name );

  /*             topo, name */
  fd_topob_wksp( topo, "tvu" );
  fd_topob_wksp( topo, "sign" );
  fd_topob_wksp( topo, "tvu_sign" );
  fd_topob_wksp( topo, "sign_tvu" );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  fd_topob_link( topo, "tvu_sign",    "tvu_sign",    0,        128UL,                                    130UL,                  1UL );
  fd_topob_link( topo, "sign_tvu",    "sign_tvu",    0,        128UL,                                    64UL,                   1UL );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX; /* Unassigned tiles will be floating. */
  ulong affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=65535 && parsed_tile_to_cpu[ i ]>=get_nprocs() ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                   "only has %d CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], get_nprocs() ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==65535, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  /*                                  topo, tile_name, tile_wksp, cnc_wksp,    metrics_wksp, cpu_idx,                       is_labs, out_link,       out_link_kind_id */
  /**/                 fd_topob_tile( topo, "tvu",     "tvu",     "tvu",       "tvu",        tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );
  /**/                 fd_topob_tile( topo, "sign",    "sign",    "sign",      "sign",       tile_to_cpu[ topo->tile_cnt ], 0,       NULL,           0UL );

  /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "sign", "tvu_sign",      0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  /**/               fd_topob_tile_out( topo, "tvu",     0UL,                        "tvu_sign",      0UL                                                  );
  /**/               fd_topob_tile_in(  topo, "tvu",     0UL,           "tvu", "sign_tvu",      0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
  /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_tvu",      0UL                                                  );

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

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( FD_UNLIKELY( !strcmp( tile->name, "tvu" ) ) ) {
        strncpy( tile->tvu.repair_peer_id, config->tiles.tvu.repair_peer_id, sizeof(tile->tvu.repair_peer_id) );
        strncpy( tile->tvu.repair_peer_addr, config->tiles.tvu.repair_peer_addr, sizeof(tile->tvu.repair_peer_addr) );
        strncpy( tile->tvu.gossip_peer_addr, config->tiles.tvu.gossip_peer_addr, sizeof(tile->tvu.gossip_peer_addr) );

        strncpy( tile->tvu.my_gossip_addr, config->tiles.tvu.my_gossip_addr, sizeof(tile->tvu.my_gossip_addr) );
        strncpy( tile->tvu.my_repair_addr, config->tiles.tvu.my_repair_addr, sizeof(tile->tvu.my_repair_addr) );
        strncpy( tile->tvu.tvu_addr, config->tiles.tvu.tvu_addr, sizeof(tile->tvu.tvu_addr) );
        strncpy( tile->tvu.tvu_fwd_addr, config->tiles.tvu.tvu_fwd_addr, sizeof(tile->tvu.tvu_fwd_addr) );
        strncpy( tile->tvu.load, config->tiles.tvu.load, sizeof(tile->tvu.load) );
        strncpy( tile->tvu.snapshot, config->tiles.tvu.snapshot, sizeof(tile->tvu.snapshot) );
	      strncpy( tile->tvu.incremental_snapshot, config->tiles.tvu.incremental_snapshot, sizeof(tile->tvu.incremental_snapshot) );
        strncpy( tile->tvu.validate_snapshot, config->tiles.tvu.validate_snapshot, sizeof(tile->tvu.validate_snapshot) );
        strncpy( tile->tvu.shred_cap, config->tiles.tvu.shred_cap, sizeof(tile->tvu.shred_cap) );
        strncpy( tile->tvu.check_hash, config->tiles.tvu.check_hash, sizeof(tile->tvu.check_hash) );
        strncpy( tile->tvu.identity_key_path, config->consensus.identity_path, sizeof(tile->tvu.identity_key_path) );
        tile->tvu.page_cnt = config->tiles.tvu.page_cnt;
        tile->tvu.gossip_listen_port = config->tiles.tvu.gossip_listen_port;
        tile->tvu.repair_listen_port = config->tiles.tvu.repair_listen_port;
        tile->tvu.tvu_port           = config->tiles.tvu.tvu_port;
        tile->tvu.tvu_fwd_port       = config->tiles.tvu.tvu_fwd_port;
        tile->tvu.rpc_listen_port    = config->tiles.tvu.rpc_listen_port;
        tile->tvu.tcnt               = config->tiles.tvu.tcnt;
        tile->tvu.txn_max            = config->tiles.tvu.txn_max;
        strncpy( tile->tvu.solcap_path, config->tiles.tvu.solcap_path, sizeof(tile->tvu.solcap_path) );
        strncpy( tile->tvu.solcap_txns, config->tiles.tvu.solcap_txns, sizeof(tile->tvu.solcap_txns) );
    } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
      strncpy( tile->sign.identity_key_path, config->consensus.identity_path, sizeof(tile->sign.identity_key_path) );
    } else {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
  config->topo = *topo;
}
